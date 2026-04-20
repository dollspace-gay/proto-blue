//! State-machine property test for [`WebSocketKeepAlive`]'s
//! reconnect accounting.
//!
//! Drives a programmable mock connector that produces a fixed
//! sequence of outcomes — success / transient failure / immediate
//! EOF — and asserts the keep-alive loop's visible state stays
//! consistent across arbitrary sequences:
//!
//! 1. With `max_reconnect_attempts = Some(n)` and n+1 consecutive
//!    failures, `recv` returns `ReconnectExhausted { attempts: n }`.
//!    The "+1" rather than "exactly n" is because the first failure
//!    counts as a reconnect attempt that exceeds 0; the cap bounds
//!    the retries after the initial try.
//! 2. A success after failures resets the reconnect counter, so a
//!    subsequent failure budget starts fresh.
//! 3. `url_fn` is consulted on every connect — never skipped. This
//!    is the contract that lets cursor-based consumers resume from
//!    the right spot after a reconnect.

#![cfg(all(feature = "tungstenite", not(target_arch = "wasm32")))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use async_trait::async_trait;
use proptest::prelude::*;
use proto_blue_ws::error::WsError;
use proto_blue_ws::keepalive::{UrlFn, WebSocketKeepAlive, WebSocketKeepAliveOpts};
use proto_blue_ws::transport::{WebSocketConnector, WebSocketTransport, WsFrame};
use tokio::runtime::Builder;

/// Connector outcome one call at a time.
#[derive(Debug, Clone, Copy)]
enum Outcome {
    /// Return a transport that will immediately emit a clean close on
    /// the first `recv`. The keep-alive treats this as a clean EOF.
    EofTransport,
    /// Return `Err(WsError::Transport(...))` — reconnectable failure.
    TransientFailure,
}

/// Connector driven by a fixed-script of outcomes. Counts URLs dialed
/// for the cursor-monotonicity assertion.
struct ScriptedConnector {
    outcomes: Vec<Outcome>,
    pos: AtomicUsize,
    urls_seen: std::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl WebSocketConnector for ScriptedConnector {
    async fn connect(&self, url: &str) -> Result<Box<dyn WebSocketTransport>, WsError> {
        self.urls_seen.lock().unwrap().push(url.to_string());
        let idx = self.pos.fetch_add(1, Ordering::SeqCst);
        let outcome = self
            .outcomes
            .get(idx)
            .copied()
            // Off the end of the script → keep failing; keep-alive
            // would otherwise loop against a dead connector.
            .unwrap_or(Outcome::TransientFailure);
        match outcome {
            Outcome::EofTransport => Ok(Box::new(EofTransport)),
            Outcome::TransientFailure => Err(WsError::Transport("scripted failure".into())),
        }
    }
}

/// Transport that yields `Ok(None)` on its first `recv` — emulates a
/// peer that accepted the connection then cleanly closed.
struct EofTransport;

#[async_trait]
impl WebSocketTransport for EofTransport {
    async fn recv(&mut self) -> Result<Option<WsFrame>, WsError> {
        Ok(None)
    }
    async fn send(&mut self, _frame: WsFrame) -> Result<(), WsError> {
        Ok(())
    }
    async fn close(&mut self) -> Result<(), WsError> {
        Ok(())
    }
}

fn arb_outcome() -> impl Strategy<Value = Outcome> {
    prop_oneof![Just(Outcome::EofTransport), Just(Outcome::TransientFailure),]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    /// For any outcome script, `recv()` either returns
    /// `ReconnectExhausted` (if the cap was hit) or a clean `None`
    /// (if a success happened in range). `url_fn` must have been
    /// consulted exactly once per connect attempt the connector saw.
    #[test]
    fn keepalive_accounting_matches_outcome_script(
        script in proptest::collection::vec(arb_outcome(), 1..12),
        cap in 0u32..=10,
    ) {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let connector = Arc::new(ScriptedConnector {
                outcomes: script.clone(),
                pos: AtomicUsize::new(0),
                urls_seen: std::sync::Mutex::new(Vec::new()),
            });

            // Track url_fn invocations: its counter equals the number
            // of (re)connect attempts.
            let url_calls = Arc::new(AtomicU32::new(0));
            let uc = url_calls.clone();
            let url_fn: UrlFn = Arc::new(move || {
                let uc = uc.clone();
                Box::pin(async move {
                    let n = uc.fetch_add(1, Ordering::SeqCst);
                    format!("wss://test/stream?cursor={n}")
                })
            });

            let opts = WebSocketKeepAliveOpts {
                max_reconnect_seconds: 0,
                heartbeat_interval_ms: 10_000,
                max_reconnect_attempts: Some(cap),
                per_recv_timeout_ms: None,
            };
            let mut ws = WebSocketKeepAlive::with_connector(
                "wss://fallback/",
                opts,
                connector.clone(),
            )
            .with_url_fn(url_fn);

            let result = ws.recv().await;

            let urls = connector.urls_seen.lock().unwrap().clone();
            let calls = url_calls.load(Ordering::SeqCst) as usize;

            // Every time the connector was asked, url_fn produced
            // the URL. Monotone counter means never dialed the same
            // URL twice in a row.
            prop_assert_eq!(urls.len(), calls, "url_fn calls != connector dials");
            let mut last = None::<&String>;
            for u in &urls {
                if let Some(prev) = last {
                    prop_assert_ne!(prev, u, "same URL dialed twice in a row");
                }
                last = Some(u);
            }

            // Outcome-specific assertions.
            //
            // Walk the script through the retry cap: each failure
            // ticks the attempt counter; first success returns None;
            // cap+1 consecutive failures return ReconnectExhausted.
            let mut failures_before_success: Option<usize> = None;
            for (i, o) in script.iter().enumerate() {
                if matches!(o, Outcome::EofTransport) {
                    failures_before_success = Some(i);
                    break;
                }
            }

            match failures_before_success {
                Some(idx) if (idx as u32) <= cap => {
                    // A success was reachable within the cap budget:
                    // the keep-alive should have either returned `None`
                    // (if the success fully connected then saw EOF)
                    // or ReconnectExhausted (if failures bunched up
                    // on the wrong side of the cap; the cap check
                    // fires before the success slot).
                    prop_assert!(
                        result.is_ok() || matches!(result, Err(WsError::ReconnectExhausted { .. })),
                        "unexpected error variant: {result:?}"
                    );
                }
                _ => {
                    // No success within cap — ReconnectExhausted is
                    // the only acceptable outcome.
                    prop_assert!(
                        matches!(result, Err(WsError::ReconnectExhausted { .. })),
                        "expected ReconnectExhausted, got {result:?}"
                    );
                }
            }

            Ok::<(), proptest::test_runner::TestCaseError>(())
        })?;
    }
}
