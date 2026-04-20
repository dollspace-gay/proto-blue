//! Differential tests against the `@atproto/syntax` TypeScript SDK.
//!
//! Each `#[test]` drives our Rust parser and the TS reference
//! implementation on the same fixture corpus and asserts the outputs
//! match. The TS side runs as a long-lived subprocess
//! (`ts-runner/index.mjs`) spoken to over line-delimited JSON.
//!
//! Gated on the `TS_RUNNER_READY` env var — running `cargo test
//! -p proto-blue-interop-tests` without installing the TS deps is a
//! no-op, so a fresh clone builds and tests clean without Node.js.
//! The CI job runs `npm ci` in `ts-runner/` first and sets
//! `TS_RUNNER_READY=1`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

/// Skip the test with an explanatory printout when the TS runner
/// isn't available. Keeps `cargo test` green on fresh clones while
/// giving CI a clear signal that it should have installed deps.
macro_rules! require_ts_runner {
    () => {
        if std::env::var("TS_RUNNER_READY").is_err() {
            eprintln!(
                "skipping — set TS_RUNNER_READY=1 after running \
                 `npm ci` in crates/proto-blue-interop-tests/ts-runner/"
            );
            return;
        }
    };
}

/// Process-wide shared runner. cargo test runs test fns in parallel
/// threads, and spawning four Node subprocesses at once turned out to
/// hang the harness (observed: stdin/stdout pipes wedge with all four
/// workers blocked on `read_line`). Gating every exchange behind a
/// single `Mutex<TsRunner>` serializes them and incidentally avoids
/// paying Node's 70ms cold start four times over.
fn runner() -> MutexGuard<'static, TsRunner> {
    static RUNNER: OnceLock<Mutex<TsRunner>> = OnceLock::new();
    RUNNER
        .get_or_init(|| Mutex::new(TsRunner::spawn()))
        .lock()
        .unwrap_or_else(|poison| {
            // A prior test poisoned the mutex — recover the inner
            // runner and keep going; the next request will surface
            // whatever failure the poisoner hit.
            poison.into_inner()
        })
}

/// Long-lived handle to the TS subprocess. Drop closes stdin, which
/// makes the Node process exit cleanly.
struct TsRunner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl TsRunner {
    fn spawn() -> Self {
        let runner_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ts-runner");
        let mut child = Command::new("node")
            .arg("index.mjs")
            .current_dir(&runner_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Pipe stderr instead of inheriting. With `inherit`,
            // multiple test binaries writing to a captured stderr
            // (cargo test's default) can deadlock — the OS pipe
            // backing that capture fills up and the child blocks on
            // its stderr write while we're blocked on its stdout read.
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn node ts-runner — is node on PATH?");
        let stdin = child.stdin.take().expect("child has stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child has stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    /// Send one request, read one response. Serializes to a single
    /// JSON line (`\n`-terminated), which is the runner's input protocol.
    fn call<T: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        op: &str,
        input: T,
    ) -> TsResult<R> {
        let req = serde_json::json!({ "op": op, "input": input });
        let line = serde_json::to_string(&req).expect("serialize request");
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .expect("write request to ts-runner stdin");

        let mut response = String::new();
        let n = self
            .stdout
            .read_line(&mut response)
            .expect("read response from ts-runner stdout");
        assert!(
            n > 0,
            "ts-runner closed stdout unexpectedly — likely crashed before replying"
        );
        serde_json::from_str(&response)
            .unwrap_or_else(|e| panic!("parse ts-runner response {response:?}: {e}"))
    }
}

impl Drop for TsRunner {
    fn drop(&mut self) {
        // Closing stdin lets the runner's readline loop finish; then
        // wait so we don't leave a zombie.
        let _ = self.child.wait();
    }
}

/// Response envelope matching the runner's output protocol.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TsResult<T> {
    Ok { value: T },
    Err { error: String, message: String },
}

impl<T> TsResult<T> {
    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
    fn into_ok(self) -> T {
        match self {
            Self::Ok { value } => value,
            Self::Err { error, message } => {
                panic!("expected TS Ok, got Err {error}: {message}")
            }
        }
    }
}

// ── Fixture corpora ──────────────────────────────────────────────────
//
// Tiny inline corpora for the initial landing; larger JSON-file
// corpora can move under `fixtures/<op>/*.json` later.

fn handle_corpus() -> &'static [&'static str] {
    &[
        "alice.bsky.social",
        "ALICE.BSKY.SOCIAL",
        "Bob.Test",
        "  padded.example.com  ",
        "emoji🚀.test",
        "no-dot",
        "",
    ]
}

fn nsid_corpus() -> &'static [&'static str] {
    &[
        "app.bsky.feed.post",
        "com.atproto.repo.createRecord",
        "APP.bsky.feed.post", // upper-case authority segment — invalid
        "app.bsky",           // too few segments
        "app..bsky.feed",     // empty segment
        "",
    ]
}

fn aturi_corpus() -> &'static [&'static str] {
    &[
        "at://did:plc:abc/app.bsky.feed.post/123",
        "at://alice.bsky.social/app.bsky.feed.post/xyz",
        // Our Rust parser enforces the spec's requirement that
        // fragments be JSON Pointers (leading `/`); the `@atproto/
        // syntax` TS parser accepts any fragment string. Test only
        // the spec-compliant case here; the divergence on `#frag`
        // (no slash) is tracked separately.
        "at://did:plc:abc/app.bsky.feed.post/123#/text",
        "at://did:plc:abc",
        "not a uri",
    ]
}

// ── normalize_handle ────────────────────────────────────────────────

#[test]
fn differential_normalize_handle() {
    require_ts_runner!();
    let mut ts = runner();
    for input in handle_corpus() {
        let rust = proto_blue_syntax::normalize_handle(input);
        let ts_val: String = ts.call("normalize_handle", input).into_ok();
        assert_eq!(
            rust, ts_val,
            "normalize_handle divergence on input {input:?}"
        );
    }
}

// ── is_valid_handle ─────────────────────────────────────────────────

#[test]
fn differential_is_valid_handle() {
    require_ts_runner!();
    let mut ts = runner();
    for input in handle_corpus() {
        let rust = proto_blue_syntax::Handle::new(input).is_ok();
        let ts_val: bool = ts.call("is_valid_handle", input).into_ok();
        assert_eq!(
            rust, ts_val,
            "is_valid_handle divergence on input {input:?}"
        );
    }
}

// ── nsid_is_valid ───────────────────────────────────────────────────

#[test]
fn differential_nsid_is_valid() {
    require_ts_runner!();
    let mut ts = runner();
    for input in nsid_corpus() {
        let rust = proto_blue_syntax::Nsid::new(input).is_ok();
        let ts_val: bool = ts.call("nsid_is_valid", input).into_ok();
        assert_eq!(rust, ts_val, "nsid_is_valid divergence on input {input:?}");
    }
}

// ── aturi_components ────────────────────────────────────────────────

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct AtUriComponents {
    authority: String,
    collection: Option<String>,
    rkey: Option<String>,
    fragment: Option<String>,
}

#[test]
fn differential_aturi_components() {
    require_ts_runner!();
    let mut ts = runner();
    for input in aturi_corpus() {
        let rust_parsed = proto_blue_syntax::AtUri::new(input);
        let ts_parsed: TsResult<AtUriComponents> = ts.call("aturi_components", input);

        // Both sides must agree on accept/reject decisions first.
        assert_eq!(
            rust_parsed.is_ok(),
            ts_parsed.is_ok(),
            "accept/reject divergence on AT-URI {input:?}: rust={:?}, ts_ok={}",
            rust_parsed.is_err(),
            ts_parsed.is_ok()
        );

        if let (
            Ok(rust_uri),
            TsResult::Ok {
                value: ts_components,
            },
        ) = (rust_parsed, ts_parsed)
        {
            let rust_components = AtUriComponents {
                authority: rust_uri.authority().to_string(),
                collection: rust_uri.collection().map(str::to_string),
                rkey: rust_uri.rkey().map(str::to_string),
                // TS's `hash` includes the leading `#`; strip so the
                // two representations line up. (Our `fragment()`
                // returns the content without the `#` prefix.)
                fragment: ts_components
                    .fragment
                    .as_ref()
                    .map(|s| s.strip_prefix('#').unwrap_or(s).to_string())
                    .filter(|s| !s.is_empty()),
            };
            let expected = AtUriComponents {
                fragment: rust_uri.fragment().map(str::to_string),
                ..rust_components
            };
            assert_eq!(
                expected,
                AtUriComponents {
                    authority: ts_components.authority,
                    collection: ts_components.collection,
                    rkey: ts_components.rkey,
                    fragment: ts_components
                        .fragment
                        .as_ref()
                        .map(|s| s.strip_prefix('#').unwrap_or(s).to_string())
                        .filter(|s| !s.is_empty()),
                },
                "AT-URI component divergence on {input:?}"
            );
        }
    }
}
