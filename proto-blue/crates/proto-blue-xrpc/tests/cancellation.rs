#![allow(clippy::pedantic, clippy::nursery)]

//! End-to-end proof that `proto_blue_common::cancellable` aborts an
//! in-flight `XrpcClient::query` call.
//!
//! The test spins up a mock server that accepts the TCP connection but
//! deliberately never responds. Without cancellation the client would
//! block forever; with cancellation, dropping the future via the
//! token closes the socket and returns `Err(CancelError::Cancelled)`
//! promptly.
//!
//! This is the smoke test for issue #21's acceptance criterion: a
//! caller holding a `CancellationToken` can stop an ongoing request
//! without mutating the request API.

use std::time::{Duration, Instant};

use proto_blue_common::{CancelError, CancellationToken, cancellable};
use proto_blue_xrpc::XrpcClient;
use tokio::net::TcpListener;

/// Bind a port, accept one connection, read what the client sends, and
/// then deliberately stall forever (never write a response, never
/// close). Perfect for verifying cancellation from the client side.
async fn spawn_stalling_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Accept a single connection, then hold it open forever.
        let (_socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        // Drop happens when the test ends, which closes the socket.
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });
    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn cancellable_aborts_in_flight_xrpc_query() {
    let base = spawn_stalling_server().await;
    let client = XrpcClient::new(&base).unwrap();

    let token = CancellationToken::new();
    let child = token.child_token();

    // Cancel shortly after the request is in flight.
    tokio::spawn({
        let t = token.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            t.cancel();
        }
    });

    let start = Instant::now();
    let outcome = cancellable(client.query("foo.bar.baz", None, None), &child).await;
    let elapsed = start.elapsed();

    // The cancellation must win — the server never replies.
    assert!(
        matches!(outcome, Err(CancelError::Cancelled)),
        "{outcome:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "cancellation should fire promptly, took {elapsed:?}"
    );
}

#[tokio::test]
async fn cancellable_passes_through_successful_xrpc_call() {
    // Server that actually responds — cancellable must not swallow the
    // success result just because a token was present.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 2048];
        let mut buf = Vec::new();
        loop {
            match socket.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let body = br#"{"ok":true}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(body).await;
        let _ = socket.flush().await;
    });
    let base = format!("http://127.0.0.1:{port}");
    let client = XrpcClient::new(&base).unwrap();

    let token = CancellationToken::new();
    let resp = cancellable(client.query("foo.bar.baz", None, None), &token)
        .await
        .unwrap();
    assert_eq!(resp.data["ok"], true);
}
