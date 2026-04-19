//! Mock-HTTP helper used by the OAuth adversarial test suite.
//!
//! Spins up a one-shot `tokio::net::TcpListener` on `127.0.0.1:0`, captures
//! the first HTTP request that arrives, and replies with a canned status +
//! body. Same pattern as `proto-blue-xrpc/tests/adversarial.rs` — no
//! external mock-http dependency needed.
//!
//! Not a full HTTP server: chunked encoding, keep-alive, and HTTP/2 are
//! not implemented. All the OAuth flows we test are a single simple POST
//! or GET, which fits this model.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// A captured HTTP request.
#[derive(Default, Debug, Clone)]
pub struct Captured {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// A canned HTTP response the mock server will emit.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "application/json".to_string())],
            body: body.into(),
        }
    }

    pub fn text(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "text/plain".to_string())],
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

/// Spawn a server that answers a single request with `reply` and
/// returns `(base_url, captured_handle)`.
pub async fn spawn_oneshot(reply: Reply) -> (String, Arc<Mutex<Option<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let out = captured.clone();

    tokio::spawn(async move {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        loop {
            let n = match socket.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                if let Some(cl) = extract_content_length(&buf) {
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    while buf.len() < end + cl {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                }
                break;
            }
        }
        *out.lock().await = Some(parse_request(&buf));

        let mut resp = format!("HTTP/1.1 {} Mock\r\n", reply.status).into_bytes();
        for (k, v) in &reply.headers {
            resp.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        resp.extend_from_slice(format!("Content-Length: {}\r\n\r\n", reply.body.len()).as_bytes());
        resp.extend_from_slice(&reply.body);
        let _ = socket.write_all(&resp).await;
        let _ = socket.flush().await;
    });

    (format!("http://127.0.0.1:{port}"), captured)
}

/// Spawn a server that answers successive requests in order. After the
/// last reply the listener closes.
pub async fn spawn_sequence(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let out = captured.clone();

    tokio::spawn(async move {
        for reply in replies {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = Vec::with_capacity(4096);
            let mut tmp = [0u8; 4096];
            loop {
                let n = match socket.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if let Some(cl) = extract_content_length(&buf) {
                        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                        while buf.len() < end + cl {
                            let n = match socket.read(&mut tmp).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&tmp[..n]);
                        }
                    }
                    break;
                }
            }
            out.lock().await.push(parse_request(&buf));

            let mut resp = format!("HTTP/1.1 {} Mock\r\n", reply.status).into_bytes();
            for (k, v) in &reply.headers {
                resp.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            resp.extend_from_slice(
                format!("Content-Length: {}\r\n\r\n", reply.body.len()).as_bytes(),
            );
            resp.extend_from_slice(&reply.body);
            let _ = socket.write_all(&resp).await;
            let _ = socket.flush().await;
        }
    });

    (format!("http://127.0.0.1:{port}"), captured)
}

fn extract_content_length(buf: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn parse_request(buf: &[u8]) -> Captured {
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = std::str::from_utf8(&buf[..split]).unwrap_or("").to_string();
    let body = if buf.len() > split + 4 {
        buf[split + 4..].to_vec()
    } else {
        Vec::new()
    };

    let mut lines = head.lines();
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Captured {
        method,
        path,
        headers,
        body,
    }
}

/// Parse an `application/x-www-form-urlencoded` body into a map.
pub fn parse_form(bytes: &[u8]) -> HashMap<String, String> {
    let s = std::str::from_utf8(bytes).unwrap_or("").to_string();
    let mut out = HashMap::new();
    for pair in s.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            out.insert(url_decode(k), url_decode(v));
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(' '),
            b'%' => {
                let hi = bytes.next().and_then(|c| (c as char).to_digit(16));
                let lo = bytes.next().and_then(|c| (c as char).to_digit(16));
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h << 4 | l) as u8) as char);
                }
            }
            _ => out.push(b as char),
        }
    }
    out
}
