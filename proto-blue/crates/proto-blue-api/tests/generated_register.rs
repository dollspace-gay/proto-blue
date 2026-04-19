//! End-to-end smoke test for generated `register()` helpers.
//!
//! Spins up an `XrpcServer` with a typed handler registered via one
//! of the codegen-emitted `register` functions, dispatches an HTTP
//! request through axum, and asserts the typed output round-trips.

#![cfg(feature = "server")]

use std::time::Duration;

use proto_blue_api::com::atproto::server::get_session;

async fn spawn_server(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    format!("http://{addr}")
}

#[tokio::test]
async fn generated_register_wraps_typed_query_handler() {
    let server = proto_blue_xrpc::XrpcServer::new();
    let server = get_session::register(server, |_ctx| async move {
        Ok(get_session::Output {
            active: Some(true),
            did: "did:plc:generated".to_string(),
            did_doc: None,
            email: None,
            email_auth_factor: None,
            email_confirmed: None,
            handle: "alice.test".to_string(),
            status: None,
        })
    });

    let base = spawn_server(server.into_router()).await;
    let resp: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/xrpc/com.atproto.server.getSession"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["did"], "did:plc:generated");
    assert_eq!(resp["handle"], "alice.test");
    assert_eq!(resp["active"], true);
}
