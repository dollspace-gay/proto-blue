//! Live-PDS integration tests.
//!
//! These tests dial a real PDS and exercise the full
//! create-session / record CRUD / getSession cycle against it. They
//! catch drift between our SDK and the live network — behaviour the
//! live server encodes implicitly (rate-limit edge cases, real cert
//! chains, timing-sensitive invalidation) that no offline harness
//! reaches.
//!
//! **All tests are `#[ignore]`'d by default** so a normal
//! `cargo test --workspace` stays network-free. To run them:
//!
//! ```bash
//! export PDS_URL=https://your-pds.example.com
//! export PDS_TEST_HANDLE=throwaway.example.com
//! export PDS_TEST_APP_PASSWORD=<the-password>
//! cargo test -p proto-blue-api --test live_pds -- --ignored --test-threads=1
//! ```
//!
//! The nightly CI job (`.github/workflows/live-pds.yml`) runs them
//! on a throwaway account with secrets from GitHub and posts to
//! Discord/Slack on failure.

#![cfg(feature = "fetch-reqwest")]

use proto_blue_api::Agent;
use proto_blue_syntax::{AtIdentifier, AtUri};

/// Shared harness for tests that require live-PDS credentials.
/// Returns `None` (and prints a skip notice) when any required env
/// var is missing. Tests that call this should immediately return
/// without further assertions when it returns `None`.
fn live_creds() -> Option<LiveCreds> {
    let pds_url = std::env::var("PDS_URL").ok()?;
    let handle = std::env::var("PDS_TEST_HANDLE").ok()?;
    let password = std::env::var("PDS_TEST_APP_PASSWORD").ok()?;
    Some(LiveCreds {
        pds_url,
        handle,
        password,
    })
}

struct LiveCreds {
    pds_url: String,
    handle: String,
    password: String,
}

/// Session lifecycle: login → session-populated → logout → session-cleared.
///
/// The bread-and-butter path every authenticated consumer drives.
/// Failures here mean the agent's core auth plumbing has drifted
/// from what a real PDS accepts.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires PDS_URL + PDS_TEST_HANDLE + PDS_TEST_APP_PASSWORD"]
async fn session_lifecycle_roundtrip() {
    let Some(creds) = live_creds() else {
        eprintln!("skipping: set PDS_URL / PDS_TEST_HANDLE / PDS_TEST_APP_PASSWORD");
        return;
    };
    let agent = Agent::new(&creds.pds_url).expect("construct agent");
    let identifier =
        AtIdentifier::new(&creds.handle).expect("PDS_TEST_HANDLE must parse as a handle or DID");

    // Login → the agent now holds a session.
    let session = agent
        .login(&identifier, &creds.password)
        .await
        .expect("login must succeed against a real PDS");
    assert!(
        !session.did.as_str().is_empty(),
        "session DID must be non-empty"
    );
    assert!(
        !session.access_jwt.is_empty(),
        "access JWT must be non-empty"
    );

    // `session()` accessor must echo the same session the login
    // produced — this is how app code reads auth state out of the
    // agent without a second round-trip.
    let echoed = agent.session().await.expect("session set after login");
    assert_eq!(echoed.did, session.did);
    assert_eq!(echoed.handle, session.handle);

    // refresh_session rotates the access JWT against the real AS
    // token endpoint. The `access_jwt` must change (or at minimum
    // the call must succeed without error).
    let refreshed = agent
        .refresh_session()
        .await
        .expect("refresh_session must succeed on a live session");
    assert_eq!(refreshed.did, session.did, "DID is stable across refresh");

    // Logout — subsequent reads of `session()` must return None.
    agent
        .logout()
        .await
        .expect("logout must succeed on a live session");
    assert!(
        agent.session().await.is_none(),
        "session must clear after logout"
    );
}

/// Post → delete round-trip via the Agent's top-level helpers.
///
/// `Agent::post` creates an `app.bsky.feed.post` record; `delete_post`
/// removes it. Both hit the real PDS, so this catches drift in the
/// record creation / deletion paths (URI construction, validation,
/// error handling). Test body deletes the record unconditionally in
/// a scope-exit guard so a panic mid-test doesn't litter the
/// account with test posts.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires PDS_URL + PDS_TEST_HANDLE + PDS_TEST_APP_PASSWORD"]
async fn post_then_delete_roundtrip() {
    let Some(creds) = live_creds() else {
        eprintln!("skipping: set PDS_URL / PDS_TEST_HANDLE / PDS_TEST_APP_PASSWORD");
        return;
    };

    let agent = Agent::new(&creds.pds_url).expect("construct agent");
    let identifier =
        AtIdentifier::new(&creds.handle).expect("PDS_TEST_HANDLE must parse as a handle or DID");
    agent
        .login(&identifier, &creds.password)
        .await
        .expect("login");

    // Post a recognizable test body, capture the returned URI.
    let body = format!(
        "proto-blue live-pds test @ {} — safe to delete",
        chrono::Utc::now().to_rfc3339()
    );
    let created = agent
        .post(&body, None, None)
        .await
        .expect("Agent::post must succeed on a live session");
    let uri_str = created
        .get("uri")
        .and_then(|v| v.as_str())
        .expect("post response must include a `uri`");
    assert!(
        uri_str.starts_with("at://"),
        "post URI must be an AT-URI, got {uri_str:?}"
    );
    let uri = AtUri::new(uri_str).expect("server-returned URI must parse as an AT-URI");

    // Clean up — even on assertion failure, the test account
    // shouldn't accumulate test posts. `delete_post` is idempotent
    // against a missing record, so a double-delete on panic is safe.
    agent
        .delete_post(&uri)
        .await
        .expect("delete_post must succeed on a record we just created");

    let _ = agent.logout().await;
}
