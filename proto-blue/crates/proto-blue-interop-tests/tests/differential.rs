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
use serde_json::json;

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

// ─────────────────────────────────────────────────────────────────────
// @atproto/common-web
// ─────────────────────────────────────────────────────────────────────

/// TID string form must match byte-for-byte across implementations:
/// atproto implementations sort repos by TID lexicographically, so
/// any drift produces a repo that the other side orders differently.
#[test]
fn differential_tid_from_time() {
    require_ts_runner!();
    let mut ts = runner();
    // Cover the realistic TID timestamp range: post-2005 micros-
    // since-epoch (above 32^10 ≈ 1.1e15), where both sides agree.
    // Below that, TS's `s32encode` produces a < 11-char timestamp
    // portion which its own validator then rejects — a known TS
    // corner-case bug we don't emulate.
    let cases = [
        (1_700_000_000_000_000u64, 0u16),    // ~2023, min clockid
        (1_700_000_000_000_000u64, 1023u16), // ~2023, max clockid
        (2_000_000_000_000_000u64, 42u16),   // ~2033
        (8_640_000_000_000_000u64, 500u16),  // year 2243
    ];
    for (ts_us, clockid) in cases {
        let rust = proto_blue_syntax::Tid::from_timestamp(ts_us, clockid).to_string();
        let ts_val: String = ts
            .call(
                "tid_from_time",
                json!({"timestamp_us": ts_us, "clockid": clockid}),
            )
            .into_ok();
        assert_eq!(
            rust, ts_val,
            "TID from ts={ts_us} clockid={clockid} diverges"
        );
    }
}

/// The accept/reject decision of `Tid::is_valid(s)` must agree with
/// the TS `TID.is(s)` classifier on well-formed inputs.
///
/// Limitation: TS `TID.is` is a length-only check
/// (`dedash(s).length === 13`) — it accepts uppercase letters and
/// punctuation that our Rust validator correctly rejects per the
/// base32-sortable charset. So the corpus here restricts to
/// length-varying cases (TS's sole axis of discrimination) within
/// the valid character set.
#[test]
fn differential_tid_is_valid() {
    require_ts_runner!();
    let mut ts = runner();
    let cases = [
        "3k2vzkz2z2z2a",  // valid shape — both should accept
        "3k2vzkz2z2z2",   // 12 chars — both should reject
        "3k2vzkz2z2z2aa", // 14 chars — both should reject
        "",               // empty — both should reject
    ];
    for input in cases {
        let rust = proto_blue_syntax::Tid::is_valid(input);
        let ts_val: bool = ts.call("tid_from_str", input).into_ok();
        assert_eq!(rust, ts_val, "Tid::is_valid diverges on {input:?}");
    }
}

/// Base32-sortable integer encoding round-trip. Used by TID
/// generation (the clock-id suffix) — any drift here silently
/// produces TIDs that sort differently on the two sides.
#[test]
fn differential_s32_encode() {
    require_ts_runner!();
    let mut ts = runner();
    for n in [0u64, 1, 31, 32, 1023, 1024, 1_000_000, u32::MAX as u64] {
        let rust = proto_blue_common::s32_encode(n);
        let ts_val: String = ts.call("s32_encode", n).into_ok();
        assert_eq!(rust, ts_val, "s32_encode({n}) diverges");
    }
}

#[test]
fn differential_s32_decode() {
    require_ts_runner!();
    let mut ts = runner();
    // Known-good shapes covering small / medium / large cases.
    for s in ["", "a", "g3t", "zzzz", "3k2vz"] {
        let rust = proto_blue_common::s32_decode(s);
        let ts_val: u64 = ts.call("s32_decode", s).into_ok();
        assert_eq!(rust, ts_val, "s32_decode({s:?}) diverges");
    }
}

/// Grapheme counting must agree. The Bluesky post length limit is
/// measured in graphemes, so off-by-one drift produces posts that
/// one side says fits and the other rejects.
#[test]
fn differential_grapheme_len() {
    require_ts_runner!();
    let mut ts = runner();
    let cases = [
        "",
        "hello",
        "héllo",
        "🚀",
        "héllo🚀world",
        "👨‍👩‍👧‍👦", // ZWJ family — one grapheme, multiple codepoints
        "🇺🇸", // flag — one grapheme, two regional-indicator codepoints
    ];
    for input in cases {
        let rust = proto_blue_common::grapheme_len(input);
        let ts_val: u64 = ts.call("grapheme_len", input).into_ok();
        assert_eq!(rust as u64, ts_val, "grapheme_len({input:?}) diverges");
    }
}

/// `getPdsEndpoint` on DID documents is how every handle-to-PDS
/// resolution path terminates. A drift here breaks authentication
/// and record reads for affected DIDs.
#[test]
fn differential_get_pds_endpoint() {
    require_ts_runner!();
    let mut ts = runner();

    // Use a real-looking DID doc with the standard `#atproto_pds`
    // service entry, and one without, and one with a malformed URL.
    let cases = [
        json!({
            "id": "did:plc:aaaabbbbccccddddeeeeffff",
            "alsoKnownAs": ["at://alice.test"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com",
            }],
        }),
        json!({
            "id": "did:plc:zzzz",
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": [],
        }),
    ];
    for doc_json in cases {
        let rust_doc: proto_blue_common::DidDocument =
            serde_json::from_value(doc_json.clone()).expect("parse DID doc");
        let rust = proto_blue_common::get_pds_endpoint(&rust_doc);
        let ts_val: Option<String> = ts.call("get_pds_endpoint", &doc_json).into_ok();
        assert_eq!(rust, ts_val, "get_pds_endpoint diverges on {doc_json:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// @atproto/crypto
// ─────────────────────────────────────────────────────────────────────

/// `did:key:` parsing — one of the most security-critical paths in
/// the SDK: a drift in how we decode a DID key produces signatures
/// that verify on one side and fail on the other. Covers both
/// P-256 and secp256k1 multikey formats.
#[test]
fn differential_did_key_parse() {
    require_ts_runner!();
    let mut ts = runner();

    #[derive(Deserialize)]
    struct TsParsed {
        #[serde(rename = "jwtAlg")]
        jwt_alg: String,
        key_hex: String,
    }

    // Canonical examples from the atproto spec tests — one per alg.
    let cases = [
        // secp256k1 (65-byte uncompressed pubkey)
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        // P-256 (65-byte uncompressed pubkey)
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    ];
    for did in cases {
        let rust = proto_blue_crypto::parse_did_key(did).expect("rust parse_did_key");
        let ts_val: TsParsed = ts.call("did_key_parse", did).into_ok();

        assert_eq!(rust.jwt_alg, ts_val.jwt_alg, "jwtAlg diverges on {did}");
        assert_eq!(
            hex::encode(&rust.key_bytes),
            ts_val.key_hex,
            "uncompressed pubkey bytes diverge on {did}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// @atproto/lexicon
// ─────────────────────────────────────────────────────────────────────

/// Lexicon validation on the same record against the same schema on
/// both sides. Highest-interop-value diff: drift here means apps
/// built with TS write records that our Rust validator rejects (or
/// vice versa).
#[test]
fn differential_lexicon_validate_record() {
    require_ts_runner!();
    let mut ts = runner();

    // A small synthetic lexicon with a required string field and an
    // optional integer with min/max. Doesn't need to match a real
    // Bluesky lexicon — the point is exercising the shared
    // validator rules on common shapes.
    let lexicon = json!({
        "lexicon": 1,
        "id": "example.test.widget",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "maxLength": 64},
                        "count": {"type": "integer", "minimum": 0, "maximum": 100}
                    }
                }
            }
        }
    });

    #[derive(Debug, Deserialize)]
    struct TsValidate {
        valid: bool,
        #[serde(default)]
        #[allow(dead_code)]
        error: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        message: Option<String>,
    }

    let cases = [
        (
            "valid minimal",
            json!({"$type": "example.test.widget", "name": "ok"}),
        ),
        (
            "valid with count",
            json!({"$type": "example.test.widget", "name": "ok", "count": 42}),
        ),
        (
            "missing required name",
            json!({"$type": "example.test.widget", "count": 5}),
        ),
        (
            "count above max",
            json!({"$type": "example.test.widget", "name": "ok", "count": 500}),
        ),
        (
            "count below min",
            json!({"$type": "example.test.widget", "name": "ok", "count": -1}),
        ),
        (
            "name too long",
            json!({
                "$type": "example.test.widget",
                "name": "x".repeat(200),
            }),
        ),
        (
            "wrong type for count",
            json!({"$type": "example.test.widget", "name": "ok", "count": "not a number"}),
        ),
    ];

    // Build the Rust Lexicons once.
    let lex_doc: proto_blue_lexicon::types::LexiconDoc =
        serde_json::from_value(lexicon.clone()).expect("parse lexicon doc");
    let mut rust_lexicons = proto_blue_lexicon::Lexicons::new();
    rust_lexicons.add(lex_doc).expect("add lexicon doc");
    let rec_def = rust_lexicons
        .get_def("example.test.widget")
        .expect("fetch main def");
    let proto_blue_lexicon::types::LexUserType::Record(record_def) = rec_def else {
        panic!("main def is not a record");
    };
    let record_def = record_def.clone();

    for (name, record) in &cases {
        let rust_val: proto_blue_lex_data::LexValue = proto_blue_lex_json::json_to_lex(record);
        let rust_result =
            proto_blue_lexicon::validate_record(&rust_lexicons, &record_def, &rust_val);
        let rust_valid = rust_result.is_ok();

        let ts_val: TsValidate = ts
            .call(
                "lexicon_validate_record",
                json!({
                    "lexicons": [lexicon],
                    "record_type": "example.test.widget",
                    "record": record,
                }),
            )
            .into_ok();

        assert_eq!(
            rust_valid,
            ts_val.valid,
            "case {name:?}: rust_valid={rust_valid} (err={:?}) vs ts_valid={}",
            rust_result.err(),
            ts_val.valid
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Known divergences — tests that assert the CURRENT state of the
// disagreements with the TS SDK (spec-strictness wins on our side).
//
// If any of these tests flip to passing, the TS SDK has tightened its
// validator to match the spec — time to relax our corpus exclusions
// in the main differential tests above and remove the exceptions
// from README.md. See "Known TS SDK divergences" in the README for
// the full writeup of why each case exists.
// ─────────────────────────────────────────────────────────────────────

/// TS `TID.is(str)` is a length-only check; it accepts any 13-char
/// string. Our `Tid::is_valid` enforces the base32-sortable charset
/// per the spec.
#[test]
fn divergence_ts_tid_is_ignores_charset() {
    require_ts_runner!();
    let mut ts = runner();
    // Upper-case, punctuation, whitespace — all 13 chars long.
    let not_tids = [
        "AAAAAAAAAAAAA",
        "!!!!!!!!!!!!!",
        "             ",
        "ABCDEFGHIJKLM",
    ];
    for s in not_tids {
        assert!(
            !proto_blue_syntax::Tid::is_valid(s),
            "Rust correctly rejects {s:?}"
        );
        let ts_accepts: bool = ts.call("tid_from_str", s).into_ok();
        assert!(
            ts_accepts,
            "TS is expected to (erroneously) accept {s:?}; \
             if this flips, TS fixed their length-only check — \
             update README.md and corpora in `differential_tid_is_valid`"
        );
    }
}

/// TS `TID.fromTime` doesn't pad the timestamp portion. For small
/// timestamps (below `32^10 ≈ 1.1e15 μs`, i.e. pre-November 2004),
/// output is fewer than 13 chars, which its own validator rejects.
///
/// Our Rust `Tid::from_timestamp` always produces a 13-char string.
#[test]
fn divergence_ts_tid_from_time_unpadded_for_small_timestamps() {
    require_ts_runner!();
    let mut ts = runner();
    let small_timestamp = 1_000u64;
    let clockid = 0u16;

    // Rust produces a valid 13-char TID regardless.
    let rust = proto_blue_syntax::Tid::from_timestamp(small_timestamp, clockid).to_string();
    assert_eq!(rust.len(), 13, "Rust pads to 13 chars");
    assert!(
        proto_blue_syntax::Tid::is_valid(&rust),
        "Rust output validates"
    );

    // TS produces output shorter than 13 chars, which its own
    // constructor throws on.
    let ts_result: TsResult<String> = ts.call(
        "tid_from_time",
        json!({"timestamp_us": small_timestamp, "clockid": clockid}),
    );
    assert!(
        !ts_result.is_ok(),
        "TS is expected to throw on small timestamps; \
         if this flips, TS fixed their padding — update the \
         realistic-range corpus in `differential_tid_from_time` \
         to extend down to timestamp=0"
    );
}

/// TS `new AtUri()` accepts fragments that don't start with `/`.
/// The spec requires JSON Pointer format (leading `/`). Our Rust
/// regex enforces the spec.
#[test]
fn divergence_ts_aturi_accepts_non_json_pointer_fragment() {
    require_ts_runner!();
    let mut ts = runner();
    // `#foo` is not a JSON Pointer. TS accepts it; we reject.
    let input = "at://did:plc:abc/app.bsky.feed.post/123#foo";

    assert!(
        proto_blue_syntax::AtUri::new(input).is_err(),
        "Rust correctly rejects non-JSON-pointer fragment {input:?}"
    );

    let ts_result: TsResult<serde_json::Value> = ts.call("aturi_components", input);
    assert!(
        ts_result.is_ok(),
        "TS is expected to (erroneously) accept {input:?}; \
         if this flips, TS tightened their AT-URI parser — \
         update the corpus in `differential_aturi_components` \
         and the README divergence list"
    );
}

// ── DAG-CBOR encode / CID computation parity (#10) ──────────────────
//
// Feeds the same `LexValue` to both impls — Rust via
// `proto_blue_lex_cbor::encode`, TS via `@atproto/common::cborEncode`
// after rebuilding the IPLD value from a tagged-enum JSON wire format.
// Asserts byte-exact equivalence on encoded bytes AND CID derivation.
//
// The wire format is a deliberate domain-specific encoding (NOT
// proto-blue-lex-json's $link/$bytes shape) — using lex-json would
// couple the parity test to lex-json's own correctness, hiding bugs.
// See `lexValueJsonToIpld` in ts-runner/index.mjs for the receiver.

use proto_blue_lex_data::{Cid, LexValue};
use serde_json::Value;
use std::collections::BTreeMap;

/// Convert a `LexValue` to its wire-format JSON representation.
fn lex_value_to_wire(v: &LexValue) -> Value {
    match v {
        LexValue::Null => json!({"t": "null"}),
        LexValue::Bool(b) => json!({"t": "bool", "v": b}),
        LexValue::Integer(n) => json!({"t": "int", "v": n}),
        LexValue::String(s) => json!({"t": "str", "v": s}),
        LexValue::Bytes(b) => json!({"t": "bytes", "hex": hex::encode(b)}),
        LexValue::Cid(c) => json!({"t": "cid", "s": c.to_string()}),
        LexValue::Array(arr) => {
            let items: Vec<Value> = arr.iter().map(lex_value_to_wire).collect();
            json!({"t": "arr", "v": items})
        }
        LexValue::Map(map) => {
            // Send entries in BTreeMap iteration order (which is
            // bytewise-lex sorted, NOT length-then-lex). The encoder
            // on each side re-sorts per dag-cbor rules — that's
            // exactly what we're testing parity on.
            let entries: Vec<Value> = map
                .iter()
                .map(|(k, v)| json!([k, lex_value_to_wire(v)]))
                .collect();
            json!({"t": "map", "v": entries})
        }
    }
}

/// Adversarial corpus — each value is engineered to hit a distinct
/// dag-cbor wire encoding edge case. Add to this list when a real-world
/// regression is found that a current fixture wouldn't have caught.
fn cbor_parity_corpus() -> Vec<(&'static str, LexValue)> {
    let mut large_map = BTreeMap::new();
    // Same-length keys to exercise lexicographic-byte tiebreak.
    large_map.insert("aaa".into(), LexValue::Integer(1));
    large_map.insert("abc".into(), LexValue::Integer(2));
    large_map.insert("aab".into(), LexValue::Integer(3));
    // Different-length keys — dag-cbor sorts shorter first.
    large_map.insert("z".into(), LexValue::Integer(4));
    large_map.insert("zz".into(), LexValue::Integer(5));
    large_map.insert("zzz".into(), LexValue::Integer(6));
    // Multi-byte UTF-8 key (sorted bytewise, not codepoint-wise).
    large_map.insert("é".into(), LexValue::Integer(7));

    let mut nested_map = BTreeMap::new();
    nested_map.insert("inner".into(), LexValue::Bool(true));
    let mut outer_map = BTreeMap::new();
    outer_map.insert("a".into(), LexValue::Map(nested_map));
    outer_map.insert("b".into(), LexValue::Array(vec![LexValue::Integer(0)]));

    let cid_a: Cid = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"
        .parse()
        .unwrap();

    vec![
        ("null", LexValue::Null),
        ("true", LexValue::Bool(true)),
        ("false", LexValue::Bool(false)),
        ("zero", LexValue::Integer(0)),
        ("one", LexValue::Integer(1)),
        ("neg_one", LexValue::Integer(-1)),
        // CBOR major-type-0/1 boundary cases.
        ("twentythree", LexValue::Integer(23)),
        ("twentyfour", LexValue::Integer(24)),
        ("u8_max", LexValue::Integer(255)),
        ("u8_max_plus_one", LexValue::Integer(256)),
        ("u16_max", LexValue::Integer(65_535)),
        ("u32_max", LexValue::Integer(4_294_967_295)),
        // Cap integers at the JS-safe range. JSON has no native i64
        // representation — values outside [-(2^53-1), 2^53-1] lose
        // precision passing through the JSON wire format and would
        // arrive on the TS side as floats, producing a spurious
        // codec divergence. A future enhancement could carry large
        // ints as strings/BigInt; for the dag-cbor parity check we
        // just stay inside the lossless JSON range. The Rust-only
        // integer-encoding tests in `proto-blue-lex-cbor` cover
        // i64::MAX / i64::MIN.
        ("safe_pos_max", LexValue::Integer((1i64 << 53) - 1)),
        ("safe_neg_max", LexValue::Integer(-((1i64 << 53) - 1))),
        ("empty_string", LexValue::String(String::new())),
        ("ascii", LexValue::String("hello".into())),
        ("emoji", LexValue::String("hi 🚀 there".into())),
        ("empty_bytes", LexValue::Bytes(Vec::new())),
        ("short_bytes", LexValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
        ("long_bytes", LexValue::Bytes(vec![0x42; 300])), // crosses 24-byte and 256-byte CBOR length thresholds
        ("cid", LexValue::Cid(cid_a.clone())),
        ("empty_arr", LexValue::Array(Vec::new())),
        ("empty_map", LexValue::Map(BTreeMap::new())),
        ("map_sort_edges", LexValue::Map(large_map)),
        ("nested_map", LexValue::Map(outer_map)),
        (
            "deep_nest",
            LexValue::Array(vec![LexValue::Array(vec![LexValue::Array(vec![
                LexValue::Integer(42),
            ])])]),
        ),
    ]
}

/// Wire-byte parity for `proto_blue_lex_cbor::encode` vs
/// `@atproto/common::cborEncode`. Hex strings must match exactly.
#[test]
fn differential_dag_cbor_encode() {
    require_ts_runner!();
    let mut ts = runner();

    for (name, val) in cbor_parity_corpus() {
        let rust_bytes = proto_blue_lex_cbor::encode(&val)
            .unwrap_or_else(|e| panic!("Rust encode({name}) failed: {e:?}"));
        let rust_hex = hex::encode(&rust_bytes);

        let wire = lex_value_to_wire(&val);
        let ts_response: TsResult<serde_json::Value> = ts.call("cbor_encode_lexvalue", wire);
        let ts_hex = ts_response
            .into_ok()
            .get("hex")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("TS cbor_encode_lexvalue({name}) returned no hex field"))
            .to_string();

        assert_eq!(
            rust_hex, ts_hex,
            "dag-cbor encode divergence on fixture {name:?}: \
             Rust produced {rust_hex}, TS produced {ts_hex}"
        );
    }
}

/// CID derivation parity — encode the same LexValue, hash, multibase-encode
/// the result. Same fixtures as `differential_dag_cbor_encode`; if encode
/// parity holds then CID parity is automatic, but a separate test catches
/// any divergence in the post-hash multibase / multihash framing.
#[test]
fn differential_cid_for_lexvalue() {
    require_ts_runner!();
    let mut ts = runner();

    for (name, val) in cbor_parity_corpus() {
        let rust_cid = proto_blue_lex_cbor::cid_for_lex(&val)
            .unwrap_or_else(|e| panic!("Rust cid_for_lex({name}) failed: {e:?}"));
        let rust_str = rust_cid.to_string();

        let wire = lex_value_to_wire(&val);
        let ts_response: TsResult<serde_json::Value> = ts.call("cid_for_lexvalue", wire);
        let ts_str = ts_response
            .into_ok()
            .get("cid")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("TS cid_for_lexvalue({name}) returned no cid field"))
            .to_string();

        assert_eq!(
            rust_str, ts_str,
            "CID derivation divergence on fixture {name:?}: \
             Rust produced {rust_str}, TS produced {ts_str}"
        );
    }
}
