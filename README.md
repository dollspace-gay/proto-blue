# proto-blue

> **Note:** This project was generated entirely by [Claude Opus 4.6](https://www.anthropic.com/claude) as a capability test and demonstration of its coding skills. The full SDK — 14 crates, ~390 tests, code generation, and OAuth implementation — was produced by the model with no human-written code.

A comprehensive Rust SDK for the [AT Protocol](https://atproto.com/) (Authenticated Transfer Protocol), the decentralized social networking protocol powering [Bluesky](https://bsky.app).

This is a faithful 1:1 translation of the official [TypeScript SDK](https://github.com/bluesky-social/atproto), organized as a Cargo workspace of 14 crates covering the full protocol stack — from low-level cryptography and CBOR encoding to high-level agent sessions and OAuth.

## Status

**v0.3.0** — Audit-driven hardening pass. All 14 SDK crates implemented and tested.

- Unit + property + doc tests across the workspace, plus `#[ignore]`'d
  live-PDS integration tests gated on env vars
- 368 generated type modules from 322 Lexicon schemas
- Zero `clippy` warnings, zero `unsafe` blocks
- Requires **Rust 1.88+** (edition 2024)

v0.3.0 lands the full external-audit response (11 closed sub-issues):
type-safe Agent surface using `proto-blue-syntax` newtypes,
`Cid::digest` widened to `[u8; 32]` (no per-CID heap allocation),
strict-mode CBOR rejecting all floats, and codegen now emits typed
newtypes for `format`-bearing strings, sum types for inline unions,
edition-2024 keyword escaping, and dash-segment / leaf-and-parent
NSID handling. New `proto-blue-interop-tests` crate runs a 28-fixture
differential dag-cbor + CID parity check against `@atproto/common`,
and `proto-blue-repo` gained 7 property tests + a fuzz target on the
proof pipeline. See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

> **Migration from 0.2.x:** Agent / Session / LabelerOpts public
> surfaces now take typed newtypes instead of `String`/`&str`. Wrap
> at the call site: `Did::new(s)?`, `Handle::new(s)?`,
> `AtIdentifier::new(s)?`. Wire format is unchanged.


| Crate | Description |
|-------|-------------|
| [`proto-blue-syntax`](crates/proto-blue-syntax) | Validated newtypes: `Did`, `Handle`, `Nsid`, `AtUri`, `Tid`, `RecordKey`, `Datetime` |
| [`proto-blue-crypto`](crates/proto-blue-crypto) | P-256/K-256 signing, `did:key` encoding, SHA-256 |
| [`proto-blue-lex-data`](crates/proto-blue-lex-data) | Core data model: `LexValue` enum, `Cid`, `BlobRef` |
| [`proto-blue-lex-cbor`](crates/proto-blue-lex-cbor) | DAG-CBOR encoding/decoding with CID tag 42 |
| [`proto-blue-lex-json`](crates/proto-blue-lex-json) | JSON &harr; LexValue conversion (`$link`, `$bytes` encoding) |
| [`proto-blue-common`](crates/proto-blue-common) | TID generation, DID document parsing, retry utilities, grapheme counting |
| [`proto-blue-lexicon`](crates/proto-blue-lexicon) | Lexicon schema types, validation engine, schema registry (322 schemas) |
| [`proto-blue-repo`](crates/proto-blue-repo) | Merkle Search Tree, CAR file read/write, BlockMap, CidSet |
| [`proto-blue-xrpc`](crates/proto-blue-xrpc) | XRPC HTTP client (reqwest-based query/procedure calls) |
| [`proto-blue-ws`](crates/proto-blue-ws) | WebSocket client with auto-reconnection and heartbeat |
| [`proto-blue-identity`](crates/proto-blue-identity) | DID resolution (`did:plc`, `did:web`), handle resolution (DNS + HTTPS) |
| [`proto-blue-api`](crates/proto-blue-api) | Generated types + Agent + RichText + Moderation engine |
| [`proto-blue-codegen`](crates/proto-blue-codegen) | Binary that generates Rust types from Lexicon JSON schemas |
| [`proto-blue-oauth`](crates/proto-blue-oauth) | OAuth 2.0 client: DPoP, PKCE, PAR, token lifecycle |

## Quick Start

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
proto-blue-api = { path = "crates/proto-blue-api" }
proto-blue-syntax = { path = "crates/proto-blue-syntax" }
tokio = { version = "1", features = ["full"] }
```

### Authenticate and Create a Post

> **Note:** For third-party applications, prefer [OAuth](#oauth) via the `proto-blue-oauth` crate.
> App password authentication (shown below) is suitable for personal scripts and bots.

```rust
use proto_blue_api::Agent;
use proto_blue_syntax::AtIdentifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = Agent::new("https://bsky.social")?;

    // Identifiers go through validated newtypes (handle or DID accepted).
    let id = AtIdentifier::new("alice.bsky.social")?;
    agent.login(&id, "app-password").await?;

    let session = agent.session().await.unwrap();
    println!("Logged in as {}", session.handle); // session.handle is `Handle`

    // Create a post (timestamp auto-generated, or pass Some("2024-01-15T12:00:00.000Z"))
    agent.post("Hello from Rust!", None, None).await?;

    Ok(())
}
```

### Rich Text with Facet Detection

```rust
use proto_blue_api::rich_text::{RichText, FacetFeature};

let mut rt = RichText::new(
    "Hello @alice.bsky.social! Check out https://bsky.app #atproto".to_string(),
    None,
);
rt.detect_facets();

for seg in &rt.segments() {
    if let Some(facet) = &seg.facet {
        match &facet.features[0] {
            FacetFeature::Mention { did } => println!("mention: @{did}"),
            FacetFeature::Link { uri } => println!("link: {uri}"),
            FacetFeature::Tag { tag } => println!("tag: #{tag}"),
        }
    }
}
```

### Validate AT Protocol Identifiers

```rust
use proto_blue_syntax::{Did, Handle, Nsid, AtUri};

let did = Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
let handle = Handle::new("alice.bsky.social").unwrap();
let nsid = Nsid::new("app.bsky.feed.post").unwrap();
let uri = AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3k2la").unwrap();

println!("{did} / {handle} / {nsid} / {uri}");
```

### Cryptographic Signing

```rust
use proto_blue_crypto::{P256Keypair, Keypair, Signer, Verifier, format_did_key};

let kp = P256Keypair::generate();
let did_key = format_did_key("ES256", &kp.public_key_compressed());
println!("did:key = {did_key}");

let sig = kp.sign(b"hello world");
assert!(kp.verify(b"hello world", &sig).is_ok());
```

### Resolve a DID

```rust
use proto_blue_identity::IdResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = IdResolver::new(None, 5000);
    let data = resolver.did.resolve_atproto_data(
        "did:plc:z72i7hdynmk6r22z27h6tvur", false
    ).await?;

    println!("Handle: {}", data.handle);
    println!("PDS:    {}", data.pds);
    Ok(())
}
```

### DAG-CBOR Encoding

```rust
use proto_blue_lex_data::LexValue;
use proto_blue_lex_cbor::{encode, decode, cid_for_lex};
use std::collections::BTreeMap;

let mut map = BTreeMap::new();
map.insert("hello".into(), LexValue::String("world".into()));
let value = LexValue::Map(map);

let bytes = encode(&value).unwrap();
let decoded = decode(&bytes).unwrap();
assert_eq!(value, decoded);

let cid = cid_for_lex(&value).unwrap();
println!("CID: {cid}");
```

### Merkle Search Tree

```rust
use proto_blue_repo::MstNode;
use proto_blue_lex_cbor::cid_for_lex;
use proto_blue_lex_data::LexValue;

let cid = cid_for_lex(&LexValue::String("test".into())).unwrap();

let mst = MstNode::empty();
let mst = mst.add("app.bsky.feed.post/abc123", cid.clone()).unwrap();
let mst = mst.add("app.bsky.feed.post/def456", cid.clone()).unwrap();

assert_eq!(mst.leaves().len(), 2);
```

### OAuth

For public third-party applications, use the `proto-blue-oauth` crate which implements the full OAuth 2.0 flow with DPoP, PKCE, and Pushed Authorization Requests (PAR):

```rust
use proto_blue_oauth::{OAuthClient, ClientMetadata, PkceChallenge, DpopProof};

// Configure your OAuth client
let metadata = ClientMetadata {
    client_id: "https://myapp.example.com/oauth/client-metadata.json".into(),
    redirect_uris: vec!["https://myapp.example.com/callback".into()],
    scope: Some("atproto transition:generic".into()),
    ..Default::default()
};

let client = OAuthClient::new(metadata);
```

See the [`proto-blue-oauth`](crates/proto-blue-oauth) crate for the complete authorization flow.

## Examples

Six runnable examples are included in the [`examples/`](examples/) directory:

```bash
cargo run --example syntax_validation   # DID, Handle, NSID, AT-URI validation
cargo run --example crypto_keys         # P-256/K-256 key generation and signing
cargo run --example repo_mst            # Merkle Search Tree operations
cargo run --example rich_text           # Rich text facet detection
cargo run --example moderation          # Label-based moderation decisions
cargo run --example resolve_identity    # Live DID/handle resolution (network)
```

## Architecture

### Dependency Layers

The crates are organized into dependency layers to minimize coupling:

| Layer | Crates | Dependencies |
|-------|--------|--------------|
| 0 (leaf) | `syntax`, `crypto`, `lex-data` | External only |
| 1 | `lex-cbor`, `lex-json` | `lex-data` |
| 2 | `common` | `syntax`, `lex-data`, `lex-json`, `lex-cbor` |
| 3 | `lexicon`, `identity` | `common`, `syntax`, `crypto` |
| 4 | `repo`, `xrpc`, `ws` | `common`, `crypto`, `lexicon`, `lex-cbor` |
| 5 | `api`, `codegen` | `common`, `syntax`, `lexicon`, `xrpc` |
| 6 | `oauth` | `identity`, `crypto`, `xrpc` |

### Code Generation

The `proto-blue-codegen` binary reads 322 Lexicon JSON schemas from the [`lexicons/`](lexicons/) directory and generates Rust types into `proto-blue-api/src/generated/`. Generated types follow AT Protocol naming conventions:

- **Objects** become `#[derive(Serialize, Deserialize)]` structs with `camelCase` serde renaming
- **Unions** become tagged enums with `#[serde(tag = "$type")]`. Inline
  unions emit local sum types instead of `serde_json::Value`.
- **Known values** become `pub type X = String` with associated `pub const` values
- **Queries/Procedures** generate `Params`, `Input`, and `Output` types
- **`format`-bearing strings** (DID, Handle, NSID, AT-URI, TID,
  RecordKey, Datetime, CID) emit the matching `proto-blue-syntax`
  newtype on the field

Codegen also handles edition-2024 keyword escaping (`gen`, `try`),
sibling identifier collisions, dash-segment NSID path/ident sync,
multi-line description `///` continuation, and the leaf-and-parent
NSID case (where the same NSID appears as both a record and a
namespace — emits `<name>/mod.rs` only).

To regenerate:

```bash
cargo run --bin proto-blue-codegen -- --lexicons lexicons --output crates/proto-blue-api/src/generated
```

To validate codegen against third-party schemas, the
`scripts/wildscrape/` side-workspace scrapes lexicon.garden's
real-world corpus into `lexicons.wild/`; the
`proto-blue-codegen::wild_corpus_compiles` test (`#[ignore]`'d, opt-in
once the corpus is populated) rustc-compiles the generated output to
catch second-order errors. See
[`proto-blue/scripts/wildscrape/README.md`](proto-blue/scripts/wildscrape/README.md).

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| `BTreeMap` for LexValue maps | DAG-CBOR requires deterministic key ordering |
| Binary codegen, not proc-macros | 368 files generated once; proc-macros would slow every build |
| Separate `lex-data` crate | `Cid`/`LexValue` needed by both `lex-cbor` and `lex-json` |
| Merged `common-web` + `common` | Rust has no browser/Node split like TypeScript |
| `thiserror` for all error types | Structured errors with `Display`, composable via `#[from]` |
| Newtypes with validation | Zero-cost abstractions; validation at construction boundaries |

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p proto-blue-syntax

# Run integration tests (requires network)
cargo test --workspace -- --ignored

# Lint
cargo clippy --workspace

# Format check
cargo fmt --check
```

### Test Coverage

Property-based tests cover syntax validation, cryptographic roundtrips,
CBOR encoding, MST operations, and (since v0.3.0) the `proto-blue-repo`
proof pipeline (`covering_proof` soundness/completeness, block-removal
sensitivity, forgery resistance) plus a `cargo-fuzz` target. Interop
test vectors from `interop-test-files/` validate compatibility with
the TypeScript reference implementation, and the
`proto-blue-interop-tests` crate runs a 28-fixture differential
dag-cbor + CID parity check against `@atproto/common` (CI gates on
parity). Live-PDS integration tests live in
`crates/proto-blue-api/tests/live_pds.rs`, are `#[ignore]`'d, and
early-return on missing `PDS_URL` / `PDS_TEST_HANDLE` /
`PDS_TEST_APP_PASSWORD` env vars so fresh clones stay network-free.

## Building

```bash
# Full workspace build
cargo build --workspace

# Release build
cargo build --workspace --release
```

**Minimum Supported Rust Version:** 1.88 (edition 2024)

The workspace uses let-chains (stabilized in Rust 1.88). CI verifies this
toolchain in the `msrv` job — bumping the MSRV requires editing
`proto-blue/Cargo.toml`, the README, and `.github/workflows/ci.yml` together.

## WASM support

proto-blue compiles for `wasm32-unknown-unknown` out of the box — the
top-level crate picks the right HTTP/WebSocket backend per target
automatically (reqwest + tungstenite + hickory on native, `fetch()` +
browser `WebSocket` via gloo-net on wasm).

```toml
[dependencies]
proto-blue = "0.3"
```

No additional configuration is needed: building for `wasm32-unknown-unknown`
drops reqwest / hickory / tokio-tungstenite and swaps in the browser
equivalents. A reduced-feature build works the same way:

```toml
[dependencies]
# Pure subset only (no network) — smallest footprint.
proto-blue = { version = "0.3", default-features = false }
```

### Feature matrix

| Feature    | Re-exports                                                             | wasm32 |
|------------|------------------------------------------------------------------------|--------|
| *(none)*   | `syntax`, `crypto`, `lex_data`, `lex_cbor`, `lex_json`, `common`, `lexicon`, `repo` | ✅ |
| `net`      | `xrpc` — `fetch()` on wasm, reqwest on native                          | ✅ |
| `ws`       | `ws` + `repo::Firehose` — browser `WebSocket` on wasm, tungstenite on native | ✅ |
| `resolver` | `identity` — HTTPS `.well-known` only on wasm (no DNS), full DNS + HTTP on native | ✅ |
| `oauth`    | `oauth` — browser fetch on wasm, reqwest on native                     | ✅ |
| `api`      | `api` — browser fetch on wasm, reqwest on native                       | ✅ |
| `full`     | everything — **default**                                               | ✅ |

CI regression-gates `cargo check --target wasm32-unknown-unknown -p proto-blue`
(full default features) plus per-crate wasm checks.

Callers who want to wire up a custom backend (mock transport, custom TLS, etc.)
can use the `with_fetch_handler` / `with_connector` constructors on `XrpcClient`,
`DidResolver`, `HandleResolver`, `IdResolver`, `OAuthClient`, `OAuthSession`,
and `WebSocketKeepAlive`.

## License

Licensed under [MIT](proto-blue/LICENSE-MIT) or [Apache-2.0](proto-blue/LICENSE-APACHE).

## Acknowledgments

- [AT Protocol specification](https://atproto.com/specs) by Bluesky PBLLC
- [TypeScript SDK](https://github.com/bluesky-social/atproto) — the reference implementation this SDK is translated from
- Lexicon schemas sourced from the official AT Protocol repository
