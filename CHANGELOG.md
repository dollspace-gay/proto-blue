# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- cargo-fuzz harnesses for every byte-level parser: `lex_cbor_decode`,
  `lex_cbor_canonical`, `lex_json_strict`, `car_parse`, `at_uri_parse`,
  `handle_parse`, `nsid_parse`, `did_parse`, `tid_parse`. Top-level
  `fuzz/` workspace with GitHub Actions matrix (60s PR sweep, 180s
  nightly). See `fuzz/README.md`. (#55)
- Proptest coverage expanded across 22 new invariants on pure data
  types: RecordKey length bounds + reserved-name rejection, Handle
  normalization idempotency + non-ASCII rejection, DID method-
  specific round-trips, AtUri builder + setter preservation, TID
  timestamp-extraction round-trip + ordering preservation, rate
  limiter accounting + key independence + combined-tightest-wins,
  Scope/ScopeSet round-trips, and `get_pds_endpoint` extraction on
  well-formed DID documents. (#56)

### Fixed
- `proto-blue-repo::read_car`: integer overflow panic on adversarial
  varint lengths (`pos + header_len > data.len()` panics when the
  sum overflows `usize`). Replaced three sites with `checked_add`.
  Regression test seeded from the libFuzzer reproducer. Found by
  the `car_parse` fuzz target. (#55)

### Changed
- Live-PDS integration tests: new
  `crates/proto-blue-api/tests/live_pds.rs` with
  `session_lifecycle_roundtrip` (login / session echo / refresh
  rotation / logout) and `post_then_delete_roundtrip` (`Agent::post`
  against a real `app.bsky.feed.post`). Every test is `#[ignore]`'d
  and additionally early-returns on missing
  `PDS_URL`/`PDS_TEST_HANDLE`/`PDS_TEST_APP_PASSWORD` env vars so
  fresh clones stay network-free. Nightly CI workflow at
  `.github/workflows/live-pds.yml` runs them against secrets at
  04:00 UTC. (#59)
- TS-interop differential test harness: new
  `proto-blue-interop-tests` crate spawns a long-lived
  `@atproto/syntax` Node subprocess and diffs its outputs against
  our Rust parsers on a shared corpus. Initial ops:
  `normalize_handle`, `is_valid_handle`, `nsid_is_valid`,
  `aturi_components`. Gated on `TS_RUNNER_READY=1`; CI workflow at
  `.github/workflows/interop.yml` sets it up. Found one real
  spec-interpretation divergence on AT-URI fragment validation
  (Rust enforces JSON Pointer per spec, TS accepts any string). (#58)
- Stateful property tests (proptest state machines) covering
  subsystems where bugs hide in operation sequences rather than
  single calls: MST add/update/delete oracle-matching over random
  40-op sequences including end-of-sequence round-trip via
  `get_all_blocks` / `load`; OAuth `OAuthSession` lifecycle
  (`did()` == `token_set().sub`, `aud` persistence across updates,
  expiry classification under jitter); and firehose
  `WebSocketKeepAlive` reconnect accounting across random
  success/failure scripts (url_fn consulted per dial, no URL
  repeat, `ReconnectExhausted` fires iff cap exceeded). (#57)

## [0.2.5] - 2026-04-19

### Fixed
- **`WebSocketTransport: Send + Sync`** (#5, via @skydeval):
  `WebSocketKeepAlive::connect(&mut self)` holds `&self` across
  `resolve_url(&self).await`, which downstream spawning on a
  work-stealing tokio runtime requires to propagate `Sync` through
  `dyn WebSocketTransport`. The native supertrait was only `Send`,
  blocking that use case. Concrete `TungsteniteTransport` was
  already `Send + Sync` (wraps `tokio-tungstenite`), so widening the
  trait bound has no impact on existing impls.

## [0.2.4] - 2026-04-19

### Fixed
- **wasm32 ergonomics**: downstream consumers of `OAuthClient::new`,
  `OAuthSession::new`, `Agent::new`, `XrpcClient::new`, `IdResolver::new`,
  `HandleResolver::new`, and `DidResolver::new` can now call the
  default constructor on wasm without manually enabling `fetch-web`.
  The `WebFetcher` impl is now always compiled on wasm (gloo-net +
  js-sys moved into unconditional `[target.cfg(target_arch = "wasm32")]`
  deps), and each `new()` has a wasm arm that uses it. The `fetch-web`
  feature is kept as a no-op for source-compat.
- **`HttpResponse` reqwest-style API**: added `status()` returning
  `http::StatusCode` (the same type reqwest re-exports as
  `reqwest::StatusCode`), plus async `text()` / `json::<T>()` methods
  on `HttpResponse`. Lets downstream crates written against reqwest
  call `resp.status().is_success()`, `resp.text().await`,
  `resp.json().await` on `OAuthSession::get` / `post` return values
  without refactoring.
- **`FetchHandler: Send + Sync` on wasm**: the wasm variant now
  requires `Send + Sync` (the future is still `?Send`). Lets
  `Arc<OAuthSession>` / `Arc<dyn FetchHandler>` live inside Bevy
  `Resource` fields, which require `Send + Sync` even on
  single-threaded wasm builds.

### Verified against
- `cargo build --workspace` ✓
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` ✓
- `cargo test --workspace --all-features` ✓
- `cargo check -p proto-blue --target wasm32-unknown-unknown` ✓
- Downstream `symbios-overlands` (Bevy + bevy_symbios_multiuser +
  proto-blue-oauth + proto-blue-api) `cargo check --target
  wasm32-unknown-unknown` ✓ (was failing on 0.2.2/0.2.3).

## [0.2.3] - 2026-04-19

### Fixed
- **wasm32 build**: default-feature chains through `proto-blue` and
  its subcrates no longer leak native-only tokio features (`net`,
  `rt-multi-thread`) into wasm builds. Offenders were
  `proto-blue-common/fetch-reqwest` explicitly enabling
  `tokio/rt-multi-thread`, and `reqwest`/`axum`/`tokio-tungstenite`/
  `hickory-resolver` being unconditional deps. All four are now
  target-gated behind `cfg(not(target_arch = "wasm32"))`; their
  associated features compile as no-ops on wasm instead of failing.
  Downstream consumers can now depend on the umbrella `proto-blue`
  crate or any subcrate with default features on either target
  without needing to override feature sets. (Reported via downstream
  CI: "Only features sync,macros,io-util,rt,time are supported on
  wasm.")
- **`TokenSet::from_response` back-compat**: restored the original
  two-arg signature `(issuer, response)` so existing callers
  upgrading from 0.2.1 don't see a compile break. The new
  audience-aware form is now `TokenSet::from_response_with_aud(issuer,
  aud, response)`.

### Added
- Server codegen: typed `register(server, handler) -> XrpcServer` helper
  emitted per query/procedure in `proto-blue-api` behind the new
  `server` feature, with automatic params/input decoding and output
  serialization (#44).
- OAuth general-purpose client surface: `SimpleStore` trait + in-memory
  default for pluggable state/session/nonce storage, `TokenSet.aud`
  for DPoP audience binding, session refresh lock (shared `/token`
  request across concurrent callers), `is_expired_jittered` for
  stampede avoidance, loopback client ID parsing
  (`http://localhost[/?…]`) with implicit metadata +
  `OAuthClient::new_loopback`, RFC 7523 `private_key_jwt` client
  authentication via `ClientKey`/`ClientKeyset` with alg negotiation,
  and end-to-end identity resolution (handle/DID/PDS-URL → PDS → AS)
  behind the new `identity-resolver` feature. `callback_verified`
  rejects AS-returned `sub` that mismatches a pre-resolved DID. (#53)

## [0.2.1] - 2026-04-19

### Changed
- Trim workspace tokio features (drop 'full' where 'net' isn't needed) (#23)
- Update 74 transitive dependencies via `cargo update` (tokio 1.50 → 1.52.1,
  serde / wasm-bindgen / zerocopy / tempfile patch bumps).
- Bump `axum` 0.7 → 0.8. Only breaking change that hit us was the path-
  param syntax (`:nsid` → `{nsid}`); fixed at the single route definition
  in `proto-blue-xrpc::server::into_router`.

## [0.2.0] - 2026-04-18

### Added
- xrpc server: body size limits, handler cancellation, paramsParseLoose (#52)
- Streaming/subscription server in proto-blue-xrpc (#35)
- Writable Repo + RepoStorage trait (proto-blue-repo) (#38)
- OAuth infrastructure: identity/resource metadata/loopback/private_key_jwt/stores/refresh-lock (#42)
- Full rate limiter (token bucket, keyed, combined) in proto-blue-xrpc (#37)
- Client codegen: AtpBaseClient + namespace tree + record helpers (#43)
- Agent surface: proxy, labelers, preferences, profile, account lifecycle (#40)
- repo: streaming CAR + MST lazy loading + traversal helpers (#51)
- Crypto helpers: multibase codec, random, sha256Hex, verifySignatureUtf8, plugin registry (#49)
- common: port obfuscate.ts + expose jitter + minor flow helpers (#50)
- Syntax helpers: isValidTld, normalizeHandle, NSID.create, isValidUri, AT-URI search/fragment (#48)
- WebSocketKeepAlive: getUrl callback, reconnect events, active heartbeat (#47)
- Top-level moderation API: moderate_post/profile + embed walker (#41)
- Session lifecycle: events + persistence callback + auto-refresh (proto-blue-api) (#39)
- Lexicon validation + cancellation + payload limits in proto-blue-xrpc (#36)
- Lexicon XRPC validators + default-value substitution + blob validator (#46)
- Add LegacyBlobRef variant to proto-blue-lex-data (#32)
- Migrate proto-blue-oauth and proto-blue-api to FetchHandler (#29)
- WebSocket abstraction for firehose (web-sys WebSocket on wasm) (#27)
- Pluggable DID/handle resolver (replace hickory-resolver default on wasm) (#26)
- Abstract XRPC transport behind a trait (pluggable fetch) (#25)
- Add wasm32 target to CI (regression gate) (#28)
- Feature-gate top-level proto-blue re-exports for wasm builds (#24)
- XRPC: implement server-side (router, validation, auth, rate-limit) (#16)
- Syntax: AtUri class-like API (setters, make, relative, searchParams) (#19)
- Repo: MST covering and commit proofs (#15)
- OAuth: implement token exchange, refresh, and revocation (#4)
- OAuth: implement Pushed Authorization Requests (PAR) (#6)
- OAuth: dynamic client metadata fetching (#7)
- Repo: sync primitives (firehose, getRepo, diff) (#14)
- OAuth: parse and validate atproto scope strings (#5)
- OAuth: add ES256K DPoP support (#8)
- Crypto: optional private-key export gating (#20)
- Identity: backup DNS nameservers for handle resolution (#11)
- Identity: verify handle->DID binding against DID doc alsoKnownAs (#12)
- Identity: add did:key resolution (#9)
- Repo: signed commit creation and verification (#13)
- WS: CBOR streaming frame encode/decode (#17)
- XRPC: parse Retry-After and RateLimit-* response headers (#22)
- Add top-level proto-blue facade crate that re-exports all SDK modules (#14)
- Add user-provided timestamp support to Agent methods (#23)
- Add MIT license (#19)
- Add comprehensive README with architecture docs and usage examples (#18)
- Add moderation engine with label decisions and mute word matching (#12)
- Add proto-blue-api crate with generated types, Agent, and RichText (#6)
- Add proto-blue-oauth crate with DPoP, PKCE, PAR, and session management (#10)
- Add moderation engine, integration tests, documentation, and examples to complete the AT Protocol Rust SDK (#11)
- Add integration tests against live PDS and formal verification (#13)
- Add examples directory with practical usage demos (#14)
- Add crate documentation and doc-tests (#15)
- Implement proto-blue-crypto crate with P-256 and K-256 signing (#5)
- Implement proto-blue-lex-data crate with CID and LexValue types (#4)
- Implement proto-blue-syntax crate with all identifier newtypes (#3)
- Set up Rust workspace structure and scaffold all crates (#2)
- Build a robust AT Protocol SDK for Rust (translated from TypeScript SDK) (#1)

### Fixed
- Typed BlobRef / CidLink / record $type in codegen (#45)
- Replace stale-refresh TODO in DidResolver with background refresh (#34)
- Verify CID-for-bytes on CAR read (proto-blue-repo) (#33)
- Wire up lex-json strict mode + typed BlobRef validation (#31)
- Enforce DAG-CBOR canonical-form on decode (lex-cbor) (#30)
- WS: add random jitter to reconnect backoff (#18)
- AT-URI regex uses global case-insensitive flag (defense-in-depth) (#3)
- normalize_datetime has broken month/day rollover on timezone offsets (#2)
- Datetime validation accepts semantically invalid values (month=0, hour=25, etc.) (#1)
- Fix Agent auth state thread-safety: token leak, giant lock, and atomicity gap (#25)
- Fix Agent resume_session to verify before updating state (#21)
- Fix all clippy warnings across workspace (#17)

### Changed
- XRPC/Identity/OAuth: support CancellationToken for mid-request abort (#21)
- Identity: race DNS and HTTPS handle resolution in parallel (#10)
- Rename all crates from atproto-* to proto-blue-* for crates.io publishing (#7)
- Update 68 dependencies to latest compatible versions (#2)
- Update jsonwebtoken from 9 to 10 for latest security fixes and features (#24)
- Update README authentication example to recommend OAuth (#22)
- Improve Agent thread-safety with lock-free session access (#20)
- Fix all compiler warnings across workspace (#16)
