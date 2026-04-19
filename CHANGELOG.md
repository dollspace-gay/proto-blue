# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Server codegen: typed `register(server, handler) -> XrpcServer` helper
  emitted per query/procedure in `proto-blue-api` behind the new
  `server` feature, with automatic params/input decoding and output
  serialization (#44).
- OAuth: `SimpleStore` trait + in-memory default for pluggable
  state/session/nonce storage, `TokenSet.aud` for DPoP audience
  binding, session refresh lock (shared `/token` request across
  concurrent callers), `is_expired_jittered` for stampede avoidance,
  loopback client ID parsing (`http://localhost[/?…]`) with implicit
  metadata + `OAuthClient::new_loopback`, RFC 7523 `private_key_jwt`
  client authentication via `ClientKey`/`ClientKeyset` with alg
  negotiation, and end-to-end identity resolution
  (handle/DID/PDS-URL → PDS → AS) behind the new `identity-resolver`
  feature. `callback_verified` rejects AS-returned `sub` that
  mismatches a pre-resolved DID. (#53)

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
