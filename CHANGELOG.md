# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
