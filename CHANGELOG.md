# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Add user-provided timestamp support to Agent methods (#23)
- Add MIT license (#19)
- Add comprehensive README with architecture docs and usage examples (#18)
- Add moderation engine with label decisions and mute word matching (#12)
- Add atproto-api crate with generated types, Agent, and RichText (#6)
- Add atproto-oauth crate with DPoP, PKCE, PAR, and session management (#10)
- Add moderation engine, integration tests, documentation, and examples to complete the AT Protocol Rust SDK (#11)
- Add integration tests against live PDS and formal verification (#13)
- Add examples directory with practical usage demos (#14)
- Add crate documentation and doc-tests (#15)
- Implement atproto-crypto crate with P-256 and K-256 signing (#5)
- Implement atproto-lex-data crate with CID and LexValue types (#4)
- Implement atproto-syntax crate with all identifier newtypes (#3)
- Set up Rust workspace structure and scaffold all crates (#2)
- Build a robust AT Protocol SDK for Rust (translated from TypeScript SDK) (#1)

### Fixed
- Fix Agent auth state thread-safety: token leak, giant lock, and atomicity gap (#25)
- Fix Agent resume_session to verify before updating state (#21)
- Fix all clippy warnings across workspace (#17)

### Changed
- Rename all crates from atproto-* to proto-blue-* for crates.io publishing (#7)
- Update 68 dependencies to latest compatible versions (#2)
- Update jsonwebtoken from 9 to 10 for latest security fixes and features (#24)
- Update README authentication example to recommend OAuth (#22)
- Improve Agent thread-safety with lock-free session access (#20)
- Fix all compiler warnings across workspace (#16)
