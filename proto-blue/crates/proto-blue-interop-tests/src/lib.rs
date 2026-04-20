//! Differential-testing harness against the `@atproto/*` TypeScript
//! SDK. The library crate here is deliberately empty — all the real
//! logic lives in `tests/differential.rs` (harness) and
//! `ts-runner/index.mjs` (subprocess). The empty lib shell gives
//! cargo a crate to hang dev-dependencies off of.
