//! Shared test helpers for the OAuth integration test suite.
//!
//! Each file in this directory is compiled as part of every integration
//! test binary that declares `mod common;`. Nothing here runs as its
//! own test binary.

pub mod mock_server;
