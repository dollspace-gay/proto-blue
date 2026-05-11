#![allow(clippy::pedantic, clippy::nursery)]

//! Interop parity tests: drive the official atproto interop fixture corpus
//! against proto-blue-syntax parsers.
//!
//! Fixture files live at `<workspace>/interop-test-files/syntax/`.
//! Each line is either a test case, a blank line, or a `#` comment.
//! `_valid.txt` asserts every case parses OK; `_invalid.txt` asserts every
//! case is rejected. `datetime_parse_invalid.txt` contains strings that are
//! syntactically well-formed (pass the regex) but fail semantic validation
//! (month 0, hour 25, etc.) — TS rejects these via Date parsing. proto-blue
//! is regex-only, so those cases are tracked as a known gap (see the
//! `#[ignore]`'d test at the bottom).

use std::fs;
use std::path::PathBuf;

use proto_blue_syntax::{AtIdentifier, AtUri, Datetime, Did, Handle, Nsid, RecordKey, Tid};

fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("../../interop-test-files/syntax")
        .join(name)
}

/// Load the list of non-comment, non-blank lines from a fixture file.
///
/// Only `\r\n` line endings are trimmed — leading/trailing spaces *inside*
/// a case are preserved because the fixtures deliberately embed them as
/// adversarial input (e.g. ` at://did:plc:asdf123`).
fn load_cases(name: &str) -> Vec<String> {
    let path = fixture_path(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    raw.lines()
        .map(|line| line.trim_end_matches(['\r', '\n']).to_owned())
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .collect()
}

fn assert_all_valid<F, E>(label: &str, cases: &[String], validator: F)
where
    F: Fn(&str) -> Result<(), E>,
    E: std::fmt::Display,
{
    let mut failures = Vec::new();
    for case in cases {
        if let Err(e) = validator(case) {
            failures.push(format!("  {label} rejected valid case {case:?}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "\n{} valid-case failures for {label}:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn assert_all_invalid<F, E>(label: &str, cases: &[String], validator: F)
where
    F: Fn(&str) -> Result<(), E>,
{
    let mut leaks = Vec::new();
    for case in cases {
        if validator(case).is_ok() {
            leaks.push(format!("  {label} accepted invalid case {case:?}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "\n{} invalid-case leaks for {label}:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

// -------- handles --------

#[test]
fn handle_valid_fixtures() {
    let cases = load_cases("handle_syntax_valid.txt");
    assert!(!cases.is_empty(), "no cases loaded");
    assert_all_valid("handle", &cases, |s| Handle::new(s).map(|_| ()));
}

#[test]
fn handle_invalid_fixtures() {
    let cases = load_cases("handle_syntax_invalid.txt");
    assert!(!cases.is_empty(), "no cases loaded");
    assert_all_invalid("handle", &cases, |s| Handle::new(s).map(|_| ()));
}

// -------- DIDs --------

#[test]
fn did_valid_fixtures() {
    let cases = load_cases("did_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("did", &cases, |s| Did::new(s).map(|_| ()));
}

#[test]
fn did_invalid_fixtures() {
    let cases = load_cases("did_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("did", &cases, |s| Did::new(s).map(|_| ()));
}

// -------- NSIDs --------

#[test]
fn nsid_valid_fixtures() {
    let cases = load_cases("nsid_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("nsid", &cases, |s| Nsid::new(s).map(|_| ()));
}

#[test]
fn nsid_invalid_fixtures() {
    let cases = load_cases("nsid_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("nsid", &cases, |s| Nsid::new(s).map(|_| ()));
}

// -------- AT-URIs --------

#[test]
fn aturi_valid_fixtures() {
    let cases = load_cases("aturi_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("at-uri", &cases, |s| AtUri::new(s).map(|_| ()));
}

#[test]
fn aturi_invalid_fixtures() {
    let cases = load_cases("aturi_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("at-uri", &cases, |s| AtUri::new(s).map(|_| ()));
}

// -------- TIDs --------

#[test]
fn tid_valid_fixtures() {
    let cases = load_cases("tid_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("tid", &cases, |s| Tid::new(s).map(|_| ()));
}

#[test]
fn tid_invalid_fixtures() {
    let cases = load_cases("tid_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("tid", &cases, |s| Tid::new(s).map(|_| ()));
}

// -------- record keys --------

#[test]
fn recordkey_valid_fixtures() {
    let cases = load_cases("recordkey_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("recordkey", &cases, |s| RecordKey::new(s).map(|_| ()));
}

#[test]
fn recordkey_invalid_fixtures() {
    let cases = load_cases("recordkey_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("recordkey", &cases, |s| RecordKey::new(s).map(|_| ()));
}

// -------- at-identifiers (DID or handle) --------

#[test]
fn atidentifier_valid_fixtures() {
    let cases = load_cases("atidentifier_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("at-identifier", &cases, |s| {
        AtIdentifier::new(s).map(|_| ())
    });
}

#[test]
fn atidentifier_invalid_fixtures() {
    let cases = load_cases("atidentifier_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("at-identifier", &cases, |s| {
        AtIdentifier::new(s).map(|_| ())
    });
}

// -------- datetimes --------

#[test]
fn datetime_valid_fixtures() {
    let cases = load_cases("datetime_syntax_valid.txt");
    assert!(!cases.is_empty());
    assert_all_valid("datetime", &cases, |s| Datetime::new(s).map(|_| ()));
}

#[test]
fn datetime_invalid_fixtures() {
    let cases = load_cases("datetime_syntax_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("datetime", &cases, |s| Datetime::new(s).map(|_| ()));
}

/// Semantic datetime validation: strings that pass the regex but fail
/// calendar checks (month 0/13, day 0/32, hour 25, minute 60, second 61,
/// Feb 29 in a non-leap year, etc.). Was `#[ignore]`'d while the
/// validator was regex-only; now enforced via chrono's RFC 3339 parser.
#[test]
fn datetime_parse_invalid_fixtures() {
    let cases = load_cases("datetime_parse_invalid.txt");
    assert!(!cases.is_empty());
    assert_all_invalid("datetime (semantic)", &cases, |s| {
        Datetime::new(s).map(|_| ())
    });
}
