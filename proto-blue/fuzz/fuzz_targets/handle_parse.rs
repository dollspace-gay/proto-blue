//! Fuzz `Handle` validation + normalization.
//!
//! Handles come from user input and the DNS / well-known resolution
//! chain — non-ASCII, mixed-case, or syntactically invalid strings
//! will show up here.
//!
//! Invariants:
//! - `Handle::new` must never panic.
//! - `normalize_handle` must never panic.
//! - Normalization is idempotent: `normalize(normalize(s)) == normalize(s)`.
//! - `normalize_and_ensure_valid_handle` must agree with
//!   `Handle::new(&normalize_handle(s))` on accept/reject.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_syntax::{Handle, normalize_and_ensure_valid_handle, normalize_handle};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Direct constructor — accepts pre-normalized input.
    let _ = Handle::new(s);

    // Normalization must be pure and idempotent.
    let n1 = normalize_handle(s);
    let n2 = normalize_handle(&n1);
    assert_eq!(
        n1, n2,
        "normalize_handle is not idempotent: {s:?} → {n1:?} → {n2:?}"
    );

    // Normalize-then-validate must match validate-on-normalized.
    let combined = normalize_and_ensure_valid_handle(s);
    let direct = Handle::new(&n1);
    assert_eq!(
        combined.is_ok(),
        direct.is_ok(),
        "normalize_and_ensure diverged from Handle::new(&normalize(_)): {s:?}"
    );
});
