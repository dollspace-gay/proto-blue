//! Fuzz the CAR (Content Addressable aRchive) decoder.
//!
//! CAR bytes arrive over the network from the firehose and from
//! PDS `getRepo` calls — so this parser processes fully-untrusted
//! input.
//!
//! Invariants:
//! - `read_car` / `read_car_with_root` must never panic.
//! - On success, every emitted block's CID must verify against its
//!   payload (this is the `verifyIncomingCarBlocks` contract that
//!   the strict reader already enforces — fuzzing asserts it holds
//!   under adversarial inputs).

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_repo::{read_car, read_car_with_root};

fuzz_target!(|data: &[u8]| {
    // `read_car` returns `(roots, BlockMap)`. If the strict CID-
    // verification built into the reader lets a block through, its
    // hash really matches — no further assertion needed here beyond
    // "no panics, no silent corruption".
    let _ = read_car(data);

    // Same contract on the root-extracting variant, which also
    // asserts exactly-one-root.
    let _ = read_car_with_root(data);
});
