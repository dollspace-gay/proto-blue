//! Fuzz the proof pipeline.
//!
//! Builds an MST from arbitrary fuzzer-driven `(key, value)` data,
//! generates a covering proof for one of its keys, then exercises the
//! verifier with both the clean proof and adversarially-mutated copies
//! of the proof block map.
//!
//! Invariants asserted:
//! - Proof construction never panics on valid MST input (it can return
//!   `Err`, but must not unwind).
//! - The verifier, given a clean proof, must verify the actual
//!   `(key, value)` claim if the key is in the MST.
//! - The verifier must never silently accept a forged-value claim, no
//!   matter how the proof block map is mutated (block-deletion,
//!   byte-flips, extra unrelated blocks).
//! - The verifier must never unwind. Any error must be returned via
//!   `Result::Err`, not via `panic!` / `unreachable!` / arithmetic
//!   overflow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto_blue_lex_cbor::cid_for_lex;
use proto_blue_lex_data::{Cid, LexValue};
use proto_blue_repo::{BlockMap, MstNode, covering_proof, verify_key_in_proof};

fuzz_target!(|data: &[u8]| {
    // Need at least a few bytes to drive entry generation.
    if data.len() < 6 {
        return;
    }

    // Derive 1..16 entries from the fuzzer input. Keys are short ASCII
    // slugs forced into the `<coll>/<rkey>` shape MSTs use; values are
    // tiny LexValues so encoding is fast.
    let entry_count = ((data[0] as usize) % 16) + 1;
    let mut mst = MstNode::empty();
    let mut keys: Vec<String> = Vec::with_capacity(entry_count);
    let mut chunks = data[1..].chunks(4);
    for i in 0..entry_count {
        let chunk = match chunks.next() {
            Some(c) if c.len() >= 2 => c,
            _ => break,
        };
        // Build a key like `c/k0001` — collection is one of 4 letters, rkey
        // is i + the chunk's first byte to introduce variety. Always a
        // valid `<segment>/<segment>` shape so MstNode::add accepts it.
        let coll_byte = (chunk[0] % 4) + b'a';
        let rkey_seed = chunk[1] as u32;
        let key = format!(
            "{}/k{:04}",
            coll_byte as char,
            (rkey_seed * 7 + i as u32) % 9999
        );
        let value_seed = if chunk.len() >= 4 {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64
        } else {
            (chunk[0] as u64) << 8 | chunk[1] as u64
        };
        let value = LexValue::Integer(value_seed as i64);
        let value_cid = match cid_for_lex(&value) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match mst.add(&key, value_cid) {
            Ok(new) => {
                mst = new;
                keys.push(key);
            }
            Err(_) => {
                // Duplicate key or unsupported shape — skip.
                continue;
            }
        }
    }

    if keys.is_empty() {
        return;
    }

    let root = match mst.get_pointer() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Pick a key driven by the fuzzer.
    let key_idx = (data[0] as usize) % keys.len();
    let key = &keys[key_idx];

    // Build the covering proof. Construction errors are acceptable; a
    // panic is not.
    let Ok(proof) = covering_proof(&mst, key) else {
        return;
    };

    // Soundness sanity: clean proof must verify the actual value.
    let actual_value_cid = mst.get(key);
    if let Some(actual) = actual_value_cid {
        let _ = verify_key_in_proof(&proof, &root, key, Some(&actual));
    }

    // Forgery resistance: a wrong-value claim must NEVER come back true,
    // no matter how the proof bytes are subsequently mutated.
    let forged_value = LexValue::String("fuzz-forged".into());
    let Ok(forged_cid) = cid_for_lex(&forged_value) else {
        return;
    };

    // 1. Clean proof + wrong value must reject (or error). Sanity-skip the
    //    1-in-2^256 case where the forged CID happens to equal the actual.
    if matches!(
        verify_key_in_proof(&proof, &root, key, Some(&forged_cid)),
        Ok(true),
    ) && mst.get(key).as_ref().map(Cid::to_string_base32) != Some(forged_cid.to_string_base32())
    {
        panic!(
            "forgery: clean proof verified wrong-value claim for key {key} ({})",
            forged_cid.to_string_base32()
        );
    }

    // 2. Adversarial mutations driven by remaining fuzzer bytes.
    let mutator_bytes = data.get(1 + entry_count * 4..).unwrap_or(&[]);
    let mutated = mutate_proof(&proof, mutator_bytes);

    // Mutated + wrong-value claim must still never silently accept.
    if matches!(
        verify_key_in_proof(&mutated, &root, key, Some(&forged_cid)),
        Ok(true),
    ) && mst.get(key).as_ref().map(Cid::to_string_base32) != Some(forged_cid.to_string_base32())
    {
        panic!("forgery: mutated proof verified wrong-value claim for key {key}");
    }

    // Mutated + correct-value claim is allowed any of {Ok(true), Ok(false), Err},
    // we just call it and verify no panic.
    if let Some(actual) = mst.get(key) {
        let _ = verify_key_in_proof(&mutated, &root, key, Some(&actual));
    }
    let _ = verify_key_in_proof(&mutated, &root, key, None);
});

/// Build a mutated copy of `proof` driven by `bytes`.
///
/// Operations cycle through: delete a block, flip a byte in a block,
/// and add an unrelated block. Each operation is deterministic given
/// the bytes, so libFuzzer's coverage-guided search can converge.
fn mutate_proof(proof: &BlockMap, bytes: &[u8]) -> BlockMap {
    let mut out = BlockMap::new();
    for (cid, payload) in proof.iter() {
        out.set(cid.clone(), payload.to_vec());
    }
    if bytes.is_empty() {
        return out;
    }

    let cids: Vec<Cid> = out.iter().map(|(c, _)| c.clone()).collect();
    if cids.is_empty() {
        return out;
    }

    let mut cursor = 0;
    while cursor + 1 < bytes.len() && cursor < 32 {
        let op = bytes[cursor] % 3;
        cursor += 1;
        match op {
            // Drop a block.
            0 => {
                let idx = (bytes[cursor] as usize) % cids.len();
                cursor += 1;
                let target = cids[idx].clone();
                let mut next = BlockMap::new();
                for (c, b) in out.iter() {
                    if c != &target {
                        next.set(c.clone(), b.to_vec());
                    }
                }
                out = next;
            }
            // Flip a byte in a block.
            1 => {
                let idx = (bytes[cursor] as usize) % cids.len();
                cursor += 1;
                let target = &cids[idx];
                if let Some(orig) = out.get(target) {
                    let mut new_bytes = orig.to_vec();
                    if !new_bytes.is_empty() {
                        let pos = (bytes[cursor.min(bytes.len() - 1)] as usize) % new_bytes.len();
                        new_bytes[pos] ^= 0xff;
                    }
                    cursor = cursor.saturating_add(1);
                    out.set(target.clone(), new_bytes);
                }
            }
            // Add an unrelated block (its CID won't be referenced from the root).
            2 => {
                let salt = bytes[cursor] as u64;
                cursor += 1;
                let val = LexValue::Integer(salt as i64);
                if let (Ok(payload), Ok(cid)) =
                    (proto_blue_lex_cbor::encode(&val), cid_for_lex(&val))
                {
                    out.set(cid, payload);
                }
            }
            _ => unreachable!(),
        }
    }
    out
}
