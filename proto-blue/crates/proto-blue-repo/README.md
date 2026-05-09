# proto-blue-repo

AT Protocol repository primitives -- Merkle Search Trees, CAR files, block storage.

## Install

```toml
[dependencies]
proto-blue-repo = "0.3"
```

## Exports

- `MstNode`
- `BlockMap`, `CidSet`
- `blocks_to_car`, `read_car`, `read_car_with_root`
- `RepoError`

## Usage

```rust
use proto_blue_repo::{MstNode, BlockMap, blocks_to_car, read_car};
use proto_blue_lex_data::LexValue;
use proto_blue_lex_cbor::cid_for_lex;

let cid = cid_for_lex(&LexValue::String("test".into())).unwrap();
let mst = MstNode::empty();
let mst = mst.add("app.bsky.feed.post/abc123", cid.clone()).unwrap();
assert_eq!(mst.leaves().len(), 1);
```

## Testing

Standard unit and round-trip tests live alongside the modules. The
proof pipeline additionally has property-based and fuzz coverage:

- `tests/property_tests.rs` — seven proptest cases over the
  `covering_proof` / `verify_proof` pair:
  - `proof_verifies_present_key` — soundness for present keys
  - `proof_rejects_wrong_value` — completeness against wrong-value
    claims
  - `proof_verifies_absence_for_missing_key` — absence proofs for
    non-members
  - `block_removal_never_produces_silent_false_accept` — removing
    any block from a valid proof either still verifies (block was
    redundant) or returns `Err(MissingBlock)`; never `Ok(false)`.
    This is the strict-superset / overestimate invariant.
  - `extra_blocks_do_not_change_verdict` — verifier ignores noise
    blocks
  - `tamper_cannot_force_wrong_value_acceptance` — no proof-byte
    mutation paired with a wrong-value claim yields `Ok(true)`
  - `covering_proof_is_superset_of_each_directional_proof` —
    structural: covering = key ∪ left-sibling ∪ right-sibling
- `proto-blue/fuzz/fuzz_targets/proof_construct_verify.rs` —
  adversarial mutation (drop / flip / insert) of proof block-maps;
  asserts no silent acceptance of forged-value claims regardless of
  mutation.

The audit's predicted "insufficient-blocks" bug class did not
surface — under deletion the verifier returns `Err(MissingBlock)`
correctly rather than a silent `Ok(false)`.

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/dollspace-gay/proto-blue) AT Protocol SDK for Rust.
