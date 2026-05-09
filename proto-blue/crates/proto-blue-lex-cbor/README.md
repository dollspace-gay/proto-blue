# proto-blue-lex-cbor

DAG-CBOR encoding/decoding with CID tag 42 for AT Protocol.

## Installation

```toml
[dependencies]
proto-blue-lex-cbor = "0.3"
```

This crate depends on `proto-blue-lex-data` for the `LexValue` type.

## Exports

- `encode` -- Serialize a `LexValue` to DAG-CBOR bytes
- `decode` -- Deserialize DAG-CBOR bytes into a `LexValue`
- `decode_all` -- Decode and verify all bytes are consumed
- `cid_for_lex` -- Compute the CID of a `LexValue`
- `CborError` -- Error type for encoding/decoding failures

## Float handling

Decoding (including `decode_lenient` and `cbor_to_lex`) rejects all CBOR
floats unconditionally with `CborError::FloatNotSupported`. Per the
dag-cbor spec, integers MUST be encoded as CBOR integer types: a
float-encoded integer is a wire-format spec violation, and earlier
versions that silently coerced integral floats (`f.fract() == 0.0`) to
`LexValue::Integer` masked encoder bugs.

The implementation continues to wrap `ciborium` with hand-written
canonical-form enforcement rather than depending on
`serde_ipld_dagcbor` -- because `LexValue` has no native `serde` impl,
the migration would replace ~20 lines of canonical-form checks with
~80-150 lines of custom `Serialize`/`Deserialize`. See the module-level
doc comment in `src/encoding.rs` for the full rationale.

## Usage

```rust
use proto_blue_lex_data::LexValue;
use proto_blue_lex_cbor::{encode, decode, cid_for_lex};
use std::collections::BTreeMap;

let mut map = BTreeMap::new();
map.insert("hello".into(), LexValue::String("world".into()));
let value = LexValue::Map(map);
let bytes = encode(&value).unwrap();
let decoded = decode(&bytes).unwrap();
let cid = cid_for_lex(&value).unwrap();
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/dollspace-gay/proto-blue) AT Protocol SDK for Rust.
