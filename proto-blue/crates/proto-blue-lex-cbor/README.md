# proto-blue-lex-cbor

DAG-CBOR encoding/decoding with CID tag 42 for AT Protocol.

## Installation

```toml
[dependencies]
proto-blue-lex-cbor = "0.1"
```

This crate depends on `proto-blue-lex-data` for the `LexValue` type.

## Exports

- `encode` -- Serialize a `LexValue` to DAG-CBOR bytes
- `decode` -- Deserialize DAG-CBOR bytes into a `LexValue`
- `decode_all` -- Decode and verify all bytes are consumed
- `cid_for_lex` -- Compute the CID of a `LexValue`
- `CborError` -- Error type for encoding/decoding failures

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

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
