# proto-blue-lex-data

Core data types for the AT Protocol Lexicon data model.

## Installation

```toml
[dependencies]
proto-blue-lex-data = "0.1"
```

## Exports

- `LexValue` -- Central enum with variants: `Null`, `Boolean`, `Integer`, `String`, `Bytes`, `Array`, `Map`, `Link`
- `Cid` -- Content Identifier
- `BlobRef` -- Blob reference descriptor
- `CidError` -- CID parsing error type
- `CBOR_CODEC`, `RAW_CODEC`, `SHA2_256` -- Multicodec constants

## Usage

```rust
use proto_blue_lex_data::{Cid, LexValue};
use std::collections::BTreeMap;

let cid: Cid = "bafyreif75igchtxu635l343pgwjxxtfdv5ngckj3khwzzpss4cv6dwvyeq".parse().unwrap();
let mut map = BTreeMap::new();
map.insert("name".into(), LexValue::String("Alice".into()));
let value = LexValue::Map(map);
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
