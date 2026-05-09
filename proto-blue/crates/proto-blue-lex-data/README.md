# proto-blue-lex-data

Core data types for the AT Protocol Lexicon data model.

## Installation

```toml
[dependencies]
proto-blue-lex-data = "0.3"
```

## Exports

- `LexValue` -- Central enum with variants: `Null`, `Boolean`, `Integer`, `String`, `Bytes`, `Array`, `Map`, `Link`
- `Cid` -- Content Identifier
- `BlobRef` -- Blob reference descriptor
- `CidError` -- CID parsing error type
- `CBOR_CODEC`, `RAW_CODEC`, `SHA2_256` -- Multicodec constants

## CID representation

`Cid::digest` is a `[u8; 32]`, not a `Vec<u8>`. SHA-256-only is enforced as
a type invariant: there is no per-CID heap allocation, `is_dasl_compliant`
no longer needs to re-check the digest length, and `from_bytes` rejects
non-32-byte digests at the parse boundary with `InvalidDigestLength`.

`Cid::for_raw_hash` is now an infallible `const fn`:

```rust
use proto_blue_lex_data::Cid;
const ZERO_CID: Cid = Cid::for_raw_hash([0u8; 32]);
```

`Cid` intentionally does **not** derive `Copy`; existing call sites that
clone CIDs would otherwise trip `clippy::clone_on_copy` en masse.

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

Part of the [proto-blue](https://github.com/dollspace-gay/proto-blue) AT Protocol SDK for Rust.
