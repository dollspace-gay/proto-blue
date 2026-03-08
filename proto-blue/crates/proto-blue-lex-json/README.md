# proto-blue-lex-json

JSON conversion for AT Protocol LexValue with `$link` and `$bytes` encoding.

## Installation

```toml
[dependencies]
proto-blue-lex-json = "0.1"
```

This crate depends on `proto-blue-lex-data` for the `LexValue` type.

## Exports

- `lex_to_json` -- Convert a `LexValue` to a `serde_json::Value`
- `json_to_lex` -- Convert a `serde_json::Value` to a `LexValue`
- `lex_stringify` -- Serialize a `LexValue` to a JSON string
- `lex_parse` -- Parse a JSON string into a `LexValue`
- `JsonError` -- Error type for conversion failures

## Usage

```rust
use proto_blue_lex_data::LexValue;
use proto_blue_lex_json::{lex_to_json, json_to_lex, lex_stringify, lex_parse};
use std::collections::BTreeMap;

let mut map = BTreeMap::new();
map.insert("text".into(), LexValue::String("Hello!".into()));
let value = LexValue::Map(map);
let json = lex_to_json(&value);
let s = lex_stringify(&value);
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
