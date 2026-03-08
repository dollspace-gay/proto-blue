# proto-blue-common

Shared utilities for the AT Protocol: TID generation, DID document parsing, retry, grapheme counting.

## Install

```toml
[dependencies]
proto-blue-common = "0.1"
```

## Exports

- `DidDocument`, `VerificationMethod`, `Service`, `SigningKey`
- `get_did`, `get_handle`, `get_signing_key`, `get_pds_endpoint`, `parse_did_document`
- `next_tid`
- `grapheme_len`, `utf8_len`
- `RetryOptions`, `retry`
- `SECOND`, `MINUTE`, `HOUR`, `DAY`

## Usage

```rust
use proto_blue_common::{grapheme_len, next_tid, HOUR, DAY};

assert_eq!(grapheme_len("Hello 🌍"), 7);
let tid = next_tid(None);
println!("Generated TID: {tid}");
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
