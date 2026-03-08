# proto-blue-syntax

Validated newtypes for AT Protocol identifiers.

## Installation

```toml
[dependencies]
proto-blue-syntax = "0.1"
```

## Exports

- `Did` -- Decentralized Identifier
- `Handle` -- AT Protocol handle
- `Nsid` -- Namespaced Identifier
- `AtUri` -- AT URI (`at://` scheme)
- `Tid` -- Timestamp Identifier
- `RecordKey` -- Record key
- `Datetime` -- AT Protocol datetime
- `AtIdentifier` -- Either a DID or a Handle
- `is_valid_language` -- Language tag validation

## Usage

```rust
use proto_blue_syntax::{Did, Handle, Nsid, AtUri, Tid, RecordKey};

let did = Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
let handle = Handle::new("alice.bsky.social").unwrap();
let nsid = Nsid::new("app.bsky.feed.post").unwrap();
let uri = AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/abc123").unwrap();
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
