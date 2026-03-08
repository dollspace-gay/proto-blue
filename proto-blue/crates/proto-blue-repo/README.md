# proto-blue-repo

AT Protocol repository primitives -- Merkle Search Trees, CAR files, block storage.

## Install

```toml
[dependencies]
proto-blue-repo = "0.1"
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

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
