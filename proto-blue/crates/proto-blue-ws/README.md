# proto-blue-ws

Auto-reconnecting WebSocket client for AT Protocol event streams.

## Install

```toml
[dependencies]
proto-blue-ws = "0.1"
```

## Exports

- `WebSocketKeepAlive`, `WebSocketKeepAliveOpts`
- `CloseCode`, `DisconnectError`, `WsError`
- `is_reconnectable`

## Usage

```rust
use proto_blue_ws::{WebSocketKeepAlive, WebSocketKeepAliveOpts};

let opts = WebSocketKeepAliveOpts {
    url: "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos".into(),
    ..Default::default()
};
let ws = WebSocketKeepAlive::new(opts);
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
