# proto-blue-xrpc

XRPC HTTP client for AT Protocol query and procedure calls.

## Install

```toml
[dependencies]
proto-blue-xrpc = "0.1"
```

## Exports

- `XrpcClient`
- `CallOptions`, `XrpcResponse`, `XrpcBody`
- `QueryParams`, `QueryValue`
- `HeadersMap`
- `HttpMethod`
- `XrpcError`

## Usage

```rust
use proto_blue_xrpc::XrpcClient;

let client = XrpcClient::new("https://bsky.social").unwrap();
let response = client.query("com.atproto.server.describeServer", None, None).await?;
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
