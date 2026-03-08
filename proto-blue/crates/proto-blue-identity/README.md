# proto-blue-identity

DID and handle resolution for the AT Protocol.

## Installation

```toml
[dependencies]
proto-blue-identity = "0.1"
```

## Exports

- `DidResolver` -- resolves `did:plc` and `did:web` documents
- `HandleResolver` -- resolves AT Protocol handles via DNS and HTTPS
- `IdResolver` -- combined DID + handle resolver
- `DidCache` (trait), `MemoryCache` -- pluggable caching layer
- `AtprotoData` -- parsed DID document fields (handle, PDS, signing key)
- `IdentityError` -- error type
- `ensure_atp_document` -- validates a DID document for AT Protocol use

## Usage

```rust
use proto_blue_identity::IdResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = IdResolver::new(None, 5000);
    let data = resolver.did.resolve_atproto_data(
        "did:plc:z72i7hdynmk6r22z27h6tvur", false
    ).await?;
    println!("Handle: {}", data.handle);
    println!("PDS: {}", data.pds);
    Ok(())
}
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
