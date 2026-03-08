# proto-blue-oauth

OAuth 2.0 client for AT Protocol with DPoP, PKCE, PAR, and token lifecycle.

## Installation

```toml
[dependencies]
proto-blue-oauth = "0.1"
```

## Exports

- `OAuthClient` -- main client for driving the OAuth flow
- `OAuthSession` -- authenticated session with automatic token refresh
- `OAuthClientMetadata`, `OAuthServerMetadata` -- metadata types
- `DpopKey`, `build_dpop_proof` -- DPoP (Demonstration of Proof-of-Possession) support
- `generate_pkce`, `PkceChallenge` -- PKCE challenge generation
- `TokenSet` -- access and refresh token pair
- `AuthState` -- in-progress authorization state
- `OAuthError` -- error type

## Usage

```rust
use proto_blue_oauth::{OAuthClient, OAuthClientMetadata};

let metadata = OAuthClientMetadata {
    client_id: "https://myapp.example.com/oauth/client-metadata.json".into(),
    redirect_uris: vec!["https://myapp.example.com/callback".into()],
    scope: Some("atproto transition:generic".into()),
    ..Default::default()
};
let client = OAuthClient::new(metadata);
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
