# proto-blue-crypto

P-256 and K-256 signing, did:key encoding, SHA-256.

## Installation

```toml
[dependencies]
proto-blue-crypto = "0.1"
```

## Exports

- `P256Keypair` -- NIST P-256 keypair
- `K256Keypair` -- secp256k1 keypair
- `Signer` -- Signing trait
- `Verifier` -- Verification trait
- `Keypair` -- Common keypair trait
- `ExportableKeypair` -- Key export trait
- `format_did_key` -- Encode a public key as a `did:key` DID
- `parse_did_key` -- Decode a `did:key` DID into its components
- `sha256` -- SHA-256 hash
- `verify_signature` -- Standalone signature verification

## Usage

```rust
use proto_blue_crypto::{P256Keypair, Keypair, Signer, Verifier, format_did_key};

let kp = P256Keypair::generate();
let sig = kp.sign(b"hello world");
assert!(kp.verify(b"hello world", &sig).is_ok());
let did_key = format_did_key("ES256", &kp.public_key_compressed());
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
