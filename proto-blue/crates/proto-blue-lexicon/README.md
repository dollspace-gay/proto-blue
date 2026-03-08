# proto-blue-lexicon

AT Protocol Lexicon schema system -- types, registry, and validation.

## Install

```toml
[dependencies]
proto-blue-lexicon = "0.1"
```

## Exports

- `Lexicons`
- `LexiconDoc`, `LexUserType`, `LexRecord`, `LexObject`
- `ValidationError`
- `validate_record`, `validate_object`, `validate_value`

## Usage

```rust
use proto_blue_lexicon::Lexicons;

let mut registry = Lexicons::new();
// Load schema documents from JSON
// registry.add(doc);
```

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
