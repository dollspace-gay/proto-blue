# proto-blue-codegen

Code generator that produces Rust types from AT Protocol Lexicon JSON schemas.

This is a binary crate, not a library.

## Installation

```bash
cargo install proto-blue-codegen
```

## Usage

```bash
proto-blue-codegen --lexicons path/to/lexicons --output path/to/output
```

The generator reads Lexicon JSON schema files from the input directory and writes
Rust source files to the output directory. The generated types include records,
queries, procedures, and subscriptions defined by the AT Protocol.

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
