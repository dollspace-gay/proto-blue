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

## Output format

- String fields with a recognised `format` (`did`, `handle`, `at-identifier`,
  `nsid`, `at-uri`, `tid`, `record-key`, `datetime`) emit as the corresponding
  validated newtype from `proto_blue_syntax` rather than `String`. XRPC param
  helpers (`to_query_params`, `params_from_ctx`) round-trip through
  `Display::to_string` and `<Newtype>::new(&str)?`.
- Inline unions in property position emit a synthesised sum-type enum named
  `<TypeName><PropertyPascalCase>Refs` (or `…ItemRefs` for `Array<Union>`),
  replacing the previous `serde_json::Value` fallback.
- Reserved-keyword sanitization covers Rust 2024 edition keywords (`gen`,
  `try`), reserved-for-future words (`abstract`, `become`, `box`, `do`,
  `final`, `macro`, `override`, `priv`, `typeof`, `unsized`, `virtual`,
  `yield`), and `union` / `dyn`.
- Sibling-name collisions after sanitization are disambiguated with
  `_2`/`_3`/... suffixes and a doc comment recording the collision, instead
  of silently emitting invalid Rust.
- An NSID that is both a leaf and a parent (e.g. `com.example.foo` and
  `com.example.foo.bar`) writes leaf content into `<path>/mod.rs` with the
  child `pub mod` declarations appended, fixing a previous E0761
  ambiguous-module-file error.
- NSID segments containing dashes emit
  `#[path = "<orig>/mod.rs"] pub mod <snake>;` so the on-disk path and the
  Rust identifier agree.
- Multi-line lexicon descriptions get `///` continuation per line.

## Tests

The crate ships two opt-in tests for catching second-order regressions
against a real-world Lexicon corpus. Drop a checkout of the wider
ecosystem's lexicons into `lexicons.wild/` at the workspace root to enable
them:

- `generate_types_from_wild_corpus` runs the codegen against the corpus and
  asserts no panics plus structural sanity.
- `wild_corpus_compiles` (`#[ignore]` by default) synthesises a side
  workspace crate from the generated output and runs `cargo build` against
  it, catching errors that only surface at rustc time.

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/dollspace-gay/proto-blue) AT Protocol SDK for Rust.
