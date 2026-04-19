# proto-blue fuzz targets

Coverage-guided fuzzing harnesses for every byte-level parser in the
workspace. These targets consume arbitrary untrusted input (network
bytes, user strings) and assert that the parsers cannot panic and
that successful decodes round-trip to byte- or structurally-identical
values.

## Requirements

- Rust nightly (libFuzzer requires sanitizer support that's nightly-only).
- `cargo-fuzz` (install with `cargo install cargo-fuzz`).

## Running

```bash
# From the repository root:
cd fuzz

# One-shot run, time-bounded:
cargo +nightly fuzz run lex_cbor_decode -- -max_total_time=60

# Drive every target for 5 minutes each:
for t in lex_cbor_decode lex_cbor_canonical lex_json_strict \
         car_parse at_uri_parse handle_parse nsid_parse \
         did_parse tid_parse; do
  cargo +nightly fuzz run "$t" -- -max_total_time=300
done

# Minimize a reproducer that libFuzzer found:
cargo +nightly fuzz tmin <target> <path-to-crash-input>
```

## Targets

| Target | Asserts |
|---|---|
| `lex_cbor_decode` | Strict DAG-CBOR decoder never panics. Successful decodes re-encode byte-identically (canonical-form). |
| `lex_cbor_canonical` | Strict decode is a proper subset of lenient: if strict rejects but lenient accepts, re-encoding the lenient result must differ from input. |
| `lex_json_strict` | JSON→LexValue→JSON→LexValue preserves the value tree. |
| `car_parse` | `read_car` / `read_car_with_root` never panic; emitted blocks verify against their CIDs (enforced by the reader itself). |
| `at_uri_parse` | `AtUri::new` never panics; `Display` round-trips. |
| `handle_parse` | `Handle::new` + `normalize_handle` never panic; normalization idempotent; normalize-then-validate matches validate-on-normalized. |
| `nsid_parse` | `Nsid::new` never panics; `Display` round-trips. |
| `did_parse` | `Did::new` never panics; `Display` round-trips. |
| `tid_parse` | `Tid::new` never panics; `is_valid` matches; `timestamp_micros` never panics; string round-trip. |

## Corpus

Seed corpora live under `corpus/<target>/`. On first run, `cargo-fuzz`
will create an empty corpus directory and start accumulating
interesting inputs from its coverage-guided search. Committing a seed
corpus (e.g., existing known-good fixtures from the crate's tests)
jump-starts coverage.

## CI

A time-bounded fuzz job runs on every PR that touches one of the
fuzzable crates. 5 minutes per target, non-blocking — true findings
are rare enough that the signal-to-noise on blocking CI is poor, but
persistent results are triaged weekly.
