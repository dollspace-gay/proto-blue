# proto-blue-interop-tests

Differential tests against the `@atproto/*` TypeScript SDK. Each
operation runs through both our Rust parser and the reference TS
implementation on the same fixture corpus, and the test fails if the
outputs disagree.

## Why

"Does not drift from `@atproto/*`" is the core value prop of this
SDK. Offline unit tests + fuzzers catch panics and internal-round-
trip bugs, but only a differential test against the reference
implementation catches semantic drift — where both sides accept the
same input but produce different results.

## Architecture

```
┌──────────────────┐   stdin JSON    ┌────────────────────────┐
│ Rust test binary │ ──────────────▶ │ node index.mjs         │
│ (differential.rs)│ ◀────────────── │ @atproto/syntax, etc.  │
└──────────────────┘   stdout JSON   └────────────────────────┘
```

The Rust test spawns a long-lived Node subprocess and sends
line-delimited JSON requests (`{op, input}`). The runner replies
with `{ok: true, value}` or `{ok: false, error, message}`. One
subprocess per test run keeps startup cost amortized.

## Operations covered

### `@atproto/syntax`

| op | Rust side | TS side |
|---|---|---|
| `normalize_handle` | `proto_blue_syntax::normalize_handle` | `normalizeHandle` |
| `is_valid_handle` | `Handle::new(..).is_ok()` | `ensureValidHandle` |
| `nsid_is_valid` | `Nsid::new(..).is_ok()` | `ensureValidNsid` |
| `aturi_components` | `AtUri::new + authority/collection/rkey/fragment` | `new AtUri(s)` fields |

### `@atproto/common-web`

| op | Rust side | TS side |
|---|---|---|
| `tid_from_time` | `Tid::from_timestamp` | `TID.fromTime` |
| `tid_from_str` | `Tid::is_valid` | `TID.is` |
| `s32_encode` | `proto_blue_common::s32_encode` | `s32encode` |
| `s32_decode` | `proto_blue_common::s32_decode` | `s32decode` |
| `grapheme_len` | `proto_blue_common::grapheme_len` | `graphemeLen` |
| `get_pds_endpoint` | `proto_blue_common::get_pds_endpoint` | `getPdsEndpoint` |

### `@atproto/crypto`

| op | Rust side | TS side |
|---|---|---|
| `did_key_parse` | `proto_blue_crypto::parse_did_key` | `parseDidKey` |

### `@atproto/lexicon`

| op | Rust side | TS side |
|---|---|---|
| `lexicon_validate_record` | `proto_blue_lexicon::validate_record` | `Lexicons.assertValidRecord` |

### `@atproto/common`

| op | Rust side | TS side |
|---|---|---|
| `cbor_encode_lexvalue` | `proto_blue_lex_cbor::encode` | `cborEncode` |
| `cid_for_lexvalue` | `proto_blue_lex_cbor::cid_for_lex` | `cidForCbor` |

Both ops drive the same 28 adversarial fixtures from
`differential_dag_cbor_encode` / `differential_cid_for_lexvalue`
and assert byte-exact hex parity / CID parity. Coverage includes
CBOR major-type-0/1 length-encoding boundaries (23, 24, 255, 256,
65535, u32::MAX, ±(2^53−1)), empty / multi-byte UTF-8 strings,
empty / short / long bytes (crossing the 24- and 256-byte CBOR
length thresholds), CID values, empty array / map, map keys
exercising length-then-lex sort + same-length lex tiebreak +
multi-byte UTF-8, a nested map (map-containing-array+map), and a
3-deep nested array.

Audit items 3–5 (MST root-CID parity, CAR layout parity, signed
commit construction parity) are tracked separately as #26, #27,
#28 — each requires substantial fixture-design work.

#### Wire-format design

The cross-impl wire format for the `@atproto/common` ops is a
tagged-enum JSON shape, **not** lex-json. Both sides build native
IPLD from it (`lexValueJsonToIpld()` on the TS side). The choice is
deliberate: routing fixtures through lex-json would couple dag-cbor
parity to lex-json's own correctness, and we want the codec parity
test to fail only when the codec drifts.

#### JS-safe-integer limit

Fixture corpus integers are capped at the JS-safe range
(`±(2^53−1)`). `i64::MAX` was tried during fixture tuning and lost
precision crossing the JSON wire format (it exceeds
`Number.MAX_SAFE_INTEGER` and round-trips through `f64`). This is
not a codec bug — it's a JSON wire-format limit. If we ever need to
exercise full-range `i64` we'll need a non-JSON transport for the
fixture itself.

Note: dispatch on the TS side is async (`cidForCbor` returns a
Promise), so the runner awaits per-op handlers.

Expand by adding fixtures + a new `dispatch` case in
`ts-runner/index.mjs` and a matching test in `tests/differential.rs`.

## Running locally

```bash
# One-time: install TS deps.
cd crates/proto-blue-interop-tests/ts-runner
npm ci   # or npm install if no lockfile yet

# Run the tests.
cd ..
TS_RUNNER_READY=1 cargo test -p proto-blue-interop-tests
```

Without `TS_RUNNER_READY=1` the tests no-op with a printed notice —
so `cargo test --workspace` on a fresh clone (no Node.js set up)
still passes.

## Pinning

`ts-runner/package.json` pins each `@atproto/*` package to a
specific minor version. Bump in a single PR; the test run will
surface any new divergences.

## Known TS SDK divergences

Three cases where our Rust implementation is **intentionally stricter
than** `@atproto/syntax` (as of the pinned version), because TS
diverges from the atproto spec. The differential tests above exclude
these from the main corpus and assert the divergence separately via
the `divergence_*` tests in `differential.rs` — if TS ever tightens
up, those tests flip and we can relax.

### 1. `TID.is(str)` accepts any 13-char string

TS impl:

```ts
static is(str: string): boolean {
  return dedash(str).length === TID_LEN
}
```

It's a length-only check. Passes on `"AAAAAAAAAAAAA"`, `"!!!!!!!!!!!!!"`,
or any 13 chars. The spec requires the base32-sortable charset
`[2-7a-z]`. Our `Tid::is_valid` enforces that correctly.

Impact: an app using TS's `TID.is` to pre-validate user-supplied
record keys could pass junk through to a PDS that then rejects it —
or worse, hand it to a sorting routine expecting base32-sortable
ordering.

### 2. `TID.fromTime(ts, clockid)` doesn't pad the timestamp

TS impl:

```ts
static fromTime(timestamp: number, clockid: number): TID {
  const str = `${s32encode(timestamp)}${s32encode(clockid).padStart(2, '2')}`
  return new TID(str)
}
```

`s32encode(timestamp)` produces a variable-length string — empty for
`0`, a few chars for small timestamps. Only the clockid portion is
padded. For any timestamp below `32^10 ≈ 1.1e15 μs` (roughly pre-
November 2004), the output is fewer than 13 chars, and TS's own
validator then rejects it.

Our `Tid::from_timestamp` always produces a 13-char string by
zero-padding (encoded as `'2'`, the base32-sortable `0` character)
at every digit position. Works for `timestamp == 0`.

Impact: any library using TS to fabricate TIDs for testing,
backfill, or deterministic reproduction against historical
timestamps gets invalid output. Our generator is usable across the
full timestamp range.

### 3. `AtUri` accepts non-JSON-Pointer fragments

The spec ([AT-URI scheme](https://atproto.com/specs/at-uri-scheme))
says fragments must be JSON Pointers — i.e. start with `/`. TS
accepts any fragment string (`#foo` works). Our regex requires the
leading slash.

Impact: a caller passing a non-JSON-pointer fragment from the TS
SDK to our Rust parser gets a parse error. In practice this is rare
because atproto AT-URIs with fragments are themselves rare, and
when they do appear they're typically JSON pointers per the spec.

### Pattern

In all three cases, our implementation follows the published spec
while TS's is laxer. We don't loosen to match TS because:

- Strictness is a backstop against invalid data leaking into our
  side of the ecosystem (records in repos, URIs in databases).
- The laxer TS behavior exists only on pure-function validators,
  not on the wire format — so real AT-URIs / TIDs / records flowing
  over the network between implementations are not affected.

If a real-world interop case surfaces where we need to parse TS-
generated output that fails our validator, we'll loosen on a case-
by-case basis and document the rationale here.
