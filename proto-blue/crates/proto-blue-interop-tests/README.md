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

| op | Rust side | TS side |
|---|---|---|
| `normalize_handle` | `proto_blue_syntax::normalize_handle` | `@atproto/syntax.normalizeHandle` |
| `is_valid_handle` | `Handle::new(..).is_ok()` | `ensureValidHandle` |
| `nsid_is_valid` | `Nsid::new(..).is_ok()` | `ensureValidNsid` |
| `aturi_components` | `AtUri::new + authority/collection/rkey/fragment` | `new AtUri(s)` fields |

Expand by adding fixtures + a new `dispatch` case in `ts-runner/index.mjs`
and a matching test in `tests/differential.rs`.

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

`ts-runner/package.json` pins `@atproto/syntax` to a specific minor
version. Bump it in a single PR; the test run will surface any new
divergences.
