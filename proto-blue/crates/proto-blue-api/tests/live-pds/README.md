# live-pds integration tests

End-to-end tests that dial a real PDS. Catches drift between our SDK
and the live network — things offline harnesses can't reach:
server-side behaviour the TS SDK encodes implicitly, rate-limit edge
cases, real cert chains, timing-sensitive session invalidation.

Tests live in `../live_pds.rs`; this directory is the home for any
supporting fixtures / configs added later.

## Opt-in

Every test is `#[ignore]`'d by default and additionally early-returns
when any required env var is missing. Two independent gates so a
fresh clone stays network-free under `cargo test --workspace`.

Required env:

| Var | What |
|---|---|
| `PDS_URL` | Base URL of the PDS (e.g. `https://bsky.social`). |
| `PDS_TEST_HANDLE` | Handle of a throwaway account. |
| `PDS_TEST_APP_PASSWORD` | App password for that account. |

## Running

```bash
export PDS_URL=https://bsky.social
export PDS_TEST_HANDLE=throwaway.test
export PDS_TEST_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
cargo test -p proto-blue-api --test live_pds -- --ignored --test-threads=1
```

`--test-threads=1` is load-bearing — running tests in parallel would
hammer the account's rate-limit budget.

## Safety

- Use a **dedicated throwaway account**. Never a real user's.
- Every record mutation is cleaned up before the test returns. No
  `#[should_panic]` tests; a panic could orphan a record.
- The `post_then_delete_roundtrip` test posts literally
  "proto-blue live-pds test @ <RFC3339>" — so if test garbage does
  leak, it's easy to spot and script-delete.

## Tests present

- `session_lifecycle_roundtrip` — login / session()/ refresh /
  logout / session-cleared.
- `post_then_delete_roundtrip` — `Agent::post` + `Agent::delete_post`
  against `app.bsky.feed.post`.

## Follow-ups

The issue (#59) scopes seven suites total; these two are the first
two. Remaining to add as dedicated `#[test]` fns:

- Firehose subscribe + receive-≥10-frames + cursor-resume.
- OAuth authorize / callback / refresh / revoke (against a staging AS).
- Rate-limit hammer → 429 + RateLimit-* headers.
- Blob upload / getBlob byte-equality.
- Identity resolution for a known handle.

## CI

`.github/workflows/live-pds.yml` — nightly cron at 04:00 UTC, reads
secrets from the repo's GitHub secret store. Non-blocking
(`continue-on-error: true`) because live-PDS flake shouldn't fail
unrelated PRs.
