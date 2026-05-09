# wildscrape

Scrapes the [Lexicon Garden](https://lexicon.garden) indexed corpus into a
local directory, one JSON file per NSID. Used by `proto-blue-codegen`'s
`generate_types_from_wild_corpus` test (which skips silently when the
corpus directory is absent) to validate codegen against real-world
third-party lexicons rather than only the canonical 322 in
`proto-blue/lexicons/`.

The corpus itself is **not** committed. Lexicon Garden indexes lexicons
from arbitrary publishers, and proto-blue redistributing thousands of
third-party schemas isn't something we want to do without explicit
licensing. The scraper is the deterministic recipe; anyone (CI or a local
dev) can populate `lexicons.wild/` themselves.

## Usage

```bash
# From the proto-blue workspace root (the directory above this scripts/ tree).
cd scripts/wildscrape
cargo run --release -- --output ../../lexicons.wild
```

Flags:

- `--output <DIR>` — destination directory (default `lexicons.wild`).
- `--only <prefix1,prefix2,...>` — only scrape these top-level prefixes
  (default: every prefix listed at <https://lexicon.garden/browse>).
- `--delay-ms <MS>` — pause between schema fetches (default 50).
- `--limit <N>` — stop after writing N new lexicons this run (default 0,
  no limit). Useful for smoke-tests.

The scraper is **idempotent**: existing non-empty `lexicons.wild/<nsid>.json`
files are skipped, so you can stop and resume freely.

## What gets validated

Once `lexicons.wild/` is populated, run:

```bash
cargo test -p proto-blue-codegen generate_types_from_wild_corpus -- --nocapture
```

That test:

1. Loads every JSON file in `lexicons.wild/` as a `LexiconDoc`.
2. Runs the generator against the full set.
3. Asserts the generator never panics and that every emitted leaf file
   carries the canonical `//! Lexicon: <nsid>` header.

It does **not** rustc-compile the emitted output — that's a heavier check
that belongs in a separate nightly CI job (we're tracking it as a follow-up).
The current scope is `Generator::generate` doesn't crash and the output
shape is structurally sound, which is enough to surface the kind of bugs
the audit-comment review predicted (sanitization gaps, type collisions,
union-shape edge cases).

## Pipeline

For each NSID:

1. Discovery via `garden.lexicon.browse` XRPC, paginated per top-level
   prefix from <https://lexicon.garden/browse>.
2. Authority-DID resolution via the docs page at `/nsid/<nsid>` (extracted
   from the canonical `<link>` URL).
3. Schema fetch from `/lexicon/<did>/<nsid>` — the embedded
   `<pre id="lexiconSchema">` carries the full LexiconDoc as HTML-encoded
   JSON, which we decode and write to disk.

Two HTTP requests per NSID. With ~2,500 indexed lexicons that's roughly
five thousand fetches; the default 50ms inter-fetch delay keeps the run
polite (a few minutes end-to-end).
