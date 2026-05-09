# proto-blue-api

High-level AT Protocol client -- Agent, RichText, moderation, and generated types from 322 Lexicon schemas.

## Installation

```toml
[dependencies]
proto-blue-api = "0.3"
```

## Exports

- `Agent`, `Session`, `AgentError` -- authenticated API client
- `RichText`, `RichTextSegment`, `Facet`, `FacetFeature`, `detect_facets` -- rich text processing
- `ModerationDecision`, `ModerationOpts`, `check_muted_words`, `known_labels` -- content moderation
- `generated::` -- types generated from AT Protocol Lexicon schemas

Identifier types (`Did`, `Handle`, `AtUri`, `AtIdentifier`, ...) live in `proto_blue_syntax`; CIDs live in `proto_blue_lex_data`. The Agent surface and generated XRPC parameters take these by reference instead of `&str`.

## Usage

### Agent

```rust
use proto_blue_api::Agent;
use proto_blue_syntax::AtIdentifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = Agent::new("https://bsky.social")?;
    let ident = AtIdentifier::new("alice.bsky.social")?;
    agent.login(&ident, "app-password").await?;
    agent.post("Hello from Rust!", None, None).await?;
    Ok(())
}
```

### RichText

```rust
use proto_blue_api::rich_text::{RichText, FacetFeature};

let mut rt = RichText::new("Hello @alice.bsky.social! #atproto".to_string(), None);
rt.detect_facets();
for seg in &rt.segments() {
    if let Some(facet) = &seg.facet {
        match &facet.features[0] {
            FacetFeature::Mention { did } => println!("@{did}"),
            FacetFeature::Link { uri } => println!("{uri}"),
            FacetFeature::Tag { tag } => println!("#{tag}"),
        }
    }
}
```

## Migrating from 0.2.x

v0.3.0 replaces `String`/`&str` identifier arguments and fields with validated newtypes from `proto_blue_syntax`. Wire format is unchanged; callers construct typed values explicitly.

```rust
use proto_blue_syntax::{Did, Handle, AtUri, AtIdentifier};
use proto_blue_lex_data::Cid;
```

Common swaps:

- `agent.login("alice.bsky.social", pw)` -> `agent.login(&AtIdentifier::new("alice.bsky.social")?, pw)`
- `agent.resolve_handle("alice.bsky.social")` -> `agent.resolve_handle(&Handle::new("alice.bsky.social")?)` (now returns `Did`)
- `agent.follow(&did_str, ...)` -> `agent.follow(&Did::new(did_str)?, ...)`
- `agent.like(&uri_str, &cid_str, ...)` -> `agent.like(&AtUri::new(uri_str)?, &Cid::new(cid_str)?, ...)`
- `agent.delete_post(&uri_str)` (and `delete_like` / `delete_repost` / `delete_follow`) -> pass `&AtUri`
- `agent.get_post_thread(&uri_str, ...)` -> `&AtUri`; `agent.get_profile(&actor_str, ...)` -> `&AtIdentifier`
- `agent.create_account(&handle_str, pw, email, ...)` -> `&Handle`
- `Session.did: String` -> `Did`; `Session.handle: String` -> `Handle`; `LabelerOpts.did: String` -> `Did`. `access_jwt`, `refresh_jwt`, and `email` remain `String`.
- `Agent::did() -> Option<Did>` (was `Option<String>`).

`resume_session` and `resolve_handle` now validate server-returned DIDs through `Did::new`; a malformed DID surfaces as `AgentError::Other(...)` instead of being stored verbatim.

Generated XRPC method parameters whose lexicons declare a `format`-typed string (did, handle, at-uri, cid, nsid, ...) now expose the corresponding newtype on the request struct.

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/dollspace-gay/proto-blue) AT Protocol SDK for Rust.
