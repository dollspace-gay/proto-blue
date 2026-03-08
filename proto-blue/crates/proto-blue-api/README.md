# proto-blue-api

High-level AT Protocol client -- Agent, RichText, moderation, and generated types from 322 Lexicon schemas.

## Installation

```toml
[dependencies]
proto-blue-api = "0.1"
```

## Exports

- `Agent`, `Session`, `AgentError` -- authenticated API client
- `RichText`, `RichTextSegment`, `Facet`, `FacetFeature`, `detect_facets` -- rich text processing
- `ModerationDecision`, `ModerationOpts`, `check_muted_words`, `known_labels` -- content moderation
- `generated::` -- types generated from AT Protocol Lexicon schemas

## Usage

### Agent

```rust
use proto_blue_api::Agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = Agent::new("https://bsky.social")?;
    agent.login("alice.bsky.social", "app-password").await?;
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

## License

Licensed under MIT OR Apache-2.0.

Part of the [proto-blue](https://github.com/user/atproto-rs) AT Protocol SDK for Rust.
