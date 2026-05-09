//! Scrape the full lexicon.garden corpus to a local directory.
//!
//! Output layout: `<output>/<nsid>.json`, one file per lexicon, containing
//! the full `com.atproto.lexicon.schema` record JSON (with `id`, `defs`,
//! `lexicon`, and `$type` fields). Idempotent — already-downloaded files
//! are skipped on rerun.
//!
//! Pipeline per run:
//! 1. Fetch `/browse` HTML → enumerate top-level NSID prefixes.
//! 2. For each prefix, paginate `garden.lexicon.browse` (XRPC) to collect
//!    every NSID under that prefix.
//! 3. For each NSID:
//!    - Fetch `/nsid/<nsid>` (docs page) and extract the authority DID
//!      from the canonical URL.
//!    - Fetch `/lexicon/<did>/<nsid>` (schema page) and extract the full
//!      lexicon JSON from the embedded `<pre id="lexiconSchema">` block.
//!    - HTML-decode and write to `<output>/<nsid>.json`.
//!
//! This binary is a developer tool — anyone wanting the wild corpus runs
//! it once locally; the corpus itself is gitignored to avoid redistributing
//! third-party schemas without explicit licensing.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;

const USER_AGENT: &str = concat!(
    "proto-blue-wildscrape/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/dollspace-gay/proto-blue)",
);
const BASE: &str = "https://lexicon.garden";

#[derive(Parser, Debug)]
#[command(
    name = "wildscrape",
    about = "Scrape lexicon.garden's indexed corpus into a local directory."
)]
struct Args {
    /// Output directory for one-JSON-file-per-NSID schema dump.
    #[arg(long, default_value = "lexicons.wild")]
    output: PathBuf,

    /// Only scrape lexicons under one or more comma-separated TLD prefixes
    /// (e.g. `app,community`). When omitted, every prefix listed at /browse
    /// is scraped.
    #[arg(long)]
    only: Option<String>,

    /// Pause this many milliseconds between schema fetches to be polite.
    #[arg(long, default_value_t = 50)]
    delay_ms: u64,

    /// Stop after this many lexicons have been written this run (useful
    /// for smoke-tests). 0 = no limit.
    #[arg(long, default_value_t = 0)]
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct BrowseResponse {
    lexicons: Vec<String>,
    #[serde(default)]
    cursor: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.output)
        .with_context(|| format!("Failed to create {}", args.output.display()))?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let prefixes: Vec<String> = match args.only {
        Some(spec) => spec
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => discover_prefixes(&client)?,
    };
    eprintln!(
        "Scraping {} prefix(es) into {}",
        prefixes.len(),
        args.output.display()
    );

    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut errored = 0usize;
    'outer: for prefix in &prefixes {
        let nsids = match list_nsids_in_prefix(&client, prefix) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  prefix {prefix}: list error: {e:#}");
                errored += 1;
                continue;
            }
        };
        eprintln!("  {prefix}: {} lexicon(s)", nsids.len());

        for nsid in nsids {
            let dest = args.output.join(format!("{nsid}.json"));
            if dest.exists() && fs::metadata(&dest).map(|m| m.len() > 0).unwrap_or(false) {
                skipped += 1;
                continue;
            }

            match fetch_one(&client, &nsid) {
                Ok(json) => {
                    if let Err(e) = fs::write(&dest, &json) {
                        eprintln!("    {nsid}: write error: {e}");
                        errored += 1;
                    } else {
                        written += 1;
                        if args.limit > 0 && written >= args.limit {
                            eprintln!("(limit reached, stopping)");
                            break 'outer;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("    {nsid}: {e:#}");
                    errored += 1;
                }
            }
            if args.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(args.delay_ms));
            }
        }
    }

    eprintln!("\nDone. {written} new, {skipped} skipped (already present), {errored} errored.",);
    Ok(())
}

/// Pull the list of top-level NSID prefixes from `/browse`.
fn discover_prefixes(client: &reqwest::blocking::Client) -> Result<Vec<String>> {
    let html = client
        .get(format!("{BASE}/browse"))
        .send()
        .context("GET /browse")?
        .error_for_status()?
        .text()?;
    let re = Regex::new(r#"href="/browse/([a-z0-9][a-z0-9-]*)""#)?;
    let mut found: Vec<String> = re.captures_iter(&html).map(|c| c[1].to_string()).collect();
    found.sort();
    found.dedup();
    if found.is_empty() {
        bail!("Could not extract any TLD prefixes from /browse");
    }
    Ok(found)
}

/// Page through `garden.lexicon.browse?prefix=<prefix>` until the cursor is
/// exhausted, returning every NSID seen.
fn list_nsids_in_prefix(client: &reqwest::blocking::Client, prefix: &str) -> Result<Vec<String>> {
    let mut all: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut req = client
            .get(format!("{BASE}/xrpc/garden.lexicon.browse"))
            .query(&[("prefix", prefix), ("limit", "100")]);
        if let Some(c) = &cursor {
            req = req.query(&[("cursor", c.as_str())]);
        }
        let resp: BrowseResponse = req
            .send()
            .with_context(|| format!("browse?prefix={prefix}"))?
            .error_for_status()?
            .json()
            .context("decoding browse response")?;
        let next_cursor = resp.cursor;
        let len_this_page = resp.lexicons.len();
        all.extend(resp.lexicons);
        match next_cursor {
            Some(c) if !c.is_empty() && len_this_page > 0 => cursor = Some(c),
            _ => break,
        }
    }
    Ok(all)
}

/// Fetch the docs page for `nsid`, extract its authority DID, then fetch the
/// schema page and return the embedded LexiconDoc JSON (HTML-decoded, ready
/// to write to disk).
fn fetch_one(client: &reqwest::blocking::Client, nsid: &str) -> Result<String> {
    let docs_html = client
        .get(format!("{BASE}/nsid/{nsid}"))
        .send()
        .with_context(|| format!("GET /nsid/{nsid}"))?
        .error_for_status()?
        .text()?;
    let did = extract_authority_did(&docs_html)
        .with_context(|| format!("could not extract DID for {nsid}"))?;

    let schema_html = client
        .get(format!("{BASE}/lexicon/{did}/{nsid}"))
        .send()
        .with_context(|| format!("GET /lexicon/{did}/{nsid}"))?
        .error_for_status()?
        .text()?;
    let raw = extract_lexicon_schema_json(&schema_html)
        .with_context(|| format!("could not extract schema JSON for {nsid}"))?;

    // Validate it parses as JSON before writing — surfaces extraction bugs
    // early rather than littering the corpus with malformed files.
    serde_json::from_str::<serde_json::Value>(&raw)
        .with_context(|| format!("schema for {nsid} did not parse as JSON"))?;
    Ok(raw)
}

/// Pull the authority DID out of the docs page HTML.
///
/// Look for the `<link rel="canonical" href="/lexicon/<did>/<nsid>/...">`
/// (HTML-encoded) since that's the most stable place lexicon.garden
/// commits to the canonical pair.
fn extract_authority_did(html: &str) -> Result<String> {
    // The href in HTML is encoded as `&#x2f;` for `/`. Match either form.
    let candidates = [
        Regex::new(
            r#"<link\s+rel="canonical"\s+href="https://lexicon\.garden/lexicon/(did:[^/]+)/[^/"]+"#,
        )?,
        Regex::new(
            r#"<link\s+rel="canonical"\s+href="https:&#x2f;&#x2f;lexicon\.garden&#x2f;lexicon&#x2f;(did:[^&]+)&#x2f;"#,
        )?,
        Regex::new(r#"og:url"\s+content="https://lexicon\.garden/lexicon/(did:[^/]+)/"#)?,
        Regex::new(
            r#"og:url"\s+content="https:&#x2f;&#x2f;lexicon\.garden&#x2f;lexicon&#x2f;(did:[^&]+)&#x2f;"#,
        )?,
    ];
    for re in &candidates {
        if let Some(c) = re.captures(html) {
            return Ok(c[1].to_string());
        }
    }
    Err(anyhow!("no canonical DID found in HTML"))
}

/// Extract and HTML-decode the JSON inside `<pre id="lexiconSchema">…</pre>`.
fn extract_lexicon_schema_json(html: &str) -> Result<String> {
    let re = Regex::new(r#"<pre\s+id="lexiconSchema"[^>]*>(?s)(.*?)</pre>"#)?;
    let caps = re
        .captures(html)
        .ok_or_else(|| anyhow!("<pre id=\"lexiconSchema\"> not found"))?;
    let raw = &caps[1];
    Ok(html_decode(raw))
}

/// Decode the HTML entities the schema page uses on its embedded JSON.
///
/// The page emits a small fixed set: `&quot;`, `&amp;`, `&lt;`, `&gt;`,
/// `&#x2f;`, and numeric character references. Decoding these is enough to
/// recover the original JSON the server received.
fn html_decode(s: &str) -> String {
    let named = [
        ("&quot;", "\""),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&#x2f;", "/"),
        ("&#x27;", "'"),
        ("&apos;", "'"),
        ("&nbsp;", " "),
    ];
    let mut out = s.to_string();
    for (k, v) in named {
        out = out.replace(k, v);
    }
    // Numeric character references — &#NN; (decimal) and &#xHH; (hex).
    let dec = Regex::new(r"&#(\d+);").unwrap();
    out = dec
        .replace_all(&out, |c: &regex::Captures| {
            c[1].parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map_or_else(|| c[0].to_string(), |ch| ch.to_string())
        })
        .into_owned();
    let hex = Regex::new(r"&#[xX]([0-9a-fA-F]+);").unwrap();
    out = hex
        .replace_all(&out, |c: &regex::Captures| {
            u32::from_str_radix(&c[1], 16)
                .ok()
                .and_then(char::from_u32)
                .map_or_else(|| c[0].to_string(), |ch| ch.to_string())
        })
        .into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_decode_basic_entities() {
        assert_eq!(html_decode("&quot;hello&quot;"), "\"hello\"");
        assert_eq!(html_decode("a&#x2f;b"), "a/b");
        assert_eq!(html_decode("&amp;quot;"), "&quot;"); // amp first wins
        assert_eq!(html_decode("&#65;"), "A");
        assert_eq!(html_decode("&#x41;"), "A");
    }

    #[test]
    fn extract_authority_did_from_canonical_url() {
        let html = r#"<link rel="canonical" href="https://lexicon.garden/lexicon/did:plc:abcdef/app.example.foo">"#;
        assert_eq!(extract_authority_did(html).unwrap(), "did:plc:abcdef");
    }

    #[test]
    fn extract_authority_did_from_html_encoded_canonical() {
        let html = r#"<link rel="canonical" href="https:&#x2f;&#x2f;lexicon.garden&#x2f;lexicon&#x2f;did:plc:abcdef&#x2f;app.example.foo">"#;
        assert_eq!(extract_authority_did(html).unwrap(), "did:plc:abcdef");
    }

    #[test]
    fn extract_lexicon_schema_pre_block() {
        let html = r#"<pre id="lexiconSchema" class="language-json">{
  &quot;id&quot;: &quot;app.example.foo&quot;,
  &quot;lexicon&quot;: 1
}</pre>"#;
        let extracted = extract_lexicon_schema_json(html).unwrap();
        let v: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        assert_eq!(v["id"], "app.example.foo");
        assert_eq!(v["lexicon"], 1);
    }
}
