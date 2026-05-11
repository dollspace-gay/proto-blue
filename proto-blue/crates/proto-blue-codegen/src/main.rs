#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

//! AT Protocol code generator: reads Lexicon JSON schemas and outputs Rust source.
//!
//! Usage: `proto-blue-codegen --lexicons <dir> --output <dir>`

mod generator;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use proto_blue_lexicon::types::LexiconDoc;

use generator::Generator;

#[derive(Parser, Debug)]
#[command(
    name = "atproto-codegen",
    about = "Generate Rust types from AT Protocol Lexicon schemas"
)]
struct Args {
    /// Path to the lexicons directory containing JSON schema files.
    #[arg(long)]
    lexicons: PathBuf,

    /// Output directory for generated Rust source files.
    #[arg(long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    // Load all lexicon JSON files
    let docs = load_lexicons(&args.lexicons);
    eprintln!("Loaded {} lexicon documents", docs.len());

    // Generate Rust source
    let generator = Generator::new(&docs);
    let files = generator.generate();
    eprintln!("Generated {} files", files.len());

    // Write output
    write_output(&args.output, &files);
    eprintln!("Output written to {}", args.output.display());
}

/// Load all .json lexicon files from a directory recursively.
fn load_lexicons(dir: &Path) -> Vec<LexiconDoc> {
    let mut docs = Vec::new();
    let mut paths = Vec::new();
    collect_json_files(dir, &mut paths);
    paths.sort();

    for path in paths {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("Failed to read {}: {}", path.display(), e);
        });
        match serde_json::from_str::<LexiconDoc>(&content) {
            Ok(doc) => docs.push(doc),
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", path.display(), e);
            }
        }
    }
    docs
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_json_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                out.push(path);
            }
        }
    }
}

/// Write generated files to the output directory.
fn write_output(output_dir: &Path, files: &BTreeMap<String, String>) {
    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        panic!("Failed to create output dir: {e}");
    });

    for (rel_path, content) in files {
        let full_path = output_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| {
                panic!("Failed to create dir {}: {}", parent.display(), e);
            });
        }
        fs::write(&full_path, content).unwrap_or_else(|e| {
            panic!("Failed to write {}: {}", full_path.display(), e);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_workspace_lexicons() {
        let lexicon_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lexicons");
        if !lexicon_dir.exists() {
            eprintln!("Skipping test: lexicons dir not found");
            return;
        }
        let docs = load_lexicons(&lexicon_dir);
        assert!(
            docs.len() > 300,
            "Expected 300+ lexicons, got {}",
            docs.len()
        );
    }

    #[test]
    fn generate_types_from_lexicons() {
        let lexicon_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lexicons");
        if !lexicon_dir.exists() {
            eprintln!("Skipping test: lexicons dir not found");
            return;
        }
        let docs = load_lexicons(&lexicon_dir);
        let generator = Generator::new(&docs);
        let files = generator.generate();

        // Should generate files for major namespaces
        assert!(!files.is_empty(), "Should generate at least some files");

        // Check for some key generated files
        let has_post = files.keys().any(|k| k.contains("app/bsky/feed/post"));
        assert!(has_post, "Should generate app.bsky.feed.post types");

        let has_profile = files.keys().any(|k| k.contains("app/bsky/actor"));
        assert!(has_profile, "Should generate app.bsky.actor types");

        // Every generated leaf file should be a real lexicon module:
        // its first lines are the header + `//! Lexicon: <nsid>` line
        // the generator writes. Some files won't carry a `use serde`
        // import (methods with no schema deserialize an opaque JSON
        // value) — the header is what proves the file was generated
        // from a document and isn't an empty placeholder.
        for (path, content) in &files {
            if path.ends_with(".rs") && !path.ends_with("mod.rs") {
                assert!(
                    content.contains("//! Lexicon:"),
                    "Generated file {path} should carry a `//! Lexicon:` header"
                );
            }
        }
    }

    /// Run the generator against the wild-lexicon corpus when it's been
    /// populated (`scripts/wildscrape/` is the discovery tool — see
    /// `<workspace-root>/scripts/wildscrape/README.md`). Skips silently if
    /// the corpus directory is absent so the per-PR test suite stays fast;
    /// nightly / on-demand runs populate `lexicons.wild/` and pick up any
    /// regressions in third-party-schema handling.
    ///
    /// Asserts only the codegen-doesn't-panic invariant (Generator::generate
    /// never panics on a valid LexiconDoc) plus structural sanity on the
    /// emitted files. We don't compile the output here — that requires
    /// invoking rustc against the synthetic crate, which is the natural
    /// scope of a follow-up CI job rather than `cargo test`.
    #[test]
    fn generate_types_from_wild_corpus() {
        let wild_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lexicons.wild");
        if !wild_dir.exists() {
            eprintln!(
                "Skipping wild-corpus test: {} not found.\n\
                 Populate it via:\n\
                 \n  cd scripts/wildscrape && cargo run --release -- --output ../../lexicons.wild\n",
                wild_dir.display(),
            );
            return;
        }

        let docs = load_lexicons(&wild_dir);
        assert!(
            !docs.is_empty(),
            "lexicons.wild/ exists but contains no parseable LexiconDocs",
        );
        eprintln!("Wild corpus: loaded {} lexicon document(s)", docs.len());

        let generator = Generator::new(&docs);
        let files = generator.generate();
        assert!(
            !files.is_empty(),
            "Generator produced no files for {}-doc wild corpus",
            docs.len(),
        );
        eprintln!(
            "Wild corpus: generated {} file(s) without panicking",
            files.len()
        );

        // Structural sanity: every leaf .rs file the generator emits has
        // the canonical lexicon header. A missing header means the file
        // came out of the generator with no document context — a bug
        // that's caught here even before the file is asked to compile.
        let mut headerless: Vec<&String> = Vec::new();
        for (path, content) in &files {
            if path.ends_with(".rs")
                && !path.ends_with("mod.rs")
                && !content.contains("//! Lexicon:")
            {
                headerless.push(path);
            }
        }
        assert!(
            headerless.is_empty(),
            "{} generated file(s) lack the `//! Lexicon:` header (sample: {:?})",
            headerless.len(),
            &headerless[..headerless.len().min(5)],
        );
    }

    /// rustc-compile the wild-corpus codegen output to catch second-order
    /// errors that the structural sanity check above misses (unresolved
    /// types, broken trait bounds, missing imports, malformed serde
    /// attributes, etc.).
    ///
    /// Synthesises a self-contained side-workspace crate under
    /// `target/wild-corpus-compile/` whose Cargo.toml mirrors
    /// `proto-blue-api`'s dependency shape, drops the generated tree into
    /// `src/generated/`, points `src/lib.rs` at it, and runs `cargo build`.
    /// Any rustc diagnostic fails the test.
    ///
    /// Marked `#[ignore]` because a wild corpus of a couple thousand
    /// lexicons compiles slowly. Run explicitly:
    ///   cargo test -p proto-blue-codegen wild_corpus_compiles -- --ignored --nocapture
    /// Skipped silently when `lexicons.wild/` is absent so it stays
    /// no-op for anyone who hasn't populated the corpus.
    #[test]
    #[ignore = "slow; requires a populated lexicons.wild/ corpus"]
    fn wild_corpus_compiles() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.join("../..").canonicalize().unwrap();
        let wild_dir = workspace_root.join("lexicons.wild");
        if !wild_dir.exists() {
            eprintln!(
                "Skipping wild_corpus_compiles: {} not found.",
                wild_dir.display()
            );
            return;
        }

        // Locate the side-workspace location and reset its `src/` so a
        // shrinking corpus can't leave stale generated files lying around.
        let test_crate_dir = workspace_root.join("target").join("wild-corpus-compile");
        let src_dir = test_crate_dir.join("src");
        if src_dir.exists() {
            fs::remove_dir_all(&src_dir).expect("clear stale src/");
        }
        fs::create_dir_all(&src_dir).expect("create src/");

        // Generate.
        let docs = load_lexicons(&wild_dir);
        assert!(!docs.is_empty(), "lexicons.wild/ has no parseable docs");
        let generator = Generator::new(&docs);
        let files = generator.generate();
        eprintln!(
            "wild_corpus_compiles: {} doc(s) → {} file(s); writing to {}",
            docs.len(),
            files.len(),
            test_crate_dir.display(),
        );
        for (rel, content) in &files {
            let dest = src_dir.join("generated").join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).expect("mkdir for generated file");
            }
            fs::write(&dest, content).expect("write generated file");
        }

        // Discover top-level NSID segments to re-export at crate root —
        // these are the modules the codegen-emitted top-level mod.rs
        // declares. We mirror them at `crate::<segment>` so cross-NSID
        // refs (`crate::app::bsky::...`) resolve.
        let top_mod_path = src_dir.join("generated").join("mod.rs");
        let top_mod = fs::read_to_string(&top_mod_path).expect("read generated/mod.rs");
        let segments: Vec<String> = top_mod
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                t.strip_prefix("pub mod ")
                    .and_then(|s| s.strip_suffix(';'))
                    .map(str::to_string)
            })
            .collect();
        assert!(
            !segments.is_empty(),
            "generated/mod.rs declares no top-level segments"
        );

        // Synthesise lib.rs.
        let mut lib_rs = String::from(
            "//! Synthesised wild-corpus compile target. Auto-generated; do not edit.\n\
             #![allow(unused_imports)]\n\
             #![allow(dead_code)]\n\
             pub mod generated;\n",
        );
        for seg in &segments {
            lib_rs.push_str(&format!("pub use generated::{seg};\n"));
        }
        fs::write(src_dir.join("lib.rs"), lib_rs).expect("write lib.rs");

        // Synthesise Cargo.toml. Path deps point at the workspace crates
        // by absolute path; `[workspace] members = ["."]` excludes us
        // from the parent workspace so the parent's build state isn't
        // disturbed.
        let crates = workspace_root.join("crates");
        let cargo_toml = format!(
            r#"[package]
name = "proto-blue-wild-corpus-compile"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]
members = ["."]

[lib]
path = "src/lib.rs"

[dependencies]
proto-blue-common = {{ path = "{common}" }}
proto-blue-syntax = {{ path = "{syntax}" }}
proto-blue-lex-data = {{ path = "{lex_data}" }}
proto-blue-lexicon = {{ path = "{lexicon}" }}
proto-blue-xrpc = {{ path = "{xrpc}", default-features = false, features = ["fetch-reqwest"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
chrono = {{ version = "0.4", features = ["serde"] }}
thiserror = "1"
"#,
            common = crates.join("proto-blue-common").display(),
            syntax = crates.join("proto-blue-syntax").display(),
            lex_data = crates.join("proto-blue-lex-data").display(),
            lexicon = crates.join("proto-blue-lexicon").display(),
            xrpc = crates.join("proto-blue-xrpc").display(),
        );
        fs::write(test_crate_dir.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");

        // Build. Capture stderr so a rustc diagnostic surfaces in the
        // test failure rather than getting lost.
        let output = std::process::Command::new("cargo")
            .arg("build")
            .arg("--quiet")
            .current_dir(&test_crate_dir)
            .output()
            .expect("invoke cargo build");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!("Wild corpus failed to compile.\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}",);
        }
        eprintln!("wild_corpus_compiles: OK");
    }
}
