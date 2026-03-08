//! AT Protocol code generator: reads Lexicon JSON schemas and outputs Rust source.
//!
//! Usage: proto-blue-codegen --lexicons <dir> --output <dir>

mod generator;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use proto_blue_lexicon::types::LexiconDoc;
use clap::Parser;

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
        panic!("Failed to create output dir: {}", e);
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

        // Check that generated code contains expected patterns
        for (path, content) in &files {
            if path.ends_with(".rs") && !path.ends_with("mod.rs") {
                assert!(
                    content.contains("use serde") || content.contains("pub mod"),
                    "Generated file {} should contain serde imports or module declarations",
                    path
                );
            }
        }
    }
}
