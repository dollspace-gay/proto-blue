//! Lexicons registry — manages a collection of lexicon documents.

use std::collections::HashMap;

use crate::error::LexiconError;
use crate::types::{LexUserType, LexiconDoc};

/// Registry of lexicon documents and their definitions.
///
/// Provides methods to add lexicon documents, look up definitions,
/// and iterate over all registered lexicons.
pub struct Lexicons {
    docs: HashMap<String, LexiconDoc>,
    defs: HashMap<String, LexUserType>,
}

impl Lexicons {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Lexicons {
            docs: HashMap::new(),
            defs: HashMap::new(),
        }
    }

    /// Add a lexicon document to the registry.
    ///
    /// All definitions in the document are registered and their
    /// references are resolved to absolute URIs.
    pub fn add(&mut self, doc: LexiconDoc) -> Result<(), LexiconError> {
        let nsid = &doc.id;

        if self.docs.contains_key(nsid) {
            return Err(LexiconError::DuplicateLexicon(nsid.clone()));
        }

        // Register each definition
        for (def_id, def) in &doc.defs {
            let uri = to_lex_uri(nsid, def_id);

            // Resolve refs in the def to absolute URIs
            let mut resolved_def = def.clone();
            resolve_refs(&mut resolved_def, nsid);

            self.defs.insert(uri.clone(), resolved_def.clone());

            // Also register "main" without the fragment
            if def_id == "main" {
                let short_uri = format!("lex:{nsid}");
                self.defs.insert(short_uri, resolved_def);
            }
        }

        self.docs.insert(nsid.clone(), doc);
        Ok(())
    }

    /// Add a lexicon document from JSON.
    pub fn add_from_json(&mut self, json: &str) -> Result<(), LexiconError> {
        let doc: LexiconDoc = serde_json::from_str(json)?;
        self.add(doc)
    }

    /// Get a lexicon document by NSID.
    pub fn get(&self, nsid: &str) -> Option<&LexiconDoc> {
        self.docs.get(nsid)
    }

    /// Get a definition by its URI.
    ///
    /// Accepts formats: `lex:nsid#defId`, `nsid#defId`, `lex:nsid`, `nsid`.
    pub fn get_def(&self, uri: &str) -> Option<&LexUserType> {
        let normalized = normalize_uri(uri);
        self.defs.get(&normalized)
    }

    /// Get a definition by URI, returning an error if not found.
    pub fn get_def_or_err(&self, uri: &str) -> Result<&LexUserType, LexiconError> {
        self.get_def(uri)
            .ok_or_else(|| LexiconError::DefNotFound(uri.to_string()))
    }

    /// Get the number of registered lexicon documents.
    pub fn doc_count(&self) -> usize {
        self.docs.len()
    }

    /// Get the number of registered definitions.
    pub fn def_count(&self) -> usize {
        self.defs.len()
    }

    /// Iterate over all registered lexicon documents.
    pub fn iter_docs(&self) -> impl Iterator<Item = &LexiconDoc> {
        self.docs.values()
    }
}

impl Default for Lexicons {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert an NSID and definition ID to a `lex:` URI.
fn to_lex_uri(nsid: &str, def_id: &str) -> String {
    format!("lex:{nsid}#{def_id}")
}

/// Normalize a URI to `lex:nsid#defId` format.
fn normalize_uri(uri: &str) -> String {
    let uri = uri.strip_prefix("lex:").unwrap_or(uri);

    if uri.contains('#') {
        format!("lex:{uri}")
    } else {
        // No fragment — treat as "main"
        format!("lex:{uri}#main")
    }
}

/// Resolve all relative references in a LexUserType to absolute URIs.
fn resolve_refs(def: &mut LexUserType, base_nsid: &str) {
    match def {
        LexUserType::Ref(r) => {
            r.ref_target = resolve_ref(&r.ref_target, base_nsid);
        }
        LexUserType::Union(u) => {
            for r in &mut u.refs {
                *r = resolve_ref(r, base_nsid);
            }
        }
        LexUserType::Object(obj) => {
            for prop in obj.properties.values_mut() {
                resolve_refs(prop, base_nsid);
            }
        }
        LexUserType::Array(arr) => {
            resolve_refs(&mut arr.items, base_nsid);
        }
        LexUserType::Record(rec) => {
            for prop in rec.record.properties.values_mut() {
                resolve_refs(prop, base_nsid);
            }
        }
        LexUserType::Query(q) => {
            if let Some(params) = &mut q.parameters {
                for prop in params.properties.values_mut() {
                    resolve_refs(prop, base_nsid);
                }
            }
            if let Some(body) = &mut q.output {
                if let Some(schema) = &mut body.schema {
                    resolve_refs(schema, base_nsid);
                }
            }
        }
        LexUserType::Procedure(p) => {
            if let Some(params) = &mut p.parameters {
                for prop in params.properties.values_mut() {
                    resolve_refs(prop, base_nsid);
                }
            }
            if let Some(body) = &mut p.input {
                if let Some(schema) = &mut body.schema {
                    resolve_refs(schema, base_nsid);
                }
            }
            if let Some(body) = &mut p.output {
                if let Some(schema) = &mut body.schema {
                    resolve_refs(schema, base_nsid);
                }
            }
        }
        LexUserType::Subscription(s) => {
            if let Some(params) = &mut s.parameters {
                for prop in params.properties.values_mut() {
                    resolve_refs(prop, base_nsid);
                }
            }
            if let Some(body) = &mut s.message {
                if let Some(schema) = &mut body.schema {
                    resolve_refs(schema, base_nsid);
                }
            }
        }
        // Primitives and other types have no refs to resolve
        _ => {}
    }
}

/// Resolve a single reference string relative to a base NSID.
fn resolve_ref(ref_str: &str, base_nsid: &str) -> String {
    if ref_str.starts_with('#') {
        // Relative ref like "#replyRef" -> "lex:app.bsky.feed.post#replyRef"
        format!("lex:{base_nsid}{ref_str}")
    } else if ref_str.starts_with("lex:") {
        // Already absolute
        ref_str.to_string()
    } else if ref_str.contains('#') {
        // Absolute without lex: prefix like "app.bsky.feed.post#entity"
        format!("lex:{ref_str}")
    } else {
        // Just an NSID like "app.bsky.richtext.facet" -> main def
        format!("lex:{ref_str}#main")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lexicon_json() -> &'static str {
        r##"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text"],
                        "properties": {
                            "text": {
                                "type": "string",
                                "maxLength": 300
                            },
                            "count": {
                                "type": "integer",
                                "minimum": 0
                            }
                        }
                    }
                },
                "myObject": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        }"##
    }

    #[test]
    fn add_and_get_doc() {
        let mut lexicons = Lexicons::new();
        lexicons.add_from_json(sample_lexicon_json()).unwrap();
        assert!(lexicons.get("com.example.test").is_some());
        assert_eq!(lexicons.doc_count(), 1);
    }

    #[test]
    fn get_def_by_uri() {
        let mut lexicons = Lexicons::new();
        lexicons.add_from_json(sample_lexicon_json()).unwrap();

        // Access via various URI formats
        assert!(lexicons.get_def("lex:com.example.test#main").is_some());
        assert!(lexicons.get_def("com.example.test#main").is_some());
        assert!(lexicons.get_def("com.example.test").is_some()); // implied #main
        assert!(lexicons.get_def("lex:com.example.test#myObject").is_some());
        assert!(lexicons.get_def("com.example.test#myObject").is_some());

        // Non-existent
        assert!(lexicons.get_def("com.example.test#nonexistent").is_none());
        assert!(lexicons.get_def("com.example.missing").is_none());
    }

    #[test]
    fn duplicate_lexicon_rejected() {
        let mut lexicons = Lexicons::new();
        lexicons.add_from_json(sample_lexicon_json()).unwrap();
        assert!(lexicons.add_from_json(sample_lexicon_json()).is_err());
    }

    #[test]
    fn resolve_relative_refs() {
        let json = r##"{
            "lexicon": 1,
            "id": "com.example.reftest",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {
                            "inner": { "type": "ref", "ref": "#myType" },
                            "external": { "type": "ref", "ref": "com.example.other" }
                        }
                    }
                },
                "myType": {
                    "type": "object",
                    "properties": {
                        "value": { "type": "string" }
                    }
                }
            }
        }"##;

        let mut lexicons = Lexicons::new();
        lexicons.add_from_json(json).unwrap();

        // The relative ref "#myType" should resolve to "lex:com.example.reftest#myType"
        let main_def = lexicons.get_def("com.example.reftest#main").unwrap();
        if let LexUserType::Record(rec) = main_def {
            let inner = rec.record.properties.get("inner").unwrap();
            if let LexUserType::Ref(r) = inner {
                assert_eq!(r.ref_target, "lex:com.example.reftest#myType");
            } else {
                panic!("Expected ref type");
            }

            let external = rec.record.properties.get("external").unwrap();
            if let LexUserType::Ref(r) = external {
                assert_eq!(r.ref_target, "lex:com.example.other#main");
            } else {
                panic!("Expected ref type");
            }
        } else {
            panic!("Expected record type");
        }
    }

    #[test]
    fn load_all_lexicon_files() {
        // Load all 322 lexicon JSON files from the lexicons/ directory
        let lexicons_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("lexicons");

        let mut lexicons = Lexicons::new();
        let mut file_count = 0;
        let mut errors = Vec::new();

        fn visit_dir(
            dir: &std::path::Path,
            lexicons: &mut Lexicons,
            file_count: &mut usize,
            errors: &mut Vec<String>,
        ) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dir(&path, lexicons, file_count, errors);
                    } else if path.extension().is_some_and(|e| e == "json") {
                        *file_count += 1;
                        let content = std::fs::read_to_string(&path).unwrap();
                        if let Err(e) = lexicons.add_from_json(&content) {
                            errors.push(format!("{}: {e}", path.display()));
                        }
                    }
                }
            }
        }

        visit_dir(&lexicons_dir, &mut lexicons, &mut file_count, &mut errors);

        assert!(
            errors.is_empty(),
            "Failed to parse {} of {} lexicon files:\n{}",
            errors.len(),
            file_count,
            errors.join("\n")
        );
        assert!(
            file_count >= 300,
            "Expected at least 300 lexicon files, found {file_count}"
        );
        assert_eq!(lexicons.doc_count(), file_count);
    }

    #[test]
    fn def_type_inspection() {
        let mut lexicons = Lexicons::new();
        lexicons.add_from_json(sample_lexicon_json()).unwrap();

        let main = lexicons.get_def("com.example.test#main").unwrap();
        assert!(main.is_primary());
        assert_eq!(main.type_name(), "record");

        let obj = lexicons.get_def("com.example.test#myObject").unwrap();
        assert!(!obj.is_primary());
        assert_eq!(obj.type_name(), "object");
    }
}
