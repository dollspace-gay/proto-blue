//! Lexicons registry — manages a collection of lexicon documents.

use std::collections::HashMap;

use proto_blue_lex_data::LexValue;

use crate::error::{LexiconError, ValidationError, ValidationResult};
use crate::types::{
    LexObject, LexRefUnion, LexUserType, LexXrpcBody, LexXrpcParameters,
    LexXrpcSubscriptionMessage, LexiconDoc,
};
use crate::validation::validate_value;

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
    #[must_use]
    pub fn new() -> Self {
        Self {
            docs: HashMap::new(),
            defs: HashMap::new(),
        }
    }

    /// Add a lexicon document to the registry.
    ///
    /// All definitions in the document are registered and their
    /// references are resolved to absolute URIs. The doc is rejected
    /// with [`LexiconError::InvalidSchema`] when any of the following
    /// spec-level refinements fail (mirroring TS `lexiconDoc.refine`):
    ///
    /// - primary defs (record / query / procedure / subscription /
    ///   permission-set) appear only under the `main` key;
    /// - every entry in an object's `required[]` list actually exists
    ///   in its `properties[]`.
    pub fn add(&mut self, doc: LexiconDoc) -> Result<(), LexiconError> {
        let nsid = &doc.id;

        if self.docs.contains_key(nsid) {
            return Err(LexiconError::DuplicateLexicon(nsid.clone()));
        }

        // Refinement 1: primary defs must live under "main".
        for (def_id, def) in &doc.defs {
            if def.is_primary() && def_id != "main" {
                return Err(LexiconError::InvalidSchema(format!(
                    "{nsid}: primary def `{}` must be at `main`, found at `{def_id}`",
                    def.type_name(),
                )));
            }
        }

        // Refinement 2: `required[]` must reference real properties.
        for (def_id, def) in &doc.defs {
            check_required_properties(nsid, def_id, def)?;
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
    #[must_use]
    pub fn get(&self, nsid: &str) -> Option<&LexiconDoc> {
        self.docs.get(nsid)
    }

    /// Get a definition by its URI.
    ///
    /// Accepts formats: `lex:nsid#defId`, `nsid#defId`, `lex:nsid`, `nsid`.
    #[must_use]
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
    #[must_use]
    pub fn doc_count(&self) -> usize {
        self.docs.len()
    }

    /// Get the number of registered definitions.
    #[must_use]
    pub fn def_count(&self) -> usize {
        self.defs.len()
    }

    /// Iterate over all registered lexicon documents.
    pub fn iter_docs(&self) -> impl Iterator<Item = &LexiconDoc> {
        self.docs.values()
    }

    // ── XRPC validator entry points ────────────────────────────────────
    //
    // These mirror TS `assertValidXrpcParams/Input/Output/Message` on
    // `Lexicons`. Each looks up the def by URI, asserts it's the right
    // primary kind, and dispatches to the corresponding validator.

    /// Validate xrpc query / procedure / subscription params.
    ///
    /// `lex_uri` is the NSID of the method (e.g. `app.bsky.feed.getTimeline`
    /// or `lex:app.bsky.feed.getTimeline`).
    pub fn assert_valid_xrpc_params(&self, lex_uri: &str, value: &LexValue) -> ValidationResult {
        let def = self.get_def_or_err(lex_uri).map_err(validator_from_lex)?;
        let params: Option<&LexXrpcParameters> = match def {
            LexUserType::Query(q) => q.parameters.as_ref(),
            LexUserType::Procedure(p) => p.parameters.as_ref(),
            LexUserType::Subscription(s) => s.parameters.as_ref(),
            _ => {
                return Err(ValidationError::new(
                    lex_uri,
                    format!(
                        "expected query/procedure/subscription, got {}",
                        def.type_name()
                    ),
                ));
            }
        };

        let map = value
            .as_map()
            .ok_or_else(|| ValidationError::new("params", "expected an object"))?;

        // No params defined → any object is accepted (matches TS).
        let Some(params) = params else {
            return Ok(());
        };
        validate_params(self, params, map)
    }

    /// Validate an xrpc procedure input body.
    pub fn assert_valid_xrpc_input(&self, lex_uri: &str, value: &LexValue) -> ValidationResult {
        let def = self.get_def_or_err(lex_uri).map_err(validator_from_lex)?;
        let input: Option<&LexXrpcBody> = match def {
            LexUserType::Procedure(p) => p.input.as_ref(),
            _ => {
                return Err(ValidationError::new(
                    lex_uri,
                    format!("expected procedure, got {}", def.type_name()),
                ));
            }
        };
        validate_xrpc_body(self, "input", input, value)
    }

    /// Validate an xrpc query / procedure output body.
    pub fn assert_valid_xrpc_output(&self, lex_uri: &str, value: &LexValue) -> ValidationResult {
        let def = self.get_def_or_err(lex_uri).map_err(validator_from_lex)?;
        let output: Option<&LexXrpcBody> = match def {
            LexUserType::Query(q) => q.output.as_ref(),
            LexUserType::Procedure(p) => p.output.as_ref(),
            _ => {
                return Err(ValidationError::new(
                    lex_uri,
                    format!("expected query or procedure, got {}", def.type_name()),
                ));
            }
        };
        validate_xrpc_body(self, "output", output, value)
    }

    /// Validate an xrpc subscription message frame body.
    pub fn assert_valid_xrpc_message(&self, lex_uri: &str, value: &LexValue) -> ValidationResult {
        let def = self.get_def_or_err(lex_uri).map_err(validator_from_lex)?;
        let message: Option<&LexXrpcSubscriptionMessage> = match def {
            LexUserType::Subscription(s) => s.message.as_ref(),
            _ => {
                return Err(ValidationError::new(
                    lex_uri,
                    format!("expected subscription, got {}", def.type_name()),
                ));
            }
        };
        let Some(message) = message else {
            // No message shape defined → any value accepted.
            return Ok(());
        };
        validate_union(self, "message", &message.schema, value)
    }
}

/// Translate a `LexiconError::DefNotFound` (from `get_def_or_err`) into
/// a `ValidationError::DefNotFound` so XRPC callers get a uniform error
/// type to match on.
fn validator_from_lex(err: LexiconError) -> ValidationError {
    match err {
        LexiconError::DefNotFound(uri) => ValidationError::DefNotFound(uri),
        other => ValidationError::new("", other.to_string()),
    }
}

/// Validate XRPC params — primitives only (string, integer, boolean,
/// unknown) plus arrays of primitives. Matches the TS param validator,
/// which deliberately disallows object/ref/union fields in query strings.
fn validate_params(
    lexicons: &Lexicons,
    params: &LexXrpcParameters,
    map: &std::collections::BTreeMap<String, LexValue>,
) -> ValidationResult {
    for req in &params.required {
        if !map.contains_key(req) {
            return Err(ValidationError::new(
                &format!("params/{req}"),
                format!("Required param missing: {req}"),
            ));
        }
    }
    for (key, prop_def) in &params.properties {
        let path = format!("params/{key}");
        if let Some(value) = map.get(key) {
            validate_value(lexicons, &path, prop_def, value)?;
        }
    }
    Ok(())
}

/// Validate a request / response body against a [`LexXrpcBody`].
///
/// If the body has no schema (raw-bytes endpoint), any value passes.
/// Otherwise the body's `schema` is expected to be an object-type def;
/// we dispatch to [`validate_value`] which handles object/ref/union.
fn validate_xrpc_body(
    lexicons: &Lexicons,
    path: &str,
    body: Option<&LexXrpcBody>,
    value: &LexValue,
) -> ValidationResult {
    let Some(body) = body else {
        return Ok(());
    };
    let Some(schema) = &body.schema else {
        return Ok(());
    };
    validate_value(lexicons, path, schema, value)
}

/// Validate a value against a [`LexRefUnion`] (used by subscription
/// messages). Delegates to the regular union validator indirectly — but
/// we can't call `validation::validate_union` since it's private, so we
/// do the minimal walk here: the value must be a map with `$type`
/// matching one of the refs (closed unions reject unknown types, open
/// unions accept them).
fn validate_union(
    lexicons: &Lexicons,
    path: &str,
    union: &LexRefUnion,
    value: &LexValue,
) -> ValidationResult {
    let map = value
        .as_map()
        .ok_or_else(|| ValidationError::new(path, "expected an object for union"))?;
    let type_val = map
        .get("$type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ValidationError::new(path, "union requires $type field"))?;

    // Normalise the value's $type to a lex URI and see if it's in the
    // permitted set. The refs were already resolved to absolute form
    // when the doc was added to the registry.
    let type_uri = if type_val.contains('#') {
        format!("lex:{type_val}")
    } else {
        format!("lex:{type_val}#main")
    };
    let known = union
        .refs
        .iter()
        .any(|r| r == &type_uri || r == &format!("lex:{type_val}"));
    if !known {
        if union.closed.unwrap_or(false) {
            return Err(ValidationError::new(
                path,
                format!("unknown type in closed union: {type_val}"),
            ));
        }
        // Open union: unknown types pass through.
        return Ok(());
    }
    if let Some(def) = lexicons.get_def(&type_uri) {
        validate_value(lexicons, path, def, value)?;
    }
    Ok(())
}

/// Walk every `LexObject` inside a definition and assert its
/// `required[]` entries all exist in `properties`. TS rejects such
/// schemas at load time via `superRefine`; we do the same so malformed
/// lexicons don't slip through and surface later as baffling
/// "required field missing" errors at validation time.
fn check_required_properties(
    nsid: &str,
    def_id: &str,
    def: &LexUserType,
) -> Result<(), LexiconError> {
    fn check_object(
        nsid: &str,
        def_id: &str,
        path: &str,
        obj: &LexObject,
    ) -> Result<(), LexiconError> {
        for req in &obj.required {
            if !obj.properties.contains_key(req) {
                return Err(LexiconError::InvalidSchema(format!(
                    "{nsid}#{def_id}: {path} lists `{req}` as required but no such property is declared",
                )));
            }
        }
        for (key, prop) in &obj.properties {
            let child_path = format!("{path}/{key}");
            check_required_properties_inner(nsid, def_id, &child_path, prop)?;
        }
        Ok(())
    }

    match def {
        LexUserType::Object(o) => check_object(nsid, def_id, "", o),
        LexUserType::Record(r) => check_object(nsid, def_id, "record", &r.record),
        LexUserType::Query(q) => {
            if let Some(p) = &q.parameters {
                check_params(nsid, def_id, "parameters", p)?;
            }
            if let Some(b) = &q.output
                && let Some(s) = &b.schema
            {
                check_required_properties_inner(nsid, def_id, "output", s)?;
            }
            Ok(())
        }
        LexUserType::Procedure(p) => {
            if let Some(params) = &p.parameters {
                check_params(nsid, def_id, "parameters", params)?;
            }
            if let Some(b) = &p.input
                && let Some(s) = &b.schema
            {
                check_required_properties_inner(nsid, def_id, "input", s)?;
            }
            if let Some(b) = &p.output
                && let Some(s) = &b.schema
            {
                check_required_properties_inner(nsid, def_id, "output", s)?;
            }
            Ok(())
        }
        LexUserType::Subscription(s) => {
            if let Some(p) = &s.parameters {
                check_params(nsid, def_id, "parameters", p)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_required_properties_inner(
    nsid: &str,
    def_id: &str,
    path: &str,
    def: &LexUserType,
) -> Result<(), LexiconError> {
    match def {
        LexUserType::Object(o) => {
            for req in &o.required {
                if !o.properties.contains_key(req) {
                    return Err(LexiconError::InvalidSchema(format!(
                        "{nsid}#{def_id}: {path} lists `{req}` as required but no such property is declared",
                    )));
                }
            }
            for (key, prop) in &o.properties {
                let child_path = format!("{path}/{key}");
                check_required_properties_inner(nsid, def_id, &child_path, prop)?;
            }
            Ok(())
        }
        LexUserType::Array(a) => {
            check_required_properties_inner(nsid, def_id, &format!("{path}[]"), &a.items)
        }
        _ => Ok(()),
    }
}

fn check_params(
    nsid: &str,
    def_id: &str,
    path: &str,
    params: &LexXrpcParameters,
) -> Result<(), LexiconError> {
    for req in &params.required {
        if !params.properties.contains_key(req) {
            return Err(LexiconError::InvalidSchema(format!(
                "{nsid}#{def_id}: {path} lists `{req}` as required but no such property is declared",
            )));
        }
    }
    Ok(())
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

/// Resolve all relative references in a `LexUserType` to absolute URIs.
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
            if let Some(body) = &mut q.output
                && let Some(schema) = &mut body.schema
            {
                resolve_refs(schema, base_nsid);
            }
        }
        LexUserType::Procedure(p) => {
            if let Some(params) = &mut p.parameters {
                for prop in params.properties.values_mut() {
                    resolve_refs(prop, base_nsid);
                }
            }
            if let Some(body) = &mut p.input
                && let Some(schema) = &mut body.schema
            {
                resolve_refs(schema, base_nsid);
            }
            if let Some(body) = &mut p.output
                && let Some(schema) = &mut body.schema
            {
                resolve_refs(schema, base_nsid);
            }
        }
        LexUserType::Subscription(s) => {
            if let Some(params) = &mut s.parameters {
                for prop in params.properties.values_mut() {
                    resolve_refs(prop, base_nsid);
                }
            }
            if let Some(msg) = &mut s.message {
                // Subscription schemas are always a LexRefUnion — resolve
                // each ref string directly.
                for r in &mut msg.schema.refs {
                    *r = resolve_ref(r, base_nsid);
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
        r#"{
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
        }"#
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
