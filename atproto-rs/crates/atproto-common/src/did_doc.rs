//! DID Document parsing utilities.
//!
//! Extracts AT Protocol-specific information from DID documents:
//! signing keys, PDS endpoints, handles, etc.

use serde::Deserialize;

/// A W3C DID Document as used in AT Protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    pub id: String,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub service: Vec<Service>,
}

/// A verification method in a DID document.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(default)]
    pub public_key_multibase: Option<String>,
}

/// A service endpoint in a DID document.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: serde_json::Value,
}

/// Signing key material extracted from a DID document.
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub key_type: String,
    pub public_key_multibase: String,
}

/// Get the DID from a DID document.
pub fn get_did(doc: &DidDocument) -> &str {
    &doc.id
}

/// Get the handle from a DID document's `alsoKnownAs` array.
///
/// Looks for an entry starting with `at://` and returns the handle portion.
pub fn get_handle(doc: &DidDocument) -> Option<&str> {
    for alias in &doc.also_known_as {
        if let Some(handle) = alias.strip_prefix("at://") {
            return Some(handle);
        }
    }
    None
}

/// Get the AT Protocol signing key from a DID document.
///
/// Looks for the verification method with id `#atproto`.
pub fn get_signing_key(doc: &DidDocument) -> Option<SigningKey> {
    get_verification_material(doc, "atproto")
}

/// Get verification material by key ID.
pub fn get_verification_material(doc: &DidDocument, key_id: &str) -> Option<SigningKey> {
    let target_id = format!("#{key_id}");
    let item = find_item_by_id_vm(doc, &target_id)?;
    let multibase = item.public_key_multibase.as_ref()?;
    Some(SigningKey {
        key_type: item.method_type.clone(),
        public_key_multibase: multibase.clone(),
    })
}

/// Get the `did:key:...` string for the signing key.
pub fn get_signing_did_key(doc: &DidDocument) -> Option<String> {
    let key = get_signing_key(doc)?;
    Some(format!("did:key:{}", key.public_key_multibase))
}

/// Get the PDS (Personal Data Server) endpoint URL.
pub fn get_pds_endpoint(doc: &DidDocument) -> Option<String> {
    get_service_endpoint(doc, "#atproto_pds", Some("AtprotoPersonalDataServer"))
}

/// Get the Feed Generator service endpoint URL.
pub fn get_feed_gen_endpoint(doc: &DidDocument) -> Option<String> {
    get_service_endpoint(doc, "#bsky_fg", Some("BskyFeedGenerator"))
}

/// Get the Notification Service endpoint URL.
pub fn get_notif_endpoint(doc: &DidDocument) -> Option<String> {
    get_service_endpoint(doc, "#bsky_notif", Some("BskyNotificationService"))
}

/// Get a service endpoint by ID and optional type.
pub fn get_service_endpoint(
    doc: &DidDocument,
    id: &str,
    expected_type: Option<&str>,
) -> Option<String> {
    let service = find_item_by_id_svc(doc, id)?;

    if let Some(t) = expected_type {
        if service.service_type != t {
            return None;
        }
    }

    let endpoint = service.service_endpoint.as_str()?;
    validate_url(endpoint)
}

/// Find a verification method by its ID (with `#` prefix matching).
fn find_item_by_id_vm<'a>(doc: &'a DidDocument, id: &str) -> Option<&'a VerificationMethod> {
    doc.verification_method
        .iter()
        .find(|item| matches_id(&item.id, &doc.id, id))
}

/// Find a service by its ID (with `#` prefix matching).
fn find_item_by_id_svc<'a>(doc: &'a DidDocument, id: &str) -> Option<&'a Service> {
    doc.service
        .iter()
        .find(|item| matches_id(&item.id, &doc.id, id))
}

/// Check if an item ID matches the target ID.
///
/// Handles both relative (`#atproto`) and absolute (`did:plc:xxx#atproto`) forms.
fn matches_id(item_id: &str, doc_id: &str, target_id: &str) -> bool {
    if item_id.starts_with('#') {
        item_id == target_id
    } else {
        // Absolute form: doc_id + target_id
        item_id.len() == doc_id.len() + target_id.len()
            && item_id.ends_with(target_id)
            && item_id.starts_with(doc_id)
    }
}

/// Validate a URL for SSRF prevention.
fn validate_url(url_str: &str) -> Option<String> {
    if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        return None;
    }
    // Verify it's a parseable URL
    if url::Url::parse(url_str).is_err() {
        return None;
    }
    Some(url_str.to_string())
}

/// Parse a DID document from JSON.
pub fn parse_did_document(json: &str) -> Result<DidDocument, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> DidDocument {
        let json = r##"{
            "id": "did:plc:testuser123",
            "alsoKnownAs": ["at://alice.bsky.social"],
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:plc:testuser123",
                "publicKeyMultibase": "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }, {
                "id": "#bsky_fg",
                "type": "BskyFeedGenerator",
                "serviceEndpoint": "https://feed.bsky.social"
            }]
        }"##;
        parse_did_document(json).unwrap()
    }

    #[test]
    fn get_did_from_doc() {
        let doc = sample_doc();
        assert_eq!(get_did(&doc), "did:plc:testuser123");
    }

    #[test]
    fn get_handle_from_doc() {
        let doc = sample_doc();
        assert_eq!(get_handle(&doc), Some("alice.bsky.social"));
    }

    #[test]
    fn get_handle_none_when_missing() {
        let doc = DidDocument {
            id: "did:plc:test".into(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![],
        };
        assert_eq!(get_handle(&doc), None);
    }

    #[test]
    fn get_signing_key_from_doc() {
        let doc = sample_doc();
        let key = get_signing_key(&doc).unwrap();
        assert_eq!(key.key_type, "Multikey");
        assert!(key.public_key_multibase.starts_with('z'));
    }

    #[test]
    fn get_signing_did_key_from_doc() {
        let doc = sample_doc();
        let did_key = get_signing_did_key(&doc).unwrap();
        assert!(did_key.starts_with("did:key:z"));
    }

    #[test]
    fn get_pds_endpoint_from_doc() {
        let doc = sample_doc();
        assert_eq!(
            get_pds_endpoint(&doc),
            Some("https://bsky.social".to_string())
        );
    }

    #[test]
    fn get_feed_gen_endpoint_from_doc() {
        let doc = sample_doc();
        assert_eq!(
            get_feed_gen_endpoint(&doc),
            Some("https://feed.bsky.social".to_string())
        );
    }

    #[test]
    fn absolute_id_matching() {
        let json = r##"{
            "id": "did:plc:abc",
            "verificationMethod": [{
                "id": "did:plc:abc#atproto",
                "type": "Multikey",
                "controller": "did:plc:abc",
                "publicKeyMultibase": "zAbcDef"
            }],
            "service": []
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let key = get_signing_key(&doc).unwrap();
        assert_eq!(key.public_key_multibase, "zAbcDef");
    }

    #[test]
    fn invalid_service_endpoint_url() {
        let json = r##"{
            "id": "did:plc:abc",
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "ftp://not-http.example.com"
            }]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        assert_eq!(get_pds_endpoint(&doc), None);
    }

    #[test]
    fn wrong_service_type() {
        let json = r##"{
            "id": "did:plc:abc",
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "WrongType",
                "serviceEndpoint": "https://example.com"
            }]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        assert_eq!(get_pds_endpoint(&doc), None);
    }
}
