//! Blob reference types for AT Protocol.
//!
//! BlobRefs represent references to binary data stored separately from
//! records. Two on-the-wire shapes exist:
//!
//! - **Typed** — current form: `{$type:"blob", ref:{$link: "<cid>"}, mimeType, size}`.
//! - **Legacy** — historical / pre-typed form still present in older
//!   records and some chat data: `{cid: "<cid>", mimeType: "<mime>"}`.
//!
//! Both round-trip through [`BlobRef`]; deserialisation tries the typed
//! form first and falls back to legacy (`untagged` union). This mirrors
//! the TypeScript SDK's `TypedBlobRef | LegacyBlobRef` union.

use crate::cid::Cid;

/// A reference to a binary blob stored in a repository.
///
/// Serializes to either the typed (`$type:"blob"`) or legacy form
/// depending on which variant is active. Deserialisation accepts either
/// shape.
#[derive(Debug, Clone, PartialEq)]
pub enum BlobRef {
    /// Current form: `{$type:"blob", ref:{$link:"<cid>"}, mimeType, size}`.
    Typed(TypedBlobRef),
    /// Historical form: `{cid:"<cid>", mimeType:"<mime>"}`. No size.
    Legacy(LegacyBlobRef),
}

/// The current, strictly-validated blob-reference shape.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedBlobRef {
    /// The CID of the blob data (typically a raw CID).
    pub r#ref: Cid,
    /// MIME type of the blob (e.g., `"image/jpeg"`).
    pub mime_type: String,
    /// Size of the blob in bytes.
    pub size: u64,
}

/// The pre-typed blob-reference shape, preserved so historical atproto
/// records round-trip. The `cid` field is a string because legacy refs
/// sometimes carried CIDv0 / non-standard encodings the strict
/// [`Cid`] parser would reject.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyBlobRef {
    /// Multibase CID string exactly as found in the source record.
    pub cid: String,
    /// MIME type of the blob.
    pub mime_type: String,
}

impl BlobRef {
    /// Construct a typed blob reference (current form).
    ///
    /// For legacy-form records, construct `BlobRef::Legacy(LegacyBlobRef{..})`
    /// directly.
    pub fn new(r#ref: Cid, mime_type: String, size: u64) -> Self {
        BlobRef::Typed(TypedBlobRef {
            r#ref,
            mime_type,
            size,
        })
    }

    /// Construct a legacy-form blob reference.
    pub fn new_legacy(cid: String, mime_type: String) -> Self {
        BlobRef::Legacy(LegacyBlobRef { cid, mime_type })
    }

    /// `true` when this is a typed (`$type:"blob"`) ref.
    pub fn is_typed(&self) -> bool {
        matches!(self, BlobRef::Typed(_))
    }

    /// `true` when this is a legacy (`{cid,mimeType}`) ref.
    pub fn is_legacy(&self) -> bool {
        matches!(self, BlobRef::Legacy(_))
    }

    /// Borrow the MIME type regardless of variant.
    pub fn mime_type(&self) -> &str {
        match self {
            BlobRef::Typed(t) => &t.mime_type,
            BlobRef::Legacy(l) => &l.mime_type,
        }
    }

    /// Size of the blob in bytes. Legacy refs don't carry a size — `None`.
    pub fn size(&self) -> Option<u64> {
        match self {
            BlobRef::Typed(t) => Some(t.size),
            BlobRef::Legacy(_) => None,
        }
    }

    /// Borrow the typed variant, if this ref is typed.
    pub fn as_typed(&self) -> Option<&TypedBlobRef> {
        match self {
            BlobRef::Typed(t) => Some(t),
            BlobRef::Legacy(_) => None,
        }
    }

    /// Borrow the legacy variant, if this ref is legacy.
    pub fn as_legacy(&self) -> Option<&LegacyBlobRef> {
        match self {
            BlobRef::Typed(_) => None,
            BlobRef::Legacy(l) => Some(l),
        }
    }

    /// Check if this is a valid blob reference.
    ///
    /// Valid blobs have a MIME type containing `/`. Typed refs
    /// additionally require a non-zero size (zero-byte blobs are
    /// permitted by the spec but TS treats `-1` as a legacy sentinel —
    /// Rust uses `u64` so negative sizes are unreachable).
    pub fn is_valid(&self) -> bool {
        self.mime_type().contains('/')
    }

    /// Check if the CID uses the raw codec (strict mode). Returns `false`
    /// for legacy refs, which don't carry structured codec information.
    pub fn is_strict_ref(&self) -> bool {
        match self {
            BlobRef::Typed(t) => t.r#ref.codec == crate::RAW_CODEC,
            BlobRef::Legacy(_) => false,
        }
    }
}

impl serde::Serialize for BlobRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            BlobRef::Typed(t) => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("$type", "blob")?;
                map.serialize_entry("ref", &t.r#ref)?;
                map.serialize_entry("mimeType", &t.mime_type)?;
                map.serialize_entry("size", &t.size)?;
                map.end()
            }
            BlobRef::Legacy(l) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("cid", &l.cid)?;
                map.serialize_entry("mimeType", &l.mime_type)?;
                map.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for BlobRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Tagged discrimination: the typed form always carries `$type:"blob"`
        // and a `ref` field; the legacy form carries a top-level `cid`
        // string and no `$type`. Deserialise into a permissive helper and
        // branch on which fields are present.
        #[derive(serde::Deserialize)]
        struct Helper {
            #[serde(rename = "$type", default)]
            type_name: Option<String>,
            #[serde(rename = "ref", default)]
            r#ref: Option<Cid>,
            #[serde(default)]
            cid: Option<String>,
            #[serde(rename = "mimeType", default)]
            mime_type: Option<String>,
            #[serde(default)]
            size: Option<u64>,
        }

        let h = Helper::deserialize(deserializer)?;
        let mime_type = h.mime_type.ok_or_else(|| {
            serde::de::Error::custom("BlobRef missing required field \"mimeType\"")
        })?;

        // Typed form: `$type == "blob"` and a `ref` CID are present.
        if let Some(type_name) = h.type_name.as_deref() {
            if type_name != "blob" {
                return Err(serde::de::Error::custom(format!(
                    "Expected $type \"blob\", got \"{type_name}\""
                )));
            }
            let r#ref = h.r#ref.ok_or_else(|| {
                serde::de::Error::custom("Typed BlobRef missing required field \"ref\"")
            })?;
            let size = h.size.ok_or_else(|| {
                serde::de::Error::custom("Typed BlobRef missing required field \"size\"")
            })?;
            return Ok(BlobRef::Typed(TypedBlobRef {
                r#ref,
                mime_type,
                size,
            }));
        }

        // Legacy form: top-level `cid` string, no `$type`.
        if let Some(cid) = h.cid {
            return Ok(BlobRef::Legacy(LegacyBlobRef { cid, mime_type }));
        }

        Err(serde::de::Error::custom(
            "BlobRef must carry either `$type:\"blob\"` + `ref` (typed form) \
             or `cid` (legacy form)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_ref_creation() {
        let cid = Cid::for_raw(b"image data");
        let blob = BlobRef::new(cid, "image/jpeg".to_string(), 1024);
        assert!(blob.is_valid());
        assert!(blob.is_strict_ref());
        assert!(blob.is_typed());
        assert_eq!(blob.size(), Some(1024));
        assert_eq!(blob.mime_type(), "image/jpeg");
    }

    #[test]
    fn legacy_blob_ref_creation() {
        let blob = BlobRef::new_legacy(
            "bafyreidyxyabc".to_string(),
            "image/png".to_string(),
        );
        assert!(blob.is_valid());
        assert!(blob.is_legacy());
        assert!(!blob.is_strict_ref());
        assert_eq!(blob.size(), None);
        assert_eq!(blob.mime_type(), "image/png");
    }

    #[test]
    fn invalid_mime_type() {
        let cid = Cid::for_raw(b"data");
        let blob = BlobRef::new(cid, "invalid".to_string(), 0);
        assert!(!blob.is_valid());
    }

    #[test]
    fn typed_blob_ref_json_roundtrip() {
        let cid = Cid::for_raw(b"image data");
        let original = BlobRef::new(cid.clone(), "image/jpeg".to_string(), 1024);
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"$type\":\"blob\""));
        assert!(json.contains("\"mimeType\":\"image/jpeg\""));
        assert!(json.contains("\"size\":1024"));
        let parsed: BlobRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn legacy_blob_ref_json_roundtrip() {
        let original = BlobRef::new_legacy(
            "bafyreidyxyabc".to_string(),
            "image/png".to_string(),
        );
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"cid":"bafyreidyxyabc","mimeType":"image/png"}"#);
        let parsed: BlobRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn deserialise_typed_with_key_order_variation() {
        // Serde can't assume field order; exercise both orderings.
        let cid = Cid::for_raw(b"x");
        let s = cid.to_string();
        let shuffled = format!(
            r#"{{"size":7,"mimeType":"image/webp","ref":"{s}","$type":"blob"}}"#
        );
        let parsed: BlobRef = serde_json::from_str(&shuffled).unwrap();
        assert!(parsed.is_typed());
        assert_eq!(parsed.size(), Some(7));
        assert_eq!(parsed.mime_type(), "image/webp");
    }

    #[test]
    fn deserialise_legacy_form() {
        let input = r#"{"cid":"bafyreidyxyabc","mimeType":"image/gif"}"#;
        let parsed: BlobRef = serde_json::from_str(input).unwrap();
        assert!(parsed.is_legacy());
        assert_eq!(parsed.mime_type(), "image/gif");
        let legacy = parsed.as_legacy().unwrap();
        assert_eq!(legacy.cid, "bafyreidyxyabc");
    }

    #[test]
    fn reject_unknown_type_name() {
        let cid = Cid::for_raw(b"x");
        let s = cid.to_string();
        let input = format!(
            r#"{{"$type":"notblob","ref":"{s}","mimeType":"x/y","size":0}}"#
        );
        let err = serde_json::from_str::<BlobRef>(&input).unwrap_err();
        assert!(
            err.to_string().contains("Expected $type \"blob\""),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_payload_with_neither_shape() {
        let input = r#"{"mimeType":"x/y","size":0}"#;
        let err = serde_json::from_str::<BlobRef>(input).unwrap_err();
        assert!(err.to_string().contains("typed form"));
    }
}
