//! Blob reference types for AT Protocol.
//!
//! BlobRefs represent references to binary data stored separately from records.

use crate::cid::Cid;

/// A reference to a binary blob stored in a repository.
///
/// Blobs are uploaded separately and referenced by their CID.
#[derive(Debug, Clone, PartialEq)]
pub struct BlobRef {
    /// The CID of the blob data (typically a raw CID).
    pub r#ref: Cid,
    /// MIME type of the blob (e.g., `"image/jpeg"`).
    pub mime_type: String,
    /// Size of the blob in bytes.
    pub size: u64,
}

impl BlobRef {
    /// Create a new blob reference.
    pub fn new(r#ref: Cid, mime_type: String, size: u64) -> Self {
        BlobRef {
            r#ref,
            mime_type,
            size,
        }
    }

    /// Check if this is a valid blob reference.
    ///
    /// Valid blobs have a MIME type containing '/' and a non-negative size.
    pub fn is_valid(&self) -> bool {
        self.mime_type.contains('/')
    }

    /// Check if the CID uses the raw codec (strict mode).
    pub fn is_strict_ref(&self) -> bool {
        self.r#ref.codec == crate::RAW_CODEC
    }
}

impl serde::Serialize for BlobRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("$type", "blob")?;
        map.serialize_entry("ref", &self.r#ref)?;
        map.serialize_entry("mimeType", &self.mime_type)?;
        map.serialize_entry("size", &self.size)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for BlobRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct BlobRefHelper {
            #[serde(rename = "$type")]
            type_name: String,
            #[serde(rename = "ref")]
            r#ref: Cid,
            #[serde(rename = "mimeType")]
            mime_type: String,
            size: u64,
        }

        let helper = BlobRefHelper::deserialize(deserializer)?;
        if helper.type_name != "blob" {
            return Err(serde::de::Error::custom(format!(
                "Expected $type \"blob\", got \"{}\"",
                helper.type_name
            )));
        }
        Ok(BlobRef {
            r#ref: helper.r#ref,
            mime_type: helper.mime_type,
            size: helper.size,
        })
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
        assert_eq!(blob.size, 1024);
    }

    #[test]
    fn invalid_mime_type() {
        let cid = Cid::for_raw(b"data");
        let blob = BlobRef::new(cid, "invalid".to_string(), 0);
        assert!(!blob.is_valid());
    }
}
