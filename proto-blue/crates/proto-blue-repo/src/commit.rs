//! Signed commits — the root of an AT Protocol repository.
//!
//! A v3 atproto commit describes the state of a repo at a point in time.
//! It is DAG-CBOR encoded, signed with the account's signing key, and
//! identified by the SHA-256 CID of its canonical encoding. The network
//! cannot tell two repo states apart from their commit CIDs alone — the
//! CID *is* the repo state.
//!
//! Shape (mirrors `packages/repo/src/types.ts`):
//!
//! ```text
//! UnsignedCommit { did, version = 3, data (CID of MST root), rev (TID), prev: CID | null }
//! SignedCommit   { ...UnsignedCommit, sig: bytes }
//! ```
//!
//! The canonical signing bytes are the DAG-CBOR encoding of the
//! `UnsignedCommit` (the `sig` field is *absent*, not set to null). DAG-CBOR
//! enforces sorted map keys so every implementation produces identical
//! bytes for the same logical commit.

use std::collections::BTreeMap;

use proto_blue_crypto::verify_signature;
use proto_blue_lex_cbor::encode as cbor_encode;
use proto_blue_lex_data::{Cid, LexValue};

use crate::error::RepoError;

/// Commit schema version — atproto is at v3.
pub const COMMIT_VERSION: i64 = 3;

/// An unsigned commit — the payload fed to the signing function. `prev` is
/// always serialized (nullable), never omitted, for v2-compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedCommit {
    /// DID of the repo owner.
    pub did: String,
    /// Always `3` for v3 commits; present in the CBOR as well.
    pub version: i64,
    /// CID of the MST root containing this commit's record set.
    pub data: Cid,
    /// Monotonically-increasing revision identifier (a TID).
    pub rev: String,
    /// CID of the previous commit, or `None` for the first commit.
    pub prev: Option<Cid>,
}

impl UnsignedCommit {
    /// Construct a new v3 unsigned commit.
    #[must_use]
    pub const fn new(did: String, data: Cid, rev: String, prev: Option<Cid>) -> Self {
        Self {
            did,
            version: COMMIT_VERSION,
            data,
            rev,
            prev,
        }
    }

    /// Serialize to the canonical DAG-CBOR bytes used as the signing input.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, RepoError> {
        Ok(cbor_encode(&self.to_lex_value())?)
    }

    /// Convert to a `LexValue::Map` ready for DAG-CBOR encoding. DAG-CBOR
    /// sorts map keys canonically at encode time, so the key order here
    /// doesn't matter for correctness.
    #[must_use]
    pub fn to_lex_value(&self) -> LexValue {
        let mut m = BTreeMap::new();
        m.insert("did".to_string(), LexValue::String(self.did.clone()));
        m.insert("version".to_string(), LexValue::Integer(self.version));
        m.insert("data".to_string(), LexValue::Cid(self.data.clone()));
        m.insert("rev".to_string(), LexValue::String(self.rev.clone()));
        // `prev` is always present, nullable. Omitting it would produce
        // different canonical bytes and break signature verification.
        m.insert(
            "prev".to_string(),
            self.prev
                .as_ref()
                .map_or(LexValue::Null, |cid| LexValue::Cid(cid.clone())),
        );
        LexValue::Map(m)
    }
}

/// A signed commit — an `UnsignedCommit` with its ECDSA signature attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    /// DID of the repo owner.
    pub did: String,
    /// Always `3` for v3.
    pub version: i64,
    /// CID of the MST root.
    pub data: Cid,
    /// Revision TID.
    pub rev: String,
    /// Previous commit CID, or `None` for the first commit.
    pub prev: Option<Cid>,
    /// Raw signature bytes (64-byte compact ECDSA over SHA-256 of the
    /// DAG-CBOR encoding of the unsigned portion).
    pub sig: Vec<u8>,
}

impl SignedCommit {
    /// Drop the signature to get the unsigned payload. Useful when you
    /// want to re-verify or re-compute the signing bytes.
    #[must_use]
    pub fn unsigned(&self) -> UnsignedCommit {
        UnsignedCommit {
            did: self.did.clone(),
            version: self.version,
            data: self.data.clone(),
            rev: self.rev.clone(),
            prev: self.prev.clone(),
        }
    }

    /// Serialize the full signed commit (including `sig`) to DAG-CBOR bytes.
    /// This is the on-wire / in-block form.
    pub fn to_cbor(&self) -> Result<Vec<u8>, RepoError> {
        Ok(cbor_encode(&self.to_lex_value())?)
    }

    /// Convert to a `LexValue::Map` with the `sig` field included.
    #[must_use]
    pub fn to_lex_value(&self) -> LexValue {
        let mut m = BTreeMap::new();
        m.insert("did".to_string(), LexValue::String(self.did.clone()));
        m.insert("version".to_string(), LexValue::Integer(self.version));
        m.insert("data".to_string(), LexValue::Cid(self.data.clone()));
        m.insert("rev".to_string(), LexValue::String(self.rev.clone()));
        m.insert(
            "prev".to_string(),
            self.prev
                .as_ref()
                .map_or(LexValue::Null, |cid| LexValue::Cid(cid.clone())),
        );
        m.insert("sig".to_string(), LexValue::Bytes(self.sig.clone()));
        LexValue::Map(m)
    }

    /// Compute the CID of this signed commit (SHA-256 over its canonical
    /// DAG-CBOR bytes, with the DAG-CBOR codec prefix).
    pub fn cid(&self) -> Result<Cid, RepoError> {
        Ok(proto_blue_lex_cbor::cid_for_lex(&self.to_lex_value())?)
    }

    /// Parse a `SignedCommit` from a `LexValue::Map` (typically obtained by
    /// decoding DAG-CBOR bytes pulled from a block store or CAR file).
    ///
    /// Strict: rejects missing fields, wrong types, and versions other
    /// than 3. Callers holding a v2 commit should convert first.
    pub fn from_lex_value(value: &LexValue) -> Result<Self, RepoError> {
        let map = value
            .as_map()
            .ok_or_else(|| RepoError::InvalidCommit("commit is not a CBOR map".into()))?;
        let did = string_field(map, "did")?;
        let version = match map.get("version") {
            Some(LexValue::Integer(n)) => *n,
            _ => return Err(RepoError::InvalidCommit("missing integer `version`".into())),
        };
        if version != COMMIT_VERSION {
            return Err(RepoError::InvalidCommit(format!(
                "unsupported commit version {version}, only v{COMMIT_VERSION} is accepted"
            )));
        }
        let data = cid_field(map, "data")?;
        let rev = string_field(map, "rev")?;
        let prev = nullable_cid_field(map, "prev")?;
        let sig = match map.get("sig") {
            Some(LexValue::Bytes(b)) => b.clone(),
            _ => return Err(RepoError::InvalidCommit("missing bytes `sig`".into())),
        };
        Ok(Self {
            did,
            version,
            data,
            rev,
            prev,
            sig,
        })
    }
}

fn string_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<String, RepoError> {
    match map.get(key) {
        Some(LexValue::String(s)) => Ok(s.clone()),
        _ => Err(RepoError::InvalidCommit(format!(
            "missing or non-string field `{key}`"
        ))),
    }
}

fn cid_field(map: &BTreeMap<String, LexValue>, key: &str) -> Result<Cid, RepoError> {
    match map.get(key) {
        Some(LexValue::Cid(c)) => Ok(c.clone()),
        _ => Err(RepoError::InvalidCommit(format!(
            "missing or non-CID field `{key}`"
        ))),
    }
}

fn nullable_cid_field(
    map: &BTreeMap<String, LexValue>,
    key: &str,
) -> Result<Option<Cid>, RepoError> {
    match map.get(key) {
        Some(LexValue::Cid(c)) => Ok(Some(c.clone())),
        Some(LexValue::Null) => Ok(None),
        // `prev` MUST be present (nullable) per the v3 schema.
        None => Err(RepoError::InvalidCommit(format!(
            "missing field `{key}` (v3 requires nullable, not absent)"
        ))),
        _ => Err(RepoError::InvalidCommit(format!(
            "field `{key}` must be CID or null"
        ))),
    }
}

/// Sign an `UnsignedCommit` with the given signer, producing a `SignedCommit`.
///
/// The signing bytes are the canonical DAG-CBOR encoding of the unsigned
/// commit (sorted map keys, with `prev: null` serialized explicitly when
/// there is no previous commit).
pub fn sign_commit(
    unsigned: &UnsignedCommit,
    signer: &dyn proto_blue_crypto::Signer,
) -> Result<SignedCommit, RepoError> {
    let bytes = unsigned.to_signing_bytes()?;
    let sig = signer.sign(&bytes)?;
    Ok(SignedCommit {
        did: unsigned.did.clone(),
        version: unsigned.version,
        data: unsigned.data.clone(),
        rev: unsigned.rev.clone(),
        prev: unsigned.prev.clone(),
        sig,
    })
}

/// Verify a `SignedCommit`'s signature against a `did:key:z...` string.
///
/// Strict (low-S, compact) — see `proto_blue_crypto::verify_signature`. The
/// signer must hold the private counterpart of the DID's embedded public
/// key or verification fails. Returns `Ok(true)` only on a valid signature.
pub fn verify_commit_sig(commit: &SignedCommit, did_key: &str) -> Result<bool, RepoError> {
    let unsigned = commit.unsigned();
    let bytes = unsigned.to_signing_bytes()?;
    Ok(verify_signature(did_key, &bytes, &commit.sig, false)?)
}

/// Verify a `SignedCommit`'s signature and return `Err(InvalidSignature)`
/// instead of `Ok(false)` on failure. Convenient when a caller expects the
/// signature to be valid and a bad signature is an error condition.
pub fn ensure_commit_sig(commit: &SignedCommit, did_key: &str) -> Result<(), RepoError> {
    if verify_commit_sig(commit, did_key)? {
        Ok(())
    } else {
        Err(RepoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_blue_crypto::{K256Keypair, Keypair, P256Keypair};

    fn dummy_cid(seed: &[u8]) -> Cid {
        // Any deterministic CID will do for these tests; we're exercising
        // signing/verification, not the CID itself.
        proto_blue_lex_cbor::cid_for_lex(&LexValue::Bytes(seed.to_vec())).unwrap()
    }

    fn sample_unsigned(prev: Option<Cid>) -> UnsignedCommit {
        UnsignedCommit::new(
            "did:plc:abcdefghijklmnop".to_string(),
            dummy_cid(b"mst-root"),
            "3jzfcijpj2z2a".to_string(),
            prev,
        )
    }

    #[test]
    fn sign_then_verify_p256_roundtrip() {
        let kp = P256Keypair::generate();
        let unsigned = sample_unsigned(None);
        let signed = sign_commit(&unsigned, &kp).unwrap();
        assert!(verify_commit_sig(&signed, &kp.did()).unwrap());
        assert_eq!(signed.unsigned(), unsigned);
    }

    #[test]
    fn sign_then_verify_k256_roundtrip() {
        let kp = K256Keypair::generate();
        let unsigned = sample_unsigned(Some(dummy_cid(b"prev")));
        let signed = sign_commit(&unsigned, &kp).unwrap();
        assert!(verify_commit_sig(&signed, &kp.did()).unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp = P256Keypair::generate();
        let attacker = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(None), &kp).unwrap();
        // Verifies against issuer key.
        assert!(verify_commit_sig(&signed, &kp.did()).unwrap());
        // Does not verify against some other key.
        assert!(!verify_commit_sig(&signed, &attacker.did()).unwrap());
    }

    #[test]
    fn tampering_any_field_breaks_verification() {
        let kp = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(None), &kp).unwrap();

        // Swap rev.
        let mut bad = signed.clone();
        bad.rev = "3jzfcijpj2z2b".to_string();
        assert!(!verify_commit_sig(&bad, &kp.did()).unwrap());

        // Swap data CID.
        let mut bad = signed.clone();
        bad.data = dummy_cid(b"different-mst");
        assert!(!verify_commit_sig(&bad, &kp.did()).unwrap());

        // Flip prev from None to Some.
        let mut bad = signed.clone();
        bad.prev = Some(dummy_cid(b"fake-prev"));
        assert!(!verify_commit_sig(&bad, &kp.did()).unwrap());

        // Flip a byte of the signature.
        let mut bad = signed;
        bad.sig[0] ^= 0xFF;
        // Could be an error (malformed sig) or a false — either is fine.
        let result = verify_commit_sig(&bad, &kp.did());
        assert!(result.as_ref().map_or(true, |v| !v));
    }

    #[test]
    fn unsigned_commit_encoding_is_deterministic() {
        // Two independently-constructed equal unsigned commits must
        // produce byte-identical signing input — the whole point of
        // DAG-CBOR canonicalization.
        let u1 = sample_unsigned(None);
        let u2 = sample_unsigned(None);
        assert_eq!(
            u1.to_signing_bytes().unwrap(),
            u2.to_signing_bytes().unwrap()
        );
    }

    #[test]
    fn prev_none_and_prev_null_produce_same_signing_bytes() {
        // Sanity: we always serialize `prev: null` for unsigned, so a
        // commit at genesis (None) round-trips through the signing bytes
        // the same way on both sides.
        let u = sample_unsigned(None);
        let bytes1 = u.to_signing_bytes().unwrap();

        let decoded = proto_blue_lex_cbor::decode(&bytes1).unwrap();
        let reenc = proto_blue_lex_cbor::encode(&decoded).unwrap();
        assert_eq!(bytes1, reenc);
    }

    #[test]
    fn ensure_commit_sig_err_on_invalid() {
        let kp = P256Keypair::generate();
        let attacker = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(None), &kp).unwrap();
        assert!(matches!(
            ensure_commit_sig(&signed, &attacker.did()),
            Err(RepoError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_commit_from_lex_value_rejects_v2() {
        let kp = P256Keypair::generate();
        let mut signed = sign_commit(&sample_unsigned(None), &kp).unwrap();
        signed.version = 2;
        // Encode as CBOR, then decode through from_lex_value: rejected.
        let bytes = signed.to_cbor().unwrap();
        let value = proto_blue_lex_cbor::decode(&bytes).unwrap();
        let err = SignedCommit::from_lex_value(&value).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    #[test]
    fn signed_commit_from_lex_value_roundtrips_via_cbor() {
        let kp = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(Some(dummy_cid(b"p"))), &kp).unwrap();
        let bytes = signed.to_cbor().unwrap();
        let value = proto_blue_lex_cbor::decode(&bytes).unwrap();
        let decoded = SignedCommit::from_lex_value(&value).unwrap();
        assert_eq!(decoded, signed);
        // Signature survives the roundtrip and still verifies.
        assert!(verify_commit_sig(&decoded, &kp.did()).unwrap());
    }

    #[test]
    fn signed_commit_from_lex_value_requires_prev_present() {
        // Build a commit with `prev` missing from the map entirely.
        let kp = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(None), &kp).unwrap();
        let mut map = match signed.to_lex_value() {
            LexValue::Map(m) => m,
            _ => unreachable!(),
        };
        map.remove("prev");
        let err = SignedCommit::from_lex_value(&LexValue::Map(map)).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    #[test]
    fn cid_is_deterministic_for_equal_commits() {
        let kp = P256Keypair::generate();
        let signed = sign_commit(&sample_unsigned(None), &kp).unwrap();
        // Cloning must produce the same CID (it's a deterministic hash).
        assert_eq!(
            signed.cid().unwrap().to_string_base32(),
            signed.cid().unwrap().to_string_base32(),
        );
    }
}
