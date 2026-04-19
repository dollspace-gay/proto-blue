//! Repo sync: parse and verify full-repo CAR files, diff commits.
//!
//! The primary entry points here consume CAR bytes (as emitted by
//! `com.atproto.sync.getRepo` or a firehose `#sync` event) and return
//! validated in-memory structures:
//!
//! - [`verify_repo_car`] — parse a CAR, locate the root commit, verify
//!   the signature (if a signing key is supplied), and load the MST.
//! - [`verify_diff_car`] — same, but also compute a [`DataDiff`] against
//!   a previously-known repo state.
//!
//! All verification is strict:
//! - missing blocks fail (no partial repo loading),
//! - a supplied `did` must match the commit's `did`,
//! - a supplied `did_key` must sign the commit's canonical bytes
//!   with a low-S 64-byte compact ECDSA signature.
//!
//! The caller can skip DID or signature verification by passing `None`
//! for the corresponding parameter — useful for trusted-source loads.

use proto_blue_lex_data::{Cid, LexValue};

use crate::block_map::BlockMap;
use crate::car::read_car_with_root;
use crate::commit::{SignedCommit, verify_commit_sig};
use crate::data_diff::DataDiff;
use crate::error::RepoError;
use crate::mst::MstNode;

/// A repository parsed from a CAR file and verified (as requested).
///
/// Holds the original blocks for any later lookup (e.g. leaf records).
#[derive(Debug, Clone)]
pub struct VerifiedRepo {
    /// CID of the signed commit (the CAR root).
    pub commit_cid: Cid,
    /// The decoded signed commit.
    pub commit: SignedCommit,
    /// The MST rooted at `commit.data`.
    pub mst: MstNode,
    /// All blocks from the CAR — commit, MST nodes, and record blobs.
    pub blocks: BlockMap,
}

impl VerifiedRepo {
    /// Convenience: return the repo's DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.commit.did
    }

    /// Convenience: return the repo's current revision TID.
    #[must_use]
    pub fn rev(&self) -> &str {
        &self.commit.rev
    }

    /// Look up a record block (the bytes behind a leaf CID).
    ///
    /// Returns `None` if the record's block isn't in the CAR —
    /// possible for partial CARs that only include the MST structure
    /// without record payloads.
    #[must_use]
    pub fn get_record_bytes(&self, cid: &Cid) -> Option<&[u8]> {
        self.blocks.get(cid)
    }

    /// Decode a record to a `LexValue` if its block is present.
    pub fn get_record(&self, cid: &Cid) -> Result<Option<LexValue>, RepoError> {
        match self.blocks.get(cid) {
            Some(bytes) => {
                let value = proto_blue_lex_cbor::decode(bytes)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

/// Diff result: a newly-verified repo plus the delta against a previous
/// one. When `prev` is `None`, every leaf in the new repo is an add.
#[derive(Debug, Clone)]
pub struct VerifiedDiff {
    /// The new verified repo.
    pub repo: VerifiedRepo,
    /// Diff against the previous MST.
    pub diff: DataDiff,
}

/// Parse a full-repo CAR and verify it.
///
/// - `car_bytes`: the raw CAR file bytes (as returned by
///   `com.atproto.sync.getRepo`).
/// - `expected_did`: if set, the commit's `did` must equal this value
///   or verification fails with `InvalidCommit`.
/// - `signing_did_key`: if set, the commit's signature must verify
///   against this `did:key:z...`.
///
/// Returns a [`VerifiedRepo`] on success.
pub fn verify_repo_car(
    car_bytes: &[u8],
    expected_did: Option<&str>,
    signing_did_key: Option<&str>,
) -> Result<VerifiedRepo, RepoError> {
    let (root, blocks) = read_car_with_root(car_bytes)?;
    verify_repo(blocks, &root, expected_did, signing_did_key)
}

/// Verify a repo given its blocks and root CID directly. Used when the
/// blocks came from somewhere other than a CAR file (e.g. a stream of
/// firehose commit events).
pub fn verify_repo(
    blocks: BlockMap,
    root: &Cid,
    expected_did: Option<&str>,
    signing_did_key: Option<&str>,
) -> Result<VerifiedRepo, RepoError> {
    // Load commit from root CID.
    let commit_bytes = blocks
        .get(root)
        .ok_or_else(|| RepoError::MissingBlock(root.clone()))?;
    let commit_value = proto_blue_lex_cbor::decode(commit_bytes)?;
    let commit = SignedCommit::from_lex_value(&commit_value)?;

    // Check expected DID.
    if let Some(expected) = expected_did {
        if commit.did != expected {
            return Err(RepoError::InvalidCommit(format!(
                "repo DID mismatch: expected {expected}, got {}",
                commit.did
            )));
        }
    }

    // Verify signature.
    if let Some(did_key) = signing_did_key {
        let ok = verify_commit_sig(&commit, did_key)?;
        if !ok {
            return Err(RepoError::InvalidSignature);
        }
    }

    // Load MST rooted at commit.data.
    let mst = MstNode::load(&commit.data, &blocks)?;

    Ok(VerifiedRepo {
        commit_cid: root.clone(),
        commit,
        mst,
        blocks,
    })
}

/// Parse a CAR, verify it, and diff it against an optional previous
/// repo state. Use this to process firehose commit events against a
/// locally-maintained repo snapshot.
pub fn verify_diff_car(
    car_bytes: &[u8],
    prev_repo: Option<&VerifiedRepo>,
    expected_did: Option<&str>,
    signing_did_key: Option<&str>,
) -> Result<VerifiedDiff, RepoError> {
    let repo = verify_repo_car(car_bytes, expected_did, signing_did_key)?;
    let diff = DataDiff::of(&repo.mst, prev_repo.map(|r| &r.mst))?;
    Ok(VerifiedDiff { repo, diff })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::car::blocks_to_car;
    use crate::commit::{UnsignedCommit, sign_commit};
    use proto_blue_crypto::{K256Keypair, Keypair, P256Keypair};
    use proto_blue_lex_cbor::cid_for_lex;

    /// Build a self-contained repo (commit + MST + a couple of records),
    /// serialize it to a CAR, and return the CAR bytes plus the key
    /// that signed it.
    fn build_repo_car(
        kp: &dyn Keypair,
        records: &[(&str, LexValue)],
        prev: Option<Cid>,
    ) -> (Vec<u8>, SignedCommit) {
        // Build MST, storing record blocks as we go.
        let mut mst = MstNode::empty();
        let mut blocks = BlockMap::new();
        for (key, value) in records {
            let cid = cid_for_lex(value).unwrap();
            blocks.add_value(value).unwrap();
            mst = mst.add(key, cid).unwrap();
        }
        // Flatten the MST into block form.
        let (mst_root, mst_blocks) = mst.get_all_blocks().unwrap();
        blocks.add_map(&mst_blocks);

        // Build and sign the commit.
        let unsigned = UnsignedCommit::new(
            kp.did().replace("did:key:", "did:plc:"), // any DID is fine for testing
            mst_root,
            "3jzfcijpj2z2a".to_string(),
            prev,
        );
        let signed = sign_commit(&unsigned, kp).unwrap();
        let commit_cid = signed.cid().unwrap();
        blocks.set(commit_cid.clone(), signed.to_cbor().unwrap());

        let car = blocks_to_car(Some(&commit_cid), &blocks).unwrap();
        (car, signed)
    }

    /// Build a repo CAR whose commit is signed by `kp` and whose
    /// commit's DID is `kp.did()` (so DID checks pass).
    fn build_repo_car_with_did(
        kp: &dyn Keypair,
        records: &[(&str, LexValue)],
    ) -> (Vec<u8>, SignedCommit) {
        let mut mst = MstNode::empty();
        let mut blocks = BlockMap::new();
        for (key, value) in records {
            let cid = cid_for_lex(value).unwrap();
            blocks.add_value(value).unwrap();
            mst = mst.add(key, cid).unwrap();
        }
        let (mst_root, mst_blocks) = mst.get_all_blocks().unwrap();
        blocks.add_map(&mst_blocks);

        let unsigned = UnsignedCommit::new(kp.did(), mst_root, "3jzfcijpj2z2a".to_string(), None);
        let signed = sign_commit(&unsigned, kp).unwrap();
        let commit_cid = signed.cid().unwrap();
        blocks.set(commit_cid.clone(), signed.to_cbor().unwrap());

        let car = blocks_to_car(Some(&commit_cid), &blocks).unwrap();
        (car, signed)
    }

    // ── verify_repo_car ──

    #[test]
    fn verifies_car_without_did_or_signing_key_check() {
        let kp = P256Keypair::generate();
        let (car, signed) =
            build_repo_car(&kp, &[("coll/a", LexValue::String("hello".into()))], None);

        let repo = verify_repo_car(&car, None, None).unwrap();
        assert_eq!(repo.commit, signed);
        assert_eq!(repo.mst.leaves().len(), 1);
    }

    #[test]
    fn verifies_car_with_signing_key_check() {
        let kp = P256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("v".into()))]);
        let repo = verify_repo_car(&car, Some(&kp.did()), Some(&kp.did())).unwrap();
        assert_eq!(repo.did(), kp.did());
    }

    #[test]
    fn rejects_car_with_wrong_did() {
        let kp = P256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("v".into()))]);
        let err = verify_repo_car(&car, Some("did:plc:someone-else"), None).unwrap_err();
        assert!(matches!(err, RepoError::InvalidCommit(_)));
    }

    #[test]
    fn rejects_car_with_wrong_signing_key() {
        let kp = P256Keypair::generate();
        let attacker = P256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("v".into()))]);
        let err = verify_repo_car(&car, None, Some(&attacker.did())).unwrap_err();
        assert!(matches!(err, RepoError::InvalidSignature));
    }

    #[test]
    fn works_with_k256_signing_key() {
        let kp = K256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("v".into()))]);
        let repo = verify_repo_car(&car, Some(&kp.did()), Some(&kp.did())).unwrap();
        assert_eq!(repo.did(), kp.did());
    }

    #[test]
    fn exposes_record_bytes_and_decoded_values() {
        let kp = P256Keypair::generate();
        let record = LexValue::String("payload".into());
        let (car, _) = build_repo_car(&kp, &[("coll/k", record.clone())], None);
        let repo = verify_repo_car(&car, None, None).unwrap();

        let leaves = repo.mst.leaves();
        assert_eq!(leaves.len(), 1);
        let leaf = &leaves[0];

        // get_record decodes the block back to a LexValue.
        let decoded = repo.get_record(&leaf.value).unwrap().unwrap();
        assert_eq!(decoded, record);

        // get_record_bytes returns the raw block.
        let bytes = repo.get_record_bytes(&leaf.value).unwrap();
        assert!(!bytes.is_empty());

        // Missing record returns None.
        let dummy = cid_for_lex(&LexValue::Null).unwrap();
        if repo.blocks.has(&dummy) {
            // The Null CID happens to already be in the map — skip.
        } else {
            assert!(repo.get_record(&dummy).unwrap().is_none());
        }
    }

    #[test]
    fn rejects_car_missing_root_block() {
        let kp = P256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("v".into()))]);

        // Corrupt the CAR by using a non-existent root. Easiest way:
        // use a made-up CID that isn't in the blocks at all. Since
        // read_car_with_root returns whatever root the CAR declared,
        // and the blocks come from the CAR, I instead test by calling
        // verify_repo directly with a fake root.
        let fake_root = cid_for_lex(&LexValue::String("not-a-commit".into())).unwrap();
        let (_, blocks) = read_car_with_root(&car).unwrap();
        let err = verify_repo(blocks, &fake_root, None, None).unwrap_err();
        assert!(matches!(err, RepoError::MissingBlock(_)));
    }

    // ── verify_diff_car ──

    #[test]
    fn diff_between_two_commits_yields_correct_changes() {
        let kp = P256Keypair::generate();

        // First commit: {a, b}.
        let (car1, _) = build_repo_car(
            &kp,
            &[
                ("coll/a", LexValue::String("a1".into())),
                ("coll/b", LexValue::String("b".into())),
            ],
            None,
        );
        let repo1 = verify_repo_car(&car1, None, None).unwrap();

        // Second commit: {a' (updated), b (same), c (new)}.
        let (car2, _) = build_repo_car(
            &kp,
            &[
                ("coll/a", LexValue::String("a2".into())),
                ("coll/b", LexValue::String("b".into())),
                ("coll/c", LexValue::String("c".into())),
            ],
            Some(repo1.commit_cid.clone()),
        );

        let verified = verify_diff_car(&car2, Some(&repo1), None, None).unwrap();
        assert_eq!(verified.diff.updates.len(), 1);
        assert!(verified.diff.updates.contains_key("coll/a"));
        assert_eq!(verified.diff.adds.len(), 1);
        assert!(verified.diff.adds.contains_key("coll/c"));
        assert!(verified.diff.deletes.is_empty());
    }

    #[test]
    fn diff_with_no_prev_is_null_diff() {
        let kp = P256Keypair::generate();
        let (car, _) = build_repo_car(&kp, &[("coll/a", LexValue::String("a".into()))], None);
        let verified = verify_diff_car(&car, None, None, None).unwrap();
        assert_eq!(verified.diff.adds.len(), 1);
        assert!(verified.diff.updates.is_empty());
        assert!(verified.diff.deletes.is_empty());
    }

    #[test]
    fn diff_car_respects_signing_key_check() {
        let kp = P256Keypair::generate();
        let attacker = P256Keypair::generate();
        let (car, _) = build_repo_car_with_did(&kp, &[("coll/a", LexValue::String("a".into()))]);
        let err = verify_diff_car(&car, None, None, Some(&attacker.did())).unwrap_err();
        assert!(matches!(err, RepoError::InvalidSignature));
    }
}
