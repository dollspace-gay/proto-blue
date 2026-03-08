//! CID set — a set of content identifiers.

use std::collections::HashSet;

use proto_blue_lex_data::Cid;

/// A set of CIDs, internally using string representation for efficient lookup.
#[derive(Debug, Clone, Default)]
pub struct CidSet {
    set: HashSet<String>,
}

impl CidSet {
    /// Create a new empty CID set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a CID set from a list of CIDs.
    pub fn from_cids(cids: &[Cid]) -> Self {
        let mut s = Self::new();
        for cid in cids {
            s.add(cid.clone());
        }
        s
    }

    /// Add a CID to the set.
    pub fn add(&mut self, cid: Cid) -> &mut Self {
        self.set.insert(cid.to_string_base32());
        self
    }

    /// Merge another set into this one (union).
    pub fn add_set(&mut self, other: &CidSet) -> &mut Self {
        for s in &other.set {
            self.set.insert(s.clone());
        }
        self
    }

    /// Remove all CIDs in `other` from this set (difference).
    pub fn subtract_set(&mut self, other: &CidSet) -> &mut Self {
        for s in &other.set {
            self.set.remove(s);
        }
        self
    }

    /// Remove a CID from the set.
    pub fn delete(&mut self, cid: &Cid) -> &mut Self {
        self.set.remove(&cid.to_string_base32());
        self
    }

    /// Check if a CID is in the set.
    pub fn has(&self, cid: &Cid) -> bool {
        self.set.contains(&cid.to_string_base32())
    }

    /// Get the number of CIDs in the set.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Remove all CIDs from the set.
    pub fn clear(&mut self) {
        self.set.clear();
    }

    /// Convert to a list of CID strings.
    pub fn to_strings(&self) -> Vec<&str> {
        self.set.iter().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cid() -> Cid {
        // Create a CID from some test data
        proto_blue_lex_cbor::cid_for_lex(&proto_blue_lex_data::LexValue::String("test".into())).unwrap()
    }

    fn test_cid2() -> Cid {
        proto_blue_lex_cbor::cid_for_lex(&proto_blue_lex_data::LexValue::String("test2".into())).unwrap()
    }

    #[test]
    fn add_and_has() {
        let mut set = CidSet::new();
        let cid = test_cid();
        assert!(!set.has(&cid));
        set.add(cid.clone());
        assert!(set.has(&cid));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn delete() {
        let mut set = CidSet::new();
        let cid = test_cid();
        set.add(cid.clone());
        assert!(set.has(&cid));
        set.delete(&cid);
        assert!(!set.has(&cid));
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn add_set_and_subtract() {
        let mut set1 = CidSet::new();
        let mut set2 = CidSet::new();
        let cid1 = test_cid();
        let cid2 = test_cid2();

        set1.add(cid1.clone());
        set2.add(cid2.clone());

        set1.add_set(&set2);
        assert!(set1.has(&cid1));
        assert!(set1.has(&cid2));
        assert_eq!(set1.len(), 2);

        set1.subtract_set(&set2);
        assert!(set1.has(&cid1));
        assert!(!set1.has(&cid2));
        assert_eq!(set1.len(), 1);
    }

    #[test]
    fn duplicate_add() {
        let mut set = CidSet::new();
        let cid = test_cid();
        set.add(cid.clone());
        set.add(cid.clone());
        assert_eq!(set.len(), 1);
    }
}
