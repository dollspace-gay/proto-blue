//! The LexValue recursive data type used in AT Protocol's data model.
//!
//! LexValue represents any valid value in the Lexicon data model.
//! It is analogous to JSON but includes CIDs and byte arrays as
//! first-class types, and forbids floating-point numbers.

use std::collections::BTreeMap;

use crate::Cid;

/// A value in the AT Protocol Lexicon data model.
///
/// This is the fundamental recursive type for all AT Protocol data.
/// It mirrors JSON but adds CID and Bytes types, and restricts
/// numbers to integers only (no floats).
///
/// Maps use `BTreeMap` for deterministic key ordering, which is
/// required by DAG-CBOR encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum LexValue {
    /// JSON null.
    Null,
    /// A boolean value.
    Bool(bool),
    /// An integer value (no floating point allowed in AT Protocol).
    Integer(i64),
    /// A UTF-8 string.
    String(String),
    /// Raw byte data.
    Bytes(Vec<u8>),
    /// A content identifier (CID).
    Cid(Cid),
    /// An ordered array of values.
    Array(Vec<LexValue>),
    /// An object with string keys, ordered deterministically.
    Map(BTreeMap<String, LexValue>),
}

impl LexValue {
    /// Check if this value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, LexValue::Null)
    }

    /// Check if this value is a scalar (not a collection).
    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            LexValue::Null
                | LexValue::Bool(_)
                | LexValue::Integer(_)
                | LexValue::String(_)
                | LexValue::Bytes(_)
                | LexValue::Cid(_)
        )
    }

    /// Try to get this value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            LexValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get this value as an integer.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            LexValue::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Try to get this value as a string reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            LexValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get this value as bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            LexValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Try to get this value as a CID reference.
    pub fn as_cid(&self) -> Option<&Cid> {
        match self {
            LexValue::Cid(c) => Some(c),
            _ => None,
        }
    }

    /// Try to get this value as an array reference.
    pub fn as_array(&self) -> Option<&[LexValue]> {
        match self {
            LexValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Try to get this value as a map reference.
    pub fn as_map(&self) -> Option<&BTreeMap<String, LexValue>> {
        match self {
            LexValue::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Try to get the `$type` field if this is a typed map.
    pub fn type_name(&self) -> Option<&str> {
        self.as_map()
            .and_then(|m| m.get("$type"))
            .and_then(|v| v.as_str())
    }
}

impl From<bool> for LexValue {
    fn from(b: bool) -> Self {
        LexValue::Bool(b)
    }
}

impl From<i64> for LexValue {
    fn from(n: i64) -> Self {
        LexValue::Integer(n)
    }
}

impl From<i32> for LexValue {
    fn from(n: i32) -> Self {
        LexValue::Integer(n as i64)
    }
}

impl From<String> for LexValue {
    fn from(s: String) -> Self {
        LexValue::String(s)
    }
}

impl From<&str> for LexValue {
    fn from(s: &str) -> Self {
        LexValue::String(s.to_string())
    }
}

impl From<Vec<u8>> for LexValue {
    fn from(b: Vec<u8>) -> Self {
        LexValue::Bytes(b)
    }
}

impl From<Cid> for LexValue {
    fn from(c: Cid) -> Self {
        LexValue::Cid(c)
    }
}

impl From<Vec<LexValue>> for LexValue {
    fn from(a: Vec<LexValue>) -> Self {
        LexValue::Array(a)
    }
}

impl From<BTreeMap<String, LexValue>> for LexValue {
    fn from(m: BTreeMap<String, LexValue>) -> Self {
        LexValue::Map(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cid;

    #[test]
    fn scalar_types() {
        assert!(LexValue::Null.is_null());
        assert!(LexValue::Null.is_scalar());
        assert!(LexValue::Bool(true).is_scalar());
        assert!(LexValue::Integer(42).is_scalar());
        assert!(LexValue::String("hello".into()).is_scalar());
        assert!(LexValue::Bytes(vec![1, 2, 3]).is_scalar());
        assert!(LexValue::Cid(Cid::for_cbor(b"test")).is_scalar());
    }

    #[test]
    fn collection_types_not_scalar() {
        assert!(!LexValue::Array(vec![]).is_scalar());
        assert!(!LexValue::Map(BTreeMap::new()).is_scalar());
    }

    #[test]
    fn accessors() {
        assert_eq!(LexValue::Bool(true).as_bool(), Some(true));
        assert_eq!(LexValue::Integer(42).as_integer(), Some(42));
        assert_eq!(LexValue::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(
            LexValue::Bytes(vec![1, 2]).as_bytes(),
            Some([1u8, 2].as_slice())
        );
    }

    #[test]
    fn type_name() {
        let mut map = BTreeMap::new();
        map.insert(
            "$type".to_string(),
            LexValue::String("app.bsky.feed.post".into()),
        );
        let val = LexValue::Map(map);
        assert_eq!(val.type_name(), Some("app.bsky.feed.post"));
    }

    #[test]
    fn from_conversions() {
        let _: LexValue = true.into();
        let _: LexValue = 42i64.into();
        let _: LexValue = "hello".into();
        let _: LexValue = vec![1u8, 2, 3].into();
    }

    #[test]
    fn equality() {
        let a = LexValue::Integer(42);
        let b = LexValue::Integer(42);
        let c = LexValue::Integer(43);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
