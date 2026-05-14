//! atproto OAuth scope strings.
//!
//! atproto defines a fixed vocabulary of static scopes plus a
//! parameterized "permission" scope syntax. This module parses,
//! validates, and normalizes both.
//!
//! ## Static scopes
//!
//! Exact-string tokens with no parameters:
//!
//! | Scope                  | Meaning                                       |
//! |------------------------|-----------------------------------------------|
//! | `atproto`              | Base atproto authentication.                  |
//! | `transition:email`     | Legacy: read the account email.               |
//! | `transition:generic`   | Legacy: broad repo + blob + rpc access.       |
//! | `transition:chat.bsky` | Legacy: bsky chat DMs.                        |
//!
//! ## Permission scopes
//!
//! Namespaced tokens of the form `<ns>:<parameters>` where `<ns>` is one
//! of `account`, `blob`, `identity`, `include`, `repo`, `rpc`. The
//! parameters' internal structure varies per namespace; we keep them as
//! an opaque string for now and validate only the namespace. A future
//! revision can add deep per-namespace parsers without breaking the
//! public API here (they'd just become stricter on the same inputs).
//!
//! ## Normalization
//!
//! OAuth scope strings are space-separated. The canonical form we emit
//! is: parsed → deduped → lexically sorted → re-joined by space. Two
//! scope strings that are equivalent under this normalization compare
//! byte-equal after `ScopeSet::parse(s).unwrap().to_string()`.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// A parsed atproto OAuth scope.
///
/// `Ord` is defined by the on-wire display form (not by enum-variant
/// declaration order) so that `ScopeSet::to_string()` produces a
/// lexical sort — two scope strings that name the same set compare
/// byte-equal after round-tripping through the parser.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `atproto`
    Atproto,
    /// `transition:email`
    TransitionEmail,
    /// `transition:generic`
    TransitionGeneric,
    /// `transition:chat.bsky`
    TransitionChatBsky,
    /// `account:...`, `blob:...`, `identity:...`, `include:...`,
    /// `repo:...`, `rpc:...`.
    ///
    /// The parameter portion (everything after the first `:`) is kept
    /// opaque — we validate only the namespace here. Callers that need
    /// to inspect parameters can match on `Scope::Permission { namespace,
    /// parameters, .. }` and parse themselves.
    Permission {
        namespace: PermissionNamespace,
        parameters: String,
    },
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by on-wire display form so BTreeSet iteration yields
        // lexical order. Slightly less efficient than a variant-first
        // comparator, but it's the order users (and the TS SDK) expect.
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Valid permission-scope namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionNamespace {
    Account,
    Blob,
    Identity,
    Include,
    Repo,
    Rpc,
}

impl PermissionNamespace {
    /// The string form used on the wire (`account`, `blob`, ...).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Blob => "blob",
            Self::Identity => "identity",
            Self::Include => "include",
            Self::Repo => "repo",
            Self::Rpc => "rpc",
        }
    }

    fn from_str_exact(s: &str) -> Option<Self> {
        match s {
            "account" => Some(Self::Account),
            "blob" => Some(Self::Blob),
            "identity" => Some(Self::Identity),
            "include" => Some(Self::Include),
            "repo" => Some(Self::Repo),
            "rpc" => Some(Self::Rpc),
            _ => None,
        }
    }
}

/// Errors raised when parsing a scope string.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScopeError {
    #[error("empty scope token")]
    Empty,

    #[error("unknown scope: {0:?}")]
    Unknown(String),

    #[error("missing parameters after `{namespace}:`")]
    MissingParameters { namespace: &'static str },
}

impl Scope {
    /// Parse a single whitespace-free scope token.
    ///
    /// Rejects:
    /// - empty input,
    /// - unknown static tokens,
    /// - unknown namespace prefixes,
    /// - empty parameter part (`repo:` with nothing after).
    pub fn parse(s: &str) -> Result<Self, ScopeError> {
        if s.is_empty() {
            return Err(ScopeError::Empty);
        }

        match s {
            "atproto" => return Ok(Self::Atproto),
            "transition:email" => return Ok(Self::TransitionEmail),
            "transition:generic" => return Ok(Self::TransitionGeneric),
            "transition:chat.bsky" => return Ok(Self::TransitionChatBsky),
            _ => {}
        }

        // Parameterized permission scope.
        if let Some((head, tail)) = s.split_once(':')
            && let Some(ns) = PermissionNamespace::from_str_exact(head)
        {
            if tail.is_empty() {
                return Err(ScopeError::MissingParameters {
                    namespace: ns.as_str(),
                });
            }
            return Ok(Self::Permission {
                namespace: ns,
                parameters: tail.to_string(),
            });
        }

        Err(ScopeError::Unknown(s.to_string()))
    }

    /// `true` iff this is one of the four static scopes.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        matches!(
            self,
            Self::Atproto
                | Self::TransitionEmail
                | Self::TransitionGeneric
                | Self::TransitionChatBsky
        )
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Atproto => f.write_str("atproto"),
            Self::TransitionEmail => f.write_str("transition:email"),
            Self::TransitionGeneric => f.write_str("transition:generic"),
            Self::TransitionChatBsky => f.write_str("transition:chat.bsky"),
            Self::Permission {
                namespace,
                parameters,
            } => write!(f, "{}:{}", namespace.as_str(), parameters),
        }
    }
}

impl FromStr for Scope {
    type Err = ScopeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A set of parsed, deduplicated, and lexically sorted scopes.
///
/// `ScopeSet` is the parsed form of a space-separated OAuth scope
/// string. Construction guarantees:
/// - every entry parses successfully,
/// - duplicates are collapsed,
/// - entries are held in a `BTreeSet`, so `to_string()` always emits
///   them in the same canonical order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
    scopes: BTreeSet<Scope>,
}

impl ScopeSet {
    /// Create an empty scope set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scopes: BTreeSet::new(),
        }
    }

    /// Parse a space-separated scope string. Strict: any unknown scope
    /// token causes the whole parse to fail. Use `parse_lax` if you
    /// want to silently drop unknown tokens (e.g. for forward-compat
    /// when receiving a scope string from a newer AS).
    pub fn parse(input: &str) -> Result<Self, ScopeError> {
        let mut set = BTreeSet::new();
        for token in input.split_whitespace() {
            set.insert(Scope::parse(token)?);
        }
        Ok(Self { scopes: set })
    }

    /// Parse a space-separated scope string, silently ignoring tokens
    /// that don't parse. Returns `(set, dropped)` where `dropped` is the
    /// list of tokens that failed to parse so a caller can log or
    /// surface them without failing the whole negotiation.
    #[must_use]
    pub fn parse_lax(input: &str) -> (Self, Vec<String>) {
        let mut set = BTreeSet::new();
        let mut dropped = Vec::new();
        for token in input.split_whitespace() {
            match Scope::parse(token) {
                Ok(scope) => {
                    set.insert(scope);
                }
                Err(_) => dropped.push(token.to_string()),
            }
        }
        (Self { scopes: set }, dropped)
    }

    /// Insert a scope, returning `true` if it was newly added.
    pub fn insert(&mut self, scope: Scope) -> bool {
        self.scopes.insert(scope)
    }

    /// Check membership.
    #[must_use]
    pub fn contains(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// Number of scopes in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// `true` if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Iterate over the scopes in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter()
    }

    // ── Transition-scope convenience checks ─────────────────────────
    //
    // Mirror the TS `ScopePermissionsTransition` helpers. These are the
    // most common legacy checks: whether the caller was granted one of
    // the broad `transition:*` scopes that override fine-grained
    // permission matching.

    /// `true` if the set contains `transition:generic` (legacy broad
    /// repo + blob + rpc access).
    #[must_use]
    pub fn has_transition_generic(&self) -> bool {
        self.scopes.contains(&Scope::TransitionGeneric)
    }

    /// `true` if the set contains `transition:email` (legacy email read).
    #[must_use]
    pub fn has_transition_email(&self) -> bool {
        self.scopes.contains(&Scope::TransitionEmail)
    }

    /// `true` if the set contains `transition:chat.bsky` (legacy chat).
    #[must_use]
    pub fn has_transition_chat_bsky(&self) -> bool {
        self.scopes.contains(&Scope::TransitionChatBsky)
    }

    /// `true` if the set contains the base `atproto` scope. OAuth clients
    /// must always request this; its absence is usually a client bug.
    #[must_use]
    pub fn has_atproto(&self) -> bool {
        self.scopes.contains(&Scope::Atproto)
    }
}

impl fmt::Display for ScopeSet {
    /// Emit as a space-separated string in canonical (sorted) order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for scope in &self.scopes {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            write!(f, "{scope}")?;
        }
        Ok(())
    }
}

impl FromStr for ScopeSet {
    type Err = ScopeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scope::parse ─────────────────────────────────────────────────

    #[test]
    fn parses_each_static_scope() {
        assert_eq!(Scope::parse("atproto").unwrap(), Scope::Atproto);
        assert_eq!(
            Scope::parse("transition:email").unwrap(),
            Scope::TransitionEmail
        );
        assert_eq!(
            Scope::parse("transition:generic").unwrap(),
            Scope::TransitionGeneric
        );
        assert_eq!(
            Scope::parse("transition:chat.bsky").unwrap(),
            Scope::TransitionChatBsky
        );
    }

    #[test]
    fn parses_each_permission_namespace() {
        for ns in ["account", "blob", "identity", "include", "repo", "rpc"] {
            let raw = format!("{ns}:thing");
            let scope = Scope::parse(&raw).unwrap();
            let Scope::Permission {
                namespace,
                parameters,
            } = scope
            else {
                panic!("expected Permission, got {scope:?}");
            };
            assert_eq!(namespace.as_str(), ns);
            assert_eq!(parameters, "thing");
        }
    }

    #[test]
    fn permission_parameters_are_opaque() {
        // Whatever comes after the first `:` is preserved verbatim,
        // including further colons, equals signs, and ampersands.
        let scope = Scope::parse("repo:app.bsky.feed.post?action=create&action=update").unwrap();
        let Scope::Permission { parameters, .. } = scope else {
            panic!("expected Permission");
        };
        assert_eq!(parameters, "app.bsky.feed.post?action=create&action=update");
    }

    // ── Scope::parse errors ─────────────────────────────────────────

    #[test]
    fn empty_token_is_error() {
        assert!(matches!(Scope::parse(""), Err(ScopeError::Empty)));
    }

    #[test]
    fn unknown_static_token_is_error() {
        assert!(matches!(Scope::parse("admin"), Err(ScopeError::Unknown(_))));
        assert!(matches!(
            Scope::parse("transition:admin"),
            Err(ScopeError::Unknown(_))
        ));
    }

    #[test]
    fn unknown_namespace_is_error() {
        assert!(matches!(
            Scope::parse("legacy:something"),
            Err(ScopeError::Unknown(_))
        ));
    }

    #[test]
    fn permission_without_parameters_is_error() {
        for ns in ["account", "blob", "identity", "include", "repo", "rpc"] {
            let raw = format!("{ns}:");
            assert!(
                matches!(
                    Scope::parse(&raw),
                    Err(ScopeError::MissingParameters { .. })
                ),
                "expected MissingParameters for {raw:?}"
            );
        }
    }

    // ── Scope display roundtrips parse ──────────────────────────────

    #[test]
    fn display_roundtrips_through_parse() {
        let cases = [
            "atproto",
            "transition:email",
            "transition:generic",
            "transition:chat.bsky",
            "account:email?action=read",
            "blob:type=image/*",
            "identity:handle",
            "include:foo",
            "repo:app.bsky.feed.post",
            "rpc:*",
        ];
        for s in cases {
            let parsed = Scope::parse(s).unwrap();
            assert_eq!(parsed.to_string(), s);
            let reparsed = Scope::parse(&parsed.to_string()).unwrap();
            assert_eq!(parsed, reparsed);
        }
    }

    // ── ScopeSet ────────────────────────────────────────────────────

    #[test]
    fn scope_set_parse_emits_canonical_sort_order() {
        // Out-of-order, with duplicates and extra spaces.
        let input = "transition:email  atproto  transition:email  rpc:*";
        let set = ScopeSet::parse(input).unwrap();
        assert_eq!(set.to_string(), "atproto rpc:* transition:email");
    }

    #[test]
    fn scope_set_empty_string_is_empty_set() {
        let set = ScopeSet::parse("").unwrap();
        assert!(set.is_empty());
        assert_eq!(set.to_string(), "");
    }

    #[test]
    fn scope_set_whitespace_only_is_empty_set() {
        let set = ScopeSet::parse("   \t  \n ").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn scope_set_parse_strict_rejects_unknown() {
        let result = ScopeSet::parse("atproto totallyMadeUp");
        assert!(matches!(result, Err(ScopeError::Unknown(_))));
    }

    #[test]
    fn scope_set_parse_lax_drops_unknown_but_keeps_valid() {
        let (set, dropped) = ScopeSet::parse_lax("atproto totallyMadeUp repo:foo");
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Scope::Atproto));
        assert_eq!(dropped, vec!["totallyMadeUp".to_string()]);
    }

    #[test]
    fn scope_set_dedupe() {
        let set = ScopeSet::parse("atproto atproto atproto").unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.to_string(), "atproto");
    }

    #[test]
    fn scope_set_transition_helpers() {
        let set =
            ScopeSet::parse("atproto transition:generic transition:email transition:chat.bsky")
                .unwrap();
        assert!(set.has_atproto());
        assert!(set.has_transition_generic());
        assert!(set.has_transition_email());
        assert!(set.has_transition_chat_bsky());
    }

    #[test]
    fn scope_set_transition_helpers_negative() {
        let set = ScopeSet::parse("atproto repo:*").unwrap();
        assert!(set.has_atproto());
        assert!(!set.has_transition_generic());
        assert!(!set.has_transition_email());
        assert!(!set.has_transition_chat_bsky());
    }

    #[test]
    fn scope_set_iter_is_sorted() {
        let set = ScopeSet::parse("rpc:* atproto repo:foo blob:bar").unwrap();
        let tokens: Vec<String> = set.iter().map(std::string::ToString::to_string).collect();
        let mut expected = tokens.clone();
        expected.sort();
        assert_eq!(tokens, expected);
    }

    #[test]
    fn scope_set_from_str_trait_works() {
        let set: ScopeSet = "atproto repo:foo".parse().unwrap();
        assert_eq!(set.len(), 2);
    }

    /// Normalization: two scope strings that name the same set must
    /// round-trip to byte-identical canonical output.
    #[test]
    fn scope_set_normalization_is_idempotent() {
        let a = ScopeSet::parse("transition:generic atproto")
            .unwrap()
            .to_string();
        let b = ScopeSet::parse("atproto transition:generic")
            .unwrap()
            .to_string();
        let c = ScopeSet::parse(&a).unwrap().to_string();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
