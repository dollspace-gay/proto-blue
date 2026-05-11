#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

//! AT Protocol OAuth 2.0 client: `DPoP`, PKCE, PAR, session management.
//!
//! Implements the OAuth 2.0 authorization code flow for AT Protocol with:
//! - **PKCE** (RFC 7636): Proof Key for Code Exchange with S256 challenge
//! - **`DPoP`** (RFC 9449): Demonstrating Proof of Possession with ES256 or
//!   ES256K (RFC 8812) JWTs
//! - **PAR** (RFC 9126): Pushed Authorization Requests
//! - Token refresh with `DPoP` nonce rotation
//! - Token revocation

pub mod client;
pub mod dpop;
pub mod error;
pub mod jwt_assertion;
pub mod loopback;
pub mod pkce;
pub mod resolve;
pub mod scope;
pub mod session;
pub mod store;
pub mod types;

#[cfg(feature = "identity-resolver")]
pub use resolve::resolve_input;
pub use resolve::{ResolvedInput, verify_token_sub};

pub use client::{DpopNonceCache, OAuthClient, validate_client_metadata};
pub use dpop::{DpopAlg, DpopKey, build_dpop_proof};
pub use error::OAuthError;
pub use jwt_assertion::{CLIENT_ASSERTION_TYPE, ClientKey, ClientKeyset, build_client_assertion};
pub use loopback::{LoopbackClientId, is_loopback_client_id, loopback_client_metadata};
pub use pkce::{PkceChallenge, generate_pkce, verify_pkce};
pub use scope::{PermissionNamespace, Scope, ScopeError, ScopeSet};
pub use session::OAuthSession;
pub use store::{MemoryStore, SimpleStore};
pub use types::{
    AuthState, OAuthClientMetadata, OAuthProtectedResourceMetadata, OAuthServerMetadata,
    OAuthTokenResponse, ParResponse, TokenSet,
};
