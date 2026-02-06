//! AT Protocol OAuth 2.0 client: DPoP, PKCE, PAR, session management.
//!
//! Implements the OAuth 2.0 authorization code flow for AT Protocol with:
//! - **PKCE** (RFC 7636): Proof Key for Code Exchange with S256 challenge
//! - **DPoP** (RFC 9449): Demonstrating Proof of Possession with ES256 JWTs
//! - **PAR** (RFC 9126): Pushed Authorization Requests
//! - Token refresh with DPoP nonce rotation
//! - Token revocation

pub mod client;
pub mod dpop;
pub mod error;
pub mod pkce;
pub mod session;
pub mod types;

pub use client::{DpopNonceCache, OAuthClient};
pub use dpop::{DpopKey, build_dpop_proof};
pub use error::OAuthError;
pub use pkce::{PkceChallenge, generate_pkce, verify_pkce};
pub use session::OAuthSession;
pub use types::{
    AuthState, OAuthClientMetadata, OAuthServerMetadata, OAuthTokenResponse, ParResponse, TokenSet,
};
