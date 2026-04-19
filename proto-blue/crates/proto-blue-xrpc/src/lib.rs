//! AT Protocol XRPC HTTP client and (optional) server.
//!
//! - [`XrpcClient`] makes outbound XRPC query (GET) and procedure (POST)
//!   calls against a remote service. HTTP transport is abstracted behind
//!   [`proto_blue_common::fetch::FetchHandler`]; the reqwest-backed
//!   [`proto_blue_common::fetch::ReqwestFetcher`] is the default on native
//!   targets and the `gloo-net`-backed `WebFetcher` is available on
//!   `wasm32-unknown-unknown`.
//! - [`server::XrpcServer`] hosts inbound XRPC endpoints on an
//!   [`axum::Router`]. Available on native targets behind the `server`
//!   feature (default on).

pub mod client;
pub mod error;
pub mod types;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "server")]
pub mod rate_limit;

pub use client::{HttpMethod, XrpcClient};
pub use error::{Error, RateLimit, ResponseType, XrpcError};
pub use types::{
    CallOptions, HeadersMap, LexiconValidation, QueryParams, QueryValue, XrpcBody, XrpcResponse,
};

#[cfg(feature = "server")]
pub use rate_limit::{CombinedLimiter, RateLimitDecision, TokenBucketLimiter};
#[cfg(feature = "server")]
pub use server::{
    AuthContext, AuthVerifier, HandlerContext, HandlerResult, RateLimiter, XrpcServer,
    XrpcServerError,
};
