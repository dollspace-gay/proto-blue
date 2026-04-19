//! AT Protocol XRPC HTTP client and server.
//!
//! - [`XrpcClient`] makes outbound XRPC query (GET) and procedure (POST)
//!   calls against a remote service.
//! - [`server::XrpcServer`] hosts inbound XRPC endpoints on an
//!   [`axum::Router`], with pluggable auth and rate-limiting.

pub mod client;
pub mod error;
pub mod server;
pub mod types;

pub use client::{HttpMethod, XrpcClient};
pub use error::{Error, RateLimit, ResponseType, XrpcError};
pub use server::{
    AuthContext, AuthVerifier, HandlerContext, HandlerResult, RateLimiter, XrpcServer,
    XrpcServerError,
};
pub use types::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcResponse};
