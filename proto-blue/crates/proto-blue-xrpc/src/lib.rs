//! AT Protocol XRPC HTTP client and (optional) server.
//!
//! - [`XrpcClient`] makes outbound XRPC query (GET) and procedure (POST)
//!   calls against a remote service. Its HTTP transport is abstracted
//!   behind the [`proto_blue_common::fetch::FetchHandler`] trait — see
//!   [`reqwest_fetch::ReqwestFetcher`] (native default) and
//!   [`web_fetch::WebFetcher`] (browser, `wasm32-unknown-unknown`).
//! - [`server::XrpcServer`] hosts inbound XRPC endpoints on an
//!   [`axum::Router`]. Available on native targets behind the `server`
//!   feature (default on).

pub mod client;
pub mod error;
pub mod types;

#[cfg(feature = "fetch-reqwest")]
pub mod reqwest_fetch;

#[cfg(all(feature = "fetch-web", target_arch = "wasm32"))]
pub mod web_fetch;

#[cfg(feature = "server")]
pub mod server;

pub use client::{HttpMethod, XrpcClient};
pub use error::{Error, RateLimit, ResponseType, XrpcError};
pub use types::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcResponse};

#[cfg(feature = "server")]
pub use server::{
    AuthContext, AuthVerifier, HandlerContext, HandlerResult, RateLimiter, XrpcServer,
    XrpcServerError,
};
