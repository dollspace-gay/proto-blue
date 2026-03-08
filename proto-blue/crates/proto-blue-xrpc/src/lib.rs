//! AT Protocol XRPC HTTP client.
//!
//! Provides an HTTP client for making XRPC query (GET) and procedure (POST)
//! calls to AT Protocol services.

pub mod client;
pub mod error;
pub mod types;

pub use client::{HttpMethod, XrpcClient};
pub use error::{Error, ResponseType, XrpcError};
pub use types::{CallOptions, HeadersMap, QueryParams, QueryValue, XrpcBody, XrpcResponse};
