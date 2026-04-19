//! Browser-native [`FetchHandler`] implementation backed by `gloo-net`.
//!
//! Available on `wasm32-unknown-unknown` only. Converts
//! [`HttpRequest`]/[`HttpResponse`] to and from
//! [`gloo_net::http::Request`] / [`gloo_net::http::Response`], which drive
//! the browser's native `fetch()` API via `wasm-bindgen`.

use async_trait::async_trait;

use proto_blue_common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};

/// Browser-fetch implementation of [`FetchHandler`].
#[derive(Debug, Clone, Default)]
pub struct WebFetcher {
    _private: (),
}

impl WebFetcher {
    /// Create a new `WebFetcher`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl FetchHandler for WebFetcher {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError> {
        let method = match req.method {
            HttpMethod::Get => gloo_net::http::Method::GET,
            HttpMethod::Post => gloo_net::http::Method::POST,
            HttpMethod::Put => gloo_net::http::Method::PUT,
            HttpMethod::Delete => gloo_net::http::Method::DELETE,
            HttpMethod::Patch => gloo_net::http::Method::PATCH,
            HttpMethod::Head => gloo_net::http::Method::HEAD,
            HttpMethod::Options => gloo_net::http::Method::OPTIONS,
        };

        // `RequestBuilder` exposes the most flexible construction surface —
        // arbitrary method, headers, and a binary body in one chain.
        let mut builder = gloo_net::http::RequestBuilder::new(&req.url).method(method);
        for (key, value) in &req.headers {
            builder = builder.header(key, value);
        }

        let request = if let Some(body) = req.body {
            // `body()` on the `RequestBuilder` accepts anything convertible
            // to `JsValue`; a `Uint8Array` is the natural fit for binary.
            let array = js_sys::Uint8Array::from(body.as_slice());
            builder
                .body(array)
                .map_err(|e| FetchError::Other(e.to_string()))?
        } else {
            builder
                .build()
                .map_err(|e| FetchError::Other(e.to_string()))?
        };

        let response = request
            .send()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?;

        let status = response.status();

        let mut headers = HttpHeaders::new();
        for (name, value) in response.headers().entries() {
            headers.insert(name.to_lowercase(), value);
        }

        let body = response
            .binary()
            .await
            .map_err(|e| FetchError::Body(e.to_string()))?;

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
