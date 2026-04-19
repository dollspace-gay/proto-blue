//! Reqwest-backed [`FetchHandler`] implementation.
//!
//! Default transport on native targets. Builds a `reqwest::RequestBuilder`
//! from the transport-independent [`HttpRequest`], sends it, and converts
//! the `reqwest::Response` back into an [`HttpResponse`].

use async_trait::async_trait;

use super::{FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse};

/// Ships a fresh `reqwest::Client` by default, or wraps a user-supplied one.
#[derive(Debug, Clone)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// Construct with a fresh default `reqwest::Client`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Wrap a user-supplied `reqwest::Client` (useful for shared connection
    /// pools, custom TLS, proxies, etc.).
    #[must_use]
    pub const fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Access the inner `reqwest::Client`.
    #[must_use]
    pub const fn inner(&self) -> &reqwest::Client {
        &self.client
    }
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FetchHandler for ReqwestFetcher {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError> {
        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        };

        let mut builder = self.client.request(method, &req.url);

        for (key, value) in &req.headers {
            builder = builder.header(key, value);
        }

        if let Some(body) = req.body {
            builder = builder.body(body);
        }

        let response = builder.send().await.map_err(reqwest_to_fetch_error)?;
        let status = response.status().as_u16();

        let mut headers = HttpHeaders::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| FetchError::Body(e.to_string()))?
            .to_vec();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

fn reqwest_to_fetch_error(e: reqwest::Error) -> FetchError {
    // Order matters: `is_request` is broad and would swallow the more
    // specific classifications below, so check timeout / builder / body
    // first. Connection-refused / DNS-failure / TLS errors ultimately
    // surface as `is_request` in reqwest 0.12, hence the final Network
    // fallback for any error produced while issuing a request.
    if e.is_timeout() {
        FetchError::Timeout
    } else if e.is_builder() {
        FetchError::InvalidUrl(e.to_string())
    } else if e.is_body() || e.is_decode() {
        FetchError::Body(e.to_string())
    } else if e.is_connect() || e.is_request() {
        FetchError::Network(e.to_string())
    } else {
        FetchError::Other(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetches_against_localhost_and_parses_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            )
            .await
            .unwrap();
            sock.flush().await.unwrap();
        });

        let fetcher = ReqwestFetcher::new();
        let resp = fetcher
            .fetch(HttpRequest::get(format!("http://{addr}/test")))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("content-type"), Some("application/json"));
        assert!(resp.is_success());
    }

    #[tokio::test]
    async fn connection_refused_maps_to_network_error() {
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let fetcher = ReqwestFetcher::from_client(
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .build()
                .unwrap(),
        );
        let err = fetcher
            .fetch(HttpRequest::get(format!("http://127.0.0.1:{port}")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::Network(_) | FetchError::Timeout),
            "expected Network or Timeout, got: {err:?}",
        );
    }

    #[test]
    fn default_is_new() {
        let a = ReqwestFetcher::default();
        let _ = a.inner();
    }
}
