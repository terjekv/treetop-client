//! Builder for configuring a [`Client`].

use std::time::Duration;

use reqwest::Certificate;

use crate::error::{Result, TreetopError};
use crate::token::UploadToken;

use super::inner::Client;

/// A builder for constructing a [`Client`] with custom configuration.
///
/// Use [`Client::builder`] to create a new builder, then chain configuration
/// methods before calling [`build`](ClientBuilder::build).
///
/// # Defaults
///
/// | Setting | Default |
/// |---------|---------|
/// | Connect timeout | 5 seconds |
/// | Request timeout | 30 seconds |
/// | Pool idle timeout | 90 seconds |
/// | Accept invalid certs | `false` |
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use treetop_client::{Client, UploadToken};
///
/// let client = Client::builder("https://treetop.example.com")
///     .connect_timeout(Duration::from_secs(10))
///     .upload_token(UploadToken::new("my-token"))
///     .build()
///     .unwrap();
/// ```
pub struct ClientBuilder {
    base_url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    upload_token: Option<UploadToken>,
    correlation_id: Option<String>,
    danger_accept_invalid_certs: bool,
    root_certificates: Vec<Certificate>,
    custom_client: Option<reqwest::Client>,
}

impl ClientBuilder {
    /// Creates a new builder for the given Treetop server base URL.
    ///
    /// The URL should include the scheme and host (e.g. `"https://treetop.example.com"`).
    /// A trailing slash is stripped automatically. The `/api/v1` path prefix is added
    /// internally.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            pool_idle_timeout: Some(Duration::from_secs(90)),
            pool_max_idle_per_host: None,
            upload_token: None,
            correlation_id: None,
            danger_accept_invalid_certs: false,
            root_certificates: Vec::new(),
            custom_client: None,
        }
    }

    /// Sets the TCP connection timeout. Default: 5 seconds.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the overall request timeout (including connection and response). Default: 30 seconds.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets how long idle connections remain in the pool before being closed. Default: 90 seconds.
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.pool_idle_timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of idle connections per host in the pool.
    pub fn pool_max_idle_per_host(mut self, n: usize) -> Self {
        self.pool_max_idle_per_host = Some(n);
        self
    }

    /// Sets the upload token used to authenticate policy uploads.
    ///
    /// Required for [`Client::upload_policies_raw`] and [`Client::upload_policies_json`].
    pub fn upload_token(mut self, token: UploadToken) -> Self {
        self.upload_token = Some(token);
        self
    }

    /// Sets a default correlation ID to include in all requests as the `x-correlation-id` header.
    ///
    /// This can also be set per-request using [`Client::with_correlation_id`].
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Controls whether to accept invalid TLS certificates. Default: `false`.
    ///
    /// **Warning:** Enabling this disables certificate validation and should only be used
    /// in development or testing environments.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Adds a custom root CA certificate to the TLS trust store.
    ///
    /// Use this when connecting to servers with certificates signed by a private CA.
    pub fn add_root_certificate(mut self, cert: Certificate) -> Self {
        self.root_certificates.push(cert);
        self
    }

    /// Uses a pre-configured [`reqwest::Client`], bypassing all connection and TLS settings.
    ///
    /// The upload token and correlation ID from this builder are still applied.
    /// This is an escape hatch for advanced configuration not covered by this builder.
    pub fn with_reqwest_client(mut self, client: reqwest::Client) -> Self {
        self.custom_client = Some(client);
        self
    }

    /// Builds the [`Client`] with the configured settings.
    ///
    /// Returns an error if the underlying reqwest client fails to initialize
    /// (e.g. due to invalid TLS configuration).
    pub fn build(self) -> Result<Client> {
        let base_url = self.base_url.trim_end_matches('/').to_string();
        let api_base = format!("{}/api/v1", base_url);

        let http = if let Some(client) = self.custom_client {
            client
        } else {
            let mut builder = reqwest::Client::builder()
                .connect_timeout(self.connect_timeout)
                .timeout(self.request_timeout)
                .danger_accept_invalid_certs(self.danger_accept_invalid_certs);

            if let Some(idle_timeout) = self.pool_idle_timeout {
                builder = builder.pool_idle_timeout(idle_timeout);
            }

            if let Some(max_idle) = self.pool_max_idle_per_host {
                builder = builder.pool_max_idle_per_host(max_idle);
            }

            for cert in self.root_certificates {
                builder = builder.add_root_certificate(cert);
            }

            builder.build().map_err(TreetopError::Transport)?
        };

        Ok(Client {
            http,
            base_url,
            api_base,
            upload_token: self.upload_token,
            correlation_id: self.correlation_id,
        })
    }
}
