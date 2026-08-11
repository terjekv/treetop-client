//! Builder for configuring a [`Client`].

use std::time::Duration;

use reqwest::Certificate;

use crate::error::{Result, TreetopError};
use crate::token::UploadToken;
use crate::types::RequestLimits;

use super::capability::{CanUpload, ReadOnly};
use super::inner::{
    BaseUrl, Client, ClientState, CorrelationId, RequestSizeLimit, ResponseSizeLimit,
};

const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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
/// | Maximum request body | 16 MiB |
/// | Maximum successful response body | 16 MiB |
/// | Request-context limits | [`RequestLimits::default`] |
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
///     .upload_token(UploadToken::new("my-token").unwrap())
///     .build()
///     .unwrap();
/// ```
pub struct ClientBuilder<Capability = ReadOnly> {
    base_url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    capability: Capability,
    correlation_id: Option<String>,
    danger_accept_invalid_certs: bool,
    root_certificates: Vec<Certificate>,
    custom_client: Option<reqwest::Client>,
    max_request_bytes: usize,
    max_response_bytes: usize,
    request_limits: RequestLimits,
    danger_allow_insecure_uploads: bool,
}

impl ClientBuilder<ReadOnly> {
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
            capability: ReadOnly,
            correlation_id: None,
            danger_accept_invalid_certs: false,
            root_certificates: Vec::new(),
            custom_client: None,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            request_limits: RequestLimits::default(),
            danger_allow_insecure_uploads: false,
        }
    }

    /// Adds validated upload authority and transitions this builder to [`CanUpload`].
    ///
    /// A client built after this transition exposes policy and schema upload methods. Clients
    /// built without this transition do not expose those methods.
    pub fn upload_token(self, token: UploadToken) -> ClientBuilder<CanUpload> {
        let Self {
            base_url,
            connect_timeout,
            request_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            capability: _,
            correlation_id,
            danger_accept_invalid_certs,
            root_certificates,
            custom_client,
            max_request_bytes,
            max_response_bytes,
            request_limits,
            danger_allow_insecure_uploads,
        } = self;

        ClientBuilder {
            base_url,
            connect_timeout,
            request_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            capability: CanUpload::new(token),
            correlation_id,
            danger_accept_invalid_certs,
            root_certificates,
            custom_client,
            max_request_bytes,
            max_response_bytes,
            request_limits,
            danger_allow_insecure_uploads,
        }
    }
}

impl<Capability> ClientBuilder<Capability> {
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
    /// This is an escape hatch for advanced configuration not covered by this builder. When an
    /// upload token is configured, ensure the custom client's redirect policy cannot forward the
    /// `X-Upload-Token` header to an unintended target.
    pub fn with_reqwest_client(mut self, client: reqwest::Client) -> Self {
        self.custom_client = Some(client);
        self
    }

    /// Sets the maximum accepted successful response body size. Default: 16 MiB.
    ///
    /// This limit protects callers from unbounded response-buffer memory use.
    /// Setting it to zero causes [`build`](Self::build) to return a configuration error.
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Sets the maximum serialized request body size. Default: 16 MiB.
    ///
    /// The limit applies to authorization requests and raw or JSON-wrapped uploads before any
    /// network request is sent. Setting it to zero causes [`build`](Self::build) to fail.
    pub fn max_request_bytes(mut self, max_request_bytes: usize) -> Self {
        self.max_request_bytes = max_request_bytes;
        self
    }

    /// Sets the limits automatically enforced for each authorization request's context.
    ///
    /// The defaults match current Treetop server defaults. Callers targeting a server with
    /// different reported limits should pass those values here.
    pub fn request_limits(mut self, request_limits: RequestLimits) -> Self {
        self.request_limits = request_limits;
        self
    }

    fn build_state(
        self,
        validate_upload_transport: bool,
        upload_redactor: Option<CanUpload>,
    ) -> Result<(ClientState, Option<CorrelationId>, Capability)> {
        let base_url = BaseUrl::parse(&self.base_url)?;
        if validate_upload_transport {
            base_url.validate_upload_transport(self.danger_allow_insecure_uploads)?;
        }
        let correlation_id = self.correlation_id.map(CorrelationId::parse).transpose()?;
        let max_request_bytes = RequestSizeLimit::new(self.max_request_bytes)?;
        let max_response_bytes = ResponseSizeLimit::new(self.max_response_bytes)?;

        let http = if let Some(client) = self.custom_client {
            client
        } else {
            let mut builder = reqwest::Client::builder()
                .connect_timeout(self.connect_timeout)
                .timeout(self.request_timeout)
                .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
                .redirect(reqwest::redirect::Policy::none());

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

        Ok((
            ClientState::new(
                http,
                base_url,
                max_request_bytes,
                max_response_bytes,
                self.request_limits,
                upload_redactor,
            ),
            correlation_id,
            self.capability,
        ))
    }
}

impl ClientBuilder<ReadOnly> {
    /// Builds a read-only [`Client`].
    ///
    /// Returns an error when the URL, headers, response limit, or HTTP configuration is invalid.
    pub fn build(self) -> Result<Client<ReadOnly>> {
        let (state, correlation_id, capability) = self.build_state(false, None)?;
        Ok(Client::new(state, correlation_id, capability))
    }
}

impl ClientBuilder<CanUpload> {
    /// Allows the upload token to be sent to a non-loopback plaintext HTTP server.
    ///
    /// This is disabled by default because an upload token sent over HTTP can be intercepted.
    /// Loopback HTTP URLs remain available for local development and tests.
    pub fn danger_allow_insecure_uploads(mut self, allow: bool) -> Self {
        self.danger_allow_insecure_uploads = allow;
        self
    }

    /// Builds a [`CanUpload`] client.
    ///
    /// Returns an error when the URL, headers, response limit, HTTP configuration, or upload
    /// transport is invalid.
    pub fn build(self) -> Result<Client<CanUpload>> {
        let upload_redactor = self.capability.clone();
        let (state, correlation_id, capability) = self.build_state(true, Some(upload_redactor))?;
        Ok(Client::new(state, correlation_id, capability))
    }
}
