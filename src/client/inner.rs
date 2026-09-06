//! The Treetop HTTP client.

use std::io::{self, Write};
use std::sync::Arc;

use reqwest::header::{CONTENT_TYPE, HeaderValue};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Host;

use crate::error::{Result, TreetopError};
use crate::types::{
    AuthorizeBriefResponse, AuthorizeDetailedResponse, AuthorizeRequest, BatchResult,
    DecisionBrief, EntityId, Namespace, PoliciesDownload, PoliciesMetadata, Request, RequestLimits,
    SchemaDownload, StatusResponse, UserPolicies, ValidationError, VersionInfo,
};

use super::authorization::Authorization;
use super::builder::ClientBuilder;
use super::capability::{CanUpload, ReadOnly};
use super::user_policies::UserPoliciesRequest;

const CORRELATION_HEADER: &str = "x-correlation-id";
const ERROR_BODY_LIMIT: usize = 64 * 1024;
const INITIAL_BODY_CAPACITY: usize = 64 * 1024;

/// A normalized, credential-free HTTP(S) service base URL.
#[derive(Debug, Clone)]
pub(super) struct BaseUrl(Url);

impl BaseUrl {
    pub(super) fn parse(value: &str) -> Result<Self> {
        let mut url = Url::parse(value.trim())?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(TreetopError::Configuration(
                "base URL scheme must be http or https".to_string(),
            ));
        }
        if !url.has_host() || url.cannot_be_a_base() {
            return Err(TreetopError::Configuration(
                "base URL must include a host".to_string(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TreetopError::Configuration(
                "base URL must not contain credentials".to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(TreetopError::Configuration(
                "base URL must not contain a query string or fragment".to_string(),
            ));
        }

        let normalized_path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&normalized_path);
        Ok(Self(url))
    }

    pub(super) fn validate_upload_transport(&self, allow_insecure: bool) -> Result<()> {
        if self.0.scheme() == "https" || allow_insecure || self.is_loopback() {
            Ok(())
        } else {
            Err(TreetopError::Configuration(
                "refusing to send an upload token over plaintext HTTP; use HTTPS or explicitly enable danger_allow_insecure_uploads".to_string(),
            ))
        }
    }

    fn is_loopback(&self) -> bool {
        match self.0.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        }
    }

    fn api_base(&self) -> Url {
        self.0
            .join("api/v1/")
            .expect("a validated HTTP base URL must support relative joins")
    }

    fn root_endpoint(&self, path: &str) -> Url {
        self.0
            .join(path)
            .expect("static root endpoint paths must be valid relative URLs")
    }

    fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }
}

/// A pre-validated HTTP correlation header value.
#[derive(Debug, Clone)]
pub(super) struct CorrelationId(HeaderValue);

impl CorrelationId {
    pub(super) fn parse(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(TreetopError::Configuration(
                "correlation ID must not be empty".to_string(),
            ));
        }
        let value = HeaderValue::try_from(value).map_err(|_| {
            TreetopError::Configuration(
                "correlation ID contains invalid HTTP header characters".to_string(),
            )
        })?;
        Ok(Self(value))
    }

    fn as_header(&self) -> &HeaderValue {
        &self.0
    }
}

/// A non-zero upper bound for successful response bodies.
#[derive(Debug, Clone, Copy)]
pub(super) struct ResponseSizeLimit(usize);

impl ResponseSizeLimit {
    pub(super) fn new(value: usize) -> Result<Self> {
        if value == 0 {
            Err(TreetopError::Configuration(
                "maximum response size must be greater than zero".to_string(),
            ))
        } else {
            Ok(Self(value))
        }
    }

    fn get(self) -> usize {
        self.0
    }
}

/// A non-zero upper bound for serialized request bodies.
#[derive(Debug, Clone, Copy)]
pub(super) struct RequestSizeLimit(usize);

impl RequestSizeLimit {
    pub(super) fn new(value: usize) -> Result<Self> {
        if value == 0 {
            Err(TreetopError::Configuration(
                "maximum request size must be greater than zero".to_string(),
            ))
        } else {
            Ok(Self(value))
        }
    }

    fn get(self) -> usize {
        self.0
    }
}

pub(super) struct ClientState {
    http: reqwest::Client,
    base_url: BaseUrl,
    api_base: Url,
    max_request_bytes: RequestSizeLimit,
    max_response_bytes: ResponseSizeLimit,
    request_limits: RequestLimits,
    upload_redactor: Option<CanUpload>,
}

impl ClientState {
    pub(super) fn new(
        http: reqwest::Client,
        base_url: BaseUrl,
        max_request_bytes: RequestSizeLimit,
        max_response_bytes: ResponseSizeLimit,
        request_limits: RequestLimits,
        upload_redactor: Option<CanUpload>,
    ) -> Self {
        let api_base = base_url.api_base();
        Self {
            http,
            base_url,
            api_base,
            max_request_bytes,
            max_response_bytes,
            request_limits,
            upload_redactor,
        }
    }

    fn endpoint(&self, path: &str) -> Url {
        self.api_base
            .join(path.trim_start_matches('/'))
            .expect("static API endpoint paths must be valid relative URLs")
    }
}

/// An async HTTP client for a Treetop policy authorization server.
///
/// Create a client using [`Client::builder`]. The client maintains a connection pool
/// internally via reqwest -- reuse the same `Client` instance across your application
/// rather than creating a new one per request.
///
/// # Connection pool sharing
///
/// Calling [`with_correlation_id`](Client::with_correlation_id) or
/// [`without_correlation_id`](Client::without_correlation_id) returns a new `Client`
/// that shares the same underlying connection pool (reqwest's `Client` is `Arc`-wrapped).
///
/// # Example
///
/// ```rust,no_run
/// use treetop_client::{Action, Client, Request, Resource, User};
///
/// # async fn example() -> treetop_client::Result<()> {
/// let client = Client::builder("https://treetop.example.com").build()?;
/// let allowed = client
///     .is_allowed(Request::new(User::new("alice").unwrap(), Action::new("view").unwrap(), Resource::new("Doc", "1").unwrap()))
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// # Upload capability
///
/// Upload methods are absent unless a validated upload token transitions the builder to
/// [`CanUpload`]:
///
/// ```compile_fail
/// use treetop_client::Client;
///
/// let client = Client::builder("https://treetop.example.com").build().unwrap();
/// let _request = client.upload_policies_raw("permit(principal, action, resource);");
/// ```
#[derive(Clone)]
pub struct Client<Capability = ReadOnly> {
    state: Arc<ClientState>,
    correlation_id: Option<CorrelationId>,
    capability: Capability,
}

impl Client<ReadOnly> {
    /// Creates a [`ClientBuilder`] for the given Treetop server base URL.
    ///
    /// The URL should include the scheme and host (e.g. `"https://treetop.example.com"`).
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder<ReadOnly> {
        ClientBuilder::new(base_url)
    }
}

impl<Capability> Client<Capability> {
    pub(super) fn new(
        state: ClientState,
        correlation_id: Option<CorrelationId>,
        capability: Capability,
    ) -> Self {
        Self {
            state: Arc::new(state),
            correlation_id,
            capability,
        }
    }

    /// Returns a new `Client` sharing the same connection pool but with the given correlation ID.
    ///
    /// The correlation ID is sent as the `x-correlation-id` header on every request
    /// made through the returned client. The original client is unaffected.
    pub fn with_correlation_id(&self, id: impl Into<String>) -> Result<Client<Capability>>
    where
        Capability: Clone,
    {
        Ok(Client {
            state: Arc::clone(&self.state),
            correlation_id: Some(CorrelationId::parse(id.into())?),
            capability: self.capability.clone(),
        })
    }

    /// Returns a new `Client` sharing the same connection pool but without a correlation ID.
    pub fn without_correlation_id(&self) -> Client<Capability>
    where
        Capability: Clone,
    {
        Client {
            state: Arc::clone(&self.state),
            correlation_id: None,
            capability: self.capability.clone(),
        }
    }

    fn apply_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        self.apply_headers_with_correlation(builder, None)
    }

    fn apply_headers_with_correlation(
        &self,
        builder: RequestBuilder,
        correlation_id: Option<&CorrelationId>,
    ) -> RequestBuilder {
        if let Some(cid) = correlation_id.or(self.correlation_id.as_ref()) {
            builder.header(CORRELATION_HEADER, cid.as_header())
        } else {
            builder
        }
    }

    async fn read_body(&self, mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|content_length| content_length > limit as u64)
        {
            return Err(TreetopError::ResponseTooLarge { limit });
        }

        let capacity = response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(limit)
            .min(INITIAL_BODY_CAPACITY);
        let mut body = Vec::with_capacity(capacity);
        while let Some(chunk) = response.chunk().await.map_err(TreetopError::Transport)? {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(TreetopError::ResponseTooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn api_error(&self, response: reqwest::Response) -> TreetopError {
        let status = response.status();
        let body = match self.read_body(response, ERROR_BODY_LIMIT).await {
            Ok(body) => body,
            Err(TreetopError::ResponseTooLarge { .. }) => {
                return TreetopError::Api {
                    status,
                    message: format!("response error body exceeded {ERROR_BODY_LIMIT} bytes"),
                };
            }
            Err(error) => return error,
        };

        #[derive(serde::Deserialize)]
        struct ErrorEnvelope {
            error: String,
        }

        let message = serde_json::from_slice::<ErrorEnvelope>(&body)
            .map(|envelope| envelope.error)
            .unwrap_or_else(|_| String::from_utf8_lossy(&body).into_owned());
        TreetopError::Api {
            status,
            message: self.redact_upload_token(message),
        }
    }

    async fn handle_response<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            let body = self
                .read_body(resp, self.state.max_response_bytes.get())
                .await?;
            serde_json::from_slice(&body).map_err(TreetopError::Deserialization)
        } else {
            Err(self.api_error(resp).await)
        }
    }

    async fn handle_text_response(&self, resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        if status.is_success() {
            self.read_text_body(resp).await
        } else {
            Err(self.api_error(resp).await)
        }
    }

    async fn read_text_body(&self, resp: reqwest::Response) -> Result<String> {
        let body = self
            .read_body(resp, self.state.max_response_bytes.get())
            .await?;
        String::from_utf8(body).map_err(|_| TreetopError::InvalidTextResponse)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .apply_headers(self.state.http.get(self.state.endpoint(path)))
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    async fn get_text(&self, url: Url) -> Result<String> {
        self.get_text_with_correlation(url, None).await
    }

    async fn get_text_with_correlation(
        &self,
        url: Url,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<String> {
        let resp = self
            .apply_headers_with_correlation(self.state.http.get(url), correlation_id)
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_text_response(resp).await
    }

    async fn post_json_with_correlation<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<T> {
        let body = self.serialize_json_body(body)?;
        let resp = self
            .apply_headers_with_correlation(
                self.state
                    .http
                    .post(self.state.endpoint(path))
                    .header(CONTENT_TYPE, "application/json")
                    .body(body),
                correlation_id,
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    fn serialize_json_body<T: Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        let limit = self.state.max_request_bytes.get();
        let mut writer = BoundedJsonWriter::new(limit);
        match serde_json::to_writer(&mut writer, value) {
            Ok(()) => Ok(writer.body),
            Err(_) if writer.exceeded => Err(TreetopError::RequestTooLarge { limit }),
            Err(error) => Err(TreetopError::Serialization(error)),
        }
    }

    fn validate_raw_body(&self, content: &str) -> Result<()> {
        let limit = self.state.max_request_bytes.get();
        if content.len() > limit {
            Err(TreetopError::RequestTooLarge { limit })
        } else {
            Ok(())
        }
    }

    fn redact_upload_token(&self, message: String) -> String {
        let Some(redactor) = &self.state.upload_redactor else {
            return message;
        };
        redactor.token().redact_from(message)
    }

    // --- Public API ---

    /// Checks process liveness through the canonical `GET /livez` operational probe.
    ///
    /// Returns `Ok(())` after a successful, bounded UTF-8 response. This probe
    /// is independent of server configuration state.
    pub async fn livez(&self) -> Result<()> {
        self.get_text(self.state.base_url.root_endpoint("livez"))
            .await
            .map(drop)
    }

    /// Checks whether the server is ready to accept traffic through `GET /readyz`.
    ///
    /// HTTP 200 maps to `Ok(true)` and HTTP 503 maps to `Ok(false)`. Both expected
    /// responses are drained through the configured response-size and UTF-8 checks;
    /// every other failure is returned as a [`TreetopError`].
    pub async fn readyz(&self) -> Result<bool> {
        let resp = self
            .apply_headers(
                self.state
                    .http
                    .get(self.state.base_url.root_endpoint("readyz")),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;

        match resp.status() {
            StatusCode::OK => {
                self.read_text_body(resp).await?;
                Ok(true)
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                self.read_text_body(resp).await?;
                Ok(false)
            }
            _ => Err(self.api_error(resp).await),
        }
    }

    /// Returns the server-generated OpenAPI document from `GET /openapi.json`.
    pub async fn openapi(&self) -> Result<serde_json::Value> {
        let resp = self
            .apply_headers(
                self.state
                    .http
                    .get(self.state.base_url.root_endpoint("openapi.json")),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    /// Returns server and Cedar engine version information from `GET /api/v1/version`.
    pub async fn version(&self) -> Result<VersionInfo> {
        self.get("/version").await
    }

    /// Returns the server's full status including policy metadata and parallelism
    /// configuration from `GET /api/v1/status`.
    pub async fn status(&self) -> Result<StatusResponse> {
        self.get("/status").await
    }

    /// Starts a fluent authorization call with brief output selected by default.
    pub fn authorization<'a>(
        &'a self,
        request: &'a AuthorizeRequest,
    ) -> Authorization<'a, Capability> {
        Authorization::new(self, request)
    }

    /// Evaluates a batch of authorization requests and returns brief results
    /// (decision + policy IDs, no full policy text).
    ///
    /// Sends `POST /api/v1/authorize?detail=brief`.
    pub async fn authorize(&self, request: &AuthorizeRequest) -> Result<AuthorizeBriefResponse> {
        self.authorization(request).send().await
    }

    pub(super) async fn send_authorization_brief(
        &self,
        request: &AuthorizeRequest,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<AuthorizeBriefResponse> {
        request.validate()?;
        request.validate_context(self.state.request_limits)?;
        let response: AuthorizeBriefResponse = self
            .post_json_with_correlation("authorize?detail=brief", request, correlation_id)
            .await?;
        response.validate_against(request)?;
        Ok(response)
    }

    /// Evaluates a batch of authorization requests and returns detailed results
    /// including the full Cedar DSL and JSON of each matching policy.
    ///
    /// Sends `POST /api/v1/authorize?detail=full`.
    pub async fn authorize_detailed(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<AuthorizeDetailedResponse> {
        self.authorization(request).detailed().send().await
    }

    pub(super) async fn send_authorization_detailed(
        &self,
        request: &AuthorizeRequest,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<AuthorizeDetailedResponse> {
        request.validate()?;
        request.validate_context(self.state.request_limits)?;
        let response: AuthorizeDetailedResponse = self
            .post_json_with_correlation("authorize?detail=full", request, correlation_id)
            .await?;
        response.validate_against(request)?;
        Ok(response)
    }

    /// Convenience method: evaluates a single authorization request and returns
    /// `true` if allowed, `false` if denied.
    ///
    /// This wraps the request into an [`AuthorizeRequest::single`], calls
    /// [`authorize`](Client::authorize), and extracts the boolean decision.
    ///
    /// Returns an error if the server returns an error or if the individual
    /// request evaluation failed.
    pub async fn is_allowed(&self, request: Request) -> Result<bool> {
        let batch = AuthorizeRequest::single(request);
        let resp = self.authorize(&batch).await?;
        let result = resp.results().first().ok_or_else(|| {
            TreetopError::InvalidResponse("empty response from authorize endpoint".to_string())
        })?;
        match &result.result {
            BatchResult::Success { data } => Ok(matches!(data.decision, DecisionBrief::Allow)),
            BatchResult::Failed { message } => Err(TreetopError::Evaluation(message.clone())),
        }
    }

    /// Downloads the currently loaded policies as structured data from `GET /api/v1/policies`.
    pub async fn get_policies(&self) -> Result<PoliciesDownload> {
        self.get("/policies").await
    }

    /// Downloads the currently loaded policies as raw Cedar DSL text
    /// from `GET /api/v1/policies?format=raw`.
    pub async fn get_policies_raw(&self) -> Result<String> {
        self.get_text(self.state.endpoint("policies?format=raw"))
            .await
    }

    /// Downloads the currently loaded schema as structured data from `GET /api/v1/schema`.
    pub async fn get_schema(&self) -> Result<SchemaDownload> {
        self.get("/schema").await
    }

    /// Downloads the currently loaded schema as raw Cedar schema JSON text
    /// from `GET /api/v1/schema?format=raw`.
    pub async fn get_schema_raw(&self) -> Result<String> {
        self.get_text(self.state.endpoint("schema?format=raw"))
            .await
    }
}

impl Client<CanUpload> {
    /// Uploads policies as raw Cedar DSL text via `POST /api/v1/policies`.
    ///
    /// Requires an upload token to be configured on the client
    /// (see [`ClientBuilder::upload_token`]).
    /// Returns the updated policy metadata on success.
    pub async fn upload_policies_raw(&self, content: &str) -> Result<PoliciesMetadata> {
        let token = self.capability.token();
        self.validate_raw_body(content)?;

        let resp = self
            .apply_headers(
                self.state
                    .http
                    .post(self.state.endpoint("policies"))
                    .header(CONTENT_TYPE, "text/plain")
                    .header("X-Upload-Token", token.header_value())
                    .body(content.to_string()),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    /// Uploads policies as a JSON-wrapped Cedar DSL string via `POST /api/v1/policies`.
    ///
    /// The content is sent as `{"policies": "<cedar_dsl>"}` with `Content-Type: application/json`.
    ///
    /// Requires an upload token to be configured on the client
    /// (see [`ClientBuilder::upload_token`]).
    /// Returns the updated policy metadata on success.
    pub async fn upload_policies_json(&self, content: &str) -> Result<PoliciesMetadata> {
        let token = self.capability.token();

        #[derive(Serialize)]
        struct Upload<'a> {
            policies: &'a str,
        }

        let body = self.serialize_json_body(&Upload { policies: content })?;
        let resp = self
            .apply_headers(
                self.state
                    .http
                    .post(self.state.endpoint("policies"))
                    .header("X-Upload-Token", token.header_value())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    /// Uploads a Cedar schema as raw Cedar schema JSON text via `POST /api/v1/schema`.
    ///
    /// Requires an upload token to be configured on the client
    /// (see [`ClientBuilder::upload_token`]).
    /// Returns the updated server metadata on success.
    pub async fn upload_schema_raw(&self, content: &str) -> Result<PoliciesMetadata> {
        let token = self.capability.token();
        self.validate_raw_body(content)?;

        let resp = self
            .apply_headers(
                self.state
                    .http
                    .post(self.state.endpoint("schema"))
                    .header(CONTENT_TYPE, "text/plain")
                    .header("X-Upload-Token", token.header_value())
                    .body(content.to_string()),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    /// Uploads a Cedar schema via `POST /api/v1/schema` using a JSON envelope.
    ///
    /// The content is sent as `{"schema": "<cedar_schema_json_text>"}` with
    /// `Content-Type: application/json`.
    ///
    /// Requires an upload token to be configured on the client
    /// (see [`ClientBuilder::upload_token`]).
    /// Returns the updated server metadata on success.
    pub async fn upload_schema_json(&self, content: &str) -> Result<PoliciesMetadata> {
        let token = self.capability.token();

        #[derive(Serialize)]
        struct Upload<'a> {
            schema: &'a str,
        }

        let body = self.serialize_json_body(&Upload { schema: content })?;
        let resp = self
            .apply_headers(
                self.state
                    .http
                    .post(self.state.endpoint("schema"))
                    .header("X-Upload-Token", token.header_value())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }
}

impl<Capability> Client<Capability> {
    /// Starts a fluent query for policies that apply to a specific user.
    pub fn user_policies(
        &self,
        user: impl Into<String>,
    ) -> Result<UserPoliciesRequest<'_, Capability>> {
        UserPoliciesRequest::new(self, user)
    }

    /// Lists policies that apply to a specific user from `GET /api/v1/policies/{user}`.
    ///
    /// Results can be filtered by group membership and Cedar namespace.
    pub async fn get_user_policies(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
    ) -> Result<UserPolicies> {
        let mut request = self.user_policies(user)?;
        for group in groups {
            request = request.group(group)?;
        }
        for namespace in namespaces {
            request = request.namespace(namespace)?;
        }
        request.send().await
    }

    pub(super) async fn send_user_policies(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
        raw: bool,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<UserPolicies> {
        let url = self.build_user_policies_url(user, groups, namespaces, raw)?;
        let resp = self
            .apply_headers_with_correlation(self.state.http.get(url), correlation_id)
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    /// Lists policies for a user as raw Cedar DSL text
    /// from `GET /api/v1/policies/{user}?format=raw`.
    ///
    /// Results can be filtered by group membership and Cedar namespace.
    pub async fn get_user_policies_raw(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
    ) -> Result<String> {
        let mut request = self.user_policies(user)?;
        for group in groups {
            request = request.group(group)?;
        }
        for namespace in namespaces {
            request = request.namespace(namespace)?;
        }
        request.raw().send().await
    }

    pub(super) async fn send_user_policies_raw(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
        raw: bool,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<String> {
        let url = self.build_user_policies_url(user, groups, namespaces, raw)?;
        self.get_text_with_correlation(url, correlation_id).await
    }

    /// Fetches Prometheus metrics from the server's `GET /metrics` endpoint.
    ///
    /// Returns the raw text in Prometheus exposition format.
    pub async fn metrics(&self) -> Result<String> {
        self.get_text(self.state.base_url.root_endpoint("metrics"))
            .await
    }

    fn build_user_policies_url(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
        raw: bool,
    ) -> Result<Url> {
        let user_id = EntityId::new(user);
        user_id.validate("user policies user")?;
        if user.is_empty() || matches!(user, "." | "..") {
            return Err(ValidationError::InvalidPathSegment {
                field: "user policies user",
                value: user.to_string(),
            }
            .into());
        }
        for group in groups {
            EntityId::new(group).validate("user policies group")?;
        }
        for namespace in namespaces {
            Namespace::new(namespace.split("::").map(str::to_string).collect())
                .validate("user policies namespace")?;
        }

        let encoded_user = percent_encode_path_segment(user_id.as_str());
        let mut url = self
            .state
            .endpoint("policies/")
            .join(&encoded_user)
            .map_err(TreetopError::InvalidUrl)?;

        let mut query = url.query_pairs_mut();
        for ns in namespaces {
            query.append_pair("namespaces[]", ns);
        }
        for group in groups {
            query.append_pair("groups[]", group);
        }
        if raw {
            query.append_pair("format", "raw");
        }
        drop(query);
        Ok(url)
    }
}

fn percent_encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

struct BoundedJsonWriter {
    body: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            body: Vec::with_capacity(limit.min(INITIAL_BODY_CAPACITY)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.body.len()) {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized request exceeds configured limit",
            ));
        }
        self.body.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for Client<ReadOnly> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.state.base_url.as_str())
            .field("upload_token", &Option::<&str>::None)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl std::fmt::Debug for Client<CanUpload> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.state.base_url.as_str())
            .field("upload_token", &Some("[SET]"))
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}
