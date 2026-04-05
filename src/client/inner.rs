//! The Treetop HTTP client.

use reqwest::RequestBuilder;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::form_urlencoded;

use crate::error::{Result, TreetopError};
use crate::token::UploadToken;
use crate::types::{
    AuthorizeBriefResponse, AuthorizeDetailedResponse, AuthorizeRequest, BatchResult,
    DecisionBrief, PoliciesDownload, PoliciesMetadata, Request, SchemaDownload, StatusResponse,
    UserPolicies, VersionInfo,
};

use super::builder::ClientBuilder;

const CORRELATION_HEADER: &str = "x-correlation-id";

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
///     .is_allowed(Request::new(User::new("alice"), Action::new("view"), Resource::new("Doc", "1")))
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Client {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) api_base: String,
    pub(crate) upload_token: Option<UploadToken>,
    pub(crate) correlation_id: Option<String>,
}

impl Client {
    /// Creates a [`ClientBuilder`] for the given Treetop server base URL.
    ///
    /// The URL should include the scheme and host (e.g. `"https://treetop.example.com"`).
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Returns a new `Client` sharing the same connection pool but with the given correlation ID.
    ///
    /// The correlation ID is sent as the `x-correlation-id` header on every request
    /// made through the returned client. The original client is unaffected.
    pub fn with_correlation_id(&self, id: impl Into<String>) -> Client {
        Client {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            api_base: self.api_base.clone(),
            upload_token: self.upload_token.clone(),
            correlation_id: Some(id.into()),
        }
    }

    /// Returns a new `Client` sharing the same connection pool but without a correlation ID.
    pub fn without_correlation_id(&self) -> Client {
        Client {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
            api_base: self.api_base.clone(),
            upload_token: self.upload_token.clone(),
            correlation_id: None,
        }
    }

    fn apply_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        if let Some(cid) = &self.correlation_id {
            builder.header(CORRELATION_HEADER, cid)
        } else {
            builder
        }
    }

    async fn handle_response<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.bytes().await.map_err(TreetopError::Transport)?;
            serde_json::from_slice(&body).map_err(TreetopError::Deserialization)
        } else {
            let body = resp.text().await.unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["error"].as_str().map(String::from))
                .unwrap_or(body);
            Err(TreetopError::Api { status, message })
        }
    }

    async fn handle_text_response(&self, resp: reqwest::Response) -> Result<String> {
        let status = resp.status();
        if status.is_success() {
            resp.text().await.map_err(TreetopError::Transport)
        } else {
            let body = resp.text().await.unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["error"].as_str().map(String::from))
                .unwrap_or(body);
            Err(TreetopError::Api { status, message })
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self
            .apply_headers(self.http.get(format!("{}{}", self.api_base, path)))
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    async fn get_text(&self, url: &str) -> Result<String> {
        let resp = self
            .apply_headers(self.http.get(url))
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_text_response(resp).await
    }

    async fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .apply_headers(
                self.http
                    .post(format!("{}{}", self.api_base, path))
                    .json(body),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
    }

    // --- Public API ---

    /// Checks server liveness by hitting `GET /api/v1/health`.
    ///
    /// Returns `Ok(())` if the server is reachable and healthy.
    pub async fn health(&self) -> Result<()> {
        let resp = self
            .apply_headers(self.http.get(format!("{}/health", self.api_base)))
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(TreetopError::Api {
                status,
                message: body,
            })
        }
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

    /// Evaluates a batch of authorization requests and returns brief results
    /// (decision + policy IDs, no full policy text).
    ///
    /// Sends `POST /api/v1/authorize?detail=brief`.
    pub async fn authorize(&self, request: &AuthorizeRequest) -> Result<AuthorizeBriefResponse> {
        self.post_json("/authorize?detail=brief", request).await
    }

    /// Evaluates a batch of authorization requests and returns detailed results
    /// including the full Cedar DSL and JSON of each matching policy.
    ///
    /// Sends `POST /api/v1/authorize?detail=full`.
    pub async fn authorize_detailed(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<AuthorizeDetailedResponse> {
        self.post_json("/authorize?detail=full", request).await
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
        let result = resp.results().first().ok_or_else(|| TreetopError::Api {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            message: "empty response from authorize endpoint".to_string(),
        })?;
        match &result.result {
            BatchResult::Success { data } => Ok(matches!(data.decision, DecisionBrief::Allow)),
            BatchResult::Failed { message } => Err(TreetopError::Api {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                message: message.clone(),
            }),
        }
    }

    /// Downloads the currently loaded policies as structured data from `GET /api/v1/policies`.
    pub async fn get_policies(&self) -> Result<PoliciesDownload> {
        self.get("/policies").await
    }

    /// Downloads the currently loaded policies as raw Cedar DSL text
    /// from `GET /api/v1/policies?format=raw`.
    pub async fn get_policies_raw(&self) -> Result<String> {
        self.get_text(&format!("{}/policies?format=raw", self.api_base))
            .await
    }

    /// Downloads the currently loaded schema as structured data from `GET /api/v1/schema`.
    pub async fn get_schema(&self) -> Result<SchemaDownload> {
        self.get("/schema").await
    }

    /// Downloads the currently loaded schema as raw Cedar schema JSON text
    /// from `GET /api/v1/schema?format=raw`.
    pub async fn get_schema_raw(&self) -> Result<String> {
        self.get_text(&format!("{}/schema?format=raw", self.api_base))
            .await
    }

    /// Uploads policies as raw Cedar DSL text via `POST /api/v1/policies`.
    ///
    /// Requires an upload token to be configured on the client
    /// (see [`ClientBuilder::upload_token`]).
    /// Returns the updated policy metadata on success.
    pub async fn upload_policies_raw(&self, content: &str) -> Result<PoliciesMetadata> {
        let token = self
            .upload_token
            .as_ref()
            .ok_or_else(|| TreetopError::Configuration("no upload token configured".to_string()))?;

        let resp = self
            .apply_headers(
                self.http
                    .post(format!("{}/policies", self.api_base))
                    .header("Content-Type", "text/plain")
                    .header("X-Upload-Token", token.expose())
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
        let token = self
            .upload_token
            .as_ref()
            .ok_or_else(|| TreetopError::Configuration("no upload token configured".to_string()))?;

        #[derive(Serialize)]
        struct Upload<'a> {
            policies: &'a str,
        }

        let resp = self
            .apply_headers(
                self.http
                    .post(format!("{}/policies", self.api_base))
                    .header("X-Upload-Token", token.expose())
                    .json(&Upload { policies: content }),
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
        let token = self
            .upload_token
            .as_ref()
            .ok_or_else(|| TreetopError::Configuration("no upload token configured".to_string()))?;

        let resp = self
            .apply_headers(
                self.http
                    .post(format!("{}/schema", self.api_base))
                    .header("Content-Type", "text/plain")
                    .header("X-Upload-Token", token.expose())
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
        let token = self
            .upload_token
            .as_ref()
            .ok_or_else(|| TreetopError::Configuration("no upload token configured".to_string()))?;

        #[derive(Serialize)]
        struct Upload<'a> {
            schema: &'a str,
        }

        let resp = self
            .apply_headers(
                self.http
                    .post(format!("{}/schema", self.api_base))
                    .header("X-Upload-Token", token.expose())
                    .json(&Upload { schema: content }),
            )
            .send()
            .await
            .map_err(TreetopError::Transport)?;
        self.handle_response(resp).await
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
        let url = self.build_user_policies_url(user, groups, namespaces, false);
        let resp = self
            .apply_headers(self.http.get(&url))
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
        let url = self.build_user_policies_url(user, groups, namespaces, true);
        self.get_text(&url).await
    }

    /// Fetches Prometheus metrics from the server's `GET /metrics` endpoint.
    ///
    /// Returns the raw text in Prometheus exposition format.
    pub async fn metrics(&self) -> Result<String> {
        let metrics_url = format!("{}/metrics", self.base_url);
        self.get_text(&metrics_url).await
    }

    fn build_user_policies_url(
        &self,
        user: &str,
        groups: &[String],
        namespaces: &[String],
        raw: bool,
    ) -> String {
        let encoded_user: String = form_urlencoded::byte_serialize(user.as_bytes()).collect();
        let mut url = format!("{}/policies/{}", self.api_base, encoded_user);

        let mut params = Vec::new();
        for ns in namespaces {
            let encoded: String = form_urlencoded::byte_serialize(ns.as_bytes()).collect();
            params.push(format!("namespaces[]={}", encoded));
        }
        for group in groups {
            let encoded: String = form_urlencoded::byte_serialize(group.as_bytes()).collect();
            params.push(format!("groups[]={}", encoded));
        }
        if raw {
            params.push("format=raw".to_string());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        url
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("upload_token", &self.upload_token.as_ref().map(|_| "[SET]"))
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}
