//! Error types for the Treetop client.

use reqwest::StatusCode;
use thiserror::Error;

use crate::types::ValidationError;

/// Errors that can occur when using the Treetop client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TreetopError {
    /// A network or connection-level error from the HTTP transport.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The server returned a non-success HTTP status with an error message.
    ///
    /// The `status` field contains the HTTP status code (e.g. 400, 403, 500),
    /// and `message` contains the server's error description.
    #[error("API error (HTTP {status}): {message}")]
    Api { status: StatusCode, message: String },

    /// Failed to deserialize the response body from the server.
    #[error("Response deserialization error: {0}")]
    Deserialization(#[from] serde_json::Error),

    /// A request value violates a local Treetop or Cedar invariant.
    #[error("Request validation error: {0}")]
    Validation(#[from] ValidationError),

    /// The provided URL could not be parsed.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// A client configuration error, such as a missing upload token.
    #[error("Client configuration error: {0}")]
    Configuration(String),

    /// A successful response body exceeded the configured safety limit.
    #[error("Response body exceeds the configured limit of {limit} bytes")]
    ResponseTooLarge { limit: usize },

    /// The server returned a structurally inconsistent successful response.
    #[error("Invalid API response: {0}")]
    InvalidResponse(String),

    /// A request in an authorization batch failed evaluation.
    #[error("Authorization evaluation failed: {0}")]
    Evaluation(String),
}

/// A `Result` type alias using [`TreetopError`].
pub type Result<T> = std::result::Result<T, TreetopError>;
