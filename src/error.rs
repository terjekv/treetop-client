//! Error types for the Treetop client.

use reqwest::StatusCode;
use thiserror::Error;

/// Errors that can occur when using the Treetop client.
#[derive(Debug, Error)]
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

    /// The provided URL could not be parsed.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// A client configuration error, such as a missing upload token.
    #[error("Client configuration error: {0}")]
    Configuration(String),
}

/// A `Result` type alias using [`TreetopError`].
pub type Result<T> = std::result::Result<T, TreetopError>;
