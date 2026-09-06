//! Secure upload token handling.

use secrecy::{ExposeSecret, SecretString};

use crate::types::ValidationError;

/// A secret token used to authenticate policy uploads to a Treetop server.
///
/// The token value is stored using [`SecretString`], which:
/// - Zeroizes the memory on drop
/// - Displays `[REDACTED]` in `Debug` output
///
/// The inner value is only accessible within the crate via an `expose` method.
#[derive(Clone)]
pub struct UploadToken(SecretString);

impl UploadToken {
    /// Creates a validated upload token from a string value.
    ///
    /// Empty values and values that cannot be represented as an HTTP header are rejected.
    pub fn new(token: impl Into<String>) -> Result<Self, ValidationError> {
        let token = Self(token.into().into());
        token.validate()?;
        Ok(token)
    }

    /// Validates that this token is non-empty and safe to place in an HTTP header.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let value = self.expose();
        if value.is_empty() || reqwest::header::HeaderValue::from_str(value).is_err() {
            Err(ValidationError::InvalidUploadToken)
        } else {
            Ok(())
        }
    }

    /// Exposes the raw token value. Crate-internal only.
    pub(crate) fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Produces a sensitive header value after [`validate`](Self::validate) has succeeded.
    pub(crate) fn header_value(&self) -> reqwest::header::HeaderValue {
        let mut header = reqwest::header::HeaderValue::try_from(self.expose())
            .expect("validated upload tokens are valid HTTP header values");
        header.set_sensitive(true);
        header
    }

    /// Redacts every occurrence of this token from a potentially reflected message.
    pub(crate) fn redact_from(&self, message: String) -> String {
        message.replace(self.expose(), "[REDACTED]")
    }
}

impl std::fmt::Debug for UploadToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UploadToken([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_token() {
        let token = UploadToken::new("super-secret-value").unwrap();
        let debug = format!("{:?}", token);
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn expose_returns_original_value() {
        let token = UploadToken::new("my-token").unwrap();
        assert_eq!(token.expose(), "my-token");
    }

    #[test]
    fn try_new_rejects_invalid_header_values() {
        assert!(UploadToken::new("").is_err());
        assert!(UploadToken::new("bad\nheader").is_err());
    }

    #[test]
    fn request_header_is_marked_sensitive() {
        let token = UploadToken::new("my-token").unwrap();
        assert!(token.header_value().is_sensitive());
    }

    #[test]
    fn reflected_token_is_redacted() {
        let token = UploadToken::new("super-secret-value").unwrap();
        let message = token.redact_from("rejected super-secret-value".to_string());

        assert_eq!(message, "rejected [REDACTED]");
    }
}
