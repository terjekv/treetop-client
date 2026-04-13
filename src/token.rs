//! Secure upload token handling.

use secrecy::{ExposeSecret, SecretString};

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
    /// Creates a new upload token from a string value.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into().into())
    }

    /// Exposes the raw token value. Crate-internal only.
    pub(crate) fn expose(&self) -> &str {
        self.0.expose_secret()
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
        let token = UploadToken::new("super-secret-value");
        let debug = format!("{:?}", token);
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn expose_returns_original_value() {
        let token = UploadToken::new("my-token");
        assert_eq!(token.expose(), "my-token");
    }
}
