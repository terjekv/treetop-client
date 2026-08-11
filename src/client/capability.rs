//! Client capability states.

use std::sync::Arc;

use crate::UploadToken;

/// Marks a client that can call read and authorization endpoints but cannot upload data.
///
/// This is the default capability produced by [`ClientBuilder::build`](crate::ClientBuilder::build)
/// when no upload token was supplied.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOnly;

/// Marks a client that is authorized to attempt policy and schema uploads.
///
/// Values of this type are created only by adding a validated [`UploadToken`] to a client builder.
#[derive(Clone)]
pub struct CanUpload {
    token: Arc<UploadToken>,
}

impl CanUpload {
    pub(super) fn new(token: UploadToken) -> Self {
        Self {
            token: Arc::new(token),
        }
    }

    pub(super) fn token(&self) -> &UploadToken {
        &self.token
    }
}

impl std::fmt::Debug for CanUpload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanUpload([REDACTED])")
    }
}
