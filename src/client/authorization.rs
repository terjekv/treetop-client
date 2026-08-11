//! Fluent authorization endpoint calls.

use crate::Result;
use crate::types::{AuthorizeBriefResponse, AuthorizeDetailedResponse, AuthorizeRequest};

use super::inner::{Client, CorrelationId};

/// A fluent authorization call that returns brief results by default.
///
/// Use [`detailed`](Self::detailed) to transition to [`DetailedAuthorization`] when matching
/// policy bodies are required.
pub struct Authorization<'a, Capability> {
    client: &'a Client<Capability>,
    request: &'a AuthorizeRequest,
    correlation_id: Option<CorrelationId>,
}

impl<'a, Capability> Authorization<'a, Capability> {
    pub(super) fn new(client: &'a Client<Capability>, request: &'a AuthorizeRequest) -> Self {
        Self {
            client,
            request,
            correlation_id: None,
        }
    }

    /// Overrides the client's correlation ID for this call.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Result<Self> {
        self.correlation_id = Some(CorrelationId::parse(id.into())?);
        Ok(self)
    }

    /// Transitions this call to detailed authorization output.
    pub fn detailed(self) -> DetailedAuthorization<'a, Capability> {
        DetailedAuthorization {
            client: self.client,
            request: self.request,
            correlation_id: self.correlation_id,
        }
    }

    /// Sends the authorization request and returns brief results.
    pub async fn send(self) -> Result<AuthorizeBriefResponse> {
        self.client
            .send_authorization_brief(self.request, self.correlation_id.as_ref())
            .await
    }
}

/// A fluent authorization call that returns full matching-policy details.
pub struct DetailedAuthorization<'a, Capability> {
    client: &'a Client<Capability>,
    request: &'a AuthorizeRequest,
    correlation_id: Option<CorrelationId>,
}

impl<Capability> DetailedAuthorization<'_, Capability> {
    /// Overrides the client's correlation ID for this call.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Result<Self> {
        self.correlation_id = Some(CorrelationId::parse(id.into())?);
        Ok(self)
    }

    /// Sends the authorization request and returns detailed results.
    pub async fn send(self) -> Result<AuthorizeDetailedResponse> {
        self.client
            .send_authorization_detailed(self.request, self.correlation_id.as_ref())
            .await
    }
}
