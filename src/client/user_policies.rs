//! Fluent user-policy endpoint calls.

use crate::types::{EntityId, Namespace, UserPolicies, ValidationError};
use crate::{Result, TreetopError};

use super::inner::{Client, CorrelationId};

/// A fluent user-policy query that returns structured policy data by default.
///
/// Add group and namespace filters before calling [`send`](Self::send), or call
/// [`raw`](Self::raw) to transition to a raw Cedar DSL response.
pub struct UserPoliciesRequest<'a, Capability> {
    client: &'a Client<Capability>,
    user: String,
    groups: Vec<String>,
    namespaces: Vec<String>,
    correlation_id: Option<CorrelationId>,
}

impl<'a, Capability> UserPoliciesRequest<'a, Capability> {
    pub(super) fn new(client: &'a Client<Capability>, user: impl Into<String>) -> Result<Self> {
        let user = user.into();
        validate_user(&user)?;
        Ok(Self {
            client,
            user,
            groups: Vec::new(),
            namespaces: Vec::new(),
            correlation_id: None,
        })
    }

    /// Adds a validated group filter.
    pub fn group(mut self, group: impl Into<String>) -> Result<Self> {
        let group = group.into();
        EntityId::new(&group).validate("user policies group")?;
        self.groups.push(group);
        Ok(self)
    }

    /// Adds a validated qualified Cedar namespace filter.
    pub fn namespace(mut self, namespace: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        Namespace::new(namespace.split("::").map(str::to_string).collect())
            .validate("user policies namespace")?;
        self.namespaces.push(namespace);
        Ok(self)
    }

    /// Overrides the client's correlation ID for this call.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Result<Self> {
        self.correlation_id = Some(CorrelationId::parse(id.into())?);
        Ok(self)
    }

    /// Transitions this query to a raw Cedar DSL response.
    pub fn raw(self) -> RawUserPoliciesRequest<'a, Capability> {
        RawUserPoliciesRequest { inner: self }
    }

    /// Sends the query and returns structured policy data.
    pub async fn send(self) -> Result<UserPolicies> {
        self.client
            .send_user_policies(
                &self.user,
                &self.groups,
                &self.namespaces,
                false,
                self.correlation_id.as_ref(),
            )
            .await
    }
}

/// A fluent user-policy query that returns raw Cedar DSL text.
pub struct RawUserPoliciesRequest<'a, Capability> {
    inner: UserPoliciesRequest<'a, Capability>,
}

impl<Capability> RawUserPoliciesRequest<'_, Capability> {
    /// Sends the query and returns raw Cedar DSL text.
    pub async fn send(self) -> Result<String> {
        self.inner
            .client
            .send_user_policies_raw(
                &self.inner.user,
                &self.inner.groups,
                &self.inner.namespaces,
                true,
                self.inner.correlation_id.as_ref(),
            )
            .await
    }
}

fn validate_user(user: &str) -> Result<()> {
    EntityId::new(user).validate("user policies user")?;
    if user.is_empty() || matches!(user, "." | "..") {
        return Err(TreetopError::from(ValidationError::InvalidPathSegment {
            field: "user policies user",
            value: user.to_string(),
        }));
    }
    Ok(())
}
