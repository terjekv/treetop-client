//! Authorization request types.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use super::action::Action;
use super::principal::Principal;
use super::resource::AttrValue;
use super::resource::Resource;
use super::status::RequestLimits;
use super::validation::{RequestId, ValidationError, validate_attribute_name};

/// A single authorization request: who (principal) wants to do what (action) on which resource.
///
/// # Wire format
/// ```json
/// {
///   "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
///   "action": { "id": "view", "namespace": [] },
///   "resource": { "kind": "Document", "id": "doc-42" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    /// The principal (actor) making the request.
    principal: Principal,
    /// The action being performed.
    action: Action,
    /// The resource being acted upon.
    resource: Resource,
}

impl Request {
    /// Creates a new authorization request.
    ///
    /// The `principal` parameter accepts anything that implements `Into<Principal>`,
    /// so you can pass a [`User`](super::principal::User) or [`Group`](super::principal::Group) directly.
    pub fn new(principal: impl Into<Principal>, action: Action, resource: Resource) -> Self {
        Self {
            principal: principal.into(),
            action,
            resource,
        }
    }

    /// Returns the principal making the request.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the action being performed.
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the resource being acted upon.
    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Validates all Cedar values in this request.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.principal.validate()?;
        self.action.validate()?;
        self.resource.validate()
    }
}

/// A single authorization request wrapped with an optional client-provided correlation ID
/// and optional request-scoped context values.
///
/// The `id` field is returned in the response, allowing callers to correlate
/// requests with results in batch operations. The `context` field provides
/// additional key-value pairs available to Cedar policy conditions. The inner
/// [`Request`] fields are flattened into the same JSON object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "AuthRequestWire")]
pub struct AuthRequest {
    /// Optional client-provided identifier for correlating this request with its result.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<RequestId>,
    /// Optional request-scoped context values available to Cedar policy conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<HashMap<String, AttrValue>>,
    /// The authorization request (flattened into the same JSON object).
    #[serde(flatten)]
    request: Request,
}

impl AuthRequest {
    /// Creates an authorization request without a correlation ID or context.
    pub fn new(request: Request) -> Self {
        Self {
            id: None,
            context: None,
            request,
        }
    }

    /// Sets a validated client-provided correlation ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Result<Self, ValidationError> {
        let id = RequestId::new(id);
        id.validate()?;
        self.id = Some(id);
        Ok(self)
    }

    /// Sets validated request-scoped context values available to Cedar policy conditions.
    pub fn with_context(
        mut self,
        context: HashMap<String, AttrValue>,
    ) -> Result<Self, ValidationError> {
        for key in context.keys() {
            validate_attribute_name(key, "auth_request.context")?;
        }
        if !context.is_empty() {
            self.context = Some(context);
        }
        Ok(self)
    }

    /// Returns the optional client-provided correlation ID.
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(RequestId::as_str)
    }

    /// Returns the request-scoped context, when present.
    pub fn context(&self) -> Option<&HashMap<String, AttrValue>> {
        self.context.as_ref()
    }

    /// Returns the underlying authorization request.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Validates this request without applying server-specific context size limits.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(id) = &self.id {
            id.validate()?;
        }
        if let Some(context) = &self.context {
            for key in context.keys() {
                validate_attribute_name(key, "auth_request.context")?;
            }
        }
        self.request.validate()
    }

    /// Validates request context against limits reported by the target server.
    pub fn validate_context(&self, limits: RequestLimits) -> Result<(), ValidationError> {
        let Some(context) = &self.context else {
            return Ok(());
        };

        if context.len() > limits.max_context_keys {
            return Err(ValidationError::ContextTooManyKeys {
                actual: context.len(),
                limit: limits.max_context_keys,
            });
        }

        let depth = context.values().map(context_value_depth).max().unwrap_or(0);
        if depth > limits.max_context_depth {
            return Err(ValidationError::ContextTooDeep {
                actual: depth,
                limit: limits.max_context_depth,
            });
        }

        let mut counter = ByteCounter::new(limits.max_context_bytes);
        if let Err(error) = serde_json::to_writer(&mut counter, context) {
            if counter.exceeded {
                return Err(ValidationError::ContextTooLarge {
                    actual: counter.bytes,
                    limit: limits.max_context_bytes,
                });
            }
            return Err(ValidationError::ContextSerialization {
                message: error.to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct AuthRequestWire {
    #[serde(default)]
    id: Option<RequestId>,
    #[serde(default)]
    context: Option<HashMap<String, AttrValue>>,
    #[serde(flatten)]
    request: Request,
}

impl TryFrom<AuthRequestWire> for AuthRequest {
    type Error = ValidationError;

    fn try_from(wire: AuthRequestWire) -> Result<Self, Self::Error> {
        let request = Self {
            id: wire.id,
            context: wire.context.filter(|context| !context.is_empty()),
            request: wire.request,
        };
        request.validate()?;
        Ok(request)
    }
}

impl From<Request> for AuthRequest {
    fn from(request: Request) -> Self {
        Self::new(request)
    }
}

/// A batch of authorization requests to evaluate against the server's loaded policies.
///
/// Use the builder methods to construct the batch, then pass it to
/// [`Client::authorize`](crate::Client::authorize) or
/// [`Client::authorize_detailed`](crate::Client::authorize_detailed).
///
/// # Example
/// ```
/// use treetop_client::{AuthorizeRequest, Request, User, Action, Resource};
///
/// let batch = AuthorizeRequest::new()
///     .add_request(Request::new(User::new("alice").unwrap(), Action::new("view").unwrap(), Resource::new("Doc", "1").unwrap()))
///     .add_request_with_id("check-2", Request::new(User::new("bob").unwrap(), Action::new("edit").unwrap(), Resource::new("Doc", "1").unwrap()))
///     .unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(try_from = "AuthorizeRequestWire")]
pub struct AuthorizeRequest {
    /// The list of authorization requests in this batch.
    requests: Vec<AuthRequest>,
}

impl AuthorizeRequest {
    /// Creates an empty batch (use builder methods to add requests).
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
        }
    }

    /// Creates a batch containing a single request with no correlation ID.
    pub fn single(request: Request) -> Self {
        Self {
            requests: vec![AuthRequest::new(request)],
        }
    }

    /// Creates a batch from an iterator of requests (none will have correlation IDs).
    pub fn from_requests(requests: impl IntoIterator<Item = Request>) -> Self {
        Self {
            requests: requests.into_iter().map(AuthRequest::from).collect(),
        }
    }

    /// Creates a batch from pre-built requests, preserving their IDs and context values.
    pub fn from_auth_requests(
        requests: impl IntoIterator<Item = AuthRequest>,
    ) -> Result<Self, ValidationError> {
        let request = Self {
            requests: requests.into_iter().collect(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Adds a request without a correlation ID to this batch (builder pattern).
    pub fn add_request(mut self, request: Request) -> Self {
        self.requests.push(AuthRequest::new(request));
        self
    }

    /// Adds a request with a client-provided correlation ID to this batch (builder pattern).
    pub fn add_request_with_id(
        self,
        id: impl Into<String>,
        request: Request,
    ) -> Result<Self, ValidationError> {
        self.add_auth_request(AuthRequest::new(request).with_id(id)?)
    }

    /// Adds a pre-built authorization request after checking batch-wide invariants.
    pub fn add_auth_request(mut self, request: AuthRequest) -> Result<Self, ValidationError> {
        if let Some(id) = request.id() {
            if self
                .requests
                .iter()
                .any(|existing| existing.id() == Some(id))
            {
                return Err(ValidationError::DuplicateRequestId {
                    value: id.to_string(),
                });
            }
        }
        self.requests.push(request);
        Ok(self)
    }

    /// Returns all requests in this batch.
    pub fn requests(&self) -> &[AuthRequest] {
        &self.requests
    }

    /// Returns the number of requests in this batch.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns `true` when the batch contains no requests.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Validates every request in the batch.
    ///
    /// Empty batches are valid and produce an empty response on compatible servers.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut request_ids = HashSet::new();
        for request in &self.requests {
            request.validate()?;
            if let Some(id) = request.id() {
                if !request_ids.insert(id) {
                    return Err(ValidationError::DuplicateRequestId {
                        value: id.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates every request context against limits reported by the target server.
    pub fn validate_context(&self, limits: RequestLimits) -> Result<(), ValidationError> {
        for request in &self.requests {
            request.validate_context(limits)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct AuthorizeRequestWire {
    requests: Vec<AuthRequest>,
}

impl TryFrom<AuthorizeRequestWire> for AuthorizeRequest {
    type Error = ValidationError;

    fn try_from(wire: AuthorizeRequestWire) -> Result<Self, Self::Error> {
        Self::from_auth_requests(wire.requests)
    }
}

fn context_value_depth(value: &AttrValue) -> usize {
    let mut maximum = 0;
    let mut pending = vec![(value, 1usize)];

    while let Some((value, depth)) = pending.pop() {
        maximum = maximum.max(depth);
        if let AttrValue::Set(values) = value {
            pending.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
        }
    }

    maximum
}

struct ByteCounter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl ByteCounter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: 0,
            limit,
            exceeded: false,
        }
    }
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        if self.bytes > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized context exceeds configured limit",
            ));
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, AttrValue, Resource, User};

    fn sample_request() -> Request {
        Request::new(
            User::new("alice").unwrap(),
            Action::new("create").unwrap(),
            Resource::new("Host", "web-01").unwrap(),
        )
    }

    #[test]
    fn request_serialization_matches_wire_format() {
        let request = sample_request();
        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json["principal"]["User"]["id"], "alice");
        assert_eq!(json["action"]["id"], "create");
        assert_eq!(json["resource"]["kind"], "Host");
        assert_eq!(json["resource"]["id"], "web-01");
    }

    #[test]
    fn auth_request_flattens_request() {
        let auth = AuthRequest::new(sample_request()).with_id("req-1").unwrap();
        let json = serde_json::to_value(&auth).unwrap();

        assert_eq!(json["id"], "req-1");
        assert_eq!(json["principal"]["User"]["id"], "alice");
        assert_eq!(json["action"]["id"], "create");
    }

    #[test]
    fn auth_request_with_context_serializes_context() {
        let mut context = HashMap::new();
        context.insert("env".to_string(), AttrValue::String("prod".to_string()));

        let auth = AuthRequest::new(sample_request())
            .with_context(context)
            .unwrap();
        let json = serde_json::to_value(&auth).unwrap();

        assert_eq!(json["context"]["env"]["type"], "String");
        assert_eq!(json["context"]["env"]["value"], "prod");
    }

    #[test]
    fn auth_request_empty_context_is_omitted() {
        let auth = AuthRequest::new(sample_request())
            .with_context(HashMap::new())
            .unwrap();
        let json = serde_json::to_value(&auth).unwrap();

        assert!(json.get("context").is_none());
    }

    #[test]
    fn authorize_request_builder() {
        let req = AuthorizeRequest::new()
            .add_request(sample_request())
            .add_request_with_id("req-2", sample_request())
            .unwrap();

        assert_eq!(req.requests().len(), 2);
        assert!(req.requests()[0].id().is_none());
        assert_eq!(req.requests()[1].id(), Some("req-2"));
    }

    #[test]
    fn authorize_request_single() {
        let req = AuthorizeRequest::single(sample_request());
        assert_eq!(req.requests().len(), 1);
    }

    #[test]
    fn authorize_request_rejects_duplicate_ids() {
        let request = AuthorizeRequest::new()
            .add_request_with_id("duplicate", sample_request())
            .unwrap()
            .add_request_with_id("duplicate", sample_request());

        assert!(matches!(
            request,
            Err(ValidationError::DuplicateRequestId { value }) if value == "duplicate"
        ));
    }

    #[test]
    fn request_roundtrip() {
        let request = sample_request();
        let json = serde_json::to_value(&request).unwrap();
        let deserialized: Request = serde_json::from_value(json).unwrap();
        assert_eq!(request, deserialized);
    }
}
