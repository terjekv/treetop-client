//! Authorization request types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::action::Action;
use super::principal::Principal;
use super::resource::AttrValue;
use super::resource::Resource;

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
    pub principal: Principal,
    /// The action being performed.
    pub action: Action,
    /// The resource being acted upon.
    pub resource: Resource,
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
}

/// A single authorization request wrapped with an optional client-provided correlation ID
/// and optional request-scoped context values.
///
/// The `id` field is returned in the response, allowing callers to correlate
/// requests with results in batch operations. The `context` field provides
/// additional key-value pairs available to Cedar policy conditions. The inner
/// [`Request`] fields are flattened into the same JSON object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthRequest {
    /// Optional client-provided identifier for correlating this request with its result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional request-scoped context values available to Cedar policy conditions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, AttrValue>>,
    /// The authorization request (flattened into the same JSON object).
    #[serde(flatten)]
    pub request: Request,
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

    /// Creates an authorization request with a client-provided correlation ID.
    pub fn with_id(id: impl Into<String>, request: Request) -> Self {
        Self {
            id: Some(id.into()),
            context: None,
            request,
        }
    }

    /// Sets request-scoped context values available to Cedar policy conditions.
    pub fn with_context(mut self, context: HashMap<String, AttrValue>) -> Self {
        if !context.is_empty() {
            self.context = Some(context);
        }
        self
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
///     .add_request(Request::new(User::new("alice"), Action::new("view"), Resource::new("Doc", "1")))
///     .add_request_with_id("check-2", Request::new(User::new("bob"), Action::new("edit"), Resource::new("Doc", "1")));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthorizeRequest {
    /// The list of authorization requests in this batch.
    pub requests: Vec<AuthRequest>,
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

    /// Adds a request without a correlation ID to this batch (builder pattern).
    pub fn add_request(mut self, request: Request) -> Self {
        self.requests.push(AuthRequest::new(request));
        self
    }

    /// Adds a request with a client-provided correlation ID to this batch (builder pattern).
    pub fn add_request_with_id(mut self, id: impl Into<String>, request: Request) -> Self {
        self.requests.push(AuthRequest::with_id(id, request));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, AttrValue, Resource, User};

    fn sample_request() -> Request {
        Request::new(
            User::new("alice"),
            Action::new("create"),
            Resource::new("Host", "web-01"),
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
        let auth = AuthRequest::with_id("req-1", sample_request());
        let json = serde_json::to_value(&auth).unwrap();

        assert_eq!(json["id"], "req-1");
        assert_eq!(json["principal"]["User"]["id"], "alice");
        assert_eq!(json["action"]["id"], "create");
    }

    #[test]
    fn auth_request_with_context_serializes_context() {
        let mut context = HashMap::new();
        context.insert("env".to_string(), AttrValue::String("prod".to_string()));

        let auth = AuthRequest::new(sample_request()).with_context(context);
        let json = serde_json::to_value(&auth).unwrap();

        assert_eq!(json["context"]["env"]["type"], "String");
        assert_eq!(json["context"]["env"]["value"], "prod");
    }

    #[test]
    fn auth_request_empty_context_is_omitted() {
        let auth = AuthRequest::new(sample_request()).with_context(HashMap::new());
        let json = serde_json::to_value(&auth).unwrap();

        assert!(json.get("context").is_none());
    }

    #[test]
    fn authorize_request_builder() {
        let req = AuthorizeRequest::new()
            .add_request(sample_request())
            .add_request_with_id("req-2", sample_request());

        assert_eq!(req.requests.len(), 2);
        assert!(req.requests[0].id.is_none());
        assert_eq!(req.requests[1].id.as_deref(), Some("req-2"));
    }

    #[test]
    fn authorize_request_single() {
        let req = AuthorizeRequest::single(sample_request());
        assert_eq!(req.requests.len(), 1);
    }

    #[test]
    fn request_roundtrip() {
        let request = sample_request();
        let json = serde_json::to_value(&request).unwrap();
        let deserialized: Request = serde_json::from_value(json).unwrap();
        assert_eq!(request, deserialized);
    }
}
