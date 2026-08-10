use std::collections::HashMap;

use serde_json::json;
use treetop_client::{
    Action, AttrValue, AuthRequest, AuthorizeRequest, Client, Request, RequestLimits, Resource,
    TreetopError, UploadToken, User, ValidationError,
};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_request() -> Request {
    Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Document", "doc-1"),
    )
}

fn brief_response() -> serde_json::Value {
    json!({
        "results": [{
            "index": 0,
            "status": "success",
            "result": {
                "decision": "Allow",
                "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
                "policy_id": "policy0"
            }
        }],
        "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 1,
        "failed": 0
    })
}

#[test]
fn request_domain_accessors_preserve_private_values() {
    let request = sample_request();
    assert_eq!(request.action().id(), "view");
    assert_eq!(request.resource().kind(), "Document");
    assert_eq!(request.resource().id(), "doc-1");
    assert!(matches!(
        request.principal(),
        treetop_client::Principal::User(_)
    ));
}

#[test]
fn invalid_cedar_names_are_rejected() {
    let action = Action::new("view").with_namespace(vec!["bad-name".to_string()]);
    assert!(matches!(
        action.validate(),
        Err(ValidationError::InvalidCedarIdentifier { .. })
    ));

    let resource = Resource::new("__cedar::Document", "doc-1");
    assert!(matches!(
        resource.validate(),
        Err(ValidationError::ReservedCedarIdentifier { .. })
    ));
}

#[test]
fn unsafe_entity_ids_are_rejected() {
    let request = Request::new(
        User::new("ali\"ce"),
        Action::new("view"),
        Resource::new("Document", "doc-1"),
    );
    assert!(matches!(
        request.validate(),
        Err(ValidationError::InvalidEntityId { .. })
    ));
}

#[test]
fn deserialization_cannot_bypass_newtype_validation() {
    let action = serde_json::from_value::<Action>(json!({
        "id": "view",
        "namespace": ["bad-name"]
    }));
    assert!(action.is_err());

    let ip = serde_json::from_value::<AttrValue>(json!({
        "type": "Ip",
        "value": "999.999.999.999"
    }));
    assert!(ip.is_err());
}

#[test]
fn context_validation_uses_reported_server_limits() {
    let mut context = HashMap::new();
    context.insert(
        "environment".to_string(),
        AttrValue::String("prod".to_string()),
    );
    context.insert("mfa".to_string(), AttrValue::Bool(true));
    let request = AuthRequest::new(sample_request()).with_context(context);

    let error = request
        .validate_context(RequestLimits {
            max_context_bytes: usize::MAX,
            max_context_depth: usize::MAX,
            max_context_keys: 1,
        })
        .unwrap_err();
    assert!(matches!(error, ValidationError::ContextTooManyKeys { .. }));
}

#[test]
fn context_validation_checks_size_and_depth() {
    let mut context = HashMap::new();
    context.insert(
        "nested".to_string(),
        AttrValue::Set(vec![AttrValue::Set(vec![AttrValue::Long(1)])]),
    );
    let request = AuthRequest::new(sample_request()).with_context(context);

    let size_error = request
        .validate_context(RequestLimits {
            max_context_bytes: 1,
            max_context_depth: usize::MAX,
            max_context_keys: usize::MAX,
        })
        .unwrap_err();
    assert!(matches!(
        size_error,
        ValidationError::ContextTooLarge { .. }
    ));

    let depth_error = request
        .validate_context(RequestLimits {
            max_context_bytes: usize::MAX,
            max_context_depth: 2,
            max_context_keys: usize::MAX,
        })
        .unwrap_err();
    assert!(matches!(
        depth_error,
        ValidationError::ContextTooDeep { .. }
    ));
}

#[test]
fn empty_batches_preserve_the_server_contract() {
    AuthorizeRequest::new().validate().unwrap();
}

#[test]
fn builder_rejects_unsafe_or_ambiguous_urls() {
    for url in [
        "ftp://example.com",
        "https://user:password@example.com",
        "https://example.com?target=other",
        "https://example.com#fragment",
    ] {
        assert!(
            Client::builder(url).build().is_err(),
            "URL should fail: {url}"
        );
    }
}

#[test]
fn builder_validates_header_values_and_response_limit() {
    assert!(
        Client::builder("http://localhost")
            .correlation_id("bad\nheader")
            .build()
            .is_err()
    );
    assert!(
        Client::builder("http://localhost")
            .upload_token(UploadToken::new("bad\nheader"))
            .build()
            .is_err()
    );
    assert!(
        Client::builder("http://localhost")
            .max_response_bytes(0)
            .build()
            .is_err()
    );
}

#[test]
fn upload_tokens_require_secure_non_loopback_transport() {
    assert!(
        Client::builder("http://example.com")
            .upload_token(UploadToken::new("secret"))
            .build()
            .is_err()
    );
    assert!(
        Client::builder("http://example.com")
            .upload_token(UploadToken::new("secret"))
            .danger_allow_insecure_uploads(true)
            .build()
            .is_ok()
    );
}

#[test]
fn scoped_correlation_ids_are_validated() {
    let client = Client::builder("http://localhost").build().unwrap();
    assert!(client.with_correlation_id("").is_err());
    assert!(client.with_correlation_id("bad\rvalue").is_err());
    assert!(client.with_correlation_id("request-123").is_ok());
}

#[tokio::test]
async fn base_url_path_prefix_is_preserved() {
    let server = MockServer::start().await;
    let client = Client::builder(format!("{}/service/", server.uri()))
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/service/api/v1/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    client.health().await.unwrap();
}

#[tokio::test]
async fn successful_response_bodies_are_bounded() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .max_response_bytes(4)
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
        .mount(&server)
        .await;

    assert!(matches!(
        client.metrics().await,
        Err(TreetopError::ResponseTooLarge { limit: 4 })
    ));
}

#[tokio::test]
async fn default_client_does_not_follow_redirects() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/target"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    assert!(matches!(
        client.health().await,
        Err(TreetopError::Api { status, .. }) if status.as_u16() == 302
    ));
}

#[tokio::test]
async fn inconsistent_authorization_responses_are_rejected() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    let mut response = brief_response();
    response["successful"] = json!(0);

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(sample_request());
    assert!(matches!(
        client.authorize(&batch).await,
        Err(TreetopError::InvalidResponse(_))
    ));
}
