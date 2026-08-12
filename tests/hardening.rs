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
        User::new("alice").unwrap(),
        Action::new("view").unwrap(),
        Resource::new("Document", "doc-1").unwrap(),
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
    assert!(matches!(
        Action::new("view")
            .unwrap()
            .with_namespace(vec!["bad-name".to_string()]),
        Err(ValidationError::InvalidCedarIdentifier { .. })
    ));

    assert!(matches!(
        Resource::new("__cedar::Document", "doc-1"),
        Err(ValidationError::ReservedCedarIdentifier { .. })
    ));
}

#[test]
fn unsafe_entity_ids_are_rejected() {
    assert!(matches!(
        User::new("ali\"ce"),
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

    let resource = serde_json::from_value::<Resource>(json!({
        "kind": "Document",
        "id": "doc-1",
        "attrs": {"bad\nkey": {"type": "Bool", "value": true}}
    }));
    assert!(resource.is_err());

    let auth_request = serde_json::from_value::<AuthRequest>(json!({
        "context": {"bad\nkey": {"type": "Bool", "value": true}},
        "principal": {"User": {"id": "alice", "namespace": [], "groups": []}},
        "action": {"id": "view", "namespace": []},
        "resource": {"kind": "Document", "id": "doc-1"}
    }));
    assert!(auth_request.is_err());
}

#[test]
fn collection_invariants_are_rejected_during_construction() {
    assert!(
        Resource::new("Document", "doc-1")
            .unwrap()
            .with_attr("bad\nkey", AttrValue::Bool(true))
            .is_err()
    );

    let mut context = HashMap::new();
    context.insert("bad\nkey".to_string(), AttrValue::Bool(true));
    assert!(
        AuthRequest::new(sample_request())
            .with_context(context)
            .is_err()
    );

    let first = AuthRequest::new(sample_request()).with_id("same").unwrap();
    let second = AuthRequest::new(sample_request()).with_id("same").unwrap();
    assert!(AuthorizeRequest::from_auth_requests([first.clone(), second.clone()]).is_err());

    let wire = json!({"requests": [first, second]});
    assert!(serde_json::from_value::<AuthorizeRequest>(wire).is_err());
}

#[test]
fn context_validation_uses_reported_server_limits() {
    let mut context = HashMap::new();
    context.insert(
        "environment".to_string(),
        AttrValue::String("prod".to_string()),
    );
    context.insert("mfa".to_string(), AttrValue::Bool(true));
    let request = AuthRequest::new(sample_request())
        .with_context(context)
        .unwrap();

    let error = request
        .validate_context(RequestLimits {
            max_batch_size: None,
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
    let request = AuthRequest::new(sample_request())
        .with_context(context)
        .unwrap();

    let size_error = request
        .validate_context(RequestLimits {
            max_batch_size: None,
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
            max_batch_size: None,
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
    assert!(UploadToken::new("bad\nheader").is_err());
    assert!(
        Client::builder("http://localhost")
            .max_response_bytes(0)
            .build()
            .is_err()
    );
    assert!(
        Client::builder("http://localhost")
            .max_request_bytes(0)
            .build()
            .is_err()
    );
}

#[test]
fn upload_tokens_require_secure_non_loopback_transport() {
    assert!(
        Client::builder("http://example.com")
            .upload_token(UploadToken::new("secret").unwrap())
            .build()
            .is_err()
    );
    assert!(
        Client::builder("http://example.com")
            .upload_token(UploadToken::new("secret").unwrap())
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
async fn health_response_bodies_are_drained_and_bounded() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .max_response_bytes(4)
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
        .mount(&server)
        .await;

    assert!(matches!(
        client.health().await,
        Err(TreetopError::ResponseTooLarge { limit: 4 })
    ));
}

#[tokio::test]
async fn successful_text_responses_require_utf8() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff]))
        .mount(&server)
        .await;

    assert!(matches!(
        client.metrics().await,
        Err(TreetopError::InvalidTextResponse)
    ));
}

#[tokio::test]
async fn operational_probe_responses_are_bounded_and_require_utf8() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .max_response_bytes(4)
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/readyz"))
        .respond_with(ResponseTemplate::new(503).set_body_string("12345"))
        .mount(&server)
        .await;

    assert!(matches!(
        client.readyz().await,
        Err(TreetopError::ResponseTooLarge { limit: 4 })
    ));

    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff]))
        .mount(&server)
        .await;

    assert!(matches!(
        client.livez().await,
        Err(TreetopError::InvalidTextResponse)
    ));
}

#[tokio::test]
async fn openapi_responses_are_bounded() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .max_response_bytes(4)
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/openapi.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
        .mount(&server)
        .await;

    assert!(matches!(
        client.openapi().await,
        Err(TreetopError::ResponseTooLarge { limit: 4 })
    ));
}

#[tokio::test]
async fn operational_endpoint_errors_redact_upload_tokens() {
    let server = MockServer::start().await;
    let token = "do-not-leak-this-token";
    let client = Client::builder(server.uri())
        .upload_token(UploadToken::new(token).unwrap())
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": format!("reflected credential: {token}")
        })))
        .mount(&server)
        .await;

    let error = client.livez().await.unwrap_err();
    assert!(!error.to_string().contains(token));
    assert!(error.to_string().contains("[REDACTED]"));
}

#[tokio::test]
async fn authorization_requests_are_bounded_before_transport() {
    let client = Client::builder("http://localhost")
        .max_request_bytes(16)
        .build()
        .unwrap();

    assert!(matches!(
        client
            .authorize(&AuthorizeRequest::single(sample_request()))
            .await,
        Err(TreetopError::RequestTooLarge { limit: 16 })
    ));
}

#[tokio::test]
async fn upload_bodies_are_bounded_before_transport() {
    let client = Client::builder("http://localhost")
        .upload_token(UploadToken::new("secret").unwrap())
        .max_request_bytes(4)
        .build()
        .unwrap();

    assert!(matches!(
        client.upload_policies_raw("12345").await,
        Err(TreetopError::RequestTooLarge { limit: 4 })
    ));
    assert!(matches!(
        client.upload_schema_json("{}").await,
        Err(TreetopError::RequestTooLarge { limit: 4 })
    ));
}

#[tokio::test]
async fn request_context_limits_are_enforced_before_transport() {
    let client = Client::builder("http://localhost")
        .request_limits(RequestLimits {
            max_batch_size: None,
            max_context_bytes: usize::MAX,
            max_context_depth: usize::MAX,
            max_context_keys: 0,
        })
        .build()
        .unwrap();
    let mut context = HashMap::new();
    context.insert(
        "environment".to_string(),
        AttrValue::String("prod".to_string()),
    );
    let auth_request = AuthRequest::new(sample_request())
        .with_context(context)
        .unwrap();
    let request = AuthorizeRequest::from_auth_requests([auth_request]).unwrap();

    assert!(matches!(
        client.authorize(&request).await,
        Err(TreetopError::Validation(
            ValidationError::ContextTooManyKeys { .. }
        ))
    ));
}

#[tokio::test]
async fn user_policy_filters_are_validated_before_transport() {
    let client = Client::builder("http://localhost").build().unwrap();

    for user in ["", ".", ".."] {
        assert!(matches!(
            client.get_user_policies(user, &[], &[]).await,
            Err(TreetopError::Validation(
                ValidationError::InvalidPathSegment { .. }
            ))
        ));
    }
    assert!(matches!(
        client
            .get_user_policies("alice", &["bad\"group".to_string()], &[])
            .await,
        Err(TreetopError::Validation(
            ValidationError::InvalidEntityId { .. }
        ))
    ));
    assert!(matches!(
        client
            .get_user_policies("alice", &[], &["bad-name".to_string()])
            .await,
        Err(TreetopError::Validation(
            ValidationError::InvalidCedarIdentifier { .. }
        ))
    ));
}

#[tokio::test]
async fn api_errors_redact_reflected_upload_tokens() {
    let server = MockServer::start().await;
    let token = "do-not-leak-this-token";
    let client = Client::builder(server.uri())
        .upload_token(UploadToken::new(token).unwrap())
        .build()
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/policies"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": format!("invalid upload token: {token}")
        })))
        .mount(&server)
        .await;

    let error = client.upload_policies_raw("permit();").await.unwrap_err();
    assert!(!error.to_string().contains(token));
    assert!(error.to_string().contains("[REDACTED]"));
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

#[tokio::test]
async fn authorization_response_ids_must_match_requests() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    let mut response = brief_response();
    response["results"][0]["id"] = json!("different");
    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;
    let batch = AuthorizeRequest::new()
        .add_request_with_id("expected", sample_request())
        .unwrap();

    assert!(matches!(
        client.authorize(&batch).await,
        Err(TreetopError::InvalidResponse(message)) if message.contains("correlation ID")
    ));
}
