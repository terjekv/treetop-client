use rstest::rstest;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use treetop_client::{
    Action, AttrValue, AuthorizeRequest, BatchResult, Client, DecisionBrief, Group, Request,
    Resource, TreetopError, UploadToken, User,
};

// ==========================================================================
// Fixtures
// ==========================================================================

async fn setup() -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri()).build().unwrap();
    (server, client)
}

async fn setup_with_token(token: &str) -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .upload_token(UploadToken::new(token))
        .build()
        .unwrap();
    (server, client)
}

fn brief_response(decision: &str, policy_id: &str) -> serde_json::Value {
    json!({
        "results": [{
            "index": 0,
            "status": "success",
            "result": {
                "decision": decision,
                "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
                "policy_id": policy_id
            }
        }],
        "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 1,
        "failed": 0
    })
}

fn policies_metadata_json() -> serde_json::Value {
    json!({
        "allow_upload": true,
        "policies": {
            "timestamp": "2026-01-01T00:00:00Z",
            "sha256": "new-hash",
            "size": 30,
            "entries": 1,
            "content": "permit(...);"
        },
        "labels": {
            "timestamp": "2026-01-01T00:00:00Z",
            "sha256": "empty",
            "size": 0,
            "entries": 0,
            "content": ""
        }
    })
}

// ==========================================================================
// Health
// ==========================================================================

#[tokio::test]
async fn health_returns_ok_on_200() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    client.health().await.unwrap();
}

#[tokio::test]
async fn health_returns_error_on_500() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "down"})))
        .mount(&server)
        .await;

    let err = client.health().await.unwrap_err();
    match err {
        TreetopError::Api { status, .. } => assert_eq!(status.as_u16(), 500),
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

// ==========================================================================
// Version
// ==========================================================================

#[tokio::test]
async fn version_deserializes_response() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "0.2.0",
            "core": { "version": "0.4.0", "cedar": "4.2.0" },
            "policies": { "hash": "deadbeef", "loaded_at": "2026-01-01T00:00:00Z" },
            "schema": { "hash": "beadfeed", "loaded_at": "2026-01-01T00:00:01Z" }
        })))
        .mount(&server)
        .await;

    let info = client.version().await.unwrap();
    assert_eq!(info.version, "0.2.0");
    assert_eq!(info.core.cedar, "4.2.0");
    assert_eq!(info.policies.hash, "deadbeef");
    assert_eq!(
        info.schema.as_ref().map(|v| v.hash.as_str()),
        Some("beadfeed")
    );
}

// ==========================================================================
// Status
// ==========================================================================

#[tokio::test]
async fn status_deserializes_response() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policy_configuration": {
                "allow_upload": true,
                "policies": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "abc",
                    "size": 100,
                    "entries": 3,
                    "content": "permit(...);"
                },
                "labels": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "def",
                    "size": 0,
                    "entries": 0,
                    "content": ""
                }
            },
            "parallel_configuration": { "cpu_count": 4 }
            ,
            "request_context": {
                "supported": true,
                "schema_backed": false,
                "fallback_reason": "no_schema"
            }
        })))
        .mount(&server)
        .await;

    let status = client.status().await.unwrap();
    assert!(status.policy_configuration.allow_upload);
    assert_eq!(status.policy_configuration.policies.entries, 3);
    assert!(status.request_context.supported);
    assert!(!status.request_context.schema_backed);
}

// ==========================================================================
// Authorize
// ==========================================================================

#[tokio::test]
async fn authorize_sends_correct_payload() {
    let (server, client) = setup().await;

    let expected_body = json!({
        "requests": [{
            "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
            "action": { "id": "view", "namespace": [] },
            "resource": { "kind": "Doc", "id": "1" }
        }]
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response("Allow", "p1")))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Doc", "1"),
    ));
    let resp = client.authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
}

#[tokio::test]
async fn authorize_with_attributes() {
    let (server, client) = setup().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response("Allow", "p1")))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        User::new("alice"),
        Action::new("create"),
        Resource::new("Host", "web-01")
            .with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()))
            .with_attr("critical", AttrValue::Bool(true)),
    ));
    let resp = client.authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
}

#[tokio::test]
async fn authorize_with_context_sends_context() {
    let (server, client) = setup().await;

    let expected_body = json!({
        "requests": [{
            "id": "ctx-1",
            "context": {
                "env": { "type": "String", "value": "prod" }
            },
            "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
            "action": { "id": "view", "namespace": [] },
            "resource": { "kind": "Doc", "id": "1" }
        }]
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response("Allow", "p1")))
        .mount(&server)
        .await;

    let mut context = std::collections::HashMap::new();
    context.insert("env".to_string(), AttrValue::String("prod".to_string()));
    let batch = AuthorizeRequest {
        requests: vec![
            treetop_client::AuthRequest::with_id(
                "ctx-1",
                Request::new(
                    User::new("alice"),
                    Action::new("view"),
                    Resource::new("Doc", "1"),
                ),
            )
            .with_context(context),
        ],
    };

    let resp = client.authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
}

#[tokio::test]
async fn authorize_detailed_sends_detail_full() {
    let (server, client) = setup().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "full"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "index": 0,
                "status": "success",
                "result": {
                    "policy": [{
                        "literal": "permit(principal, action, resource);",
                        "json": {"effect": "permit"},
                        "annotation_id": "p1",
                        "cedar_id": "policy0"
                    }],
                    "decision": "Allow",
                    "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" }
                }
            }],
            "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
            "successful": 1,
            "failed": 0
        })))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Doc", "1"),
    ));
    let resp = client.authorize_detailed(&batch).await.unwrap();
    let result = &resp.results()[0];
    match &result.result {
        BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Allow);
            assert_eq!(data.policy.len(), 1);
            assert_eq!(data.policy[0].cedar_id, "policy0");
        }
        _ => panic!("expected success"),
    }
}

#[tokio::test]
async fn authorize_with_group_principal() {
    let (server, client) = setup().await;

    let expected_body = json!({
        "requests": [{
            "principal": { "Group": { "id": "admins", "namespace": ["DNS"] } },
            "action": { "id": "manage", "namespace": [] },
            "resource": { "kind": "Zone", "id": "example.com" }
        }]
    });

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "brief"))
        .and(body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response("Allow", "p1")))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        Group::new("admins").with_namespace(vec!["DNS".to_string()]),
        Action::new("manage"),
        Resource::new("Zone", "example.com"),
    ));
    let resp = client.authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
}

// ==========================================================================
// is_allowed -- parameterized over Allow/Deny
// ==========================================================================

#[rstest]
#[case::allow("Allow", "p1", true)]
#[case::deny("Deny", "", false)]
#[tokio::test]
async fn is_allowed_returns_expected_decision(
    #[case] decision: &str,
    #[case] policy_id: &str,
    #[case] expected: bool,
) {
    let (server, client) = setup().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response(decision, policy_id)))
        .mount(&server)
        .await;

    let allowed = client
        .is_allowed(Request::new(
            User::new("alice"),
            Action::new("view"),
            Resource::new("Doc", "1"),
        ))
        .await
        .unwrap();
    assert_eq!(allowed, expected);
}

#[tokio::test]
async fn is_allowed_returns_error_on_failed_result() {
    let (server, client) = setup().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "index": 0,
                "status": "failed",
                "error": "invalid principal format"
            }],
            "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
            "successful": 0,
            "failed": 1
        })))
        .mount(&server)
        .await;

    let err = client
        .is_allowed(Request::new(
            User::new("bad"),
            Action::new("view"),
            Resource::new("Doc", "1"),
        ))
        .await
        .unwrap_err();
    match err {
        TreetopError::Api { message, .. } => {
            assert!(message.contains("invalid principal format"));
        }
        _ => panic!("expected Api error"),
    }
}

// ==========================================================================
// Correlation ID
// ==========================================================================

#[tokio::test]
async fn correlation_id_sent_as_header() {
    let (server, client) = setup().await;
    let traced = client.with_correlation_id("req-abc-123");

    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .and(header("x-correlation-id", "req-abc-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    traced.health().await.unwrap();
}

#[tokio::test]
async fn builder_correlation_id_sent_on_all_requests() {
    let server = MockServer::start().await;
    let client = Client::builder(server.uri())
        .correlation_id("build-time-id")
        .build()
        .unwrap();

    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .and(header("x-correlation-id", "build-time-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    client.health().await.unwrap();
}

#[tokio::test]
async fn without_correlation_id_removes_header() {
    let (server, client) = setup().await;
    let traced = client.with_correlation_id("temp-id");
    let untraced = traced.without_correlation_id();

    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    untraced.health().await.unwrap();
}

// ==========================================================================
// Policies
// ==========================================================================

#[tokio::test]
async fn get_policies_json() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policies": {
                "timestamp": "2026-01-01T00:00:00Z",
                "sha256": "abc",
                "size": 50,
                "entries": 2,
                "content": "permit(...);"
            }
        })))
        .mount(&server)
        .await;

    let download = client.get_policies().await.unwrap();
    assert_eq!(download.policies.entries, 2);
    assert_eq!(download.policies.content, "permit(...);");
}

#[tokio::test]
async fn get_policies_raw() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies"))
        .and(query_param("format", "raw"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("permit(principal, action, resource);"),
        )
        .mount(&server)
        .await;

    let raw = client.get_policies_raw().await.unwrap();
    assert_eq!(raw, "permit(principal, action, resource);");
}

#[tokio::test]
async fn get_schema_json() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/schema"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schema": {
                "timestamp": "2026-01-01T00:00:00Z",
                "sha256": "schema-hash",
                "size": 93,
                "entries": 1,
                "content": "{\"\": {\"entityTypes\": {}, \"actions\": {}}}"
            }
        })))
        .mount(&server)
        .await;

    let download = client.get_schema().await.unwrap();
    assert_eq!(download.schema.sha256, "schema-hash");
    assert_eq!(download.schema.entries, 1);
}

#[tokio::test]
async fn get_schema_raw() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/schema"))
        .and(query_param("format", "raw"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"": {"entityTypes": {}, "actions": {}}}"#),
        )
        .mount(&server)
        .await;

    let raw = client.get_schema_raw().await.unwrap();
    assert!(raw.contains("entityTypes"));
}

// ==========================================================================
// Upload -- parameterized: both raw and json require a token
// ==========================================================================

#[rstest]
#[case::raw("raw")]
#[case::json("json")]
#[tokio::test]
async fn upload_without_token_returns_configuration_error(#[case] variant: &str) {
    let (_server, client) = setup().await;
    let err = match variant {
        "raw" => client
            .upload_policies_raw("permit(...);")
            .await
            .unwrap_err(),
        "json" => client
            .upload_policies_json("permit(...);")
            .await
            .unwrap_err(),
        _ => unreachable!(),
    };
    match err {
        TreetopError::Configuration(msg) => {
            assert!(msg.contains("no upload token"));
        }
        _ => panic!("expected Configuration error, got: {err:?}"),
    }
}

#[tokio::test]
async fn upload_raw_sends_token_and_content_type() {
    let (server, client) = setup_with_token("secret-token").await;

    Mock::given(method("POST"))
        .and(path("/api/v1/policies"))
        .and(header("X-Upload-Token", "secret-token"))
        .and(header("Content-Type", "text/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policies_metadata_json()))
        .mount(&server)
        .await;

    let meta = client.upload_policies_raw("permit(...);").await.unwrap();
    assert_eq!(meta.policies.sha256, "new-hash");
}

#[tokio::test]
async fn upload_json_sends_token_and_json_body() {
    let (server, client) = setup_with_token("my-token").await;

    Mock::given(method("POST"))
        .and(path("/api/v1/policies"))
        .and(header("X-Upload-Token", "my-token"))
        .and(body_json(json!({"policies": "permit(...);"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(policies_metadata_json()))
        .mount(&server)
        .await;

    let meta = client.upload_policies_json("permit(...);").await.unwrap();
    assert_eq!(meta.policies.entries, 1);
}

#[tokio::test]
async fn upload_schema_raw_sends_token_and_content_type() {
    let (server, client) = setup_with_token("schema-token").await;

    Mock::given(method("POST"))
        .and(path("/api/v1/schema"))
        .and(header("X-Upload-Token", "schema-token"))
        .and(header("Content-Type", "text/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policies_metadata_json()))
        .mount(&server)
        .await;

    let meta = client
        .upload_schema_raw(r#"{"": {"entityTypes": {}, "actions": {}}}"#)
        .await
        .unwrap();
    assert_eq!(meta.policies.sha256, "new-hash");
}

#[tokio::test]
async fn upload_schema_json_sends_token_and_json_body() {
    let (server, client) = setup_with_token("schema-json-token").await;

    Mock::given(method("POST"))
        .and(path("/api/v1/schema"))
        .and(header("X-Upload-Token", "schema-json-token"))
        .and(body_json(json!({
            "schema": r#"{"": {"entityTypes": {}, "actions": {}}}"#
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(policies_metadata_json()))
        .mount(&server)
        .await;

    let meta = client
        .upload_schema_json(r#"{"": {"entityTypes": {}, "actions": {}}}"#)
        .await
        .unwrap();
    assert_eq!(meta.policies.entries, 1);
}

// ==========================================================================
// User policies
// ==========================================================================

#[tokio::test]
async fn get_user_policies_with_filters() {
    let (server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/policies/alice"))
        .and(query_param("namespaces[]", "DNS"))
        .and(query_param("groups[]", "admins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": "alice",
            "policies": [{"effect": "permit"}]
        })))
        .mount(&server)
        .await;

    let policies = client
        .get_user_policies("alice", &["admins".into()], &["DNS".into()])
        .await
        .unwrap();
    assert_eq!(policies.user, "alice");
    assert_eq!(policies.policies.len(), 1);
}

#[tokio::test]
async fn user_policies_with_empty_groups_and_namespaces() {
    let (server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/policies/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": "alice",
            "policies": []
        })))
        .mount(&server)
        .await;

    let policies = client.get_user_policies("alice", &[], &[]).await.unwrap();
    assert_eq!(policies.user, "alice");
    assert!(policies.policies.is_empty());
}

// --- URL encoding edge cases (parameterized) ---

#[rstest]
#[case::at_sign("alice@example.com", "/api/v1/policies/alice%40example.com", &[], &[])]
#[case::space("alice doe", "/api/v1/policies/alice+doe", &[], &[])]
#[tokio::test]
async fn user_policies_encodes_user_in_path(
    #[case] user: &str,
    #[case] expected_path: &str,
    #[case] groups: &[String],
    #[case] namespaces: &[String],
) {
    let (server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path(expected_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": user,
            "policies": []
        })))
        .mount(&server)
        .await;

    let policies = client
        .get_user_policies(user, groups, namespaces)
        .await
        .unwrap();
    assert_eq!(policies.user, user);
}

#[rstest]
#[case::unicode_namespace("alice", "namespaces[]", "Caf\u{00e9}", &[], &["Caf\u{00e9}".to_string()])]
#[case::ampersand_group("bob", "groups[]", "r&d", &["r&d".to_string()], &[])]
#[tokio::test]
async fn user_policies_encodes_query_params(
    #[case] user: &str,
    #[case] param_key: &str,
    #[case] param_value: &str,
    #[case] groups: &[String],
    #[case] namespaces: &[String],
) {
    let (server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/policies/{user}")))
        .and(query_param(param_key, param_value))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": user,
            "policies": []
        })))
        .mount(&server)
        .await;

    let policies = client
        .get_user_policies(user, groups, namespaces)
        .await
        .unwrap();
    assert_eq!(policies.user, user);
}

// ==========================================================================
// Metrics
// ==========================================================================

#[tokio::test]
async fn metrics_returns_text() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("# HELP requests_total\nrequests_total 42\n"),
        )
        .mount(&server)
        .await;

    let text = client.metrics().await.unwrap();
    assert!(text.contains("requests_total 42"));
}

// ==========================================================================
// Error handling -- parameterized over status codes and body formats
// ==========================================================================

#[rstest]
#[case::bad_request_json(400, r#"{"error": "bad request details"}"#, "bad request details")]
#[case::forbidden_json(403, r#"{"error": "Invalid upload token"}"#, "Invalid upload token")]
#[case::internal_json(500, r#"{"error": "lock poisoned"}"#, "lock poisoned")]
#[case::plain_text_503(503, "service unavailable", "service unavailable")]
#[case::empty_body_502(502, "", "")]
#[tokio::test]
async fn api_error_extracts_status_and_message(
    #[case] status_code: u16,
    #[case] body: &str,
    #[case] expected_message: &str,
) {
    let (server, client) = setup().await;

    let response = if body.starts_with('{') {
        ResponseTemplate::new(status_code).set_body_raw(body.to_string(), "application/json")
    } else {
        ResponseTemplate::new(status_code).set_body_string(body)
    };

    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(response)
        .mount(&server)
        .await;

    let err = client.version().await.unwrap_err();
    match err {
        TreetopError::Api { status, message } => {
            assert_eq!(status.as_u16(), status_code);
            assert_eq!(message, expected_message);
        }
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

#[tokio::test]
async fn api_403_on_upload() {
    let (server, client) = setup_with_token("wrong-token").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/policies"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": "Invalid upload token provided"})),
        )
        .mount(&server)
        .await;

    let err = client
        .upload_policies_raw("permit(...);")
        .await
        .unwrap_err();
    match err {
        TreetopError::Api { status, message } => {
            assert_eq!(status.as_u16(), 403);
            assert!(message.contains("Invalid upload token"));
        }
        _ => panic!("expected Api error"),
    }
}

// ==========================================================================
// Batch with mixed results
// ==========================================================================

#[tokio::test]
async fn batch_with_mixed_success_and_failure() {
    let (server, client) = setup().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "index": 0,
                    "id": "good",
                    "status": "success",
                    "result": {
                        "decision": "Allow",
                        "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
                        "policy_id": "p1"
                    }
                },
                {
                    "index": 1,
                    "id": "bad",
                    "status": "failed",
                    "error": "invalid resource type"
                }
            ],
            "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
            "successful": 1,
            "failed": 1
        })))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::new()
        .add_request_with_id(
            "good",
            Request::new(User::new("a"), Action::new("v"), Resource::new("D", "1")),
        )
        .add_request_with_id(
            "bad",
            Request::new(User::new("b"), Action::new("v"), Resource::new("D", "2")),
        );
    let resp = client.authorize(&batch).await.unwrap();

    assert_eq!(resp.successes(), 1);
    assert_eq!(resp.failures(), 1);
    assert_eq!(resp.total(), 2);

    let good = resp.find_by_id("good").unwrap();
    assert!(matches!(&good.result, BatchResult::Success { .. }));

    let bad = resp.find_by_id("bad").unwrap();
    match &bad.result {
        BatchResult::Failed { message } => assert!(message.contains("invalid resource")),
        _ => panic!("expected failure"),
    }
}

// ==========================================================================
// into_results
// ==========================================================================

#[tokio::test]
async fn into_results_consumes_response() {
    let (server, client) = setup().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(brief_response("Allow", "p1")))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Doc", "1"),
    ));
    let resp = client.authorize(&batch).await.unwrap();
    let results = resp.into_results();
    assert_eq!(results.len(), 1);
}

// ==========================================================================
// Display and Copy traits -- parameterized
// ==========================================================================

#[rstest]
#[case::allow(DecisionBrief::Allow, "Allow")]
#[case::deny(DecisionBrief::Deny, "Deny")]
fn decision_brief_display(#[case] decision: DecisionBrief, #[case] expected: &str) {
    assert_eq!(format!("{decision}"), expected);
}

#[test]
fn decision_brief_is_copy() {
    let d = DecisionBrief::Allow;
    let d2 = d; // copy
    assert_eq!(d, d2); // original still usable
}

#[test]
fn policy_version_display() {
    let v = treetop_client::PolicyVersion {
        hash: "abc123".to_string(),
        loaded_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert_eq!(format!("{v}"), "abc123 (loaded 2026-01-01T00:00:00Z)");
}

// ==========================================================================
// Client builder -- parameterized trailing slash stripping
// ==========================================================================

#[rstest]
#[case::single_slash("http://localhost:9999/")]
#[case::multiple_slashes("http://localhost:9999///")]
#[case::no_slash("http://localhost:9999")]
fn builder_normalizes_base_url(#[case] input: &str) {
    let client = Client::builder(input).build().unwrap();
    let debug = format!("{:?}", client);
    assert!(debug.contains("http://localhost:9999\""));
    assert!(!debug.contains("http://localhost:9999/"));
}

#[tokio::test]
async fn builder_with_reqwest_client_escape_hatch() {
    let server = MockServer::start().await;
    let custom = reqwest::Client::new();
    let client = Client::builder(server.uri())
        .with_reqwest_client(custom)
        .build()
        .unwrap();

    Mock::given(method("GET"))
        .and(path("/api/v1/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    client.health().await.unwrap();
}

// ==========================================================================
// Client Debug output
// ==========================================================================

#[test]
fn client_debug_does_not_leak_token() {
    let client = Client::builder("http://localhost:9999")
        .upload_token(UploadToken::new("super-secret"))
        .build()
        .unwrap();
    let debug = format!("{:?}", client);
    assert!(!debug.contains("super-secret"));
    assert!(debug.contains("[SET]"));
}

#[test]
fn client_debug_shows_none_when_no_token() {
    let client = Client::builder("http://localhost:9999").build().unwrap();
    let debug = format!("{:?}", client);
    assert!(debug.contains("None"));
}

// ==========================================================================
// Serde resilience (forward compatibility)
// ==========================================================================

#[tokio::test]
async fn version_ignores_extra_fields() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "0.2.0",
            "core": { "version": "0.4.0", "cedar": "4.2.0", "extra_field": true },
            "policies": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z", "serial": 42 },
            "new_top_level": "hello"
        })))
        .mount(&server)
        .await;

    let info = client.version().await.unwrap();
    assert_eq!(info.version, "0.2.0");
}

#[test]
fn metadata_missing_optional_fields() {
    let json = json!({
        "timestamp": "2026-01-01T00:00:00Z",
        "sha256": "abc",
        "size": 100,
        "entries": 5,
        "content": "data"
    });
    let meta: treetop_client::Metadata = serde_json::from_value(json).unwrap();
    assert!(meta.source.is_none());
    assert!(meta.refresh_frequency.is_none());
}

// --- PermitPolicy annotation_id: null, absent, or present ---

#[rstest]
#[case::explicit_null(json!({"literal": "p(...);", "json": {}, "annotation_id": null, "cedar_id": "p0"}), None)]
#[case::field_absent(json!({"literal": "p(...);", "json": {}, "cedar_id": "p0"}), None)]
#[case::field_present(json!({"literal": "p(...);", "json": {}, "annotation_id": "my-id", "cedar_id": "p0"}), Some("my-id"))]
fn permit_policy_annotation_id(#[case] input: serde_json::Value, #[case] expected: Option<&str>) {
    let policy: treetop_client::PermitPolicy = serde_json::from_value(input).unwrap();
    assert_eq!(policy.annotation_id.as_deref(), expected);
    assert_eq!(policy.cedar_id, "p0");
}

#[test]
fn authorize_response_with_extra_fields() {
    let json = json!({
        "results": [{
            "index": 0,
            "status": "success",
            "result": {
                "decision": "Allow",
                "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
                "policy_id": "p1",
                "extra": "ignored"
            },
            "extra_result_field": 123
        }],
        "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 1,
        "failed": 0,
        "extra_response_field": true
    });
    let resp: treetop_client::AuthorizeBriefResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.successes(), 1);
}

// ==========================================================================
// AuthorizeResponse accessor tests
// ==========================================================================

#[test]
fn find_by_id_returns_none_for_missing_id() {
    let json = json!({
        "results": [{
            "index": 0,
            "status": "success",
            "result": {
                "decision": "Allow",
                "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
                "policy_id": "p1"
            }
        }],
        "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 1,
        "failed": 0
    });
    let resp: treetop_client::AuthorizeBriefResponse = serde_json::from_value(json).unwrap();
    assert!(resp.find_by_id("nonexistent").is_none());
}

#[test]
fn response_into_iterator() {
    let json = json!({
        "results": [
            {
                "index": 0,
                "id": "a",
                "status": "success",
                "result": {
                    "decision": "Allow",
                    "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
                    "policy_id": "p1"
                }
            },
            {
                "index": 1,
                "id": "b",
                "status": "success",
                "result": {
                    "decision": "Deny",
                    "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
                    "policy_id": ""
                }
            }
        ],
        "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 2,
        "failed": 0
    });
    let resp: treetop_client::AuthorizeBriefResponse = serde_json::from_value(json).unwrap();

    let ids: Vec<&str> = resp.iter().filter_map(|r| r.id.as_deref()).collect();
    assert_eq!(ids, vec!["a", "b"]);

    let mut count = 0;
    for _result in &resp {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn into_results_gives_ownership() {
    let json = json!({
        "results": [{
            "index": 0,
            "id": "own-me",
            "status": "success",
            "result": {
                "decision": "Allow",
                "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
                "policy_id": "p1"
            }
        }],
        "version": { "hash": "h", "loaded_at": "2026-01-01T00:00:00Z" },
        "successful": 1,
        "failed": 0
    });
    let resp: treetop_client::AuthorizeBriefResponse = serde_json::from_value(json).unwrap();
    let mut results = resp.into_results();
    assert_eq!(results.len(), 1);
    results[0].id = Some("modified".to_string());
    assert_eq!(results[0].id.as_deref(), Some("modified"));
}

// ==========================================================================
// AuthorizeRequest builder edge cases
// ==========================================================================

#[test]
fn authorize_request_default_is_empty() {
    let req = AuthorizeRequest::default();
    assert!(req.requests.is_empty());
}

#[test]
fn authorize_request_from_requests_iterator() {
    let requests = vec![
        Request::new(User::new("a"), Action::new("v"), Resource::new("D", "1")),
        Request::new(User::new("b"), Action::new("v"), Resource::new("D", "2")),
        Request::new(User::new("c"), Action::new("v"), Resource::new("D", "3")),
    ];
    let batch = AuthorizeRequest::from_requests(requests);
    assert_eq!(batch.requests.len(), 3);
    assert!(batch.requests.iter().all(|r| r.id.is_none()));
}

// ==========================================================================
// Detailed response with null annotation_id
// ==========================================================================

#[tokio::test]
async fn detailed_response_with_no_annotation_id() {
    let (server, client) = setup().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authorize"))
        .and(query_param("detail", "full"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "index": 0,
                "status": "success",
                "result": {
                    "policy": [{
                        "literal": "permit(principal, action, resource);",
                        "json": {"effect": "permit"},
                        "cedar_id": "policy0"
                    }],
                    "decision": "Deny",
                    "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" }
                }
            }],
            "version": { "hash": "abc", "loaded_at": "2026-01-01T00:00:00Z" },
            "successful": 1,
            "failed": 0
        })))
        .mount(&server)
        .await;

    let batch = AuthorizeRequest::single(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Doc", "1"),
    ));
    let resp = client.authorize_detailed(&batch).await.unwrap();
    match &resp.results()[0].result {
        BatchResult::Success { data } => {
            assert!(data.policy[0].annotation_id.is_none());
            assert_eq!(data.policy[0].cedar_id, "policy0");
            assert_eq!(data.decision, DecisionBrief::Deny);
        }
        _ => panic!("expected success"),
    }
}

// ==========================================================================
// AttrValue edge cases
// ==========================================================================

#[rstest]
#[case::nested_sets(AttrValue::Set(vec![
    AttrValue::String("outer".to_string()),
    AttrValue::Set(vec![AttrValue::Long(1), AttrValue::Long(2)]),
]))]
#[case::empty_set(AttrValue::Set(vec![]))]
fn attrvalue_edge_case_roundtrip(#[case] val: AttrValue) {
    let json = serde_json::to_value(&val).unwrap();
    let roundtripped: AttrValue = serde_json::from_value(json).unwrap();
    assert_eq!(val, roundtripped);
}

#[test]
fn attrvalue_empty_set_serializes_correctly() {
    let val = AttrValue::Set(vec![]);
    let json = serde_json::to_value(&val).unwrap();
    assert_eq!(json, json!({"type": "Set", "value": []}));
}

// ==========================================================================
// Deserialization error path
// ==========================================================================

#[tokio::test]
async fn deserialization_error_on_malformed_json_body() {
    let (server, client) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(r#"{"version": 123}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let err = client.version().await.unwrap_err();
    assert!(
        matches!(err, TreetopError::Deserialization(_)),
        "expected Deserialization error, got: {err:?}"
    );
}

// ==========================================================================
// AuthRequest without ID omits the id field
// ==========================================================================

#[test]
fn auth_request_without_id_omits_id_field() {
    let auth = treetop_client::AuthRequest::new(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Doc", "1"),
    ));
    let json = serde_json::to_value(&auth).unwrap();
    assert!(
        json.get("id").is_none(),
        "id field should be absent, got: {json}"
    );
    // Flattened fields should still be present
    assert!(json.get("principal").is_some());
}

// ==========================================================================
// Resource with_attr overwrites duplicate keys
// ==========================================================================

#[test]
fn resource_with_attr_overwrites_duplicate_key() {
    let resource = Resource::new("Host", "web-01")
        .with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()))
        .with_attr("ip", AttrValue::Ip("192.168.1.1".to_string()));

    assert_eq!(resource.attrs.len(), 1);
    assert_eq!(
        resource.attrs.get("ip"),
        Some(&AttrValue::Ip("192.168.1.1".to_string()))
    );
}
