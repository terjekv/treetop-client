#![cfg(feature = "server-tests")]

mod common;

use common::server;
use treetop_client::RequestContextFallbackReason;

#[tokio::test]
async fn health_returns_ok() {
    let s = server().await;
    s.client().health().await.unwrap();
}

#[tokio::test]
async fn version_has_expected_fields() {
    let s = server().await;
    let info = s.client().version().await.unwrap();
    assert!(!info.version.is_empty(), "version should be non-empty");
    assert!(
        !info.core.version.is_empty(),
        "core version should be non-empty"
    );
    assert!(
        !info.core.cedar.is_empty(),
        "cedar version should be non-empty"
    );
    assert!(
        !info.policies.hash.is_empty(),
        "policy hash should be non-empty"
    );
    assert!(
        !info.policies.loaded_at.is_empty(),
        "loaded_at should be non-empty"
    );
}

#[tokio::test]
async fn status_shows_upload_enabled() {
    let s = server().await;
    let status = s.client().status().await.unwrap();
    assert!(
        status.policy_configuration.allow_upload,
        "server was started with TREETOP_ALLOW_UPLOAD=true"
    );
}

#[tokio::test]
async fn status_reports_schema_defaults() {
    let s = server().await;
    let status = s.client().status().await.unwrap();
    assert_eq!(
        status.policy_configuration.schema_validation_mode, "permissive",
        "default schema_validation_mode should be permissive"
    );
    assert!(
        status.policy_configuration.schema.is_some(),
        "v0.0.6 status should include schema metadata"
    );
}

#[tokio::test]
async fn status_reports_request_context_runtime() {
    let s = server().await;
    let status = s.client().status().await.unwrap();
    assert!(status.request_context.supported);
    assert!(!status.request_context.schema_backed);
    assert_eq!(
        status.request_context.fallback_reason,
        Some(RequestContextFallbackReason::NoSchema)
    );
}

#[tokio::test]
async fn status_has_parallel_config() {
    let s = server().await;
    let status = s.client().status().await.unwrap();
    assert!(
        status.parallel_configuration.is_object(),
        "parallel_configuration should be a JSON object"
    );
}

#[tokio::test]
async fn status_has_request_limits() {
    let s = server().await;
    let status = s.client().status().await.unwrap();
    assert_eq!(status.request_limits.max_context_bytes, 16 * 1024);
    assert_eq!(status.request_limits.max_context_depth, 8);
    assert_eq!(status.request_limits.max_context_keys, 64);
}
