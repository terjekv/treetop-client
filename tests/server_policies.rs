#![cfg(feature = "server-tests")]

mod common;

use common::{
    CONTEXT_POLICY, INVALID_CEDAR, SIMPLE_POLICIES, all_policies, ensure_policies,
    restore_policies, server,
};
use rstest::rstest;
use serial_test::serial;
use treetop_client::{
    Action, AttrValue, AuthRequest, AuthorizeRequest, BatchResult, DecisionBrief,
    PolicyMatchReason, Request, Resource, TreetopError, User,
};

// ==========================================================================
// Upload tests (serial -- these mutate server state)
// ==========================================================================

#[tokio::test]
#[serial]
async fn upload_raw_succeeds() {
    let s = server().await;
    let meta = s
        .client_with_token()
        .upload_policies_raw(&all_policies())
        .await
        .unwrap();
    assert!(meta.allow_upload);
    assert!(!meta.policies.sha256.is_empty());
    assert!(meta.policies.content.contains("permit"));
}

#[tokio::test]
#[serial]
async fn upload_json_succeeds() {
    let s = server().await;
    let meta = s
        .client_with_token()
        .upload_policies_json(&all_policies())
        .await
        .unwrap();
    assert!(meta.allow_upload);
    assert!(!meta.policies.sha256.is_empty());
}

#[tokio::test]
#[serial]
async fn upload_changes_policy_hash() {
    let s = server().await;
    let client = s.client_with_token();

    let meta1 = client.upload_policies_raw(SIMPLE_POLICIES).await.unwrap();
    let meta2 = client.upload_policies_raw(&all_policies()).await.unwrap();

    assert_ne!(
        meta1.policies.sha256, meta2.policies.sha256,
        "different policies should produce different hashes"
    );

    // Restore
    restore_policies(s).await;
}

#[tokio::test]
#[serial]
async fn upload_and_verify_authorization() {
    let s = server().await;
    let client = s.client_with_token();
    let read_client = s.client();

    // Upload a policy that only allows bob
    let bob_only = r#"permit(principal == User::"bob", action, resource);"#;
    client.upload_policies_raw(bob_only).await.unwrap();

    // Alice should be denied
    let alice_allowed = read_client
        .is_allowed(Request::new(
            User::new("alice"),
            Action::new("view"),
            Resource::new("Photo", "test"),
        ))
        .await
        .unwrap();
    assert!(
        !alice_allowed,
        "alice should be denied under bob-only policy"
    );

    // Bob should be allowed
    let bob_allowed = read_client
        .is_allowed(Request::new(
            User::new("bob"),
            Action::new("view"),
            Resource::new("Photo", "test"),
        ))
        .await
        .unwrap();
    assert!(bob_allowed, "bob should be allowed under bob-only policy");

    // Restore
    restore_policies(s).await;
}

#[tokio::test]
#[serial]
async fn upload_context_policy_and_authorize_with_context() {
    let s = server().await;
    s.client_with_token()
        .upload_policies_raw(CONTEXT_POLICY)
        .await
        .unwrap();

    let mut context = std::collections::HashMap::new();
    context.insert("env".to_string(), AttrValue::String("prod".to_string()));

    let batch = AuthorizeRequest {
        requests: vec![
            AuthRequest::with_id(
                "ctx-1",
                Request::new(
                    User::new("alice"),
                    Action::new("view"),
                    Resource::new("Photo", "VacationPhoto94.jpg"),
                ),
            )
            .with_context(context),
        ],
    };

    let resp = s.client().authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
    assert_eq!(resp.failures(), 0);

    match &resp.results()[0].result {
        BatchResult::Success { data } => assert_eq!(data.decision, DecisionBrief::Allow),
        _ => panic!("expected success"),
    }

    restore_policies(s).await;
}

// ==========================================================================
// Download tests (serial -- shared policy state with upload tests)
// ==========================================================================

#[tokio::test]
#[serial]
async fn get_policies_json_has_metadata() {
    let s = server().await;
    ensure_policies(s).await;

    let download = s.client().get_policies().await.unwrap();
    assert!(!download.policies.sha256.is_empty());
    assert!(download.policies.content.contains("permit"));
}

#[tokio::test]
#[serial]
async fn get_policies_raw_returns_cedar() {
    let s = server().await;
    ensure_policies(s).await;

    let raw = s.client().get_policies_raw().await.unwrap();
    assert!(
        raw.contains("permit"),
        "raw policies should contain Cedar DSL"
    );
}

#[tokio::test]
#[serial]
async fn raw_matches_json_content() {
    let s = server().await;
    ensure_policies(s).await;

    let client = s.client();
    let raw = client.get_policies_raw().await.unwrap();
    let json = client.get_policies().await.unwrap();
    assert_eq!(
        raw, json.policies.content,
        "raw and JSON content should match"
    );
}

// ==========================================================================
// User policies (serial -- shared policy state with upload tests)
// ==========================================================================

#[tokio::test]
#[serial]
async fn user_policies_alice_returns_policies() {
    let s = server().await;
    ensure_policies(s).await;

    let policies = s
        .client()
        .get_user_policies("alice", &[], &[])
        .await
        .unwrap();
    assert_eq!(policies.user, "alice");
    assert!(!policies.policies.is_empty(), "alice should have policies");
}

#[tokio::test]
#[serial]
async fn user_policies_has_matches() {
    let s = server().await;
    s.client_with_token()
        .upload_policies_raw(
            r#"permit (
    principal == User::"alice",
    action,
    resource
);"#,
        )
        .await
        .unwrap();

    let policies = s
        .client()
        .get_user_policies("alice", &[], &[])
        .await
        .unwrap();
    assert_eq!(policies.matches.len(), 1, "expected one exact match");
    assert!(
        !policies.matches[0].cedar_id.is_empty(),
        "cedar_id should be populated"
    );
    assert_eq!(
        policies.matches[0].reasons,
        vec![PolicyMatchReason::PrincipalEq]
    );

    restore_policies(s).await;
}

#[tokio::test]
#[serial]
async fn user_policies_group_match_reason_is_exact() {
    let s = server().await;
    s.client_with_token()
        .upload_policies_raw(
            r#"permit (
    principal in DNS::Group::"admins",
    action,
    resource
);"#,
        )
        .await
        .unwrap();

    let policies = s
        .client()
        .get_user_policies("charlie", &["admins".into()], &["DNS".into()])
        .await
        .unwrap();
    assert_eq!(policies.matches.len(), 1, "expected one group-based match");
    assert!(
        !policies.matches[0].cedar_id.is_empty(),
        "cedar_id should be populated"
    );
    assert_eq!(
        policies.matches[0].reasons,
        vec![PolicyMatchReason::PrincipalIn]
    );

    restore_policies(s).await;
}

#[tokio::test]
#[serial]
async fn user_policies_raw_returns_text() {
    let s = server().await;
    ensure_policies(s).await;

    let raw = s
        .client()
        .get_user_policies_raw("alice", &[], &[])
        .await
        .unwrap();
    assert!(
        raw.contains("permit"),
        "raw user policies should contain Cedar DSL"
    );
}

#[tokio::test]
#[serial]
async fn user_policies_with_dns_namespace() {
    let s = server().await;
    ensure_policies(s).await;

    let policies = s
        .client()
        .get_user_policies("charlie", &["admins".into()], &["DNS".into()])
        .await
        .unwrap();
    assert_eq!(policies.user, "charlie");
    assert!(
        !policies.policies.is_empty(),
        "charlie in DNS admins should have policies"
    );
}

#[tokio::test]
#[serial]
async fn user_policies_super_returns_wildcard() {
    let s = server().await;
    ensure_policies(s).await;

    let policies = s
        .client()
        .get_user_policies("super", &[], &[])
        .await
        .unwrap();
    assert_eq!(policies.user, "super");
    assert!(
        !policies.policies.is_empty(),
        "super should have the wildcard policy"
    );
}

// ==========================================================================
// Upload error cases
// ==========================================================================

#[rstest]
#[case::raw("raw")]
#[case::json("json")]
#[tokio::test]
async fn upload_without_token_returns_configuration_error(#[case] variant: &str) {
    let s = server().await;
    let client = s.client(); // no token
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
    assert!(
        matches!(err, TreetopError::Configuration(_)),
        "expected Configuration error, got: {err:?}"
    );
}

#[tokio::test]
async fn upload_with_wrong_token_returns_403() {
    let s = server().await;
    let err = s
        .client_with_wrong_token()
        .upload_policies_raw("permit(principal, action, resource);")
        .await
        .unwrap_err();
    match err {
        TreetopError::Api { status, message } => {
            assert_eq!(status.as_u16(), 403);
            assert!(
                message.contains("Invalid upload token"),
                "unexpected message: {message}"
            );
        }
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

#[tokio::test]
async fn upload_invalid_cedar_returns_400() {
    let s = server().await;
    let err = s
        .client_with_token()
        .upload_policies_raw(INVALID_CEDAR)
        .await
        .unwrap_err();
    match err {
        TreetopError::Api { status, message } => {
            assert_eq!(status.as_u16(), 400);
            assert!(
                message.contains("compile") || message.contains("parse"),
                "error should mention compilation/parsing: {message}"
            );
        }
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

#[tokio::test]
async fn upload_empty_content_returns_400() {
    let s = server().await;
    let err = s
        .client_with_token()
        .upload_policies_raw("")
        .await
        .unwrap_err();
    match err {
        TreetopError::Api { status, message } => {
            assert_eq!(status.as_u16(), 400);
            assert!(
                message.contains("Invalid text payload"),
                "unexpected message: {message}"
            );
        }
        _ => panic!("expected Api error, got: {err:?}"),
    }
}
