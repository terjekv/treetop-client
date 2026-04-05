#![cfg(feature = "server-tests")]

mod common;

use common::{
    alice_view_photo, bob_view_photo, dns_action, dns_user, ensure_policies, extract_decision,
    server, super_any,
};
use rstest::rstest;
use treetop_client::{
    Action, AuthorizeRequest, BatchResult, DecisionBrief, Request, Resource, User,
};

// ==========================================================================
// Simple policy authorization (parameterized)
// ==========================================================================

#[rstest]
#[case::alice_view_allowed("alice", "view", "Photo", "VacationPhoto94.jpg", true)]
#[case::alice_edit_forbidden("alice", "edit", "Photo", "VacationPhoto94.jpg", false)]
#[case::alice_delete_forbidden("alice", "delete", "Photo", "VacationPhoto94.jpg", false)]
#[case::bob_view_denied("bob", "view", "Photo", "VacationPhoto94.jpg", false)]
#[case::bob_delete_forbidden("bob", "delete", "Photo", "VacationPhoto94.jpg", false)]
#[case::alice_only_here_any("alice", "only_here", "Anything", "whatever", true)]
#[case::unknown_user_denied("nobody", "view", "Photo", "VacationPhoto94.jpg", false)]
#[case::super_admin_wildcard("super", "anything", "Whatever", "something", true)]
#[tokio::test]
async fn simple_authorization(
    #[case] user: &str,
    #[case] action: &str,
    #[case] kind: &str,
    #[case] id: &str,
    #[case] expected: bool,
) {
    let s = server().await;
    ensure_policies(s).await;

    let allowed = s
        .client()
        .is_allowed(Request::new(
            User::new(user),
            Action::new(action),
            Resource::new(kind, id),
        ))
        .await
        .unwrap();
    assert_eq!(
        allowed,
        expected,
        "{user} {action} {kind}::{id} should be {}",
        if expected { "allowed" } else { "denied" }
    );
}

// ==========================================================================
// DNS namespaced authorization (parameterized)
// ==========================================================================

#[rstest]
#[case::admin_create_host("alice", &["admins"], "create_host", true)]
#[case::admin_delete_host("alice", &["admins"], "delete_host", true)]
#[case::admin_view_host("alice", &["admins"], "view_host", true)]
#[case::user_view_host("dave", &["users"], "view_host", true)]
#[case::user_cannot_create("dave", &["users"], "create_host", false)]
#[case::charlie_admin_but_forbid_delete("charlie", &["admins"], "delete_host", false)]
#[tokio::test]
async fn dns_authorization(
    #[case] user_name: &str,
    #[case] groups: &[&str],
    #[case] action: &str,
    #[case] expected: bool,
) {
    let s = server().await;
    ensure_policies(s).await;

    let allowed = s
        .client()
        .is_allowed(Request::new(
            dns_user(user_name, groups),
            dns_action(action),
            Resource::new("Host", "web-01.example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(
        allowed,
        expected,
        "DNS {user_name} ({groups:?}) {action} should be {}",
        if expected { "allowed" } else { "denied" }
    );
}

// ==========================================================================
// Brief vs detailed responses
// ==========================================================================

#[tokio::test]
async fn authorize_brief_has_policy_id_on_allow() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::single(alice_view_photo());
    let resp = s.client().authorize(&batch).await.unwrap();
    let result = &resp.results()[0];
    match &result.result {
        BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Allow);
            assert!(
                !data.policy_id.is_empty(),
                "allowed result should have a policy_id"
            );
        }
        _ => panic!("expected success"),
    }
}

#[tokio::test]
async fn authorize_brief_has_empty_policy_id_on_deny() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::single(bob_view_photo());
    let resp = s.client().authorize(&batch).await.unwrap();
    let result = &resp.results()[0];
    match &result.result {
        BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Deny);
            assert!(
                data.policy_id.is_empty(),
                "denied result should have empty policy_id"
            );
        }
        _ => panic!("expected success"),
    }
}

#[tokio::test]
async fn authorize_detailed_includes_policy_text() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::single(alice_view_photo());
    let resp = s.client().authorize_detailed(&batch).await.unwrap();
    let result = &resp.results()[0];
    match &result.result {
        BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Allow);
            assert!(
                !data.policy.is_empty(),
                "allowed result should have policies"
            );
            let p = &data.policy[0];
            assert!(!p.literal.is_empty(), "policy literal should be non-empty");
            assert!(
                !p.cedar_id.is_empty(),
                "policy cedar_id should be non-empty"
            );
        }
        _ => panic!("expected success"),
    }
}

#[tokio::test]
async fn authorize_detailed_deny_has_empty_policies() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::single(bob_view_photo());
    let resp = s.client().authorize_detailed(&batch).await.unwrap();
    let result = &resp.results()[0];
    match &result.result {
        BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Deny);
            assert!(
                data.policy.is_empty(),
                "denied result should have empty policies"
            );
        }
        _ => panic!("expected success"),
    }
}

// ==========================================================================
// Batch authorization
// ==========================================================================

#[tokio::test]
async fn batch_mixed_allow_deny() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::new()
        .add_request_with_id("allow", alice_view_photo())
        .add_request_with_id("deny", bob_view_photo());

    let resp = s.client().authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 2);
    assert_eq!(resp.failures(), 0);
    assert_eq!(resp.total(), 2);

    assert_eq!(
        extract_decision(&treetop_client::AuthorizeResponse {
            results: vec![resp.find_by_id("allow").unwrap().clone()],
            version: resp.version().clone(),
            successful: 1,
            failed: 0,
        }),
        DecisionBrief::Allow
    );

    let deny = resp.find_by_id("deny").unwrap();
    match &deny.result {
        BatchResult::Success { data } => assert_eq!(data.decision, DecisionBrief::Deny),
        _ => panic!("expected success"),
    }
}

#[tokio::test]
async fn batch_preserves_request_ids() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::new()
        .add_request_with_id("first", alice_view_photo())
        .add_request_with_id("second", super_any());

    let resp = s.client().authorize(&batch).await.unwrap();

    let first = resp.find_by_id("first").unwrap();
    assert_eq!(first.index, 0);
    let second = resp.find_by_id("second").unwrap();
    assert_eq!(second.index, 1);
}

#[tokio::test]
async fn batch_without_ids() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::from_requests(vec![alice_view_photo(), bob_view_photo()]);
    let resp = s.client().authorize(&batch).await.unwrap();
    assert_eq!(resp.total(), 2);

    for result in resp.results() {
        assert!(
            result.id.is_none(),
            "from_requests should produce results without IDs"
        );
    }
}

#[tokio::test]
async fn empty_batch_returns_zero_results() {
    let s = server().await;
    ensure_policies(s).await;

    let batch = AuthorizeRequest::new();
    let resp = s.client().authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 0);
    assert_eq!(resp.failures(), 0);
    assert_eq!(resp.total(), 0);
}

#[tokio::test]
async fn response_version_matches_server() {
    let s = server().await;
    ensure_policies(s).await;

    let client = s.client();
    let version_info = client.version().await.unwrap();
    let batch = AuthorizeRequest::single(alice_view_photo());
    let resp = client.authorize(&batch).await.unwrap();

    assert_eq!(
        resp.version().hash,
        version_info.policies.hash,
        "authorize response version hash should match server version"
    );
}
