#![cfg(feature = "server-tests")]

mod common;

use common::{alice_view_photo, ensure_policies, server};
use treetop_client::{AuthorizeRequest, Client, DecisionBrief};

// The live treetop-rest container does not expose received correlation IDs in
// responses or metrics. Exact header propagation is asserted in wiremock tests;
// these server tests are smoke tests that prove correlation IDs are accepted
// end-to-end without changing behavior.

#[tokio::test]
async fn correlation_id_health_smoke() {
    let s = server().await;
    s.client()
        .with_correlation_id("test-corr-123")
        .health()
        .await
        .unwrap();
}

#[tokio::test]
async fn correlation_id_does_not_change_decision() {
    let s = server().await;
    ensure_policies(s).await;

    let request = alice_view_photo();
    let without = s.client().is_allowed(request.clone()).await.unwrap();
    let with = s
        .client()
        .with_correlation_id("corr-id")
        .is_allowed(request)
        .await
        .unwrap();

    assert_eq!(
        without, with,
        "correlation ID should not affect authorization decision"
    );
}

#[tokio::test]
async fn without_correlation_id_works() {
    let s = server().await;
    let client = s
        .client()
        .with_correlation_id("temp")
        .without_correlation_id();
    client.health().await.unwrap();
}

#[tokio::test]
async fn correlation_id_builder_smoke_across_endpoints() {
    let s = server().await;
    ensure_policies(s).await;

    let client = Client::builder(&s.base_url)
        .correlation_id("builder-corr")
        .build()
        .unwrap();

    client.health().await.unwrap();
    let _version = client.version().await.unwrap();

    let batch = AuthorizeRequest::single(alice_view_photo());
    let resp = client.authorize(&batch).await.unwrap();
    assert_eq!(resp.successes(), 1);
    match &resp.results()[0].result {
        treetop_client::BatchResult::Success { data } => {
            assert_eq!(data.decision, DecisionBrief::Allow);
        }
        _ => panic!("expected success"),
    }
}
