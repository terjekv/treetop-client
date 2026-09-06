#![cfg(feature = "server-tests")]

mod common;

use common::{alice_view_photo, bob_view_photo, ensure_policies, server};

/// Exercises the strict current server contract against the pinned candidate.
#[tokio::test]
async fn supported_server_contract() {
    let server = server().await;
    let client = server.client();

    client.livez().await.unwrap();
    let version = client.version().await.unwrap();
    assert!(!version.version.is_empty());
    assert!(!version.core.version.is_empty());
    assert!(!version.core.cedar.is_empty());

    assert_eq!(version.version.trim_start_matches('v'), "0.1.0");
    assert_eq!(version.core.version.trim_start_matches('v'), "0.1.0");

    ensure_policies(server).await;
    assert!(client.is_allowed(alice_view_photo()).await.unwrap());
    assert!(!client.is_allowed(bob_view_photo()).await.unwrap());

    let policies = client.get_policies_raw().await.unwrap();
    assert!(policies.contains("permit"));
}
