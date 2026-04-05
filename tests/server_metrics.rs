#![cfg(feature = "server-tests")]

mod common;

use common::{alice_view_photo, ensure_policies, server};
use serial_test::serial;
use treetop_client::AuthorizeRequest;

fn counter_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> u64 {
    for line in metrics.lines() {
        if !(line.starts_with(&format!("{name}{{")) || line.starts_with(&format!("{name} "))) {
            continue;
        }

        if labels
            .iter()
            .all(|(key, value)| line.contains(&format!(r#"{key}="{value}""#)))
        {
            return line
                .split_whitespace()
                .last()
                .expect("metric line should end with a numeric value")
                .parse()
                .expect("metric value should parse as u64");
        }
    }

    0
}

#[tokio::test]
#[serial]
async fn metrics_returns_prometheus_format() {
    let s = server().await;
    let text = s.client().metrics().await.unwrap();
    assert!(
        text.contains("# HELP") || text.contains("# TYPE"),
        "metrics should contain Prometheus exposition format markers"
    );
}

#[tokio::test]
#[serial]
async fn metrics_contains_http_request_metrics() {
    let s = server().await;
    s.client().health().await.unwrap();

    let text = s.client().metrics().await.unwrap();
    assert!(
        counter_value(
            &text,
            "http_requests_total",
            &[
                ("method", "GET"),
                ("path", "/api/v1/health"),
                ("status_code", "200"),
            ],
        ) >= 1,
        "health request counter should be present"
    );
}

#[tokio::test]
#[serial]
async fn metrics_update_after_requests() {
    let s = server().await;
    ensure_policies(s).await;

    let client = s.client();
    let before = counter_value(
        &client.metrics().await.unwrap(),
        "http_requests_total",
        &[
            ("method", "POST"),
            ("path", "/api/v1/authorize"),
            ("status_code", "200"),
        ],
    );

    // Make several requests
    let batch = AuthorizeRequest::single(alice_view_photo());
    for _ in 0..5 {
        client.authorize(&batch).await.unwrap();
    }

    let after = counter_value(
        &client.metrics().await.unwrap(),
        "http_requests_total",
        &[
            ("method", "POST"),
            ("path", "/api/v1/authorize"),
            ("status_code", "200"),
        ],
    );

    assert_eq!(
        after,
        before + 5,
        "authorize request counter should increase by exactly five"
    );
}

#[tokio::test]
#[serial]
async fn policy_eval_counter_increments() {
    let s = server().await;
    let client = s.client();
    let before = counter_value(
        &client.metrics().await.unwrap(),
        "http_requests_total",
        &[
            ("method", "GET"),
            ("path", "/api/v1/health"),
            ("status_code", "200"),
        ],
    );
    client.health().await.unwrap();

    let after = counter_value(
        &client.metrics().await.unwrap(),
        "http_requests_total",
        &[
            ("method", "GET"),
            ("path", "/api/v1/health"),
            ("status_code", "200"),
        ],
    );

    assert_eq!(
        after,
        before + 1,
        "health request counter should increase by exactly one"
    );
}
