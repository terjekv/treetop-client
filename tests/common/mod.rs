#![cfg(feature = "server-tests")]
#![allow(dead_code)]

use std::process::Command;
use std::time::Duration;

use regex::Regex;
use tokio::sync::OnceCell;
use treetop_client::{
    Action, AuthorizeBriefResponse, BatchResult, Client, DecisionBrief, Group, Request, Resource,
    UploadToken, User,
};

// ==========================================================================
// Container image
// ==========================================================================

const IMAGE: &str = "ghcr.io/terjekv/treetop-rest:v0.0.6";
const CONTAINER_PREFIX: &str = "treetop-test-";
const TEST_LABEL_KEY: &str = "treetop-client.test";
const TEST_LABEL_VALUE: &str = "true";

// ==========================================================================
// Test policies
// ==========================================================================

pub const SIMPLE_POLICIES: &str = r#"
permit (
    principal == User::"alice",
    action in [Action::"view", Action::"edit", Action::"delete"],
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal,
    action == Action::"delete",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"alice",
    action == Action::"only_here",
    resource
);
"#;

pub const DNS_POLICIES: &str = r#"
@id("DNS.admins_policy")
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"create_host",
         DNS::Action::"delete_host",
         DNS::Action::"view_host",
         DNS::Action::"edit_host"],
    resource is Host
);

@id("DNS.users_policy")
permit (
    principal in DNS::Group::"users",
    action == DNS::Action::"view_host",
    resource is Host
);

@id("DNS.charlie_forbid_delete_host_policy")
forbid (
    principal == DNS::User::"charlie",
    action == DNS::Action::"delete_host",
    resource is Host
);

@id("global.super_admin_allow_all_policy")
permit (
    principal == User::"super",
    action,
    resource
);
"#;

pub const INVALID_CEDAR: &str = "permit(this is not valid cedar syntax";

pub const CONTEXT_POLICY: &str = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
) when {
    context.env == "prod"
};
"#;

pub const CONTEXT_SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "User": {},
      "Photo": {}
    },
    "actions": {
      "view": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Photo"],
          "context": {
            "type": "Record",
            "attributes": {
              "env": {
                "type": "String",
                "required": true
              }
            },
            "additionalAttributes": false
          }
        }
      }
    }
  }
}"#;

/// All test policies combined.
pub fn all_policies() -> String {
    format!("{}\n{}", SIMPLE_POLICIES, DNS_POLICIES)
}

// ==========================================================================
// TestServer
// ==========================================================================

pub struct TestServer {
    pub container_id: String,
    pub base_url: String,
    pub upload_token: String,
}

impl TestServer {
    /// Builds a Client without upload token (for read-only operations).
    pub fn client(&self) -> Client {
        Client::builder(&self.base_url).build().unwrap()
    }

    /// Builds a Client with the correct upload token.
    pub fn client_with_token(&self) -> Client {
        Client::builder(&self.base_url)
            .upload_token(UploadToken::new(&self.upload_token))
            .build()
            .unwrap()
    }

    /// Builds a Client with a wrong token (for testing 403 errors).
    pub fn client_with_wrong_token(&self) -> Client {
        Client::builder(&self.base_url)
            .upload_token(UploadToken::new("wrong-token-value"))
            .build()
            .unwrap()
    }

    async fn start() -> Self {
        // Only clean up stopped containers from previous runs. Each integration-test
        // binary has its own process and may start its own container concurrently.
        cleanup_stale_containers();

        let container_name = format!(
            "{}{}-{}",
            CONTAINER_PREFIX,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let label = format!("{TEST_LABEL_KEY}={TEST_LABEL_VALUE}");

        // Start container
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &container_name,
                "--label",
                &label,
                "-e",
                "TREETOP_LISTEN=0.0.0.0",
                "-e",
                "TREETOP_CLIENT_ALLOWLIST=*",
                "-e",
                "TREETOP_ALLOW_UPLOAD=true",
                "-e",
                "RUST_LOG=warn",
                "-p",
                "0:9999",
                IMAGE,
            ])
            .output()
            .expect("failed to start docker container -- is Docker running?");

        let container_id = String::from_utf8(output.stdout)
            .expect("invalid container ID")
            .trim()
            .to_string();

        assert!(
            !container_id.is_empty(),
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Get assigned port
        let port_output = Command::new("docker")
            .args(["port", &container_id, "9999"])
            .output()
            .expect("failed to get container port");

        let port_str = String::from_utf8(port_output.stdout).unwrap();
        let port = port_str
            .trim()
            .rsplit(':')
            .next()
            .expect("failed to parse port from docker port output");
        let base_url = format!("http://localhost:{}", port);

        // Extract upload token from logs (retry since logs may take a moment)
        let token = extract_token(&container_id);

        let server = TestServer {
            container_id,
            base_url,
            upload_token: token,
        };

        // Wait for health check
        server.wait_for_healthy().await;

        server
    }

    async fn wait_for_healthy(&self) {
        let client = Client::builder(&self.base_url)
            .connect_timeout(Duration::from_secs(10))
            .request_timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        for attempt in 1..=120 {
            match client.health().await {
                Ok(()) => return,
                Err(_) if attempt < 120 => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => panic!(
                    "server did not become healthy after 60s (container {}): {e}",
                    self.container_id
                ),
            }
        }
    }
}

fn cleanup_stale_containers() {
    for status in ["created", "exited", "dead"] {
        let output = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                &format!("label={TEST_LABEL_KEY}={TEST_LABEL_VALUE}"),
                "--filter",
                &format!("status={status}"),
                "--format",
                "{{.ID}}",
            ])
            .output();

        if let Ok(output) = output {
            let ids = String::from_utf8_lossy(&output.stdout);
            for id in ids.lines().filter(|l| !l.is_empty()) {
                let _ = Command::new("docker").args(["rm", "-f", id]).output();
            }
        }
    }
}

fn extract_token(container_id: &str) -> String {
    let re = Regex::new(r#""token"\s*:\s*"([^"]+)""#).unwrap();

    for _ in 0..30 {
        let output = Command::new("docker")
            .args(["logs", container_id])
            .output()
            .expect("failed to get docker logs");

        let logs = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}{}", logs, stderr);

        if let Some(caps) = re.captures(&combined) {
            return caps[1].to_string();
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    panic!(
        "failed to extract upload token from container {} logs after 15s",
        container_id
    );
}

// ==========================================================================
// Global singleton
// ==========================================================================

static TEST_SERVER: OnceCell<TestServer> = OnceCell::const_new();

/// Returns a reference to the shared test server.
/// Starts the container on first call, reuses it for all subsequent calls.
pub async fn server() -> &'static TestServer {
    TEST_SERVER
        .get_or_init(|| async { TestServer::start().await })
        .await
}

// ==========================================================================
// Policy upload (once)
// ==========================================================================

static POLICIES_UPLOADED: OnceCell<()> = OnceCell::const_new();

/// Ensures the standard test policies are uploaded to the server.
/// Idempotent -- only uploads on the first call.
pub async fn ensure_policies(server: &TestServer) {
    POLICIES_UPLOADED
        .get_or_init(|| async {
            let client = server.client_with_token();
            client
                .upload_policies_raw(&all_policies())
                .await
                .expect("failed to upload test policies");
        })
        .await;
}

/// Restores the standard test policies. Call this after tests that modify policies.
pub async fn restore_policies(server: &TestServer) {
    let client = server.client_with_token();
    client
        .upload_policies_raw(&all_policies())
        .await
        .expect("failed to restore test policies");
}

// ==========================================================================
// Request builders
// ==========================================================================

pub fn alice_view_photo() -> Request {
    Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Photo", "VacationPhoto94.jpg"),
    )
}

pub fn bob_view_photo() -> Request {
    Request::new(
        User::new("bob"),
        Action::new("view"),
        Resource::new("Photo", "VacationPhoto94.jpg"),
    )
}

pub fn super_any() -> Request {
    Request::new(
        User::new("super"),
        Action::new("anything"),
        Resource::new("Whatever", "something"),
    )
}

pub fn dns_user(name: &str, groups: &[&str]) -> User {
    User::new(name)
        .with_namespace(vec!["DNS".to_string()])
        .with_groups(
            groups
                .iter()
                .map(|g| Group::new(*g).with_namespace(vec!["DNS".to_string()]))
                .collect(),
        )
}

pub fn dns_action(name: &str) -> Action {
    Action::new(name).with_namespace(vec!["DNS".to_string()])
}

// ==========================================================================
// Assertion helpers
// ==========================================================================

/// Extracts the decision from the first result in a brief response, panicking on failure.
pub fn extract_decision(resp: &AuthorizeBriefResponse) -> DecisionBrief {
    match &resp.results()[0].result {
        BatchResult::Success { data } => data.decision,
        BatchResult::Failed { message } => panic!("expected success, got failure: {message}"),
    }
}
