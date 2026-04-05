# Examples

Extended usage examples for `treetop-client`.

## Table of contents

- [Client configuration](#client-configuration)
- [Authorization patterns](#authorization-patterns)
- [Policy management](#policy-management)
- [Error handling](#error-handling)
- [Correlation IDs and tracing](#correlation-ids-and-tracing)
- [Connection pool tuning](#connection-pool-tuning)
- [Custom TLS](#custom-tls)

## Client configuration

### Minimal setup

```rust
use treetop_client::Client;

let client = Client::builder("http://localhost:9999").build()?;
```

### Full configuration

```rust
use std::time::Duration;
use treetop_client::{Client, UploadToken};

let client = Client::builder("https://treetop.example.com")
    .connect_timeout(Duration::from_secs(3))
    .request_timeout(Duration::from_secs(15))
    .pool_idle_timeout(Duration::from_secs(120))
    .pool_max_idle_per_host(20)
    .upload_token(UploadToken::new("my-secret-token"))
    .correlation_id("service-startup")
    .build()?;
```

### Using an existing reqwest client

If you need configuration options not exposed by the builder (e.g. proxy settings,
custom redirect policies), construct a `reqwest::Client` yourself and pass it in:

```rust
use treetop_client::{Client, UploadToken};

let reqwest_client = reqwest::Client::builder()
    .proxy(reqwest::Proxy::all("http://proxy.internal:8080")?)
    .redirect(reqwest::redirect::Policy::none())
    .build()?;

let client = Client::builder("https://treetop.example.com")
    .with_reqwest_client(reqwest_client)
    .upload_token(UploadToken::new("token"))
    .build()?;
```

## Authorization patterns

### Single check with `is_allowed`

The simplest way to check authorization. Returns a boolean:

```rust
use treetop_client::{Action, Request, Resource, User};

let allowed = client
    .is_allowed(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Document", "quarterly-report"),
    ))
    .await?;

if allowed {
    // serve the document
} else {
    // return 403
}
```

### User with groups and namespace

```rust
use treetop_client::{Action, Group, Request, Resource, User};

let user = User::new("alice")
    .with_namespace(vec!["DNS".to_string()])
    .with_groups(vec![
        Group::new("admins").with_namespace(vec!["DNS".to_string()]),
        Group::new("operators"),
    ]);

let request = Request::new(
    user,
    Action::new("create_host").with_namespace(vec!["DNS".to_string()]),
    Resource::new("Host", "web-01.example.com"),
);

let allowed = client.is_allowed(request).await?;
```

### Resource with typed attributes

Attributes are used in Cedar policy conditions (e.g. `when { resource.ip.isInRange(ip("10.0.0.0/8")) }`):

```rust
use treetop_client::{Action, AttrValue, Request, Resource, User};

let resource = Resource::new("Host", "web-01.example.com")
    .with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()))
    .with_attr("name", AttrValue::String("web-01.example.com".to_string()))
    .with_attr("critical", AttrValue::Bool(true))
    .with_attr("priority", AttrValue::Long(1))
    .with_attr(
        "tags",
        AttrValue::Set(vec![
            AttrValue::String("production".to_string()),
            AttrValue::String("web".to_string()),
        ]),
    );

let allowed = client
    .is_allowed(Request::new(
        User::new("alice"),
        Action::new("delete"),
        resource,
    ))
    .await?;
```

### Batch authorization

Evaluate multiple requests in a single API call. All requests in the batch
are evaluated against the same policy snapshot:

```rust
use treetop_client::{Action, AuthorizeRequest, BatchResult, Request, Resource, User};

let batch = AuthorizeRequest::new()
    .add_request_with_id("alice-view", Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Document", "doc-1"),
    ))
    .add_request_with_id("bob-edit", Request::new(
        User::new("bob"),
        Action::new("edit"),
        Resource::new("Document", "doc-1"),
    ))
    .add_request_with_id("charlie-delete", Request::new(
        User::new("charlie"),
        Action::new("delete"),
        Resource::new("Document", "doc-1"),
    ));

let response = client.authorize(&batch).await?;

println!(
    "Policy version: {} (loaded at {})",
    response.version().hash,
    response.version().loaded_at
);
println!("Successful: {}, Failed: {}", response.successes(), response.failures());

// Iterate over results
for result in &response {
    let id = result.id.as_deref().unwrap_or("(no id)");
    match &result.result {
        BatchResult::Success { data } => {
            println!("[{}] {} -> {:?}", result.index, id, data.decision);
        }
        BatchResult::Failed { message } => {
            println!("[{}] {} -> ERROR: {}", result.index, id, message);
        }
    }
}

// Look up a specific result by ID
if let Some(result) = response.find_by_id("bob-edit") {
    println!("bob-edit was at index {}", result.index);
}
```

### Batch from an iterator

```rust
use treetop_client::{Action, AuthorizeRequest, Request, Resource, User};

let users = vec!["alice", "bob", "charlie"];
let requests: Vec<Request> = users
    .iter()
    .map(|name| {
        Request::new(
            User::new(*name),
            Action::new("view"),
            Resource::new("Dashboard", "main"),
        )
    })
    .collect();

let batch = AuthorizeRequest::from_requests(requests);
let response = client.authorize(&batch).await?;
```

### Detailed authorization

Get the full text and JSON of matching policies:

```rust
use treetop_client::{AuthorizeRequest, BatchResult, Request};

let response = client.authorize_detailed(&batch).await?;

for result in &response {
    if let BatchResult::Success { data } = &result.result {
        for policy in &data.policy {
            println!("Matched policy ({}): {}", policy.cedar_id, policy.literal);
            if let Some(annotation) = &policy.annotation_id {
                println!("  Annotation @id: {}", annotation);
            }
        }
    }
}
```

## Policy management

### Download policies

```rust
// As structured data (includes metadata)
let download = client.get_policies().await?;
println!("Policy hash: {}", download.policies.sha256);
println!("Entries: {}", download.policies.entries);
println!("Content:\n{}", download.policies.content);

// As raw Cedar DSL text
let cedar_dsl = client.get_policies_raw().await?;
println!("{cedar_dsl}");
```

### Upload policies

Uploading requires an upload token configured on both the client and the server.

```rust
use treetop_client::{Client, UploadToken};

let client = Client::builder("https://treetop.example.com")
    .upload_token(UploadToken::new("server-generated-token"))
    .build()?;

// Upload raw Cedar DSL
let cedar_dsl = r#"
permit(
    principal == User::"alice",
    action == Action::"view",
    resource
);
"#;
let metadata = client.upload_policies_raw(cedar_dsl).await?;
println!("Uploaded {} policies (hash: {})", metadata.policies.entries, metadata.policies.sha256);

// Upload as a JSON object that wraps the Cedar DSL string
let metadata = client.upload_policies_json(cedar_dsl).await?;
```

### List policies for a user

```rust
// With group and namespace filters
let policies = client
    .get_user_policies(
        "alice",
        &["admins".to_string(), "editors".to_string()],
        &["MyApp".to_string()],
    )
    .await?;

println!("Policies for {}: {}", policies.user, policies.policies.len());
for policy_json in &policies.policies {
    println!("{}", serde_json::to_string_pretty(policy_json)?);
}

// As raw Cedar DSL text
let raw = client
    .get_user_policies_raw("alice", &["admins".to_string()], &[])
    .await?;
println!("{raw}");
```

### Server info

```rust
// Version info
let version = client.version().await?;
println!("Server: {}", version.version);
println!("Core: {}", version.core.version);
println!("Cedar: {}", version.core.cedar);
println!("Policy hash: {}", version.policies.hash);

// Full status
let status = client.status().await?;
let pc = &status.policy_configuration;
println!("Upload allowed: {}", pc.allow_upload);
println!("Policies: {} entries, {} bytes", pc.policies.entries, pc.policies.size);
if let Some(source) = &pc.policies.source {
    println!("Source: {source}");
}
if let Some(freq) = pc.policies.refresh_frequency {
    println!("Refresh every {freq}s");
}

// Prometheus metrics
let metrics = client.metrics().await?;
println!("{metrics}");
```

## Error handling

### Matching on error variants

```rust
use treetop_client::TreetopError;

match client.authorize(&batch).await {
    Ok(response) => {
        println!("Got {} results", response.total());
    }
    Err(TreetopError::Transport(e)) => {
        // Network error: connection refused, DNS resolution failure, timeout, etc.
        eprintln!("Cannot reach server: {e}");
    }
    Err(TreetopError::Api { status, message }) => {
        // Server returned an HTTP error (400, 403, 500, etc.)
        eprintln!("Server error (HTTP {status}): {message}");
        match status.as_u16() {
            400 => eprintln!("Bad request -- check your payload"),
            403 => eprintln!("Forbidden -- check your upload token"),
            500 => eprintln!("Internal server error"),
            _ => {}
        }
    }
    Err(TreetopError::Deserialization(e)) => {
        // Response body didn't match the expected type
        eprintln!("Unexpected response format: {e}");
    }
    Err(TreetopError::Configuration(msg)) => {
        // Client misconfiguration (e.g. missing upload token)
        eprintln!("Configuration error: {msg}");
    }
    Err(e) => {
        eprintln!("Other error: {e}");
    }
}
```

### Upload without a token

Calling `upload_policies_raw` or `upload_policies_json` without a configured
upload token returns `TreetopError::Configuration` immediately, without making
a network request:

```rust
let client = Client::builder("http://localhost:9999").build()?;

match client.upload_policies_raw("permit(principal, action, resource);").await {
    Err(TreetopError::Configuration(msg)) => {
        assert!(msg.contains("no upload token"));
    }
    _ => unreachable!(),
}
```

### Health check with retry

```rust
use std::time::Duration;

async fn wait_for_server(client: &treetop_client::Client) -> treetop_client::Result<()> {
    for attempt in 1..=10 {
        match client.health().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("Health check attempt {attempt}/10 failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    client.health().await
}
```

## Correlation IDs and tracing

Correlation IDs are managed via the clone-with-override pattern. The cloned
client shares the same underlying connection pool, so there is no overhead:

```rust
use treetop_client::Client;

let client = Client::builder("https://treetop.example.com").build()?;

// Per-request correlation -- useful in HTTP handlers
async fn handle_request(client: &Client, request_id: &str) -> treetop_client::Result<bool> {
    let traced = client.with_correlation_id(request_id);
    // All calls through `traced` send x-correlation-id: <request_id>
    traced.is_allowed(/* ... */).await
}

// Default correlation ID set at build time
let client = Client::builder("https://treetop.example.com")
    .correlation_id("my-service-instance-1")
    .build()?;
// All calls include x-correlation-id: my-service-instance-1

// Override for a specific request
let traced = client.with_correlation_id("specific-request-123");
// This call sends x-correlation-id: specific-request-123
traced.health().await?;

// The original client still sends x-correlation-id: my-service-instance-1
client.health().await?;

// Remove correlation ID entirely
let untraced = client.without_correlation_id();
// This call sends no x-correlation-id header
untraced.health().await?;
```

## Connection pool tuning

The client uses reqwest's built-in connection pool (backed by hyper). Key settings:

```rust
use std::time::Duration;

let client = Client::builder("https://treetop.example.com")
    // How long idle connections stay in the pool (default: 90s)
    .pool_idle_timeout(Duration::from_secs(120))
    // Max idle connections per host (default: reqwest/hyper default)
    .pool_max_idle_per_host(32)
    // TCP connection timeout (default: 5s)
    .connect_timeout(Duration::from_secs(3))
    // Overall request timeout including response body (default: 30s)
    .request_timeout(Duration::from_secs(10))
    .build()?;
```

**Important:** Always reuse the same `Client` instance. Each `Client::builder().build()`
creates a new, independent connection pool. Cloning via `with_correlation_id()` or
`without_correlation_id()` shares the same pool.

## Custom TLS

### Private CA certificate

When connecting to a Treetop server behind a private CA:

```rust
let ca_cert = std::fs::read("ca.pem")?;
let cert = reqwest::Certificate::from_pem(&ca_cert)?;

let client = Client::builder("https://treetop.internal")
    .add_root_certificate(cert)
    .build()?;
```

### Multiple CA certificates

```rust
let certs = vec!["ca1.pem", "ca2.pem"];

let mut builder = Client::builder("https://treetop.internal");
for path in certs {
    let pem = std::fs::read(path)?;
    builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
}
let client = builder.build()?;
```

### Disabling certificate validation (development only)

```rust
let client = Client::builder("https://localhost:9999")
    .danger_accept_invalid_certs(true)
    .build()?;
```

**Warning:** Never use `danger_accept_invalid_certs(true)` in production. It
disables all TLS certificate validation, making the connection vulnerable to
man-in-the-middle attacks.
