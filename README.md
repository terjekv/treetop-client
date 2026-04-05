# treetop-client

A Rust client library for [Treetop](https://github.com/terjekv/treetop-rest) policy authorization servers.

Treetop is a Cedar-based policy evaluation service. This client provides a typed, async API for evaluating authorization requests, managing policies, and querying server status.

## Compatibility

This version targets [treetop-rest v0.0.6](https://github.com/terjekv/treetop-rest/releases/tag/v0.0.6). Types are backward-compatible with v0.0.4+ servers where newer fields use `#[serde(default)]`.

## Features

- **Type-driven design** -- strongly typed request/response types with serde, wire-compatible with the Treetop REST API
- **Connection pooling** -- built on reqwest with configurable pool sizes and idle timeouts
- **Secure token handling** -- upload tokens backed by `SecretString` (zeroized on drop, redacted in Debug output)
- **TLS by default** -- uses rustls (pure-Rust TLS, no OpenSSL dependency) with optional custom root certificates
- **Builder patterns** -- ergonomic builders for client configuration, authorization requests, users, resources, and actions
- **Batch authorization** -- evaluate multiple authorization requests in a single API call
- **Correlation IDs** -- clone-with-override pattern for request tracing without shared mutable state
- **Schema management** -- download and upload Cedar schema data alongside policies

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
treetop-client = "0.0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust
use treetop_client::{
    Action, AuthorizeRequest, Client, Request, Resource, User,
};

#[tokio::main]
async fn main() -> treetop_client::Result<()> {
    // Create a client
    let client = Client::builder("https://treetop.example.com").build()?;

    // Check server health
    client.health().await?;

    // Simple authorization check
    let allowed = client
        .is_allowed(Request::new(
            User::new("alice"),
            Action::new("view"),
            Resource::new("Document", "doc-42"),
        ))
        .await?;

    println!("Allowed: {allowed}");
    Ok(())
}
```

## Usage

### Client configuration

```rust
use std::time::Duration;
use treetop_client::{Client, UploadToken};

let client = Client::builder("https://treetop.example.com")
    .connect_timeout(Duration::from_secs(5))
    .request_timeout(Duration::from_secs(30))
    .pool_idle_timeout(Duration::from_secs(90))
    .pool_max_idle_per_host(10)
    .upload_token(UploadToken::new("my-secret-token"))
    .build()?;
```

For custom TLS configuration:

```rust
use treetop_client::Client;

let client = Client::builder("https://treetop.internal")
    .add_root_certificate(my_ca_cert)
    .build()?;
```

Or bring your own pre-configured reqwest client:

```rust
let client = Client::builder("https://treetop.example.com")
    .with_reqwest_client(my_reqwest_client)
    .build()?;
```

### Correlation IDs

Correlation IDs are managed via a clone-with-override pattern. The cloned client shares the same connection pool:

```rust
let traced = client.with_correlation_id("req-abc-123");
traced.authorize(&request).await?;  // sends x-correlation-id header

// Original client is unaffected
client.authorize(&request).await?;  // no correlation header
```

### Authorization

#### Single check

```rust
use treetop_client::{Action, Request, Resource, User};

let allowed = client
    .is_allowed(Request::new(
        User::new("alice").with_group_names(&["admins"]),
        Action::new("delete"),
        Resource::new("Host", "web-01"),
    ))
    .await?;
```

#### Batch authorization

```rust
use treetop_client::{Action, AttrValue, AuthorizeRequest, Request, Resource, User};

let batch = AuthorizeRequest::new()
    .add_request(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Document", "doc-1"),
    ))
    .add_request_with_id("check-2", Request::new(
        User::new("bob"),
        Action::new("edit"),
        Resource::new("Document", "doc-1")
            .with_attr("owner", AttrValue::String("alice".to_string())),
    ));

let response = client.authorize(&batch).await?;

println!("Successful: {}, Failed: {}", response.successes(), response.failures());

// Look up a result by client-provided ID
if let Some(result) = response.find_by_id("check-2") {
    println!("check-2 index: {}", result.index);
}
```

#### Detailed authorization (includes matching policies)

```rust
let response = client.authorize_detailed(&batch).await?;
```

### Resources with attributes

```rust
use treetop_client::{AttrValue, Resource};

let resource = Resource::new("Host", "web-01.example.com")
    .with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()))
    .with_attr("environment", AttrValue::String("production".to_string()))
    .with_attr("critical", AttrValue::Bool(true))
    .with_attr("priority", AttrValue::Long(1));
```

### Namespaced types

Users, groups, and actions support Cedar namespaces:

```rust
use treetop_client::{Action, Group, User};

let user = User::new("alice")
    .with_namespace(vec!["MyApp".to_string()])
    .with_group_names(&["admins", "editors"]);

let action = Action::new("delete")
    .with_namespace(vec!["Admin".to_string()]);

let group = Group::new("superusers")
    .with_namespace(vec!["MyApp".to_string()]);
```

### Policy management

```rust
// Download policies as structured data
let download = client.get_policies().await?;

// Download policies as raw Cedar DSL
let cedar_text = client.get_policies_raw().await?;

// Upload policies (requires upload token)
let metadata = client
    .upload_policies_raw("permit(principal, action, resource);")
    .await?;

// List policies for a specific user
let user_policies = client
    .get_user_policies("alice", &["admins".into()], &["MyApp".into()])
    .await?;
```

### Schema management

```rust
// Download schema as structured metadata
let schema = client.get_schema().await?;

// Download schema as raw Cedar schema JSON
let raw_schema = client.get_schema_raw().await?;

// Upload schema (requires upload token)
let metadata = client
    .upload_schema_raw(r#"{"": {"entityTypes": {}, "actions": {}}}"#)
    .await?;
```

### Server status

```rust
let version = client.version().await?;
println!("Server: {}, Cedar: {}", version.version, version.core.cedar);

let status = client.status().await?;
println!("Policies loaded: {}", status.policy_configuration.policies.entries);
println!("Context supported: {}", status.request_context.supported);
```

### Request context

Request-scoped context is serialized on the wire via `AuthRequest.context` and evaluated by `treetop-rest v0.0.6`.

```rust
use std::collections::HashMap;
use treetop_client::{Action, AttrValue, AuthRequest, AuthorizeRequest, Request, Resource, User};

let mut context = HashMap::new();
context.insert("env".to_string(), AttrValue::String("prod".to_string()));

let batch = AuthorizeRequest {
    requests: vec![AuthRequest::new(Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Photo", "VacationPhoto94.jpg"),
    ))
    .with_context(context)],
};

let response = client.authorize(&batch).await?;
```

Inspect `status.request_context` if you need to know whether the server runtime is currently schema-backed or running in permissive fallback mode. Uploading a schema via `upload_schema_raw()` or `upload_schema_json()` lets you verify the schema-backed path explicitly.

### Prometheus metrics

```rust
let metrics_text = client.metrics().await?;
```

## Error handling

All methods return `treetop_client::Result<T>`, which uses `TreetopError`:

```rust
use treetop_client::TreetopError;

match client.health().await {
    Ok(()) => println!("Server is healthy"),
    Err(TreetopError::Transport(e)) => println!("Network error: {e}"),
    Err(TreetopError::Api { status, message }) => {
        println!("Server returned HTTP {status}: {message}");
    }
    Err(e) => println!("Other error: {e}"),
}
```

## License

MIT
