# treetop-client

A Rust client library for [Treetop](https://github.com/terjekv/treetop-rest) policy authorization servers.

Treetop is a Cedar-based policy evaluation service. This client provides a typed, async API for evaluating authorization requests, managing policies, and querying server status.

## Compatibility

`treetop-client` is pre-1.0; API compatibility is not guaranteed between `0.0.x` releases.

This version targets [treetop-rest v0.0.10](https://github.com/terjekv/treetop-rest/releases/tag/v0.0.10).
CI verifies the stable health, version, policy, and authorization contract against v0.0.4 through
v0.0.11; v0.0.10 receives the complete endpoint suite. Newer response fields use
`#[serde(default)]` for backward compatibility.

## Features

- **Type-driven design** -- strongly typed request/response types with serde, wire-compatible with the Treetop REST API
- **Capability-safe uploads** -- upload methods exist only on `Client<CanUpload>` values built with a validated token
- **Connection pooling** -- built on reqwest with configurable pool sizes and idle timeouts
- **Secure token handling** -- upload tokens backed by `SecretString` (zeroized on drop, redacted in Debug output)
- **Validated construction** -- fallible constructors preserve Cedar, entity, attribute, context, and header invariants
- **TLS by default** -- uses rustls without an OpenSSL/system-TLS dependency, with optional custom root certificates
- **Bounded I/O** -- request and successful-response bodies are capped at 16 MiB by default, with configurable limits
- **Fluent endpoint calls** -- typed detail and output transitions for authorization and user-policy queries
- **Batch authorization** -- evaluate multiple authorization requests in a single API call
- **Correlation IDs** -- clone-with-override pattern for request tracing without shared mutable state
- **Schema management** -- download and upload Cedar schema data alongside policies
- **Operational endpoints** -- typed liveness/readiness checks and access to the generated OpenAPI document

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
treetop-client = "0.0.2"
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
            User::new("alice")?,
            Action::new("view")?,
            Resource::new("Document", "doc-42")?,
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
use treetop_client::{Client, RequestLimits, UploadToken};

let client = Client::builder("https://treetop.example.com")
    .connect_timeout(Duration::from_secs(5))
    .request_timeout(Duration::from_secs(30))
    .pool_idle_timeout(Duration::from_secs(90))
    .pool_max_idle_per_host(10)
    .max_request_bytes(16 * 1024 * 1024)
    .max_response_bytes(16 * 1024 * 1024)
    .request_limits(RequestLimits::default())
    .upload_token(UploadToken::new("my-secret-token")?)
    .build()?;
```

Without `.upload_token(...)`, `build()` returns `Client<ReadOnly>` and upload methods are not
available. Adding the token transitions the builder and resulting client to `CanUpload`; read and
authorization methods remain available in both states.

Upload tokens require HTTPS unless the destination is loopback. For an explicitly accepted
plaintext development server, opt in with `.danger_allow_insecure_uploads(true)`. The default
HTTP client also rejects redirects so a token cannot be forwarded to a redirect target. A custom
reqwest client bypasses that redirect policy, so configure its policy deliberately.

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
let traced = client.with_correlation_id("req-abc-123")?;
traced.authorize(&request).await?;  // sends x-correlation-id header

// Original client is unaffected
client.authorize(&request).await?;  // no correlation header

// Fluent endpoint calls can override correlation without cloning the client
client
    .authorization(&request)
    .correlation_id("req-def-456")?
    .send()
    .await?;
```

### Authorization

Request fields are private and exposed through read-only accessors. Constructors and fluent
setters validate before returning a value, while batch- and server-dependent invariants are checked
before transport. Duplicate request IDs are rejected, and response IDs, indices, ordering, counts,
policy versions, and decisions are checked against the submitted batch. `AttrValue::ip()` always
validates its IP/CIDR value.

#### Single check

```rust
use treetop_client::{Action, Request, Resource, User};

let allowed = client
    .is_allowed(Request::new(
        User::new("alice")?.with_group_names(&["admins"])?,
        Action::new("delete")?,
        Resource::new("Host", "web-01")?,
    ))
    .await?;
```

#### Batch authorization

```rust
use treetop_client::{Action, AttrValue, AuthorizeRequest, Request, Resource, User};

let batch = AuthorizeRequest::new()
    .add_request(Request::new(
        User::new("alice")?,
        Action::new("view")?,
        Resource::new("Document", "doc-1")?,
    ))
    .add_request_with_id("check-2", Request::new(
        User::new("bob")?,
        Action::new("edit")?,
        Resource::new("Document", "doc-1")?
            .with_attr("owner", AttrValue::String("alice".to_string()))?,
    ))?;

let response = client.authorization(&batch).send().await?;

println!("Successful: {}, Failed: {}", response.successes(), response.failures());

// Look up a result by client-provided ID
if let Some(result) = response.find_by_id("check-2") {
    println!("check-2 index: {}", result.index);
}
```

#### Detailed authorization (includes matching policies)

```rust
let response = client.authorization(&batch).detailed().send().await?;
```

### Resources with attributes

```rust
use treetop_client::{AttrValue, Resource};

let resource = Resource::new("Host", "web-01.example.com")?
    .with_attr("ip", AttrValue::ip("10.0.0.1")?)?
    .with_attr("environment", AttrValue::String("production".to_string()))?
    .with_attr("critical", AttrValue::Bool(true))?
    .with_attr("priority", AttrValue::Long(1))?;
```

### Namespaced types

Users, groups, and actions support Cedar namespaces:

```rust
use treetop_client::{Action, Group, User};

let user = User::new("alice")?
    .with_namespace(vec!["MyApp".to_string()])?
    .with_group_names(&["admins", "editors"])?;

let action = Action::new("delete")?
    .with_namespace(vec!["Admin".to_string()])?;

let group = Group::new("superusers")?
    .with_namespace(vec!["MyApp".to_string()])?;
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
    .user_policies("alice")?
    .group("admins")?
    .namespace("MyApp")?
    .send()
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
if let Some(source) = &status.policy_configuration.policies.source {
    println!("Policy source: {}", source.as_str());
}
```

The canonical operational probes and generated OpenAPI document are available directly:

```rust
client.livez().await?;
if client.readyz().await? {
    println!("Server is ready");
}

let openapi = client.openapi().await?;
println!("OpenAPI version: {}", openapi["openapi"]);
```

### Request context

Request-scoped context is serialized on the wire via `AuthRequest.context` and evaluated by
`treetop-rest v0.0.10`. The client automatically enforces `RequestLimits::default()` before
transport; configure limits reported by a differently configured server with
`ClientBuilder::request_limits()`.

```rust
use std::collections::HashMap;
use treetop_client::{Action, AttrValue, AuthRequest, AuthorizeRequest, Request, Resource, User};

let mut context = HashMap::new();
context.insert("env".to_string(), AttrValue::String("prod".to_string()));

let request = AuthRequest::new(Request::new(
    User::new("alice")?,
    Action::new("view")?,
    Resource::new("Photo", "VacationPhoto94.jpg")?,
))
    .with_context(context)?;
let batch = AuthorizeRequest::from_auth_requests([request])?;

let response = client.authorization(&batch).send().await?;
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

## Releasing

Stable tags drive the crates.io and GitHub release workflow. See
[RELEASING.md](RELEASING.md) for the release process.
