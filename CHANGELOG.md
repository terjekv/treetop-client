# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `PolicyVersion` now retains nullable `label_set` and unsigned
  `generation` metadata. Add `label_set: None, generation: 0` to existing struct
  literals. Responses from older servers default missing fields to those values;
  serialization includes both fields.
- Brief and detailed batch validation compares every version field and rejects
  results that differ only in label configuration or engine generation.

## [0.0.3] - 2026-08-14

Targets
[treetop-rest v0.0.12](https://github.com/treetop-policy-engine/treetop-rest/releases/tag/v0.0.12).

### Changed

- Move the canonical source repository to the `treetop-policy-engine` GitHub organization and use
  organization-owned server images for compatibility testing. The crate name and API are unchanged.
- Extend the stable treetop-rest compatibility matrix through v0.0.12 and run the complete client
  suite against v0.0.12 by default.
- Refresh Rust dependencies to the latest releases compatible with Rust 1.85, including rstest
  v0.26.1, and update pinned GitHub Actions to their latest stable revisions.

## [0.0.2] - 2026-08-13

Targets
[treetop-rest v0.0.10](https://github.com/treetop-policy-engine/treetop-rest/releases/tag/v0.0.10).

### Added

- Add configurable 16 MiB request-body limits and automatic per-request context-limit enforcement.
- Add `MetadataSource`, a validated crate-owned representation of the server's source endpoint.
- Add `ReadOnly` and `CanUpload` client capability states. Upload methods are available only on a
  `Client<CanUpload>` produced by adding a validated upload token to `ClientBuilder`.
- Add `Client::authorization()` with typed brief and detailed call states, including per-call
  correlation IDs.
- Add `Client::user_policies()` with fluent group and namespace filters and typed structured/raw
  response states.
- Add `Client::livez()`, `Client::readyz()`, and `Client::openapi()` for the canonical operational
  probes and generated OpenAPI document introduced by treetop-rest v0.0.10.
- Expose the server-reported optional `RequestLimits::max_batch_size` field.

### Changed

- **Breaking:** `User::new`, `Group::new`, `Action::new`, `Resource::new`, and `UploadToken::new`
  now return `Result` and reject invalid values immediately. Their fluent namespace, group-name,
  attribute, request-ID, and context setters are now fallible for the same reason. Replace delayed
  `validate()` calls with `?` at construction and setter call sites.
- **Breaking:** `ClientBuilder::upload_token` now transitions the builder from `ReadOnly` to
  `CanUpload`; code that stores an upload-capable client with an explicit type must use
  `Client<CanUpload>`. Calling uploads on a client built without a token no longer produces a
  runtime configuration error because those methods are absent at compile time.
- **Breaking:** `ClientBuilder::danger_allow_insecure_uploads` is now available only after
  `upload_token`; move the insecure-upload opt-in after `.upload_token(...)` in existing builder
  chains.
- **Breaking:** `AuthRequest::with_id` is now a fluent setter used as
  `AuthRequest::new(request).with_id(id)?`. `AuthorizeRequest::from_auth_requests` and
  `add_request_with_id` now return `Result` and reject duplicate request IDs during construction.
- Validate resource attribute keys, request-context keys, and batch request-ID uniqueness during
  deserialization so serde cannot bypass public constructor invariants.
- Require GitHub-verified signed annotated release tags before publishing.
- **Breaking:** Change `Metadata.source` from `Option<String>` to `Option<MetadataSource>` to match
  the v0.0.7 `{ "url": "..." }` wire shape. Use `source.as_str()` to migrate string access.
- Authorization now rejects duplicate request IDs and verifies response ordering, IDs, counts,
  policy versions, and allow/deny policy consistency before returning results.
- Successful plain-text endpoints now reject invalid UTF-8 instead of replacing invalid bytes.
- User-policy endpoint parameters are validated before transport, and path spaces are encoded as
  `%20` rather than form-style `+`.
- Target treetop-rest v0.0.10 for the full integration suite and extend stable compatibility
  coverage through v0.0.10.

### Fixed

- Deserialize the current object-shaped policy metadata source while retaining compatibility with
  legacy bare-string snapshots.
- Treat a missing pre-v0.0.7 `request_context` field as unsupported instead of reporting support.
- Drain and bound successful health bodies, cap initial response allocations, and stream request
  serialization into bounded buffers.

### Security

- Redact configured upload tokens if a server reflects one in an API error response.
- Pin every third-party GitHub Action to a full commit SHA, pin installed audit/fuzz tool versions,
  and limit the first-release crates.io bootstrap secret to the steps that require it.

## [0.0.1] - 2026-08-10

Targets
[treetop-rest v0.0.7](https://github.com/treetop-policy-engine/treetop-rest/releases/tag/v0.0.7).

### Added

- Initial release of the Treetop client library.
- `Client` with builder pattern for configuration (timeouts, TLS, connection pooling, upload tokens).
- Typed request/response types wire-compatible with the Treetop REST API v0.0.7:
  - `User`, `Group`, `Principal` with namespace support.
  - `Action` with namespace support.
  - `Resource` with typed attributes (`AttrValue`: String, Bool, Long, Ip, Set).
  - `Request`, `AuthRequest`, `AuthorizeRequest` with fluent builder API.
  - `AuthRequest` with optional `context` for request-scoped Cedar context values.
  - `AuthorizeBriefResponse` and `AuthorizeDetailedResponse` for authorization results.
  - `StatusResponse`, `VersionInfo`, `PoliciesMetadata`, `Metadata`, `RequestLimits` for server status.
  - `PermitPolicy`, `PoliciesDownload`, `UserPolicies` for policy management.
  - `PolicyMatch`, `PolicyMatchReason` for policy match metadata.
  - `BatchResult`, `IndexedResult` for batch evaluation results.
- Client endpoint methods:
  - `health()` -- server liveness check.
  - `version()` -- server and Cedar version info.
  - `status()` -- server status with policy, parallelism, and request limit configuration.
  - `authorize()` -- batch authorization with brief results.
  - `authorize_detailed()` -- batch authorization with full policy details.
  - `is_allowed()` -- single-request convenience returning a boolean.
  - `get_policies()` / `get_policies_raw()` -- download loaded policies.
  - `upload_policies_raw()` / `upload_policies_json()` -- upload new policies.
  - `get_schema()` / `get_schema_raw()` -- download the loaded Cedar schema.
  - `upload_schema_raw()` / `upload_schema_json()` -- upload a Cedar schema.
  - `get_user_policies()` / `get_user_policies_raw()` -- list policies for a user.
  - `metrics()` -- fetch Prometheus metrics.
- `UploadToken` with `SecretString` backing (zeroized on drop, redacted in Debug).
- `TreetopError` with variants for transport, API, deserialization, URL, and configuration errors.
- Correlation ID support via clone-with-override pattern (`with_correlation_id` / `without_correlation_id`).
- rustls-tls for pure-Rust TLS without OpenSSL dependency.
- Container-based integration test suite (`--features server-tests`) testing against a real treetop-rest v0.0.7 server.
- `StatusResponse.request_context` with runtime context support and fallback metadata.
- `VersionInfo.schema` for the optional loaded-schema version metadata returned by `/api/v1/version`.
- `SchemaDownload` for the `/api/v1/schema` response shape.
- `PolicyMatchReason` action variants for `v0.0.7` list-policies match metadata.
- Private request-domain fields with read-only accessors and local validation before transport.
- Validated Cedar identifier, entity ID, request ID, and IP/CIDR newtypes.
- Configurable successful-response limit (16 MiB by default) and a 64 KiB error-body limit.
- Base URL and HTTP header validation, redirect denial on the default client, and protection
  against sending upload tokens over non-loopback plaintext HTTP.
- Structural validation for authorization response counts and indices.
- Forward-compatible unknown variants for policy-match and request-context fallback reasons.
- RustSec, cargo-deny, and license-policy CI gates.
- Property tests and cargo-fuzz targets for deserialization, URLs, nested context, and response
  consistency.
- A treetop-rest v0.0.4 through v0.0.7 compatibility matrix and automatic test-container cleanup.
- Tag-driven crates.io and GitHub release automation, including first-release token bootstrap and
  subsequent OIDC trusted publishing.

[Unreleased]: https://github.com/treetop-policy-engine/treetop-client/compare/v0.0.3...HEAD
[0.0.3]: https://github.com/treetop-policy-engine/treetop-client/releases/tag/v0.0.3
[0.0.2]: https://github.com/treetop-policy-engine/treetop-client/releases/tag/v0.0.2
[0.0.1]: https://github.com/treetop-policy-engine/treetop-client/releases/tag/v0.0.1
