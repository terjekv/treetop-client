# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-04-04

Targets [treetop-rest v0.0.6](https://github.com/terjekv/treetop-rest/releases/tag/v0.0.6).

### Added

- Initial release of the Treetop client library.
- `Client` with builder pattern for configuration (timeouts, TLS, connection pooling, upload tokens).
- Typed request/response types wire-compatible with the Treetop REST API v0.0.6:
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
- Container-based integration test suite (`--features server-tests`) testing against a real treetop-rest v0.0.6 server.
- `StatusResponse.request_context` with runtime context support and fallback metadata.
- `VersionInfo.schema` for the optional loaded-schema version metadata returned by `/api/v1/version`.
- `SchemaDownload` for the `/api/v1/schema` response shape.
- `PolicyMatchReason` action variants for `v0.0.6` list-policies match metadata.
