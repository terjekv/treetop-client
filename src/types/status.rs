//! Server status and metadata types.

use serde::{Deserialize, Serialize};

/// Metadata about a loaded data set (policies, labels, or schema) in the Treetop server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    /// ISO 8601 timestamp of when this data was loaded.
    pub timestamp: String,
    /// SHA-256 hash of the content.
    pub sha256: String,
    /// Size of the content in bytes.
    pub size: usize,
    /// The URL this data was fetched from, if loaded from a remote source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// How often the data is refreshed from the source, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_frequency: Option<u32>,
    /// The number of entries (e.g. policy rules or labels).
    pub entries: usize,
    /// The full raw content string.
    pub content: String,
}

/// Metadata about policies, labels, and schema in the Treetop server's policy store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoliciesMetadata {
    /// Whether the server allows policy uploads.
    pub allow_upload: bool,
    /// The Cedar schema validation mode (e.g. `"permissive"` or `"strict"`).
    #[serde(default)]
    pub schema_validation_mode: String,
    /// Metadata about the currently loaded policies.
    pub policies: Metadata,
    /// Metadata about the currently loaded labels.
    pub labels: Metadata,
    /// Metadata about the currently loaded Cedar schema, if any.
    #[serde(default)]
    pub schema: Option<Metadata>,
}

/// Server-enforced limits on authorization request context values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestLimits {
    /// Maximum total size in bytes for context values in a single request.
    pub max_context_bytes: usize,
    /// Maximum nesting depth for context values.
    pub max_context_depth: usize,
    /// Maximum number of keys in a context map.
    pub max_context_keys: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_context_bytes: 16 * 1024,
            max_context_depth: 8,
            max_context_keys: 64,
        }
    }
}

/// Why request context evaluation is currently not schema-backed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RequestContextFallbackReason {
    /// No schema is currently uploaded.
    NoSchema,
    /// The uploaded schema is incompatible with the active policy set.
    SchemaIncompatible,
}

/// Runtime request-context capability reported by the server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContextStatus {
    /// Whether the bundled core supports request context at all.
    pub supported: bool,
    /// Whether request evaluation is currently using a schema-backed engine.
    pub schema_backed: bool,
    /// Why runtime is not schema-backed, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<RequestContextFallbackReason>,
}

impl Default for RequestContextStatus {
    fn default() -> Self {
        Self {
            supported: true,
            schema_backed: false,
            fallback_reason: Some(RequestContextFallbackReason::NoSchema),
        }
    }
}

/// Full status response from the `/api/v1/status` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    /// Policy, label, and schema configuration metadata.
    pub policy_configuration: PoliciesMetadata,
    /// Parallelism configuration (CPU count, worker threads, etc.).
    /// Represented as opaque JSON since the structure may vary.
    pub parallel_configuration: serde_json::Value,
    /// Server-enforced limits on authorization request context.
    #[serde(default)]
    pub request_limits: RequestLimits,
    /// Runtime request-context mode and fallback status.
    #[serde(default)]
    pub request_context: RequestContextStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_deserialization_v006() {
        let json = serde_json::json!({
            "policy_configuration": {
                "allow_upload": true,
                "schema_validation_mode": "permissive",
                "policies": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "abc123",
                    "size": 1024,
                    "source": "https://example.com/policies",
                    "refresh_frequency": 60,
                    "entries": 5,
                    "content": "permit(...)"
                },
                "labels": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "def456",
                    "size": 256,
                    "entries": 2,
                    "content": "labels"
                },
                "schema": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "",
                    "size": 0,
                    "entries": 0,
                    "content": ""
                }
            },
            "parallel_configuration": {
                "workers": 2,
                "cpu_count": 8,
                "rayon_threads": 4,
                "par_threshold": 8,
                "allow_parallel": true
            },
            "request_limits": {
                "max_context_bytes": 16384,
                "max_context_depth": 8,
                "max_context_keys": 64
            },
            "request_context": {
                "supported": true,
                "schema_backed": false,
                "fallback_reason": "no_schema"
            }
        });

        let status: StatusResponse = serde_json::from_value(json).unwrap();
        assert!(status.policy_configuration.allow_upload);
        assert_eq!(
            status.policy_configuration.schema_validation_mode,
            "permissive"
        );
        assert_eq!(status.policy_configuration.policies.entries, 5);
        assert!(status.policy_configuration.schema.is_some());
        assert_eq!(status.request_limits.max_context_bytes, 16384);
        assert!(status.request_context.supported);
        assert!(!status.request_context.schema_backed);
        assert_eq!(
            status.request_context.fallback_reason,
            Some(RequestContextFallbackReason::NoSchema)
        );
    }

    #[test]
    fn status_response_backward_compat_v004() {
        let json = serde_json::json!({
            "policy_configuration": {
                "allow_upload": true,
                "policies": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "abc",
                    "size": 100,
                    "entries": 3,
                    "content": "permit(...);"
                },
                "labels": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "def",
                    "size": 0,
                    "entries": 0,
                    "content": ""
                }
            },
            "parallel_configuration": { "cpu_count": 4 }
        });

        let status: StatusResponse = serde_json::from_value(json).unwrap();
        assert!(status.policy_configuration.allow_upload);
        assert_eq!(status.policy_configuration.schema_validation_mode, "");
        assert!(status.policy_configuration.schema.is_none());
        assert_eq!(status.request_limits, RequestLimits::default());
        assert_eq!(status.request_context, RequestContextStatus::default());
    }

    #[test]
    fn request_limits_default() {
        let limits = RequestLimits::default();
        assert_eq!(limits.max_context_bytes, 16 * 1024);
        assert_eq!(limits.max_context_depth, 8);
        assert_eq!(limits.max_context_keys, 64);
    }

    #[test]
    fn request_context_status_default() {
        let status = RequestContextStatus::default();
        assert!(status.supported);
        assert!(!status.schema_backed);
        assert_eq!(
            status.fallback_reason,
            Some(RequestContextFallbackReason::NoSchema)
        );
    }
}
