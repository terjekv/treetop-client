//! Version and policy version types.

use serde::{Deserialize, Serialize};

/// Identifies a specific version of the loaded policy set.
///
/// Every authorization response includes a `PolicyVersion` so callers can verify
/// which policy snapshot was used for evaluation.
///
/// Displays as `"{hash} (loaded {loaded_at})"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PolicyVersion {
    /// SHA-256 hash of the policy source content.
    pub hash: String,
    /// ISO 8601 timestamp of when these policies were loaded.
    pub loaded_at: String,
}

impl std::fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (loaded {})", self.hash, self.loaded_at)
    }
}

/// Version information for the Treetop core library (Cedar engine).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Core {
    /// The treetop-core library version.
    pub version: String,
    /// The Cedar policy engine version.
    pub cedar: String,
}

/// Full version information returned by the `/api/v1/version` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    /// The treetop-rest server version.
    pub version: String,
    /// Core library and Cedar version details.
    pub core: Core,
    /// The policy version currently loaded in the server.
    pub policies: PolicyVersion,
    /// The schema version currently loaded in the server, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<PolicyVersion>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_info_roundtrip() {
        let json = serde_json::json!({
            "version": "0.1.0",
            "core": {
                "version": "0.3.0",
                "cedar": "0.11.0"
            },
            "policies": {
                "hash": "abc123",
                "loaded_at": "2025-01-01T00:00:00Z"
            }
        });
        let info: VersionInfo = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.core.cedar, "0.11.0");
        assert_eq!(info.policies.hash, "abc123");
        assert!(info.schema.is_none());

        let reserialized = serde_json::to_value(&info).unwrap();
        assert_eq!(json, reserialized);
    }

    #[test]
    fn version_info_with_schema() {
        let json = serde_json::json!({
            "version": "0.1.0",
            "core": {
                "version": "0.3.0",
                "cedar": "0.11.0"
            },
            "policies": {
                "hash": "abc123",
                "loaded_at": "2025-01-01T00:00:00Z"
            },
            "schema": {
                "hash": "schema123",
                "loaded_at": "2025-01-01T00:00:01Z"
            }
        });

        let info: VersionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(
            info.schema.as_ref().map(|v| v.hash.as_str()),
            Some("schema123")
        );
    }
}
