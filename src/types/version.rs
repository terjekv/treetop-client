//! Version and policy version types.

use serde::{Deserialize, Serialize};

/// Identifies the policy and label state used for authorization.
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
    /// Stable label configuration identifier, when supplied by the server.
    /// Required on the wire; explicit null means no configured label identifier.
    #[serde(deserialize_with = "deserialize_label_set")]
    pub label_set: Option<String>,
    /// Generation within one engine instance; this can restart on replacement.
    /// Required on the wire; no old-server default is inferred.
    pub generation: u64,
}

fn deserialize_label_set<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
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

/// Identifies loaded schema content, separately from an authorization generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaVersion {
    /// SHA-256 hash of the schema source.
    pub hash: String,
    /// ISO 8601 timestamp of when the schema was loaded.
    pub loaded_at: String,
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
    pub schema: Option<SchemaVersion>,
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
                "loaded_at": "2025-01-01T00:00:00Z",
                "label_set": "labels-v2",
                "generation": 7}
        });
        let info: VersionInfo = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.core.cedar, "0.11.0");
        assert_eq!(info.policies.hash, "abc123");
        assert_eq!(info.policies.label_set.as_deref(), Some("labels-v2"));
        assert_eq!(info.policies.generation, 7);
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
                "loaded_at": "2025-01-01T00:00:00Z", "label_set": null, "generation": 0},
            "schema": {
                "hash": "schema123",
                "loaded_at": "2025-01-01T00:00:01Z"}
        });

        let info: VersionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(
            info.schema.as_ref().map(|v| v.hash.as_str()),
            Some("schema123")
        );
        assert_eq!(info.policies.label_set, None);
        assert_eq!(info.policies.generation, 0);
    }

    #[test]
    fn policy_version_requires_every_current_field() {
        let complete =
            serde_json::json!({"hash":"h","loaded_at":"t","label_set":null,"generation":0});
        for field in ["hash", "loaded_at", "label_set", "generation"] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<PolicyVersion>(incomplete).is_err(),
                "{field}"
            );
        }
        assert!(serde_json::from_value::<PolicyVersion>(complete).is_ok());
    }

    #[test]
    fn generation_accepts_only_unsigned_integers() {
        for generation in [
            serde_json::json!(-1),
            serde_json::json!(true),
            serde_json::json!(1.5),
            serde_json::json!("1"),
            serde_json::json!(null),
        ] {
            let value = serde_json::json!({
                "hash": "hash", "loaded_at": "2026-09-05T00:00:00Z",
                "label_set": null, "generation": generation});
            assert!(serde_json::from_value::<PolicyVersion>(value).is_err());
        }
        let value = serde_json::json!({
            "hash": "hash", "loaded_at": "2026-09-05T00:00:00Z",
            "label_set": null, "generation": u64::MAX});
        let version: PolicyVersion = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(version.generation, u64::MAX);
        assert_eq!(serde_json::to_value(version).unwrap(), value);
    }
}
