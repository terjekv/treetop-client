//! Policy types for policy management endpoints.

use serde::{Deserialize, Serialize};

use super::status::Metadata;

/// A Cedar policy that matched a permit decision, including both its DSL literal
/// and JSON representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermitPolicy {
    /// The policy in Cedar DSL format (e.g. `"permit(principal == User::\"alice\", ...);"`).
    pub literal: String,
    /// The policy in Cedar JSON format.
    pub json: serde_json::Value,
    /// The policy ID from a `@id` annotation, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation_id: Option<String>,
    /// The Cedar-assigned policy ID (e.g. `"policy0"`).
    pub cedar_id: String,
}

/// Response from `GET /api/v1/policies` containing policy metadata and content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoliciesDownload {
    /// Metadata about the downloaded policies.
    pub policies: Metadata,
}

/// Response from `GET /api/v1/schema` containing schema metadata and content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaDownload {
    /// Metadata about the downloaded schema.
    pub schema: Metadata,
}

/// Why a policy was selected by the list-policies API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PolicyMatchReason {
    /// The policy's principal constraint matches the queried user exactly.
    PrincipalEq,
    /// The policy's principal constraint matches via group membership.
    PrincipalIn,
    /// The policy applies to any principal.
    PrincipalAny,
    /// The policy's principal constraint uses `is` (type check).
    PrincipalIs,
    /// The policy's principal constraint uses `is ... in` (type + membership).
    PrincipalIsIn,
    /// The policy's action constraint matches exactly.
    ActionEq,
    /// The policy's action constraint matches via `in`.
    ActionIn,
    /// The policy applies to any action.
    ActionAny,
    /// The policy's resource constraint matches exactly.
    ResourceEq,
    /// The policy's resource constraint matches via `in`.
    ResourceIn,
    /// The policy applies to any resource.
    ResourceAny,
    /// The policy's resource constraint uses `is` (type check).
    ResourceIs,
    /// The policy's resource constraint uses `is ... in` (type + membership).
    ResourceIsIn,
}

/// Match metadata for a listed policy, explaining why it was selected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMatch {
    /// The Cedar-assigned policy ID (e.g. `"policy0"`).
    pub cedar_id: String,
    /// The reasons this policy matched the queried user/resource.
    pub reasons: Vec<PolicyMatchReason>,
}

/// Policies associated with a specific user, returned by `GET /api/v1/policies/{user}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserPolicies {
    /// The user identifier these policies apply to.
    pub user: String,
    /// The matching policies in Cedar JSON format.
    pub policies: Vec<serde_json::Value>,
    /// Match metadata explaining why each policy was selected.
    #[serde(default)]
    pub matches: Vec<PolicyMatch>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_policy_deserialization() {
        let json = serde_json::json!({
            "literal": "permit(principal, action, resource);",
            "json": {"effect": "permit"},
            "annotation_id": "policy-1",
            "cedar_id": "policy0"
        });
        let policy: PermitPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(policy.annotation_id.as_deref(), Some("policy-1"));
        assert_eq!(policy.cedar_id, "policy0");
    }

    #[test]
    fn user_policies_deserialization_v005() {
        let json = serde_json::json!({
            "user": "alice",
            "policies": [
                {"effect": "permit", "principal": {"op": "==", "entity": {"type": "User", "id": "alice"}}}
            ],
            "matches": [
                {"cedar_id": "policy0", "reasons": ["PrincipalEq"]}
            ]
        });
        let up: UserPolicies = serde_json::from_value(json).unwrap();
        assert_eq!(up.user, "alice");
        assert_eq!(up.policies.len(), 1);
        assert_eq!(up.matches.len(), 1);
        assert_eq!(up.matches[0].cedar_id, "policy0");
        assert_eq!(up.matches[0].reasons, vec![PolicyMatchReason::PrincipalEq]);
    }

    #[test]
    fn user_policies_backward_compat_no_matches() {
        let json = serde_json::json!({
            "user": "alice",
            "policies": [{"effect": "permit"}]
        });
        let up: UserPolicies = serde_json::from_value(json).unwrap();
        assert_eq!(up.user, "alice");
        assert!(up.matches.is_empty());
    }

    #[test]
    fn policy_match_reason_roundtrip() {
        let reasons = vec![
            PolicyMatchReason::PrincipalEq,
            PolicyMatchReason::PrincipalIn,
            PolicyMatchReason::PrincipalAny,
            PolicyMatchReason::ActionEq,
            PolicyMatchReason::ActionIn,
            PolicyMatchReason::ActionAny,
            PolicyMatchReason::ResourceAny,
        ];
        let json = serde_json::to_value(&reasons).unwrap();
        let deserialized: Vec<PolicyMatchReason> = serde_json::from_value(json).unwrap();
        assert_eq!(reasons, deserialized);
    }

    #[test]
    fn schema_download_deserialization() {
        let json = serde_json::json!({
            "schema": {
                "timestamp": "2026-01-01T00:00:00Z",
                "sha256": "schema-hash",
                "size": 128,
                "entries": 1,
                "content": "{\"\": {\"entityTypes\": {}, \"actions\": {}}}"
            }
        });
        let download: SchemaDownload = serde_json::from_value(json).unwrap();
        assert_eq!(download.schema.sha256, "schema-hash");
        assert_eq!(download.schema.entries, 1);
    }
}
