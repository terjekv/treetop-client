//! Action type for Cedar authorization requests.

use serde::{Deserialize, Serialize};

/// A Cedar action identifier with optional namespace.
///
/// Represents the action being performed in an authorization request
/// (e.g. `"view"`, `"delete"`, `"create_host"`).
///
/// # Wire format
/// ```json
/// { "id": "view", "namespace": ["Admin"] }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Action {
    /// The action identifier (e.g. `"view"`, `"delete"`).
    pub id: String,
    /// Optional Cedar namespace path (e.g. `["Admin", "Core"]`).
    #[serde(default)]
    pub namespace: Vec<String>,
}

impl Action {
    /// Creates a new action with no namespace.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            namespace: Vec::new(),
        }
    }

    /// Sets the Cedar namespace for this action.
    pub fn with_namespace(mut self, namespace: Vec<String>) -> Self {
        self.namespace = namespace;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_serialization() {
        let action = Action::new("create");
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json["id"], "create");
        assert_eq!(json["namespace"], serde_json::json!([]));
    }

    #[test]
    fn action_with_namespace() {
        let action = Action::new("delete").with_namespace(vec!["Admin".to_string()]);
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json["namespace"], serde_json::json!(["Admin"]));
    }

    #[test]
    fn action_roundtrip() {
        let action =
            Action::new("view").with_namespace(vec!["App".to_string(), "Core".to_string()]);
        let json = serde_json::to_value(&action).unwrap();
        let deserialized: Action = serde_json::from_value(json).unwrap();
        assert_eq!(action, deserialized);
    }
}
