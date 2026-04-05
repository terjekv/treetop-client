//! Principal types for Cedar authorization (users and groups).

use serde::{Deserialize, Serialize};

/// A Cedar group entity with an identifier and optional namespace.
///
/// Groups can be attached to [`User`]s or used directly as a [`Principal`].
///
/// # Wire format
/// ```json
/// { "id": "admins", "namespace": ["MyApp"] }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Group {
    /// The group identifier (e.g. `"admins"`).
    pub id: String,
    /// Optional Cedar namespace path (e.g. `["MyApp", "Core"]`).
    #[serde(default)]
    pub namespace: Vec<String>,
}

impl Group {
    /// Creates a new group with no namespace.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            namespace: Vec::new(),
        }
    }

    /// Sets the Cedar namespace for this group.
    pub fn with_namespace(mut self, namespace: Vec<String>) -> Self {
        self.namespace = namespace;
        self
    }
}

/// A Cedar user entity with an identifier, optional namespace, and optional group memberships.
///
/// # Wire format
/// ```json
/// { "id": "alice", "namespace": [], "groups": [{ "id": "admins", "namespace": [] }] }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct User {
    /// The user identifier (e.g. `"alice"`).
    pub id: String,
    /// Optional Cedar namespace path (e.g. `["MyApp"]`).
    #[serde(default)]
    pub namespace: Vec<String>,
    /// Groups this user belongs to, used for group-based policy matching.
    #[serde(default)]
    pub groups: Vec<Group>,
}

impl User {
    /// Creates a new user with no namespace or groups.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            namespace: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// Sets the Cedar namespace for this user.
    pub fn with_namespace(mut self, namespace: Vec<String>) -> Self {
        self.namespace = namespace;
        self
    }

    /// Sets the group memberships using pre-built [`Group`] values.
    pub fn with_groups(mut self, groups: Vec<Group>) -> Self {
        self.groups = groups;
        self
    }

    /// Sets group memberships from a list of group name strings (no namespaces).
    ///
    /// This is a convenience method for the common case where groups have no namespace.
    pub fn with_group_names(mut self, names: &[&str]) -> Self {
        self.groups = names.iter().map(|n| Group::new(*n)).collect();
        self
    }
}

/// The principal (actor) in an authorization request -- either a [`User`] or a [`Group`].
///
/// Serializes as an externally tagged enum:
/// ```json
/// { "User": { "id": "alice", ... } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Principal {
    /// A user principal.
    User(User),
    /// A group principal.
    Group(Group),
}

impl From<User> for Principal {
    fn from(user: User) -> Self {
        Principal::User(user)
    }
}

impl From<Group> for Principal {
    fn from(group: Group) -> Self {
        Principal::Group(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_serialization_without_groups() {
        let user = User::new("alice");
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "alice");
        assert_eq!(json["namespace"], serde_json::json!([]));
        assert_eq!(json["groups"], serde_json::json!([]));
    }

    #[test]
    fn user_serialization_with_groups_and_namespace() {
        let user = User::new("alice")
            .with_namespace(vec!["App".to_string()])
            .with_group_names(&["admins", "users"]);
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "alice");
        assert_eq!(json["namespace"], serde_json::json!(["App"]));
        assert_eq!(json["groups"][0]["id"], "admins");
        assert_eq!(json["groups"][1]["id"], "users");
    }

    #[test]
    fn principal_user_serialization() {
        let principal = Principal::User(User::new("alice"));
        let json = serde_json::to_value(&principal).unwrap();
        assert!(json["User"].is_object());
        assert_eq!(json["User"]["id"], "alice");
    }

    #[test]
    fn principal_group_serialization() {
        let principal = Principal::Group(Group::new("admins"));
        let json = serde_json::to_value(&principal).unwrap();
        assert!(json["Group"].is_object());
        assert_eq!(json["Group"]["id"], "admins");
    }

    #[test]
    fn user_roundtrip() {
        let user = User::new("bob")
            .with_namespace(vec!["Infra".to_string()])
            .with_groups(vec![
                Group::new("ops").with_namespace(vec!["Infra".to_string()]),
            ]);
        let json = serde_json::to_value(&user).unwrap();
        let deserialized: User = serde_json::from_value(json).unwrap();
        assert_eq!(user, deserialized);
    }
}
