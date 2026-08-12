//! Principal types for Cedar authorization (users and groups).

use serde::{Deserialize, Serialize};

use super::validation::{EntityId, Namespace, ValidationError};

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
    id: EntityId,
    /// Optional Cedar namespace path (e.g. `["MyApp", "Core"]`).
    #[serde(default)]
    namespace: Namespace,
}

impl Group {
    /// Creates a validated group with no namespace.
    pub fn new(id: impl Into<String>) -> Result<Self, ValidationError> {
        let group = Self {
            id: EntityId::new(id),
            namespace: Namespace::default(),
        };
        group.validate()?;
        Ok(group)
    }

    /// Creates and validates a new group with no namespace.
    #[deprecated(since = "0.0.2", note = "Group::new now validates its input")]
    pub fn try_new(id: impl Into<String>) -> Result<Self, ValidationError> {
        Self::new(id)
    }

    /// Sets and validates the Cedar namespace for this group.
    pub fn with_namespace(mut self, namespace: Vec<String>) -> Result<Self, ValidationError> {
        self.namespace = Namespace::new(namespace);
        self.validate()?;
        Ok(self)
    }

    /// Sets and validates the Cedar namespace for this group.
    #[deprecated(
        since = "0.0.2",
        note = "Group::with_namespace now validates its input"
    )]
    pub fn try_with_namespace(self, namespace: Vec<String>) -> Result<Self, ValidationError> {
        self.with_namespace(namespace)
    }

    /// Returns the group entity identifier.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns the Cedar namespace path.
    pub fn namespace(&self) -> &[String] {
        self.namespace.as_slice()
    }

    /// Validates this group against Cedar and Treetop request invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate("group.id")?;
        self.namespace.validate("group.namespace")
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
    id: EntityId,
    /// Optional Cedar namespace path (e.g. `["MyApp"]`).
    #[serde(default)]
    namespace: Namespace,
    /// Groups this user belongs to, used for group-based policy matching.
    #[serde(default)]
    groups: Vec<Group>,
}

impl User {
    /// Creates a validated user with no namespace or groups.
    pub fn new(id: impl Into<String>) -> Result<Self, ValidationError> {
        let user = Self {
            id: EntityId::new(id),
            namespace: Namespace::default(),
            groups: Vec::new(),
        };
        user.validate()?;
        Ok(user)
    }

    /// Creates and validates a new user with no namespace or groups.
    #[deprecated(since = "0.0.2", note = "User::new now validates its input")]
    pub fn try_new(id: impl Into<String>) -> Result<Self, ValidationError> {
        Self::new(id)
    }

    /// Sets and validates the Cedar namespace for this user.
    pub fn with_namespace(mut self, namespace: Vec<String>) -> Result<Self, ValidationError> {
        self.namespace = Namespace::new(namespace);
        self.validate()?;
        Ok(self)
    }

    /// Sets and validates the Cedar namespace for this user.
    #[deprecated(since = "0.0.2", note = "User::with_namespace now validates its input")]
    pub fn try_with_namespace(self, namespace: Vec<String>) -> Result<Self, ValidationError> {
        self.with_namespace(namespace)
    }

    /// Sets the group memberships using pre-built [`Group`] values.
    pub fn with_groups(mut self, groups: Vec<Group>) -> Self {
        self.groups = groups;
        self
    }

    /// Sets group memberships from a list of group name strings (no namespaces).
    ///
    /// This is a convenience method for the common case where groups have no namespace.
    pub fn with_group_names(mut self, names: &[&str]) -> Result<Self, ValidationError> {
        self.groups = names
            .iter()
            .map(|name| Group::new(*name))
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    /// Returns the user entity identifier.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns the Cedar namespace path.
    pub fn namespace(&self) -> &[String] {
        self.namespace.as_slice()
    }

    /// Returns the user's group memberships.
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// Validates this user and all of its groups against request invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.id.validate("user.id")?;
        self.namespace.validate("user.namespace")?;
        for group in &self.groups {
            group.validate()?;
        }
        Ok(())
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

impl Principal {
    /// Validates the concrete user or group principal.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::User(user) => user.validate(),
            Self::Group(group) => group.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_serialization_without_groups() {
        let user = User::new("alice").unwrap();
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "alice");
        assert_eq!(json["namespace"], serde_json::json!([]));
        assert_eq!(json["groups"], serde_json::json!([]));
    }

    #[test]
    fn user_serialization_with_groups_and_namespace() {
        let user = User::new("alice")
            .unwrap()
            .with_namespace(vec!["App".to_string()])
            .unwrap()
            .with_group_names(&["admins", "users"])
            .unwrap();
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "alice");
        assert_eq!(json["namespace"], serde_json::json!(["App"]));
        assert_eq!(json["groups"][0]["id"], "admins");
        assert_eq!(json["groups"][1]["id"], "users");
    }

    #[test]
    fn principal_user_serialization() {
        let principal = Principal::User(User::new("alice").unwrap());
        let json = serde_json::to_value(&principal).unwrap();
        assert!(json["User"].is_object());
        assert_eq!(json["User"]["id"], "alice");
    }

    #[test]
    fn principal_group_serialization() {
        let principal = Principal::Group(Group::new("admins").unwrap());
        let json = serde_json::to_value(&principal).unwrap();
        assert!(json["Group"].is_object());
        assert_eq!(json["Group"]["id"], "admins");
    }

    #[test]
    fn user_roundtrip() {
        let user = User::new("bob")
            .unwrap()
            .with_namespace(vec!["Infra".to_string()])
            .unwrap()
            .with_groups(vec![
                Group::new("ops")
                    .unwrap()
                    .with_namespace(vec!["Infra".to_string()])
                    .unwrap(),
            ]);
        let json = serde_json::to_value(&user).unwrap();
        let deserialized: User = serde_json::from_value(json).unwrap();
        assert_eq!(user, deserialized);
    }
}
