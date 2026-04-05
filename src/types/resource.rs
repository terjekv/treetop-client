//! Resource types for Cedar authorization requests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A typed attribute value that can be attached to a [`Resource`].
///
/// Serializes using adjacently tagged representation:
/// ```json
/// { "type": "String", "value": "hello" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
pub enum AttrValue {
    /// A string attribute value.
    String(String),
    /// A boolean attribute value.
    Bool(bool),
    /// A 64-bit integer attribute value.
    Long(i64),
    /// An IP address or CIDR block (e.g. `"10.0.0.1"` or `"10.0.0.0/8"`).
    Ip(String),
    /// A set of attribute values (typically homogeneous, e.g. a set of strings).
    Set(Vec<AttrValue>),
}

/// A Cedar resource entity -- the target of an authorization request.
///
/// Resources have a `kind` (entity type name), an `id`, and optional typed attributes
/// that can be used in Cedar policy conditions.
///
/// # Wire format
/// ```json
/// { "kind": "Host", "id": "web-01", "attrs": { "ip": { "type": "Ip", "value": "10.0.0.1" } } }
/// ```
///
/// The `attrs` field is omitted from serialization when empty.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    /// The resource type name (e.g. `"Host"`, `"Document"`).
    pub kind: String,
    /// The resource identifier (e.g. `"web-01"`, `"doc-42"`).
    pub id: String,
    /// Optional key-value attributes for policy evaluation conditions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, AttrValue>,
}

impl Resource {
    /// Creates a new resource with no attributes.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            attrs: BTreeMap::new(),
        }
    }

    /// Adds a typed attribute to this resource (builder pattern).
    ///
    /// If the key already exists, its value is overwritten.
    pub fn with_attr(mut self, key: impl Into<String>, value: AttrValue) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn resource_without_attrs() {
        let resource = Resource::new("Host", "web-01");
        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["kind"], "Host");
        assert_eq!(json["id"], "web-01");
        assert!(json.get("attrs").is_none());
    }

    #[test]
    fn resource_with_attrs() {
        let resource = Resource::new("Document", "doc1")
            .with_attr("owner", AttrValue::String("alice".to_string()))
            .with_attr("public", AttrValue::Bool(false))
            .with_attr("priority", AttrValue::Long(5))
            .with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()));
        let json = serde_json::to_value(&resource).unwrap();
        assert!(json["attrs"].is_object());
        assert_eq!(json["attrs"]["owner"]["type"], "String");
        assert_eq!(json["attrs"]["owner"]["value"], "alice");
        assert_eq!(json["attrs"]["public"]["type"], "Bool");
    }

    #[rstest]
    #[case::string(AttrValue::String("hello".to_string()))]
    #[case::bool_true(AttrValue::Bool(true))]
    #[case::bool_false(AttrValue::Bool(false))]
    #[case::long_positive(AttrValue::Long(42))]
    #[case::long_negative(AttrValue::Long(-1))]
    #[case::long_zero(AttrValue::Long(0))]
    #[case::ip_v4(AttrValue::Ip("192.168.1.1".to_string()))]
    #[case::ip_cidr(AttrValue::Ip("10.0.0.0/8".to_string()))]
    #[case::set(AttrValue::Set(vec![AttrValue::String("a".to_string()), AttrValue::String("b".to_string())]))]
    #[case::empty_set(AttrValue::Set(vec![]))]
    #[case::nested_set(AttrValue::Set(vec![AttrValue::Set(vec![AttrValue::Long(1)])]))]
    fn attrvalue_roundtrip(#[case] val: AttrValue) {
        let json = serde_json::to_value(&val).unwrap();
        let deserialized: AttrValue = serde_json::from_value(json).unwrap();
        assert_eq!(val, deserialized);
    }

    #[test]
    fn resource_roundtrip() {
        let resource =
            Resource::new("Host", "web-01").with_attr("ip", AttrValue::Ip("10.0.0.1".to_string()));
        let json = serde_json::to_value(&resource).unwrap();
        let deserialized: Resource = serde_json::from_value(json).unwrap();
        assert_eq!(resource, deserialized);
    }
}
