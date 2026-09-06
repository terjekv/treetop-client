//! Resource types for Cedar authorization requests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::validation::{
    CedarIpAddr, CedarTypeName, EntityId, ValidationError, validate_attribute_name,
};

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
    Ip(CedarIpAddr),
    /// A set of attribute values (typically homogeneous, e.g. a set of strings).
    Set(Vec<AttrValue>),
}

impl AttrValue {
    /// Creates a validated Cedar IP extension value.
    pub fn ip(value: impl Into<String>) -> Result<Self, ValidationError> {
        CedarIpAddr::new(value).map(Self::Ip)
    }
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
#[serde(try_from = "ResourceWire")]
pub struct Resource {
    /// The resource type name (e.g. `"Host"`, `"Document"`).
    kind: CedarTypeName,
    /// The resource identifier (e.g. `"web-01"`, `"doc-42"`).
    id: EntityId,
    /// Optional key-value attributes for policy evaluation conditions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attrs: BTreeMap<String, AttrValue>,
}

#[derive(Deserialize)]
struct ResourceWire {
    kind: CedarTypeName,
    id: EntityId,
    #[serde(default)]
    attrs: BTreeMap<String, AttrValue>,
}

impl TryFrom<ResourceWire> for Resource {
    type Error = ValidationError;

    fn try_from(wire: ResourceWire) -> Result<Self, Self::Error> {
        let resource = Self {
            kind: wire.kind,
            id: wire.id,
            attrs: wire.attrs,
        };
        resource.validate()?;
        Ok(resource)
    }
}

impl Resource {
    /// Creates a validated resource with no attributes.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Result<Self, ValidationError> {
        let resource = Self {
            kind: CedarTypeName::new(kind),
            id: EntityId::new(id),
            attrs: BTreeMap::new(),
        };
        resource.validate()?;
        Ok(resource)
    }

    /// Adds a typed attribute to this resource (builder pattern).
    ///
    /// If the key already exists, its value is overwritten.
    pub fn with_attr(
        mut self,
        key: impl Into<String>,
        value: AttrValue,
    ) -> Result<Self, ValidationError> {
        let key = key.into();
        validate_attribute_name(&key, "resource.attrs")?;
        self.attrs.insert(key, value);
        Ok(self)
    }

    /// Returns the qualified Cedar resource type.
    pub fn kind(&self) -> &str {
        self.kind.as_str()
    }

    /// Returns the resource entity identifier.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns the resource attributes.
    pub fn attrs(&self) -> &BTreeMap<String, AttrValue> {
        &self.attrs
    }

    /// Returns an attribute by name.
    pub fn attr(&self, key: &str) -> Option<&AttrValue> {
        self.attrs.get(key)
    }

    /// Validates this resource against Cedar and Treetop request invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.kind.validate("resource.kind")?;
        self.id.validate("resource.id")?;
        for key in self.attrs.keys() {
            validate_attribute_name(key, "resource.attrs")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn resource_without_attrs() {
        let resource = Resource::new("Host", "web-01").unwrap();
        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["kind"], "Host");
        assert_eq!(json["id"], "web-01");
        assert!(json.get("attrs").is_none());
    }

    #[test]
    fn resource_with_attrs() {
        let resource = Resource::new("Document", "doc1")
            .unwrap()
            .with_attr("owner", AttrValue::String("alice".to_string()))
            .unwrap()
            .with_attr("public", AttrValue::Bool(false))
            .unwrap()
            .with_attr("priority", AttrValue::Long(5))
            .unwrap()
            .with_attr("ip", AttrValue::ip("10.0.0.1").unwrap());
        let resource = resource.unwrap();
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
    #[case::ip_v4(AttrValue::ip("192.168.1.1").unwrap())]
    #[case::ip_cidr(AttrValue::ip("10.0.0.0/8").unwrap())]
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
        let resource = Resource::new("Host", "web-01")
            .unwrap()
            .with_attr("ip", AttrValue::ip("10.0.0.1").unwrap())
            .unwrap();
        let json = serde_json::to_value(&resource).unwrap();
        let deserialized: Resource = serde_json::from_value(json).unwrap();
        assert_eq!(resource, deserialized);
    }
}
