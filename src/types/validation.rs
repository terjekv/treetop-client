//! Validation primitives shared by request-domain types.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// An error reported when a request value cannot be represented safely by Treetop or Cedar.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// A Cedar identifier does not follow Cedar's identifier grammar.
    #[error("{field} contains an invalid Cedar identifier segment: {value:?}")]
    InvalidCedarIdentifier {
        /// The request field containing the invalid value.
        field: &'static str,
        /// The invalid identifier segment.
        value: String,
    },

    /// A Cedar name uses Cedar's reserved internal namespace.
    #[error("{field} contains the reserved Cedar identifier `__cedar`")]
    ReservedCedarIdentifier {
        /// The request field containing the reserved value.
        field: &'static str,
    },

    /// An entity identifier cannot be safely converted by the current Treetop wire contract.
    #[error("{field} contains a character that cannot be represented safely: {character:?}")]
    InvalidEntityId {
        /// The request field containing the invalid value.
        field: &'static str,
        /// The first unsupported character.
        character: char,
    },

    /// An attribute or context key is empty or contains a control character.
    #[error("{field} contains an invalid attribute name: {value:?}")]
    InvalidAttributeName {
        /// The request field containing the invalid value.
        field: &'static str,
        /// The invalid attribute name.
        value: String,
    },

    /// An IP extension value is neither an IP address nor a CIDR network.
    #[error("invalid Cedar IP address or network: {value:?}")]
    InvalidIpAddress {
        /// The invalid value.
        value: String,
    },

    /// A request correlation ID is empty or contains a control character.
    #[error("invalid request correlation ID")]
    InvalidRequestId,

    /// An upload token is empty or cannot be represented as an HTTP header value.
    #[error("upload token must be non-empty and contain only valid HTTP header characters")]
    InvalidUploadToken,

    /// Request context contains more keys than the selected server limit.
    #[error("context has too many keys: {actual} > {limit}")]
    ContextTooManyKeys {
        /// The number of supplied keys.
        actual: usize,
        /// The configured maximum.
        limit: usize,
    },

    /// Serialized request context exceeds the selected server limit.
    #[error("context payload is too large: {actual} bytes > {limit} bytes")]
    ContextTooLarge {
        /// The serialized size in bytes.
        actual: usize,
        /// The configured maximum.
        limit: usize,
    },

    /// Request context nesting exceeds the selected server limit.
    #[error("context nesting is too deep: {actual} > {limit}")]
    ContextTooDeep {
        /// The actual nesting depth.
        actual: usize,
        /// The configured maximum.
        limit: usize,
    },

    /// Request context could not be serialized for size validation.
    #[error("context could not be serialized: {message}")]
    ContextSerialization {
        /// The serialization failure.
        message: String,
    },
}

/// A Cedar entity identifier.
///
/// Cedar entity IDs are string values rather than Cedar identifiers. Treetop's current core
/// turns these values into quoted Cedar UIDs, so quote, backslash, and control characters are
/// rejected until the core performs Cedar string escaping itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct EntityId(String);

impl EntityId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ValidationError> {
        if let Some(character) = self
            .0
            .chars()
            .find(|character| character.is_control() || matches!(character, '"' | '\\'))
        {
            return Err(ValidationError::InvalidEntityId { field, character });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for EntityId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let id = Self(value);
        id.validate("entity id").map_err(serde::de::Error::custom)?;
        Ok(id)
    }
}

/// A possibly qualified Cedar type name such as `Infra::Host`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct CedarTypeName(String);

impl CedarTypeName {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ValidationError> {
        validate_cedar_path(&self.0, field)
    }
}

impl<'de> Deserialize<'de> for CedarTypeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let name = Self(value);
        name.validate("entity type")
            .map_err(serde::de::Error::custom)?;
        Ok(name)
    }
}

/// A Cedar namespace represented as validated identifier segments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct Namespace(Vec<String>);

impl Namespace {
    pub(crate) fn new(value: Vec<String>) -> Self {
        Self(value)
    }

    pub(crate) fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ValidationError> {
        for segment in &self.0 {
            validate_cedar_identifier(segment, field)?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Namespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<String>::deserialize(deserializer)?;
        let namespace = Self(value);
        namespace
            .validate("namespace")
            .map_err(serde::de::Error::custom)?;
        Ok(namespace)
    }
}

/// An opaque client-provided request correlation ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct RequestId(String);

impl RequestId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        if self.0.is_empty() || self.0.chars().any(char::is_control) {
            Err(ValidationError::InvalidRequestId)
        } else {
            Ok(())
        }
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let id = Self(value);
        id.validate().map_err(serde::de::Error::custom)?;
        Ok(id)
    }
}

/// A validated Cedar IP extension value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CedarIpAddr(String);

impl CedarIpAddr {
    /// Parses an IP address or CIDR network.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.parse::<IpAddr>().is_ok() || value.parse::<ipnet::IpNet>().is_ok() {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidIpAddress { value })
        }
    }

    /// Returns the original validated string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value and returns its string representation.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for CedarIpAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for CedarIpAddr {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for CedarIpAddr {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for CedarIpAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CedarIpAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn validate_cedar_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), ValidationError> {
    let mut bytes = value.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());

    if !valid {
        return Err(ValidationError::InvalidCedarIdentifier {
            field,
            value: value.to_string(),
        });
    }
    if value == "__cedar" {
        return Err(ValidationError::ReservedCedarIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_cedar_path(value: &str, field: &'static str) -> Result<(), ValidationError> {
    for segment in value.split("::") {
        validate_cedar_identifier(segment, field)?;
    }
    Ok(())
}

pub(crate) fn validate_attribute_name(
    value: &str,
    field: &'static str,
) -> Result<(), ValidationError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(ValidationError::InvalidAttributeName {
            field,
            value: value.to_string(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cedar_identifier_uses_documented_ascii_grammar() {
        for valid in ["User", "_internal", "NS1"] {
            assert!(validate_cedar_identifier(valid, "test").is_ok());
        }
        for invalid in ["", "1User", "a-b", "with space", "Nøn"] {
            assert!(validate_cedar_identifier(invalid, "test").is_err());
        }
    }

    #[test]
    fn cedar_internal_namespace_is_reserved() {
        assert!(matches!(
            validate_cedar_identifier("__cedar", "test"),
            Err(ValidationError::ReservedCedarIdentifier { .. })
        ));
    }

    #[test]
    fn ip_address_accepts_addresses_and_networks() {
        for valid in ["192.0.2.1", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"] {
            assert!(CedarIpAddr::new(valid).is_ok());
        }
        assert!(CedarIpAddr::new("999.0.0.1").is_err());
    }
}
