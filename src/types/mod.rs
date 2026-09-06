//! Types for the Treetop REST API, wire-compatible with treetop-core and treetop-rest 0.1.0.

mod action;
mod policy;
mod principal;
mod request;
mod resource;
mod response;
mod status;
mod validation;
mod version;

pub use action::Action;
pub use policy::{
    PermitPolicy, PoliciesDownload, PolicyMatch, PolicyMatchReason, SchemaDownload, UserPolicies,
};
pub use principal::{Group, Principal, User};
pub use request::{AuthRequest, AuthorizeRequest, Request};
pub use resource::{AttrValue, Resource};
pub use response::{
    AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDecisionDetailed,
    AuthorizeDetailedResponse, AuthorizeResponse, BatchResult, DecisionBrief, IndexedResult,
};
pub use status::{
    Metadata, MetadataSource, PoliciesMetadata, RequestContextFallbackReason, RequestContextStatus,
    RequestLimits, StatusResponse,
};
pub use validation::{CedarIpAddr, ValidationError};
pub(crate) use validation::{EntityId, Namespace};
pub use version::{Core, PolicyVersion, VersionInfo};
