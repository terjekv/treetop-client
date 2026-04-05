//! Types for the Treetop REST API, wire-compatible with treetop-core and treetop-rest v0.0.6.

mod action;
mod policy;
mod principal;
mod request;
mod resource;
mod response;
mod status;
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
    Metadata, PoliciesMetadata, RequestContextFallbackReason, RequestContextStatus, RequestLimits,
    StatusResponse,
};
pub use version::{Core, PolicyVersion, VersionInfo};
