//! Typed async Rust client for Treetop policy authorization servers.
//!
//! Treetop is a Cedar-based policy evaluation service. This crate provides a strongly typed,
//! async client for evaluating authorization requests, managing policies, and querying
//! server status over the Treetop REST API.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use treetop_client::{Action, Client, Request, Resource, User};
//!
//! # async fn example() -> treetop_client::Result<()> {
//! let client = Client::builder("https://treetop.example.com").build()?;
//!
//! let allowed = client
//!     .is_allowed(Request::new(
//!         User::new("alice"),
//!         Action::new("view"),
//!         Resource::new("Document", "doc-42"),
//!     ))
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Connection pooling
//!
//! The [`Client`] reuses connections via reqwest's built-in connection pool. Create one
//! `Client` and share it across your application. Cloning a `Client` (e.g. via
//! [`Client::with_correlation_id`]) shares the same underlying pool at zero cost.
//!
//! # Security
//!
//! Upload tokens are stored using [`secrecy::SecretString`], which zeroizes memory on drop
//! and is redacted in `Debug` output. TLS uses rustls by default (pure Rust, no OpenSSL).

pub mod client;
pub mod error;
pub mod token;
pub mod types;

pub use client::{Client, ClientBuilder};
pub use error::{Result, TreetopError};
pub use token::UploadToken;
pub use types::{
    Action, AttrValue, AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief,
    AuthorizeDecisionDetailed, AuthorizeDetailedResponse, AuthorizeRequest, AuthorizeResponse,
    BatchResult, Core, DecisionBrief, Group, IndexedResult, Metadata, PermitPolicy,
    PoliciesDownload, PoliciesMetadata, PolicyMatch, PolicyMatchReason, PolicyVersion, Principal,
    Request, RequestContextFallbackReason, RequestContextStatus, RequestLimits, Resource,
    SchemaDownload, StatusResponse, User, UserPolicies, VersionInfo,
};
