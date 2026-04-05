//! HTTP client for communicating with Treetop servers.

mod builder;
mod inner;

pub use builder::ClientBuilder;
pub use inner::Client;
