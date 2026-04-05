//! Authorization response types.

use serde::{Deserialize, Serialize};

use super::policy::PermitPolicy;
use super::version::PolicyVersion;

/// The authorization decision: either `Allow` or `Deny`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DecisionBrief {
    /// The request was allowed by one or more policies.
    Allow,
    /// The request was denied (no matching permit policy).
    Deny,
}

impl std::fmt::Display for DecisionBrief {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecisionBrief::Allow => write!(f, "Allow"),
            DecisionBrief::Deny => write!(f, "Deny"),
        }
    }
}

/// A brief authorization decision with the policy version and matching policy IDs.
///
/// Returned when using [`Client::authorize`](crate::Client::authorize)
/// (the `detail=brief` query parameter).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizeDecisionBrief {
    /// The authorization decision.
    pub decision: DecisionBrief,
    /// The policy version used for this evaluation.
    pub version: PolicyVersion,
    /// Semicolon-separated IDs of the policies that matched (empty string if denied).
    pub policy_id: String,
}

/// A detailed authorization decision including the full text and JSON of matching policies.
///
/// Returned when using [`Client::authorize_detailed`](crate::Client::authorize_detailed)
/// (the `detail=full` query parameter).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizeDecisionDetailed {
    /// The policies that matched and permitted the request (empty if denied).
    pub policy: Vec<PermitPolicy>,
    /// The authorization decision.
    pub decision: DecisionBrief,
    /// The policy version used for this evaluation.
    pub version: PolicyVersion,
}

/// The outcome of a single request within a batch -- either success or failure.
///
/// Uses a tagged enum representation:
/// ```json
/// { "status": "success", "result": { ... } }
/// { "status": "failed", "error": "message" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum BatchResult<T> {
    /// The request was successfully evaluated.
    Success {
        /// The evaluation result.
        #[serde(rename = "result")]
        data: T,
    },
    /// The request failed to evaluate (e.g. invalid principal format).
    Failed {
        /// A human-readable error message describing what went wrong.
        #[serde(rename = "error")]
        message: String,
    },
}

/// A single result from a batch authorization, tagged with its position and optional client ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexedResult<T> {
    /// The zero-based index of this result in the original request batch.
    pub index: usize,
    /// The client-provided correlation ID, if one was set on the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The evaluation outcome (success with data, or failure with error message).
    #[serde(flatten)]
    pub result: BatchResult<T>,
}

/// The full response from a batch authorization request.
///
/// Generic over the decision type `T`, which is either [`AuthorizeDecisionBrief`]
/// or [`AuthorizeDecisionDetailed`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizeResponse<T> {
    /// The individual results, one per request in the batch.
    pub results: Vec<IndexedResult<T>>,
    /// The policy version used for all evaluations in this batch.
    pub version: PolicyVersion,
    /// The number of requests that were successfully evaluated.
    pub successful: usize,
    /// The number of requests that failed evaluation.
    pub failed: usize,
}

impl<T> AuthorizeResponse<T> {
    /// Returns the count of successfully evaluated requests.
    pub fn successes(&self) -> usize {
        self.successful
    }

    /// Returns the count of requests that failed evaluation.
    pub fn failures(&self) -> usize {
        self.failed
    }

    /// Returns the policy version used for all evaluations in this batch.
    pub fn version(&self) -> &PolicyVersion {
        &self.version
    }

    /// Returns the total number of results (successes + failures).
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// Returns a slice of all results in batch order.
    pub fn results(&self) -> &[IndexedResult<T>] {
        &self.results
    }

    /// Finds the first result with the given client-provided correlation ID.
    ///
    /// Returns `None` if no request in the batch had the specified ID.
    pub fn find_by_id(&self, id: &str) -> Option<&IndexedResult<T>> {
        self.results.iter().find(|r| r.id.as_deref() == Some(id))
    }

    /// Returns an iterator over all results.
    pub fn iter(&self) -> impl Iterator<Item = &IndexedResult<T>> {
        self.results.iter()
    }

    /// Consumes the response and returns the results vector.
    pub fn into_results(self) -> Vec<IndexedResult<T>> {
        self.results
    }
}

impl<'a, T> IntoIterator for &'a AuthorizeResponse<T> {
    type Item = &'a IndexedResult<T>;
    type IntoIter = std::slice::Iter<'a, IndexedResult<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.results.iter()
    }
}

/// Authorization response with brief decision info (policy IDs only).
pub type AuthorizeBriefResponse = AuthorizeResponse<AuthorizeDecisionBrief>;

/// Authorization response with detailed decision info (full policy text and JSON).
pub type AuthorizeDetailedResponse = AuthorizeResponse<AuthorizeDecisionDetailed>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brief_response_deserialization() {
        let json = serde_json::json!({
            "results": [{
                "index": 0,
                "id": "req-1",
                "status": "success",
                "result": {
                    "decision": "Allow",
                    "version": { "hash": "abc", "loaded_at": "2025-01-01T00:00:00Z" },
                    "policy_id": "policy1"
                }
            }],
            "version": { "hash": "abc", "loaded_at": "2025-01-01T00:00:00Z" },
            "successful": 1,
            "failed": 0
        });

        let resp: AuthorizeBriefResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.successes(), 1);
        assert_eq!(resp.failures(), 0);
        assert_eq!(resp.total(), 1);

        let result = resp.find_by_id("req-1").unwrap();
        assert_eq!(result.index, 0);
        match &result.result {
            BatchResult::Success { data } => {
                assert_eq!(data.decision, DecisionBrief::Allow);
                assert_eq!(data.policy_id, "policy1");
            }
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn failed_result_deserialization() {
        let json = serde_json::json!({
            "results": [{
                "index": 0,
                "status": "failed",
                "error": "invalid principal"
            }],
            "version": { "hash": "abc", "loaded_at": "2025-01-01T00:00:00Z" },
            "successful": 0,
            "failed": 1
        });

        let resp: AuthorizeBriefResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.failures(), 1);
        match &resp.results()[0].result {
            BatchResult::Failed { message } => assert_eq!(message, "invalid principal"),
            _ => panic!("expected failure"),
        }
    }
}
