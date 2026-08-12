use std::collections::HashMap;

use proptest::collection::vec;
use proptest::prelude::*;
use treetop_client::{
    Action, AttrValue, AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief,
    AuthorizeRequest, BatchResult, Client, DecisionBrief, Group, IndexedResult, PolicyVersion,
    Request, RequestLimits, Resource, StatusResponse, User, VersionInfo,
};

fn sample_request() -> Request {
    Request::new(
        User::new("alice"),
        Action::new("view"),
        Resource::new("Document", "doc-1"),
    )
}

fn attr_value() -> impl Strategy<Value = AttrValue> {
    prop_oneof![
        any::<String>().prop_map(AttrValue::String),
        any::<bool>().prop_map(AttrValue::Bool),
        any::<i64>().prop_map(AttrValue::Long),
    ]
    .prop_recursive(6, 256, 8, |inner| vec(inner, 0..4).prop_map(AttrValue::Set))
}

fn attr_depth(value: &AttrValue) -> usize {
    match value {
        AttrValue::Set(values) => 1 + values.iter().map(attr_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn policy_version(hash: &str) -> PolicyVersion {
    PolicyVersion {
        hash: hash.to_string(),
        loaded_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn valid_response(successes: &[bool]) -> AuthorizeBriefResponse {
    let version = policy_version("batch");
    let results = successes
        .iter()
        .enumerate()
        .map(|(index, success)| IndexedResult {
            index,
            id: None,
            result: if *success {
                BatchResult::Success {
                    data: AuthorizeDecisionBrief {
                        decision: DecisionBrief::Allow,
                        version: version.clone(),
                        policy_id: "policy".to_string(),
                    },
                }
            } else {
                BatchResult::Failed {
                    message: "evaluation failed".to_string(),
                }
            },
        })
        .collect();
    let successful = successes.iter().filter(|success| **success).count();

    AuthorizeBriefResponse {
        results,
        version,
        successful,
        failed: successes.len() - successful,
    }
}

proptest! {
    #[test]
    fn arbitrary_input_deserialization_never_panics(input in vec(any::<u8>(), 0..4096)) {
        let _ = serde_json::from_slice::<Action>(&input);
        let _ = serde_json::from_slice::<Group>(&input);
        let _ = serde_json::from_slice::<User>(&input);
        let _ = serde_json::from_slice::<Resource>(&input);
        let _ = serde_json::from_slice::<Request>(&input);
        let _ = serde_json::from_slice::<AuthorizeRequest>(&input);
        let _ = serde_json::from_slice::<AuthorizeBriefResponse>(&input);
        let _ = serde_json::from_slice::<StatusResponse>(&input);
        let _ = serde_json::from_slice::<VersionInfo>(&input);
    }

    #[test]
    fn arbitrary_urls_never_panic(value in any::<String>()) {
        let _ = Client::builder(value).build();
    }

    #[test]
    fn ordinary_http_urls_are_accepted(
        secure in any::<bool>(),
        host in "[a-z][a-z0-9]{0,15}\\.example",
        segments in vec("[a-zA-Z0-9_-]{1,12}", 0..5),
    ) {
        let scheme = if secure { "https" } else { "http" };
        let path = segments.join("/");
        let url = format!("{scheme}://{host}/{path}");
        prop_assert!(Client::builder(url).build().is_ok());
    }

    #[test]
    fn cedar_ip_validation_matches_ip_parsers(value in any::<String>()) {
        let expected = value.parse::<std::net::IpAddr>().is_ok()
            || value.parse::<ipnet::IpNet>().is_ok();
        prop_assert_eq!(AttrValue::ip(value).is_ok(), expected);
    }

    #[test]
    fn nested_context_depth_has_an_exact_boundary(value in attr_value()) {
        let depth = attr_depth(&value);
        let mut context = HashMap::new();
        context.insert("value".to_string(), value);
        let request = AuthRequest::new(sample_request()).with_context(context);

        let at_boundary = request.validate_context(RequestLimits {
            max_context_bytes: usize::MAX,
            max_context_depth: depth,
            max_context_keys: usize::MAX,
        });
        prop_assert!(at_boundary.is_ok());

        if depth > 0 {
            let below_boundary = request.validate_context(RequestLimits {
                max_context_bytes: usize::MAX,
                max_context_depth: depth - 1,
                max_context_keys: usize::MAX,
            });
            prop_assert!(below_boundary.is_err());
        }
    }

    #[test]
    fn structurally_consistent_responses_validate(successes in vec(any::<bool>(), 0..64)) {
        let response = valid_response(&successes);
        prop_assert!(response.validate(successes.len()).is_ok());
    }

    #[test]
    fn inconsistent_response_counts_are_rejected(successes in vec(any::<bool>(), 0..64)) {
        let mut response = valid_response(&successes);
        response.successful = response.successful.saturating_add(1);
        prop_assert!(response.validate(successes.len()).is_err());
    }

    #[test]
    fn duplicate_response_indices_are_rejected(successes in vec(any::<bool>(), 2..64)) {
        let mut response = valid_response(&successes);
        response.results[1].index = response.results[0].index;
        prop_assert!(response.validate(successes.len()).is_err());
    }

    #[test]
    fn reordered_response_indices_are_rejected(successes in vec(any::<bool>(), 2..64)) {
        let mut response = valid_response(&successes);
        response.results.swap(0, 1);
        prop_assert!(response.validate(successes.len()).is_err());
    }

    #[test]
    fn mismatched_response_versions_are_rejected(successes in vec(Just(true), 1..64)) {
        let mut response = valid_response(&successes);
        let BatchResult::Success { data } = &mut response.results[0].result else {
            unreachable!("the generated result is always successful");
        };
        data.version = policy_version("different");
        prop_assert!(response.validate(successes.len()).is_err());
    }
}
