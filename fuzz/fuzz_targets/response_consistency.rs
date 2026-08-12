#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_client::{
    AuthorizeBriefResponse, AuthorizeDecisionBrief, BatchResult, DecisionBrief, IndexedResult,
    PolicyVersion,
};

fn take_byte(data: &[u8], cursor: &mut usize) -> u8 {
    let value = data.get(*cursor).copied().unwrap_or_default();
    *cursor = cursor.saturating_add(1);
    value
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = 0;
    let expected = usize::from(take_byte(data, &mut cursor) % 32);
    let result_count = usize::from(take_byte(data, &mut cursor) % 32);
    let version = PolicyVersion {
        hash: "batch".to_string(),
        loaded_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let mut results = Vec::with_capacity(result_count);

    for _ in 0..result_count {
        let index = usize::from(take_byte(data, &mut cursor) % 40);
        let success = take_byte(data, &mut cursor) % 2 == 0;
        let matching_version = take_byte(data, &mut cursor) % 2 == 0;
        let allow = take_byte(data, &mut cursor) % 2 == 0;
        let has_policy = take_byte(data, &mut cursor) % 2 == 0;
        let result = if success {
            BatchResult::Success {
                data: AuthorizeDecisionBrief {
                    decision: if allow {
                        DecisionBrief::Allow
                    } else {
                        DecisionBrief::Deny
                    },
                    version: if matching_version {
                        version.clone()
                    } else {
                        PolicyVersion {
                            hash: "other".to_string(),
                            loaded_at: version.loaded_at.clone(),
                        }
                    },
                    policy_id: if has_policy {
                        "policy".to_string()
                    } else {
                        String::new()
                    },
                },
            }
        } else {
            BatchResult::Failed {
                message: "failed".to_string(),
            }
        };
        results.push(IndexedResult {
            index,
            id: None,
            result,
        });
    }

    let successful = usize::from(take_byte(data, &mut cursor) % 40);
    let failed = usize::from(take_byte(data, &mut cursor) % 40);
    let response = AuthorizeBriefResponse {
        results,
        version,
        successful,
        failed,
    };

    let actual_successful = response
        .results()
        .iter()
        .filter(|result| matches!(result.result, BatchResult::Success { .. }))
        .count();
    let indices_are_ordered = response
        .results()
        .iter()
        .enumerate()
        .all(|(position, result)| result.index == position);
    let versions_match = response
        .results()
        .iter()
        .all(|result| match &result.result {
            BatchResult::Success { data } => data.version == *response.version(),
            BatchResult::Failed { .. } => true,
        });
    let decisions_are_consistent = response
        .results()
        .iter()
        .all(|result| match &result.result {
            BatchResult::Success { data } => match data.decision {
                DecisionBrief::Allow => !data.policy_id.is_empty(),
                DecisionBrief::Deny => data.policy_id.is_empty(),
            },
            BatchResult::Failed { .. } => true,
        });
    let should_validate = response.total() == expected
        && response.successes() == actual_successful
        && response.failures() == response.total() - actual_successful
        && indices_are_ordered
        && versions_match
        && decisions_are_consistent;

    assert_eq!(response.validate(expected).is_ok(), should_validate);
});
