#![no_main]

use std::collections::HashSet;

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
        let result = if success {
            BatchResult::Success {
                data: AuthorizeDecisionBrief {
                    decision: DecisionBrief::Allow,
                    version: if matching_version {
                        version.clone()
                    } else {
                        PolicyVersion {
                            hash: "other".to_string(),
                            loaded_at: version.loaded_at.clone(),
                        }
                    },
                    policy_id: "policy".to_string(),
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
    let unique_indices = response
        .results()
        .iter()
        .map(|result| result.index)
        .collect::<HashSet<_>>();
    let versions_match = response
        .results()
        .iter()
        .all(|result| match &result.result {
            BatchResult::Success { data } => data.version == *response.version(),
            BatchResult::Failed { .. } => true,
        });
    let should_validate = response.total() == expected
        && response.successes() == actual_successful
        && response.failures() == response.total() - actual_successful
        && unique_indices.len() == expected
        && unique_indices.iter().all(|index| *index < expected)
        && versions_match;

    assert_eq!(response.validate(expected).is_ok(), should_validate);
});
