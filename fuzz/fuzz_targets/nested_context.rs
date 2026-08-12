#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use treetop_client::{Action, AttrValue, AuthRequest, Request, RequestLimits, Resource, User};

fn take_byte(data: &[u8], cursor: &mut usize) -> u8 {
    let value = data.get(*cursor).copied().unwrap_or_default();
    *cursor = cursor.saturating_add(1);
    value
}

fn attr_value(data: &[u8], cursor: &mut usize, depth: usize) -> AttrValue {
    if depth >= 32 || *cursor >= data.len() {
        return AttrValue::Long(i64::from(take_byte(data, cursor)));
    }

    match take_byte(data, cursor) % 4 {
        0 => AttrValue::Bool(take_byte(data, cursor) % 2 == 0),
        1 => AttrValue::Long(i64::from(take_byte(data, cursor))),
        2 => {
            let length = usize::from(take_byte(data, cursor) % 32);
            let start = (*cursor).min(data.len());
            let end = start.saturating_add(length).min(data.len());
            let value = String::from_utf8_lossy(&data[start..end]).into_owned();
            *cursor = end;
            AttrValue::String(value)
        }
        _ => {
            let length = usize::from(take_byte(data, cursor) % 8);
            AttrValue::Set(
                (0..length)
                    .map(|_| attr_value(data, cursor, depth + 1))
                    .collect(),
            )
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = 0;
    let mut context = HashMap::new();
    let entries = usize::from(take_byte(data, &mut cursor) % 32);
    for index in 0..entries {
        context.insert(format!("key_{index}"), attr_value(data, &mut cursor, 0));
    }

    let request = AuthRequest::new(Request::new(
        User::new("fuzzer").unwrap(),
        Action::new("check").unwrap(),
        Resource::new("Document", "target").unwrap(),
    ))
    .with_context(context)
    .unwrap();
    let limits = RequestLimits {
        max_batch_size: None,
        max_context_bytes: usize::from(take_byte(data, &mut cursor)) * 128,
        max_context_depth: usize::from(take_byte(data, &mut cursor) % 40),
        max_context_keys: usize::from(take_byte(data, &mut cursor) % 40),
    };
    let _ = request.validate();
    let _ = request.validate_context(limits);
    let _ = serde_json::to_vec(&request);
});
