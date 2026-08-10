#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_client::{
    Action, AuthorizeBriefResponse, AuthorizeRequest, Group, Request, Resource, StatusResponse,
    User, VersionInfo,
};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Action>(data).and_then(|value| serde_json::to_vec(&value));
    let _ = serde_json::from_slice::<Group>(data).and_then(|value| serde_json::to_vec(&value));
    let _ = serde_json::from_slice::<User>(data).and_then(|value| serde_json::to_vec(&value));
    let _ = serde_json::from_slice::<Resource>(data).and_then(|value| serde_json::to_vec(&value));
    let _ = serde_json::from_slice::<Request>(data).and_then(|value| serde_json::to_vec(&value));
    let _ = serde_json::from_slice::<AuthorizeRequest>(data).and_then(|value| {
        let _ = value.validate();
        serde_json::to_vec(&value)
    });
    let _ = serde_json::from_slice::<AuthorizeBriefResponse>(data).and_then(|value| {
        let _ = value.validate(value.total());
        serde_json::to_vec(&value)
    });
    let _ =
        serde_json::from_slice::<StatusResponse>(data).and_then(|value| serde_json::to_vec(&value));
    let _ =
        serde_json::from_slice::<VersionInfo>(data).and_then(|value| serde_json::to_vec(&value));
});
