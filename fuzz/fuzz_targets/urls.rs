#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_client::Client;

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    if let Ok(client) = Client::builder(value.as_ref()).build() {
        let _ = client.with_correlation_id(value.as_ref());
        let _ = client.without_correlation_id();
    }
});
