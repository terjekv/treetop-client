#![cfg(feature = "server-tests")]

mod common;

use common::server;
use serial_test::serial;

const SCHEMA_BACKED_CONTEXT_SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "Group": {},
      "Photo": {}
    },
    "actions": {
      "view": {
        "appliesTo": {
          "principalTypes": ["Group"],
          "resourceTypes": ["Photo"],
          "context": {
            "type": "Record",
            "attributes": {
              "env": {
                "type": "String",
                "required": true
              }
            },
            "additionalAttributes": false
          }
        }
      }
    }
  }
}"#;

#[tokio::test]
#[serial]
async fn upload_schema_enables_schema_backed_context_runtime() {
    let s = server().await;
    let admin = s.client_with_token();

    let metadata = admin
        .upload_schema_raw(SCHEMA_BACKED_CONTEXT_SCHEMA_JSON)
        .await
        .unwrap();
    assert!(
        metadata.schema.is_some(),
        "schema metadata should be populated"
    );

    let downloaded = s.client().get_schema().await.unwrap();
    assert_eq!(downloaded.schema.content, SCHEMA_BACKED_CONTEXT_SCHEMA_JSON);

    let raw = s.client().get_schema_raw().await.unwrap();
    assert_eq!(raw, SCHEMA_BACKED_CONTEXT_SCHEMA_JSON);

    let status = s.client().status().await.unwrap();
    assert!(status.request_context.supported);
    assert!(status.request_context.schema_backed);
    assert_eq!(status.request_context.fallback_reason, None);
}
