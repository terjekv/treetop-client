# Wire format reference

This document describes the exact JSON wire format for all request and response
types exchanged between `treetop-client` and a Treetop REST server. Use this as
a reference when debugging or building interoperable clients.

All endpoints live under `/api/v1/` except for `/metrics`.

## Endpoints summary

| Method | Path | Client method | Response type |
| ------ | ---- | ------------- | ------------- |
| GET | `/api/v1/health` | `health()` | `{}` (empty) |
| GET | `/api/v1/version` | `version()` | `VersionInfo` |
| GET | `/api/v1/status` | `status()` | `StatusResponse` |
| POST | `/api/v1/authorize?detail=brief` | `authorize()` | `AuthorizeBriefResponse` |
| POST | `/api/v1/authorize?detail=full` | `authorize_detailed()` | `AuthorizeDetailedResponse` |
| GET | `/api/v1/policies` | `get_policies()` | `PoliciesDownload` |
| GET | `/api/v1/policies?format=raw` | `get_policies_raw()` | Plain text |
| POST | `/api/v1/policies` | `upload_policies_raw()` / `upload_policies_json()` | `PoliciesMetadata` |
| GET | `/api/v1/schema` | `get_schema()` | `SchemaDownload` |
| GET | `/api/v1/schema?format=raw` | `get_schema_raw()` | Plain text |
| POST | `/api/v1/schema` | `upload_schema_raw()` / `upload_schema_json()` | `PoliciesMetadata` |
| GET | `/api/v1/policies/{user}` | `get_user_policies()` | `UserPolicies` |
| GET | `/metrics` | `metrics()` | Plain text (Prometheus) |

## Headers

| Header | When | Purpose |
| ------ | ---- | ------- |
| `x-correlation-id` | Any request | Optional request tracing ID, set via `with_correlation_id()` |
| `X-Upload-Token` | `POST /api/v1/policies`, `POST /api/v1/schema` | Required authentication token for uploads |
| `Content-Type` | `POST /api/v1/policies`, `POST /api/v1/schema` | `text/plain` for raw Cedar DSL or schema JSON, `application/json` for JSON-wrapped |

## Error responses

All error responses use the same shape regardless of endpoint:

```json
{
  "error": "Human-readable error message"
}
```

HTTP status codes:

- **400** -- invalid payload, invalid Cedar DSL, validation errors
- **403** -- upload not allowed, invalid or missing upload token
- **500** -- internal server error (lock poisoning, evaluation failure)

Mapped to `TreetopError::Api { status, message }` in the client.

## Type reference

### Principal

Externally tagged enum -- either `User` or `Group`:

```json
{ "User": { "id": "alice", "namespace": ["MyApp"], "groups": [{ "id": "admins", "namespace": [] }] } }
```

```json
{ "Group": { "id": "admins", "namespace": ["MyApp"] } }
```

### User

```json
{
  "id": "alice",
  "namespace": [],
  "groups": [
    { "id": "admins", "namespace": [] },
    { "id": "editors", "namespace": [] }
  ]
}
```

- `id` (string, required): user identifier.
- `namespace` (array of strings): Cedar namespace path. Empty array if no namespace.
- `groups` (array of Group): group memberships. Empty array if none.

### Group

```json
{
  "id": "admins",
  "namespace": ["MyApp"]
}
```

- `id` (string, required): group identifier.
- `namespace` (array of strings): Cedar namespace path. Empty array if no namespace.

### Action

```json
{
  "id": "create_host",
  "namespace": ["DNS"]
}
```

- `id` (string, required): action identifier.
- `namespace` (array of strings): Cedar namespace path. Empty array if no namespace.

### Resource

```json
{
  "kind": "Host",
  "id": "web-01.example.com",
  "attrs": {
    "ip": { "type": "Ip", "value": "10.0.0.1" },
    "environment": { "type": "String", "value": "production" },
    "critical": { "type": "Bool", "value": true },
    "priority": { "type": "Long", "value": 1 },
    "tags": { "type": "Set", "value": [{ "type": "String", "value": "web" }] }
  }
}
```

- `kind` (string, required): resource entity type name.
- `id` (string, required): resource identifier.
- `attrs` (object, optional): typed key-value attributes. Omitted from JSON when empty.

### AttrValue

Adjacently tagged enum using `type` and `value` fields:

| Type | Value | Example |
| ---- | ----- | ------- |
| `String` | string | `{ "type": "String", "value": "hello" }` |
| `Bool` | boolean | `{ "type": "Bool", "value": true }` |
| `Long` | 64-bit integer | `{ "type": "Long", "value": 42 }` |
| `Ip` | IP address or CIDR string | `{ "type": "Ip", "value": "10.0.0.0/8" }` |
| `Set` | array of AttrValue | `{ "type": "Set", "value": [{ "type": "String", "value": "a" }] }` |

### Request

A single authorization check (principal + action + resource):

```json
{
  "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
  "action": { "id": "view", "namespace": [] },
  "resource": { "kind": "Document", "id": "doc-42" }
}
```

### AuthRequest

A `Request` with an optional client-provided correlation ID and optional request-scoped
`context`. The `Request` fields are flattened (not nested) into the same JSON object:

```json
{
  "id": "check-1",
  "context": {
    "env": { "type": "String", "value": "prod" }
  },
  "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
  "action": { "id": "view", "namespace": [] },
  "resource": { "kind": "Document", "id": "doc-42" }
}
```

### AuthorizeRequest

The request body for `POST /api/v1/authorize`:

```json
{
  "requests": [
    {
      "id": "check-1",
      "principal": { "User": { "id": "alice", "namespace": [], "groups": [] } },
      "action": { "id": "view", "namespace": [] },
      "resource": { "kind": "Document", "id": "doc-42" }
    },
    {
      "principal": { "User": { "id": "bob", "namespace": [], "groups": [] } },
      "action": { "id": "edit", "namespace": [] },
      "resource": { "kind": "Document", "id": "doc-42" }
    }
  ]
}
```

The `id` field is optional on each request. Requests without an `id` will not
have an `id` field in the corresponding response result.

The `context` field is optional on each request. When present, its values use the
same `AttrValue` encoding as resource attributes.

### AuthorizeBriefResponse

Response from `POST /api/v1/authorize?detail=brief`:

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "decision": "Allow",
        "policy_id": "default-permit",
        "version": {
          "hash": "c82d1168...",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 1,
      "status": "success",
      "result": {
        "decision": "Deny",
        "policy_id": "",
        "version": {
          "hash": "c82d1168...",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    },
    {
      "index": 2,
      "status": "failed",
      "error": "Evaluation failed: invalid resource"
    }
  ],
  "version": {
    "hash": "c82d1168...",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 2,
  "failed": 1
}
```

Each result is tagged with `"status": "success"` or `"status": "failed"`:

- **Success**: contains a `result` object with `decision` (`Allow` or `Deny`),
  `policy_id` (semicolon-separated matching policy IDs, empty string if denied),
  and `version`.
- **Failed**: contains an `error` string describing the evaluation failure.

The `id` field is only present if the corresponding request had one.

### AuthorizeDetailedResponse

Response from `POST /api/v1/authorize?detail=full`:

```json
{
  "results": [
    {
      "index": 0,
      "id": "check-1",
      "status": "success",
      "result": {
        "policy": [
          {
            "literal": "permit(principal == User::\"alice\", action, resource);",
            "json": { "effect": "permit", "...": "..." },
            "annotation_id": "allow-alice",
            "cedar_id": "policy0"
          }
        ],
        "decision": "Allow",
        "version": {
          "hash": "c82d1168...",
          "loaded_at": "2025-12-19T00:14:38.577289000Z"
        }
      }
    }
  ],
  "version": {
    "hash": "c82d1168...",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  },
  "successful": 1,
  "failed": 0
}
```

The `policy` array contains the full Cedar DSL (`literal`) and JSON representation
of each matching policy. The `annotation_id` is the policy's `@id` annotation if
present; otherwise `null`. The `cedar_id` is the engine-assigned identifier.

### SchemaDownload

Response from `GET /api/v1/schema`:

```json
{
  "schema": {
    "timestamp": "2026-01-01T00:00:00Z",
    "sha256": "schema-hash",
    "size": 411,
    "entries": 1,
    "content": "{\"\": {\"entityTypes\": {}, \"actions\": {}}}"
  }
}
```

The `schema` field uses the same `Metadata` shape as policy and label downloads.

### PolicyVersion

Appears in authorization responses and version info:

```json
{
  "hash": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
  "loaded_at": "2025-12-19T00:14:38.577289000Z"
}
```

### VersionInfo

Response from `GET /api/v1/version`:

```json
{
  "version": "0.1.0",
  "core": {
    "version": "0.3.0",
    "cedar": "0.11.0"
  },
  "policies": {
    "hash": "c82d1168...",
    "loaded_at": "2025-12-19T00:14:38.577289000Z"
  }
}
```

### StatusResponse

Response from `GET /api/v1/status`:

```json
{
  "policy_configuration": {
    "allow_upload": false,
    "policies": {
      "timestamp": "2025-12-19T00:14:38.577289000Z",
      "sha256": "c82d1168...",
      "size": 2049,
      "source": "https://example.com/policies.cedar",
      "refresh_frequency": 300,
      "entries": 42,
      "content": "permit(...);\nforbid(...);"
    },
    "labels": {
      "timestamp": "2025-12-19T00:10:00.123456000Z",
      "sha256": "a1b2c3d4...",
      "size": 512,
      "entries": 10,
      "content": "..."
    }
  },
  "parallel_configuration": {
    "cpu_count": 8,
    "worker_threads": 4,
    "parallel_cutoff": 5
  }
}
```

The `source` and `refresh_frequency` fields are optional (omitted when policies
were loaded from a file rather than a URL). The `parallel_configuration` field
is represented as opaque JSON (`serde_json::Value`) since its shape may vary
between server versions.

### Metadata

Appears within `StatusResponse` and `PoliciesDownload`:

```json
{
  "timestamp": "2025-12-19T00:14:38.577289000Z",
  "sha256": "c82d116854d77bf689c3d15e167764876dffe869c970bc08ab7c5dacd7726219",
  "size": 2049,
  "source": "https://example.com/policies.cedar",
  "refresh_frequency": 300,
  "entries": 42,
  "content": "permit(...);"
}
```

### PoliciesDownload

Response from `GET /api/v1/policies` (JSON mode):

```json
{
  "policies": {
    "timestamp": "...",
    "sha256": "...",
    "size": 2049,
    "entries": 42,
    "content": "permit(...);"
  }
}
```

### UserPolicies

Response from `GET /api/v1/policies/{user}`:

```json
{
  "user": "alice",
  "policies": [
    { "effect": "permit", "principal": { "...": "..." }, "action": { "...": "..." }, "resource": { "...": "..." } },
    { "effect": "permit", "...": "..." }
  ]
}
```

The `policies` array contains each matching policy in Cedar JSON format.

### PoliciesMetadata

Response from `POST /api/v1/policies` (successful upload):

```json
{
  "allow_upload": true,
  "policies": {
    "timestamp": "...",
    "sha256": "...",
    "size": 1024,
    "entries": 5,
    "content": "permit(...);"
  },
  "labels": {
    "timestamp": "...",
    "sha256": "...",
    "size": 0,
    "entries": 0,
    "content": ""
  }
}
```

## Query parameters

### Authorization endpoint

| Parameter | Values | Default | Purpose |
| --------- | ------ | ------- | ------- |
| `detail` | `brief`, `full`, `detailed` | `brief` | Controls response verbosity. `full` and `detailed` are equivalent. |

### Policies endpoints

| Parameter | Values | Default | Purpose |
| --------- | ------ | ------- | ------- |
| `format` | `raw`, `text`, (omit) | JSON | `raw` or `text` returns plain Cedar DSL text instead of JSON. |

### User policies endpoint

| Parameter | Values | Purpose |
| --------- | ------ | ------- |
| `namespaces[]` | string (repeatable) | Filter policies by Cedar namespace. |
| `groups[]` | string (repeatable) | Include group memberships for policy matching. |
| `format` | `raw`, `text`, (omit) | Return plain text instead of JSON. |
