# Breaking 0.1.0 migration

Upgrade to the coordinated REST 0.1.0 contract. Early releases prioritize correctness
and a strict current contract over compatibility; no old-server adapters remain.

- Replace `health()` with `livez()` for liveness and `readyz()` for readiness.
- Replace deprecated `try_new`, `try_with_namespace`, and `try_with_attr` aliases
  with their fallible `new`, `with_namespace`, and `with_attr` methods.
- Build identified requests with `AuthRequest::new(request).with_id(id)` and add
  context with `with_context`. Use `add_request_with_id` on authorization batches.
- Every policy version must contain `hash`, `loaded_at`, `label_set`, and
  `generation`. Explicit null is valid for `label_set`; omission is not. Generation
  is an unsigned 64-bit integer local to an engine instance.
- Status requires schema metadata, schema-validation mode, request limits, and
  request-context capabilities. `max_batch_size` is an unsigned integer. Metadata
  sources must be URL objects; bare strings are rejected. Policy listings require
  match metadata and remain non-authoritative candidates, never allow decisions.

## Label configuration

REST and Bundle rules use the same explicit target syntax:

```json
{
  "target": {"resource_type": "App::Host", "attribute": "labels"},
  "field": "name",
  "patterns": [{"name": "prod", "regex": "^prod"}]
}
```

Replace old `kind`/`output` keys, set module and bundle manifests to format 2,
rebuild archives, and re-sign them. One owner exists per exact resource-type and
attribute tuple. Scope controls sanitization too: a labeler for `App::Host.labels`
does not clear `Other::Host.labels`. Constrain resource types in policies before
trusting derived labels. Invalid configuration and failed reloads fail closed.

## Candidate verification

CI builds the exact REST candidate pinned in its workflow and runs the full
server suite against it. After approval, release Core, Bundle, and REST before
publishing this SDK and upgrading CLI consumers. Do not merge or release before
user approval.
