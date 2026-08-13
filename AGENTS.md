# Repository Guidelines

These instructions apply to the entire repository. Keep them aligned with the actual project
commands, CI workflows, and release process whenever those change.

## Priorities

- Preserve the Treetop JSON wire contract and the client's security boundaries.
- Prefer small, explicit, typed APIs over convenience that weakens validation or leaks
  implementation details.
- Keep changes scoped to the task. Do not mix refactors, dependency churn, and behavior changes
  without a concrete reason.
- This crate is pre-1.0. API compatibility is not guaranteed between `0.0.x` releases, but breaking
  changes must still be intentional, tested, documented, and called out to users.

## Verification

Run the checks relevant to the change before considering it complete. The normal local baseline is:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --doc
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

- Run `cargo test --all-features` when client transport behavior, endpoint behavior, or server-facing
  types change. This requires Docker and exercises the full suite against the current target server.
- Run the compatibility contract against a specific supported server with:

  ```bash
  TREETOP_TEST_IMAGE=ghcr.io/terjekv/treetop-rest:vX.Y.Z \
    cargo test --features server-tests --test server_compat
  ```

- The supported compatibility matrix is defined in `.github/workflows/ci.yml`. Update the matrix,
  README, documentation, and tests together when changing the supported server range.
- Run `cargo audit --deny warnings` and
  `cargo deny check advisories bans licenses sources` after dependency or policy changes.
- Run `cargo package --locked` for release-related changes and inspect `cargo package --list` when
  changing included or excluded files.
- Run `shellcheck scripts/*.sh` after changing shell scripts.
- Run the relevant `cargo fuzz run <target>` smoke tests after changing parsers, deserialization,
  URL handling, nested context, response consistency, or another untrusted-input boundary.
- If a required external service or Docker is unavailable, run the strongest local subset and state
  exactly what remains unverified. Do not describe an unrun check as passing.

## Architecture

- Keep HTTP transport, response limits, URL construction, and endpoint methods in `src/client/`.
- Keep wire-domain types in `src/types/`, grouped by their API role. Re-export intentional public
  types through `src/types/mod.rs` and `src/lib.rs`.
- Keep request validation in crate-owned types and `src/types/validation.rs`; reject invalid states
  before transport whenever practical.
- Keep error mapping centralized in `TreetopError`. Use specific variants and actionable messages
  rather than collapsing failures into generic strings.
- Keep upload-token behavior in `src/token.rs` and preserve `SecretString` storage, redacted debug
  output, zeroization, and sensitive-header handling.
- Reuse the underlying `reqwest::Client` and connection pool. Do not add blocking work to async
  request paths.
- Avoid expanding exposure of third-party types unless they are the intentional integration surface.
  Prefer crate-owned validated types at public boundaries.

## Wire Compatibility

- Treat `docs/api.md`, server snapshot tests, and released `treetop-rest` behavior as the sources of
  truth for JSON shapes and endpoint semantics.
- Preserve serde field names, enum tagging, omission rules, defaults, and flattening. A Rust
  round-trip alone is not proof of server compatibility; assert the exact JSON shape.
- Add serde and wiremock tests for every new or changed request/response shape.
- Keep newer response fields backward-compatible with older supported servers using defaults only
  where a missing value has a safe and unambiguous meaning.
- Preserve explicit unknown/fallback enum variants where newer servers may add values. Do not turn
  forward-compatible server additions into deserialization failures without a deliberate reason.
- Validate response counts, indices, policy versions, and other cross-field invariants before
  returning data to callers.
- When targeting a new server release, compare its API and snapshots, update `docs/api.md`, README
  compatibility text, the CI matrix, structured tests, and full server tests in the same change.

## Security Boundaries

- Never expose upload tokens in `Debug`, errors, logs, panic messages, test output, or URLs.
- Never send an upload token over non-loopback plaintext HTTP unless the caller explicitly opts in
  through the existing danger-prefixed escape hatch.
- Preserve redirect denial for the default HTTP client so credentials cannot be forwarded to an
  unintended host. Document the responsibility transferred to callers using a custom client.
- Keep base URLs credential-free and reject unsupported schemes, query strings, and fragments.
- Bound successful and error response bodies before buffering them. New response paths must use the
  existing bounded readers or provide an equally strong limit.
- Validate HTTP header values, Cedar identifiers, entity IDs, request IDs, IP addresses/CIDRs,
  context depth, and request sizes at the boundary.
- Do not weaken a secure default or a `danger_*` opt-in without focused regression tests and an
  explicit security rationale in the pull request.
- Avoid panics on network data and other untrusted input. Return typed errors instead.

## Rust Standards

- Follow idiomatic Rust and the repository's existing patterns. The declared MSRV is Rust 1.85;
  do not use newer language or library features in package code unless the MSRV is intentionally
  raised everywhere in the same change.
- Prefer validated newtypes with private fields, constructors, and accessors over unchecked
  primitive values.
- Put behavior on the type that owns the invariant. Prefer small `impl` APIs over collections of
  loosely related helper functions.
- Use builders where several options are involved. Use typestate only when it prevents a meaningful
  invalid call order or missing required state.
- Prefer `use` imports over repeated fully qualified paths, except to resolve ambiguity or make a
  one-off reference clearer.
- Use conventional Rust module discovery (`foo.rs` or `foo/mod.rs`); do not add `#[path = "..."]`
  overrides.
- Do not add dead code, unused fields, broad lint suppressions, or `#[allow(dead_code)]` merely to
  make a build or test pass.
- Keep public items documented and ensure examples compile as doctests where practical.

## Tests

- Keep each test focused on one behavior. Use `rstest` cases for input variants instead of stacking
  unrelated assertions into a single test.
- Put narrow type and invariant tests beside the implementation. Put HTTP contract tests in
  `tests/integration.rs` or another focused integration-test file and use `wiremock`.
- Add property tests for invariants with broad structured input spaces and fuzz targets for parsers
  or other hostile-input boundaries.
- Add full server tests for behavior that a mock cannot establish, and compatibility tests for the
  stable contract shared by all supported server releases.
- Tests that start local mock servers require permission to bind loopback ports. A sandbox denial is
  an environment failure, not a product-test failure; rerun in an environment that permits binding.
- Do not make tests order-dependent. Server-backed tests must use the shared test harness and clean
  up containers and other external resources.

## Dependencies And Packaging

- Keep `Cargo.lock` committed and use `--locked` for release verification. Keep `fuzz/Cargo.lock`
  consistent with the fuzz workspace.
- Preserve the default pure-Rust rustls transport unless an intentional feature design says
  otherwise. Avoid introducing an implicit OpenSSL/system-library requirement.
- Review new licenses, advisories, duplicate versions, default features, and MSRV impact before
  accepting a dependency.
- Keep fuzz-only code excluded from the published crate. Verify packaging whenever `Cargo.toml`,
  repository metadata, documentation paths, or exclusions change.

## Documentation And Changelog

- Update `docs/api.md` when endpoint behavior, headers, error mapping, or wire shapes change.
- Update README examples and compatibility statements when public usage or the target server changes.
- Treat changelog review as required for every pull request. Put user-facing additions, changes,
  fixes, breaking changes, and security notes under `[Unreleased]`.
- If a pull request has no changelog-worthy impact, say so in the PR description rather than adding
  an empty or internal-only entry.
- Call out every breaking change in both the PR description and changelog, including the action a
  user must take to migrate, even though `0.0.x` releases do not promise API compatibility.
- Give every fenced Markdown code block a language (`text` for plain output or diagrams), and keep
  table formatting consistent within each file.

## Pull Requests And Merges

- Use a focused `agent/<description>` branch when starting work from `main`.
- Write imperative commit subjects, keep the first line under 72 characters, and reference issues
  where useful.
- Sign commits. The `main` ruleset requires GitHub-verified commit signatures; do not bypass it.
- The PR body must explain what changed, why, user/developer impact, root cause for fixes, breaking
  behavior, and the validation performed.
- Do not merge with failing or incomplete relevant checks.
- Prefer squash merges for focused changes. Use the substantive PR description as the squash commit
  body, preserving rationale and behavior notes while removing verification-only command lists and
  checklists.
- Use stacked pull requests only for strict linear dependencies where every layer is independently
  reviewable. Keep unrelated or merely sequential work in separate PRs targeting `main`.

## Releases

- Follow `RELEASING.md`; do not improvise around the release workflow.
- Do not bump the package version until the release has a concrete payload.
- Before preparing a release commit, update all Rust dependencies and GitHub Actions to their
  latest stable versions, and pin every Action to its full commit SHA. Refresh every committed
  lockfile, review upstream release notes for compatibility and MSRV changes, and run the full
  verification, RustSec, and cargo-deny checks on the resulting dependency set.
- Land dependency and GitHub Actions updates before the version-bump release commit so the signed
  release tag points at a green commit that already contains every update.
- Before tagging, update `Cargo.toml`, `Cargo.lock`, README installation examples, changelog section
  and comparison links, then run `scripts/check-release.sh vX.Y.Z` from a clean checkout.
- Release commits must be on `main`. Release tags must be signed, annotated
  `vMAJOR.MINOR.PATCH` tags and pass `scripts/check-release-signature.sh` in GitHub Actions.
- Treat pushed tags and crates.io versions as immutable. Fix a failed release with a new commit and
  patch version rather than moving or reusing a published tag.
- Keep crates.io trusted publishing scoped to this repository, `release.yml`, and the `release`
  environment. Do not restore a long-lived publishing token.

## Change Discipline

- Read the surrounding implementation and tests before editing.
- Add or update tests whenever behavior changes or a regression would otherwise be easy to repeat.
- Prefer clear, reviewable code over cleverness, premature abstraction, or broad mechanical churn.
- Preserve unrelated user changes in a dirty worktree and stage only files that belong to the task.
