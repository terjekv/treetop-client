# Contributing to treetop-client

Thank you for considering contributing to treetop-client.

## Getting started

1. Fork the repository and clone your fork.
2. Make sure you have Rust 1.85+ installed (`rustup update stable`).
3. Run the local verification baseline below.

## Development workflow

### Before submitting a PR

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --doc
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Run `cargo test --all-features` after transport, endpoint, or server-facing type changes; it
requires Docker. After dependency or policy changes, also run:

```bash
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

Run relevant fuzz targets after changing an untrusted-input boundary, and use
`cargo package --locked` when release or package contents change. All applicable checks must pass.
If an external service or tool is unavailable, state exactly which check remains unverified.

### Code style

- Follow existing patterns in the codebase.
- All public items (structs, enums, methods, functions, type aliases) must have doc comments.
- Prefer builder patterns over constructors with many parameters.
- Keep serde attributes wire-compatible with the Treetop REST API.

### Testing

- Unit tests go in `#[cfg(test)] mod tests` within the source file.
- Integration tests go in `tests/`.
- Use `wiremock` for HTTP integration tests.
- Test serde round-trips for any new or modified types.
- Add property tests for invariants with broad structured input spaces.
- Add or update a `cargo-fuzz` target for parsers and other untrusted-input boundaries.

The `TREETOP_TEST_IMAGE` environment variable selects the container image used by server tests.
CI runs the stable compatibility contract against treetop-rest v0.0.4 through v0.0.11 and the full
suite against v0.0.10.

### Wire compatibility

This crate replicates types from `treetop-core` and `treetop-rest` for JSON wire
compatibility. When modifying types:

- Check the exact JSON format against the server's snapshot tests or `docs/api.md`.
- Verify serde round-trip correctness with a test.
- Do not add `#[serde(skip)]` or change field names without confirming the server
  produces the same output.

### Commit messages

- Use imperative mood ("Fix bug" not "Fixed bug").
- Keep the first line under 72 characters.
- Reference issues where applicable.

## Reporting issues

- Use GitHub Issues for bug reports and feature requests.
- Include the treetop-client version, Rust version, and server version if relevant.
- For bugs, include a minimal reproduction case.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
