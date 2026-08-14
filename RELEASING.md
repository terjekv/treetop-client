# Releasing treetop-client

Releases are driven by stable `vMAJOR.MINOR.PATCH` tags. The release workflow verifies that the
tag is annotated and has a GitHub-verified signature, points to a commit on `main`, matches the
package version and changelog, passes the complete CI suite, publishes the crate, and creates the
GitHub release.

## First release: v0.0.1

crates.io trusted publishing can only be configured after the crate exists. Bootstrap the first
release with one of these approaches:

1. Recommended automated bootstrap:
   - Create a short-lived crates.io API token capable of publishing a new crate.
   - Create the GitHub environment named `release`, ideally with required-reviewer protection.
   - Store the token as the `CRATES_IO_BOOTSTRAP_TOKEN` environment secret.
   - Merge the release commit to `main`, create the signed tag `v0.0.1`, and push it.
   - After the workflow publishes, configure the crates.io trusted publisher for repository
     `treetop-policy-engine/treetop-client`, workflow `release.yml`, and environment `release`.
   - Revoke the bootstrap token and delete the GitHub secret.

2. Manual bootstrap:
   - From the exact clean release commit, run `cargo publish --locked` with a short-lived token.
   - Create and push `v0.0.1`. The workflow detects the existing crate version, skips publishing,
     and creates the GitHub release after all checks pass.

## Subsequent releases

1. Update `version` in `Cargo.toml` and refresh `Cargo.lock`.
2. Move the accumulated `CHANGELOG.md` entries from `[Unreleased]` into a dated section matching
   the new version, and update the comparison links.
3. Run `scripts/check-release.sh vX.Y.Z` from a clean checkout and complete the local checks in
   `CONTRIBUTING.md`.
4. Merge signed commits to `main`, then create and push the signed annotated tag:

   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

With the trusted publisher configured, the workflow uses a short-lived OIDC credential and needs
no long-lived crates.io secret. Published crates.io versions are immutable, so never reuse a tag or
package version. Treat a pushed release tag as immutable as well; if a release fails, fix the
problem in a new commit and publish a new patch version instead of moving the tag.
