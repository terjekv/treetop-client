#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: check-release.sh vMAJOR.MINOR.PATCH}"
if [[ ! "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "release tag must be a stable vMAJOR.MINOR.PATCH tag: $tag" >&2
    exit 1
fi

version="${tag#v}"
manifest_version="$(sed -nE 's/^version = "([^"]+)"/\1/p' Cargo.toml | head -n1)"
if [[ "$manifest_version" != "$version" ]]; then
    echo "tag $tag does not match Cargo.toml version $manifest_version" >&2
    exit 1
fi

if ! grep -Fq "## [$version]" CHANGELOG.md; then
    echo "CHANGELOG.md has no release heading for $version" >&2
    exit 1
fi

if [[ -n "$(git status --short)" ]]; then
    echo "release checkout contains uncommitted changes" >&2
    exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "tag=$tag"
        echo "version=$version"
    } >> "$GITHUB_OUTPUT"
fi

echo "release metadata is consistent for $tag"
