#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: check-release-signature.sh TAG REPOSITORY [EXPECTED_COMMIT]}"
repository="${2:?usage: check-release-signature.sh TAG REPOSITORY [EXPECTED_COMMIT]}"
expected_commit="${3:-}"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release tag must be a stable vMAJOR.MINOR.PATCH tag: $tag" >&2
    exit 1
fi

ref_type="$(gh api "repos/$repository/git/ref/tags/$tag" --jq '.object.type')"
if [[ "$ref_type" != "tag" ]]; then
    echo "release tag $tag must be annotated and signed; GitHub reports a $ref_type object" >&2
    exit 1
fi

tag_object="$(gh api "repos/$repository/git/ref/tags/$tag" --jq '.object.sha')"
mapfile -t details < <(
    gh api "repos/$repository/git/tags/$tag_object" \
        --jq '.tag, .object.type, .object.sha, (.verification.verified | tostring), .verification.reason'
)

declared_tag="${details[0]:-}"
target_type="${details[1]:-}"
target_commit="${details[2]:-}"
verified="${details[3]:-false}"
reason="${details[4]:-missing verification result}"

if [[ "$declared_tag" != "$tag" ]]; then
    echo "tag object declares $declared_tag instead of $tag" >&2
    exit 1
fi
if [[ "$target_type" != "commit" ]]; then
    echo "release tag $tag targets a $target_type object instead of a commit" >&2
    exit 1
fi
if [[ -n "$expected_commit" && "$target_commit" != "$expected_commit" ]]; then
    echo "release tag $tag targets $target_commit instead of workflow commit $expected_commit" >&2
    exit 1
fi
if [[ "$verified" != "true" ]]; then
    echo "GitHub did not verify the signature on $tag: $reason" >&2
    exit 1
fi

echo "release tag $tag has a GitHub-verified signature and targets $target_commit"
