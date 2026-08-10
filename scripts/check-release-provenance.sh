#!/usr/bin/env bash
set -euo pipefail

release_commit="${1:?usage: check-release-provenance.sh COMMIT MAIN_REF}"
main_ref="${2:?usage: check-release-provenance.sh COMMIT MAIN_REF}"

if ! git merge-base --is-ancestor "$release_commit" "$main_ref"; then
    echo "release commit $release_commit is not reachable from $main_ref" >&2
    exit 1
fi

echo "release commit $release_commit is reachable from $main_ref"
