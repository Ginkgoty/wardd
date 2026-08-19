#!/bin/sh
set -eu

tag=${1:-}

if ! printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "invalid release tag: expected vMAJOR.MINOR.PATCH, got '$tag'" >&2
    exit 1
fi

version=${tag#v}
project_version=$(sed -n \
    's/^[[:space:]]*VERSION[[:space:]]\+\([0-9][0-9.]*\)[[:space:]]*$/\1/p' \
    CMakeLists.txt | head -n 1)

if [ -z "$project_version" ]; then
    echo "cannot read project version from CMakeLists.txt" >&2
    exit 1
fi

if [ "$version" != "$project_version" ]; then
    echo "release tag $tag does not match project version $project_version" >&2
    exit 1
fi

printf '%s\n' "$version"
