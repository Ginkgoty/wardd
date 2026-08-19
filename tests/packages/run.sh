#!/bin/bash
# Build wardd packages inside a clean container for one distribution family and
# run the lifecycle contract test (tests/packages/lifecycle.sh) against them.
#
#   tests/packages/run.sh ubuntu-24.04
#   tests/packages/run.sh rocky-9
#
# Requires Docker. Nothing is installed on the host.
set -euo pipefail

TARGET="${1:?usage: run.sh <ubuntu-24.04|rocky-9>}"
SOURCE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_ID="202601010000.000000000000"

case "$TARGET" in
    ubuntu-24.04) IMAGE="ubuntu:24.04"; FAMILY="deb" ;;
    rocky-9)      IMAGE="rockylinux:9"; FAMILY="rpm" ;;
    *) echo "unknown target: $TARGET" >&2; exit 2 ;;
esac

exec docker run --rm \
    -v "$SOURCE_DIR:/src:ro" \
    -e FAMILY="$FAMILY" -e BUILD_ID="$BUILD_ID" \
    "$IMAGE" bash -euo pipefail -c '
if [ "$FAMILY" = "deb" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq build-essential ca-certificates clang cmake dpkg-dev \
        libbpf-dev libcurl4-openssl-dev libmaxminddb-dev libssl-dev libxdp-dev \
        pkg-config file >/dev/null
    GENERATOR=DEB
else
    dnf -y install dnf-plugins-core >/dev/null 2>&1
    dnf config-manager --set-enabled crb >/dev/null 2>&1
    dnf -y install ca-certificates clang cmake gcc libbpf-devel libcurl-devel \
        libmaxminddb-devel libxdp-devel make openssl-devel pkgconf-pkg-config \
        rpm-build findutils >/dev/null 2>&1
    GENERATOR=RPM
fi

build_channel() {
    local channel="$1" outdir="$2"
    shift 2
    cmake -S /src -B "$outdir" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_SYSCONFDIR=/etc \
        -DWARDD_BUILD_BPF=ON \
        -DWARDD_PACKAGE_CHANNEL="$channel" "$@" >/dev/null
    cmake --build "$outdir" --parallel >/dev/null
    cpack --config "$outdir/CPackConfig.cmake" -G "$GENERATOR" >/dev/null
}

echo "== building nightly and stable packages =="
build_channel nightly /tmp/b-nightly -DWARDD_PACKAGE_BUILD_ID="$BUILD_ID"
build_channel stable  /tmp/b-stable

NIGHTLY=$(find /tmp/b-nightly/packages -type f -name "*.${FAMILY}" | head -1)
STABLE=$(find /tmp/b-stable/packages  -type f -name "*.${FAMILY}" | head -1)
echo "nightly: $(basename "$NIGHTLY")"
echo "stable:  $(basename "$STABLE")"

bash /src/tests/packages/lifecycle.sh "$FAMILY" "$NIGHTLY" "$STABLE"
'
