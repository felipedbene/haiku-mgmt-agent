#!/bin/bash
# build-hpkg.sh -- assemble and create haiku_mgmt_agent-<ver>-<rev>-arm64.hpkg.
#
# Replaces the by-hand packaging of v0.1.0 with something reproducible. Runs on
# the cross-build host (the `package` host tool comes out of the Haiku jam
# build); the result installs on Haiku with `pkgman install -y <file>` and is
# what the self-update manifest (F3) points at.
#
# Usage: packaging/build-hpkg.sh            (after `make strip`)
#   VERSION=0.2.0 REVISION=1 to override; PACKAGE_TOOL to point elsewhere.
set -euo pipefail

VERSION=${VERSION:-$(sed -n 's/.*kAgentVersion = "\(.*\)".*/\1/p' "$(dirname "$0")/../src/main.cpp")}
REVISION=${REVISION:-1}
ARCH=${ARCH:-arm64}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PACKAGE_TOOL=${PACKAGE_TOOL:-/opt/haiku/haiku/generated.arm64/objects/linux/arm64/release/tools/package/package}

BIN=$ROOT/build/haiku-mgmt-agent
[ -f "$BIN" ] || { echo "no $BIN -- run make && make strip first" >&2; exit 1; }
[ -x "$PACKAGE_TOOL" ] || { echo "no package tool at $PACKAGE_TOOL" >&2; exit 1; }

PKGROOT=$ROOT/build/pkgroot
rm -rf "$PKGROOT"
mkdir -p "$PKGROOT/bin" "$PKGROOT/data/launch" "$PKGROOT/data/licenses"

cp "$BIN" "$PKGROOT/bin/haiku-mgmt-agent"
chmod 755 "$PKGROOT/bin/haiku-mgmt-agent"
# The packaged launch job (starts /boot/system/bin/haiku-mgmt-agent); the
# non-packaged variant stays in packaging/launch/haiku-mgmt-agent.
cp "$ROOT/packaging/launch/haiku-mgmt-agent-packaged" "$PKGROOT/data/launch/haiku-mgmt-agent"
cp "$ROOT/LICENSE" "$PKGROOT/data/licenses/MIT"

sed -e "s/@VERSION@/$VERSION-$REVISION/" \
    -e "s/@PLAIN_VERSION@/$VERSION/" \
    -e "s/@ARCH@/$ARCH/" \
    "$ROOT/packaging/PackageInfo.in" > "$PKGROOT/.PackageInfo"

OUT=$ROOT/build/haiku_mgmt_agent-$VERSION-$REVISION-$ARCH.hpkg
rm -f "$OUT"
"$PACKAGE_TOOL" create -C "$PKGROOT" "$OUT"
echo "created $OUT"
sha256sum "$OUT"
