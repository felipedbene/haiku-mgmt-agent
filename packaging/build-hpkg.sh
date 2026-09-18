#!/bin/bash
# build-hpkg.sh -- assemble and create debeos_ssm_agent-<ver>-<rev>-arm64.hpkg.
#
# Reproducible packaging of the agent. Works two ways:
#   * NATIVE (on a DeBeOS/Haiku arm64 box): the `package` tool is on PATH at
#     /boot/system/bin/package -- the default below finds it.
#   * CROSS (on the Linux cross-build host): set PACKAGE_TOOL to the `package`
#     host tool that jam builds under generated.arm64/objects/linux/.../tools.
#
# The result installs on DeBeOS/Haiku with `pkgman install -y <file>` and is
# what the AMI bake drops into system/packages (glob debeos_ssm_agent-*).
#
# Usage: packaging/build-hpkg.sh            (after `make strip`)
#   VERSION=0.5.0 REVISION=1 to override; PACKAGE_TOOL to point elsewhere.
#
# ZLIB, not the tool's default zstd: the lean arm64 AMI's packagefs has no zstd
# reader (the zstd build feature is off), so a zstd-compressed hpkg lands in
# system/packages but fails to activate ("Failed to decompress chunk data:
# Operation not supported"). zlib activates in both the lean image and a full
# runtime install. See DeBeOS graviton/ssh/UserBuildConfig.
set -euo pipefail

VERSION=${VERSION:-$(sed -n 's/.*kAgentVersion = "\(.*\)".*/\1/p' "$(dirname "$0")/../src/main.cpp")}
REVISION=${REVISION:-1}
ARCH=${ARCH:-arm64}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Prefer the native package tool; fall back to the cross-build host tool.
if [ -z "${PACKAGE_TOOL:-}" ]; then
	if [ -x /boot/system/bin/package ]; then
		PACKAGE_TOOL=/boot/system/bin/package
	else
		PACKAGE_TOOL=/opt/haiku/haiku/generated.arm64/objects/linux/arm64/release/tools/package/package
	fi
fi

BIN=$ROOT/build/haiku-mgmt-agent
[ -f "$BIN" ] || { echo "no $BIN -- run make && make strip first" >&2; exit 1; }
[ -x "$PACKAGE_TOOL" ] || { echo "no package tool at $PACKAGE_TOOL" >&2; exit 1; }

PKGROOT=$ROOT/build/pkgroot
rm -rf "$PKGROOT"
mkdir -p "$PKGROOT/bin" "$PKGROOT/data/launch" "$PKGROOT/data/licenses"

# Installed binary name is debeos-ssm-agent (the fleet + bake scripts reference
# /boot/system/bin/debeos-ssm-agent).
cp "$BIN" "$PKGROOT/bin/debeos-ssm-agent"
chmod 755 "$PKGROOT/bin/debeos-ssm-agent"
# The packaged launch job passes --metrics (CloudWatch host metrics default-on).
cp "$ROOT/packaging/launch/debeos_ssm_agent-packaged" "$PKGROOT/data/launch/debeos_ssm_agent"
cp "$ROOT/LICENSE" "$PKGROOT/data/licenses/MIT"

sed -e "s/@VERSION@/$VERSION-$REVISION/" \
    -e "s/@PLAIN_VERSION@/$VERSION/" \
    -e "s/@ARCH@/$ARCH/" \
    "$ROOT/packaging/PackageInfo.in" > "$PKGROOT/.PackageInfo"

OUT=$ROOT/build/debeos_ssm_agent-$VERSION-$REVISION-$ARCH.hpkg
rm -f "$OUT"
"$PACKAGE_TOOL" create -z zlib -C "$PKGROOT" "$OUT"
echo "created $OUT"
sha256sum "$OUT"
