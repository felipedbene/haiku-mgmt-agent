#!/bin/bash
# build-cloudwatch-hpkg.sh -- assemble and create debeos_cloudwatch-<ver>-<rev>-arm64.hpkg.
#
# The standalone CloudWatch host-metrics daemon (#119). Build first with:
#   make cloudwatch && make strip-cloudwatch
#
# Works two ways:
#   * NATIVE (on a DeBeOS/Haiku arm64 box): the `package` tool is at
#     /boot/system/bin/package -- the default below finds it.
#   * CROSS (on the Linux cross-build host): set PACKAGE_TOOL to the `package`
#     host tool that jam builds under generated.arm64/objects/linux/.../tools.
#
# ZLIB, not the tool's default zstd: the lean arm64 AMI's packagefs has no zstd
# reader, so a zstd-compressed hpkg lands in system/packages but fails to
# activate. See DeBeOS graviton/ssh/UserBuildConfig.
set -euo pipefail

VERSION=${VERSION:-$(sed -n 's/.*kVersion = "\(.*\)".*/\1/p' "$(dirname "$0")/../src/cw_metrics_main.cpp")}
REVISION=${REVISION:-1}
ARCH=${ARCH:-arm64}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [ -z "${PACKAGE_TOOL:-}" ]; then
	if [ -x /boot/system/bin/package ]; then
		PACKAGE_TOOL=/boot/system/bin/package
	else
		PACKAGE_TOOL=/opt/haiku/haiku/generated.arm64/objects/linux/arm64/release/tools/package/package
	fi
fi

BIN=$ROOT/build/debeos-cloudwatch
[ -f "$BIN" ] || { echo "no $BIN -- run make cloudwatch && make strip-cloudwatch first" >&2; exit 1; }
[ -x "$PACKAGE_TOOL" ] || { echo "no package tool at $PACKAGE_TOOL" >&2; exit 1; }

PKGROOT=$ROOT/build/pkgroot-cloudwatch
rm -rf "$PKGROOT"
mkdir -p "$PKGROOT/bin" "$PKGROOT/data/launch" "$PKGROOT/data/licenses"

cp "$BIN" "$PKGROOT/bin/debeos-cloudwatch"
chmod 755 "$PKGROOT/bin/debeos-cloudwatch"
cp "$ROOT/packaging/cloudwatch/launch/debeos_cloudwatch" "$PKGROOT/data/launch/debeos_cloudwatch"
cp "$ROOT/LICENSE" "$PKGROOT/data/licenses/MIT"

sed -e "s/@VERSION@/$VERSION-$REVISION/" \
    -e "s/@PLAIN_VERSION@/$VERSION/" \
    -e "s/@ARCH@/$ARCH/" \
    "$ROOT/packaging/cloudwatch/PackageInfo.in" > "$PKGROOT/.PackageInfo"

OUT=$ROOT/build/debeos_cloudwatch-$VERSION-$REVISION-$ARCH.hpkg
rm -f "$OUT"
"$PACKAGE_TOOL" create -z zlib -C "$PKGROOT" "$OUT"
echo "created $OUT"
sha256sum "$OUT"
