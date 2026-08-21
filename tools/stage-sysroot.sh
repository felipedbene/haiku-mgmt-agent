#!/bin/bash
# stage-sysroot.sh -- populate a usable sysroot for the haiku/arm64 cross-tools.
#
# Adapted from haiku-graviton/ssh/build-openssh-arm64.sh, which explains why this
# is necessary: the cross-tools' own sysroot ships empty, because Haiku's jam
# passes header and library paths explicitly. gcc *is* configured to look in
# <sysroot>/boot/system/develop/{headers,lib}, so filling those two directories
# makes the toolchain work for ordinary (non-jam) projects like this one.
#
# Files are COPIED, not symlinked, into a stable location: jam recreates the
# package staging directories during an image build, and symlinks into them
# vanish mid-compile.
#
# Requires a completed jam image build (the haiku_devel/haiku package staging
# dirs). Safe to re-run.
set -euo pipefail

HAIKU_TOP=${HAIKU_TOP:-/opt/haiku/haiku}
GEN=${GEN:-$HAIKU_TOP/generated.arm64}
SYSROOT=${SYSROOT:-/opt/haiku/sysroot-arm64}
PROFILE=${PROFILE:-minimum}

CT=$GEN/cross-tools-arm64
PB=$GEN/objects/haiku/arm64/packaging/packages_build/$PROFILE
DEVPKG=$PB/hpkg_-haiku_devel.hpkg/contents
RTPKG=$PB/hpkg_-haiku.hpkg/contents

echo "== sanity checks =="
[ -x "$CT/bin/aarch64-unknown-haiku-gcc" ] || { echo "no arm64 cross gcc at $CT/bin" >&2; exit 1; }
[ -d "$DEVPKG/develop/headers/posix" ] || {
    echo "haiku_devel staging dir missing: $DEVPKG" >&2
    echo "(run: cd $GEN && jam -q -j\$(nproc) @${PROFILE}-raw)" >&2
    exit 1
}

echo "== staging sysroot at $SYSROOT =="
SR=$SYSROOT/boot/system
sudo mkdir -p "$SR/develop/lib"
sudo rsync -aL --delete "$DEVPKG/develop/headers/" "$SR/develop/headers/"
# Static libs and the crt glue objects (crti.o, crtn.o, start_dyn.o,
# init_term_dyn.o, haiku_version_glue.o) come from haiku_devel. The .so entries
# there are symlinks to ../../lib, which only resolve on an installed system, so
# they are excluded here and taken from the runtime package below.
sudo rsync -a --delete --exclude '*.so' "$DEVPKG/develop/lib/" "$SR/develop/lib/"

# Mirror the on-device layout: real shared objects in /boot/system/lib, with
# /boot/system/develop/lib holding ../../lib/* symlinks. Doing it this way makes
# the symlinks that haiku_devel and gcc_syslibs_devel already ship resolve,
# instead of leaving them dangling.
sudo mkdir -p "$SR/lib"

# haiku_devel carries only libroot.so and libpackage.so; linking needs
# libnetwork.so (sockets live there on Haiku) and libbsd.so, which exist only in
# the haiku runtime package.
sudo cp -f "$RTPKG"/lib/*.so "$SR/lib/"

# libstdc++ is not part of Haiku itself: it ships in gcc_syslibs, staged by jam
# under build_packages. Without it, g++'s implicit -lstdc++ cannot resolve.
for d in "$GEN"/build_packages/gcc_syslibs-*/lib; do
    [ -d "$d" ] || continue
    sudo cp -af "$d"/. "$SR/lib/"
done

# Expose every runtime library to the linker.
for f in "$SR"/lib/*.so*; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    sudo ln -sfn "../../lib/$b" "$SR/develop/lib/$b"
done

# Point the toolchain's built-in sysroot at the staged tree.
sudo rm -rf "$CT/sysroot"
sudo mkdir -p "$CT/sysroot/boot/system/develop"
sudo ln -sfn "$SR/develop/headers" "$CT/sysroot/boot/system/develop/headers"
sudo ln -sfn "$SR/develop/lib" "$CT/sysroot/boot/system/develop/lib"

echo "== verifying: compile and link a hello world =="
tmp=$(mktemp -d)
cat > "$tmp/t.cpp" <<'EOF'
#include <cstdio>
int main() { std::printf("ok\n"); return 0; }
EOF
"$CT/bin/aarch64-unknown-haiku-g++" -std=c++17 "$tmp/t.cpp" -o "$tmp/t" -lnetwork
file "$tmp/t"
rm -rf "$tmp"
echo "sysroot ready: $SYSROOT"
