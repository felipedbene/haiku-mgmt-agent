#!/bin/bash
# build-mbedtls.sh -- cross-build mbedTLS as static libs for haiku/arm64.
#
# This is the whole reason Phase 1 could proceed: haiku/arm64 has no OpenSSL and
# no package repository to get one from (NOTES.md 1). mbedTLS is plain C99 with
# no autotools and no asm, so it cross-builds with just the Haiku cross-gcc --
# which is why it was chosen over porting OpenSSL system-wide (NOTES.md 4, B).
#
# Output: $PREFIX/{include,lib} with libmbedtls.a libmbedx509.a libmbedcrypto.a
set -euo pipefail

VERSION=${VERSION:-3.6.2}
GEN=${GEN:-/opt/haiku/haiku/generated.arm64}
CT=$GEN/cross-tools-arm64
PREFIX=${PREFIX:-/opt/haiku/mbedtls-arm64}
WORK=${WORK:-/opt/haiku/build-mbedtls}
JOBS=${JOBS:-$(nproc)}

CROSS=aarch64-unknown-haiku
export PATH="$CT/bin:$PATH"
command -v $CROSS-gcc >/dev/null || { echo "no $CROSS-gcc in PATH ($CT/bin)" >&2; exit 1; }

mkdir -p "$WORK"
cd "$WORK"

TARBALL=mbedtls-$VERSION.tar.bz2
if [ ! -f "$TARBALL" ]; then
    echo "== fetching mbedTLS $VERSION =="
    curl -fsSLo "$TARBALL" \
        "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$VERSION/$TARBALL"
fi

rm -rf "mbedtls-$VERSION"
tar xf "$TARBALL"
cd "mbedtls-$VERSION"

echo "== building static libs for $CROSS =="
# Haiku puts sockets in libnetwork; nothing in the library build links, so we
# only need the compiler to find headers via the toolchain's sysroot.
make -j"$JOBS" lib \
    CC="$CROSS-gcc" \
    AR="$CROSS-ar" \
    CFLAGS="-O2 -fPIC -D_GNU_SOURCE" \
    SHARED=

echo "== installing to $PREFIX =="
sudo mkdir -p "$PREFIX/lib" "$PREFIX/include"
sudo cp library/libmbedtls.a library/libmbedx509.a library/libmbedcrypto.a "$PREFIX/lib/"
sudo rsync -a include/mbedtls include/psa "$PREFIX/include/"

echo "== verifying archives are aarch64 Haiku objects =="
$CROSS-ar t "$PREFIX/lib/libmbedcrypto.a" | head -3
$CROSS-objdump -f "$PREFIX/lib/libmbedcrypto.a" 2>/dev/null | grep -m1 "file format" || true
echo "mbedTLS ready: $PREFIX"
