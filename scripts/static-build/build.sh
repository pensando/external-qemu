#!/usr/bin/env bash
# Build a fully static (musl/Alpine) QEMU: x86_64/arm/riscv64 softmmu + slirp.
#
# Output lands in build-static/ in the repo root, owned by the invoking user
# (the container runs as the host UID, not root).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE=qemu-static-builder
BUILD_DIR=build-static
DIST_DIR=dist
BINARIES="qemu-system-x86_64 qemu-system-arm qemu-system-riscv64"

if [ -n "${CONTAINER_ENGINE:-}" ]; then
    ENGINE="$CONTAINER_ENGINE"
elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    ENGINE=podman
elif command -v docker >/dev/null 2>&1; then
    ENGINE=docker
else
    echo "error: no working docker or podman found (set CONTAINER_ENGINE to override)" >&2
    exit 1
fi
echo "using container engine: $ENGINE"

cd "$REPO_ROOT"

"$ENGINE" build -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.alpine" "$SCRIPT_DIR"

"$ENGINE" run --rm \
    -v "$REPO_ROOT":/src \
    -w /src \
    "$IMAGE" \
    bash -c "
        set -euo pipefail
        git config --global --add safe.directory /src
        mkdir -p '$BUILD_DIR'
        cd '$BUILD_DIR'
        ../configure \
            --static \
            -Ddefault_library=static \
            --without-default-features \
            --target-list=x86_64-softmmu,arm-softmmu,riscv64-softmmu \
            --enable-slirp \
            --enable-curses \
            --enable-iconv \
            --enable-kvm \
            --enable-guest-agent \
            --enable-tools \
            --enable-linux-aio \
            --enable-attr \
            --disable-docs \
            --extra-cflags=-Wno-error=discarded-qualifiers \
            --extra-ldflags=-Wl,-z,stack-size=8388608
        ninja -j\$(nproc)
    "

# Assemble a small, self-contained dist/ directory: the stripped binaries plus
# firmware blobs laid out as a "qemu-bundle" (see get_relocated_path() in
# util/cutils.c) so QEMU finds pc-bios/ automatically with zero -L/-bios
# flags, as long as the two are copied around together.
echo
echo "=== assembling $DIST_DIR ==="
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/qemu-bundle/usr/local/share/qemu"
for bin in $BINARIES; do
    cp "$BUILD_DIR/$bin" "$DIST_DIR/"
done
cp -r pc-bios/. "$DIST_DIR/qemu-bundle/usr/local/share/qemu/"
# Drop the compressed edk2/UEFI firmware and stray build files: not needed
# unless you boot via UEFI instead of legacy BIOS/OpenSBI, and they're most
# of pc-bios/'s size.
rm -f "$DIST_DIR"/qemu-bundle/usr/local/share/qemu/*.bz2 \
      "$DIST_DIR"/qemu-bundle/usr/local/share/qemu/meson.build \
      "$DIST_DIR"/qemu-bundle/usr/local/share/qemu/README
du -sh "$DIST_DIR"

echo
echo "=== static-linkage check ==="
for bin in $BINARIES; do
    path="$DIST_DIR/$bin"
    if [ -x "$path" ]; then
        echo "-- $bin --"
        file "$path"
        ldd "$path" || true
    fi
done
