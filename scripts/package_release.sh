#!/usr/bin/env bash
# Assemble a relocatable release tarball (Phase 1 of docs/PLAN-v0.4.md):
#
#   codeskeptic-v<version>-<os>-<arch>/
#     bin/codeskeptic
#     lib/clang/<N>/include/   intrinsic headers (stddef.h, stdarg.h, ...)
#                              copied from the build LLVM — the binary
#                              finds them exe-relative (ResourceDir.cpp),
#                              so the unpacked tree works anywhere
#     DEPENDENCIES.txt         honest list of remaining dynamic deps
#     LICENSE, README.md
#
# Only include/ is shipped from the resource dir — the full resource dir
# also carries sanitizer runtime libraries (tens of MB) the analyzer
# never uses.
#
# Usage: scripts/package_release.sh <codeskeptic-binary> [out-dir] [clang]
set -euo pipefail

BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OUT="${2:-dist}"
CLANG="${3:-}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -z "$CLANG" ]; then
    for c in clang-20 clang-19 clang-18 clang; do
        if command -v "$c" >/dev/null 2>&1; then CLANG="$c"; break; fi
    done
fi
[ -n "$CLANG" ] || { echo "PACKAGE_FAIL no clang found for -print-resource-dir"; exit 1; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
# Git Bash / MSYS on Windows reports MINGW64_NT-... — normalize; the
# Windows package is a zip with codeskeptic.exe (static-CRT build, no
# libs to bundle).
case "$OS" in mingw*|msys*|cygwin*) OS=windows ;; esac
EXE=""
[ "$OS" = windows ] && EXE=".exe"

RES_DIR=$("$CLANG" -print-resource-dir)
# clang.exe prints a native C:\ path; POSIX tools here need /c/...
[ "$OS" = windows ] && RES_DIR=$(cygpath -u "$RES_DIR")
[ -d "$RES_DIR/include" ] || { echo "PACKAGE_FAIL resource dir has no include/: $RES_DIR"; exit 1; }

VERSION=$("$BIN" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.-]*' | head -1)
[ -n "$VERSION" ] || { echo "PACKAGE_FAIL could not parse --version output"; exit 1; }

ARCH=$(uname -m)
NAME="codeskeptic-v${VERSION}-${OS}-${ARCH}"
STAGE="$OUT/$NAME"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin"

cp "$BIN" "$STAGE/bin/codeskeptic$EXE"

MAJOR=$(basename "$RES_DIR")
mkdir -p "$STAGE/lib/clang/$MAJOR"
cp -R "$RES_DIR/include" "$STAGE/lib/clang/$MAJOR/include"

cp LICENSE "$STAGE/LICENSE"
cp README.md "$STAGE/README.md"

# Bundle the LLVM/Clang shared libraries the binary links (distro LLVM
# packages use a shared libLLVM.so / libclang-cpp.so). The binary
# carries an rpath to ../lib (src/CMakeLists.txt), so the unpacked tree
# is self-contained on machines with no LLVM installed. Common system
# libs (libzstd, zlib, tinfo, libc) are NOT bundled — they stay in
# DEPENDENCIES.txt.
mkdir -p "$STAGE/lib"
if [ "$OS" = "windows" ]; then
    # Nothing to bundle: the official LLVM windows-msvc dist is
    # static (/MT), so codeskeptic.exe links only Windows system DLLs.
    :
elif [ "$OS" = "darwin" ]; then
    otool -L "$STAGE/bin/codeskeptic" | awk 'NR>1{print $1}' \
      | grep -Ei 'libLLVM|libclang' | while read -r so; do
        real="$so"
        case "$so" in
            @rpath/*) real="$(brew --prefix llvm 2>/dev/null)/lib/${so#@rpath/}" ;;
        esac
        [ -f "$real" ] || { echo "PACKAGE_WARN cannot resolve $so"; continue; }
        cp -L "$real" "$STAGE/lib/"
        install_name_tool -change "$so" \
            "@executable_path/../lib/$(basename "$so")" \
            "$STAGE/bin/codeskeptic"
    done || true
    # install_name_tool invalidates the ad-hoc signature on arm64
    codesign -f -s - "$STAGE/bin/codeskeptic" 2>/dev/null || true
else
    # Bundle EVERYTHING except the glibc core (which must come from the
    # host — bundling glibc breaks more than it fixes). Chasing named
    # libs one by one is whack-a-mole: libLLVM pulls libedit, libxml2,
    # icu, ... — ldd lists the full transitive closure, so one pass
    # catches them all. (|| true: nothing to bundle is success, not an
    # error, under set -o pipefail.)
    GLIBC_CORE='ld-linux|libc\.so|libm\.so|libpthread\.so|libdl\.so|librt\.so|libresolv\.so|libutil\.so|libgcc_s\.so|libstdc\+\+\.so'
    ldd "$STAGE/bin/codeskeptic" | awk '$3 ~ /\// {print $3}' \
      | grep -Ev "$GLIBC_CORE" | sort -u | while read -r so; do
        cp -L "$so" "$STAGE/lib/"
    done || true
fi

# Honest dependency listing: what the binary still links dynamically.
{
    echo "# Dynamic dependencies of bin/codeskeptic$EXE ($OS-$ARCH)"
    echo "# Analyzing code also needs the TARGET's own headers installed"
    echo "# (libc6-dev / Xcode CLT / MSVC toolset + Windows SDK) — as any"
    echo "# compiler does."
    if [ "$OS" = "darwin" ]; then
        otool -L "$STAGE/bin/codeskeptic" || true
    elif [ "$OS" = "windows" ]; then
        echo "# Static-CRT (/MT) build: only Windows system DLLs."
        ldd "$STAGE/bin/codeskeptic$EXE" 2>/dev/null || true
    else
        ldd "$STAGE/bin/codeskeptic" || true
    fi
} > "$STAGE/DEPENDENCIES.txt"

mkdir -p "$OUT"
if [ "$OS" = "windows" ]; then
    # zip is the Windows convention (Expand-Archive works out of the
    # box); 7z is present on the runners and in Git Bash PATH.
    ARCHIVE="$NAME.zip"
    (cd "$OUT" && rm -f "$ARCHIVE" && 7z a -bso0 -bsp0 "$ARCHIVE" "$NAME" >/dev/null)
else
    ARCHIVE="$NAME.tar.gz"
    tar czf "$OUT/$ARCHIVE" -C "$OUT" "$NAME"
fi
(cd "$OUT" && { command -v sha256sum >/dev/null && sha256sum "$ARCHIVE" || shasum -a 256 "$ARCHIVE"; } >> sha256sums.txt)

SIZE=$(du -h "$OUT/$ARCHIVE" | cut -f1)
echo "PACKAGE_RESULT name=$ARCHIVE size=$SIZE version=$VERSION resource_major=$MAJOR"
