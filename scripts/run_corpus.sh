#!/usr/bin/env bash
# Gercek dunya regresyon korpusu: sabit surumlu acik kaynak projeleri
# indirir, compile_commands.json uretir ve zerodefect'i uzerlerinde kosar.
#
# Basari kriteri: analizci CRASH ETMEDEN calisir (exit code 0 veya 1).
# Bulgu sayilari bilgi amacli yazdirilir — surumler sabit oldugu icin
# beklenmedik sicramalar log'dan izlenebilir.
#
# Kullanim: scripts/run_corpus.sh <zerodefect-binary> [calisma-dizini]
set -euo pipefail

ZD_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="${2:-corpus-work}"
mkdir -p "$WORK"
cd "$WORK"

fetch() { # <dizin> <url>
    local dir="$1" url="$2"
    if [ ! -d "$dir" ]; then
        echo "[corpus] fetching $dir ..."
        curl -sL --retry 3 "$url" -o "$dir.tgz"
        mkdir "$dir"
        tar xzf "$dir.tgz" -C "$dir" --strip-components=1
    fi
}

# Sabit surumler — bulgu sayilari karsilastirilabilir kalsin
fetch cjson    "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz"
fetch tinyxml2 "https://github.com/leethomason/tinyxml2/archive/refs/tags/10.0.0.tar.gz"

run_one() { # <dizin>
    local dir="$1"
    echo ""
    echo "=== [$dir] ==="
    # Build dizini kaynak AGACININ DISINDA: tarayici build/ icindeki
    # CMake feature-test kaynaklarini (CMakeCCompilerId.c vb.) gormesin.
    # CMAKE_POLICY_VERSION_MINIMUM: eski cmake_minimum_required degerleri
    # CMake 4.x'te hata vermesin.
    cmake -S "$dir" -B "build-$dir" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 > /dev/null

    set +e
    "$ZD_BIN" "$dir" --build-path "build-$dir"
    local code=$?
    set -e

    echo "[$dir] exit code: $code"
    if [ "$code" -gt 1 ]; then
        echo "[$dir] FAIL: analyzer crashed or errored (exit $code)"
        return 1
    fi
}

run_one cjson
run_one tinyxml2

echo ""
echo "[corpus] OK — both projects analyzed crash-free"
