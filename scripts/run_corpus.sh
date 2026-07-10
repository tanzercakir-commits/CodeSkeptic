#!/usr/bin/env bash
# Gercek dunya regresyon korpusu: sabit surumlu acik kaynak projeleri
# indirir, compile_commands.json uretir ve zerodefect'i uzerlerinde kosar.
#
# Basari kriterleri:
#   1. Analizci CRASH ETMEDEN calisir (exit code 0 veya 1).
#   2. Bulgu sayisi corpus_expected.txt'teki sabitlenmis degerden
#      (%10+2 toleransla) sapmaz — surumler sabit oldugu icin sapma
#      SEMANTIK REGRESYON isaretidir (sessiz bulgu kaybi / FP patlamasi).
#      Kayitli deger yoksa yalnizca CORPUS_RESULT satiri basilir
#      (yeni proje eklerken ilk kosudan sabitlenir).
#
# Kullanim: scripts/run_corpus.sh <zerodefect-binary> [calisma-dizini]
set -euo pipefail

# Kendi dizinimizi HERHANGI bir cd'den ONCE coz (goreli yol tuzagi)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

    # Boru YOK: exit kodu boruya degil analizciye ait olmali
    # (tee tuzagi — Juliet'te sahte yesil boyle dogmustu)
    set +e
    "$ZD_BIN" "$dir" --build-path "build-$dir" > "out-$dir.txt" 2>&1
    local code=$?
    set -e
    cat "out-$dir.txt"

    echo "[$dir] exit code: $code"
    if [ "$code" -gt 1 ]; then
        echo "[$dir] FAIL: analyzer crashed or errored (exit $code)"
        return 1
    fi

    # Bulgu sayisini konsol satirlarindan olc (path:satir:kolon [sev])
    local count
    count=$(grep -cE '^\S+:[0-9]+:[0-9]+ \[(warning|error)\]' \
        "out-$dir.txt" || true)
    echo "CORPUS_RESULT $dir findings=$count"

    # Sabitlenmis beklentiyle karsilastir (varsa). Tolerans %10+2:
    # surumler sabit, buyuk sapma semantik regresyondur.
    local expected
    expected=$(awk -v d="$dir" '$1 == d { print $2 }' \
        "$SCRIPT_DIR/corpus_expected.txt" 2>/dev/null || true)
    if [ -n "$expected" ]; then
        local tol=$(( expected / 10 + 2 ))
        if [ "$count" -lt $(( expected - tol )) ] || \
           [ "$count" -gt $(( expected + tol )) ]; then
            echo "[$dir] FAIL: bulgu sayisi sapti" \
                 "(beklenen $expected ±$tol, olculen $count)"
            return 1
        fi
        echo "[$dir] bulgu sayisi beklenen aralikta ($expected ±$tol)"
    else
        echo "[$dir] NOT: beklenen sayi kayitli degil" \
             "(scripts/corpus_expected.txt) — ilk kosudan sabitleyin"
    fi
}

run_one cjson
run_one tinyxml2

echo ""
echo "[corpus] OK — both projects analyzed crash-free"
