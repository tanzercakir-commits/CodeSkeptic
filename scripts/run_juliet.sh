#!/usr/bin/env bash
# NIST Juliet C/C++ 1.3 uzerinde olcum: kurallarimizla eslesen CWE
# dizinlerini tarar, bulgulari good/bad fonksiyon adlariyla puanlar.
#
# Kullanim: scripts/run_juliet.sh <zerodefect-binary> [calisma-dizini] [dosya-limiti]
#   dosya-limiti: CWE basina taranacak azami dosya (varsayilan 400;
#                 0 = limitsiz). CI suresini sinirlamak icin.
#
# JULIET_DIR onceden indirilmis paketi gosteriyorsa indirme atlanir
# (yerel/testte sahte mini-suite ile calistirmayi da mumkun kilar).
set -euo pipefail

# Kendi dizinimizi HERHANGI bir cd'den ONCE coz (goreli yol tuzagi)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ZD_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="${2:-juliet-work}"
LIMIT="${3:-400}"
mkdir -p "$WORK"
cd "$WORK"

JULIET_URL="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

if [ -z "${JULIET_DIR:-}" ]; then
    if [ ! -d juliet ]; then
        echo "[juliet] downloading suite (~120MB)..."
        curl -sL --retry 3 "$JULIET_URL" -o juliet.zip
        mkdir juliet
        unzip -q juliet.zip -d juliet
    fi
    JULIET_DIR="$(pwd)/juliet"
fi

# Zip yerlesimi surumden suruma degisebilir — testcasesupport'u arayarak
# kok dizini sagalamlastir
if [ ! -d "$JULIET_DIR/C/testcases" ]; then
    found="$(find "$JULIET_DIR" -maxdepth 4 -type d -name testcasesupport \
        | head -1 || true)"
    [ -n "$found" ] && JULIET_DIR="$(dirname "$found")/.."
fi
TESTCASES="$(cd "$JULIET_DIR" && pwd)/C/testcases"
SUPPORT="$(cd "$JULIET_DIR" && pwd)/C/testcasesupport"
if [ ! -d "$TESTCASES" ]; then
    # Alternatif: dogrudan testcases iceren yerlesim
    alt="$(find "$JULIET_DIR" -maxdepth 4 -type d -name testcases | head -1 || true)"
    [ -n "$alt" ] || { echo "[juliet] testcases bulunamadi: $JULIET_DIR"; exit 1; }
    TESTCASES="$alt"
    SUPPORT="$(dirname "$alt")/testcasesupport"
fi

# Kural -> CWE eslemesi
CWES=(
    "CWE476_NULL_Pointer_Dereference"
    "CWE401_Memory_Leak"
    "CWE415_Double_Free"
    "CWE416_Use_After_Free"
    "CWE369_Divide_by_Zero"
)

run_cwe() { # <cwe-adi>
    local cwe="$1"
    local dir="$TESTCASES/$cwe"
    [ -d "$dir" ] || { echo "[juliet] atlandi (dizin yok): $cwe"; return 0; }

    # Windows/pthread varyantlarini ele; .c/.cpp dosyalarini sec
    local list="files_$cwe.txt"
    find "$dir" -type f \( -name '*.c' -o -name '*.cpp' \) \
        | grep -v -e 'w32' -e 'wchar_t' -e 'pthread' -e 'fscanf' -e 'socket' \
        | sort > "$list"
    if [ "$LIMIT" -gt 0 ]; then
        head -n "$LIMIT" "$list" > "$list.tmp" && mv "$list.tmp" "$list"
    fi
    local count
    count=$(wc -l < "$list")
    [ "$count" -gt 0 ] || { echo "[juliet] $cwe: uygun dosya yok"; return 0; }

    # compile_commands.json uret: her dosya icin destek include'lariyla
    local build="build_$cwe"
    mkdir -p "$build"
    python3 - "$list" "$SUPPORT" "$build/compile_commands.json" << 'PYEOF'
import json, sys
files, support, out = sys.argv[1], sys.argv[2], sys.argv[3]
entries = []
with open(files) as f:
    for path in (l.strip() for l in f if l.strip()):
        lang = "c++" if path.endswith(".cpp") else "c"
        entries.append({
            "directory": "/",
            "file": path,
            "command": f"cc -x {lang} -c {path} -I {support}",
        })
with open(out, "w") as f:
    json.dump(entries, f)
PYEOF

    echo ""
    echo "[juliet] $cwe: $count dosya taraniyor..."
    set +e
    # --files: yalnizca secilmis (elenmis + limitli) dosyalar analiz edilir
    "$ZD_BIN" --files "$list" --build-path "$build" \
        --json "findings_$cwe.json" > /dev/null 2> "log_$cwe.txt"
    local code=$?
    set -e
    if [ "$code" -gt 1 ]; then
        echo "[juliet] FAIL: analizci hatasi ($cwe, exit $code)"
        tail -5 "log_$cwe.txt"
        return 1
    fi

    python3 "$SCRIPT_DIR/juliet_eval.py" "findings_$cwe.json" "$cwe" "$list"
}

overall=0
for cwe in "${CWES[@]}"; do
    run_cwe "$cwe" || overall=1
done

echo ""
if [ "$overall" -eq 0 ]; then
    echo "[juliet] OK — ozet icin JULIET_RESULT satirlarina bakin"
else
    echo "[juliet] tamamlandi (bazi CWE'lerde hata) — loglara bakin"
fi
exit "$overall"
