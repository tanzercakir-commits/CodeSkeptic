#!/usr/bin/env bash
# Diff-farkinda analiz: verilen git referansindan bu yana degisen C/C++
# dosyalarini zerodefect'ten gecirir. Ajan/CI dongusunde "yalnizca
# dokundugun yerleri kontrol et" primitifi.
#
# Kullanim: scripts/analyze_diff.sh <zerodefect-binary> <git-ref> [ek args...]
#   ornek:  scripts/analyze_diff.sh build/src/zerodefect origin/main --severity error
set -euo pipefail

ZD_BIN="${1:?usage: analyze_diff.sh <zerodefect-binary> <git-ref> [extra args...]}"
REF="${2:?usage: analyze_diff.sh <zerodefect-binary> <git-ref> [extra args...]}"
shift 2

mapfile -t files < <(git diff --name-only --diff-filter=d "$REF" -- \
    | grep -E '\.(c|cpp|cc|cxx)$' || true)

if [ ${#files[@]} -eq 0 ]; then
    echo "[analyze-diff] no changed C/C++ files since $REF"
    exit 0
fi

# Hunk basliklarindan (+baslangic,adet) degisen satir araliklarini cikar.
# Adet yoksa 1; adet 0 ise (salt silme) ekleme noktasinin satiri alinir —
# silmenin etkiledigi cevre kod da kontrol edilsin.
changed_ranges() { # <dosya>
    git diff -U0 --diff-filter=d "$REF" -- "$1" \
        | sed -n 's/^@@ .*+\([0-9][0-9]*\)\(,\([0-9][0-9]*\)\)\{0,1\} @@.*/\1 \3/p' \
        | while read -r start count; do
              if [ -z "$count" ]; then count=1; fi
              if [ "$count" -eq 0 ]; then
                  [ "$start" -eq 0 ] && start=1
                  echo "${start}-${start}"
              else
                  echo "${start}-$((start + count - 1))"
              fi
          done | paste -sd, -
}

echo "[analyze-diff] ${#files[@]} changed file(s) since $REF"
overall=0
for f in "${files[@]}"; do
    echo ""
    ranges="$(changed_ranges "$f")"
    if [ -n "$ranges" ]; then
        echo "=== $f (lines $ranges) ==="
        set -- "$@" # mevcut ek argumanlar korunur
        code=0
        "$ZD_BIN" "$f" --lines "$ranges" "$@" || code=$?
    else
        echo "=== $f ==="
        code=0
        "$ZD_BIN" "$f" "$@" || code=$?
    fi
    if [ "$code" -gt 1 ]; then
        echo "[analyze-diff] FAIL: analyzer error on $f (exit $code)"
        exit "$code"
    fi
    [ "$code" -eq 1 ] && overall=1
done

exit "$overall"
