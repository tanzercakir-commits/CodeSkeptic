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

echo "[analyze-diff] ${#files[@]} changed file(s) since $REF"
overall=0
for f in "${files[@]}"; do
    echo ""
    echo "=== $f ==="
    code=0
    "$ZD_BIN" "$f" "$@" || code=$?
    if [ "$code" -gt 1 ]; then
        echo "[analyze-diff] FAIL: analyzer error on $f (exit $code)"
        exit "$code"
    fi
    [ "$code" -eq 1 ] && overall=1
done

exit "$overall"
