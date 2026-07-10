#!/usr/bin/env bash
# Diff-aware analysis: runs zerodefect over the C/C++ files changed
# since the given git ref. The "only check what you touched" primitive
# for agent/CI loops.
#
# Usage: scripts/analyze_diff.sh <zerodefect-binary> <git-ref> [extra args...]
#   example: scripts/analyze_diff.sh build/src/zerodefect origin/main --severity error
#
# Extra arguments are forwarded to the binary verbatim; with --summary-in
# the diff loop gains whole-project knowledge (callee summaries from
# other files become visible):
#   scripts/analyze_diff.sh build/src/zerodefect origin/main \
#       --summary-in .zerodefect-summaries
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

# Extract changed line ranges from hunk headers (+start,count).
# No count means 1; count 0 (pure deletion) takes the insertion point's
# line — so the surrounding code affected by the deletion is checked too.
changed_ranges() { # <file>
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
        set -- "$@" # existing extra arguments are preserved
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
