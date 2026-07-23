#!/usr/bin/env bash
# Thesis recall/precision gate (Phase 2d of docs/PLAN-v0.4.md).
#
# Re-analyzes the frozen blind AI first-draft corpus
# (tests/thesis_corpus/) and checks each file against the adjudicated
# manifest (thesis_expected.txt):
#   CLEAN files -> findings MUST be 0 (precision regression = red)
#   BUG   files -> findings MUST be >= the pinned floor (recall
#                  regression = red)
# A deterministic compile_commands.json is generated so header
# resolution never depends on the fallback path (the #92 lesson: a
# bare .c with no compile DB can silently become a broken TU).
#
# Usage: scripts/run_thesis.sh <codeskeptic-binary>
set -euo pipefail

CS_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/thesis_corpus"
EXPECTED="$DIR/thesis_expected.txt"

# Pick a C compiler for the compile DB entries (parse only).
CC=""
for c in clang-20 clang-19 clang-18 clang cc; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done
[ -n "$CC" ] || { echo "THESIS_FAIL no C compiler for compile DB"; exit 1; }

# Deterministic compile DB: one -std=gnu11 entry per corpus file.
DB="$(mktemp -d)/compile_commands.json"
{
    echo "["
    first=1
    for f in "$DIR"/*.c; do
        [ "$first" -eq 1 ] || echo ","
        first=0
        printf '  {"directory": "%s", "command": "%s -std=gnu11 -c %s", "file": "%s"}' \
            "$DIR" "$CC" "$f" "$f"
    done
    echo ""
    echo "]"
} > "$DB"
DB_DIR="$(dirname "$DB")"

fail=0
clean_fp=0
bug_caught=0
bug_total=0
total_findings=0

# Read the manifest (skip comments/blank lines).
while read -r file role floor; do
    case "$file" in ""|\#*) continue ;; esac
    src="$DIR/$file"
    [ -f "$src" ] || { echo "THESIS_FAIL manifest lists missing file: $file"; fail=1; continue; }

    # Findings print to stderr; count the "file:line:col [sev]" lines.
    out="$("$CS_BIN" "$src" --build-path "$DB_DIR" 2>&1 >/dev/null || true)"
    n="$(printf '%s\n' "$out" | grep -cE '\.c:[0-9]+:[0-9]+ \[(warning|error|info)\]' || true)"
    total_findings=$((total_findings + n))

    if [ "$role" = "CLEAN" ]; then
        if [ "$n" -ne 0 ]; then
            echo "THESIS_FAIL precision: $file is CLEAN but produced $n finding(s)"
            clean_fp=$((clean_fp + n))
            fail=1
        fi
    elif [ "$role" = "BUG" ]; then
        bug_total=$((bug_total + 1))
        [ "$n" -gt 0 ] && bug_caught=$((bug_caught + 1))
        if [ "$n" -lt "$floor" ]; then
            echo "THESIS_FAIL recall: $file expected >= $floor finding(s), got $n"
            fail=1
        fi
    else
        echo "THESIS_FAIL manifest bad role '$role' for $file"
        fail=1
    fi
done < "$EXPECTED"

rm -rf "$DB_DIR"

echo "THESIS_RESULT clean_fp=$clean_fp bug_caught=$bug_caught/$bug_total total_findings=$total_findings"
if [ "$fail" -eq 0 ]; then
    echo "[thesis] gate OK — precision clean, recall floors held"
fi
exit "$fail"
