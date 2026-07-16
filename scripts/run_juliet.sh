#!/usr/bin/env bash
# Measurement on NIST Juliet C/C++ 1.3: scans the CWE directories that
# match our rules and scores findings via good/bad function names.
#
# Usage: scripts/run_juliet.sh <zerodefect-binary> [work-dir] [file-limit]
#   file-limit: maximum files to scan per CWE (default 400;
#               0 = unlimited). Used to bound CI time.
#
# If JULIET_DIR points to a pre-downloaded package the download is
# skipped (this also makes it possible to run against a fake mini-suite
# locally/in tests). Output: JULIET_RESULT (trend) + FP_SAMPLE (raw
# material for rule improvement) lines are grep-friendly. Rule-change
# PRs can trigger the Juliet run by touching this file (the known path,
# since workflow_dispatch returns 403 on the integration token).
#
# Trigger touch 2026-07-16 (#69a): bitwise/modulo interval modeling in
# IntervalEval feeds DivByZeroRule (CWE369 floor). The new intervals are
# zero-CONTAINING ([0,c] / [0,c-1]), so they cannot prove a divisor
# non-zero and cannot kill a true finding — but CWE369 gates it here
# regardless.
set -euo pipefail

# Resolve our own directory BEFORE any cd (relative-path trap)
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

# The zip layout can change between releases — harden the root directory
# detection by searching for testcasesupport
if [ ! -d "$JULIET_DIR/C/testcases" ]; then
    found="$(find "$JULIET_DIR" -maxdepth 4 -type d -name testcasesupport \
        | head -1 || true)"
    [ -n "$found" ] && JULIET_DIR="$(dirname "$found")/.."
fi
TESTCASES="$(cd "$JULIET_DIR" && pwd)/C/testcases"
SUPPORT="$(cd "$JULIET_DIR" && pwd)/C/testcasesupport"
if [ ! -d "$TESTCASES" ]; then
    # Alternative: a layout containing testcases directly
    alt="$(find "$JULIET_DIR" -maxdepth 4 -type d -name testcases | head -1 || true)"
    [ -n "$alt" ] || { echo "[juliet] testcases not found: $JULIET_DIR"; exit 1; }
    TESTCASES="$alt"
    SUPPORT="$(dirname "$alt")/testcasesupport"
fi

# Rule -> CWE mapping
CWES=(
    "CWE476_NULL_Pointer_Dereference"
    "CWE401_Memory_Leak"
    "CWE415_Double_Free"
    "CWE416_Use_After_Free"
    "CWE369_Divide_by_Zero"
)

run_cwe() { # <cwe-name>
    local cwe="$1"
    local dir="$TESTCASES/$cwe"
    [ -d "$dir" ] || { echo "[juliet] skipped (no directory): $cwe"; return 0; }

    # Filter out Windows/pthread variants; pick .c/.cpp files
    local list="files_$cwe.txt"
    find "$dir" -type f \( -name '*.c' -o -name '*.cpp' \) \
        | grep -v -e 'w32' -e 'wchar_t' -e 'pthread' -e 'fscanf' -e 'socket' \
        | sort > "$list"
    # GROUP-based strided sampling. Two lessons at once:
    #  1. head -N picked the alphabetically first variant family and
    #     introduced bias (CWE369: all of the first 400 files were
    #     float_*).
    #  2. File-level stride broke the a/b PAIRS of flow variants
    #     (63a scanned, 63b skipped) — no pair was left for cross-TU
    #     summaries to link (whole-program effect unmeasurable).
    # Solution: files are reduced to their variant group (trailing
    # letter suffix dropped: 63a/63b -> 63), groups are sampled at
    # even intervals, and ALL files of a selected group go in. The
    # limit is checked at group start — a group is never split
    # (slight overshoot accepted).
    if [ "$LIMIT" -gt 0 ]; then
        awk -v limit="$LIMIT" '
            function base(p) { g = p; sub(/[a-e]?\.(c|cpp)$/, "", g)
                               return g }
            NR == FNR { b = base($0)
                        if (!(b in seen)) { seen[b] = 1; ngroups++ }
                        total++; next }
            FNR == 1  { gstep = (ngroups * limit) / total
                        gstep = ngroups / (gstep < 1 ? 1 : gstep)
                        # target: ~limit files => limit*ngroups/total groups
                        if (gstep < 1) gstep = 1
                        next_g = 1; gi = 0; lastb = "" }
            {
                b = base($0)
                if (b != lastb) {
                    lastb = b; gi++
                    pick = (gi >= next_g && picked < limit)
                    if (pick) next_g += gstep
                }
                if (pick) { print; picked++ }
            }' "$list" "$list" > "$list.tmp" && mv "$list.tmp" "$list"
    fi
    local count
    count=$(wc -l < "$list")
    [ "$count" -gt 0 ] || { echo "[juliet] $cwe: no eligible files"; return 0; }

    # Generate compile_commands.json: with support includes for each file
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
    echo "[juliet] $cwe: scanning $count files..."
    set +e
    # --files: only the selected (filtered + limited) files are analyzed
    # --whole-program: flow variants (61/63/64...) split source/sink
    # across a/b files — invisible without cross-TU summaries
    "$ZD_BIN" --files "$list" --build-path "$build" --whole-program \
        --json "findings_$cwe.json" > /dev/null 2> "log_$cwe.txt"
    local code=$?
    set -e
    if [ "$code" -gt 1 ]; then
        echo "[juliet] FAIL: analyzer error ($cwe, exit $code)"
        tail -5 "log_$cwe.txt"
        return 1
    fi

    python3 "$SCRIPT_DIR/juliet_eval.py" "findings_$cwe.json" "$cwe" \
        "$list" "$SCRIPT_DIR/juliet_expected.txt"
}

overall=0
for cwe in "${CWES[@]}"; do
    run_cwe "$cwe" || overall=1
done

echo ""
if [ "$overall" -eq 0 ]; then
    echo "[juliet] OK — see the JULIET_RESULT lines for a summary"
else
    echo "[juliet] finished (errors in some CWEs) — check the logs"
fi
exit "$overall"
