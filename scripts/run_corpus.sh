#!/usr/bin/env bash
# Real-world regression corpus: downloads pinned-version open-source
# projects, generates compile_commands.json and runs zerodefect on them.
#
# Success criteria:
#   1. The analyzer runs WITHOUT CRASHING (exit code 0 or 1).
#   2. The finding count does not deviate from the value pinned in
#      corpus_expected.txt (10%+2 tolerance) — versions are pinned, so
#      deviation signals a SEMANTIC REGRESSION (silent finding loss /
#      FP explosion). If no value is recorded, only the CORPUS_RESULT
#      line is printed (pin it from the first run when adding a project).
#
# Usage: scripts/run_corpus.sh <zerodefect-binary> [work-dir]
set -euo pipefail

# Resolve our own directory BEFORE any cd (relative-path trap)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ZD_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="${2:-corpus-work}"
mkdir -p "$WORK"
cd "$WORK"

fetch() { # <dir> <url>
    local dir="$1" url="$2"
    if [ ! -d "$dir" ]; then
        echo "[corpus] fetching $dir ..."
        curl -sL --retry 3 "$url" -o "$dir.tgz"
        mkdir "$dir"
        tar xzf "$dir.tgz" -C "$dir" --strip-components=1
    fi
}

# Pinned versions — keep finding counts comparable
fetch cjson    "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz"
fetch tinyxml2 "https://github.com/leethomason/tinyxml2/archive/refs/tags/10.0.0.tar.gz"
# abseil is DEEP-only (CORPUS_DEEP=1): ~2 min of analysis — weekly cron,
# not every PR (CI cost balance). Real modern C++ (template-heavy,
# RAW_CHECK/PREDICT macros, leak-on-purpose singletons) — the FP net
# that Juliet cannot provide.
if [ "${CORPUS_DEEP:-0}" = "1" ]; then
    fetch abseil "https://github.com/abseil/abseil-cpp/archive/refs/tags/20260526.0.tar.gz"
    fetch catch2 "https://github.com/catchorg/Catch2/archive/refs/tags/v3.15.2.tar.gz"
fi

run_one() { # <mode: scan|db> <dir> [extra cmake args...]
    # scan: analyze the whole source tree (cjson/tinyxml2 pins were
    #       measured this way — do not change their input set).
    # db:   analyze exactly the compile-DB files (abseil's tree carries
    #       test/tooling sources a directory scan would wrongly include).
    local mode="$1" dir="$2"; shift 2 || true
    echo ""
    echo "=== [$dir] ==="
    # Build directory OUTSIDE the source TREE: the scanner must not see
    # the CMake feature-test sources inside build/ (CMakeCCompilerId.c
    # etc.). CMAKE_POLICY_VERSION_MINIMUM: keep old
    # cmake_minimum_required values from erroring on CMake 4.x.
    cmake -S "$dir" -B "build-$dir" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@" > /dev/null

    # NO pipe: the exit code must belong to the analyzer, not the pipe
    # (the tee trap — this is how the fake green appeared on Juliet)
    set +e
    if [ "$mode" = "db" ]; then
        python3 - "$dir" <<'PYEOF'
import json, sys
d = sys.argv[1]
db = json.load(open(f"build-{d}/compile_commands.json"))
open(f"files-{d}.txt", "w").write("\n".join(sorted({e["file"] for e in db})))
PYEOF
        "$ZD_BIN" --files "files-$dir.txt" --build-path "build-$dir" \
            > "out-$dir.txt" 2>&1
    else
        "$ZD_BIN" "$dir" --build-path "build-$dir" > "out-$dir.txt" 2>&1
    fi
    local code=$?
    set -e
    cat "out-$dir.txt"

    echo "[$dir] exit code: $code"
    if [ "$code" -gt 1 ]; then
        echo "[$dir] FAIL: analyzer crashed or errored (exit $code)"
        return 1
    fi

    # Measure the finding count from console lines (path:line:col [sev])
    local count
    count=$(grep -cE '^\S+:[0-9]+:[0-9]+ \[(warning|error)\]' \
        "out-$dir.txt" || true)
    echo "CORPUS_RESULT $dir findings=$count"

    # Compare against the pinned expectation (if any). Tolerance 10%+2:
    # versions are pinned, a large deviation is a semantic regression.
    local expected
    expected=$(awk -v d="$dir" '$1 == d { print $2 }' \
        "$SCRIPT_DIR/corpus_expected.txt" 2>/dev/null || true)
    if [ -n "$expected" ]; then
        local tol=$(( expected / 10 + 2 ))
        if [ "$count" -lt $(( expected - tol )) ] || \
           [ "$count" -gt $(( expected + tol )) ]; then
            echo "[$dir] FAIL: finding count deviated" \
                 "(expected $expected ±$tol, measured $count)"
            return 1
        fi
        echo "[$dir] finding count within expected range ($expected ±$tol)"
    else
        echo "[$dir] NOTE: no expected count recorded" \
             "(scripts/corpus_expected.txt) — pin it from the first run"
    fi
}

run_one scan cjson
run_one scan tinyxml2
if [ "${CORPUS_DEEP:-0}" = "1" ]; then
    run_one db abseil -DCMAKE_CXX_STANDARD=17 -DABSL_BUILD_TESTING=OFF
    # catch2 pins at ZERO findings: a clean modern-C++ codebase is the
    # FP-explosion tripwire — any rule change that suddenly produces
    # findings here turns the guard red.
    run_one db catch2 -DCATCH_BUILD_TESTING=OFF -DCATCH_INSTALL_DOCS=OFF
fi

echo ""
echo "[corpus] OK — all projects analyzed crash-free"
