#!/usr/bin/env bash
# Real-world regression corpus: downloads pinned-version open-source
# projects, generates compile_commands.json and runs codeskeptic on them.
#
# Success criteria:
#   1. Every translation unit selected from the generated compilation
#      database is analyzed (exit code 0 or 1, no broken/skipped TU).
#   2. The finding count does not deviate from the value pinned in
#      corpus_expected.txt (10%+2 tolerance) — versions are pinned, so
#      deviation signals a SEMANTIC REGRESSION (silent finding loss /
#      FP explosion). If no value is recorded, only the CORPUS_RESULT
#      line is printed (pin it from the first run when adding a project).
#
# Usage: scripts/run_corpus.sh <codeskeptic-binary> [work-dir]
set -euo pipefail

# Resolve our own directory BEFORE any cd (relative-path trap)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CS_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="${2:-corpus-work}"
mkdir -p "$WORK"
cd "$WORK"

fetch() {
    local dir="$1" url="$2"
    local archive="${dir}.tgz" staging="${dir}.extract"
    if [[ ! -f "${dir}.ready" ]]; then
        echo "[corpus] fetching $(basename "$dir")"
        local attempt valid=false
        for attempt in 1 2 3; do
            rm -f "$archive"
            if curl --fail --show-error --location --retry 3 --retry-all-errors \
                    --retry-delay 2 --output "$archive" "$url" \
                    && tar -tzf "$archive" >/dev/null 2>&1; then
                valid=true
                break
            fi
            sleep $((attempt * 2))
        done
        if [[ "$valid" != true ]]; then
            echo "[corpus] download validation failed: $(basename "$dir")" >&2
            return 1
        fi
        rm -rf "$staging"
        mkdir -p "$staging"
        tar -xzf "$archive" -C "$staging" --strip-components=1
        rm -rf "$dir"
        mv "$staging" "$dir"
        touch "${dir}.ready"
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

run_one() { # <dir> [extra cmake args...]
    # Analyze exactly the compile-DB files. A directory scan also admits
    # vendored fixtures and tooling sources that the project never builds;
    # accepting those skipped TUs would fabricate a project verdict.
    local dir="$1"; shift || true
    echo ""
    echo "=== [$dir] ==="
    # Build directory OUTSIDE the source TREE: the scanner must not see
    # the CMake feature-test sources inside build/ (CMakeCCompilerId.c
    # etc.). CMAKE_POLICY_VERSION_MINIMUM: keep old
    # cmake_minimum_required values from erroring on CMake 4.x.
    cmake -S "$dir" -B "build-$dir" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@" > /dev/null

    python3 - "$dir" <<'PYEOF'
import json
from pathlib import Path
import sys

project = sys.argv[1]
database_path = Path(f"build-{project}/compile_commands.json")
database = json.loads(database_path.read_text(encoding="utf-8"))
files = set()
for entry in database:
    source = Path(entry["file"])
    if not source.is_absolute():
        source = Path(entry["directory"]) / source
    files.add(str(source.resolve(strict=True)))
if not files:
    raise SystemExit(f"{database_path}: compilation database has no files")
Path(f"files-{project}.txt").write_text(
    "\n".join(sorted(files)) + "\n", encoding="utf-8"
)
PYEOF
    local requested
    requested=$(wc -l < "files-$dir.txt")

    # NO pipe: the exit code must belong to the analyzer, not the pipe
    # (the tee trap — this is how the fake green appeared on Juliet).
    set +e
    "$CS_BIN" --files "files-$dir.txt" --build-path "build-$dir" \
        > "out-$dir.txt" 2>&1
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

    # Name and prove the surface the count belongs to. The verdict is valid
    # only when every requested compile-DB translation unit was analyzed.
    local seen broke missing analysed
    # A --files run emits one aggregate start line, then nested one-file
    # starts while each requested TU is analyzed. Treating every match as
    # one shell integer produces a multiline arithmetic expression and can
    # skip this fail-closed coverage gate while the script still exits 0.
    # The aggregate is the first advertised surface; if it is absent, the
    # nested lines must not be summed into a fabricated complete verdict.
    seen=$(awk '
        /Analysis starting\.\.\. \([0-9]+ files/ {
            value = $0
            sub(/^.*Analysis starting\.\.\. \(/, "", value)
            sub(/ files.*$/, "", value)
            print value
            exit
        }
    ' "out-$dir.txt")
    broke=$(grep -oE '[0-9]+ translation unit\(s\) failed to COMPILE' \
            "out-$dir.txt" | grep -oE '^[0-9]+' || true)
    missing=$(grep -cF 'Compile command not found.' "out-$dir.txt" || true)
    analysed=$(( ${seen:-0} - ${broke:-0} - ${missing:-0} ))
    if [ "${seen:-0}" -ne "$requested" ] || \
       [ "${broke:-0}" -ne 0 ] || \
       [ "${missing:-0}" -ne 0 ] || \
       [ "$analysed" -ne "$requested" ]; then
        echo "[$dir] FAIL: incomplete compile-database coverage" \
             "(requested=$requested, enumerated=${seen:-0}," \
             "broken=${broke:-0}, missing_compile_commands=${missing:-0}," \
             "analysed=$analysed)"
        return 1
    fi
    echo "CORPUS_COVERAGE $dir enumerated=${seen:-?} broken=${broke:-0}" \
         "missing_compile_commands=${missing:-0} analysed=$analysed"

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
        if [ "$count" -ne "$expected" ]; then
            # Inside the band but not ON the pin. This is exactly how the
            # cjson pin sat at 53 from 895c813 while every measurement
            # read 54: the tolerance absorbed the gap, nothing went red,
            # and the drift stayed invisible. A pin one below the true
            # level is worse than a merely wrong number — a real -1 then
            # lands on it and reads as "unchanged". Loud but not fatal:
            # re-centring is a deliberate act that belongs in a commit
            # explaining why the level moved.
            echo "[$dir] PIN_DRIFT expected=$expected measured=$count" \
                 "(within ±$tol, not a failure) — re-centre the pin in" \
                 "scripts/corpus_expected.txt or explain the gap"
        fi
        echo "[$dir] finding count within expected range ($expected ±$tol)"
    else
        echo "[$dir] NOTE: no expected count recorded" \
             "(scripts/corpus_expected.txt) — pin it from the first run"
    fi
}

run_one cjson
run_one tinyxml2
if [ "${CORPUS_DEEP:-0}" = "1" ]; then
    run_one abseil -DCMAKE_CXX_STANDARD=17 -DABSL_BUILD_TESTING=OFF
    # catch2 pins at ZERO findings: a clean modern-C++ codebase is the
    # FP-explosion tripwire — any rule change that suddenly produces
    # findings here turns the guard red.
    run_one catch2 -DCATCH_BUILD_TESTING=OFF -DCATCH_INSTALL_DOCS=OFF
fi

echo ""
echo "[corpus] OK — all projects analyzed crash-free"
