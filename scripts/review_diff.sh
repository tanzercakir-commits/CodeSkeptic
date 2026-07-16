#!/usr/bin/env bash
# Diff-native semantic review (c1): the PR-review verdict for the change
# between a base git revision and the current working tree.
#
# What it does (and analyze_diff.sh does not): analyze BOTH sides of the
# change — the changed files at base (in a temporary git worktree, with
# the head compile commands remapped onto it) and at head — and report
# the DELTA:
#   * NEW findings the change introduces (with dataflow traces; steps on
#     changed lines are marked),
#   * FIXED findings (present at base, gone at head),
#   * CONTRACT changes (--summary-diff over both harvests: WEAKENED gates),
#   * a coverage/honesty section (what was NOT analyzed, and why).
# analyze_diff.sh remains the fast path (head-only, changed hunks only);
# this script is the verdict path (whole changed files, base-aware).
#
# Usage:
#   scripts/review_diff.sh <zerodefect-binary> <base-ref> [options] [-- <analyzer args>]
#     --build-path <dir>   compile_commands.json directory (default .)
#     --out <file>         write the markdown review here (default stdout)
#     --gate error|warn    exit 1 on a failing verdict (default error)
#     --strict             new warnings also gate (default: only new
#                          errors and weakened contracts gate)
#     --exclude <pat>      skip changed files matching this glob (e.g.
#                          'tests/*'; repeatable) — they are listed in
#                          the coverage section, never silently dropped
#     --no-assumptions     disable the assumption delta (see below)
#   Arguments after -- go to BOTH analyzer runs verbatim (e.g.
#   --alloc-functions git__malloc) — both sides must run with identical
#   settings or the delta is not a delta.
#
# The ASSUMPTION DELTA is on by default in review mode: a new inferred,
# unchecked precondition ("parameter p is assumed non-null — dereferenced,
# never checked") introduced by the change is exactly the CWE-476 shape
# reviews exist to catch (it found cJSON #991 in the field trial), and
# the delta bounds the assumption engine's volume to the change (0 new
# findings across a 116-commit real-history range). Info severity: it
# informs, and gates only under --strict.
#
# Exit codes: 0 pass (or --gate warn), 1 failing verdict, 2 infrastructure
# error (analyzer crash, unreadable inputs). Run from inside the git
# repository being reviewed; head = the WORKING TREE (what a CI checkout
# holds), base = <base-ref>.
set -euo pipefail

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
}

[ $# -ge 2 ] || usage
ZD_BIN="$1"; BASE_REF="$2"; shift 2

BUILD_PATH="."; OUT=""; GATE="error"; STRICT=0; ASSUMPTIONS=1
EXTRA=(); EXCLUDES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --build-path) BUILD_PATH="${2:?--build-path needs a value}"; shift 2;;
        --out)        OUT="${2:?--out needs a value}"; shift 2;;
        --gate)       GATE="${2:?--gate needs error|warn}"; shift 2;;
        --strict)     STRICT=1; shift;;
        --exclude)    EXCLUDES+=("${2:?--exclude needs a glob pattern}"); shift 2;;
        --no-assumptions) ASSUMPTIONS=0; shift;;
        --)           shift; EXTRA=("$@"); break;;
        *) echo "[review] unknown option: $1 (analyzer args go after --)" >&2
           usage;;
    esac
done
if [ "$ASSUMPTIONS" -eq 1 ]; then EXTRA+=(--assumptions); fi
case "$GATE" in error|warn) ;; *)
    echo "[review] --gate expects 'error' or 'warn', got: $GATE" >&2; exit 2;;
esac

# Resolve our own paths BEFORE any cd (relative-path trap)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZD_BIN="$(cd "$(dirname "$ZD_BIN")" && pwd)/$(basename "$ZD_BIN")"
REPORT_PY="$SCRIPT_DIR/review_report.py"
BUILD_PATH="$(cd "$BUILD_PATH" && pwd)"

HEAD_ROOT="$(git rev-parse --show-toplevel)"
BASE_SHA="$(git rev-parse --verify "${BASE_REF}^{commit}")"
BASE_SHORT="$(git rev-parse --short "$BASE_SHA")"

TMP="$(mktemp -d)"
BASE_WT="$TMP/base"
cleanup() {
    git worktree remove --force "$BASE_WT" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---- classify the change set --------------------------------------------
# name-status with rename detection: R entries analyze the OLD path on
# the base side and map old->new when comparing finding keys, so a pure
# rename introduces no "new" findings.
git diff --name-status --find-renames "$BASE_SHA" > "$TMP/name-status.txt"
git diff -U0 --find-renames "$BASE_SHA" > "$TMP/diff.txt"

is_src() { case "$1" in *.c|*.cpp|*.cc|*.cxx) return 0;; *) return 1;; esac; }
# --exclude patterns match the repo-relative path (bash `case` globbing:
# `*` crosses directory separators, so tests/* covers tests/a/b.c).
is_excluded() {
    local rel="$1" pat
    for pat in ${EXCLUDES[@]+"${EXCLUDES[@]}"}; do
        case "$rel" in $pat) return 0;; esac
    done
    return 1
}
# A changed file is reviewed when it is a C/C++ source and not excluded.
wants() { is_src "$1" && ! is_excluded "$1"; }

: > "$TMP/head-files.txt"
: > "$TMP/base-files.txt"   # base-side paths, RELATIVE (worktree-joined later)
: > "$TMP/renames.txt"
while IFS=$'\t' read -r st p1 p2; do
    case "$st" in
        A) if wants "$p1"; then echo "$HEAD_ROOT/$p1" >> "$TMP/head-files.txt"; fi;;
        M) if wants "$p1"; then
               echo "$HEAD_ROOT/$p1" >> "$TMP/head-files.txt"
               echo "$p1" >> "$TMP/base-files.txt"
           fi;;
        R*) if wants "$p2"; then
                echo "$HEAD_ROOT/$p2" >> "$TMP/head-files.txt"
                if is_src "$p1"; then
                    echo "$p1" >> "$TMP/base-files.txt"
                    printf '%s\t%s\n' "$p1" "$p2" >> "$TMP/renames.txt"
                fi
            fi;;
        C*) if wants "$p2"; then echo "$HEAD_ROOT/$p2" >> "$TMP/head-files.txt"; fi;;
        D) : ;;  # listed in the honesty section by the assembler
    esac
done < "$TMP/name-status.txt"

# ---- run the analyzer on both sides --------------------------------------
# Exit 0/1 = clean/findings (both fine here); anything above 1 is an
# analyzer failure and the review must NOT pretend to be a verdict.
run_zd() { # <files-list> <build-path> <json-out> <summary-out> <stderr-log>
    local code=0
    "$ZD_BIN" --files "$1" --build-path "$2" --json "$3" \
        --summary-out "$4" --lang en \
        ${EXTRA[@]+"${EXTRA[@]}"} 2> "$5" || code=$?
    # 0/1 = clean/findings. The binary maps internal "no files" (2) onto
    # exit 1 as well, so the JSON's existence is the real success signal.
    if [ "$code" -gt 1 ] || [ ! -f "$3" ]; then
        echo "[review] FAIL: analyzer error (exit $code) — stderr tail:" >&2
        tail -n 20 "$5" >&2
        exit 2
    fi
}

HEAD_JSON=""; BASE_JSON=""; SUMDIFF=""
if [ -s "$TMP/head-files.txt" ]; then
    run_zd "$TMP/head-files.txt" "$BUILD_PATH" "$TMP/head.json" \
        "$TMP/head.sum" "$TMP/head-stderr.log"
    HEAD_JSON="$TMP/head.json"
fi

if [ -s "$TMP/base-files.txt" ]; then
    git worktree add --detach "$BASE_WT" "$BASE_SHA" >/dev/null 2>&1

    # Base compile DB: head commands remapped onto the worktree. Without
    # a head compile DB both sides run in the same fallback parse mode —
    # still a fair delta.
    BASE_DB="$BASE_WT"
    if [ -f "$BUILD_PATH/compile_commands.json" ]; then
        BASE_DB="$TMP/basedb"
        python3 "$REPORT_PY" remap-db --src "$BUILD_PATH/compile_commands.json" \
            --from-root "$HEAD_ROOT" --to-root "$BASE_WT" \
            --protect "$BUILD_PATH" \
            --out "$BASE_DB/compile_commands.json"
    fi

    : > "$TMP/base-files-abs.txt"
    while IFS= read -r rel; do
        [ -f "$BASE_WT/$rel" ] && echo "$BASE_WT/$rel" >> "$TMP/base-files-abs.txt"
    done < "$TMP/base-files.txt"

    if [ -s "$TMP/base-files-abs.txt" ]; then
        run_zd "$TMP/base-files-abs.txt" "$BASE_DB" "$TMP/base.json" \
            "$TMP/base.sum" "$TMP/base-stderr.log"
        BASE_JSON="$TMP/base.json"
    fi
fi

# ---- contract diff (WEAKENED gates via the assembler) ---------------------
# --gate warn here so a weakened contract does not stop the pipeline; the
# assembler is the single gate point. Exit 2 (unreadable) stays fatal.
if [ -s "$TMP/base.sum" ] && [ -s "$TMP/head.sum" ]; then
    code=0
    "$ZD_BIN" --summary-diff "$TMP/base.sum" "$TMP/head.sum" --gate warn \
        --lang en > "$TMP/sumdiff.txt" || code=$?
    if [ "$code" -ge 2 ]; then
        echo "[review] FAIL: summary diff could not read its inputs" >&2
        exit 2
    fi
    SUMDIFF="$TMP/sumdiff.txt"
fi

# ---- assemble the review; its exit code is the verdict --------------------
STRICT_ARG=()
if [ "$STRICT" -eq 1 ]; then STRICT_ARG=(--strict); fi
EXCLUDE_ARGS=()
for pat in ${EXCLUDES[@]+"${EXCLUDES[@]}"}; do
    EXCLUDE_ARGS+=(--exclude "$pat")
done

python3 "$REPORT_PY" assemble \
    ${BASE_JSON:+--base-json "$BASE_JSON"} \
    ${HEAD_JSON:+--head-json "$HEAD_JSON"} \
    --base-root "$BASE_WT" --head-root "$HEAD_ROOT" \
    --renames "$TMP/renames.txt" \
    --diff "$TMP/diff.txt" \
    --name-status "$TMP/name-status.txt" \
    --head-files "$TMP/head-files.txt" \
    ${SUMDIFF:+--summary-diff "$SUMDIFF"} \
    --head-stderr "$TMP/head-stderr.log" \
    --gate "$GATE" \
    ${STRICT_ARG[@]+"${STRICT_ARG[@]}"} \
    ${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"} \
    --base-label "$BASE_SHORT" --head-label "working tree" \
    ${OUT:+--out "$OUT"}
