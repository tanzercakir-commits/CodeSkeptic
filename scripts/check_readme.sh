#!/usr/bin/env bash
# README/docs structure guard (Phase 0 of docs/PLAN-v0.4.md).
#
# Enforces the "first five minutes" contract so the README cannot
# silently regrow into a wall of text:
#   1. Line budget: README.md <= 300 lines (the deep content lives in
#      docs/ — layered, not deleted).
#   2. Required sections: the questions a first-time reader must be
#      able to answer on the first screen(s).
#   3. Relative-link integrity: every relative markdown link in the
#      README and the curated docs resolves to a real file/dir.
#
# Usage: scripts/check_readme.sh   (from the repo root; CI runs it in docs.yml)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail=0

# --- 1. Line budget -------------------------------------------------
MAX_LINES=300
lines=$(wc -l < README.md)
if [ "$lines" -gt "$MAX_LINES" ]; then
    echo "FAIL: README.md is $lines lines (budget: $MAX_LINES)." \
         "Move depth into docs/ instead of growing the front page."
    fail=1
else
    echo "ok: README.md line budget ($lines/$MAX_LINES)"
fi

# --- 2. Required sections -------------------------------------------
required=(
    "## Quickstart"
    "## What it won't catch"
    "## Use it alongside"
    "## Rules"
    "## License"
)
for h in "${required[@]}"; do
    if ! grep -qF "$h" README.md; then
        echo "FAIL: README.md is missing required section: '$h'"
        fail=1
    fi
done
[ "$fail" -eq 0 ] && echo "ok: all required README sections present"

# --- 3. Relative-link integrity -------------------------------------
# Files under the guard (the curated reader-facing set; the devlog and
# working plans are exempt).
docs_files=(
    README.md
    ROADMAP.md
    docs/usage.md
    docs/integrations.md
    docs/benchmarks.md
    docs/comparison.md
    docs/engine.md
    docs/evaluate.md
    docs/token-ablation.md
    docs/windows-support.md
    docs/devlog/README.md
)
for f in "${docs_files[@]}"; do
    [ -f "$f" ] || { echo "FAIL: guarded file missing: $f"; fail=1; continue; }
    dir=$(dirname "$f")
    # extract (target) of every [text](target) / ![alt](target)
    while IFS= read -r target; do
        case "$target" in
            http://*|https://*|mailto:*|"#"*) continue ;;
        esac
        path="${target%%#*}"            # strip anchor
        [ -n "$path" ] || continue
        if [ ! -e "$dir/$path" ]; then
            echo "FAIL: $f -> broken relative link: $target"
            fail=1
        fi
    done < <(grep -oE '\]\([^)]+\)' "$f" | sed -E 's/^\]\(//; s/\)$//')
done
[ "$fail" -eq 0 ] && echo "ok: all relative links resolve"

exit "$fail"
