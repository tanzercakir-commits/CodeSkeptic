#!/usr/bin/env bash
# Doc-hygiene guard (2026-07-30). Mechanically enforces the working
# agreement so it does not rest on memory:
#   1. the canonical planning files exist and are non-empty;
#   2. no scattered per-feature PLAN-*.md briefs (fold into PLAN.md);
#   3. a src/ change ships with a changelog entry (progress is logged).
# Runs in the required build-and-test lane, so a miss blocks merge.
set -uo pipefail
fail=0

# 1. Canonical trio.
for f in docs/PLAN.md docs/TODO.md docs/devlog/changelog.md; do
    if [ ! -s "$f" ]; then
        echo "FAIL: missing or empty canonical file: $f"
        fail=1
    fi
done

# 2. No scattered plan briefs — the whole plan lives in one PLAN.md.
briefs=$(ls docs/PLAN-*.md 2>/dev/null || true)
if [ -n "$briefs" ]; then
    echo "FAIL: scattered plan briefs found (fold into docs/PLAN.md, delete these):"
    echo "$briefs" | sed 's/^/  /'
    fail=1
fi

# 3. changelog freshness: a src/ change must be logged. Best-effort —
#    silently skipped when no shared base is available (shallow clone,
#    first commit), never a false failure.
base=""
if git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    base=origin/main
elif git fetch -q --depth=50 origin main 2>/dev/null; then
    base=FETCH_HEAD
fi
if [ -n "$base" ] && git merge-base "$base" HEAD >/dev/null 2>&1; then
    mb=$(git merge-base "$base" HEAD)
    changed=$(git diff --name-only "$mb" HEAD)
    if echo "$changed" | grep -qE '^src/' &&
       ! echo "$changed" | grep -qxF 'docs/devlog/changelog.md'; then
        echo "FAIL: src/ changed but docs/devlog/changelog.md was not updated."
        echo "      Every code change logs its rationale in the changelog."
        fail=1
    fi
else
    echo "note: changelog-freshness check skipped (no shared base)"
fi

[ "$fail" -eq 0 ] && echo "ok: docs in sync (canonical files, no scatter, changelog fresh)"
exit "$fail"
