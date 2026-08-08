#!/usr/bin/env bash
# Doc-hygiene guard (2026-07-30). Mechanically enforces the working
# agreement so it does not rest on memory:
#   1. the canonical planning files exist and are non-empty;
#   2. no scattered per-feature PLAN-*.md briefs (fold into PLAN.md);
#   3. a src/ change ships with a changelog entry (progress is logged).
#   6. TODO's state block agrees with git (generated, not remembered).
#   7. the executable real-world replay ledger is internally consistent.
# Runs in the required build-and-test lane, so a miss blocks merge.
#
# --fix regenerates what is derivable (check 6) instead of only
# complaining about it: the guard alone catches forgetting but does not
# undo it, and a generator alone drifts whenever nobody runs it. Both
# together close the hole.
set -uo pipefail
fail=0
mode="${1:-check}"

# The derivable half of TODO's state block: which main commit the work
# sits on, and which phase branches are alive on the remote. Prints the
# block body, or returns 1 when git cannot answer (no shared base).
state_block() {
    local b branches cur
    b=$(git merge-base "$1" HEAD 2>/dev/null) || return 1
    b=$(git rev-parse --short "$b" 2>/dev/null) || return 1
    cur="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}"
    # In flight means UNMERGED, not merely present: a phase branch left
    # on the remote after its ff is a leftover, and listing it would
    # manufacture exactly the false record this check exists to kill.
    branches=$(git ls-remote --heads origin 'refs/heads/phase-*' 2>/dev/null \
               | while read -r sha ref; do
                     git merge-base --is-ancestor "$sha" "$1" 2>/dev/null \
                         || printf '%s\n' "${ref#refs/heads/}"
                 done)
    case "$cur" in phase-*) branches=$(printf '%s\n%s\n' "$branches" "$cur") ;; esac
    branches=$(printf '%s\n' "$branches" | grep -v '^$' | sort -u | tr '\n' ' ')
    branches="${branches% }"
    [ -z "$branches" ] && branches="yok"
    printf 'base   = %s\nuçuşta = %s\n' "$b" "$branches"
}

# The body currently recorded between the markers, fences stripped.
recorded_block() {
    awk '/<!-- cs:state-begin/{f=1;next} /<!-- cs:state-end/{f=0} f' \
        docs/TODO.md | grep -vE '^```$' | grep -v '^$'
}

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
elif [ -n "${GITHUB_ACTIONS:-}" ]; then
    # In CI a base is always obtainable, so failing to find one means the
    # checkout is shallow and checks 3 and 6 are about to no-op. That is
    # how they ran from c8ca617 to 2026-08-01: lane green, guard never
    # executed. A guard that cannot check must say so loudly, not pass.
    echo "FAIL: no shared base with main, so the changelog-freshness and"
    echo "      state-block checks cannot run. Under CI that is a broken"
    echo "      guard, not a soft skip — check out with fetch-depth: 0."
    fail=1
else
    echo "note: changelog-freshness check skipped (no shared base — local shallow clone)"
fi

# --fix: regenerate the derivable block and stop. Everything else in
# TODO.md is judgment (priorities, open user decisions) and is never
# touched — generating it would be fabricating a record, not keeping one.
if [ "$mode" = "--fix" ]; then
    body=$(state_block "${base:-origin/main}") || {
        echo "FAIL: --fix cannot derive the state block (no shared base)."
        exit 1
    }
    awk -v body="$body" '
        /<!-- cs:state-begin/ { print; print "```"; print body; print "```"; s=1; next }
        /<!-- cs:state-end/   { s=0 }
        !s { print }
    ' docs/TODO.md > docs/TODO.md.tmp && mv docs/TODO.md.tmp docs/TODO.md
    echo "fixed: docs/TODO.md state block regenerated"
    printf '%s\n' "$body" | sed 's/^/  /'
    exit 0
fi

# 6. TODO state block <-> git reality. Both facts in it — the main
#    commit this work sits on, and the phase branches alive on the
#    remote — are derivable, so they are GENERATED and verified here
#    instead of remembered. The failure this closes was silent: the
#    block read `main = 3ae3ecb` for five commits while listing two
#    long-merged branches as in flight, and nothing could notice.
#    Enforced on phase* branches, where the refresh belongs; on main the
#    block records the round that just merged and has nothing to prove.
cur_ref="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}"
is_phase=0
case "$cur_ref" in phase-*) is_phase=1 ;; esac
if [ "$is_phase" = 0 ]; then
    echo "state-block check n/a on '$cur_ref' (enforced on phase* branches)"
fi
if [ -n "$base" ] && [ "$is_phase" = 1 ]; then
    if ! grep -q 'cs:state-begin' docs/TODO.md; then
        echo "FAIL: docs/TODO.md has no <!-- cs:state-begin --> block to verify."
        fail=1
    elif want=$(state_block "$base"); then
        if [ "$(recorded_block)" != "$want" ]; then
            echo "FAIL: docs/TODO.md state block disagrees with git."
            echo "  recorded:"; recorded_block | sed 's/^/    /'
            echo "  actual:";   printf '%s\n' "$want" | sed 's/^/    /'
            echo "      Refresh it: scripts/check_docs_sync.sh --fix"
            fail=1
        else
            # Affirm on success too. A silent pass cannot be told apart
            # from a check that never ran — the exact way this guard was
            # able to report success from a shallow checkout for days.
            echo "state-block verified: $(printf '%s' "$want" | tr '\n' ' ')"
        fi
    elif [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "FAIL: state-block check could not resolve a base under CI."
        fail=1
    else
        echo "note: state-block check skipped (git could not resolve a base)"
    fi
fi

# 4. Rule registry <-> README Rules table: every finding rule_id the
#    code can emit must appear in README.md, so a shipped rule can never
#    be silently absent from the public capability list (the drift an
#    external review flagged, 2026-07-30). Skip-list holds ids that are
#    diagnostics, not detection rules (malformed-contract reporting).
rule_skip=" contract-syntax "
ids=$( { grep -rhoE 'return "[a-z0-9-]+";' src/rules/*.cpp src/rules/*.h;
         grep -rhoE 'rule_id = "[a-z0-9-]+"' src/rules/*.cpp; } \
       | grep -oE '"[a-z0-9-]+"' | tr -d '"' | sort -u )
for id in $ids; do
    case "$rule_skip" in *" $id "*) continue ;; esac
    if ! grep -qF "$id" README.md; then
        echo "FAIL: rule '$id' is emitted by the code but not in README.md."
        echo "      Add it to the Rules table (or the skip-list if it is not a detection rule)."
        fail=1
    fi
done

# 5. Doc version pins agree with the canonical CMake version, so a
#    release bumps the install docs in the same commit (README already
#    did; evaluate.md drifted to an older tag before this guard).
ver=$(grep -oE 'VERSION [0-9]+\.[0-9]+\.[0-9]+' CMakeLists.txt | head -1 | awk '{print $2}')
if [ -n "$ver" ]; then
    for f in README.md docs/evaluate.md; do
        [ -f "$f" ] || continue
        bad=$(grep -oE '(:v|@v)[0-9]+\.[0-9]+\.[0-9]+' "$f" | grep -vF "v$ver" || true)
        if [ -n "$bad" ]; then
            echo "FAIL: $f pins a version other than the canonical v$ver (CMakeLists):"
            echo "$bad" | sed 's/^/  /'
            fail=1
        fi
    done
fi

# 7. A measurement ledger is a contract, not prose. Reject duplicate/missing
# projects, non-SHA inputs, unavailable verdicts, and dishonest triage sums
# before realworld.yml consumes the values.
if ! python3 scripts/check_realworld_ledger.py; then
    fail=1
fi

[ "$fail" -eq 0 ] && echo "ok: docs in sync (canonical files, no scatter, changelog fresh, rules listed, versions pinned)"
exit "$fail"
