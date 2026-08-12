#!/usr/bin/env bash
# Doc-hygiene guard (2026-07-30). Mechanically enforces the working
# agreement so it does not rest on memory:
#   1. the canonical planning/progress files exist and are non-empty;
#   2. no scattered per-feature PLAN-*.md briefs (fold into PLAN.md);
#   3. a src/ change ships with a changelog entry (progress is logged).
#   6. append-only protected-main progress and TODO state agree with git.
#   7. the executable real-world replay ledger is internally consistent.
# Runs in the required build-and-test lane, so a miss blocks merge.
#
# --fix appends verified protected-main transitions and regenerates the
# derivable TODO state view (check 6) instead of only
# complaining about it: the guard alone catches forgetting but does not
# undo it, and a generator alone drifts whenever nobody runs it. Both
# together close the hole.
set -uo pipefail
fail=0
mode="${1:-check}"

# 1. Canonical plan, compass, verified ledger, and detailed history.
for f in docs/PLAN.md docs/TODO.md docs/PROGRESS.md docs/devlog/changelog.md; do
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

# --fix: append only transitions already reachable from protected main and
# regenerate the marked TODO state view. Everything else in TODO.md remains
# judgment and is never touched.
if [ "$mode" = "--fix" ]; then
    python3 scripts/progress_status.py sync \
        --base-ref "${base:-origin/main}" || exit 1
    echo "fixed: verified progress appended and TODO state regenerated"
    exit 0
fi

# 6. PROGRESS/TODO <-> protected-main reality. The ledger is append-only and
#    may call a transition MERGED only after the commit is reachable from
#    main. TODO's marked view binds the ledger digest, verified main, branch
#    base, and live phase refs. Main cannot record its own merge commit in the
#    same tree, so enforcement belongs to phase branches and PR head refs.
cur_ref="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}}"
is_phase=0
case "$cur_ref" in phase-*) is_phase=1 ;; esac
if [ "$is_phase" = 0 ]; then
    echo "progress/state check n/a on '$cur_ref' (enforced on phase* branches)"
fi
if [ -n "$base" ] && [ "$is_phase" = 1 ]; then
    if python3 scripts/progress_status.py check --base-ref "$base"; then
        :
    elif [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "FAIL: verified progress/state could not be proven under CI."
        fail=1
    else
        echo "FAIL: verified progress/state is stale or unavailable."
        echo "      Refresh it: scripts/check_docs_sync.sh --fix"
        fail=1
    fi
fi

# 4. Rule registry <-> README Rules table: every finding rule_id the
#    code can emit must appear in README.md, so a shipped rule can never
#    be silently absent from the public capability list (the drift an
#    external review flagged, 2026-07-30). Skip-list holds ids that are
#    diagnostics, not detection rules (malformed-contract reporting).
rule_skip=" contract-syntax contract-unsupported "
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

# 4b. Product-scope tiers are one contract across runtime source, README and
#     the detailed rule documentation. This also enforces supported/default/
#     quality/blocking and experimental/report-only invariants.
python3 scripts/check_capabilities_sync.py || fail=1

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

# 5b. Phase 2 measurement is one executable/documented contract. A missing
# workflow, receipt producer, comparator, baseline, or schema explanation
# would make the PR dashboard look present while silently dropping an axis.
for f in .github/workflows/measurement.yml \
         scripts/run_measurement_lab.py scripts/compare_measurements.py \
         scripts/render_quality_dashboard.py scripts/measurement_baseline.json; do
    if [ ! -s "$f" ]; then
        echo "FAIL: missing or empty measurement contract file: $f"
        fail=1
    fi
done
for marker in 'csf1' 'JULIET_MISS_CLASS' 'measurement.yml'; do
    if ! grep -qF "$marker" docs/benchmarks.md; then
        echo "FAIL: docs/benchmarks.md omits measurement contract marker: $marker"
        fail=1
    fi
done

# 7. A measurement ledger is a contract, not prose. Reject duplicate/missing
# projects, non-SHA inputs, unavailable verdicts, and dishonest triage sums
# before realworld.yml consumes the values.
if ! python3 scripts/check_realworld_ledger.py; then
    fail=1
fi

# 8. Current-head candidate summaries are derived evidence. When retained
# receipts exist, bind their checksums, exact manifest, frozen revision,
# semantic result, and canonical summaries so a transcription cannot pass CI.
if ! python3 scripts/check_upstream_candidate_evidence.py; then
    fail=1
fi

[ "$fail" -eq 0 ] && echo "ok: docs in sync (canonical files, no scatter, changelog fresh, rules listed, versions pinned)"
exit "$fail"
