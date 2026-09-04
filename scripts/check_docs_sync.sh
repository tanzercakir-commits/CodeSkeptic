#!/usr/bin/env bash
# Local FIFO replaces the retired phase ledger. No network or implicit fixes.
# Preserve existing capability, version, measurement and real-world guards.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1
fail=0
if [ "${1:-check}" != "check" ]; then
    echo 'FAIL: no manual --fix; use project_queue.py finalize/amend/recover'
    exit 1
fi
python3 -B scripts/project_queue.py check || fail=1

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

[ "$fail" -eq 0 ] && echo "ok: FIFO views, rules, capabilities, versions and measurement contracts agree"
exit "$fail"
