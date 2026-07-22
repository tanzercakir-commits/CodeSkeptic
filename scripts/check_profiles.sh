#!/usr/bin/env bash
# Profile format guard (Phase 3 of docs/PLAN-v0.4.md): every
# profiles/*.conf must parse as key = value lines whose keys Config
# actually understands — a silently-ignored key in a shipped example
# is worse than no example. Keep KNOWN_KEYS in sync with
# Config::loadFromFile (src/config/Config.cpp).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

KNOWN_KEYS='source_path|build_path|output_format|json_output|sarif_output|html_output|min_severity|lang|baseline|function|fatal_asserts|alloc_functions|free_functions|owning_pointers|untrusted_int_sources|report_paths|policy|summary_diff_gate|analyze_broken_tus|enable_rule|disable_rule'

fail=0
shopt -s nullglob
profiles=(profiles/*.conf)
if [ "${#profiles[@]}" -eq 0 ]; then
    echo "FAIL: no profiles found under profiles/"
    exit 1
fi

for f in "${profiles[@]}"; do
    lineno=0
    while IFS= read -r line; do
        lineno=$((lineno + 1))
        # strip comments and blank lines
        stripped="${line%%#*}"
        stripped="$(echo "$stripped" | xargs 2>/dev/null || true)"
        [ -z "$stripped" ] && continue
        if ! echo "$stripped" | grep -qE "^(${KNOWN_KEYS})[[:space:]]*=[[:space:]]*[^[:space:]]"; then
            echo "FAIL: $f:$lineno unknown key or malformed line: $line"
            fail=1
        fi
    done < "$f"
    echo "ok: $f"
done

# Config.cpp drift check: every key in KNOWN_KEYS must still appear in
# the parser, so the list cannot silently rot.
IFS='|' read -ra keys <<< "$KNOWN_KEYS"
for k in "${keys[@]}"; do
    if ! grep -q "\"$k\"" src/config/Config.cpp; then
        echo "FAIL: check_profiles.sh KNOWN_KEYS lists '$k' but Config.cpp does not parse it"
        fail=1
    fi
done

exit "$fail"
