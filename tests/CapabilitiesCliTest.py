#!/usr/bin/env python3
"""End-to-end validation of the installed capability discovery surface."""

import json
from pathlib import Path
import subprocess
import sys


def fail(message: str) -> None:
    print(f"CAPABILITIES_CLI_FAIL {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: CapabilitiesCliTest.py <codeskeptic-binary>")

binary = Path(sys.argv[1])
result = subprocess.run(
    [str(binary), "--capabilities", "--json"],
    check=False,
    text=True,
    capture_output=True,
)
if result.returncode != 0:
    fail(f"json discovery exit={result.returncode} stderr={result.stderr!r}")

try:
    payload = json.loads(result.stdout)
except json.JSONDecodeError as error:
    fail(f"invalid JSON: {error}")

if payload.get("schema_version") != 2:
    fail(f"schema_version={payload.get('schema_version')!r}")
# Schema v2 adds tier metadata without removing v1 name-enumeration fields.
legacy = {
    "languages": ["c", "cpp"],
    "frontends": ["cli", "mcp"],
    "outputs": ["console", "json", "sarif-2.1.0", "html"],
}
for field, expected in legacy.items():
    if payload.get(field) != expected:
        fail(f"legacy {field} expected={expected!r} got={payload.get(field)!r}")
if len(payload.get("rules", [])) != 14:
    fail("legacy rules list is missing or incomplete")
if payload.get("success_metrics", {}).get("cwe_count") is not False:
    fail("CWE count must be published as a non-metric")

rules = payload.get("rule_capabilities")
if not isinstance(rules, list) or len(rules) != 14:
    fail(f"expected 14 rules, got {len(rules) if isinstance(rules, list) else type(rules)}")
if len({rule.get("id") for rule in rules}) != len(rules):
    fail("duplicate rule id")

expected_supported = {
    "double-free",
    "use-after-free",
    "div-by-zero",
    "null-deref",
    "int-overflow",
}
actual_supported = set()
for rule in rules:
    tier = rule.get("tier")
    rule_id = rule.get("id")
    if tier == "supported":
        actual_supported.add(rule_id)
        if not all(
            rule.get(field) is True
            for field in ("default_enabled", "quality_gated", "blocks_verdict")
        ):
            fail(f"supported invariant violated by {rule_id}")
    elif tier == "experimental":
        if rule.get("blocks_verdict") is not False:
            fail(f"experimental rule blocks: {rule_id}")
    else:
        fail(f"invalid rule tier {tier!r} for {rule_id}")
if actual_supported != expected_supported:
    fail(f"supported set expected={sorted(expected_supported)} got={sorted(actual_supported)}")

out_of_scope = {
    item.get("id")
    for item in payload.get("capabilities", {}).get("out_of_scope", [])
    if item.get("tier") == "out-of-scope"
}
expected_out_of_scope = {
    "injection-taint",
    "race-detection",
    "automatic-fixes",
    "ide",
    "cloud-dashboard",
}
if out_of_scope != expected_out_of_scope:
    fail(
        f"out-of-scope expected={sorted(expected_out_of_scope)} "
        f"got={sorted(out_of_scope)}"
    )

text_result = subprocess.run(
    [str(binary), "--capabilities"],
    check=False,
    text=True,
    capture_output=True,
)
if text_result.returncode != 0 or "experimental rules:" not in text_result.stdout:
    fail("human-readable discovery contract failed")

print("CAPABILITIES_CLI_OK schema=2 rules=14 supported=5 out_of_scope=5")
