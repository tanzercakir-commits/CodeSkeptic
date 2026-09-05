#!/usr/bin/env python3
"""End-to-end validation of the installed capability discovery surface."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
from collections import Counter


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
if len(payload.get("rules", [])) != 15:
    fail("legacy rules list is missing or incomplete")
if payload.get("success_metrics", {}).get("cwe_count") is not False:
    fail("CWE count must be published as a non-metric")

rules = payload.get("rule_capabilities")
if not isinstance(rules, list) or len(rules) != 15:
    fail(f"expected 15 rules, got {len(rules) if isinstance(rules, list) else type(rules)}")
if len({rule.get("id") for rule in rules}) != len(rules):
    fail("duplicate rule id")

expected_supported = {
    "double-free",
    "memory-leak",
    "use-after-free",
    "div-by-zero",
    "null-deref",
    "int-overflow",
    "resource-leak",
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

alloc_size = next(
    (rule for rule in rules if rule.get("id") == "alloc-size-overflow"),
    None,
)
expected_alloc_size = {
    "tier": "experimental",
    "default_enabled": True,
    "quality_gated": False,
    "blocks_verdict": False,
}
if alloc_size is None:
    fail("alloc-size-overflow capability is missing")
for field, expected in expected_alloc_size.items():
    if alloc_size.get(field) != expected:
        fail(
            f"alloc-size-overflow {field} expected={expected!r} "
            f"got={alloc_size.get(field)!r}"
        )

scalar = next((rule for rule in rules if rule.get("id") == "uninit-scalar"), None)
if scalar is None:
    fail("uninit-scalar capability is missing")
for field, expected in expected_alloc_size.items():
    if scalar.get(field) != expected:
        fail(f"uninit-scalar {field} expected={expected!r} got={scalar.get(field)!r}")

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

print("CAPABILITIES_CLI_OK schema=2 rules=15 supported=7 out_of_scope=5")

# The advertised diagnostic IDs must select every producer, not just a class
# with the same name. Exercise actual CLI reports and the MCP wire protocol.
binary = binary.resolve()
with tempfile.TemporaryDirectory(prefix="codeskeptic-rule-selection-") as directory:
    root = Path(directory)
    source = root / "selection.cpp"
    source.write_text('''
struct FILE; struct DIR;
extern FILE* fopen(const char*,const char*); extern int fclose(FILE*);
extern DIR* opendir(const char*); extern int closedir(DIR*);
extern int open(const char*,int,...); extern int close(int);
extern void* malloc(unsigned long); extern void free(void*);
int file_leak(const char* p){FILE* f=fopen(p,"r");if(!f)return 1;return 0;}
int dir_leak(const char* p){DIR* d=opendir(p);if(!d)return 1;return 0;}
void fd_leak(const char* p){int fd=open(p,0);(void)fd;}
void heap_leak(){void* p=malloc(8);(void)p;}
int file_safe(const char* p){FILE* f=fopen(p,"r");if(!f)return 1;fclose(f);return 0;}
int dir_safe(const char* p){DIR* d=opendir(p);if(!d)return 1;closedir(d);return 0;}
void fd_safe(const char* p){int fd=open(p,0);close(fd);}
void heap_safe(){void* p=malloc(8);free(p);}
''')
    expected_all = Counter({"resource-leak": 3, "memory-leak": 1})
    def run(arguments, requests=None):
        return subprocess.run([str(binary), *map(str, arguments)], cwd=root,
                              input=requests, text=True, capture_output=True, timeout=45)
    def check_report(report, expected, finding_key="diagnostics", id_key="rule_id"):
        assert report["complete"] is True, report
        assert report["coverage"] == {"attempted_tus": 1, "analyzed_tus": 1,
                                       "broken_tus": 0, "incomplete_functions": 0}, report
        findings = report[finding_key]
        assert Counter(d[id_key] for d in findings) == expected, findings
        assert all(not d.get("function", "").endswith("_safe") for d in findings), findings
        if finding_key == "diagnostics":
            assert report["total"] == sum(expected.values()), report
        else:
            assert report["count"] == report["blocking_count"] == sum(expected.values()), report
            assert report["report_only_count"] == 0, report
    for name, options, expected in [
        ("default", [], expected_all),
        ("no-resource", ["--disable-rule", "resource-leak"], Counter({"memory-leak": 1})),
        ("no-memory", ["--disable-rule", "memory-leak"], Counter({"resource-leak": 3})),
    ]:
        output = root / (name + ".json")
        result = run([source, "--json", output, *options])
        assert result.returncode == 1, result.stderr
        check_report(json.loads(output.read_text()), expected)
        sarif = root / (name + ".sarif")
        result = run([source, "--sarif", sarif, *options])
        assert result.returncode == 1, result.stderr
        findings = json.loads(sarif.read_text())["runs"][0]["results"]
        assert Counter(d["ruleId"] for d in findings) == expected, findings
    def request(identifier, **options):
        return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                "params": {"name": "analyze", "arguments": {"path": str(source), **options}}}
    requests = [request(1, disable_rules="resource-leak"), request(2),
                request(3, disable_rules="resource-leak"),
                request(4, disable_rules="memory-leak")]
    result = run(["--serve"], "".join(json.dumps(r) + "\n" for r in requests))
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == len(requests), result.stdout
    for index, (response, expected) in enumerate(zip(responses,
            [Counter({"memory-leak": 1}), expected_all,
             Counter({"memory-leak": 1}), Counter({"resource-leak": 3})]), 1):
        assert response["id"] == index and "error" not in response, response
        assert response["result"]["isError"] is False, response
        data = json.loads(response["result"]["content"][0]["text"])
        check_report(data, expected, "findings", "rule")
    # Startup flags must reach the real server, without importing unrelated
    # launch report destinations or changing defaults between requests.
    result = run(["--serve", "--disable-rule", "resource-leak"],
                 json.dumps(request(10)) + "\n" + json.dumps(request(11)) + "\n")
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == 2, result.stdout
    for response in responses:
        check_report(json.loads(response["result"]["content"][0]["text"]),
                     Counter({"memory-leak": 1}), "findings", "rule")
print("DIAGNOSTIC_SELECTION_CLI_MCP_OK mixed producers, JSON/SARIF, request isolation, server defaults")
