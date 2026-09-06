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
        coverage = report["coverage"]
        expected_coverage = {"attempted_tus": 1, "analyzed_tus": 1,
                             "broken_tus": 0, "incomplete_functions": 0,
                             "skipped_tus": 0, "failed_tus": 0, "recovery_tus": 0,
                             "attempted_commands": 1, "analyzed_commands": 1,
                             "skipped_commands": 0, "failed_commands": 0}
        assert all(type(coverage[key]) is int and coverage[key] == value
                   for key, value in expected_coverage.items()), coverage
        assert coverage["schema"] == "codeskeptic-source-coverage/v1", coverage
        assert coverage["complete"] is True, coverage
        assert coverage["accept_partial_coverage"] is False, coverage
        assert coverage["analyze_broken_tus"] is False, coverage
        assert len(coverage["sources"]) == 1, coverage
        row = coverage["sources"][0]
        assert row["file"] == str(source.resolve()), row
        assert row["status"] == row["reason"] == "analyzed", row
        assert row["commands"] == row["analyzed_commands"] == 1, row
        assert row["skipped_commands"] == row["failed_commands"] == row["recovery_commands"] == 0, row
        assert row["prepass"] == {"status": "not_requested", "reason": "", "recovery_commands": 0}, row
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
    # Rejection must be shared with CLI and leave the next request untouched.
    invalid_values = ["", "memory-leak,,bounds", "memory-leak,zz-unknown", [], None, False]
    requests = [request(20, disable_rules="resource-leak")]
    requests += [request(21 + i, disable_rules=value) for i, value in enumerate(invalid_values)]
    requests += [request(30), request(31, disable_rules="resource-leak")]
    result = run(["--serve"], "".join(json.dumps(r) + "\n" for r in requests))
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r["id"] for r in responses] == [r["id"] for r in requests], responses
    for response, value in zip(responses[1:-2], invalid_values):
        assert "result" not in response and response["error"]["code"] == -32602, response
        error = response["error"]["data"]
        assert error["schema"] == "codeskeptic-input-error/v1", error
        assert error["field"] == "disable_rules", error
        if isinstance(value, str):
            cli = run([source, "--disable-rule", value])
            assert cli.returncode == 2, cli.stderr
            prefix = "[CodeSkeptic] input-error "
            errors = [json.loads(line[len(prefix):]) for line in cli.stderr.splitlines()
                      if line.startswith(prefix)]
            assert errors == [error], (cli.stderr, response)
        else:
            assert error["reason"] == "invalid_type", error
    first = json.loads(responses[0]["result"]["content"][0]["text"])
    restored = json.loads(responses[-1]["result"]["content"][0]["text"])
    assert restored == first, (first, restored)
    check_report(json.loads(responses[-2]["result"]["content"][0]["text"]),
                 expected_all, "findings", "rule")

    def check_no_rules(response):
        assert response["result"]["isError"] is True, response
        data = json.loads(response["result"]["content"][0]["text"])
        assert data["exit_code"] == 2 and data["status"] == "failed", data
        assert data["complete"] is False and data["count"] == 0, data
        assert data["coverage"]["analyzed_tus"] == 0, data

    all_ids = ",".join(rule["id"] for rule in rules)
    for options in ([], ["--assumptions"]):
        result = run([source, "--disable-rule", all_ids, *options])
        assert result.returncode == 2, result.stderr
        result = run(["--serve", *options],
                     json.dumps(request(40, disable_rules=all_ids)) + "\n")
        assert result.returncode == 0, result.stderr
        check_no_rules(json.loads(result.stdout))

    # Actual config-file allowlists reach both entry points. A per-request
    # exclusion adds to immutable defaults; it does not replace the allowlist.
    (root / ".codeskeptic.conf").write_text(
        "enable_rule=memory-leak\nenable_rule=resource-leak\ndisable_rule=resource-leak\n")
    output = root / "config-selection.json"
    result = run([source, "--json", output])
    assert result.returncode == 1, result.stderr
    check_report(json.loads(output.read_text()), Counter({"memory-leak": 1}))
    result = run(["--serve"], "".join(json.dumps(r) + "\n" for r in [
        request(50), request(51, disable_rules="memory-leak"), request(52)]))
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r["id"] for r in responses] == [50, 51, 52], responses
    check_no_rules(responses[1])
    for response in (responses[0], responses[2]):
        check_report(json.loads(response["result"]["content"][0]["text"]),
                     Counter({"memory-leak": 1}), "findings", "rule")
print("DIAGNOSTIC_SELECTION_CLI_MCP_OK mixed producers, JSON/SARIF, request isolation, server defaults")

# One source location can be a read under one compilation command and a write
# under another. Deduplication must retain both proven CWEs without multiplying
# findings or changing the source fingerprint. Command order is not authority.
with tempfile.TemporaryDirectory(prefix="codeskeptic-cwe-variants-") as directory:
    root = Path(directory)
    source = root / "variants.cpp"
    source.write_text('''
extern void sink(int);
#if WRITE_MODE
#define ACTION(x) ((x)=1)
#else
#define ACTION(x) sink(x)
#endif
void f(){int a[1]={}; ACTION(a[2]);}
''')
    fingerprints = set()
    for label, modes, expected in (
            ("read-write", [0, 1], [125, 787]),
            ("write-read", [1, 0], [125, 787]),
            ("same-read", [0, 0], [125]),
            ("same-write", [1, 1], [787])):
        database = root / label
        database.mkdir()
        entries = [{"directory": str(root), "file": str(source),
                    "arguments": ["clang++", "-std=c++17", f"-DWRITE_MODE={mode}",
                                  "-c", str(source)]} for mode in modes]
        (database / "compile_commands.json").write_text(json.dumps(entries))
        surfaces = []
        for output_format in ("json", "sarif"):
            output = database / ("result." + output_format)
            result = subprocess.run(
                [str(binary), str(source), "--build-path", str(database),
                 "--" + output_format, str(output)], cwd=root,
                capture_output=True, text=True, timeout=45)
            assert result.returncode == 0, (label, output_format, result.stderr)
            report = json.loads(output.read_text())
            if output_format == "json":
                assert report["complete"] is True, report
                assert report["finding_counts"] == {"total": 1, "blocking": 0, "report_only": 1}, report
                findings = report["diagnostics"]
                assert len(findings) == 1, findings
                row = findings[0]
                assert row["rule_id"] == "bounds", row
                metadata = row["rule_metadata"]
                fingerprints.add(row["fingerprint"])
            else:
                findings = report["runs"][0]["results"]
                assert len(findings) == 1, findings
                row = findings[0]
                assert row["ruleId"] == "bounds", row
                metadata = row["properties"]["codeskeptic/ruleMetadata"]
                fingerprints.add(row["partialFingerprints"]["codeskeptic/v1"])
            actual = sorted(cwe["id"] for cwe in metadata["cwes"])
            assert actual == expected, (label, output_format, expected, actual)
            surfaces.append(metadata)
        assert surfaces[0] == surfaces[1], surfaces
    assert len(fingerprints) == 1, fingerprints
print("CWE_VARIANT_METADATA_CLI_OK order-independent union, same-kind dedup, JSON/SARIF parity")

# Memory and non-memory lifetimes share stable public rule IDs, not CWEs.
# These are compile-only analyzer fixtures; no invalid operation is executed.
with tempfile.TemporaryDirectory(prefix="codeskeptic-cwe-lifetimes-") as directory:
    root = Path(directory)
    (root / ".codeskeptic.conf").write_text(
        "enable_rule=double-free\nenable_rule=use-after-free\n"
        "allocator_pairs=pool_alloc=pool_free\n")
    source = root / "lifetimes.cpp"
    source.write_text('''
struct FILE {int value;}; struct DIR {int value;};
using Size = decltype(sizeof(0));
extern "C" void* malloc(Size); extern "C" void free(void*);
extern "C" void* realloc(void*,Size);
struct Handle {int value;}; Handle* malloc(int,int); void free(Handle*,int);
extern "C" FILE* fopen(const char*,const char*); extern "C" int fclose(FILE*);
extern "C" DIR* opendir(const char*); extern "C" int closedir(DIR*);
extern void* pool_alloc(unsigned long); extern void pool_free(void*);
namespace handle_api {void* malloc(unsigned long); void free(void*);}
namespace std {
template<class T> class unique_ptr {
public: explicit unique_ptr(T* p=nullptr); void reset(T* p=nullptr); ~unique_ptr();
};
}
void heap_double(){int* p=(int*)malloc(8);free(p);free(p);}
int heap_use(){int* p=(int*)malloc(8);free(p);return *p;}
void new_double(){int* p=new int;delete p;delete p;}
int new_use(){int* p=new int;delete p;return *p;}
void alias_double(){int* p=(int*)malloc(8);int* q=p;free(q);free(p);}
int alias_use(){int* p=(int*)malloc(8);int* q=p;free(p);return *q;}
void file_double(){FILE* p=fopen("x","r");fclose(p);fclose(p);}
int file_use(){FILE* p=fopen("x","r");fclose(p);return p->value;}
void dir_double(){DIR* p=opendir("x");closedir(p);closedir(p);}
int dir_use(){DIR* p=opendir("x");closedir(p);return p->value;}
void file_alias_double(){FILE* p=fopen("x","r");FILE* q=p;fclose(q);fclose(p);}
int dir_alias_use(){DIR* p=opendir("x");DIR* q=p;closedir(p);return q->value;}
int file_to_heap(){FILE* p=fopen("x","r");fclose(p);p=(FILE*)malloc(8);free(p);return p->value;}
int heap_to_file(){FILE* p=(FILE*)malloc(8);free(p);p=fopen("x","r");fclose(p);return p->value;}
int mixed_branch(bool b){FILE* p;if(b){p=(FILE*)malloc(8);free(p);}else{p=fopen("x","r");fclose(p);}return p->value;}
void mixed_release(){FILE* p=fopen("x","r");fclose(p);free(p);}
void realloc_double(){int* p=(int*)malloc(8);int* q=(int*)realloc(p,16);if(q){free(p);free(q);}}
int realloc_use(){int* p=(int*)malloc(8);int* q=(int*)realloc(p,16);if(q){int v=*p;free(q);return v;}free(p);return 0;}
int realloc_alias_use(){int* p=(int*)malloc(8);int* a=p;int* q=(int*)realloc(a,16);if(q){int v=*p;free(q);return v;}free(p);return 0;}
void custom_double(){int* p=(int*)pool_alloc(8);pool_free(p);pool_free(p);}
int custom_use(){int* p=(int*)pool_alloc(8);pool_free(p);return *p;}
void namespace_double(){void* p=handle_api::malloc(8);handle_api::free(p);handle_api::free(p);}
int namespace_use(){int* p=(int*)handle_api::malloc(8);handle_api::free(p);return *p;}
void overload_double(){Handle* p=malloc(1,2);free(p,3);free(p,4);}
int overload_use(){Handle* p=malloc(1,2);free(p,3);return p->value;}
void reset_double(){int* p=new int;std::unique_ptr<int> owner(p);delete p;owner.reset();}
int reset_use(){int* p=new int;std::unique_ptr<int> owner(p);owner.reset();return *p;}
int destructor_use(){int* p=new int;{std::unique_ptr<int> owner(p);}return *p;}
void heap_safe(){int* p=(int*)malloc(8);free(p);}
void file_safe(){FILE* p=fopen("x","r");fclose(p);}
void dir_safe(){DIR* p=opendir("x");closedir(p);}
''')
    expected = {
        "heap_double": ("double-free", 415), "heap_use": ("use-after-free", 416),
        "new_double": ("double-free", 415), "new_use": ("use-after-free", 416),
        "alias_double": ("double-free", 415), "alias_use": ("use-after-free", 416),
        "file_double": ("double-free", 675), "file_use": ("use-after-free", 672),
        "dir_double": ("double-free", 675), "dir_use": ("use-after-free", 672),
        "file_alias_double": ("double-free", 675), "dir_alias_use": ("use-after-free", 672),
        "file_to_heap": ("use-after-free", 672), "heap_to_file": ("use-after-free", 672),
        "mixed_branch": ("use-after-free", 672), "mixed_release": ("double-free", 675),
        "realloc_double": ("double-free", 675), "realloc_use": ("use-after-free", 672),
        "realloc_alias_use": ("use-after-free", 672),
        "custom_double": ("double-free", 675), "custom_use": ("use-after-free", 672),
        "namespace_double": ("double-free", 675), "namespace_use": ("use-after-free", 672),
        "overload_double": ("double-free", 675), "overload_use": ("use-after-free", 672),
        "reset_double": ("double-free", 675), "reset_use": ("use-after-free", 672),
        "destructor_use": ("use-after-free", 672),
    }
    registry = {rule["id"]: rule for rule in rules}
    language_identities = []
    for language in ("en", "tr"):
        surfaces = []
        for output_format in ("json", "sarif"):
            output = root / (language + "." + output_format)
            result = subprocess.run(
                [str(binary), str(source),
                 "--lang", language, "--" + output_format, str(output)],
                cwd=root, capture_output=True, text=True, timeout=45)
            assert result.returncode == 1, (output_format, result.stderr)
            report = json.loads(output.read_text())
            if output_format == "json":
                assert report["complete"] is True, report
                findings = report["diagnostics"]
                assert len(findings) == len(expected), findings
                assert {row["function"] for row in findings} == set(expected), findings
                for row in findings:
                    rule_id, cwe_id = expected[row["function"]]
                    assert row["rule_id"] == rule_id, row
                    metadata = row["rule_metadata"]
                    assert metadata["cwe_mapping"] == "mapped", row
                    assert [cwe["id"] for cwe in metadata["cwes"]] == [cwe_id], row
                    advertised = registry[rule_id]
                    assert metadata["description"] == advertised["description"], row
                    assert metadata["help_uri"] == advertised["help_uri"], row
                    assert metadata["cwes"][0] in advertised["potential_cwes"], row
                    assert row["blocks_verdict"] is True, row
                    assert row["capability_tier"] == "supported", row
                surfaces.append({row["fingerprint"]: row["rule_metadata"] for row in findings})
            else:
                findings = report["runs"][0]["results"]
                assert len(findings) == len(expected), findings
                surfaces.append({row["partialFingerprints"]["codeskeptic/v1"]:
                                 row["properties"]["codeskeptic/ruleMetadata"] for row in findings})
        assert surfaces[0] == surfaces[1], surfaces
        language_identities.append(surfaces[0])
    assert language_identities[0] == language_identities[1], language_identities
print("CWE_LIFETIME_METADATA_CLI_OK memory/resource/alias/reassignment/realloc, EN/TR, JSON/SARIF/registry parity")

# Legacy leak selectors are intentionally preserved. Actual acquisitions, not
# the declaration's initializer, determine the selected weakness subtype.
with tempfile.TemporaryDirectory(prefix="codeskeptic-cwe-leaks-") as directory:
    root = Path(directory)
    (root / ".codeskeptic.conf").write_text(
        "enable_rule=memory-leak\nenable_rule=resource-leak\n"
        "allocator_pairs=pool_alloc=pool_free\n")
    source = root / "leaks.cpp"
    source.write_text('''
struct FILE; struct DIR;
using Size = decltype(sizeof(0));
extern "C" void* malloc(Size); extern "C" void free(void*);
extern "C" FILE* fopen(const char*,const char*); extern "C" int fclose(FILE*);
extern "C" DIR* opendir(const char*); extern "C" int closedir(DIR*);
extern "C" int open(const char*,int,...); extern "C" int pipe(int*);
extern "C" int openat(int,const char*,int,...); extern "C" int socket(int,int,int);
extern "C" int mkstemp(char*);
extern void* pool_alloc(Size); extern void pool_free(void*);
int open(double); int dup(int value){return value;}
void heap_assigned(){void* p;p=malloc(8);(void)p;}
void file_assigned(){FILE* p;p=fopen("x","r");(void)p;}
void dir_assigned(){DIR* p;p=opendir("x");(void)p;}
void file_overwrite(){FILE* p=fopen("x","r");
p=fopen("x","r");fclose(p);}
void heap_to_file_leak(){FILE* p=(FILE*)malloc(8);free(p);p=fopen("x","r");(void)p;}
void file_to_heap_leak(){FILE* p=fopen("x","r");fclose(p);p=(FILE*)malloc(8);(void)p;}
void direct_heap_leak(){void* p=malloc(8);(void)p;}
void direct_file_leak(){FILE* p=fopen("x","r");(void)p;}
void custom_leak(){void* p=pool_alloc(8);(void)p;}
void discarded_heap(){malloc(8);}
void discarded_file(){fopen("x","r");}
void discarded_custom(){pool_alloc(8);}
void native_fd_leak(){int fd=open("x",0);(void)fd;}
void native_openat_leak(){int fd=openat(1,"x",0);(void)fd;}
void native_socket_leak(){int fd=socket(1,1,0);(void)fd;}
void native_mkstemp_leak(char* path){int fd=mkstemp(path);(void)fd;}
void native_pipe_leak(){int fd[2];if(pipe(fd)<0)return;}
int acquire_handle(){return open("x",0);}
void summary_handle_leak(){int fd=acquire_handle();(void)fd;}
void overload_fd_leak(){int fd=open(1.5);(void)fd;}
void defined_body_fd_leak(){int fd=dup(1);(void)fd;}
void safe_heap(){void* p=malloc(8);free(p);}
void safe_file(){FILE* p=fopen("x","r");fclose(p);}
''')
    expected = {
        "heap_assigned": ("memory-leak", 401), "file_assigned": ("memory-leak", 775),
        "dir_assigned": ("memory-leak", 775), "file_overwrite": ("memory-leak", 775),
        "heap_to_file_leak": ("memory-leak", 772), "file_to_heap_leak": ("resource-leak", 772),
        "direct_heap_leak": ("memory-leak", 401), "direct_file_leak": ("resource-leak", 775),
        "custom_leak": ("memory-leak", 772), "discarded_heap": ("memory-leak", 401),
        "discarded_file": ("resource-leak", 775), "discarded_custom": ("memory-leak", 772),
        "native_fd_leak": ("resource-leak", 775), "native_pipe_leak": ("resource-leak", 775),
        "native_openat_leak": ("resource-leak", 775), "native_socket_leak": ("resource-leak", 775),
        "native_mkstemp_leak": ("resource-leak", 775),
        "summary_handle_leak": ("resource-leak", 772),
        "overload_fd_leak": ("resource-leak", 772), "defined_body_fd_leak": ("resource-leak", 772),
    }
    counts = Counter({function: 1 for function in expected})
    counts["native_pipe_leak"] = 2
    registry = {rule["id"]: rule for rule in rules}
    language_identities = []
    for language in ("en", "tr"):
        surfaces = []
        for output_format in ("json", "sarif"):
            output = root / (language + "." + output_format)
            result = subprocess.run(
                [str(binary), str(source), "--lang", language,
                 "--" + output_format, str(output)],
                cwd=root, capture_output=True, text=True, timeout=45)
            assert result.returncode == 1, (output_format, result.stderr)
            report = json.loads(output.read_text())
            if output_format == "json":
                assert report["complete"] is True, report
                findings = report["diagnostics"]
                assert Counter(row["function"] for row in findings) == counts, findings
                for row in findings:
                    rule_id, cwe_id = expected[row["function"]]
                    assert row["rule_id"] == rule_id, row
                    metadata = row["rule_metadata"]
                    assert metadata["cwe_mapping"] == "mapped", row
                    assert [cwe["id"] for cwe in metadata["cwes"]] == [cwe_id], row
                    advertised = registry[rule_id]
                    assert metadata["description"] == advertised["description"], row
                    assert metadata["help_uri"] == advertised["help_uri"], row
                    assert metadata["cwes"][0] in advertised["potential_cwes"], row
                surfaces.append(Counter((row["fingerprint"], json.dumps(row["rule_metadata"], sort_keys=True))
                                        for row in findings))
            else:
                findings = report["runs"][0]["results"]
                assert len(findings) == sum(counts.values()), findings
                surfaces.append(Counter((row["partialFingerprints"]["codeskeptic/v1"],
                    json.dumps(row["properties"]["codeskeptic/ruleMetadata"], sort_keys=True)) for row in findings))
        assert surfaces[0] == surfaces[1], surfaces
        language_identities.append(surfaces[0])
    assert language_identities[0] == language_identities[1], language_identities
print("CWE_LEAK_METADATA_CLI_OK assignment/overwrite/mixed/custom/native, EN/TR, JSON/SARIF/registry parity")
