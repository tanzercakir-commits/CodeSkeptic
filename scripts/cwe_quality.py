#!/usr/bin/env python3
"""Validate frozen CWE inputs or measure their isolated-rule regression profile.

Check never scans. Run never refreshes expectations or promotes a rule; full
source and inherited external gates remain separate mandatory evidence lanes.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time

import run_stress_matrix as stress

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "tests/cwe_corpus/catalog.json"
INVENTORY = "tests/cwe_corpus/regression_inventory.json"
REGISTRY = "src/core/RuleCapabilities.def"
HISTORICAL_FILES = {
    "tests/cwe_corpus/snapshots/terminal-4fd4a21-catalog.json":
        "ceaf1a23727e5379f55c7fa8baec97e30d29d9897c59f24d543617ba4cfb3681",
    "tests/cwe_corpus/snapshots/terminal-4fd4a21-inventory.json":
        "8eb0230c7c3135816d9aecf37e8d4351be5e943a151443b26e0309d16a69ac9c",
    "tests/cwe_corpus/snapshots/terminal-4fd4a21-contract.json":
        "63554f0f6f7efd8e70ca5ef38838f5c4920ef62d33de3ff8f4d15cbe3a861e0e",
}
VERSION_INPUTS = ("scripts/cwe_quality.py", "scripts/check_capabilities_sync.py",
                  "tests/cwe_corpus/test_catalog.py")
# Planned names bound the approved extension namespace, not installed behavior.
PLANNED_CWES = {"format-string": [134], "command-injection": [78],
                "sql-injection": [89], "path-traversal": [22]}
FLOORS = (
    REGISTRY, "CMakeLists.txt", "src/CMakeLists.txt",
    "scripts/corpus_expected.txt", "scripts/run_corpus.sh",
    "scripts/corpus_compile_commands.cpp", "scripts/juliet_expected.txt",
    "scripts/juliet_eval.py", "scripts/run_juliet.sh", "scripts/run_thesis.sh",
    "scripts/measurement_baseline.json", "scripts/realworld_manifest.json",
    "scripts/realworld_expected.txt", "scripts/run_realworld_campaign.py",
    "scripts/run_regression_checkpoint.py", "scripts/verify_regression_checkpoint.py",
    "scripts/run_stress_matrix.py", "ci/regression-checkpoint.json",
    "ci/regression-adjudications.json", "scripts/compare_measurements.py",
    "scripts/run_measurement_lab.py", "scripts/render_quality_dashboard.py",
    "scripts/test_first_scan.sh", "scripts/local_test.sh",
    ".github/workflows/ci.yml", ".github/workflows/windows.yml",
    ".github/workflows/juliet.yml", ".github/workflows/realworld.yml",
)
SHA = re.compile(r"[0-9a-f]{64}")
ID = re.compile(r"[a-z][a-z0-9-]{1,95}")
ENTRY = re.compile(
    r'^CODESKEPTIC_RULE_CAPABILITY\("([^"]+)", (Supported|Experimental), '
    r'(true|false), (true|false), (true|false), "([^"]*)", "([^"]*)", \(([0-9,]*)\)\)$')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()), label + " fields")


def nonempty(value):
    return type(value) is str and bool(value.strip())


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def safe_file(root, name):
    require(type(name) is str and bool(name) and "\\" not in name, "invalid path")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and relative.as_posix() == name
            and all(part not in (".", "..") for part in relative.parts), "unsafe path")
    path = root / name
    require(not any(part.is_symlink() for part in (path, *path.parents)
                    if part != root and root in part.parents), "symlink input")
    require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024, "missing/oversized input: " + name)
    return path


def digest_file(root, name):
    return hashlib.sha256(safe_file(root, name).read_bytes()).hexdigest()


def read_json(root, name):
    path = safe_file(root, name)
    require(path.stat().st_size <= 2 * 1024 * 1024, "oversized catalog JSON")
    def invalid(value):
        raise ValueError("non-finite JSON: " + value)
    def finite(value):
        number = float(value)
        require(math.isfinite(number), "non-finite JSON number")
        return number
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                      parse_constant=invalid, parse_float=finite)


def required_inputs(root, version=1):
    # Freeze the complete existing test tree, not a hand-picked passing subset.
    # Generated Python bytecode is not source; this new catalog has its own hash.
    result = set(FLOORS)
    if version == 2:
        result.update(VERSION_INPUTS)
    for path in (root / "tests").rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[:2] == ("tests", "cwe_corpus") or "__pycache__" in relative.parts:
            continue
        if path.is_file() or path.is_symlink():
            result.add(relative.as_posix())
    return result


def canonical_digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def historical_snapshot(root):
    """Authenticate historical metadata bytes, not current input execution."""
    for name, sha in HISTORICAL_FILES.items():
        require(digest_file(root, name) == sha, "historical snapshot changed: " + name)
    catalog, inventory, contract = (read_json(root, name) for name in HISTORICAL_FILES)
    require(catalog["inventory_sha256"] == contract["inventory_sha256"], "historical snapshot linkage")
    return {"catalog": catalog, "inventory": inventory, "contract": contract}


def historical_identity(root):
    snapshot = historical_snapshot(root)
    contract, counts = snapshot["contract"], snapshot["contract"]["counts"]
    return {"source_revision": contract["source_revision"], "catalog_sha256": contract["catalog_sha256"],
            "inventory_sha256": contract["inventory_sha256"],
            "public_capabilities": counts["public_capabilities"], "rules": counts["cwe_families"],
            "cases": counts["cases"], "protected_inputs": counts["protected_inputs"],
            "source_test_inputs": counts["source_test_inputs"], "roles": counts["roles"],
            "current_inputs_verified": False, "quality_measured": False}


def registry_descriptor(root):
    result = {}
    for raw in safe_file(root, REGISTRY).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("CODESKEPTIC_RULE_CAPABILITY("):
            continue
        match = ENTRY.fullmatch(line)
        require(match is not None, "unparseable capability")
        name, tier, default, gated, blocking, evidence, description, cwes = match.groups()
        require(ID.fullmatch(name) and name not in result, "duplicate/invalid capability")
        ids = [int(x) for x in cwes.split(",")] if cwes else []
        require(len(ids) == len(set(ids)) and all(cwe > 0 for cwe in ids), "duplicate/invalid capability CWE")
        flags = (default == "true", gated == "true", blocking == "true")
        require((tier != "Supported" or all(flags)) and (tier != "Experimental" or not flags[2]),
                "capability tier/flag invariant")
        require(nonempty(evidence) and nonempty(description), "missing capability explanation")
        result[name] = {"tier": tier.lower(), "cwes": ids, "default_enabled": flags[0],
                        "quality_gated": flags[1], "blocks_verdict": flags[2],
                        "evidence": evidence, "description": description}
    require(bool(result), "empty capability registry")
    return result


def evidence_payload_digest(catalog):
    body = dict(catalog)
    version = catalog["evidence_version"]
    require(type(version.get("review")) is dict, "successor review fields")
    body["evidence_version"] = {key: value for key, value in version.items() if key != "id"}
    body["evidence_version"]["review"] = {key: value for key, value in version["review"].items()
                                          if key != "payload_sha256"}
    return canonical_digest(body)


def validate_evidence_version(root, catalog, snapshot=None):
    snapshot = snapshot or historical_snapshot(root)
    version = catalog["evidence_version"]
    fields(version, "schema sequence previous_catalog_sha256 previous_inventory_sha256 previous_version_id "
           "registry_sha256 capabilities input_paths case_ids id review", "evidence version")
    require(version["schema"] == "codeskeptic-cwe-evidence-version/v1", "evidence version schema")
    require(type(version["sequence"]) is int and 1 <= version["sequence"] <= 1000, "evidence version sequence")
    for name in ("previous_catalog_sha256", "previous_inventory_sha256", "registry_sha256", "id"):
        require(type(version[name]) is str and SHA.fullmatch(version[name]) and version[name] != "0" * 64,
                "invalid evidence version digest")
    if version["sequence"] == 1:
        prior = snapshot["contract"]["reviewed_u001_successor"]
        require(version["previous_catalog_sha256"] == prior["catalog_sha256"]
                and version["previous_inventory_sha256"] == prior["inventory_sha256"]
                and version["previous_version_id"] is None, "wrong initial version predecessor")
    else:
        previous = version["previous_version_id"]
        require(type(previous) is str and SHA.fullmatch(previous) and previous != "0" * 64
                and previous != version["id"], "invalid previous version identity")
    require(version["id"] == evidence_payload_digest(catalog), "evidence version payload changed")
    review = version["review"]
    fields(review, "schema source_base source_head implementer verifier verdict findings reason payload_sha256", "successor review")
    require(review["schema"] == "codeskeptic-cwe-successor-review/v1"
            and all(type(review[name]) is str and re.fullmatch(r"[0-9a-f]{40}", review[name])
                    and review[name] != "0" * 40 for name in ("source_base", "source_head"))
            and review["source_base"] != review["source_head"], "successor review source identity")
    require(all(nonempty(review[name]) for name in ("implementer", "verifier", "reason"))
            and review["implementer"] != review["verifier"] and review["verdict"] == "PASS"
            and review["findings"] == [] and review["payload_sha256"] == version["id"],
            "missing/stale independent successor review")
    require(type(version["capabilities"]) is dict
            and canonical_digest(version["capabilities"]) == canonical_digest(registry_descriptor(root))
            and version["registry_sha256"] == digest_file(root, REGISTRY), "version capability registry mismatch")
    baseline = snapshot["contract"]["capabilities"]
    current = version["capabilities"]
    require(set(baseline) <= set(current) <= set(baseline) | set(PLANNED_CWES), "unapproved capability identity")
    for name, row in current.items():
        if name in PLANNED_CWES:
            require(row["cwes"] == PLANNED_CWES[name], "unapproved capability CWE mapping")
        elif name == "bounds":
            require(set(baseline[name]["cwes"]) <= set(row["cwes"])
                    <= set(baseline[name]["cwes"]) | {121, 122}, "unapproved bounds subtype")
        else:
            require(row["cwes"] == baseline[name]["cwes"], "historical capability CWE changed")
        if name in baseline and baseline[name]["tier"] == "supported":
            require(row["tier"] == "supported", "historical supported rule demoted")
        if name in ("assumption", "contract", "policy"):
            require(row == baseline[name], "report-only project capability changed")
    require(type(version["input_paths"]) is list
            and all(type(path) is str for path in version["input_paths"])
            and version["input_paths"] == sorted(set(version["input_paths"])), "version input identities")
    require(type(version["case_ids"]) is list and all(type(name) is str for name in version["case_ids"])
            and len(version["case_ids"]) == len(set(version["case_ids"])), "version fixture identities")
    return version


def registry(root, catalog=None):
    catalog = read_json(root, CATALOG) if catalog is None else catalog
    if catalog.get("schema") == "codeskeptic-cwe-catalog/v2":
        return validate_evidence_version(root, catalog)["capabilities"]
    require(catalog.get("schema") == "codeskeptic-cwe-catalog/v1", "catalog schema")
    expected = historical_snapshot(root)["contract"]["capabilities"]
    actual = registry_descriptor(root)
    require(actual == expected, "capability registry changed without reviewed version")
    return actual


def frozen_contract_counts(root, catalog):
    if catalog["schema"] == "codeskeptic-cwe-catalog/v1":
        return historical_identity(root)
    version = validate_evidence_version(root, catalog)
    return {"rules": sum(bool(row["cwes"]) for row in version["capabilities"].values()),
            "cases": len(version["case_ids"]), "protected_inputs": len(version["input_paths"]),
            "source_test_inputs": sum(path.startswith("tests/") for path in version["input_paths"]),
            "roles": dict(Counter(case["role"] for case in catalog["cases"]))}


def validate(root, catalog, inventory):
    require(type(catalog) is dict and catalog.get("schema") in
            ("codeskeptic-cwe-catalog/v1", "codeskeptic-cwe-catalog/v2"), "catalog schema")
    version_number = 2 if catalog["schema"].endswith("/v2") else 1
    fields(catalog, "schema selection_base profile inventory_sha256 rules excluded_capabilities cases"
           + (" evidence_version" if version_number == 2 else ""), "catalog")
    snapshot = historical_snapshot(root)
    require(type(catalog["selection_base"]) is str and re.fullmatch(r"[0-9a-f]{40}", catalog["selection_base"]), "selection base")
    require(catalog["profile"] == "linux-x86_64-clang20-cxx17-isolated-rule", "catalog profile")
    require(catalog["inventory_sha256"] == digest_file(root, INVENTORY), "inventory digest changed")
    fields(inventory, "schema selection_base inputs", "inventory")
    require(inventory["schema"] == f"codeskeptic-cwe-regression-inputs/v{version_number}"
            and inventory["selection_base"] == catalog["selection_base"], "inventory identity")
    require(type(inventory["inputs"]) is list and 1 <= len(inventory["inputs"]) <= 2000, "inventory size")
    names = []
    for entry in inventory["inputs"]:
        fields(entry, "path sha256", "inventory input")
        name = entry["path"]
        require(type(entry["sha256"]) is str and SHA.fullmatch(entry["sha256"]), "inventory SHA")
        require(digest_file(root, name) == entry["sha256"], "protected input changed: " + name)
        names.append(name)
    require(names == sorted(set(names)) and set(names) == required_inputs(root, version_number), "missing/extra/unordered protected inputs")
    require({row["path"] for row in snapshot["inventory"]["inputs"]} <= set(names),
            "historical protected input removed")
    for row in snapshot["contract"]["immutable_quality_inputs"]:
        require(digest_file(root, row["path"]) == row["sha256"], "historical quality floor changed: " + row["path"])
    require(type(catalog["cases"]) is list and catalog["cases"][:len(snapshot["catalog"]["cases"])]
            == snapshot["catalog"]["cases"], "historical fixture contract changed")
    version = validate_evidence_version(root, catalog, snapshot) if version_number == 2 else None
    if version is not None:
        require(version["input_paths"] == names and version["case_ids"] == [case["id"] for case in catalog["cases"]],
                "version input/fixture set mismatch")

    capabilities = registry(root, catalog)
    wanted = {name for name, row in capabilities.items() if row["cwes"]}
    require(type(catalog["rules"]) is dict and set(catalog["rules"]) == wanted, "missing/extra CWE rules")
    for name, rule in catalog["rules"].items():
        fields(rule, "tier_at_selection cwes subset limitations", "rule")
        require(type(rule["cwes"]) is list and all(type(cwe) is int for cwe in rule["cwes"])
                and rule["tier_at_selection"] == capabilities[name]["tier"]
                and rule["cwes"] == capabilities[name]["cwes"], "rule registry mismatch")
        require(nonempty(rule["subset"]) and type(rule["limitations"]) is list
                and rule["limitations"] and all(nonempty(x) for x in rule["limitations"]), "unnamed rule boundary")
    excluded = catalog["excluded_capabilities"]
    require(type(excluded) is dict and set(excluded) == set(capabilities) - wanted
            and all(nonempty(reason) for reason in excluded.values()), "unexplained non-CWE capability")

    require(type(catalog["cases"]) is list and 24 <= len(catalog["cases"]) <= 1000, "case count")
    ids, paths, roles = [], [], {name: set() for name in wanted}
    for case in catalog["cases"]:
        fields(case, "id rule role path sha256 expected_diagnostics rationale origin compile_flags untrusted_sources", "case")
        name, rule, role = case["id"], case["rule"], case["role"]
        require(type(name) is str and ID.fullmatch(name) and rule in wanted, "case identity")
        require(role in ("buggy", "safe", "unknown", "unsupported"), "case role")
        require(case["path"] == "tests/cwe_corpus/" + name + ".cpp", "case path does not bind ID")
        require(case["sha256"] == digest_file(root, case["path"]), "fixture changed: " + name)
        require(nonempty(case["rationale"]) and case["origin"] in names, "missing semantic rationale/origin")
        require(case["compile_flags"] == ["-std=c++17"], "unexpected compile flags")
        sources = case["untrusted_sources"]
        require(type(sources) is list and len(sources) <= 8
                and all(type(x) is str and re.fullmatch(r"[A-Za-z_]\w*", x) for x in sources)
                and sources == sorted(set(sources)), "invalid untrusted sources")
        expected = case["expected_diagnostics"]
        if role in ("unknown", "unsupported"):
            require(expected is None, "unscored boundary cannot claim clean or FN")
        else:
            require(type(expected) is list and len(expected) <= 32, "diagnostic expectation")
            for diag in expected:
                require(type(diag) is list and len(diag) == 2 and diag[0] == rule
                        and diag[1] == "f", "unexpected diagnostic identity")
            require(bool(expected) == (role == "buggy"), "safe/buggy expectation mismatch")
        ids.append(name)
        paths.append(case["path"])
        roles[rule].add(role)
    require(len(ids) == len(set(ids)) and len(paths) == len(set(paths)), "duplicate fixture")
    # Close the entire input namespace, not only the current .cpp suffix.
    # Otherwise a new .cc/.cxx/.c file (or an unbound included header) can be
    # omitted from both this profile and the protected pre-existing test tree.
    expected_files = set(paths) | {CATALOG, INVENTORY, "tests/cwe_corpus/test_catalog.py"} | set(HISTORICAL_FILES)
    actual = {p.relative_to(root).as_posix() for p in (root / "tests/cwe_corpus").rglob("*")
              if p.is_file() or p.is_symlink()}
    require(actual == expected_files, "unlisted/missing corpus file")
    for name in expected_files:
        safe_file(root, name)
    require(all({"buggy", "safe"} <= value for value in roles.values()), "rule lacks positive/negative pair")
    return {"catalog_sha256": digest_file(root, CATALOG), "cases": len(ids),
            "roles": dict(sorted(Counter(c["role"] for c in catalog["cases"]).items())),
            "rules": len(wanted), "protected_inputs": len(names), "quality_measured": False,
            **({"evidence_version_id": version["id"]} if version is not None else {})}


def measure_report(report, case, source, exit_code, version, capability):
    """Reject untrustworthy evidence before scoring exact finding multisets."""
    stress.validate_report(report, source, exit_code)
    require(report.get("schema") == "codeskeptic-report/v1"
            and report.get("tool_version") == version, "report schema/version mismatch")
    require("baseline" in report and report["baseline"] is None
            and report.get("suppressions") == [], "baseline/suppression active or missing")
    require(report["complete"] is True, "incomplete measurement")
    identities = set()
    for diag in report["diagnostics"]:
        require(diag["rule_id"] == case["rule"], "rule isolation failed")
        require(diag.get("capability_tier") == capability["tier"]
                and diag["blocks_verdict"] is (capability["tier"] == "supported"), "diagnostic tier mismatch")
        require(all(type(diag.get(k)) is int and diag[k] > 0 for k in ("line", "column"))
                and nonempty(diag.get("message")) and nonempty(diag.get("function")), "diagnostic location/message")
        fingerprint = diag.get("fingerprint")
        require(type(fingerprint) is str and re.fullmatch(r"csf1-[0-9a-f]{16}", fingerprint), "invalid fingerprint")
        # csf1 binds a rule/function/source LINE, not a unique finding. Both
        # endpoints of a pipe can correctly share it; preserve multiplicity.
        identity = json.dumps({key: diag.get(key) for key in
                               ("rule_id", "file", "line", "column", "function", "message", "notes")}, sort_keys=True)
        require(identity not in identities, "identical duplicate diagnostic")
        identities.add(identity)
        metadata = diag.get("rule_metadata")
        require(type(metadata) is dict and metadata.get("cwe_mapping") == "mapped", "missing CWE metadata")
        cwes = metadata.get("cwes")
        require(type(cwes) is list and bool(cwes)
                and all(type(cwe) is dict and type(cwe.get("id")) is int
                        and cwe["id"] in capability["cwes"] for cwe in cwes)
                and len({cwe["id"] for cwe in cwes}) == len(cwes), "invalid finding CWE")
    if case["role"] in ("unknown", "unsupported"):
        require(case["expected_diagnostics"] is None, "unscored expectation changed")
        return None
    expected = Counter(tuple(d) for d in case["expected_diagnostics"])
    observed = Counter((d["rule_id"], d["function"]) for d in report["diagnostics"])
    return {"tp": sum((expected & observed).values()), "fp": sum((observed - expected).values()),
            "fn": sum((expected - observed).values()), "expected": sum(expected.values()),
            "observed": sum(observed.values())}


def summarize(selected, rows):
    require(bool(selected) and len(rows) == len(selected)
            and Counter(row["id"] for row in rows) == Counter(case["id"] for case in selected)
            and len({row["id"] for row in rows}) == len(rows), "missing/extra/duplicate measurement row")
    by_id = {row["id"]: row for row in rows}
    result = {}
    for rule in sorted({case["rule"] for case in selected}):
        cases = [case for case in selected if case["rule"] == rule]
        complete = all(by_id[case["id"]]["coverage_complete"] is True for case in cases)
        metric = {key: 0 for key in ("tp", "fp", "fn", "expected", "observed")} if complete else None
        safe_fp = 0 if complete else None
        if complete:
            for case in cases:
                row_metric = by_id[case["id"]]["metrics"]
                if case["role"] in ("buggy", "safe"):
                    require(type(row_metric) is dict, "missing scored metrics")
                    for key in metric:
                        metric[key] += row_metric[key]
                    if case["role"] == "safe":
                        safe_fp += row_metric["fp"]
                else:
                    require(row_metric is None, "unscored row entered metrics")
        result[rule] = {"cases": len(cases), "roles": dict(sorted(Counter(c["role"] for c in cases).items())),
                        "measurement_complete": complete, "metrics": metric, "safe_fp": safe_fp,
                        "precision": metric["tp"] / (metric["tp"] + metric["fp"])
                        if metric and metric["tp"] + metric["fp"] else None,
                        "addressable_recall": metric["tp"] / metric["expected"]
                        if metric and metric["expected"] else None}
    return result


def file_sha(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def save_json(path, value):
    # Fresh files only. Failure evidence cannot be overwritten by a retry.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def checked_process(command, directory, timeout):
    result = stress.run_process(command, directory, timeout)
    require(not result["reason"] and not result.get("stdout_truncated")
            and not result.get("stderr_truncated"), "process failed or output truncated: " + str(result))
    return result


def source_checkout(root, revision):
    identity = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel', 'HEAD', 'HEAD^{tree}'],
                              capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
    require(len(identity) == 3 and Path(identity[0]).resolve() == root.resolve()
            and identity[1] == revision and re.fullmatch(r"[0-9a-f]{40}", identity[2]), "checkout identity mismatch")
    status = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=all'],
                            capture_output=True, text=True, timeout=10, check=True)
    require(not status.stdout.strip(), "dirty checkout cannot be qualified")
    return identity[2]


def capability_parity(actual, version, capabilities):
    """Native discovery is compared with explicit source flags, never inferred counts."""
    require(type(actual) is dict and type(actual.get("schema_version")) is int and actual["schema_version"] == 2
            and actual.get("product") == "CodeSkeptic" and actual.get("version") == version,
            "capability identity mismatch")
    rules = actual.get("rule_capabilities")
    require(type(rules) is list and all(type(row) is dict and type(row.get("id")) is str for row in rules),
            "capability rows malformed")
    require(len(rules) == len(capabilities) and len({row["id"] for row in rules}) == len(rules)
            and {row["id"] for row in rules} == set(capabilities), "capability set mismatch")
    for row in rules:
        expected = capabilities[row["id"]]
        require(row.get("tier") == expected["tier"]
                and type(row.get("potential_cwes")) is list
                and all(type(cwe) is dict and type(cwe.get("id")) is int for cwe in row["potential_cwes"])
                and [cwe["id"] for cwe in row["potential_cwes"]] == expected["cwes"]
                and all(type(row.get(flag)) is bool and row[flag] == expected[flag]
                        for flag in ("default_enabled", "quality_gated", "blocks_verdict")),
                "capability registry mismatch")


def scan_case(binary, case, source, directory, capabilities, version, timeout):
    require(file_sha(source) == case["sha256"], "frozen fixture digest mismatch")
    directory.mkdir()
    entry = {"directory": str(directory), "file": str(source),
             "arguments": ["clang++", *case["compile_flags"], "-c", str(source)]}
    save_json(directory / "compile_commands.json", [entry])
    command = [str(binary), "--source", str(source), "--build-path", str(directory),
               "--json", str(directory / "report.json"), "--lang", "en", "--severity", "info",
               "--no-analysis-cache",
               "--disable-rule", ",".join(sorted(set(capabilities) - {case["rule"]}))]
    if case["untrusted_sources"]:
        command += ["--untrusted-int-sources", ",".join(case["untrusted_sources"])]
    row = {"id": case["id"], "source": str(source), "source_sha256": file_sha(source),
           "command": command, "compile_command": entry, "timeout_seconds": timeout,
           "coverage_complete": False, "metrics": None}
    row["process"] = stress.run_process(command, directory, timeout)
    try:
        process = row["process"]
        require(not process["reason"] and not process.get("stdout_truncated")
                and not process.get("stderr_truncated"), "process failure/truncated output")
        report = read_json(directory, "report.json")
        row["report_sha256"] = digest_file(directory, "report.json")
        row["metrics"] = measure_report(report, case, source, process["returncode"], version,
                                        capabilities[case["rule"]])
        require(row["source_sha256"] == file_sha(source) == case["sha256"], "source changed during scan")
        row["coverage_complete"] = True
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        row.update(error=str(error), metrics=None)
    save_json(directory / "execution.json", row)
    return row


def run_catalog(root, binary, output, revision, timeout=20, tier="supported"):
    """Select a complete frozen tier, never a result-dependent rule subset."""
    require(type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision), "exact source revision required")
    require(math.isfinite(timeout) and 0 < timeout <= 60, "invalid timeout")
    require(type(tier) is str and tier in ("supported", "experimental"), "invalid measurement tier")
    catalog, inventory = read_json(root, CATALOG), read_json(root, INVENTORY)
    integrity = validate(root, catalog, inventory)
    tree = source_checkout(root, revision)
    capabilities = registry(root)
    selected = [case for case in catalog["cases"] if capabilities[case["rule"]]["tier"] == tier]
    require(bool(selected), "empty tier selection")
    require(not binary.is_symlink() and binary.is_file(), "binary must be a regular non-symlink file")
    binary = binary.resolve(strict=True)
    # Refuse existing output even when empty. Parent resolution disallows hidden
    # symlink redirection; the caller owns the evidence parent directory.
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent, "unsafe output parent")
    output.mkdir()
    result = {"schema": "codeskeptic-cwe-measurement/v1", "source_revision": revision,
              "source_tree": tree, "profile": catalog["profile"], "tier": tier, "input_integrity": integrity,
              "binary": str(binary), "binary_sha256": file_sha(binary), "cases": [],
              "measurement_complete": False, "regression_passed": False,
              "full_product_qualification": False}
    started = time.monotonic()
    try:
        version_run = checked_process([str(binary), "--version"], output, 10)
        result["version_process"] = version_run
        require(version_run["returncode"] == 0, "version command failed")
        version = version_run["stdout"].strip().removeprefix("CodeSkeptic ")
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-dev\+g" + revision[:12], version), "binary source version mismatch")
        result["tool_version"] = version
        discovery = checked_process([str(binary), "--capabilities", "--json"], output, 10)
        result["capabilities_process"] = discovery
        require(discovery["returncode"] == 0, "capabilities command failed")
        actual = json.loads(discovery["stdout"], object_pairs_hook=unique,
                            parse_constant=stress.invalid_constant, parse_float=stress.finite_float)
        capability_parity(actual, version, capabilities)
        # Analyzed by the same embedded frontend with the exact fixture flags.
        # No target override: verify the real default ABI before measurement.
        probe = output / "profile.cpp"
        with probe.open("x", encoding="utf-8") as stream:
            stream.write('#if !defined(__linux__) || !defined(__x86_64__) || __clang_major__ != 20\n'
                         '#error wrong frontend or platform\n#endif\n'
                         'static_assert(__cplusplus == 201703L, "wrong language mode");\n'
                         'static_assert(sizeof(void*) == 8 && sizeof(__SIZE_TYPE__) == 8, "wrong ABI");\n'
                         'int f(){return 0;}\n')
        probe_case = {"id": "profile", "rule": "null-deref", "role": "safe",
                      "expected_diagnostics": [], "compile_flags": ["-std=c++17"], "untrusted_sources": [],
                      "sha256": file_sha(probe)}
        result["profile_probe"] = scan_case(binary, probe_case, probe, output / "profile", capabilities, version, timeout)
        require(result["profile_probe"]["coverage_complete"]
                and result["profile_probe"]["metrics"]["observed"] == 0, "frontend/profile probe failed")
        for case in selected:
            require(time.monotonic() - started < 240, "overall measurement time budget exceeded")
            result["cases"].append(scan_case(binary, case, safe_file(root, case["path"]),
                                             output / case["id"], capabilities, version, timeout))
        result["rules"] = summarize(selected, result["cases"])
        require(validate(root, read_json(root, CATALOG), read_json(root, INVENTORY)) == integrity,
                "input integrity changed during measurement")
        require(file_sha(binary) == result["binary_sha256"], "binary changed during measurement")
        require(source_checkout(root, revision) == tree, "checkout changed during measurement")
        result["measurement_complete"] = all(r["measurement_complete"] for r in result["rules"].values())
        result["regression_passed"] = result["measurement_complete"] and all(
            r["metrics"]["fp"] == r["metrics"]["fn"] == 0 for r in result["rules"].values())
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    save_json(output / "results.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "historical-identity"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--tier", choices=("supported", "experimental"), default="supported")
    args = parser.parse_args()
    try:
        if args.command == "historical-identity":
            print(json.dumps(historical_identity(ROOT), sort_keys=True))
            return 0
        if args.command == "run":
            require(args.binary is not None and args.out is not None and args.revision is not None,
                    "run requires --binary, --out and --revision")
            result = run_catalog(ROOT, args.binary, args.out, args.revision, args.timeout, args.tier)
            print(json.dumps({k: v for k, v in result.items() if k in
                              ("measurement_complete", "regression_passed", "rules", "error")}, sort_keys=True))
            return 0 if result["regression_passed"] else 1
        result = validate(ROOT, read_json(ROOT, CATALOG), read_json(ROOT, INVENTORY))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("CWE_CATALOG_FAIL: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
