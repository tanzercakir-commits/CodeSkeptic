#!/usr/bin/env python3
"""Validate the pre-measurement CWE catalog. No scans, refresh, or promotion.

This is an input-integrity gate, never a product quality verdict. The later
qualification units execute the frozen cases AND the complete source suite.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "tests/cwe_corpus/catalog.json"
INVENTORY = "tests/cwe_corpus/regression_inventory.json"
REGISTRY = "src/core/RuleCapabilities.def"
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
    r'(true|false), (true|false), (true|false), "[^"]*", "[^"]*", \(([0-9,]*)\)\)$')


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


def required_inputs(root):
    # Freeze the complete existing test tree, not a hand-picked passing subset.
    # Generated Python bytecode is not source; this new catalog has its own hash.
    result = set(FLOORS)
    for path in (root / "tests").rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[:2] == ("tests", "cwe_corpus") or "__pycache__" in relative.parts:
            continue
        if path.is_file() or path.is_symlink():
            result.add(relative.as_posix())
    return result


def registry(root):
    result = {}
    for line in safe_file(root, REGISTRY).read_text(encoding="utf-8").splitlines():
        if not line.startswith("CODESKEPTIC_RULE_CAPABILITY("):
            continue
        match = ENTRY.fullmatch(line)
        require(match is not None, "unparseable capability")
        name, tier, default, gated, blocking, cwes = match.groups()
        require(name not in result, "duplicate capability")
        result[name] = {"tier": tier.lower(), "cwes": [int(x) for x in cwes.split(",")] if cwes else []}
    require(len(result) == 15, "capability registry changed")
    return result


def validate(root, catalog, inventory):
    fields(catalog, "schema selection_base profile inventory_sha256 rules excluded_capabilities cases", "catalog")
    require(catalog["schema"] == "codeskeptic-cwe-catalog/v1", "catalog schema")
    require(type(catalog["selection_base"]) is str and re.fullmatch(r"[0-9a-f]{40}", catalog["selection_base"]), "selection base")
    require(catalog["profile"] == "linux-x86_64-clang20-cxx17-isolated-rule", "catalog profile")
    require(catalog["inventory_sha256"] == digest_file(root, INVENTORY), "inventory digest changed")
    fields(inventory, "schema selection_base inputs", "inventory")
    require(inventory["schema"] == "codeskeptic-cwe-regression-inputs/v1"
            and inventory["selection_base"] == catalog["selection_base"], "inventory identity")
    require(type(inventory["inputs"]) is list and 1 <= len(inventory["inputs"]) <= 2000, "inventory size")
    names = []
    for entry in inventory["inputs"]:
        fields(entry, "path sha256", "inventory input")
        name = entry["path"]
        require(type(entry["sha256"]) is str and SHA.fullmatch(entry["sha256"]), "inventory SHA")
        require(digest_file(root, name) == entry["sha256"], "protected input changed: " + name)
        names.append(name)
    require(names == sorted(set(names)) and set(names) == required_inputs(root), "missing/extra/unordered protected inputs")

    capabilities = registry(root)
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
    expected_files = set(paths) | {CATALOG, INVENTORY, "tests/cwe_corpus/test_catalog.py"}
    actual = {p.relative_to(root).as_posix() for p in (root / "tests/cwe_corpus").rglob("*")
              if p.is_file() or p.is_symlink()}
    require(actual == expected_files, "unlisted/missing corpus file")
    for name in expected_files:
        safe_file(root, name)
    require(all({"buggy", "safe"} <= value for value in roles.values()), "rule lacks positive/negative pair")
    return {"catalog_sha256": digest_file(root, CATALOG), "cases": len(ids),
            "roles": dict(sorted(Counter(c["role"] for c in catalog["cases"]).items())),
            "rules": len(wanted), "protected_inputs": len(names), "quality_measured": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check",))
    parser.parse_args()
    try:
        result = validate(ROOT, read_json(ROOT, CATALOG), read_json(ROOT, INVENTORY))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("CWE_CATALOG_FAIL: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
