#!/usr/bin/env python3
"""Pure occurrence accounting for the separately frozen product profiles.

These functions do not run an analyzer, authenticate a report, select a corpus,
or certify a release. The caller must first verify exact input/source/binary,
complete coverage and unmodified raw evidence. A family metric PASS alone is
not a product PASS: frozen sample quotas, three repetitions, all-rule mode and
the stricter inherited gates are independently mandatory.
"""
from collections import Counter
import re

FAMILIES = frozenset(("memory-leak", "double-free", "use-after-free", "resource-leak",
                      "div-by-zero", "null-deref", "int-overflow", "uninit-ptr",
                      "uninit-scalar", "bounds", "sign-conversion", "alloc-size-overflow",
                      "format-string", "command-injection", "sql-injection", "path-traversal"))
FAILURES = frozenset(("CRASH", "TIMEOUT", "INCOMPLETE", "PLANNED_NOT_IMPLEMENTED",
                      "OOM", "INVALID_REPORT", "INPUT_CHANGED", "UNAVAILABLE"))
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,95}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()), label + " fields")


def nonempty(value):
    return type(value) is str and bool(value.strip()) and "\0" not in value


def identities(values):
    require(type(values) is list and len(values) <= 4096, "occurrences must be a bounded array")
    result = []
    for value in values:
        fields(value, "rule function line cwes", "occurrence")
        require(nonempty(value["rule"]) and value["rule"] in FAMILIES
                and nonempty(value["function"]), "occurrence rule/function")
        require(type(value["line"]) is int and value["line"] > 0, "occurrence source line")
        cwes = value["cwes"]
        require(type(cwes) is list and 1 <= len(cwes) <= 16
                and all(type(cwe) is int and cwe > 0 for cwe in cwes)
                and len(cwes) == len(set(cwes)), "occurrence CWE mapping")
        result.append((value["rule"], value["function"], value["line"], tuple(sorted(cwes))))
    return Counter(result)


def score(expected, observed):
    """Match exact source locations/mappings as multisets, never fingerprints."""
    expected, observed = identities(expected), identities(observed)
    return {"tp": sum((expected & observed).values()),
            "fp": sum((observed - expected).values()),
            "fn": sum((expected - observed).values()),
            "expected": sum(expected.values()), "observed": sum(observed.values())}


def metrics(counts, safe_fp):
    fields(counts, "tp fp fn expected observed", "metric")
    require(all(type(value) is int and value >= 0 for value in counts.values()), "metric integer counts")
    tp, fp, fn = (counts[key] for key in ("tp", "fp", "fn"))
    require(counts["expected"] == tp + fn and counts["observed"] == tp + fp,
            "metric conservation")
    require(type(safe_fp) is int and 0 <= safe_fp <= fp, "safe FP count")
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    # Integer comparisons implement the frozen inclusive 0.90 / 0.70 gates;
    # no floating-point rounding can turn a just-below threshold into PASS.
    passed = bool(tp + fp and tp + fn and tp * 10 >= (tp + fp) * 9
                  and tp * 10 >= (tp + fn) * 7 and safe_fp == 0)
    return {**counts, "safe_fp": safe_fp, "precision": precision,
            "addressable_recall": recall, "passed": passed}


def case_keys(cases):
    require(type(cases) is list and 1 <= len(cases) <= 10000, "case array")
    seen = set()
    groups = {}
    for case in cases:
        fields(case, "id family subprofile role expected", "case projection")
        name, family = case["id"], case["family"]
        require(type(name) is str and IDENTIFIER.fullmatch(name) and name not in seen,
                "duplicate/invalid case ID")
        require(type(family) is str and family in FAMILIES, "case family")
        seen.add(name)
        role, expected = case["role"], case["expected"]
        require(type(role) is str and role in ("buggy", "safe", "unknown", "unsupported"), "case role")
        if role in ("unknown", "unsupported"):
            require(expected is None, "boundary cannot claim a scored expectation")
        else:
            identities(expected)
            require(bool(expected) == (role == "buggy"), "role/expectation contradiction")
            require(all(item["rule"] == family for item in expected), "wrong expected target family")
        subprofile = case["subprofile"]
        require(subprofile is None or (family == "bounds" and type(subprofile) is str
                                       and subprofile in ("cwe-121", "cwe-122")), "case subprofile")
        groups.setdefault(family, []).append(case)
        if subprofile:
            groups.setdefault(family + "/" + subprofile, []).append(case)
    return seen, groups


def summarize(cases, rows):
    """Score one isolated-family campaign after the caller authenticates it.

Non-target alarms remain excess observations, not credits for another rule.
Unknown/unsupported occurrences remain visible but never enter TP/FP/FN.
Failure of even an unscored row leaves the group's measurement incomplete.
"""
    names, groups = case_keys(cases)
    require(type(rows) is list and len(rows) == len(cases), "measurement row count")
    by_id = {}
    for row in rows:
        fields(row, "id status observed", "measurement projection")
        name, status = row["id"], row["status"]
        require(type(name) is str and name in names and name not in by_id, "measurement identity")
        require(type(status) is str and status in FAILURES | {"MEASURED"}, "measurement status")
        if status == "MEASURED":
            identities(row["observed"])
        else:
            require(row["observed"] is None, "failed execution cannot invent observations")
        by_id[name] = row
    result = {}
    for group, selected in sorted(groups.items()):
        complete = all(by_id[case["id"]]["status"] == "MEASURED" for case in selected)
        counts = {key: 0 for key in ("tp", "fp", "fn", "expected", "observed")}
        safe_fp, unscored = 0, 0
        for case in selected:
            row = by_id[case["id"]]
            if row["status"] != "MEASURED":
                continue
            if case["role"] in ("unknown", "unsupported"):
                unscored += len(row["observed"])
                continue
            value = score(case["expected"], row["observed"])
            for key in counts:
                counts[key] += value[key]
            if case["role"] == "safe":
                safe_fp += value["fp"]
        value = metrics(counts, safe_fp) if complete else None
        result[group] = {"cases": len(selected),
                         "roles": dict(sorted(Counter(case["role"] for case in selected).items())),
                         "measurement_complete": complete, "metrics": value,
                         "unscored_occurrences": unscored,
                         "statuses": dict(sorted(Counter(by_id[case["id"]]["status"] for case in selected).items())),
                         "passed": bool(value and value["passed"])}
    return result
