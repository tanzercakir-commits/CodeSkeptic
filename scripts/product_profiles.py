#!/usr/bin/env python3
"""Read-only prospective product-profile accounting, never a quality verdict.

Quota arithmetic authenticates neither source provenance nor semantic sample
independence. Exact source/label review, content hashing and complete corpus
selection remain separate gates. No download, execution, rebaseline or pin
refresh is performed here.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys

from product_quality import FAMILIES, fields, nonempty, require

BUCKETS = tuple(sorted(FAMILIES - {"bounds"})) + ("bounds/cwe-121", "bounds/cwe-122")
SHA = re.compile(r"[0-9a-f]{64}")
HISTORICAL_REVISION = "c4fa60864f2e5853581c2f8a0dd66a3fc967239b"
PROJECT_PINS = {"cjson":{"version":"1.7.18","revision":"acc76239bee01d8e9c858ae2cab296704e52d916","archive_sha256":"88be7eb146a320e255212cf1ec77e393846979ce1d2579917c5ae87c2d4ce3dd","tree_inventory_sha256":"86ce5cf13453ba8e80f1028d23be178510bd174ddb3660d7e8bc28c2793477ef"},"tinyxml2":{"version":"10.0.0","revision":"321ea883b7190d4e85cae5512a12e5eaa8f8731f","archive_sha256":"d5ae097578717b42b4f05f2c6b2d09f473a1c30d1552ca4e2dcb4eab5b34de84","tree_inventory_sha256":"b671a97d9ea8eb50301dc7c957234d4ba974c015f688158d783bb98469d18f2e"},"googletest":{"version":"1.14.0","revision":"f8d7d77c06936315286eb55f8de22cd23c188571","archive_sha256":"7ff5db23de232a39cbb5c9f5143c355885e30ac596161a6b9fc50c4538bfbf01","tree_inventory_sha256":"2bc79a01f3c87d7f8a3f263f56610a2476b7967bdc3d8e1f3bb1cfcffa615b6d"}}
HISTORICAL_PINS = {"cjson":{"report_sha256":"2859167f347bb071a9435cb752af3cd5acbe380ccc6b4fc2641bfb827739f3fd","review_sha256":"821350f4734d52265c66cebd0ea60c435317b914240a7f7ee6548456441b0dae","counts":{"TP":9,"FP":39,"unknown":6},"findings":54,"distinct_fingerprints":53},"tinyxml2":{"report_sha256":"9962edb317b494f4f460a251d13f0e1444aff8401c5463c9cea49c77006ddbf6","review_sha256":"1f7708dda174c38ec15d6018aaa7abf391fb596cd7e1e2488bde76ed8d46fddf","counts":{"TP":0,"FP":5,"unknown":4},"findings":9,"distinct_fingerprints":9},"googletest":{"report_sha256":"7631f99e219127ee0a12b9986ac482a4d9cafc79b41ca75df7216184c09e1059","review_sha256":"b774c54034a096404f09a303d5f1bc5294387850e9ff248d06ceb39fe944beee","counts":{"TP":0,"FP":3,"unknown":0},"findings":3,"distinct_fingerprints":3}}

# Fixed before the first new product measurement. These are qualification
# limits, not measured performance claims. Native worker memory semantics are
# platform-specific; the Linux harness limit is not a universal RSS limit.
LIMITS = {
    "repetitions": 3,
    "family_precision_min": "0.90",
    "addressable_recall_min": "0.70",
    "safe_fp_max": 0,
    "buggy_min_per_bucket": 30,
    "safe_min_per_bucket": 30,
    "origins_min_per_bucket": 3,
    "unique_quota_sources_min": 1020,
    "case_timeout_seconds": 30,
    "project_timeout_seconds": 1200,
    "campaign_timeout_seconds": 43200,
    "capture_bytes_per_stream": 2097152,
    "linux_harness_cpu_quota": 2,
    "linux_harness_memory_mib": 6144,
    "linux_harness_memory_plus_swap_mib": 12288,
    "linux_harness_pids_max": 256,
    "linux_harness_tmpfs_mib": 1024,
    "worker_timeout_ms": 120000,
    "worker_memory_mib": 2048,
    "string_flow_call_depth_max": 4,
    "string_flow_states_per_function_max": 256,
    "string_flow_transfer_steps_per_function_max": 65536,
}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False) + "\n"


def validate_limits(values):
    require(type(values) is dict and canonical(values) == canonical(LIMITS),
            "prospective limits or quality floors changed")
    return dict(values)


def quota_readiness(rows, registered_origins):
    """Account a source-reviewed projection without claiming that review exists.

The caller supplies canonical provenance lineages, not aliases for the same
repository or generation batch. Cluster labels require source-based review;
hash/similarity checks can reject or flag, never establish independence.
One semantic cluster/hash receives at most one quota credit globally. Narrow
bad/fixed pairs may remain supplemental and cannot fill a quota deficit.
"""
    require(type(rows) is list and len(rows) <= 10000, "bounded selection array")
    require(type(registered_origins) is set and all(nonempty(origin) for origin in registered_origins),
            "registered provenance lineages")
    names, hashes, clusters = set(), set(), set()
    counts = {bucket: {"buggy": 0, "safe": 0, "origins": set()} for bucket in BUCKETS}
    supplemental = 0
    for row in rows:
        fields(row, "id family subprofile role quota origin cluster sha256 selection", "quota projection")
        require(nonempty(row["id"]) and row["id"] not in names, "duplicate/invalid selection ID")
        names.add(row["id"])
        require(type(row["family"]) is str and row["family"] in FAMILIES, "selection family")
        require(type(row["role"]) is str and row["role"] in
                ("buggy", "safe", "unknown", "unsupported"), "selection role")
        require(type(row["quota"]) is bool, "quota must be boolean")
        require(nonempty(row["origin"]) and row["origin"] in registered_origins, "unregistered provenance")
        require(nonempty(row["cluster"]), "missing semantic independence cluster")
        require(type(row["sha256"]) is str and SHA.fullmatch(row["sha256"])
                and row["sha256"] != "0" * 64, "selection source digest")
        require(row["selection"] == "independent-evaluation", "training cannot enter independent evaluation")
        subtype = row["subprofile"]
        require(subtype is None or (row["family"] == "bounds" and type(subtype) is str
                                    and subtype in ("cwe-121", "cwe-122")), "selection subprofile")
        if not row["quota"]:
            supplemental += 1
            continue
        require(row["role"] in ("buggy", "safe"), "unscored boundary cannot supply quota")
        require(row["sha256"] not in hashes, "duplicate quota source hash")
        require(row["cluster"] not in clusters, "semantic cluster reused across quota slots")
        hashes.add(row["sha256"])
        clusters.add(row["cluster"])
        bucket = row["family"] + ("/" + subtype if subtype else "")
        require(bucket in counts, "bounds quota requires proven stack/heap write subtype")
        counts[bucket][row["role"]] += 1
        counts[bucket]["origins"].add(row["origin"])
    deficits = []
    for bucket, count in counts.items():
        for role in ("buggy", "safe"):
            if count[role] < 30:
                deficits.append(f"{bucket}: {role} {count[role]}/30")
        if len(count["origins"]) < 3:
            deficits.append(f"{bucket}: origins {len(count['origins'])}/3")
    if len(hashes) < 1020:
        deficits.append(f"independent quota sources {len(hashes)}/1020")
    return {"quota_examples": len(hashes), "supplemental_examples": supplemental,
            "buckets": {bucket: {**count, "origins": sorted(count["origins"])}
                        for bucket, count in sorted(counts.items())},
            "deficits": deficits, "ground_truth_verified": False,
            "product_qualified": False}


def historical_summary(index):
    """Check indexed occurrence accounting, not external evidence or relabeling."""
    fields(index, "schema source_revision selection boundary expected_total projects", "historical index")
    require(index["schema"] == "codeskeptic-product-historical-burden/v1"
            and index["source_revision"] == HISTORICAL_REVISION
            and index["selection"] == "known-training-and-adjudication-not-independent-evaluation"
            and nonempty(index["boundary"]), "historical identity/boundary")
    require(canonical(index["expected_total"]) == canonical({"TP": 9, "FP": 47, "unknown": 10}),
            "historical total changed")
    require(type(index["projects"]) is dict and set(index["projects"]) == set(HISTORICAL_PINS),
            "historical project identity")
    total, projects = Counter(), {}
    for name, project in index["projects"].items():
        fields(project, "source_revision report_sha256 review_sha256 report_evidence review_evidence "
               "findings distinct_fingerprints source_sha256 counts occurrences", "historical project")
        require(project["source_revision"] == HISTORICAL_REVISION
                and all(nonempty(project[key]) for key in ("report_evidence", "review_evidence")),
                "historical evidence identity")
        pin = HISTORICAL_PINS[name]
        require(canonical({key: project[key] for key in pin}) == canonical(pin), "historical pinned project changed")
        rows, sources = project["occurrences"], project["source_sha256"]
        require(type(rows) is list and len(rows) == pin["findings"]
                and type(sources) is dict and sources
                and all(nonempty(path) and type(sha) is str and SHA.fullmatch(sha)
                        for path, sha in sources.items()), "historical source/occurrence inventory")
        counts, fingerprints = Counter(), set()
        for position, row in enumerate(rows):
            fields(row, "occurrence_index diagnostic classification rationale source_refs", "historical occurrence")
            require(type(row["occurrence_index"]) is int and row["occurrence_index"] == position,
                    "historical occurrence order/multiplicity")
            require(type(row["classification"]) is str and row["classification"] in ("TP", "FP", "unknown")
                    and nonempty(row["rationale"]), "historical label/rationale")
            diagnostic, refs = row["diagnostic"], row["source_refs"]
            require(type(diagnostic) is dict and diagnostic.get("file") in sources
                    and nonempty(diagnostic.get("fingerprint")) and type(refs) is list and refs,
                    "historical diagnostic/source references")
            for reference in refs:
                require(nonempty(reference), "historical source reference")
                path, separator, line = reference.rpartition(":")
                require(separator and path in sources and re.fullmatch(r"[1-9][0-9]*", line),
                        "historical reference line")
            fingerprints.add(diagnostic["fingerprint"])
            counts[row["classification"]] += 1
        actual_counts = {key: counts[key] for key in ("TP", "FP", "unknown")}
        require(actual_counts == pin["counts"] and len(fingerprints) == pin["distinct_fingerprints"],
                "historical labels or fingerprint multiplicity changed")
        total.update(counts)
        projects[name] = {"findings": len(rows), "distinct_fingerprints": len(fingerprints), "counts": actual_counts}
    require(dict(total) == {"TP": 9, "FP": 47, "unknown": 10}, "historical global partition changed")
    return {"source_revision": HISTORICAL_REVISION, "projects": projects, "counts": dict(total),
            "raw_evidence_verified": False, "fresh_measurement": False,
            "independent_evaluation_examples": 0, "product_qualified": False}


def regular_file(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and not path.is_symlink() and path.stat().st_size <= maximum, "unsafe/missing/oversized input")
    return path


def file_sha(path):
    with regular_file(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def number(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite JSON")
        return value
    return json.loads(regular_file(path).read_text(encoding="utf-8"),
                      object_pairs_hook=pairs, parse_float=number, parse_constant=number)


def verify_historical(index, repo, frozen):
    """Reconcile the preserved index with original reports, reviews and sources.

Original label judgments remain historical; this does not newly adjudicate
the ten unknowns or imply that any reported production vulnerability exists.
"""
    result = historical_summary(index)
    def source_path(name):
        if name.startswith("/workspace/build/googletest/"):
            return repo / "build/cwe-restart/googletest" / name[len("/workspace/build/googletest/"):]
        prefix = "/evidence/corpus-diagnostic-comparison/"
        require(name.startswith(prefix), "unknown historical source namespace")
        return frozen / name[len(prefix):]
    for name, project in index["projects"].items():
        for kind in ("report", "review"):
            require(file_sha(project[kind + "_evidence"]) == HISTORICAL_PINS[name][kind + "_sha256"],
                    "original historical evidence changed")
        report, review = (read_json(project[kind + "_evidence"]) for kind in ("report", "review"))
        require(review["revision"] == HISTORICAL_REVISION and review["project"] == name
                and review["report_sha256"] == project["report_sha256"]
                and canonical(review["source_sha256"]) == canonical(project["source_sha256"]),
                "original historical review identity")
        for source, sha in project["source_sha256"].items():
            require(file_sha(source_path(source)) == sha, "original historical source changed")
        require(canonical(report["diagnostics"]) == canonical([row["diagnostic"] for row in project["occurrences"]]),
                "historical indexed diagnostics differ from original raw report")
        for row in project["occurrences"]:
            matched = [group for group in review["groups"] if row["occurrence_index"] in group["diagnostic_indices"]]
            require(len(matched) == 1 and all(canonical(row[key]) == canonical(matched[0][key])
                    for key in ("classification", "rationale", "source_refs")), "historical indexed judgment changed")
            for reference in row["source_refs"]:
                source, line = reference.rsplit(":", 1)
                require(int(line) <= len(regular_file(source_path(source)).read_text(encoding="utf-8").splitlines()),
                        "historical reference outside actual source")
    return {**result, "raw_evidence_verified": True, "source_snapshots_verified": True}


def source_metadata(manifest):
    fields(manifest, "schema state selection_base limits projects historical_index historical_index_sha256 "
           "evaluation_state independent_quota_examples native_environment_state boundary", "profile manifest")
    require(manifest["schema"] == "codeskeptic-product-profiles/v1"
            and manifest["selection_base"] == "de642695c96224ab11c5add000c7ad9c996d0a50"
            and nonempty(manifest["boundary"]), "profile source identity")
    require(manifest["historical_index"] == "tests/product_corpus/historical/measurement-index.json"
            and type(manifest["historical_index_sha256"]) is str
            and SHA.fullmatch(manifest["historical_index_sha256"])
            and manifest["historical_index_sha256"] != "0" * 64,
            "historical index path/digest linkage")
    validate_limits(manifest["limits"])
    require(type(manifest["projects"]) is list and len(manifest["projects"]) == 3, "source projects")
    names, total = [], 0
    for project in manifest["projects"]:
        fields(project, "id version revision url license archive_sha256 archive_bytes local_snapshot files "
               "tree_inventory_sha256 cmake_options surfaces selection compile_database_policy measurement_state",
               "source project")
        name = project["id"]
        require(type(name) is str and name in PROJECT_PINS and name not in names, "source project identity")
        pin = PROJECT_PINS[name]
        require(canonical({key: project[key] for key in pin}) == canonical(pin), "pinned source changed")
        require(type(project["archive_bytes"]) is int and project["archive_bytes"] > 0
                and nonempty(project["local_snapshot"]) and Path(project["local_snapshot"]).is_absolute()
                and type(project["url"]) is str and project["url"].startswith("https://")
                and nonempty(project["selection"]) and nonempty(project["compile_database_policy"]),
                "source archive/selection metadata")
        require(type(project["cmake_options"]) is dict and project["cmake_options"]
                and all(type(key) is str and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key)
                        and value in ("ON", "OFF") for key, value in project["cmake_options"].items()),
                "source CMake options")
        fields(project["surfaces"], "library test example native_driver source_generator unselected boundary",
               "source surfaces")
        require(all(type(value) is list and all(nonempty(item) for item in value)
                    for key, value in project["surfaces"].items() if key != "boundary")
                and nonempty(project["surfaces"]["boundary"]), "source surface distinctions")
        files = project["files"]
        require(type(files) is list and 1 <= len(files) <= 10000, "source file inventory")
        paths = []
        for row in files:
            fields(row, "path sha256 bytes", "source input")
            name_in_tree = row["path"]
            require(type(name_in_tree) is str and nonempty(name_in_tree) and "\\" not in name_in_tree,
                    "source relative path")
            relative = PurePosixPath(name_in_tree)
            require(not relative.is_absolute() and relative.as_posix() == name_in_tree
                    and all(part not in (".", "..") for part in relative.parts), "unsafe source input path")
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * 1024 * 1024
                    and type(row["sha256"]) is str and SHA.fullmatch(row["sha256"]), "source input size/hash")
            paths.append(name_in_tree)
        require(paths == sorted(set(paths)), "missing/duplicate/unordered source inventory")
        actual_sha = hashlib.sha256(canonical(files).encode("utf-8")).hexdigest()
        require(actual_sha == pin["tree_inventory_sha256"], "source inventory identity changed")
        fields(project["license"], "path sha256 spdx", "source license")
        license_row = project["license"]
        require(nonempty(license_row["spdx"]) and any(row["path"] == license_row["path"]
                and row["sha256"] == license_row["sha256"] for row in files), "source license linkage")
        names.append(name)
        total += len(files)
    require(names == ["cjson", "tinyxml2", "googletest"], "source project order changed")
    return {"projects": names, "source_files": total, "actual_source_bytes_verified": False,
            "configured_coverage_verified": False, "product_qualified": False}


def verify_sources(manifest):
    result = source_metadata(manifest)
    for project in manifest["projects"]:
        root = Path(project["local_snapshot"])
        require(root.is_dir() and root.resolve() == root, "unsafe/missing source root")
        actual = {path.relative_to(root).as_posix() for path in root.rglob("*")
                  if path.is_file() or path.is_symlink()}
        require(actual == {row["path"] for row in project["files"]}, "source tree closure changed")
        for row in project["files"]:
            path = regular_file(root / row["path"])
            require(path.stat().st_size == row["bytes"] and file_sha(path) == row["sha256"],
                    "actual source input changed")
    return {**result, "actual_source_bytes_verified": True}


def linked_historical_index(manifest, root):
    """Bind the selected index to its actual bytes, without new adjudication."""
    source_metadata(manifest)
    path = Path(root) / manifest["historical_index"]
    require(file_sha(path) == manifest["historical_index_sha256"],
            "historical index digest mismatch")
    index = read_json(path)
    historical_summary(index)
    return index


def draft_readiness(manifest):
    metadata = source_metadata(manifest)
    require(manifest["state"] == "DRAFT_NOT_FROZEN"
            and manifest["evaluation_state"] == "SELECTION_AND_INDEPENDENT_LABEL_REVIEW_PENDING"
            and type(manifest["independent_quota_examples"]) is int and manifest["independent_quota_examples"] == 0
            and manifest["native_environment_state"] == "PROSPECTIVE_REQUIREMENTS_ONLY_ACTUAL_IDENTITY_CAPTURE_PENDING"
            and all(project["measurement_state"] == "NOT_CONFIGURED_NOT_MEASURED" for project in manifest["projects"]),
            "draft cannot fabricate completed source/corpus/environment qualification")
    return {"state": manifest["state"], "task_ready": False, "product_qualified": False,
            "source_metadata": metadata, "independent_quota_examples": 0,
            "gaps": ["independent evaluation selection and source-label review missing",
                     "1020 independent quota sources and three origins per bucket not established",
                     "required supplemental source-attributed security-fix pair review incomplete",
                     "prospective native environment realization and exact identity capture pending"],
            "boundary": "An honest incomplete draft, not an activated evaluation freeze or permission to skip FRONT."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("historical-check", "limits", "sources-check", "readiness"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--historical-sources", type=Path, default=Path(
        "/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S04-U001/corpus-diagnostic-comparison"))
    args = parser.parse_args()
    try:
        if args.command == "limits":
            result = {"limits": validate_limits(LIMITS), "measured": False,
                      "boundary": "Prospective limits only; not environment realization, dataset freeze or product PASS."}
        else:
            manifest = read_json(args.root / "scripts/product_profiles.json")
            index = linked_historical_index(manifest, args.root)
            if args.command == "historical-check":
                result = verify_historical(index, args.root, args.historical_sources)
            elif args.command == "sources-check":
                result = verify_sources(manifest)
            else:
                result = draft_readiness(manifest)
        print(canonical(result), end="")
        if args.command == "readiness" and not result["task_ready"]:
            return 2
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as error:
        print(f"PRODUCT_PROFILE_FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
