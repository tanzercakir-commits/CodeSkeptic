#!/usr/bin/env python3
"""Prospective product-profile accounting, never a quality verdict.

Quota arithmetic authenticates neither source provenance nor semantic sample
independence. Exact source/label review, content hashing and complete corpus
selection remain separate gates. Checks are read-only. Only the explicit
stage-gcc-inputs command downloads four pinned ordinary GCC inputs into a new
external directory. No execution, rebaseline or pin refresh is performed here.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import sys
import urllib.request

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


def parse_json(text):
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
    return json.loads(text,
                      object_pairs_hook=pairs, parse_float=number, parse_constant=number)


def read_json(path):
    return parse_json(regular_file(path).read_text(encoding="utf-8"))


def external_relative(value):
    """Small portable filename subset, not arbitrary host path interpretation."""
    require(type(value) is str and 0 < len(value) <= 512, "external relative path")
    parts = value.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    require(len(parts) <= 8 and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", part)
            and not part.endswith(".") and part.split(".")[0].upper() not in reserved for part in parts),
            "external relative path")
    return Path(*parts)


def external_digest(value):
    require(type(value) is str and SHA.fullmatch(value) and value != "0" * 64,
            "external digest")
    return value


def external_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ExternalIdentityError(ValueError):
    """Only static check/field names, never input bytes, paths or stat values."""
    def __init__(self, phase, actual, expected, birthtime=False):
        super().__init__("external input identity changed")
        self.phase = phase
        names = ("device", "inode", "mode", "links", "size", "mtime_ns",
                 "birthtime_ns" if birthtime else "ctime_ns")
        self.changed_fields = tuple(name for name, left, right in zip(names, actual, expected) if left != right)


def check_external_identity(actual, expected, phase, *, cross_query=False):
    left, right = external_identity(actual), external_identity(expected)
    birthtime = cross_query and sys.platform == "win32" and (
        hasattr(actual, "st_birthtime_ns") or hasattr(expected, "st_birthtime_ns"))
    if birthtime:
        # CPython 3.12 Windows lstat aliases ctime to birthtime, while fstat
        # can expose ChangeTime. Compare creation with creation only here;
        # raw same-query ctime checks remain mandatory before/after reading.
        require(type(getattr(actual, "st_birthtime_ns", None)) is int
                and type(getattr(expected, "st_birthtime_ns", None)) is int,
                "external creation timestamp unavailable")
        left = left[:6] + (actual.st_birthtime_ns,)
        right = right[:6] + (expected.st_birthtime_ns,)
    if left != right:
        raise ExternalIdentityError(phase, left, right, birthtime)


def external_read(path, capture=False):
    """Bounded descriptor read with ordinary-race checks, not hostile-root isolation.

    Content is returned only when the caller explicitly requests capture;
    public check results export metadata, not captured evidence text.
    O_NOFOLLOW is supplementary where available; canonical paths, lstat, fstat
    and final identities are checked on every host. This does not provide an
    atomic snapshot against malicious ancestor replacement/restoration.
    """
    require(path.is_absolute() and path.resolve(strict=True) == path, "external path alias")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 < before.st_size <= 16 * 1024 * 1024, "external input type/size/link")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    digest, size, chunks = hashlib.sha256(), 0, []
    try:
        opened = os.fstat(descriptor)
        check_external_identity(opened, before, "descriptor-open", cross_query=True)
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= before.st_size, "external input grew")
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        final = os.fstat(descriptor)
        check_external_identity(final, opened, "descriptor-final")
        check_external_identity(final, before, "descriptor-final", cross_query=True)
        require(size == before.st_size and path.resolve(strict=True) == path
                and external_identity(path.lstat()) == external_identity(before), "external input changed")
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size_bytes": size}, before, b"".join(chunks)


def external_tree(root, expected):
    """Exact bounded directory/file set; reject even empty unexpected directories."""
    directories = {root}
    for path in expected:
        directories.update(parent for parent in path.parents if parent == root or root in parent.parents)
    remaining, pending, identities = set(expected), [root], {}
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and directory.resolve(strict=True) == directory,
                "external directory alias/type")
        identities[directory] = external_identity(info)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = directory / entry.name
                require(not entry.is_symlink(), "external symlink")
                if entry.is_dir(follow_symlinks=False):
                    require(path in directories, "unexpected external directory")
                    pending.append(path)
                else:
                    require(path in remaining, "unexpected external file")
                    remaining.remove(path)
    require(not remaining, "missing external file")
    return identities


def verify_external_inputs(binding_path, repo, source_root):
    """Verify reviewed source bytes only; never execute, download or admit a case.

    The tracked binding plus exact-head human review is the trust anchor, not
    self-reported hashes. A caller changing both manifest and bytes obtains a
    different manifest identity, not proof that the changed source was reviewed.
    """
    try:
        repo, root, binding_path = Path(repo), Path(source_root), Path(binding_path)
        for directory in (repo, root):
            require(directory.is_absolute() and directory.resolve(strict=True) == directory
                    and directory.is_dir(), "external root alias/type")
        require(repo != root and repo not in root.parents and root not in repo.parents,
                "external root overlaps checkout")
        require(repo in binding_path.parents, "external manifest outside checkout")
        binding_hash, binding_info, raw = external_read(binding_path, capture=True)
        manifest = parse_json(raw.decode("utf-8"))
        fields(manifest, "schema state id adjudication inputs", "external binding")
        require(manifest["schema"] == "codeskeptic-product-external-inputs/v1"
                and manifest["state"] == "SOURCE_BINDING_ONLY_NOT_FROZEN"
                and type(manifest["id"]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", manifest["id"]),
                "external binding identity/state")
        link = manifest["adjudication"]
        fields(link, "path sha256", "external adjudication")
        review_path = repo / external_relative(link["path"])
        external_digest(link["sha256"])
        review_hash, review_info, raw = external_read(review_path, capture=True)
        require(review_hash["sha256"] == link["sha256"], "external adjudication changed")
        review = parse_json(raw.decode("utf-8"))
        rows = manifest["inputs"]
        require(type(rows) is list and 4 <= len(rows) <= 64, "external input inventory size")
        expected, roles, names, total = {}, Counter(), [], 0
        for row in rows:
            fields(row, "role path size_bytes sha256", "external input")
            require(type(row["role"]) is str and row["role"] in ("candidate", "origin", "lineage", "notice"),
                    "external role")
            relative = external_relative(row["path"])
            external_digest(row["sha256"])
            require(type(row["size_bytes"]) is int and 0 < row["size_bytes"] <= 16 * 1024 * 1024,
                    "external declared size")
            total += row["size_bytes"]
            expected[root / relative] = row
            names.append(row["path"])
            roles[row["role"]] += 1
        require(names == sorted(names) and len(set(name.casefold() for name in names)) == len(names)
                and total <= 64 * 1024 * 1024 and roles["candidate"] == roles["origin"] == 1
                and roles["lineage"] >= 1 and roles["notice"] >= 1, "external inventory ordering/roles/budget")
        for path in expected:
            require(not any(parent in expected for parent in path.parents), "external file/directory collision")
        require(type(review) is dict and review["id"] == manifest["id"], "external review case identity")
        for role, field in (("candidate", "source"), ("origin", "origin")):
            require(type(review[field]) is dict and review[field]["sha256"] ==
                    next(row["sha256"] for row in rows if row["role"] == role), "external reviewed bytes mismatch")
        before_tree = external_tree(root, expected)
        files, inodes = {binding_path: binding_info, review_path: review_info}, set()
        for path, row in expected.items():
            actual, info, _ = external_read(path)
            require(actual == {key: row[key] for key in ("size_bytes", "sha256")}, "external source changed")
            require((info.st_dev, info.st_ino) not in inodes, "external duplicate inode")
            inodes.add((info.st_dev, info.st_ino))
            files[path] = info
        require(external_tree(root, expected) == before_tree, "external tree changed")
        for path, before in files.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "external final identity changed")
        return {"schema": "codeskeptic-product-external-input-check/v1", "id": manifest["id"],
                "binding_sha256": binding_hash["sha256"], "adjudication_sha256": review_hash["sha256"],
                "source_bytes_verified": True, "verified_inputs": len(rows), "verified_bytes": total,
                "independent_quota_examples": 0, "task_ready": False, "product_qualified": False,
                "native_commands_bound": False, "license_qualified": False,
                "state": "SOURCE_BINDING_ONLY_NOT_FROZEN"}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError):
        # Parser/OS exception text can contain private paths or input fragments.
        raise ValueError("external input binding rejected") from None


GCC_BINDING = "tests/product_corpus/candidates/gcc-mixed-storage-binding.json"
GCC_REVISION = "5115c7e447fc07457443df874bf57840e8316d5f"
GCC_LICENSE_BASIS = "tests/product_corpus/candidates/gcc-mixed-storage-license-basis.json"
GCC_SOURCE_CANDIDATE = "tests/product_corpus/candidates/gcc-mixed-storage-source-candidate.json"
GCC_CASE_SHA = "5c5563b8ed6e5715cb1913e223276146bc4c8799c11ee4dace55cf6e8a5e4b0a"
GCC_CANDIDATE_LINKS = {
    "source_binding": GCC_BINDING,
    "source_review": "tests/product_corpus/candidates/gcc-mixed-storage-selection.json",
    "license_basis": GCC_LICENSE_BASIS,
    "analysis_profile": "tests/product_corpus/candidates/gcc-mixed-storage-linux.json",
    "compiler_commands": "tests/product_corpus/candidates/gcc-mixed-storage-linux/compile_commands.json",
}
GCC_INPUTS = {
    "origin/malloc-vs-local-3.c": "gcc/testsuite/c-c++-common/analyzer/malloc-vs-local-3.c",
    "lineage/malloc-vs-local-2.c": "gcc/testsuite/c-c++-common/analyzer/malloc-vs-local-2.c",
    "notices/COPYING3": "COPYING3",
    "notices/README": "gcc/testsuite/README",
}


def gcc_license_metadata(value):
    """Validate the scope of a project-license reference record, not permissions."""
    fields(value, "schema state id revision source_binding source_sha256 references assessment boundary",
           "GCC license basis")
    require(value["schema"] == "codeskeptic-gcc-license-basis/v1"
            and value["state"] == "PROJECT_LICENSE_REFERENCES_BOUND_NOT_DISTRIBUTION_CLEARANCE"
            and value["id"] == "gcc-mixed-storage-local-loss" and value["revision"] == GCC_REVISION
            and nonempty(value["boundary"]), "GCC license reference identity")
    external_digest(value["source_sha256"])
    fields(value["source_binding"], "path sha256", "GCC license source binding")
    require(value["source_binding"]["path"] == GCC_BINDING, "GCC license binding path")
    external_digest(value["source_binding"]["sha256"])
    expected = {
        "license-text": ("COPYING3", f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/COPYING3"),
        "project-statement": ("gcc-license-statement.html", "https://gcc.gnu.org/pipermail/gcc/2021-June/236201.html"),
        "root-notice": ("root-README", f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/README"),
    }
    require(type(value["references"]) is list and len(value["references"]) == 3, "GCC license references")
    roles = []
    for row in value["references"]:
        fields(row, "role path url size_bytes sha256", "GCC license reference")
        require(type(row["role"]) is str and row["role"] in expected
                and (row["path"], row["url"]) == expected[row["role"]]
                and type(row["size_bytes"]) is int and 0 < row["size_bytes"] <= 262144,
                "GCC reference location/size")
        external_digest(row["sha256"])
        roles.append(row["role"])
    require(roles == sorted(expected), "GCC reference ordering/duplicate role")
    assessment = value["assessment"]
    fields(assessment, "upstream_project_spdx basis source_specific_boundary distribution_boundary "
           "license_qualified redistribution_approved author_completeness_verified", "GCC license assessment")
    require(assessment["upstream_project_spdx"] == "GPL-3.0-or-later"
            and all(nonempty(assessment[key]) for key in
                    ("basis", "source_specific_boundary", "distribution_boundary"))
            and all(assessment[key] is False for key in
                    ("license_qualified", "redistribution_approved", "author_completeness_verified")),
            "project declaration is not source-specific distribution clearance")
    return {"upstream_project_spdx": assessment["upstream_project_spdx"],
            "reference_bytes_verified": False, "source_bytes_verified": False,
            "license_qualified": False, "redistribution_approved": False,
            "independent_quota_examples": 0, "task_ready": False, "product_qualified": False}


def verify_gcc_license_basis(repo, evidence_root, source_root):
    """Bind actual references to the unchanged source snapshot; never download."""
    try:
        repo, root = Path(repo), Path(evidence_root)
        require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir()
                and root != repo and repo not in root.parents and root not in repo.parents,
                "GCC license evidence root")
        path = repo / GCC_LICENSE_BASIS
        actual, info, raw = external_read(path, capture=True)
        value = parse_json(raw.decode("utf-8"))
        result = gcc_license_metadata(value)
        binding = verify_external_inputs(repo / GCC_BINDING, repo, source_root)
        require(binding["binding_sha256"] == value["source_binding"]["sha256"], "GCC license binding drift")
        manifest = read_json(repo / GCC_BINDING)
        require(next(row["sha256"] for row in manifest["inputs"] if row["role"] == "candidate")
                == value["source_sha256"], "GCC license source drift")
        rows = value["references"]
        require(next(row["sha256"] for row in rows if row["role"] == "license-text") ==
                next(row["sha256"] for row in manifest["inputs"] if row["path"] == "notices/COPYING3"),
                "GCC source notice differs from license reference")
        observations = {path: info}
        for row in rows:
            path = root / external_relative(row["path"])
            observed, info, _ = external_read(path)
            require(observed == {key: row[key] for key in ("sha256", "size_bytes")}, "GCC license reference drift")
            observations[path] = info
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "GCC license final identity changed")
        return {**result, "reference_bytes_verified": True, "source_bytes_verified": True,
                "license_record_sha256": actual["sha256"], "source_binding_sha256": binding["binding_sha256"],
                "source_sha256": value["source_sha256"], "verified_references": len(rows)}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, StopIteration):
        raise ValueError("GCC license reference binding rejected") from None


def gcc_candidate_metadata(value):
    """One pre-result ordinary memory source proposal, not an admission receipt."""
    fields(value, "schema state id family subprofile role selection origin cluster source links "
           "license_evidence_root analysis_selection limits expected boundaries qualification", "source candidate")
    require(value["schema"] == "codeskeptic-product-source-candidate/v1"
            and value["state"] == "PRE_RESULT_SOURCE_SELECTION_FOR_REVIEW"
            and value["id"] == "gcc-mixed-storage-local-loss"
            and value["family"] == "memory-leak" and value["subprofile"] is None
            and value["role"] == "buggy" and value["selection"] == "independent-evaluation"
            and value["origin"] == "gcc-analyzer-testsuite"
            and value["cluster"] == "mixed-automatic-heap-small-buffer-fallback-loss"
            and value["analysis_selection"] == "linux-x86_64-ubuntu24-clang20-c17-native-malloc-v1",
            "source candidate identity/selection")
    source = value["source"]
    fields(source, "path sha256 language snapshot_root", "candidate source")
    require(source["path"] == "/input/case.c" and source["sha256"] == GCC_CASE_SHA
            and source["language"] == "C17" and nonempty(source["snapshot_root"])
            and nonempty(value["license_evidence_root"]), "candidate source identity")
    fields(value["links"], " ".join(GCC_CANDIDATE_LINKS), "candidate links")
    for name, link in value["links"].items():
        fields(link, "path sha256", "candidate link")
        require(link["path"] == GCC_CANDIDATE_LINKS[name], "candidate link path")
        external_digest(link["sha256"])
    validate_limits(value["limits"])
    require(canonical(value["expected"]) == canonical([
        {"rule": "memory-leak", "function": "test_2", "line": 28, "column": 1, "cwes": [401], "multiplicity": 1}]),
        "pre-result source expectation changed")
    fields(value["boundaries"], "allocation independence addressability all_rule_ground_truth platforms measurement rights",
           "candidate boundaries")
    require(all(nonempty(item) for item in value["boundaries"].values()), "candidate boundary missing")
    fields(value["qualification"], "evaluation_frozen native_product_qualified license_qualified "
           "redistribution_approved analyzer_run task_ready product_qualified", "candidate qualification")
    require(all(item is False for item in value["qualification"].values()), "source proposal cannot qualify product")
    return {key: value[key] for key in ("id", "family", "subprofile", "role", "origin", "cluster", "selection")} | {
        "sha256": source["sha256"], "quota": False}


def verify_gcc_source_candidate(repo):
    """Verify actual proposed inputs and predeclared recipe; do not run/admit it."""
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "candidate checkout root")
        observations = {}

        def read_bound(path, sha=None, document=True):
            actual, info, raw = external_read(path, capture=True)
            require(sha is None or actual["sha256"] == sha, "candidate linked evidence changed")
            observations[path] = info
            return (parse_json(raw.decode("utf-8")) if document else None), actual["sha256"]

        value, candidate_sha = read_bound(repo / GCC_SOURCE_CANDIDATE)
        projection = gcc_candidate_metadata(value)
        linked = {name: read_bound(repo / link["path"], link["sha256"])[0]
                  for name, link in value["links"].items()}
        licensing = verify_gcc_license_basis(repo, value["license_evidence_root"], value["source"]["snapshot_root"])
        require(licensing["license_record_sha256"] == value["links"]["license_basis"]["sha256"]
                and licensing["source_sha256"] == projection["sha256"], "candidate license identity")
        binding, review, recipe = (linked[key] for key in ("source_binding", "source_review", "analysis_profile"))
        require(binding["adjudication"] == value["links"]["source_review"]
                and review["source"]["sha256"] == projection["sha256"]
                and review["source_label"]["family"] == projection["family"]
                and review["source_label"]["label"] == "BUGGY_CWE401"
                and review["independence"]["cluster"] == projection["cluster"]
                and review["independence"]["verdict"] == "DISTINCT_PROSPECTIVE_CLUSTER", "candidate source review")
        previous = review["review"]
        for key in ("proof_evidence", "review_evidence", "history_evidence"):
            read_bound(Path(previous[key]), previous[key + "_sha256"], document=False)
        require(recipe["id"] == projection["id"] and recipe["source_binding"]["case_sha256"] == projection["sha256"]
                and {key: recipe["source_binding"][key] for key in ("path", "sha256")} == value["links"]["source_binding"]
                and {key: recipe["compilation_database"][key] for key in ("path", "sha256")} == value["links"]["compiler_commands"]
                and recipe["source_binding"]["case"] == value["source"]["path"]
                and recipe["analyzer_recipes"]["state"] == "PREDECLARED_NOT_EXECUTED"
                and recipe["analyzer_recipes"]["executable_sha256"] is None
                and recipe["analyzer_recipes"]["repetitions"] == LIMITS["repetitions"]
                and recipe["analyzer_recipes"]["outer_case_timeout_seconds"] == LIMITS["case_timeout_seconds"],
                "candidate prospective recipe linkage")
        cdb = linked["compiler_commands"]
        require(type(cdb) is list and len(cdb) == 1 and cdb[0]["file"] == value["source"]["path"]
                and cdb[0]["arguments"][0] == recipe["environment_reference"]["compiler"]
                and cdb[0]["arguments"][-1] == value["source"]["path"]
                and "-std=c17" in cdb[0]["arguments"], "candidate selected C17 translation unit")
        native = recipe["native_evidence"]
        for key in ("source_abi_summary", "source_abi_wrapper", "source_abi_review",
                    "selected_recipe_summary", "selected_recipe_wrapper"):
            read_bound(Path(native[key]), native[key + "_sha256"], document=False)
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "candidate evidence final identity changed")
        return {"candidate_sha256": candidate_sha, "projection": projection,
                "linked_evidence_files": len(observations), "source_bytes_verified": True,
                "pre_result_recipe_bound": True, "fresh_independent_admission_required": True,
                "independent_quota_examples": 0, "task_ready": False, "product_qualified": False}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, IndexError):
        raise ValueError("source candidate binding rejected") from None


def admission_review_metadata(review, candidate, candidate_sha):
    """Check a procedural source-count decision, never authenticate its author."""
    fields(review, "schema repository_head candidate_path candidate_sha256 source_sha256 implementer verifier "
           "verdict admitted_source_count projection reviewed_links rationale remaining_gaps qualification", "source admission review")
    require(review["schema"] == "codeskeptic-source-admission-review/v1"
            and type(review["repository_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", review["repository_head"])
            and review["repository_head"] != "0" * 40
            and review["candidate_path"] == GCC_SOURCE_CANDIDATE and review["candidate_sha256"] == candidate_sha
            and review["verdict"] == "ADMIT_ONE_SOURCE" and type(review["admitted_source_count"]) is int
            and review["admitted_source_count"] == 1, "source admission identity/verdict")
    for key in ("implementer", "verifier"):
        require(type(review[key]) is str and re.fullmatch(r"/[a-z0-9_]+(?:/[a-z0-9_]+)*", review[key])
                and len(review[key]) <= 128, "source admission agent identity")
    require(review["implementer"] != review["verifier"], "source admission is not independent")
    projection = {**gcc_candidate_metadata(candidate), "quota": True}
    require(review["source_sha256"] == projection["sha256"]
            and canonical(review["projection"]) == canonical(projection)
            and canonical(review["reviewed_links"]) == canonical(candidate["links"])
            and canonical(review["qualification"]) == canonical(candidate["qualification"]),
            "source admission candidate/projection/qualification mismatch")
    require(nonempty(review["rationale"]) and len(review["rationale"]) <= 8192
            and type(review["remaining_gaps"]) is list and 1 <= len(review["remaining_gaps"]) <= 32
            and all(nonempty(gap) and len(gap) <= 2048 for gap in review["remaining_gaps"]),
            "source admission rationale/boundaries")
    return projection


def verify_reviewed_files(repo, head, links, *, expected_tree=None):
    """Bind reviewed bytes to a real ancestor commit, permitting later integration."""
    repo = Path(repo)
    require(repo.is_absolute() and repo.resolve(strict=True) == repo, "reviewed checkout root")
    require(type(head) is str and re.fullmatch(r"[0-9a-f]{40}", head) and head != "0" * 40,
            "reviewed commit identity")
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")

    def git(*args):
        result = subprocess.run(["git", "--no-pager", "--literal-pathspecs", "-C", str(repo), *args],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, env=environment)
        require(result.returncode == 0, "reviewed Git object unavailable")
        return result.stdout

    git("cat-file", "-e", head + "^{commit}")
    git("merge-base", "--is-ancestor", head, "HEAD")
    if expected_tree is not None:
        require(type(expected_tree) is str and re.fullmatch(r"[0-9a-f]{40}", expected_tree)
                and git("rev-parse", head + "^{tree}").decode("ascii").strip() == expected_tree,
                "observed producer tree changed")
    require(type(links) is list and 1 <= len(links) <= 64, "reviewed file links")
    names = set()
    for link in links:
        fields(link, "path sha256", "reviewed file")
        # One actual producer input lives under a dot-directory. Keep the
        # external-source filename grammar unchanged; this is a Git blob read.
        relative = (link["path"] if link["path"] == ".github/workflows/product-identity.yml"
                    else external_relative(link["path"]).as_posix())
        external_digest(link["sha256"])
        require(relative not in names, "duplicate reviewed file")
        names.add(relative)
        entry = git("ls-tree", "-z", head, "--", relative)
        require(entry.endswith(b"\0") and entry.count(b"\0") == 1, "reviewed tree entry")
        info, name = entry[:-1].split(b"\t", 1)
        mode, kind, blob = info.split(b" ")
        require(mode in (b"100644", b"100755") and kind == b"blob" and name.decode("utf-8") == relative,
                "reviewed file is not a regular blob")
        blob_name = blob.decode("ascii")
        size = int(git("cat-file", "-s", blob_name))
        require(0 < size <= 16 * 1024 * 1024, "reviewed blob size")
        raw = git("cat-file", "blob", blob_name)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == link["sha256"],
                "reviewed commit bytes changed")


SOURCE_SELECTION = "tests/product_corpus/selection.json"


def verify_source_selection(repo, link):
    """Read an entire partial selection before returning any admitted count.

    Exact reviewed commits, actual linked bytes and distinct procedural agent
    identities are checked. This shared-account process is not signed provenance
    or proof against an author forging both an index and its review evidence.
    """
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "selection checkout root")
        observations = {}

        def read_link(item, external=False, maximum=16 * 1024 * 1024):
            fields(item, "path sha256", "selection link")
            external_digest(item["sha256"])
            path = Path(item["path"]) if external else repo / external_relative(item["path"])
            require(not external or (path.is_absolute() and repo not in path.parents), "review evidence must be external")
            actual, info, raw = external_read(path, capture=True)
            require(actual["sha256"] == item["sha256"] and actual["size_bytes"] <= maximum, "selection evidence drift/size")
            observations[path] = info
            return parse_json(raw.decode("utf-8"))

        require(type(link) is dict and link.get("path") == SOURCE_SELECTION, "selection manifest path")
        value = read_link(link)
        fields(value, "schema state origins admissions boundary", "source selection")
        require(value["schema"] == "codeskeptic-product-reviewed-source-selection/v1"
                and value["state"] == "PARTIAL_REVIEWED_SOURCE_SELECTION_NOT_FROZEN"
                and nonempty(value["boundary"]), "source selection state")
        origins = value["origins"]
        require(type(origins) is dict and 1 <= len(origins) <= 1000
                and all(type(name) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", name)
                        and type(url) is str and re.fullmatch(r"https://[A-Za-z0-9./_-]+", url)
                        and not url.endswith("/") for name, url in origins.items())
                and len(set(url.casefold() for url in origins.values())) == len(origins), "canonical source origins")
        require(type(value["admissions"]) is list and len(value["admissions"]) <= 10000, "bounded source admissions")
        rows = []
        for entry in value["admissions"]:
            fields(entry, "candidate review", "source admission entry")
            require(type(entry["candidate"]) is dict and entry["candidate"].get("path") == GCC_SOURCE_CANDIDATE,
                    "unimplemented source candidate schema")
            candidate = read_link(entry["candidate"], maximum=65536)
            review = read_link(entry["review"], external=True, maximum=65536)
            projection = admission_review_metadata(review, candidate, entry["candidate"]["sha256"])
            require(origins.get(projection["origin"]) == "https://github.com/gcc-mirror/gcc", "candidate canonical origin")
            verify_reviewed_files(repo, review["repository_head"], [entry["candidate"], *review["reviewed_links"].values()])
            actual = verify_gcc_source_candidate(repo)
            require(actual["candidate_sha256"] == entry["candidate"]["sha256"]
                    and canonical({**actual["projection"], "quota": True}) == canonical(projection),
                    "admitted candidate no longer matches actual inputs")
            rows.append(projection)
        result = quota_readiness(rows, set(origins))
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "selection evidence final identity changed")
        return {**result, "state": value["state"], "selection_sha256": link["sha256"],
                "source_admission_reviews_bound": len(rows), "evaluation_frozen": False,
                "task_ready": False, "native_product_qualified": False, "license_qualified": False,
                "redistribution_approved": False}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError("reviewed source selection rejected") from None


GCC_GROUND_TRUTH = "tests/product_corpus/candidates/gcc-mixed-storage-ground-truth.json"
GROUND_TRUTH_INDEX = "tests/product_corpus/ground_truth.json"
GROUND_TRUTH_REFERENCES = (
    "src/core/RuleCapabilities.def", "src/core/Capabilities.cpp", "src/rules/AssumptionRule.cpp",
    "src/rules/ContractRule.cpp", "src/rules/PolicyRule.cpp", "scripts/cwe_quality.py",
    "scripts/product_quality.py", "docs/product-quality-contract.md",
)
GROUND_TRUTH_PLANNED = frozenset(("format-string", "command-injection", "sql-injection", "path-traversal"))


def gcc_ground_truth_metadata(value, candidate):
    """Check one exact source's proposed labels; human source review is separate."""
    gcc_candidate_metadata(candidate)
    fields(value, "schema state id candidate source reference_head references data_model assumptions "
           "families project_diagnostics boundary additional_quota_examples qualification", "all-rule source labels")
    require(value["schema"] == "codeskeptic-product-source-all-rule-ground-truth/v1"
            and value["state"] == "SOURCE_DERIVED_LABELS_FOR_INDEPENDENT_REVIEW"
            and value["id"] == candidate["id"], "all-rule source identity")
    fields(value["candidate"], "path sha256", "all-rule candidate link")
    require(value["candidate"]["path"] == GCC_SOURCE_CANDIDATE, "all-rule candidate path")
    external_digest(value["candidate"]["sha256"])
    fields(value["source"], "path sha256 language line_count", "all-rule source")
    require({key: value["source"][key] for key in ("path", "sha256", "language")}
            == {key: candidate["source"][key] for key in ("path", "sha256", "language")}
            and type(value["source"]["line_count"]) is int and value["source"]["line_count"] == 28,
            "all-rule source binding")
    require(type(value["reference_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["reference_head"])
            and value["reference_head"] != "0" * 40, "all-rule reference commit")
    references = value["references"]
    require(type(references) is list and len(references) == len(GROUND_TRUTH_REFERENCES), "all-rule reference coverage")
    for link, path in zip(references, GROUND_TRUTH_REFERENCES):
        fields(link, "path sha256", "all-rule reference")
        require(link["path"] == path, "all-rule reference path/order")
        external_digest(link["sha256"])
    require(canonical(value["data_model"]) == canonical({
        "char_bit": 8, "int_bits": 32, "size_t_bits": 64, "pointer_bits": 64,
        "int_max": 2**31 - 1, "allocation_n_min": 11, "allocation_bytes_max": 4 * (2**31 - 1)}),
        "all-rule conditional data model")
    require(type(value["assumptions"]) is list and 1 <= len(value["assumptions"]) <= 16
            and all(nonempty(item) and len(item) <= 2048 for item in value["assumptions"])
            and nonempty(value["boundary"]) and len(value["boundary"]) <= 8192,
            "all-rule assumptions/boundary")
    require(type(value["additional_quota_examples"]) is int and value["additional_quota_examples"] == 0
            and canonical(value["qualification"]) == canonical(candidate["qualification"]),
            "all-rule labels cannot add quota or qualification")

    def source_basis(row):
        lines = row["source_lines"]
        require(type(lines) is list and lines and all(type(line) is int and 1 <= line <= 28 for line in lines)
                and lines == sorted(set(lines)) and nonempty(row["rationale"]) and len(row["rationale"]) <= 8192,
                "all-rule bounded source rationale")

    rows = value["families"]
    require(type(rows) is list and len(rows) == len(FAMILIES), "all-rule family coverage")
    for row, family in zip(rows, sorted(FAMILIES)):
        fields(row, "rule availability role expected source_lines rationale", "all-rule family")
        require(row["rule"] == family and row["availability"] == (
                "PLANNED_NOT_IMPLEMENTED" if family in GROUND_TRUTH_PLANNED else "INSTALLED_AT_REFERENCE_HEAD"),
                "all-rule family order/availability")
        # This is the already-bound 28-line GCC source, not a generic labeler.
        # Any different label needs new independently reviewed source evidence.
        expected = candidate["expected"] if family == "memory-leak" else []
        require(row["role"] == ("buggy" if expected else "safe")
                and canonical(row["expected"]) == canonical(expected), "all-rule source expectation")
        source_basis(row)
    projects = value["project_diagnostics"]
    require(type(projects) is list and len(projects) == 3, "all-rule project diagnostic coverage")
    for row, rule in zip(projects, ("assumption", "contract", "policy")):
        fields(row, "rule role expected source_lines rationale", "all-rule project diagnostic")
        require(row["rule"] == rule and row["role"] == "no-trigger" and row["expected"] == [],
                "all-rule report-only expectation")
        source_basis(row)
    return {"family_labels": len(rows), "project_diagnostics": len(projects), "expected_occurrences": 1,
            "additional_quota_examples": 0, "source_labels_independently_reviewed": False,
            **candidate["qualification"]}


def verify_gcc_ground_truth(repo):
    """Read actual candidate/source/reference bytes without running an analyzer."""
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "all-rule checkout root")
        observations = {}

        def read(path, expected=None):
            info, before, raw = external_read(path, capture=True)
            require(expected is None or info["sha256"] == expected, "all-rule input changed")
            observations[path] = before
            return info, raw

        info, raw = read(repo / GCC_GROUND_TRUTH)
        require(info["size_bytes"] <= 65536, "all-rule record size")
        value = parse_json(raw.decode("utf-8"))
        candidate_info, candidate_raw = read(repo / GCC_SOURCE_CANDIDATE, value["candidate"]["sha256"])
        candidate = parse_json(candidate_raw.decode("utf-8"))
        result = gcc_ground_truth_metadata(value, candidate)
        actual = verify_gcc_source_candidate(repo)
        require(actual["candidate_sha256"] == candidate_info["sha256"], "all-rule candidate evidence changed")
        recipe_link = candidate["links"]["analysis_profile"]
        _, recipe_raw = read(repo / recipe_link["path"], recipe_link["sha256"])
        native = parse_json(recipe_raw.decode("utf-8"))["native_evidence"]
        require(type(native["char_bit"]) is int and native["char_bit"] == value["data_model"]["char_bit"]
                and all(type(native[role + "_bytes"]) is int
                        and native[role + "_bytes"] * native["char_bit"] == value["data_model"][role + "_bits"]
                        for role in ("int", "size_t", "pointer")), "all-rule recipe data model mismatch")
        _, source = read(Path(candidate["source"]["snapshot_root"]) / "case.c", candidate["source"]["sha256"])
        require(len(source.decode("utf-8").splitlines()) == value["source"]["line_count"], "all-rule source line count")
        verify_reviewed_files(repo, value["reference_head"], value["references"])
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "all-rule final input identity changed")
        return {**result, "record_sha256": info["sha256"], "candidate_sha256": candidate_info["sha256"],
                "source_sha256": candidate["source"]["sha256"], "reference_head": value["reference_head"],
                "source_bytes_verified": True}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError("GCC all-rule source binding rejected") from None


def ground_truth_review_metadata(review, value, record_sha):
    external_digest(record_sha)
    fields(review, "schema repository_head record candidate source_sha256 implementer verifier verdict findings "
           "rationale additional_quota_examples qualification", "all-rule source review")
    require(review["schema"] == "codeskeptic-all-rule-source-review/v1"
            and type(review["repository_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", review["repository_head"])
            and review["repository_head"] != "0" * 40
            and review["record"] == {"path": GCC_GROUND_TRUTH, "sha256": record_sha}
            and review["candidate"] == value["candidate"] and review["source_sha256"] == value["source"]["sha256"]
            and review["verdict"] == "ACCEPT_SOURCE_LABELS" and review["findings"] == [], "all-rule reviewed identity/verdict")
    for key in ("implementer", "verifier"):
        require(type(review[key]) is str and re.fullmatch(r"/[a-z0-9_]+(?:/[a-z0-9_]+)*", review[key])
                and len(review[key]) <= 128, "all-rule review agent identity")
    require(review["implementer"] != review["verifier"] and nonempty(review["rationale"])
            and len(review["rationale"]) <= 8192 and type(review["additional_quota_examples"]) is int
            and review["additional_quota_examples"] == 0
            and canonical(review["qualification"]) == canonical(value["qualification"]),
            "all-rule review independence/boundaries")
    fields(review["qualification"], "evaluation_frozen native_product_qualified license_qualified "
           "redistribution_approved analyzer_run task_ready product_qualified", "all-rule review qualification")
    require(all(item is False for item in review["qualification"].values()), "source review is not qualification")


def verify_ground_truth_index(repo):
    """Read a separately reviewed label sidecar; never amend source admission."""
    try:
        repo = Path(repo)
        observations = {}

        def read(path, expected=None):
            info, before, raw = external_read(path, capture=True)
            require(info["size_bytes"] <= 65536 and (expected is None or info["sha256"] == expected),
                    "all-rule reviewed evidence size/hash")
            observations[path] = before
            return parse_json(raw.decode("utf-8"))

        index = read(repo / GROUND_TRUTH_INDEX)
        fields(index, "schema state entries boundary", "all-rule label index")
        require(index["schema"] == "codeskeptic-product-reviewed-ground-truth/v1"
                and index["state"] == "PARTIAL_REVIEWED_SOURCE_LABELS_NOT_FROZEN"
                and nonempty(index["boundary"]) and type(index["entries"]) is list and len(index["entries"]) == 1,
                "all-rule label index state")
        entry = index["entries"][0]
        fields(entry, "record review", "all-rule index entry")
        for link in entry.values():
            fields(link, "path sha256", "all-rule index link")
            external_digest(link["sha256"])
        require(entry["record"]["path"] == GCC_GROUND_TRUTH, "all-rule indexed record path")
        value = read(repo / GCC_GROUND_TRUTH, entry["record"]["sha256"])
        review_path = Path(entry["review"]["path"])
        require(review_path.is_absolute() and repo not in review_path.parents, "all-rule review must be external")
        review = read(review_path, entry["review"]["sha256"])
        ground_truth_review_metadata(review, value, entry["record"]["sha256"])
        verify_reviewed_files(repo, review["repository_head"], [entry["record"], value["candidate"]])
        actual = verify_gcc_ground_truth(repo)
        require(actual["record_sha256"] == entry["record"]["sha256"], "all-rule reviewed record changed")
        manifest = read_json(repo / "scripts/product_profiles.json")
        source_metadata(manifest)
        selection = verify_source_selection(repo, manifest["source_selection"])
        selected = read(repo / SOURCE_SELECTION, manifest["source_selection"]["sha256"])
        require(selection["quota_examples"] >= 1
                and selection["quota_examples"] == manifest["independent_quota_examples"]
                and any(item["candidate"] == value["candidate"] for item in selected["admissions"]),
                "all-rule record requires its original source admission")
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "all-rule reviewed evidence final identity changed")
        return {**actual, "source_labels_independently_reviewed": True,
                "source_selection_quota_examples": selection["quota_examples"], "review_head": review["repository_head"]}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError("reviewed all-rule source labels rejected") from None


GCC_PLATFORM_FILES = {
    "Windows": "tests/product_corpus/candidates/gcc-mixed-storage-windows.json",
    "Darwin": "tests/product_corpus/candidates/gcc-mixed-storage-macos.json",
}
GCC_PLATFORM_REFERENCES = (
    "src/source_manager/SourceManager.cpp", "src/source_manager/ResourceDir.cpp",
    "src/config/Config.cpp", "src/config/Config.h", "src/core/RuleCapabilities.def",
    "src/analyzer/BuiltinRules.h", "src/main.cpp", "src/source_manager/CompilationDatabaseDiscovery.cpp",
    "src/analyzer/StaticAnalyzer.cpp", "src/analyzer/AnalysisCoordinator.cpp", "src/CMakeLists.txt",
)
GCC_PLATFORM_QUALIFICATION = (
    "evaluation_frozen", "platform_source_labels_reviewed", "adjusted_header_closure_verified",
    "native_bytes_reopened", "native_product_qualified", "analyzer_run", "license_qualified",
    "redistribution_approved", "task_ready", "product_qualified",
)
GCC_ISOLATED_DISABLED = ("uninit-ptr,uninit-scalar,double-free,use-after-free,resource-leak,div-by-zero,"
                         "null-deref,bounds,int-overflow,sign-conversion,alloc-size-overflow,assumption,contract,policy")


def map_gcc_native_source(system, mapping, filename):
    """Lexical mapping of exactly one source, never a filesystem/SDK relocation."""
    require(type(system) is str and system in GCC_PLATFORM_FILES, "native mapping platform")
    fields(mapping, "kind logical_path native_path", "native source mapping")
    require(mapping["kind"] == "EXACT_SOURCE_ONLY" and mapping["logical_path"] == "/input/case.c",
            "native mapping scope")
    path_type = PureWindowsPath if system == "Windows" else PurePosixPath
    for path in (mapping["native_path"], filename):
        require(type(path) is str and 0 < len(path) <= 4096 and not any(ord(char) < 32 for char in path),
                "native source path")
        parts = re.split(r"[/\\]", path) if system == "Windows" else path.split("/")
        parsed = path_type(path)
        require(parsed.is_absolute() and not any(part in (".", "..") for part in parts)
                and (bool(re.fullmatch(r"[A-Za-z]:", parsed.drive)) if system == "Windows" else not path.startswith("//")),
                "native source path form")
    require(path_type(filename) == path_type(mapping["native_path"]) and path_type(mapping["native_path"]).name == "case.c",
            "unmapped native source")
    return mapping["logical_path"]


def gcc_platform_recipe_parts(value):
    """Deterministic prospective recipe parts; this function never runs tools."""
    import product_identity as identity
    identity.validate_case_document(value)
    native = value["native_identity"]
    system = native["platform"]["system"]
    require(system in GCC_PLATFORM_FILES, "native recipe platform")
    path_type = PureWindowsPath if system == "Windows" else PurePosixPath
    source = value["input"]["path"]
    mapping = {"kind": "EXACT_SOURCE_ONLY", "logical_path": "/input/case.c", "native_path": source}
    map_gcc_native_source(system, mapping, source)
    source_root = path_type(source).parent
    root = source_root.parent / "codeskeptic-gcc-analysis"
    profile, output, temporary = (root / name for name in ("profile", "output", "tmp"))
    executable = str(root / "product/bin" / ("codeskeptic.exe" if system == "Windows" else "codeskeptic"))
    tool = native["tools"]["clang"]
    environment = {"CODESKEPTIC_RESOURCE_DIR": tool["resource_dir"], "LANG": "C", "LC_ALL": "C"}
    if system == "Windows":
        keys = ("INCLUDE", "VCToolsInstallDir", "VCToolsVersion", "VSINSTALLDIR", "WindowsSdkDir",
                "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion", "SystemRoot", "WINDIR", "SystemDrive",
                "COMSPEC", "USERPROFILE", "APPDATA", "LOCALAPPDATA")
        environment.update({key: value["environment"][key] for key in keys if key in value["environment"]})
        path = [str(path_type(executable).parent), str(path_type(tool["file"]["path"]).parent)]
        if "SystemRoot" in environment:
            path.append(str(path_type(environment["SystemRoot"]) / "System32"))
        environment.update(PATH=";".join(path), TEMP=str(temporary), TMP=str(temporary), VSLANG="1033")
    else:
        environment.update({key: value["environment"][key] for key in
                            ("DEVELOPER_DIR", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET")})
        environment.update(PATH=str(path_type(executable).parent) + ":/usr/bin:/bin", TMPDIR=str(temporary))

    def command(report):
        return [executable, "--source", source, "--build-path", str(profile), "--json", str(output / report),
                "--severity", "info", "--lang", "en", "--worker-timeout-ms", str(LIMITS["worker_timeout_ms"]),
                "--worker-memory-mb", str(LIMITS["worker_memory_mib"]), "--no-analysis-cache"]

    extra = []
    if system == "Darwin":
        extra += ["-isystem", "/usr/include", "-isystem", "/usr/local/include"]
    extra += ["-resource-dir", tool["resource_dir"]]
    if system == "Darwin":
        extra += ["-isysroot", environment["SDKROOT"]]
    closures = {name: {"input_count": len(value["probes"][name]["headers"]),
                       "records_sha256": hashlib.sha256(canonical(value["probes"][name]["headers"]).encode()).hexdigest()}
                for name in ("candidate", "abi")}
    return {
        "source_mapping": mapping,
        "compiler": tool,
        "compilation_database": [{"directory": str(source_root), "file": source,
                                  "arguments": value["probes"]["candidate"]["command"]["argv"]}],
        "header_closures": closures,
        "abi_preflight": {"char_bit": 8, "int_bytes": 4, "size_t_bytes": 8, "pointer_bytes": 8,
                          "malloc_compatible_type": "void *(*)(size_t)",
                          "boundary": "Historical Clang C17 size/prototype assertions and two rejected negatives, not runtime calling ABI, allocator implementation or noninterposition proof."},
        "frontend": {"state": "ADJUSTED_HEADER_CLOSURE_AND_EMBEDDED_FRONTEND_PENDING",
                     "begin_adjusters_in_registration_order": [["-fparse-all-comments"], extra],
                     "argument_handling": "The comment adjuster is registered before the platform adjuster. Each uses BEGIN; this is not a captured final argv and no CDB option deduplication is claimed.",
                     "resource_precondition": "Before analysis, verify the selected resource directory and full referenced native header identities; otherwise the implementation may silently select bundled/build-time fallback headers.",
                     "sdk_precondition": "On macOS, verify SDKROOT alias/resolved SDK identity and the eagerly executed xcrun probe. Explicit SDKROOT does not suppress that subprocess.",
                     "boundary": "Historical external compiler syntax success is not embedded product frontend compatibility or selected-versus-adjusted dependency equivalence."},
        "analyzer": {
            "state": "PREDECLARED_NOT_EXECUTED", "executable": executable, "executable_sha256": None,
            "executable_policy": "FUTURE_U004_CLEAN_RELEASE_SOURCE_TREE_TOOLCHAIN_AND_BINARY_IDENTITY_REQUIRED",
            "cwd": str(profile), "environment": environment, "inherit_environment": False,
            "memory_leak_only": command("memory-leak.json") + ["--disable-rule", GCC_ISOLATED_DISABLED],
            "all_current_rules_including_assumptions": command("all-current-rules.json") + ["--assumptions"],
            "outer_case_timeout_seconds": LIMITS["case_timeout_seconds"], "repetitions": LIMITS["repetitions"],
            "required_conditions": [
                "Only the bound one-command compile_commands.json in the declared profile cwd; no .codeskeptic.conf there.",
                "Verify exact source bytes and all native compiler/resource/SDK/header identities before each invocation; no undeclared environment inheritance.",
                "Recreate an isolated profile/output/tmp and worker state per repetition after retaining prior evidence; existing outputs or caches cannot be reused.",
                "No baseline, custom model/sidecar, checkpoint/resume, suppression or scope-filter inputs. --no-analysis-cache does not disable config discovery.",
                "Keep every raw diagnostic and multiplicity. Reject unmapped source paths rather than discard observations. A missing expected leak remains a miss.",
                "Require complete one-source/one-command coverage. Outer timeout is separate from worker limits; neither is raised on retry.",
            ],
            "new_injection_families": "PLANNED_NOT_IMPLEMENTED_RED_NO_FAKE_CLI_ENABLEMENT_OR_ZERO_FINDING_PASS",
        },
    }


def gcc_platform_recipe_metadata(value, cdb, native, candidate, labels):
    fields(value, "schema state id platform candidate linux_recipe ground_truth ground_truth_index reference "
           "native_evidence compilation_database recipe limits source_label_applicability additional_quota_examples "
           "qualification boundary", "native recipe")
    system = value["platform"]
    require(value["schema"] == "codeskeptic-product-prospective-platform-recipe/v1"
            and value["state"] == "PREDECLARED_NATIVE_RECIPE_NOT_QUALIFIED"
            and value["id"] == candidate["id"] and type(system) is str and system in GCC_PLATFORM_FILES
            and native["native_identity"]["platform"]["system"] == system, "native recipe identity")
    gcc_ground_truth_metadata(labels, candidate)
    cdb_path = GCC_PLATFORM_FILES[system][:-5] + "/compile_commands.json"
    links = {"candidate": GCC_SOURCE_CANDIDATE, "linux_recipe": GCC_CANDIDATE_LINKS["analysis_profile"],
             "ground_truth": GCC_GROUND_TRUTH, "ground_truth_index": GROUND_TRUTH_INDEX,
             "compilation_database": cdb_path}
    for field, path in links.items():
        fields(value[field], "path sha256", "native recipe link")
        require(value[field]["path"] == path, "native recipe linked path")
        external_digest(value[field]["sha256"])
    require(value["linux_recipe"] == candidate["links"]["analysis_profile"], "original Linux recipe changed")
    reference = value["reference"]
    fields(reference, "head files", "native recipe reference")
    require(type(reference["head"]) is str and re.fullmatch(r"[0-9a-f]{40}", reference["head"])
            and type(reference["files"]) is list and len(reference["files"]) == len(GCC_PLATFORM_REFERENCES),
            "native recipe reference coverage")
    for link, path in zip(reference["files"], GCC_PLATFORM_REFERENCES):
        fields(link, "path sha256", "native recipe reference link")
        require(link["path"] == path, "native recipe reference path")
        external_digest(link["sha256"])
    evidence = value["native_evidence"]
    fields(evidence, "state run_id run_attempt producer_source case run", "native recipe evidence")
    require(evidence["state"] == "HISTORICAL_HOSTED_PREFLIGHT_NOT_CURRENT_QUALIFICATION"
            and type(evidence["run_id"]) is int and evidence["run_id"] > 0
            and type(evidence["run_attempt"]) is int and evidence["run_attempt"] == 1
            and evidence["producer_source"] == native["native_identity"]["source"], "native recipe producer")
    for key in ("case", "run"):
        fields(evidence[key], "path sha256", "native recipe external evidence")
        require(nonempty(evidence[key]["path"]), "native recipe external path")
        external_digest(evidence[key]["sha256"])
    expected = gcc_platform_recipe_parts(native)
    expected_cdb = expected.pop("compilation_database")
    require(canonical(cdb) == canonical(expected_cdb) and canonical(value["recipe"]) == canonical(expected),
            "native prospective commands/environment/closure changed")
    validate_limits(value["limits"])
    require(value["source_label_applicability"] == "PENDING_ADDITIVE_PLATFORM_SOURCE_REVIEW"
            and type(value["additional_quota_examples"]) is int and value["additional_quota_examples"] == 0
            and nonempty(value["boundary"]) and len(value["boundary"]) <= 8192, "native recipe limits/boundary")
    fields(value["qualification"], " ".join(GCC_PLATFORM_QUALIFICATION), "native recipe qualification")
    require(all(item is False for item in value["qualification"].values()), "prospective recipe cannot qualify product")
    return {"platform": system, "source_sha256": native["input"]["sha256"], "command_count": len(cdb),
            "candidate_input_count": expected["header_closures"]["candidate"]["input_count"],
            "producer_head": evidence["producer_source"]["head"], "additional_quota_examples": 0,
            **value["qualification"]}


def verify_gcc_platform_recipes(repo):
    """Read historical native evidence and prospective recipes without execution."""
    try:
        import product_identity as identity
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "native recipe checkout root")
        observations = {}

        def read(path, expected=None, external=False, maximum=65536):
            require(not external or (path.is_absolute() and repo not in path.parents), "native evidence must be external")
            info, before, raw = external_read(path, capture=True)
            require(info["size_bytes"] <= maximum and (expected is None or info["sha256"] == expected),
                    "native recipe evidence size/hash")
            if path in observations:
                require(external_identity(observations[path]) == external_identity(before),
                        "native recipe evidence changed between reads")
            observations[path] = before
            return parse_json(raw.decode("utf-8")), info["sha256"]

        original = verify_ground_truth_index(repo)
        results = []
        for system, path in GCC_PLATFORM_FILES.items():
            value, record_sha = read(repo / path)
            linked = {}
            for key in ("candidate", "linux_recipe", "ground_truth", "ground_truth_index", "compilation_database"):
                link = value[key]
                linked[key], _ = read(repo / external_relative(link["path"]), link["sha256"])
            evidence = value["native_evidence"]
            native, _ = read(Path(evidence["case"]["path"]), evidence["case"]["sha256"], True, 4 * 1024 * 1024)
            run, _ = read(Path(evidence["run"]["path"]), evidence["run"]["sha256"], True)
            result = gcc_platform_recipe_metadata(value, linked["compilation_database"], native,
                                                  linked["candidate"], linked["ground_truth"])
            require(result["platform"] == system and result["source_sha256"] == original["source_sha256"]
                    and value["candidate"]["sha256"] == original["candidate_sha256"]
                    and value["ground_truth"]["sha256"] == original["record_sha256"], "native recipe original labels changed")
            source = evidence["producer_source"]
            require(type(run["id"]) is int and run["id"] == evidence["run_id"]
                    and type(run["run_attempt"]) is int and run["run_attempt"] == evidence["run_attempt"]
                    and run["head_sha"] == source["head"] and run["status"] == "completed" and run["conclusion"] == "success"
                    and run["path"] == ".github/workflows/product-identity.yml" and run["event"] == "push"
                    and run["head_branch"] == "agent/cs3-ch08-s01-u003-frozen-product-profiles"
                    and run["repository"]["full_name"] == "tanzercakir-commits/CodeSkeptic", "native recipe hosted run identity")
            environment = native["environment"]
            require(environment["GITHUB_SHA"] == source["head"]
                    and environment["GITHUB_RUN_ID"] == str(run["id"])
                    and environment["GITHUB_RUN_ATTEMPT"] == str(run["run_attempt"]), "native recipe runner identity")
            candidate = linked["candidate"]
            require(native["binding"]["binding_sha256"] == candidate["links"]["source_binding"]["sha256"]
                    and native["binding"]["adjudication_sha256"] == candidate["links"]["source_review"]["sha256"],
                    "native recipe source binding changed")
            producer_files = [{"path": path, "sha256": source[field]} for field, path in identity.SOURCE_FILES.items()]
            producer_files += [{"path": path, "sha256": sha} for path, sha in native["source_files"].items()]
            verify_reviewed_files(repo, source["head"], producer_files, expected_tree=source["tree"])
            verify_reviewed_files(repo, value["reference"]["head"], value["reference"]["files"])
            results.append({**result, "record_sha256": record_sha})
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "native recipe evidence final identity changed")
        return {"recipes": results, "recipe_count": len(results), "unique_source_count": 1,
                "source_selection_quota_examples": original["source_selection_quota_examples"],
                "original_source_labels_independently_reviewed": original["source_labels_independently_reviewed"],
                "additional_quota_examples": 0, **{key: False for key in GCC_PLATFORM_QUALIFICATION}}
    except (ValueError, OSError, TypeError, KeyError, IndexError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError("GCC prospective platform recipes rejected") from None


def adapt_gcc_source(raw):
    """Replay the reviewed line selection; the caller binds input/output hashes."""
    lines = raw.decode("utf-8").splitlines()
    require(len(lines) == 66 and lines[7] == "static int __attribute__((noinline))"
            and ' /* { dg-message' in lines[64], "GCC adaptation structure changed")
    prefix = ["/* Standalone adaptation of GCC malloc-vs-local-3.c: helper and test_2.",
              "   GCC revision: " + GCC_REVISION + " (15.2.0).",
              "   Removed diagnostic instrumentation, unrelated cases, and noinline attribute.",
              "   Standard-library declarations come from the native stdlib.h.",
              "   Candidate only: source label, independence, licensing and freeze pending. */"]
    selected = [lines[2], "", "static int", *lines[8:12], "", *lines[47:58],
                *lines[60:62], lines[64].split(' /* { dg-message', 1)[0], lines[65]]
    return ("\n".join(prefix + selected) + "\n").encode("utf-8")


def fetch_gcc_input(relative, row):
    """Explicit, size/hash-bound fetch from one revision; never follow redirects."""
    require(relative in GCC_INPUTS and type(row["size_bytes"]) is int
            and 0 < row["size_bytes"] <= 16 * 1024 * 1024, "GCC input selection/size")
    external_digest(row["sha256"])
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    url = "https://raw.githubusercontent.com/gcc-mirror/gcc/" + GCC_REVISION + "/" + GCC_INPUTS[relative]
    with urllib.request.build_opener(NoRedirect()).open(url, timeout=30) as response:
        require(response.status == 200, "GCC input HTTP status")
        raw = response.read(row["size_bytes"] + 1)
    require(len(raw) == row["size_bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
            "GCC input bytes changed")
    return raw


def gcc_stage_failure(error, phase):
    """Locate a failed guard using public code positions, without exception text."""
    admitted = {"destination", "binding", "adaptation", "write", "verification",
                "download-0", "download-1", "download-2", "download-3"}
    phase = phase if phase in admitted else "unknown"
    line, identity, seen = 0, "", set()
    while error is not None and id(error) not in seen and len(seen) < 8:
        seen.add(id(error))
        trace = error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code.co_filename == __file__:
                line = trace.tb_lineno
            trace = trace.tb_next
        if isinstance(error, ExternalIdentityError) and error.phase in ("descriptor-open", "descriptor-final"):
            identity = "; identity=" + error.phase + ":" + ",".join(error.changed_fields)
        error = error.__context__
    return ("GCC staging rejected at " + phase + "; profile-check=" + str(line) + identity
            + "; a newly created partial destination may remain")


def stage_gcc_inputs(repo, destination):
    """Materialize only the reviewed candidate, lineage and notices outside Git.

    All upstream bytes are checked before creating the new destination. Failure
    after creation may leave that owned partial directory; nothing is overwritten
    or recursively removed. Staging does not resolve the pending rights gate.
    """
    phase = "destination"
    try:
        repo, destination = Path(repo), Path(destination)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo and repo.is_dir(), "GCC checkout root")
        require(destination.is_absolute() and destination.parent.resolve(strict=True) == destination.parent
                and destination.parent.is_dir() and not destination.exists() and not destination.is_symlink()
                and repo != destination and repo not in destination.parents and destination not in repo.parents,
                "GCC staging destination must be new and external")
        phase = "binding"
        binding = read_json(repo / GCC_BINDING)
        rows = binding["inputs"]
        require(type(rows) is list and len(rows) == 5
                and {row["path"] for row in rows} == set(GCC_INPUTS) | {"case.c"}, "GCC input closure changed")
        payloads = {}
        for number, row in enumerate(row for row in rows if row["path"] != "case.c"):
            phase = "download-" + str(number)
            payloads[row["path"]] = fetch_gcc_input(row["path"], row)
        phase = "adaptation"
        payloads["case.c"] = adapt_gcc_source(payloads["origin/malloc-vs-local-3.c"])
        for row in rows:
            require(len(payloads[row["path"]]) == row["size_bytes"]
                    and hashlib.sha256(payloads[row["path"]]).hexdigest() == row["sha256"], "GCC staged bytes differ")
        phase = "write"
        destination.mkdir()
        for name, payload in payloads.items():
            path = destination / external_relative(name)
            path.parent.mkdir(exist_ok=True)
            with path.open("xb") as stream:
                stream.write(payload)
        phase = "verification"
        return verify_external_inputs(repo / GCC_BINDING, repo, destination)
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError) as error:
        raise ValueError(gcc_stage_failure(error, phase)) from None


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


# Prospective role constraints, not native-header authentication or analyzer models.
NATIVE_SOURCE_CORE = {
    "entry.argv": ["main argv", "entry-argument-content", None, None, 1, "int", ["int", "char**"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.getenv": ["getenv", "returned-content", "stdlib.h", None, None, "char*", ["const char*"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.fgets": ["fgets", "output-buffer", "stdio.h", 0, None, "char*", ["char*", "int", "FILE*"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.fread": ["fread", "output-buffer", "stdio.h", 0, None, "size_t", ["void*", "size_t", "size_t", "FILE*"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "posix.read": ["read", "output-buffer", "unistd.h", 1, None, "ssize_t", ["int", "void*", "size_t"], False, ["linux-x86_64", "macos-arm64"]],
    "ucrt._read": ["_read", "output-buffer", "io.h", 1, None, "int", ["int", "void*", "unsigned int"], False, ["windows-x64"]],
    "posix.recv": ["recv", "output-buffer", "sys/socket.h", 1, None, "ssize_t", ["int", "void*", "size_t", "int"], False, ["linux-x86_64", "macos-arm64"]],
    "winsock.recv": ["recv", "output-buffer", "winsock2.h", 1, None, "int", ["SOCKET", "char*", "int", "int"], False, ["windows-x64"]],
}

NATIVE_SINK_CORE = {
    "c.printf": ["format-string", "printf", "stdio.h", 0, "int", ["const char*"], True, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.fprintf": ["format-string", "fprintf", "stdio.h", 1, "int", ["FILE*", "const char*"], True, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.sprintf": ["format-string", "sprintf", "stdio.h", 1, "int", ["char*", "const char*"], True, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.snprintf": ["format-string", "snprintf", "stdio.h", 2, "int", ["char*", "size_t", "const char*"], True, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.system": ["command-injection", "system", "stdlib.h", 0, "int", ["const char*"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "posix.popen": ["command-injection", "popen", "stdio.h", 0, "FILE*", ["const char*", "const char*"], False, ["linux-x86_64", "macos-arm64"]],
    "ucrt._popen": ["command-injection", "_popen", "stdio.h", 0, "FILE*", ["const char*", "const char*"], False, ["windows-x64"]],
    "sqlite.exec": ["sql-injection", "sqlite3_exec", "sqlite3.h", 1, "int", ["sqlite3*", "const char*", "int(*)(void*,int,char**,char**)", "void*", "char**"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "sqlite.prepare_v2": ["sql-injection", "sqlite3_prepare_v2", "sqlite3.h", 1, "int", ["sqlite3*", "const char*", "int", "sqlite3_stmt**", "const char**"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "sqlite.prepare_v3": ["sql-injection", "sqlite3_prepare_v3", "sqlite3.h", 1, "int", ["sqlite3*", "const char*", "int", "unsigned int", "sqlite3_stmt**", "const char**"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "c.fopen": ["path-traversal", "fopen", "stdio.h", 0, "FILE*", ["const char*", "const char*"], False, ["linux-x86_64", "windows-x64", "macos-arm64"]],
    "posix.open": ["path-traversal", "open", "fcntl.h", 0, "int", ["const char*", "int"], True, ["linux-x86_64", "macos-arm64"]],
    "posix.openat": ["path-traversal", "openat", "fcntl.h", 1, "int", ["int", "const char*", "int"], True, ["linux-x86_64", "macos-arm64"]],
    "ucrt._open": ["path-traversal", "_open", "io.h", 0, "int", ["const char*", "int"], True, ["windows-x64"]],
}

NATIVE_BOUNDARY_LISTS = {
    "flow.required_behaviors": ["local assignment and complete overwrite", "branch joins preserving origin alternatives", "alias-aware current object/version", "byte-region copy and concatenation", "partial buffer mutation and termination", "direct same-TU parameter/return/output-buffer/sink summaries", "category-specific validation on the checked branch and value"],
    "flow.states": ["CONSTANT", "EXPLICITLY_TRUSTED", "UNTRUSTED", "UNKNOWN"],
    "flow.excluded_helpers": ["recursive", "mutually-recursive", "indirect", "virtual", "external-TU", "persisted string summaries", "arbitrary heap/field/container graph"],
    "flow.trace_required": ["source location and model", "propagation locations and consumed byte/value relation", "caller and callee locations for summaries", "sink location and exact argument", "validation context or explicit unsupported reason"],
    "declaration_identity.required_evidence": ["platform/library version", "resolved canonical declaration and linkage", "complete target-resolved signature and variadic arity", "actual defining header path and content digest", "included header closure and compilation-command identity", "no conflicting user implementation or unsupported interposition"],
    "category_validation.shared.required_binding": ["category", "platform and exact grammar/context", "checked object/version", "successful branch/result", "consuming sink"],
    "category_validation.path-traversal.required_boundaries": ["absolute path", "parent components", "prefix collision", "separator and platform differences", "canonicalization failure", "ignored check result", "post-check mutation", "symlink/TOCTOU not proven"],
    "required_negative_classes": ["fake same-name/signature API", "wrong argument position", "trusted nonliteral input", "unknown source", "partial or failed output mutation", "ignored/failed validation", "post-validation mutation", "validation on only one branch", "unsupported helper target", "flow budget exhaustion", "cross-category sanitizer reuse", "cross-platform quoting or path reuse"],
}

NATIVE_BOUNDARY_VALUES = {
    "qualification": {"installed": False, "native_headers_verified": False, "corpus_accepted": False, "measurements_performed": False},
    "declaration_identity": {"name_only_allowed": False, "system_header_marker_alone_allowed": False, "user_body_may_inherit_native_model": False, "invented_forward_declaration_allowed": False},
    "flow": {"unknown_is_safe": False, "unknown_mutation_preserves_validation": False, "existing_integer_or_nullness_domain_is_string_origin": False},
    "category_validation.shared": {"generic_sanitizer_allowed": False, "mutation_invalidates": True, "ignored_or_failed_result_validates": False, "one_branch_validates_join": False},
    "category_validation.format-string": {"nonliteral_alone_is_defect": False},
    "category_validation.command-injection": {"generic_quoting_allowed": False, "separate_argv_is_automatic_shell_injection": False},
    "category_validation.sql-injection": {"prepare_sanitizes_constructed_query": False, "bind_sanitizes_original_source": False, "sql_argument_index": 1, "bind_value_argument_index": 2, "sql_parameter_index_base": 1},
    "category_validation.path-traversal": {"explicit_root_policy_required": True, "user_filename_alone_is_defect": False, "canonicalization_alone_is_containment": False, "string_prefix_alone_is_containment": False, "symlink_or_toctou_guarantee": False},
}

def native_api_metadata(model):
    """Check draft role/shape consistency, never source semantics or actual ABI."""
    fields(model, "schema state argument_indexing boundary qualification references reference_boundary "
           "declaration_identity flow sources sinks category_validation required_negative_classes "
           "selection_gaps no_hidden_scope_extension", "native API model")
    require(model["schema"] == "codeskeptic-product-native-api-models/v1"
            and model["state"] == "DRAFT_NOT_FROZEN"
            and model["argument_indexing"] == "zero-based-call-arguments-not-SQL-parameter-numbers",
            "native API draft identity")
    for key in ("boundary", "reference_boundary", "no_hidden_scope_extension"):
        require(nonempty(model[key]), "native API boundary")
    fields(model["qualification"], "installed native_headers_verified corpus_accepted measurements_performed",
           "native API qualification")
    fields(model["declaration_identity"], "name_only_allowed system_header_marker_alone_allowed "
           "user_body_may_inherit_native_model invented_forward_declaration_allowed required_evidence "
           "alias_boundary native_header_inventory_state entry_boundary", "native declaration identity")
    require(model["declaration_identity"]["native_header_inventory_state"] ==
            "PENDING_ACTUAL_THREE_PLATFORM_CAPTURE", "native header identity not yet realized")
    for key in ("alias_boundary", "entry_boundary"):
        require(nonempty(model["declaration_identity"][key]), "native declaration boundary")
    flow = model["flow"]
    fields(flow, "limits required_behaviors states unknown_is_safe unknown_mutation_preserves_validation "
           "existing_integer_or_nullness_domain_is_string_origin identity overwrite_boundary formatting_boundary "
           "helper_boundary excluded_helpers budget_exhaustion trace_required output_boundary", "native string flow")
    require(canonical(flow["limits"]) == canonical({
        "call_depth": LIMITS["string_flow_call_depth_max"],
        "states_per_function": LIMITS["string_flow_states_per_function_max"],
        "transfer_steps_per_function": LIMITS["string_flow_transfer_steps_per_function_max"]}),
        "native flow budget changed")
    require(flow["budget_exhaustion"] == "INCOMPLETE_NOT_SAFE", "budget failure cannot become safe")
    for key in ("identity", "overwrite_boundary", "formatting_boundary", "helper_boundary", "output_boundary"):
        require(nonempty(flow[key]), "native flow boundary")
    references = model["references"]
    require(type(references) is dict and 1 <= len(references) <= 64
            and all(nonempty(key) and type(url) is str and url.startswith("https://")
                    for key, url in references.items()), "native API documentation references")

    def texts(values, what):
        require(type(values) is list and values and all(nonempty(value) for value in values)
                and len(values) == len(set(values)), what)

    def refs(values):
        texts(values, "native API row references")
        require(all(value in references for value in values), "unknown native API reference")

    for group, pins in (("sources", NATIVE_SOURCE_CORE), ("sinks", NATIVE_SINK_CORE)):
        rows = model[group]
        require(type(rows) is list and len(rows) == len(pins), "native API table membership")
        names = []
        for row in rows:
            extra = ("kind output_argument entry_argument_index success extent failure" if group == "sources"
                     else "family argument_index")
            fields(row, "id symbol header signature platforms references " + extra, "native API row")
            name = row["id"]
            require(type(name) is str and name in pins, "native API row identity")
            names.append(name)
            signature = row["signature"]
            fields(signature, "result parameters variadic", "native API signature")
            if group == "sources":
                prefix = [row["symbol"], row["kind"], row["header"],
                          row["output_argument"], row["entry_argument_index"]]
                for key in ("success", "extent", "failure"):
                    require(nonempty(row[key]), "native source success/extent/failure boundary")
            else:
                prefix = [row["family"], row["symbol"], row["header"], row["argument_index"]]
            core = prefix + [signature["result"], signature["parameters"], signature["variadic"], row["platforms"]]
            require(canonical(core) == canonical(pins[name]), "native API role/signature/platform changed")
            refs(row["references"])
        require(names == list(pins), "duplicate/missing/reordered native APIs")

    validation = model["category_validation"]
    fields(validation, "shared format-string command-injection sql-injection path-traversal",
           "category-specific validation")
    fields(validation["shared"], "generic_sanitizer_allowed required_binding mutation_invalidates "
           "ignored_or_failed_result_validates one_branch_validates_join", "validation binding")
    fields(validation["format-string"], "nonliteral_alone_is_defect condition safe_controls unmodeled",
           "format-string boundary")
    fields(validation["command-injection"], "generic_quoting_allowed separate_argv_is_automatic_shell_injection "
           "condition platform_boundary safe_controls unmodeled", "command-injection boundary")
    fields(validation["sql-injection"], "database prepare_sanitizes_constructed_query bind_sanitizes_original_source "
           "sql_argument_index bind_value_argument_index sql_parameter_index_base condition safe_controls boundary "
           "references", "SQLite boundary")
    fields(validation["path-traversal"], "explicit_root_policy_required user_filename_alone_is_defect "
           "canonicalization_alone_is_containment string_prefix_alone_is_containment symlink_or_toctou_guarantee "
           "condition safe_controls required_boundaries references", "restricted-root boundary")
    require(validation["sql-injection"]["database"] == "SQLite UTF-8 SQL text only", "SQLite-only native profile")
    for name in ("format-string", "command-injection", "sql-injection", "path-traversal"):
        require(nonempty(validation[name]["condition"]), "category-specific condition")
        texts(validation[name]["safe_controls"], "category-specific safe controls")
    for name, key in (("format-string", "unmodeled"), ("command-injection", "unmodeled"),
                      ("command-injection", "platform_boundary"), ("sql-injection", "boundary")):
        require(nonempty(validation[name][key]), "category-specific model boundary")
    for name in ("sql-injection", "path-traversal"):
        refs(validation[name]["references"])

    def at(path):
        value = model
        for part in path.split("."):
            require(type(value) is dict and part in value, "missing native model boundary")
            value = value[part]
        return value

    for path, expected in NATIVE_BOUNDARY_LISTS.items():
        require(canonical(at(path)) == canonical(expected), "native model coverage boundary changed")
    for path, expected in NATIVE_BOUNDARY_VALUES.items():
        actual = at(path)
        require(canonical({key: actual[key] for key in expected}) == canonical(expected),
                "native model trust boundary changed")
    texts(model["selection_gaps"], "native API selection gaps")
    return {"state": model["state"], "sources": len(model["sources"]), "sinks": len(model["sinks"]),
            "families": sorted({row["family"] for row in model["sinks"]}),
            "installed": False, "native_headers_verified": False, "product_qualified": False,
            "metadata_only": True}


def source_metadata(manifest):
    require(type(manifest) is dict, "profile manifest")
    version2 = manifest.get("schema") == "codeskeptic-product-profiles/v2"
    fields(manifest, "schema state selection_base limits projects historical_index historical_index_sha256 "
           "evaluation_state independent_quota_examples native_environment_state native_api_model "
           "native_api_model_sha256 boundary" + (" source_selection" if version2 else ""), "profile manifest")
    require(manifest["schema"] in ("codeskeptic-product-profiles/v1", "codeskeptic-product-profiles/v2")
            and manifest["selection_base"] == "de642695c96224ab11c5add000c7ad9c996d0a50"
            and nonempty(manifest["boundary"]), "profile source identity")
    if version2:
        fields(manifest["source_selection"], "path sha256", "profile source selection")
        require(manifest["source_selection"]["path"] == SOURCE_SELECTION, "profile source selection path")
        external_digest(manifest["source_selection"]["sha256"])
    require(manifest["historical_index"] == "tests/product_corpus/historical/measurement-index.json"
            and type(manifest["historical_index_sha256"]) is str
            and SHA.fullmatch(manifest["historical_index_sha256"])
            and manifest["historical_index_sha256"] != "0" * 64,
            "historical index path/digest linkage")
    require(manifest["native_api_model"] == "tests/product_corpus/native-api-models.json"
            and type(manifest["native_api_model_sha256"]) is str
            and SHA.fullmatch(manifest["native_api_model_sha256"])
            and manifest["native_api_model_sha256"] != "0" * 64,
            "native API model path/digest linkage")
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


def linked_native_api_model(manifest, root):
    """Read the selected draft API bytes; do not authenticate actual native APIs."""
    source_metadata(manifest)
    path = Path(root) / manifest["native_api_model"]
    require(file_sha(path) == manifest["native_api_model_sha256"], "native API model digest mismatch")
    model = read_json(path)
    native_api_metadata(model)
    return model


def draft_readiness(manifest, root=None):
    metadata = source_metadata(manifest)
    version2 = manifest["schema"] == "codeskeptic-product-profiles/v2"
    evaluation = "PARTIAL_INDEPENDENT_SOURCE_SELECTION_NOT_FROZEN" if version2 else "SELECTION_AND_INDEPENDENT_LABEL_REVIEW_PENDING"
    environment = "PARTIAL_NATIVE_OBSERVATIONS_NOT_FINAL_PROFILE" if version2 else "PROSPECTIVE_REQUIREMENTS_ONLY_ACTUAL_IDENTITY_CAPTURE_PENDING"
    require(manifest["state"] == "DRAFT_NOT_FROZEN"
            and manifest["evaluation_state"] == evaluation
            and type(manifest["independent_quota_examples"]) is int
            and (0 <= manifest["independent_quota_examples"] <= 10000 if version2 else manifest["independent_quota_examples"] == 0)
            and manifest["native_environment_state"] == environment
            and all(project["measurement_state"] == "NOT_CONFIGURED_NOT_MEASURED" for project in manifest["projects"]),
            "draft cannot fabricate completed source/corpus/environment qualification")
    selected = None
    if version2:
        require(root is not None, "v2 readiness requires actual selected-source evidence")
        selected = verify_source_selection(root, manifest["source_selection"])
        require(manifest["independent_quota_examples"] == selected["quota_examples"], "declared source count differs from reviewed evidence")
    result = {"state": manifest["state"], "task_ready": False, "product_qualified": False,
            "source_metadata": metadata, "independent_quota_examples": selected["quota_examples"] if selected else 0,
            "gaps": ["independent evaluation selection and source-label review incomplete" if version2 else
                     "independent evaluation selection and source-label review missing",
                     "1020 independent quota sources and three origins per bucket not established",
                     "required supplemental source-attributed security-fix pair review incomplete",
                     "native API draft lacks actual header/ABI and complete per-case model qualification",
                     "final native analysis profiles and all-rule ground truth pending" if version2 else
                     "prospective native environment realization and exact identity capture pending"],
            "boundary": "An honest incomplete draft, not an activated evaluation freeze or permission to skip FRONT."}
    if selected is not None:
        result["source_selection"] = selected
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("historical-check", "limits", "sources-check", "api-check", "readiness", "external-source-check", "stage-gcc-inputs", "license-basis-check", "source-candidate-check", "selection-check", "ground-truth-candidate-check", "ground-truth-check", "platform-recipes-check"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--historical-sources", type=Path, default=Path(
        "/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S04-U001/corpus-diagnostic-comparison"))
    parser.add_argument("--binding", type=Path, help="tracked binding manifest (absolute path)")
    parser.add_argument("--external-root", type=Path, help="explicit external snapshot root (absolute canonical path)")
    parser.add_argument("--evidence-root", type=Path, help="explicit external license-reference directory")
    args = parser.parse_args()
    try:
        if args.command == "selection-check":
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "reviewed selection uses its explicit tracked roots")
        if args.command == "platform-recipes-check":
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "native recipes use their fixed tracked roots")
            result = verify_gcc_platform_recipes(args.root)
        elif args.command in ("ground-truth-candidate-check", "ground-truth-check"):
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "all-rule source labels use their fixed tracked roots")
            result = (verify_gcc_ground_truth(args.root) if args.command == "ground-truth-candidate-check"
                      else verify_ground_truth_index(args.root))
        elif args.command == "source-candidate-check":
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "source candidate uses its explicit tracked roots")
            result = verify_gcc_source_candidate(args.root)
        elif args.command == "license-basis-check":
            require(args.binding is None, "GCC licensing uses its fixed tracked binding")
            result = verify_gcc_license_basis(args.root, args.evidence_root, args.external_root)
        elif args.command == "stage-gcc-inputs":
            require(args.binding is None, "GCC staging uses its fixed tracked binding")
            result = stage_gcc_inputs(args.root, args.external_root)
        elif args.command == "external-source-check":
            result = verify_external_inputs(args.binding, args.root, args.external_root)
        elif args.command == "limits":
            result = {"limits": validate_limits(LIMITS), "measured": False,
                      "boundary": "Prospective limits only; not environment realization, dataset freeze or product PASS."}
        else:
            manifest = read_json(args.root / "scripts/product_profiles.json")
            index = linked_historical_index(manifest, args.root)
            model = linked_native_api_model(manifest, args.root)
            if args.command == "historical-check":
                result = verify_historical(index, args.root, args.historical_sources)
            elif args.command == "sources-check":
                result = verify_sources(manifest)
            elif args.command == "api-check":
                result = native_api_metadata(model)
            else:
                result = draft_readiness(manifest, args.root)
                if args.command == "selection-check":
                    require(manifest["schema"] == "codeskeptic-product-profiles/v2", "selection check requires profiles v2")
                    result = result["source_selection"]
        print(canonical(result), end="")
        if args.command == "readiness" and not result["task_ready"]:
            return 2
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as error:
        print(f"PRODUCT_PROFILE_FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
