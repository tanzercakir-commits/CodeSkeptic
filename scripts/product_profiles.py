#!/usr/bin/env python3
"""Prospective product-profile accounting, never a quality verdict.

Quota arithmetic authenticates neither source provenance nor semantic sample
independence. Exact source/label review, content hashing and complete corpus
selection remain separate gates. Checks are read-only. Only the explicit
stage-gcc-inputs command downloads four pinned ordinary GCC inputs into a new
external directory. No execution, rebaseline or pin refresh is performed here.
"""
import argparse
import base64
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
from urllib.parse import quote

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


def remember_input_identities(guard, files, directories=None):
    """Private read-transaction guard; never part of JSON evidence output."""
    if guard is None:
        return
    identities = {path: external_identity(info) for path, info in files.items()}
    identities.update(directories or {})
    for path, identity in identities.items():
        require(path not in guard or guard[path] == identity, 'earlier input identity changed')
        guard[path] = identity


def verify_input_identities(guard):
    for path, identity in guard.items():
        require(path.resolve(strict=True) == path and external_identity(path.lstat()) == identity,
                'transitive input identity changed')


RETAINED_GITHUB_INPUTS = 'codeskeptic-product-retained-github-inputs/v1'


def retained_github_evidence(review, rows, captured):
    """Check retained metadata consistency, not upstream authentication or labels.

    Extraction descriptions are linked to the reviewed bytes, not executed or
    mechanically certified equivalent. Semantic comparison is never lineage.
    """
    origin = review['origin']
    repository = origin['repository']
    require(type(repository) is str and re.fullmatch(
        r'https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',
        repository) and not repository.endswith('.git'), 'retained repository identity')
    revision = origin['revision']
    require(type(revision) is str and re.fullmatch(r'[0-9a-f]{40}', revision)
            and revision != '0' * 40
            and origin['source_specific_genetic_lineage_established'] is False
            and origin['tag_signature_authenticated'] is False, 'retained history boundary')
    # This is an upstream Git path used only in metadata/URL comparison, never
    # opened locally. Preserve the stricter portable external_relative policy.
    upstream_path = origin['path']
    require(type(upstream_path) is str and 0 < len(upstream_path) <= 512
            and len(upstream_path.split('/')) <= 16
            and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', part)
                    and not part.endswith('.') for part in upstream_path.split('/')),
            'retained upstream path')
    original = captured['origin']
    blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
    require(origin['git_blob'] == blob, 'retained origin blob')
    api = parse_json(captured['provenance'].decode('utf-8'))
    url = ('https://api.github.com/repos/' + repository.removeprefix('https://github.com/')
           + '/contents/' + quote(upstream_path, safe='/') + '?ref=' + revision)
    require(type(api) is dict and api['type'] == 'file' and api['encoding'] == 'base64'
            and api['path'] == upstream_path and api['sha'] == blob
            and type(api['size']) is int and api['size'] == len(original)
            and api['url'] == url and type(api['content']) is str, 'retained metadata identity')
    require(base64.b64decode(''.join(api['content'].split()), validate=True) == original,
            'retained metadata content')
    extraction = parse_json(captured['extraction'].decode('utf-8'))
    fields(extraction, 'schema source_sha256 origin_sha256 lines adaptation equivalence', 'retained extraction')
    require(extraction['schema'] == 'codeskeptic-reviewed-extraction-description/v1'
            and extraction['source_sha256'] == review['source']['sha256']
            and extraction['origin_sha256'] == origin['sha256']
            and extraction['adaptation'] == review['source']['adaptation']
            and nonempty(extraction['adaptation']) and len(extraction['adaptation']) <= 8192
            and extraction['equivalence'] == 'INDEPENDENT_REVIEW_REQUIRED_NOT_EXECUTED',
            'retained extraction linkage')
    ranges = extraction['lines']
    require(type(ranges) is list and 1 <= len(ranges) <= 64
            and canonical(ranges) == canonical(origin['lines']),
            'retained selected ranges')
    last, line_count = 0, len(original.decode('utf-8').splitlines())
    for pair in ranges:
        require(type(pair) is list and len(pair) == 2 and all(type(n) is int for n in pair)
                and last < pair[0] <= pair[1] <= line_count, 'retained range bounds/order')
        last = pair[1]
    comparison = next(row for row in rows if row['role'] == 'semantic-comparison')
    require(review['independence']['same_cluster_comparison']['sha256'] == comparison['sha256'],
            'retained reviewed comparison bytes')


def verify_external_inputs(binding_path, repo, source_root, *, _input_guard=None):
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
        retained = type(manifest) is dict and manifest.get('schema') == RETAINED_GITHUB_INPUTS
        fields(manifest, "schema state id adjudication inputs" + (' genetic_history' if retained else ''),
               "external binding")
        require(manifest["schema"] in ("codeskeptic-product-external-inputs/v1", RETAINED_GITHUB_INPUTS)
                and manifest["state"] == "SOURCE_BINDING_ONLY_NOT_FROZEN"
                and type(manifest["id"]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", manifest["id"]),
                "external binding identity/state")
        if retained:
            require(manifest['genetic_history'] == 'UNKNOWN_NOT_ASSERTED', 'retained history claim')
        link = manifest["adjudication"]
        fields(link, "path sha256", "external adjudication")
        review_path = repo / external_relative(link["path"])
        external_digest(link["sha256"])
        review_hash, review_info, raw = external_read(review_path, capture=True)
        require(review_hash["sha256"] == link["sha256"], "external adjudication changed")
        review = parse_json(raw.decode("utf-8"))
        rows = manifest["inputs"]
        require(type(rows) is list and (6 if retained else 4) <= len(rows) <= 64, "external input inventory size")
        expected, roles, names, total = {}, Counter(), [], 0
        allowed_roles = (('candidate', 'origin', 'provenance', 'extraction', 'semantic-comparison', 'notice')
                         if retained else ('candidate', 'origin', 'lineage', 'notice'))
        for row in rows:
            fields(row, "role path size_bytes sha256", "external input")
            require(type(row["role"]) is str and row["role"] in allowed_roles,
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
                and roles["notice"] >= 1, "external inventory ordering/roles/budget")
        require((roles['provenance'] == roles['extraction'] == roles['semantic-comparison'] == 1)
                if retained else roles['lineage'] >= 1, 'external evidence roles')
        for path in expected:
            require(not any(parent in expected for parent in path.parents), "external file/directory collision")
        require(type(review) is dict and review["id"] == manifest["id"], "external review case identity")
        for role, field in (("candidate", "source"), ("origin", "origin")):
            require(type(review[field]) is dict and review[field]["sha256"] ==
                    next(row["sha256"] for row in rows if row["role"] == role), "external reviewed bytes mismatch")
        before_tree = external_tree(root, expected)
        files, inodes, captured = {binding_path: binding_info, review_path: review_info}, set(), {}
        for path, row in expected.items():
            capture = retained and row['role'] in ('origin', 'provenance', 'extraction')
            actual, info, raw = external_read(path, capture=capture)
            require(actual == {key: row[key] for key in ("size_bytes", "sha256")}, "external source changed")
            require((info.st_dev, info.st_ino) not in inodes, "external duplicate inode")
            inodes.add((info.st_dev, info.st_ino))
            files[path] = info
            if capture:
                captured[row['role']] = raw
        if retained:
            retained_github_evidence(review, rows, captured)
        require(external_tree(root, expected) == before_tree, "external tree changed")
        for path, before in files.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "external final identity changed")
        remember_input_identities(_input_guard, files, before_tree)
        result = {"schema": "codeskeptic-product-external-input-check/v1", "id": manifest["id"],
                "binding_sha256": binding_hash["sha256"], "adjudication_sha256": review_hash["sha256"],
                "source_bytes_verified": True, "verified_inputs": len(rows), "verified_bytes": total,
                "independent_quota_examples": 0, "task_ready": False, "product_qualified": False,
                "native_commands_bound": False, "license_qualified": False,
                "state": "SOURCE_BINDING_ONLY_NOT_FROZEN"}
        if retained:
            result.update(schema='codeskeptic-product-retained-github-input-check/v1',
                          genetic_lineage_established=False, upstream_authenticated=False,
                          extraction_equivalence_verified=False, semantic_independence_verified=False)
        return result
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


def verify_gcc_license_basis(repo, evidence_root, source_root, *, _input_guard=None):
    """Bind actual references to the unchanged source snapshot; never download."""
    try:
        guard = {} if _input_guard is None else _input_guard
        repo, root = Path(repo), Path(evidence_root)
        require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir()
                and root != repo and repo not in root.parents and root not in repo.parents,
                "GCC license evidence root")
        path = repo / GCC_LICENSE_BASIS
        actual, info, raw = external_read(path, capture=True)
        value = parse_json(raw.decode("utf-8"))
        result = gcc_license_metadata(value)
        binding = verify_external_inputs(repo / GCC_BINDING, repo, source_root, _input_guard=guard)
        require(binding['schema'] == 'codeskeptic-product-external-input-check/v1'
                and binding["binding_sha256"] == value["source_binding"]["sha256"], "GCC license binding drift")
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
        remember_input_identities(guard, observations)
        verify_input_identities(guard)
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


def verify_gcc_source_candidate(repo, *, _input_guard=None):
    """Verify actual proposed inputs and predeclared recipe; do not run/admit it."""
    try:
        guard = {} if _input_guard is None else _input_guard
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
        licensing = verify_gcc_license_basis(repo, value["license_evidence_root"], value["source"]["snapshot_root"],
                                            _input_guard=guard)
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
        remember_input_identities(guard, observations)
        verify_input_identities(guard)
        return {"candidate_sha256": candidate_sha, "projection": projection,
                "linked_evidence_files": len(observations), "source_bytes_verified": True,
                "pre_result_recipe_bound": True, "fresh_independent_admission_required": True,
                "independent_quota_examples": 0, "task_ready": False, "product_qualified": False}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, IndexError):
        raise ValueError("source candidate binding rejected") from None


RETAINED_CANDIDATE = 'codeskeptic-product-retained-source-candidate/v1'
SOURCE_QUALIFICATION = ('evaluation_frozen native_product_qualified license_qualified '
                        'redistribution_approved analyzer_run task_ready product_qualified')


def empty_native_stream(path):
    """Only a declared empty compiler stream; source readers still reject empties."""
    require(path.is_absolute() and path.suffix in ('.stdout', '.stderr')
            and path.resolve(strict=True) == path, 'native empty stream path')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 0,
            'native empty stream identity')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                         | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(descriptor)
        check_external_identity(opened, before, 'native-stream-open', cross_query=True)
        require(os.read(descriptor, 1) == b'', 'native empty stream grew')
        final = os.fstat(descriptor)
        check_external_identity(final, opened, 'native-stream-final')
        check_external_identity(final, before, 'native-stream-final', cross_query=True)
        require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                'native empty stream changed')
    finally:
        os.close(descriptor)
    return before


def retained_candidate_metadata(value):
    """Ordinary C17 retained-source proposal; source labels still need ADMIT."""
    fields(value, 'schema state id family subprofile role selection origin origin_repository cluster source '
           'links analysis_selection limits expected boundaries qualification', 'retained candidate')
    require(value['schema'] == RETAINED_CANDIDATE
            and value['state'] == 'PRE_RESULT_SOURCE_SELECTION_FOR_REVIEW'
            and value['selection'] == 'independent-evaluation', 'retained candidate state')
    for key in ('id', 'origin', 'cluster'):
        require(type(value[key]) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,127}', value[key]),
                'retained candidate identifier')
    require(type(value['analysis_selection']) is str
            and re.fullmatch(r'[a-z][a-z0-9_-]{0,127}', value['analysis_selection']),
            'retained analysis selection')
    # The four new families require additional native API/security-fix-pair
    # evidence; an ordinary retained regression cannot silently satisfy it.
    require(type(value['family']) is str
            and value['family'] in FAMILIES - {'command-injection', 'path-traversal', 'sql-injection', 'format-string'}
            and value['role'] in ('buggy', 'safe')
            and (value['subprofile'] in ('cwe-121', 'cwe-122') if value['family'] == 'bounds'
                 else value['subprofile'] is None), 'retained ordinary source family')
    require(type(value['origin_repository']) is str and re.fullmatch(
        r'https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',
        value['origin_repository']) and not value['origin_repository'].endswith('.git'), 'retained origin URL')
    source = value['source']
    fields(source, 'path sha256 language snapshot_root', 'retained candidate source')
    require(source['path'] == '/input/case.c' and source['language'] == 'C17'
            and nonempty(source['snapshot_root']), 'retained candidate source selection')
    external_digest(source['sha256'])
    fields(value['links'], ' '.join(GCC_CANDIDATE_LINKS), 'retained candidate links')
    paths = []
    for link in value['links'].values():
        fields(link, 'path sha256', 'retained candidate link')
        relative = external_relative(link['path']).as_posix()
        require(relative.startswith('tests/product_corpus/candidates/'), 'retained candidate link scope')
        external_digest(link['sha256'])
        paths.append(relative.casefold())
    require(len(set(paths)) == len(paths), 'duplicate retained candidate link')
    validate_limits(value['limits'])
    expected = value['expected']
    require(type(expected) is list and len(expected) <= 64
            and bool(expected) == (value['role'] == 'buggy'), 'retained source expectations')
    for row in expected:
        fields(row, 'rule function line column cwes multiplicity', 'retained expected occurrence')
        require(nonempty(row['rule']) and nonempty(row['function'])
                and all(type(row[key]) is int and 1 <= row[key] <= 1000000
                        for key in ('line', 'column', 'multiplicity'))
                and type(row['cwes']) is list and 1 <= len(row['cwes']) <= 26
                and all(type(cwe) is int and 1 <= cwe <= 10000 for cwe in row['cwes'])
                and row['cwes'] == sorted(set(row['cwes'])), 'retained occurrence fields')
    fields(value['boundaries'], 'allocation independence addressability all_rule_ground_truth platforms measurement rights',
           'retained candidate boundaries')
    require(all(nonempty(item) and len(item) <= 8192 for item in value['boundaries'].values()),
            'retained candidate boundary')
    fields(value['qualification'], SOURCE_QUALIFICATION, 'retained candidate qualification')
    require(all(item is False for item in value['qualification'].values()), 'retained proposal cannot qualify product')
    return {key: value[key] for key in ('id', 'family', 'subprofile', 'role', 'origin', 'cluster', 'selection')} | {
        'sha256': source['sha256'], 'quota': False}


def verify_retained_source_candidate(repo, candidate_path, *, _input_guard=None):
    """Read the reviewed source, rights boundary and native preflight, not admit."""
    try:
        guard = {} if _input_guard is None else _input_guard
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, 'retained checkout')
        observations = {}

        def read(path, sha=None):
            path = Path(path)
            actual, info, raw = external_read(path, capture=True)
            require(sha is None or actual['sha256'] == sha, 'retained candidate evidence drift')
            observations[path] = info
            return parse_json(raw.decode('utf-8')), actual['sha256']

        def linked(link, external=False):
            fields(link, 'path sha256', 'retained linked evidence')
            external_digest(link['sha256'])
            path = Path(link['path']) if external else repo / external_relative(link['path'])
            require(not external or (path.is_absolute() and repo not in path.parents), 'retained external evidence')
            return read(path, link['sha256'])[0]

        relative = external_relative(candidate_path).as_posix()
        require(relative.startswith('tests/product_corpus/candidates/'), 'retained candidate path')
        value, candidate_sha = read(repo / relative)
        projection = retained_candidate_metadata(value)
        links = value['links']
        records = {name: linked(link) for name, link in links.items()}
        binding = verify_external_inputs(repo / links['source_binding']['path'], repo, value['source']['snapshot_root'],
                                         _input_guard=guard)
        require(binding['schema'] == 'codeskeptic-product-retained-github-input-check/v1'
                and binding['binding_sha256'] == links['source_binding']['sha256']
                and binding['adjudication_sha256'] == links['source_review']['sha256'], 'retained binding protocol')
        manifest, review, rights, recipe, cdb = (records[name] for name in
            ('source_binding', 'source_review', 'license_basis', 'analysis_profile', 'compiler_commands'))
        source_root = Path(value['source']['snapshot_root'])
        source_paths = {source_root / row['path'] for row in manifest['inputs']}
        source_tree = external_tree(source_root, source_paths)
        for path in source_paths:
            observations[path] = path.lstat()
        require(manifest['id'] == review['id'] == value['id']
                and manifest['adjudication'] == links['source_review']
                and review['source']['sha256'] == projection['sha256']
                and review['source_label']['family'] == projection['family']
                and review['independence']['cluster'] == projection['cluster']
                and review['origin']['id'] == projection['origin']
                and review['origin']['repository'] == value['origin_repository'], 'retained source review linkage')
        mapping = review['prospective_mapping']
        expected = (mapping['expected'] if 'expected' in mapping else
                    [{key: mapping[key] for key in ('rule', 'function', 'line', 'column', 'cwes', 'multiplicity')}])
        require(canonical(expected) == canonical(value['expected']) and mapping['analyzer_run'] is False,
                'retained prospective expectation mismatch')
        source_reviews = review['review']
        for key in ('proof_evidence', 'initial_review', 'addressability_proposal', 'supplement'):
            path = Path(source_reviews[key])
            actual, info, _ = external_read(path)
            require(path.is_absolute() and repo not in path.parents
                    and actual['sha256'] == source_reviews[key + '_sha256'], 'retained source review drift')
            observations[path] = info

        fields(rights, 'schema state id source_binding source_sha256 origin_revision references assessment boundary',
               'retained rights boundary')
        require(rights['schema'] == 'codeskeptic-product-retained-rights-basis/v1'
                and rights['state'] == 'PROJECT_REFERENCES_BOUND_SOURCE_SPECIFIC_RIGHTS_UNRESOLVED'
                and rights['id'] == value['id'] and rights['source_binding'] == links['source_binding']
                and rights['source_sha256'] == projection['sha256']
                and rights['origin_revision'] == review['origin']['revision'] and nonempty(rights['boundary']),
                'retained rights/source linkage')
        assessment = rights['assessment']
        fields(assessment, 'upstream_project_spdx basis source_specific_boundary distribution_boundary '
               'license_qualified redistribution_approved author_completeness_verified', 'retained rights assessment')
        require(all(nonempty(assessment[key]) for key in ('upstream_project_spdx', 'basis',
                    'source_specific_boundary', 'distribution_boundary'))
                and all(assessment[key] is False for key in
                        ('license_qualified', 'redistribution_approved', 'author_completeness_verified')),
                'retained reference bytes are not rights clearance')
        require(type(rights['references']) is list and len(rights['references']) == 3, 'retained rights references')
        roles, names = [], set()
        notices = {row['sha256'] for row in manifest['inputs'] if row['role'] == 'notice'}
        for row in rights['references']:
            fields(row, 'role path url size_bytes sha256', 'retained rights reference')
            require(nonempty(row['url']) and row['url'].startswith('https://')
                    and type(row['size_bytes']) is int and 0 < row['size_bytes'] <= 262144,
                    'retained reference location/size')
            external_digest(row['sha256'])
            path = Path(row['path'])
            require(path.is_absolute() and repo not in path.parents and str(path).casefold() not in names,
                    'retained reference path')
            names.add(str(path).casefold())
            actual, info, _ = external_read(path)
            require(actual == {key: row[key] for key in ('size_bytes', 'sha256')}, 'retained reference bytes')
            if row['role'] in ('license-text', 'root-notice'):
                require(row['sha256'] in notices, 'retained reference differs from source notices')
            observations[path] = info
            roles.append(row['role'])
        require(roles == ['license-text', 'project-statement', 'root-notice'], 'retained reference roles')

        fields(recipe, 'schema state id source_binding source definition_reference environment preflight '
               'compiler_commands analyzer limits expected qualification boundary', 'retained native recipe')
        require(recipe['schema'] == 'codeskeptic-product-retained-native-recipe/v1'
                and recipe['state'] == 'PRE_RESULT_COMPILER_PREFLIGHT_REVIEWED_NOT_ANALYZED'
                and recipe['id'] == value['id'] and recipe['source_binding'] == links['source_binding']
                and recipe['source'] == {key: value['source'][key] for key in ('path', 'sha256', 'language')}
                and recipe['compiler_commands'] == links['compiler_commands']
                and canonical(recipe['expected']) == canonical(value['expected'])
                and canonical(recipe['qualification']) == canonical(value['qualification']) and nonempty(recipe['boundary']),
                'retained native recipe source/expectations')
        validate_limits(recipe['limits'])
        definition = recipe['definition_reference']
        fields(definition, 'head files', 'retained recipe definition')
        verify_reviewed_files(repo, definition['head'], definition['files'])
        require({'src/source_manager/SourceManager.cpp', 'src/main.cpp', 'src/core/RuleCapabilities.def'}
                <= {row['path'] for row in definition['files']}, 'retained CLI/frontend definition closure')
        preflight = recipe['preflight']
        fields(preflight, 'head wrapper observation review', 'retained preflight')
        wrapper, native, native_review = (linked(preflight[key], external=True)
                                          for key in ('wrapper', 'observation', 'review'))
        for key in ('implementer', 'verifier'):
            require(type(native_review[key]) is str and len(native_review[key]) <= 128
                    and re.fullmatch(r'/[a-z0-9_]+(?:/[a-z0-9_]+)*', native_review[key]),
                    'retained native reviewer identity')
        fields(native_review['qualification'], 'admission_ready allocator_noninterposition_verified analyzer_run '
               'calling_abi_verified candidate_executed compiler_runtime_closure_verified embedded_frontend_verified '
               'evaluation_frozen hosted_qualification_verified image_signature_authenticated implemented_emission_verified '
               'license_qualified native_product_qualified pop_authorized product_qualified publication_approved '
               'quota_credit redistribution_approved runtime_allocator_semantics_verified source_admitted task_ready '
               'upstream_authenticated', 'retained native review qualification')
        require(native_review['schema'] == 'codeskeptic-native-preflight-review/v1'
                and wrapper['schema'] == 'codeskeptic-retained-linux-native-preflight-driver/v1'
                and native['schema'] == 'codeskeptic-retained-linux-native-preflight/v1'
                and native_review['task_id'] == 'CS3-CH08-S01-U003'
                and native_review['verdict'] == 'PASS_WITH_STATED_BOUNDARIES' and native_review['findings'] == []
                and native_review['implementer'] != native_review['verifier']
                and native_review['head'] == wrapper['head'] == preflight['head'] == definition['head']
                and native_review['source_sha256'] == native['source_sha256'] == projection['sha256']
                and native_review['wrapper_summary_sha256'] == preflight['wrapper']['sha256']
                and native_review['observation_summary_sha256'] == wrapper['observation_sha256'] == preflight['observation']['sha256']
                and wrapper['exit_code'] == 0 and type(wrapper['exit_code']) is int
                and wrapper['source_binding'] == binding
                and native_review['compilation_database_sha256'] == native['compilation_database_sha256'] == links['compiler_commands']['sha256']
                and canonical(cdb) == canonical(native['compilation_database']), 'retained reviewed native preflight')
        require(all(item is False for item in native_review['qualification'].values())
                and native['candidate_and_abi_syntax_verified'] is True
                and native['same_header_closure_verified'] is True
                and native['before_after_input_identity_verified'] is True
                and all(native[key] is False for key in ('analyzer_run', 'candidate_executed', 'native_product_qualified',
                                                        'quota_credit', 'task_ready')),
                'retained native evidence cannot qualify product')
        # Preserve the raw compiler evidence as a live transitive input, not
        # merely an inventory declared inside the previously reviewed summary.
        streams = native['files']
        require(type(streams) is list and len(streams) == 41, 'retained native stream inventory')
        expected_commands = ['resource-directory', 'compiler-version']
        for form in ('cdb', 'frontend-adjusted'):
            expected_commands.extend(form + '-' + name for name in (
                'candidate-dependencies-before', 'abi-dependencies-before', 'candidate-syntax', 'abi-syntax',
                'wrong-width', 'wrong-malloc', 'wrong-free', 'candidate-dependencies-after', 'abi-dependencies-after'))
        require(type(native['commands']) is list and len(native['commands']) == 20
                and [row['name'] for row in native['commands']] == expected_commands,
                'retained native command inventory')
        expected_names = {'compile_commands.json'} | {name + suffix for name in expected_commands
                                                       for suffix in ('.stdout', '.stderr')}
        require({row['file'] for row in streams} == expected_names, 'retained native stream names')
        directory = Path(preflight['observation']['path']).parent
        expected_tree = {directory / 'summary.json', *(directory / name for name in expected_names)}
        initial_tree = external_tree(directory, expected_tree)
        for row in streams:
            fields(row, 'file sha256 size_bytes', 'retained native stream')
            require(type(row['size_bytes']) is int and 0 <= row['size_bytes'] <= 2 * 1024 * 1024,
                    'retained native stream size')
            external_digest(row['sha256'])
            path = directory / row['file']
            if row['size_bytes'] == 0:
                require(row['sha256'] == hashlib.sha256(b'').hexdigest(), 'retained empty stream digest')
                observations[path] = empty_native_stream(path)
            else:
                actual, info, _ = external_read(path)
                require(actual == {key: row[key] for key in ('size_bytes', 'sha256')}, 'retained native stream drift')
                observations[path] = info
        require(external_tree(directory, expected_tree) == initial_tree, 'retained native stream tree changed')
        producer_links = []
        require(type(wrapper['producer_inputs']) is dict and len(wrapper['producer_inputs']) == 9,
                'retained producer inputs')
        for name, row in wrapper['producer_inputs'].items():
            path = Path(name)
            if repo in path.parents:
                producer_links.append({'path': path.relative_to(repo).as_posix(), 'sha256': row['content']['sha256']})
            else:
                actual, info, _ = external_read(path)
                require(actual == row['content'], 'retained external producer drift')
                observations[path] = info
        require({row['path'] for row in producer_links} == {
            'scripts/product_profiles.py', 'scripts/product_identity.py', 'scripts/product_quality.py'},
            'retained producer helper closure')
        verify_reviewed_files(repo, preflight['head'], producer_links)
        environment = recipe['environment']
        fields(environment, 'platform kind image_id image_manifest_digest compiler resource_directory '
               'observed_kernel os_release image_signature_authenticated compiler_runtime_closure_verified',
               'retained environment')
        require(environment['platform'] == 'linux-x86_64'
                and environment['kind'] == 'LOCAL_UBUNTU_USERSPACE_NOT_HOSTED_PRODUCT_QUALIFICATION'
                and environment['image_id'] == wrapper['image']
                and environment['image_manifest_digest'] == wrapper['image_manifest_digest']
                and environment['compiler'] == native['initial_identities']['/usr/bin/clang-20']
                and environment['os_release'] == native['initial_identities']['/etc/os-release']
                and environment['resource_directory'] == native['resource_directory']
                and environment['observed_kernel'] == native['observed_kernel']
                and environment['image_signature_authenticated'] is False
                and environment['compiler_runtime_closure_verified'] is False, 'retained environment identity')
        for key, expected_path in (('compiler', '/usr/bin/clang-20'), ('os_release', '/etc/os-release')):
            observed = environment[key]
            fields(observed, 'path resolved_path sha256 bytes', 'retained observed identity')
            external_digest(observed['sha256'])
            require(observed['path'] == expected_path and type(observed['bytes']) is int and observed['bytes'] > 0
                    and type(observed['resolved_path']) is str
                    and PurePosixPath(observed['resolved_path']).is_absolute()
                    and '..' not in PurePosixPath(observed['resolved_path']).parts
                    and str(PurePosixPath(observed['resolved_path'])) == observed['resolved_path'],
                    'retained observed identity fields')
        resource = native['resource_directory']
        compiler = environment['compiler']['path']
        arguments = [compiler, '--no-default-config', '-fno-modules', '--target=x86_64-pc-linux-gnu',
                     '-resource-dir', resource, '-x', 'c', '-std=c17', '-fsyntax-only', '/input/case.c']
        require(canonical(cdb) == canonical([{'directory': '/input', 'file': '/input/case.c', 'arguments': arguments}]),
                'retained selected C17 command')
        adjusted = [compiler, '-resource-dir', resource, '-fparse-all-comments', *arguments[1:]]
        require(native['frontend_adjusted_arguments'] == adjusted, 'retained frontend-adjusted command')
        base_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': '/tmp'}
        selected_env = {**base_env, 'CODESKEPTIC_RESOURCE_DIR': resource}
        command_projections = []
        for name, argument in (('resource-directory', '-print-resource-dir'), ('compiler-version', '--version')):
            command_projections.append({'name': name, 'argv': [compiler, '--no-default-config', argument],
                                        'cwd': '/input', 'environment': base_env, 'exit_code': 0,
                                        'expected_exit': 0, 'stderr_marker': None})
        for form, argv in (('cdb', arguments), ('frontend-adjusted', adjusted)):
            for name in expected_commands[2:11]:
                suffix = name.removeprefix('cdb-')
                name = form + '-' + suffix
                bad = suffix in ('wrong-width', 'wrong-malloc', 'wrong-free')
                path = ('/runner/' + suffix + '.c' if bad else
                        '/runner/probe.c' if suffix.startswith('abi-') else '/input/case.c')
                actual_argv = ([arg for arg in argv[:-1] if arg != '-fsyntax-only']
                               + ['-M', '-MT', 'identity-probe', path] if 'dependencies' in suffix else [*argv[:-1], path])
                command_projections.append({'name': name, 'argv': actual_argv, 'cwd': '/input', 'environment': selected_env,
                                            'exit_code': int(bad), 'expected_exit': int(bad),
                                            'stderr_marker': 'parent-child-' + suffix + '-control' if bad else None})
                if bad:
                    _, _, raw = external_read(directory / (name + '.stderr'), capture=True)
                    require(command_projections[-1]['stderr_marker'].encode() in raw, 'retained failed assertion marker')
        require(canonical(native['commands']) == canonical(command_projections), 'retained preflight command/status drift')
        analyzer = recipe['analyzer']
        fields(analyzer, 'state executable_sha256 cwd environment selected_rule all_current_rules required_conditions',
               'retained analyzer recipe')
        require(analyzer['state'] == 'PREDECLARED_NOT_EXECUTED' and analyzer['executable_sha256'] is None
                and analyzer['cwd'] == '/profile'
                and analyzer['environment'] == {'CODESKEPTIC_RESOURCE_DIR': resource, 'LANG': 'C', 'LC_ALL': 'C',
                                               'PATH': '/usr/bin:/bin', 'TMPDIR': '/tmp'}
                and type(analyzer['required_conditions']) is list and len(analyzer['required_conditions']) >= 1
                and all(nonempty(row) for row in analyzer['required_conditions']), 'retained analyzer state')
        common = ['/product/bin/codeskeptic', '--source', '/input/case.c', '--build-path', '/profile', '--json',
                  '/output/' + value['family'] + '.json', '--severity', 'info', '--lang', 'en',
                  '--worker-timeout-ms', str(LIMITS['worker_timeout_ms']), '--worker-memory-mb',
                  str(LIMITS['worker_memory_mib']), '--no-analysis-cache']
        families = ('memory-leak', 'uninit-ptr', 'uninit-scalar', 'double-free', 'use-after-free', 'resource-leak',
                    'div-by-zero', 'null-deref', 'bounds', 'int-overflow', 'sign-conversion', 'alloc-size-overflow',
                    'assumption', 'contract', 'policy')
        all_current = list(common)
        all_current[6] = '/output/all-current-rules.json'
        require(analyzer['selected_rule'] == common + ['--disable-rule', ','.join(name for name in families if name != value['family'])]
                and analyzer['all_current_rules'] == all_current + ['--assumptions'], 'retained predeclared CLI')
        # The source was checked before the rest of the packet. Reopen it at
        # the completion boundary as well, then retain identity checks across
        # this entire read. No filesystem snapshot/hostile-root claim is made.
        require(verify_external_inputs(repo / links['source_binding']['path'], repo, source_root) == binding,
                'retained source changed during candidate check')
        require(external_tree(source_root, source_paths) == source_tree
                and external_tree(directory, expected_tree) == initial_tree, 'retained final input tree changed')
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    'retained candidate final identity')
        remember_input_identities(guard, observations, {**source_tree, **initial_tree})
        verify_input_identities(guard)
        return {'candidate_sha256': candidate_sha, 'projection': projection, 'source_bytes_verified': True,
                'pre_result_recipe_bound': True, 'fresh_independent_admission_required': True,
                'linked_evidence_files': len(observations), 'independent_quota_examples': 0,
                'task_ready': False, 'product_qualified': False}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, IndexError,
            subprocess.SubprocessError):
        raise ValueError('retained source candidate binding rejected') from None


def verify_source_candidate(repo, candidate_path=GCC_SOURCE_CANDIDATE):
    """Explicit schema dispatch; legacy records retain their original reader."""
    try:
        relative = external_relative(candidate_path).as_posix()
        require(relative.startswith('tests/product_corpus/candidates/'), 'source candidate path')
        _, _, raw = external_read(Path(repo) / relative, capture=True)
        value = parse_json(raw.decode('utf-8'))
        require(type(value) is dict, 'source candidate record')
        if value.get('schema') == RETAINED_CANDIDATE:
            return verify_retained_source_candidate(repo, relative)
        require(relative == GCC_SOURCE_CANDIDATE
                and value.get('schema') == 'codeskeptic-product-source-candidate/v1', 'source candidate schema')
        return verify_gcc_source_candidate(repo)
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('source candidate dispatch rejected') from None


def admission_review_metadata(review, candidate, candidate_sha, candidate_path=GCC_SOURCE_CANDIDATE):
    """Check a procedural source-count decision, never authenticate its author."""
    fields(review, "schema repository_head candidate_path candidate_sha256 source_sha256 implementer verifier "
           "verdict admitted_source_count projection reviewed_links rationale remaining_gaps qualification", "source admission review")
    retained = type(candidate) is dict and candidate.get('schema') == RETAINED_CANDIDATE
    relative = external_relative(candidate_path).as_posix()
    require(relative.startswith('tests/product_corpus/candidates/')
            and (retained or relative == GCC_SOURCE_CANDIDATE), 'source admission candidate path')
    require(review["schema"] == ("codeskeptic-source-admission-review/v2" if retained
                                  else "codeskeptic-source-admission-review/v1")
            and type(review["repository_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", review["repository_head"])
            and review["repository_head"] != "0" * 40
            and review["candidate_path"] == relative and review["candidate_sha256"] == candidate_sha
            and review["verdict"] == "ADMIT_ONE_SOURCE" and type(review["admitted_source_count"]) is int
            and review["admitted_source_count"] == 1, "source admission identity/verdict")
    for key in ("implementer", "verifier"):
        require(type(review[key]) is str and re.fullmatch(r"/[a-z0-9_]+(?:/[a-z0-9_]+)*", review[key])
                and len(review[key]) <= 128, "source admission agent identity")
    require(review["implementer"] != review["verifier"], "source admission is not independent")
    projection = {**(retained_candidate_metadata(candidate) if retained else gcc_candidate_metadata(candidate)), "quota": True}
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
    names, contents = set(), {}
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
        contents[relative] = {'sha256': link['sha256'], 'size_bytes': size}
    return contents


SOURCE_SELECTION = "tests/product_corpus/selection.json"


def verify_source_selection(repo, link, *, _input_guard=None):
    """Read an entire partial selection before returning any admitted count.

    Exact reviewed commits, actual linked bytes and distinct procedural agent
    identities are checked. This shared-account process is not signed provenance
    or proof against an author forging both an index and its review evidence.
    """
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "selection checkout root")
        observations = {}
        input_guard = {} if _input_guard is None else _input_guard

        def read_link(item, external=False, maximum=16 * 1024 * 1024):
            fields(item, "path sha256", "selection link")
            external_digest(item["sha256"])
            path = Path(item["path"]) if external else repo / external_relative(item["path"])
            require(not external or (path.is_absolute() and repo not in path.parents), "review evidence must be external")
            actual, info, raw = external_read(path, capture=True)
            require(actual["sha256"] == item["sha256"] and actual["size_bytes"] <= maximum, "selection evidence drift/size")
            observations[path] = info
            remember_input_identities(input_guard, {path: info})
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
            require(type(entry["candidate"]) is dict, "source candidate entry")
            candidate_path = external_relative(entry['candidate']['path']).as_posix()
            require(candidate_path.startswith('tests/product_corpus/candidates/'), 'source candidate entry path')
            candidate = read_link(entry["candidate"], maximum=65536)
            review = read_link(entry["review"], external=True, maximum=65536)
            projection = admission_review_metadata(review, candidate, entry["candidate"]["sha256"], candidate_path)
            retained = candidate.get('schema') == RETAINED_CANDIDATE
            require(origins.get(projection["origin"]) == (candidate['origin_repository'] if retained
                                                        else "https://github.com/gcc-mirror/gcc"), "candidate canonical origin")
            verify_reviewed_files(repo, review["repository_head"], [entry["candidate"], *review["reviewed_links"].values()])
            actual = (verify_retained_source_candidate(repo, candidate_path, _input_guard=input_guard) if retained
                      else verify_gcc_source_candidate(repo, _input_guard=input_guard))
            require(actual["candidate_sha256"] == entry["candidate"]["sha256"]
                    and canonical({**actual["projection"], "quota": True}) == canonical(projection),
                    "admitted candidate no longer matches actual inputs")
            rows.append(projection)
        result = quota_readiness(rows, set(origins))
        remember_input_identities(input_guard, observations)
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "selection evidence final identity changed")
        verify_input_identities(input_guard)
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


RETAINED_GROUND_TRUTH_INDEX = 'tests/product_corpus/retained_ground_truth.json'
RETAINED_GROUND_TRUTH_SCHEMA = 'codeskeptic-product-retained-source-all-rule-ground-truth/v1'


def retained_ground_truth_metadata(value, candidate):
    """Validate proposed label structure, never infer source safety or review."""
    retained_candidate_metadata(candidate)
    fields(value, 'schema state id candidate source reference_head references analysis_profile data_model '
           'assumptions families project_diagnostics boundary additional_quota_examples qualification',
           'retained source labels')
    require(value['schema'] == RETAINED_GROUND_TRUTH_SCHEMA
            and value['state'] == 'SOURCE_DERIVED_LABELS_FOR_INDEPENDENT_REVIEW'
            and value['id'] == candidate['id'], 'retained label identity')
    fields(value['candidate'], 'path sha256', 'retained label candidate')
    relative = external_relative(value['candidate']['path']).as_posix()
    require(relative.startswith('tests/product_corpus/candidates/'), 'retained label candidate scope')
    external_digest(value['candidate']['sha256'])
    fields(value['source'], 'path sha256 language line_count', 'retained label source')
    source = value['source']
    require(all(source[key] == candidate['source'][key] for key in ('path', 'sha256', 'language'))
            and type(source['line_count']) is int and 1 <= source['line_count'] <= 100000,
            'retained label source binding')
    require(value['analysis_profile'] == candidate['links']['analysis_profile'], 'retained label recipe binding')
    require(type(value['reference_head']) is str and re.fullmatch(r'[0-9a-f]{40}', value['reference_head'])
            and value['reference_head'] != '0' * 40, 'retained label reference head')
    references = value['references']
    require(type(references) is list and len(references) == len(GROUND_TRUTH_REFERENCES),
            'retained label reference coverage')
    for link, path in zip(references, GROUND_TRUTH_REFERENCES):
        fields(link, 'path sha256', 'retained label reference')
        require(link['path'] == path, 'retained label reference order')
        external_digest(link['sha256'])
    # This supported retained C17 recipe has a bounded conditional native model.
    # No claim about a live runtime or another platform follows from these bits.
    require(canonical(value['data_model']) == canonical(
        {'char_bit': 8, 'int_bits': 32, 'size_t_bits': 64, 'pointer_bits': 64}),
        'retained label conditional data model')
    require(type(value['assumptions']) is list and 1 <= len(value['assumptions']) <= 16
            and all(nonempty(item) and len(item) <= 2048 for item in value['assumptions'])
            and nonempty(value['boundary']) and len(value['boundary']) <= 8192,
            'retained label assumptions and boundary')
    require(type(value['additional_quota_examples']) is int and value['additional_quota_examples'] == 0
            and canonical(value['qualification']) == canonical(candidate['qualification']),
            'retained source labels cannot qualify or add quota')

    def source_basis(row):
        lines = row['source_lines']
        require(type(lines) is list and lines
                and all(type(line) is int and 1 <= line <= source['line_count'] for line in lines)
                and lines == sorted(set(lines)) and nonempty(row['rationale']) and len(row['rationale']) <= 8192,
                'retained source rationale')

    families = value['families']
    require(type(families) is list and len(families) == len(FAMILIES), 'retained label family coverage')
    occurrences = 0
    for row, family in zip(families, sorted(FAMILIES)):
        fields(row, 'rule availability role expected source_lines rationale', 'retained family label')
        require(row['rule'] == family and row['availability'] == (
            'PLANNED_NOT_IMPLEMENTED' if family in GROUND_TRUTH_PLANNED else 'INSTALLED_AT_REFERENCE_HEAD'),
            'retained family order and availability')
        require(type(row['role']) is str and row['role'] in ('buggy', 'safe', 'unknown', 'unsupported')
                and type(row['expected']) is list and len(row['expected']) <= 64
                and bool(row['expected']) == (row['role'] == 'buggy'), 'retained family expectations')
        identities = set()
        for occurrence in row['expected']:
            fields(occurrence, 'rule function line column cwes multiplicity', 'retained label occurrence')
            require(occurrence['rule'] == family and nonempty(occurrence['function'])
                    and len(occurrence['function']) <= 512
                    and type(occurrence['line']) is int and 1 <= occurrence['line'] <= source['line_count']
                    and all(type(occurrence[key]) is int and 1 <= occurrence[key] <= 1000000
                            for key in ('column', 'multiplicity'))
                    and type(occurrence['cwes']) is list and 1 <= len(occurrence['cwes']) <= 26
                    and all(type(cwe) is int and 1 <= cwe <= 10000 for cwe in occurrence['cwes'])
                    and occurrence['cwes'] == sorted(set(occurrence['cwes'])), 'retained label occurrence fields')
            identity = canonical({key: item for key, item in occurrence.items() if key != 'multiplicity'})
            require(identity not in identities, 'duplicate retained label occurrence')
            identities.add(identity)
            occurrences += occurrence['multiplicity']
        if family == candidate['family']:
            require(row['role'] == candidate['role']
                    and canonical(row['expected']) == canonical(candidate['expected']),
                    'retained labels must preserve admitted target')
        source_basis(row)
    projects = value['project_diagnostics']
    require(type(projects) is list and len(projects) == 3, 'retained project label coverage')
    for row, rule in zip(projects, ('assumption', 'contract', 'policy')):
        fields(row, 'rule role expected source_lines rationale', 'retained project label')
        require(row['rule'] == rule and row['role'] == 'no-trigger' and row['expected'] == [],
                'retained project label expectation')
        source_basis(row)
    return {'family_labels': len(families), 'project_diagnostics': len(projects),
            'expected_occurrences': occurrences, 'additional_quota_examples': 0,
            'source_labels_independently_reviewed': False, **candidate['qualification']}


def _ground_truth_input(path, guard, expected=None, *, json_value=True, maximum=65536):
    info, before, raw = external_read(path, capture=True)
    require(info['size_bytes'] <= maximum and (expected is None or info['sha256'] == expected),
            'retained label input size or hash')
    # Register immediately, so a later observation cannot overwrite an earlier
    # identity. The same guard spans label records, candidates and admissions.
    remember_input_identities(guard, {path: before})
    return info, parse_json(raw.decode('utf-8')) if json_value else raw


def verify_retained_ground_truth(repo, record_path, *, _input_guard=None):
    """Reopen an explicit proposed source-label record without accepting it."""
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, 'retained label checkout')
        guard = {} if _input_guard is None else _input_guard
        relative = external_relative(record_path).as_posix()
        require(relative.startswith('tests/product_corpus/candidates/'), 'retained label record scope')
        info, value = _ground_truth_input(repo / relative, guard)
        candidate_link = value['candidate']
        candidate_path = external_relative(candidate_link['path']).as_posix()
        candidate_info, candidate = _ground_truth_input(repo / candidate_path, guard, candidate_link['sha256'])
        result = retained_ground_truth_metadata(value, candidate)
        actual = verify_retained_source_candidate(repo, candidate_path, _input_guard=guard)
        require(actual['candidate_sha256'] == candidate_info['sha256'], 'retained label candidate changed')
        source_path = Path(candidate['source']['snapshot_root']) / 'case.c'
        _, source = _ground_truth_input(source_path, guard, candidate['source']['sha256'],
                                        json_value=False, maximum=16 * 1024 * 1024)
        require(len(source.decode('utf-8').splitlines()) == value['source']['line_count'],
                'retained label source line count')
        # Semantic references belong to their declared ancestor commit. Read
        # those actual Git blobs, permitting later implementation/docs changes
        # without rewriting a frozen source-label decision. Live candidate,
        # source, rights and stream identities still span the whole read.
        verify_reviewed_files(repo, value['reference_head'], value['references'])
        verify_input_identities(guard)
        return {**result, 'record_sha256': info['sha256'], 'candidate_sha256': candidate_info['sha256'],
                'source_sha256': value['source']['sha256'], 'reference_head': value['reference_head'],
                'source_bytes_verified': True}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('retained all-rule source binding rejected') from None


def retained_ground_truth_review_metadata(review, value, record_path, record_sha):
    fields(review, 'schema repository_head record candidate source_sha256 implementer verifier verdict findings '
           'rationale additional_quota_examples qualification', 'retained source-label review')
    external_digest(record_sha)
    require(review['schema'] == 'codeskeptic-retained-all-rule-source-review/v1'
            and type(review['repository_head']) is str and re.fullmatch(r'[0-9a-f]{40}', review['repository_head'])
            and review['repository_head'] != '0' * 40
            and review['record'] == {'path': record_path, 'sha256': record_sha}
            and review['candidate'] == value['candidate'] and review['source_sha256'] == value['source']['sha256']
            and review['verdict'] == 'ACCEPT_SOURCE_LABELS' and review['findings'] == [],
            'retained source-label reviewed binding')
    for key in ('implementer', 'verifier'):
        require(type(review[key]) is str and re.fullmatch(r'/[a-z0-9_]+(?:/[a-z0-9_]+)*', review[key])
                and len(review[key]) <= 128, 'retained source-label reviewer identity')
    require(review['implementer'] != review['verifier'] and nonempty(review['rationale'])
            and len(review['rationale']) <= 8192
            and type(review['additional_quota_examples']) is int and review['additional_quota_examples'] == 0
            and canonical(review['qualification']) == canonical(value['qualification']),
            'retained source-label review boundaries')
    fields(review['qualification'], SOURCE_QUALIFICATION, 'retained source-label review qualification')
    require(all(item is False for item in review['qualification'].values()), 'retained review cannot qualify')


def verify_retained_ground_truth_index(repo):
    """Separate partial index; preserve the original platform-bound label index."""
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, 'retained label index checkout')
        guard = {}
        _, index = _ground_truth_input(repo / RETAINED_GROUND_TRUTH_INDEX, guard, maximum=16 * 1024 * 1024)
        fields(index, 'schema state entries boundary', 'retained label index')
        require(index['schema'] == 'codeskeptic-product-reviewed-retained-ground-truth/v1'
                and index['state'] == 'PARTIAL_REVIEWED_SOURCE_LABELS_NOT_FROZEN'
                and type(index['entries']) is list and 1 <= len(index['entries']) <= 10000
                and nonempty(index['boundary']) and len(index['boundary']) <= 8192, 'retained label index state')
        records, candidates, sources, results, admitted = set(), set(), set(), [], []
        for entry in index['entries']:
            fields(entry, 'record review', 'retained label entry')
            for link in entry.values():
                fields(link, 'path sha256', 'retained label entry link')
                external_digest(link['sha256'])
            relative = external_relative(entry['record']['path']).as_posix()
            require(relative.startswith('tests/product_corpus/candidates/') and relative.casefold() not in records,
                    'retained label indexed record path')
            records.add(relative.casefold())
            _, value = _ground_truth_input(repo / relative, guard, entry['record']['sha256'])
            review_path = Path(entry['review']['path'])
            require(review_path.is_absolute() and repo not in review_path.parents, 'retained review must be external')
            _, review = _ground_truth_input(review_path, guard, entry['review']['sha256'])
            retained_ground_truth_review_metadata(review, value, relative, entry['record']['sha256'])
            verify_reviewed_files(repo, review['repository_head'], [entry['record'], value['candidate']])
            actual = verify_retained_ground_truth(repo, relative, _input_guard=guard)
            require(actual['record_sha256'] == entry['record']['sha256'], 'retained reviewed labels changed')
            candidate_path = value['candidate']['path'].casefold()
            require(candidate_path not in candidates and value['source']['sha256'] not in sources,
                    'retained label source or candidate duplicated')
            candidates.add(candidate_path)
            sources.add(value['source']['sha256'])
            admitted.append(value['candidate'])
            results.append({**actual, 'review_head': review['repository_head'],
                            'source_labels_independently_reviewed': True})
        _, manifest = _ground_truth_input(repo / 'scripts/product_profiles.json', guard,
                                         maximum=16 * 1024 * 1024)
        source_metadata(manifest)
        selection = verify_source_selection(repo, manifest['source_selection'], _input_guard=guard)
        _, selected = _ground_truth_input(repo / SOURCE_SELECTION, guard, manifest['source_selection']['sha256'],
                                         maximum=16 * 1024 * 1024)
        require(selection['quota_examples'] == manifest['independent_quota_examples']
                and all(any(item['candidate'] == candidate for item in selected['admissions'])
                        for candidate in admitted), 'retained labels require original source admissions')
        verify_input_identities(guard)
        return {'state': index['state'], 'records': results, 'reviewed_sources': len(results),
                'source_selection_quota_examples': selection['quota_examples'], 'additional_quota_examples': 0,
                'source_labels_independently_reviewed': True,
                **{key: False for key in SOURCE_QUALIFICATION.split()}}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('reviewed retained all-rule source labels rejected') from None


GCC_PLATFORM_FILES = {
    "Windows": "tests/product_corpus/candidates/gcc-mixed-storage-windows.json",
    "Darwin": "tests/product_corpus/candidates/gcc-mixed-storage-macos.json",
}
GCC_PLATFORM_REVIEW_INDEX = "tests/product_corpus/platform_source_labels.json"
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


def gcc_platform_source_review_metadata(review, recipes, ground_truth):
    """Validate a procedural conditional judgment, never its native prerequisites."""
    fields(review, "schema repository_head implementer verifier verdict findings source_sha256 recipes ground_truth "
           "additional_quota_examples conditions rationale qualification", "platform source review")
    require(type(recipes) is list and len(recipes) == len(GCC_PLATFORM_FILES), "reviewed platform coverage")
    for link, path in zip(recipes, GCC_PLATFORM_FILES.values()):
        fields(link, "path sha256", "reviewed platform recipe")
        require(link["path"] == path, "reviewed platform path")
        external_digest(link["sha256"])
    fields(ground_truth, "path sha256", "reviewed platform ground truth")
    require(ground_truth["path"] == GCC_GROUND_TRUTH, "reviewed platform ground-truth path")
    external_digest(ground_truth["sha256"])
    require(review["schema"] == "codeskeptic-platform-source-applicability-review/v1"
            and type(review["repository_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", review["repository_head"])
            and review["repository_head"] != "0" * 40
            and review["verdict"] == "ACCEPT_CONDITIONAL_PLATFORM_SOURCE_LABELS" and review["findings"] == []
            and review["source_sha256"] == GCC_CASE_SHA
            and canonical(review["recipes"]) == canonical(recipes)
            and canonical(review["ground_truth"]) == canonical(ground_truth), "platform source reviewed identity")
    for key in ("implementer", "verifier"):
        require(type(review[key]) is str and re.fullmatch(r"/[a-z0-9_]+(?:/[a-z0-9_]+)*", review[key])
                and len(review[key]) <= 128, "platform source reviewer identity")
    require(review["implementer"] != review["verifier"]
            and type(review["additional_quota_examples"]) is int and review["additional_quota_examples"] == 0
            and nonempty(review["rationale"]) and len(review["rationale"]) <= 8192
            and type(review["conditions"]) is list and 1 <= len(review["conditions"]) <= 32
            and all(nonempty(item) and len(item) <= 2048 for item in review["conditions"]),
            "platform source review independence/conditions")
    qualification = tuple(key for key in GCC_PLATFORM_QUALIFICATION if key != "platform_source_labels_reviewed")
    fields(review["qualification"], " ".join(qualification), "platform source review qualification")
    require(all(value is False for value in review["qualification"].values()), "conditional review is not qualification")
    return {"platform_source_labels_reviewed": True, "conditional_only": True, "conditions_satisfied": False,
            "conditions": list(review["conditions"]), "review_head": review["repository_head"],
            "additional_quota_examples": 0, **review["qualification"]}


def verify_gcc_platform_source_labels(repo):
    """Bind an additive review while preserving both original prospective records.

    Agent identities and reviewed Git bytes establish the repository's shared-user
    review procedure, not a signature or automatic proof of genuine authorship.
    No condition is declared satisfied and no native tool is invoked.
    """
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, "platform source checkout root")
        observations = {}

        def read(path, expected=None):
            info, before, raw = external_read(path, capture=True)
            require(info["size_bytes"] <= 65536 and (expected is None or info["sha256"] == expected),
                    "platform source review size/hash")
            if path in observations:
                require(external_identity(observations[path]) == external_identity(before),
                        "platform source evidence changed between reads")
            observations[path] = before
            return parse_json(raw.decode("utf-8"))

        index = read(repo / GCC_PLATFORM_REVIEW_INDEX)
        fields(index, "schema state recipes ground_truth review boundary", "platform source review index")
        require(index["schema"] == "codeskeptic-product-reviewed-platform-source-labels/v1"
                and index["state"] == "CONDITIONAL_PLATFORM_SOURCE_LABELS_NOT_NATIVE_QUALIFIED"
                and nonempty(index["boundary"]) and len(index["boundary"]) <= 8192, "platform source review index state")
        fields(index["review"], "path sha256", "platform source review link")
        external_digest(index["review"]["sha256"])
        review_path = Path(index["review"]["path"])
        require(review_path.is_absolute() and repo not in review_path.parents, "platform source review must be external")
        review = read(review_path, index["review"]["sha256"])
        accepted = gcc_platform_source_review_metadata(review, index["recipes"], index["ground_truth"])
        links = {}

        def linked(link):
            fields(link, "path sha256", "platform source reviewed file")
            relative = external_relative(link["path"]).as_posix()
            external_digest(link["sha256"])
            require(relative not in links or links[relative] == link, "platform source shared link changed")
            links[relative] = link
            return read(repo / relative, link["sha256"])

        linked(index["ground_truth"])
        for link in index["recipes"]:
            value = linked(link)
            require(value["ground_truth"] == index["ground_truth"], "platform source label binding changed")
            for key in ("compilation_database", "candidate", "linux_recipe", "ground_truth_index"):
                linked(value[key])
        verify_reviewed_files(repo, review["repository_head"], list(links.values()))
        actual = verify_gcc_platform_recipes(repo)
        current_links = [{"path": GCC_PLATFORM_FILES[row["platform"]], "sha256": row["record_sha256"]}
                         for row in actual["recipes"]]
        require(canonical(current_links) == canonical(index["recipes"]), "platform source reviewed recipes changed")
        for path, before in observations.items():
            require(path.resolve(strict=True) == path and external_identity(path.lstat()) == external_identity(before),
                    "platform source review final identity changed")
        return {**actual, **accepted, "review_sha256": index["review"]["sha256"],
                "recipes": [{**row, "platform_source_labels_reviewed": True,
                             "conditional_only": True, "conditions_satisfied": False} for row in actual["recipes"]]}
    except (ValueError, OSError, TypeError, KeyError, IndexError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError("reviewed GCC platform source labels rejected") from None


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


SOURCE_COHORT_SCHEMA = 'codeskeptic-product-source-cohort/v1'
SOURCE_COHORT_RECORDS_MAX = 64
SOURCE_COHORT_LINKED_BYTES_MAX = 64 * 1024 * 1024


def source_cohort_metadata(value):
    """Bound content-addressed preparation records, never grant source credit.

    Individual record hashes do not depend on unrelated records in the same
    shard. A later admission protocol must bind its own actual reviewed Git
    objects and decisions; these proposed labels are not that review.
    """
    fields(value, 'schema state id origins records limits boundary qualification', 'source cohort')
    identifier = lambda item: type(item) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,95}', item)
    text_bound = lambda item, maximum: nonempty(item) and len(item) <= maximum
    require(value['schema'] == SOURCE_COHORT_SCHEMA
            and value['state'] == 'PRE_RESULT_SOURCE_PREPARATION_NOT_ADMITTED'
            and identifier(value['id']) and text_bound(value['boundary'], 8192), 'source cohort identity')
    validate_limits(value['limits'])
    fields(value['qualification'], SOURCE_QUALIFICATION, 'source cohort qualification')
    require(all(item is False for item in value['qualification'].values()), 'source cohort cannot qualify')
    require(type(value['origins']) is list and 1 <= len(value['origins']) <= 64, 'source cohort origins')
    origins, linked_bytes = set(), 0
    for origin in value['origins']:
        fields(origin, 'id repository revision path git_blob source api_capture', 'source cohort origin')
        require(identifier(origin['id']) and origin['id'] not in origins, 'duplicate source cohort origin')
        origins.add(origin['id'])
        require(type(origin['repository']) is str and re.fullmatch(
            r'https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',
            origin['repository']) and not origin['repository'].endswith('.git'), 'source cohort repository')
        require(all(type(origin[key]) is str and re.fullmatch(r'[0-9a-f]{40}', origin[key])
                    and origin[key] != '0' * 40 for key in ('revision', 'git_blob')), 'source cohort Git identity')
        path = origin['path']
        require(type(path) is str and 0 < len(path) <= 512 and len(path.split('/')) <= 16
                and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', part)
                        and not part.endswith('.') for part in path.split('/')), 'source cohort upstream path')
        for link in (origin['source'], origin['api_capture']):
            fields(link, 'path sha256 size_bytes', 'source cohort external link')
            external_digest(link['sha256'])
            require(nonempty(link['path']) and len(link['path']) <= 4096
                    and Path(link['path']).is_absolute()
                    and type(link['size_bytes']) is int and 0 < link['size_bytes'] <= 16 * 1024 * 1024,
                    'source cohort external identity')
            linked_bytes += link['size_bytes']
    require(linked_bytes <= SOURCE_COHORT_LINKED_BYTES_MAX, 'source cohort linked byte budget')
    require(type(value['records']) is list and 1 <= len(value['records']) <= SOURCE_COHORT_RECORDS_MAX,
            'source cohort record bound')
    records, hashes, candidate_clusters, used_origins, results = {}, set(), set(), set(), []
    for entry in value['records']:
        fields(entry, 'sha256 value', 'source cohort entry')
        external_digest(entry['sha256'])
        record = entry['value']
        require(hashlib.sha256(canonical(record).encode('utf-8')).hexdigest() == entry['sha256'],
                'source cohort entry digest')
        fields(record, 'id selection family subprofile role origin cluster related_to source extraction '
               'assumptions expected boundary', 'source cohort record')
        require(identifier(record['id']) and record['id'] not in records
                and identifier(record['cluster']) and type(record['origin']) is str
                and record['origin'] in origins, 'source cohort record identity')
        records[record['id']] = record
        used_origins.add(record['origin'])
        require(type(record['selection']) is str and record['selection'] in
                ('independent-evaluation-candidate', 'supplemental-control'), 'source cohort selection')
        if record['selection'] == 'independent-evaluation-candidate':
            require(record['related_to'] is None and record['cluster'] not in candidate_clusters,
                    'source cohort candidate cluster')
            candidate_clusters.add(record['cluster'])
        else:
            require(identifier(record['related_to']) and record['related_to'] != record['id'],
                    'source cohort supplemental relation')
        require(type(record['family']) is str and record['family'] in FAMILIES - GROUND_TRUTH_PLANNED
                and type(record['role']) is str and record['role'] in ('buggy', 'safe')
                and (record['subprofile'] in ('cwe-121', 'cwe-122') if record['family'] == 'bounds'
                     else record['subprofile'] is None), 'source cohort ordinary family')
        source = record['source']
        fields(source, 'language text sha256 size_bytes', 'source cohort adapted source')
        external_digest(source['sha256'])
        require(source['language'] == 'C17' and type(source['text']) is str
                and '\0' not in source['text'] and source['text'].endswith('\n'), 'source cohort source form')
        raw = source['text'].encode('utf-8')
        require(type(source['size_bytes']) is int and 0 < len(raw) == source['size_bytes'] <= 65536
                and hashlib.sha256(raw).hexdigest() == source['sha256'] and source['sha256'] not in hashes,
                'source cohort source identity or duplicate')
        hashes.add(source['sha256'])
        extraction = record['extraction']
        fields(extraction, 'ranges raw_sha256 adaptation', 'source cohort extraction')
        external_digest(extraction['raw_sha256'])
        require(extraction['adaptation'] == 'native-stdlib-prefix/v1'
                and type(extraction['ranges']) is list and 1 <= len(extraction['ranges']) <= 64,
                'source cohort extraction form')
        last = 0
        for pair in extraction['ranges']:
            require(type(pair) is list and len(pair) == 2 and all(type(n) is int for n in pair)
                    and last < pair[0] <= pair[1] <= 1000000, 'source cohort extraction ranges')
            last = pair[1]
        require(type(record['assumptions']) is list and 1 <= len(record['assumptions']) <= 16
                and all(text_bound(item, 2048) for item in record['assumptions'])
                and text_bound(record['boundary'], 8192), 'source cohort conditional source model')
        require(type(record['expected']) is list and len(record['expected']) <= 64
                and bool(record['expected']) == (record['role'] == 'buggy'), 'source cohort expectations')
        occurrences, line_count = set(), len(source['text'].splitlines())
        for occurrence in record['expected']:
            fields(occurrence, 'rule function line column cwes multiplicity', 'source cohort occurrence')
            require(occurrence['rule'] == record['family'] and text_bound(occurrence['function'], 512)
                    and type(occurrence['line']) is int and 1 <= occurrence['line'] <= line_count
                    and all(type(occurrence[key]) is int and 1 <= occurrence[key] <= 1000000
                            for key in ('column', 'multiplicity'))
                    and type(occurrence['cwes']) is list and 1 <= len(occurrence['cwes']) <= 26
                    and all(type(cwe) is int and 1 <= cwe <= 10000 for cwe in occurrence['cwes'])
                    and occurrence['cwes'] == sorted(set(occurrence['cwes'])), 'source cohort occurrence shape')
            identity = canonical({key: item for key, item in occurrence.items() if key != 'multiplicity'})
            require(identity not in occurrences, 'source cohort duplicate occurrence')
            occurrences.add(identity)
        results.append({key: record[key] for key in
                        ('id', 'origin', 'cluster', 'selection', 'role', 'family', 'related_to')} | {
                            'record_sha256': entry['sha256'], 'source_sha256': source['sha256']})
    require(used_origins == origins, 'source cohort unused origins')
    for record in records.values():
        if record['selection'] == 'supplemental-control':
            parent = records.get(record['related_to'])
            require(parent is not None and parent['selection'] == 'independent-evaluation-candidate'
                    and all(parent[key] == record[key] for key in ('origin', 'family', 'subprofile', 'cluster')),
                    'source cohort control must belong to its candidate mechanism')
    return {'records': results, 'total_sources': len(results), 'preparation_candidates': len(candidate_clusters),
            'control_sources': len(results) - len(candidate_clusters), 'source_bytes_verified': False,
            'independently_reviewed': False, 'admitted_sources': 0, 'additional_quota_examples': 0,
            **value['qualification']}


def verify_source_cohort(repo, cohort_path, *, _input_guard=None):
    """Read one bounded preparation shard and all linked provenance atomically
    with respect to ordinary observed drift, not as a hostile-root snapshot.

    No prior fictional HOLD/supplement history is required. Real independent
    source, cluster, all-rule, rights and native qualification remain later
    gates. Returned per-entry digests are not admission receipts.
    """
    try:
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, 'source cohort checkout')
        relative = external_relative(cohort_path).as_posix()
        require(relative.startswith('tests/product_corpus/cohorts/'), 'source cohort scope')
        guard = {} if _input_guard is None else _input_guard
        info, value = _ground_truth_input(repo / relative, guard, maximum=16 * 1024 * 1024)
        result = source_cohort_metadata(value)

        def read_link(link):
            path = Path(link['path'])
            require(repo != path and repo not in path.parents, 'source cohort evidence must be external')
            actual, before, raw = external_read(path, capture=True)
            require(actual == {key: link[key] for key in ('sha256', 'size_bytes')}, 'source cohort input drift')
            remember_input_identities(guard, {path: before})
            return raw

        # Shared origins are reopened once in this transaction, not cached
        # across invocations. Every file remains in the final identity guard.
        origins = {}
        for origin in value['origins']:
            raw = read_link(origin['source'])
            raw.decode('utf-8')
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            require(blob == origin['git_blob'], 'source cohort origin blob')
            capture = parse_json(read_link(origin['api_capture']).decode('utf-8'))
            fields(capture, 'command cwd exit expected_exit head working_diff_sha256 stdout stderr '
                   'capture_script_sha256', 'source cohort API capture')
            route = ('repos/' + origin['repository'].removeprefix('https://github.com/') + '/contents/'
                     + quote(origin['path'], safe='/') + '?ref=' + origin['revision'])
            require(capture['command'] == ['gh', 'api', route]
                    and type(capture['exit']) is int and capture['exit'] == 0
                    and type(capture['expected_exit']) is int and capture['expected_exit'] == 0
                    and capture['stderr'] == '' and type(capture['stdout']) is str,
                    'source cohort pinned API command')
            api = parse_json(capture['stdout'])
            require(type(api) is dict and api['type'] == 'file' and api['encoding'] == 'base64'
                    and api['path'] == origin['path'] and api['sha'] == blob
                    and type(api['size']) is int and api['size'] == len(raw)
                    and api['url'] == 'https://api.github.com/' + route and type(api['content']) is str,
                    'source cohort API identity')
            require(base64.b64decode(''.join(api['content'].split()), validate=True) == raw,
                    'source cohort API source bytes')
            origins[origin['id']] = raw.splitlines(keepends=True)
        for entry in value['records']:
            record = entry['value']
            lines = origins[record['origin']]
            ranges = record['extraction']['ranges']
            require(ranges[-1][-1] <= len(lines), 'source cohort extraction exceeds actual source')
            selected = b''.join(line for first, last in ranges for line in lines[first - 1:last])
            require(hashlib.sha256(selected).hexdigest() == record['extraction']['raw_sha256']
                    and b'#include <stdlib.h>\n\n' + selected == record['source']['text'].encode('utf-8'),
                    'source cohort extraction bytes or adaptation changed')
        verify_input_identities(guard)
        return {**result, 'source_bytes_verified': True, 'cohort_sha256': info['sha256']}
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('source cohort preparation rejected') from None


def _cohort_entry_projection(value, link, cohort_sha):
    fields(link, 'path sha256 id record_sha256 source_sha256', 'cohort entry reference')
    require(external_relative(link['path']).as_posix().startswith('tests/product_corpus/cohorts/'),
            'cohort entry scope')
    for key in ('sha256', 'record_sha256', 'source_sha256'):
        external_digest(link[key])
    require(link['sha256'] == cohort_sha and type(link['id']) is str
            and re.fullmatch(r'[a-z][a-z0-9-]{0,95}', link['id']), 'cohort entry reference identity')
    entries = [entry for entry in value['records'] if entry['value']['id'] == link['id']]
    require(len(entries) == 1 and entries[0]['sha256'] == link['record_sha256']
            and entries[0]['value']['source']['sha256'] == link['source_sha256'], 'cohort entry binding')
    record = entries[0]['value']
    return {key: record[key] for key in ('id', 'origin', 'cluster', 'selection', 'role', 'family', 'related_to')} | {
        'record_sha256': link['record_sha256'], 'source_sha256': link['source_sha256'],
        'cohort_sha256': cohort_sha, 'source_bytes_verified': True, 'independently_reviewed': False,
        'admitted_sources': 0, 'additional_quota_examples': 0, **value['qualification']}


def verify_source_cohort_entry(repo, link, *, _input_guard=None):
    """Resolve one actual preparation entry, not an admission or label decision."""
    try:
        guard = {} if _input_guard is None else _input_guard
        fields(link, 'path sha256 id record_sha256 source_sha256', 'cohort entry reference')
        result = verify_source_cohort(repo, link['path'], _input_guard=guard)
        _, value = _ground_truth_input(Path(repo) / external_relative(link['path']), guard,
                                      link['sha256'], maximum=16 * 1024 * 1024)
        projection = _cohort_entry_projection(value, link, result['cohort_sha256'])
        verify_input_identities(guard)
        return projection
    except (ValueError, OSError, TypeError, KeyError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('source cohort entry rejected') from None


def _cohort_native_commands(records, resource):
    """Recorded compiler-only matrix for the explicit caller-slot pair profile."""
    compiler = '/usr/bin/clang-20'
    require(resource == '/usr/lib/llvm-20/lib/clang/20', 'cohort native resource directory')
    sources = {row['id']: '/input/' + row['id'] + '.c' for row in records}
    roles = {**sources, 'abi': '/runner/probe.c'}
    controls = ['wrong-width', 'wrong-malloc', 'wrong-slot']
    prefix = [compiler, '--no-default-config', '-fno-modules', '--target=x86_64-pc-linux-gnu',
              '-resource-dir', resource, '-x', 'c', '-std=c17', '-fsyntax-only']
    adjusted = [compiler, '-resource-dir', resource, '-fparse-all-comments', *prefix[1:]]
    base_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': '/tmp'}
    selected_env = {**base_env, 'CODESKEPTIC_RESOURCE_DIR': resource}
    commands = []

    def append(name, argv, environment, bad=False, marker=None):
        commands.append({'name': name, 'argv': argv, 'cwd': '/input', 'environment': environment,
                         'exit_code': int(bad), 'expected_exit': int(bad), 'stderr_marker': marker})

    for name, flag in (('resource-directory', '-print-resource-dir'), ('compiler-version', '--version')):
        append(name, [compiler, '--no-default-config', flag], base_env)
    for form, argv in (('cdb', prefix), ('frontend-adjusted', adjusted)):
        def dependencies(phase):
            for role, path in roles.items():
                append(form + '-' + role + '-dependencies-' + phase,
                       [arg for arg in argv if arg != '-fsyntax-only'] + ['-M', '-MT', 'identity-probe', path],
                       selected_env)
        dependencies('before')
        for role, path in roles.items():
            append(form + '-' + role + '-syntax', [*argv, path], selected_env)
        for control in controls:
            append(form + '-' + control, [*argv, '/runner/' + control + '.c'], selected_env,
                   bad=True, marker='slot-' + control + '-control')
        dependencies('after')
    return {
        'commands': commands, 'roles': roles, 'controls': controls, 'environment': selected_env,
        'cdb': [{'directory': '/input', 'file': path, 'arguments': [*prefix, path]} for path in sources.values()],
        'adjusted': {name: [*adjusted, path] for name, path in sources.items()},
        'matrix': {'source_roles': list(roles), 'command_forms': ['cdb', 'frontend-adjusted'],
                   'negative_controls': controls, 'expected_commands': 2 + 2 * (3 * len(roles) + len(controls))}}


def _cohort_native_identity(path, value):
    fields(value, 'path resolved_path sha256 bytes', 'cohort native recorded file identity')
    external_digest(value['sha256'])
    require(value['path'] == path and type(value['bytes']) is int and 0 < value['bytes'] <= 2 ** 32,
            'cohort native recorded file content')
    for name in (path, value['resolved_path']):
        require(type(name) is str and 0 < len(name) <= 4096 and not any(ord(char) < 32 for char in name)
                and PurePosixPath(name).is_absolute() and not name.startswith('//')
                and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name)) == name,
                'cohort native recorded file path')


def verify_cohort_native(repo, evidence_path, *, _input_guard=None):
    """Reopen the reviewed caller-slot compiler packet, never execute or admit.

Recorded native header identities are not fresh image extraction or signed
attestation. One guard covers live sidecar/source/API/review/producer/stream
bytes; historical checkout helpers instead bind actual producer-head blobs.
    """
    try:
        import product_identity as identity
        guard = {} if _input_guard is None else _input_guard
        repo = Path(repo)
        require(repo.is_absolute() and repo.resolve(strict=True) == repo, 'cohort native checkout')
        relative = external_relative(evidence_path).as_posix()
        require(relative.startswith('tests/product_corpus/cohort_evidence/'), 'cohort native packet scope')
        info, value = _ground_truth_input(repo / relative, guard)
        fields(value, 'schema state id profile cohort records native definition_reference limits '
               'additional_quota_examples qualification boundary', 'cohort native packet')
        require(value['schema'] == 'codeskeptic-product-cohort-native-evidence/v1'
                and value['state'] == 'PRE_RESULT_REVIEWED_COMPILER_PACKET_NOT_ADMITTED'
                and value['profile'] == 'caller-slot-publication-c17-v1'
                and type(value['id']) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,95}', value['id'])
                and nonempty(value['boundary']) and len(value['boundary']) <= 8192, 'cohort native identity')
        validate_limits(value['limits'])
        fields(value['qualification'], SOURCE_QUALIFICATION, 'cohort native qualification')
        require(all(item is False for item in value['qualification'].values())
                and type(value['additional_quota_examples']) is int and value['additional_quota_examples'] == 0,
                'cohort native cannot grant quota or qualify')
        fields(value['cohort'], 'path sha256', 'cohort native source link')
        external_digest(value['cohort']['sha256'])
        source = verify_source_cohort(repo, value['cohort']['path'], _input_guard=guard)
        _, cohort = _ground_truth_input(repo / external_relative(value['cohort']['path']), guard,
                                       value['cohort']['sha256'], maximum=16 * 1024 * 1024)
        require(source['cohort_sha256'] == value['cohort']['sha256'], 'cohort native source changed')
        records = value['records']
        require(type(records) is list and len(records) == source['total_sources'] == 2
                and cohort['id'] == 'llvm-caller-slot-v1', 'cohort native pair size and profile')
        projections = []
        for record in records:
            fields(record, 'id record_sha256 source_sha256', 'cohort native entry')
            projections.append(_cohort_entry_projection(cohort, {**value['cohort'], **record}, source['cohort_sha256']))
        candidate, control = projections
        require([row['id'] for row in records] == ['llvm-caller-slot-overwrite', 'llvm-caller-slot-retained-control']
                and candidate['selection'] == 'independent-evaluation-candidate' and candidate['role'] == 'buggy'
                and control['selection'] == 'supplemental-control' and control['role'] == 'safe'
                and candidate['family'] == control['family'] == 'memory-leak'
                and control['related_to'] == candidate['id']
                and all(candidate[key] == control[key] for key in ('origin', 'cluster')),
                'cohort native source/control mechanism')
        native_link = value['native']
        fields(native_link, 'head root wrapper_sha256 observation_sha256 review', 'cohort native link')
        for key in ('wrapper_sha256', 'observation_sha256'):
            external_digest(native_link[key])
        root = Path(native_link['root'])
        require(root.is_absolute() and root.resolve(strict=True) == root and repo != root and repo not in root.parents,
                'cohort native external root')
        fields(native_link['review'], 'path sha256', 'cohort native review link')
        external_digest(native_link['review']['sha256'])
        review_path = Path(native_link['review']['path'])
        require(review_path.is_absolute() and repo not in review_path.parents and root not in review_path.parents,
                'cohort native external review')
        parts = _cohort_native_commands(records, '/usr/lib/llvm-20/lib/clang/20')
        command_names = [row['name'] for row in parts['commands']]
        stream_names = {'compile_commands.json'} | {name + '.' + suffix for name in command_names
                                                     for suffix in ('stdout', 'stderr')}
        runner_names = ('run.py', 'observe.py', 'probe.c', 'wrong-width.c', 'wrong-malloc.c', 'wrong-slot.c')
        expected_tree = {root / name for name in (*runner_names, 'summary.json', 'image-inspect.json',
                                                  'container.stdout', 'container.stderr')}
        expected_tree.update(root / 'inputs' / (row['id'] + '.c') for row in records)
        expected_tree.update(root / 'observation' / name for name in stream_names | {'summary.json'})
        remember_input_identities(guard, {}, external_tree(root, expected_tree))
        _, wrapper = _ground_truth_input(root / 'summary.json', guard, native_link['wrapper_sha256'],
                                         maximum=16 * 1024 * 1024)
        _, native = _ground_truth_input(root / 'observation/summary.json', guard, native_link['observation_sha256'],
                                        maximum=16 * 1024 * 1024)
        _, review = _ground_truth_input(review_path, guard, native_link['review']['sha256'])
        fields(wrapper, 'schema head image image_manifest_digest argv exit_code source_cohort producer_inputs '
               'image_inspection_sha256 stdout_sha256 stderr_sha256 analyzer_run candidate_executed '
               'source_admitted additional_quota_examples product_qualified task_ready observation_sha256',
               'cohort native driver')
        require(wrapper['schema'] == 'codeskeptic-source-cohort-native-preflight-driver/v1'
                and type(wrapper['exit_code']) is int and wrapper['exit_code'] == 0
                and wrapper['head'] == native_link['head']
                and wrapper['observation_sha256'] == native_link['observation_sha256']
                and canonical(wrapper['source_cohort']) == canonical(source), 'cohort native driver binding')
        require(all(wrapper[key] is False for key in ('analyzer_run', 'candidate_executed', 'source_admitted',
                                                     'product_qualified', 'task_ready'))
                and type(wrapper['additional_quota_examples']) is int and wrapper['additional_quota_examples'] == 0,
                'cohort native driver qualification')
        fields(review, 'schema implementer verifier head branch verdict findings evidence checks source_assessment '
               'limitations boundary', 'cohort native independent review')
        for key in ('implementer', 'verifier'):
            require(type(review[key]) is str and len(review[key]) <= 128
                    and re.fullmatch(r'/[a-z0-9_]+(?:/[a-z0-9_]+)*', review[key]), 'cohort native reviewer identity')
        require(review['schema'] == 'codeskeptic-source-cohort-native-preflight-review/v1'
                and review['verdict'] == 'PASS_BOUNDED_COMPILER_ONLY_PREFLIGHT' and review['findings'] == []
                and review['implementer'] != review['verifier'] and review['head'] == native_link['head']
                and review['branch'] == 'agent/cs3-ch08-s01-u003-frozen-product-profiles'
                and review['evidence'] == {'root': str(root), 'driver_sha256': native_link['wrapper_sha256'],
                    'observation_sha256': native_link['observation_sha256'], 'cohort_sha256': source['cohort_sha256'],
                    'candidate_sha256': candidate['source_sha256'], 'control_sha256': control['source_sha256']},
                'cohort native review binding')
        for key in ('checks', 'limitations'):
            require(type(review[key]) is list and 1 <= len(review[key]) <= 64
                    and all(nonempty(item) and len(item) <= 8192 for item in review[key]), 'cohort native review coverage')
        require(all(nonempty(review[key]) and len(review[key]) <= 8192 for key in ('source_assessment', 'boundary')),
                'cohort native review boundary')
        definition = value['definition_reference']
        fields(definition, 'head files', 'cohort native definitions')
        require(definition['head'] == native_link['head'] and type(definition['files']) is list
                and [row['path'] for row in definition['files']] == [
                    'src/source_manager/SourceManager.cpp', 'src/main.cpp', 'src/core/RuleCapabilities.def'],
                'cohort native definition closure')
        verify_reviewed_files(repo, definition['head'], definition['files'])

        expected_producers = {repo / 'scripts' / name for name in
                              ('product_profiles.py', 'product_identity.py', 'product_quality.py')}
        expected_producers.add(repo / value['cohort']['path'])
        expected_producers.update(root / name for name in runner_names)
        expected_producers.update(root / 'inputs' / (row['id'] + '.c') for row in records)
        expected_producers.update(Path(origin[key]['path']) for origin in cohort['origins']
                                  for key in ('source', 'api_capture'))
        require(type(wrapper['producer_inputs']) is dict
                and set(wrapper['producer_inputs']) == {str(path) for path in expected_producers},
                'cohort native producer closure')
        producer_contents, repo_links = {}, []
        for name, row in wrapper['producer_inputs'].items():
            fields(row, 'content identity', 'cohort native producer')
            fields(row['content'], 'sha256 size_bytes', 'cohort native producer content')
            external_digest(row['content']['sha256'])
            require(type(row['content']['size_bytes']) is int and 0 < row['content']['size_bytes'] <= 16 * 1024 * 1024
                    and type(row['identity']) is list and len(row['identity']) == 7
                    and all(type(number) is int and number >= 0 for number in row['identity'])
                    and stat.S_ISREG(row['identity'][2]) and row['identity'][3] == 1
                    and row['identity'][4] == row['content']['size_bytes'], 'cohort native historical identity')
            path = Path(name)
            if repo in path.parents:
                repo_links.append({'path': path.relative_to(repo).as_posix(), 'sha256': row['content']['sha256']})
            else:
                actual, _ = _ground_truth_input(path, guard, row['content']['sha256'], json_value=False,
                                                maximum=16 * 1024 * 1024)
                require(actual == row['content'], 'cohort native producer bytes')
            producer_contents[path] = row['content']
        historical = verify_reviewed_files(repo, native_link['head'], repo_links)
        require(all(historical[row['path']] == producer_contents[repo / row['path']] for row in repo_links),
                'cohort native historical producer size')
        for row in records:
            content = producer_contents[root / 'inputs' / (row['id'] + '.c')]
            require(content['sha256'] == row['source_sha256'], 'cohort native materialized source')
        external_digest(wrapper['image'])
        require(type(wrapper['image_manifest_digest']) is str
                and re.fullmatch(r'sha256:[0-9a-f]{64}', wrapper['image_manifest_digest']), 'cohort native image digest')
        external_digest(wrapper['image_inspection_sha256'])
        _, inspection = _ground_truth_input(root / 'image-inspect.json', guard, wrapper['image_inspection_sha256'],
                                            maximum=16 * 1024 * 1024)
        require(type(inspection) is list and len(inspection) == 1 and type(inspection[0]) is dict
                and inspection[0]['Id'] == wrapper['image'] and inspection[0]['Digest'] == wrapper['image_manifest_digest'],
                'cohort native recorded image inspection')
        argv = ['podman', 'run', '--rm', '--pull=never', '--network=none', '--read-only', '--timeout=150',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--security-opt=label=disable',
                '--cpus=2', '--memory=6144m', '--memory-swap=12288m', '--pids-limit=256',
                '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=1024m',
                '--mount', 'type=bind,src=' + str(repo / 'scripts') + ',dst=/helpers,ro=true',
                '--mount', 'type=bind,src=' + str(root / 'inputs') + ',dst=/input,ro=true',
                '--mount', 'type=bind,src=' + str(root) + ',dst=/runner,ro=true',
                '--mount', 'type=bind,src=' + str(root / 'observation') + ',dst=/output,rw=true',
                '--entrypoint=/usr/bin/python3', wrapper['image'], '-B', '/runner/observe.py']
        for row in records:
            argv.extend(['--case', row['id'] + '=' + row['source_sha256']])
        require(wrapper['argv'] == argv, 'cohort native recorded container command')

        def read_stream(path, digest, size=None):
            external_digest(digest)
            if size is None:
                size = path.lstat().st_size
            require(type(size) is int and 0 <= size <= LIMITS['capture_bytes_per_stream'], 'cohort native stream size')
            if size == 0:
                require(digest == hashlib.sha256(b'').hexdigest(), 'cohort native empty stream digest')
                remember_input_identities(guard, {path: empty_native_stream(path)})
                return b''
            actual, raw = _ground_truth_input(path, guard, digest, json_value=False,
                                              maximum=LIMITS['capture_bytes_per_stream'])
            require(actual['size_bytes'] == size, 'cohort native stream byte count')
            return raw

        container_stdout = read_stream(root / 'container.stdout', wrapper['stdout_sha256'])
        require(read_stream(root / 'container.stderr', wrapper['stderr_sha256']) == b'', 'cohort native container failure')
        require(parse_json(container_stdout.decode('utf-8')) == {
            'commands': len(parts['commands']), 'negative_controls': 2 * len(parts['controls']), 'sources': len(records),
            'summary_sha256': native_link['observation_sha256'], 'analyzer_run': False}, 'cohort native container result')
        fields(native, 'schema profile cases initial_identities compiler_version resource_directory userspace observed_kernel '
               'compilation_database compilation_database_sha256 frontend_adjusted_arguments child_environment commands files '
               'native_inputs matrix candidate_and_abi_syntax_verified same_header_closure_verified '
               'before_after_input_identity_verified analyzer_run candidate_executed native_product_qualified '
               'embedded_frontend_verified calling_abi_executed runtime_allocator_semantics_verified source_admitted '
               'additional_quota_examples task_ready product_qualified boundary', 'cohort native observation')
        require(native['schema'] == 'codeskeptic-source-cohort-native-preflight/v1' and native['profile'] == value['profile']
                and native['resource_directory'] == '/usr/lib/llvm-20/lib/clang/20'
                and native['cases'] == {row['id']: {'path': '/input/' + row['id'] + '.c', 'sha256': row['source_sha256']}
                                        for row in records}
                and canonical(native['commands']) == canonical(parts['commands'])
                and canonical(native['matrix']) == canonical(parts['matrix'])
                and native['compilation_database'] == parts['cdb']
                and native['frontend_adjusted_arguments'] == parts['adjusted']
                and native['child_environment'] == parts['environment'], 'cohort native observed command matrix')
        require(all(native[key] is True for key in ('candidate_and_abi_syntax_verified', 'same_header_closure_verified',
                                                   'before_after_input_identity_verified'))
                and all(native[key] is False for key in ('analyzer_run', 'candidate_executed', 'native_product_qualified',
                    'embedded_frontend_verified', 'calling_abi_executed', 'runtime_allocator_semantics_verified',
                    'source_admitted', 'task_ready', 'product_qualified'))
                and type(native['additional_quota_examples']) is int and native['additional_quota_examples'] == 0
                and nonempty(native['boundary']) and len(native['boundary']) <= 8192
                and nonempty(native['observed_kernel']) and len(native['observed_kernel']) <= 512,
                'cohort native observed boundaries')
        require(type(native['files']) is list and len(native['files']) == len(stream_names)
                and {row['file'] for row in native['files']} == stream_names, 'cohort native raw file closure')
        streams = {}
        for row in native['files']:
            fields(row, 'file sha256 size_bytes', 'cohort native raw file')
            streams[row['file']] = read_stream(root / 'observation' / row['file'], row['sha256'], row['size_bytes'])
        require(hashlib.sha256(streams['compile_commands.json']).hexdigest() == native['compilation_database_sha256']
                and parse_json(streams['compile_commands.json'].decode('utf-8')) == parts['cdb'], 'cohort native actual CDB')
        require(streams['resource-directory.stdout'].decode('utf-8').strip() == native['resource_directory']
                and streams['compiler-version.stdout'].decode('utf-8') == native['compiler_version']
                and nonempty(native['compiler_version']), 'cohort native raw compiler metadata')
        for command in parts['commands']:
            stdout, stderr = (streams[command['name'] + '.' + suffix] for suffix in ('stdout', 'stderr'))
            if command['stderr_marker'] is not None:
                require(stdout == b'' and command['stderr_marker'].encode() in stderr
                        and b'static assertion failed' in stderr, 'cohort native intended assertion failure')
            else:
                require(stderr == b'' and (not command['name'].endswith('-syntax') or stdout == b''),
                        'cohort native positive compiler failure')
        fields(native['native_inputs'], 'cdb frontend-adjusted', 'cohort native input forms')
        require(canonical(native['native_inputs']['cdb']) == canonical(native['native_inputs']['frontend-adjusted']),
                'cohort native cross-form identity drift')
        inputs = native['native_inputs']['cdb']
        fields(inputs, 'dependency_paths input_identities', 'cohort native inputs')
        require(type(inputs['dependency_paths']) is dict and set(inputs['dependency_paths']) == set(parts['roles'])
                and type(inputs['input_identities']) is dict, 'cohort native dependency roles')
        union = set()
        for role, source_path in parts['roles'].items():
            actual_paths = None
            for form in ('cdb', 'frontend-adjusted'):
                for phase in ('before', 'after'):
                    raw = streams[form + '-' + role + '-dependencies-' + phase + '.stdout']
                    paths = identity.dependency_paths(raw.decode('utf-8'), 'posix')
                    require(actual_paths is None or paths == actual_paths, 'cohort native raw dependency drift')
                    actual_paths = paths
            require(actual_paths == inputs['dependency_paths'][role] and source_path in actual_paths
                    and '/usr/include/stdlib.h' in actual_paths
                    and (role != 'abi' or all(row['path'] in actual_paths for row in native['cases'].values())),
                    'cohort native source/header dependency closure')
            union.update(actual_paths)
        require(set(inputs['input_identities']) == union, 'cohort native complete header identity set')
        for path, row in inputs['input_identities'].items():
            _cohort_native_identity(path, row)
            require(path in parts['roles'].values() or path.startswith('/usr/include/')
                    or path.startswith(native['resource_directory'] + '/include/'), 'cohort native dependency scope')
        mapped = {'/runner/' + name: root / name for name in runner_names if name != 'run.py'}
        mapped.update({'/helpers/product_identity.py': repo / 'scripts/product_identity.py'})
        mapped.update({row['path']: root / 'inputs' / Path(row['path']).name for row in native['cases'].values()})
        require(type(native['initial_identities']) is dict
                and set(native['initial_identities']) == set(mapped) | {'/usr/bin/clang-20', '/etc/os-release'},
                'cohort native initial identity closure')
        for path, row in native['initial_identities'].items():
            _cohort_native_identity(path, row)
            if path in mapped:
                require({'sha256': row['sha256'], 'size_bytes': row['bytes']} == producer_contents[mapped[path]],
                        'cohort native logical-to-producer identity')
            if path in inputs['input_identities']:
                require(row == inputs['input_identities'][path], 'cohort native overlapping identity drift')
        require(type(native['userspace']) is str
                and {'sha256': hashlib.sha256(native['userspace'].encode('utf-8')).hexdigest(),
                     'bytes': len(native['userspace'].encode('utf-8'))} == {
                        key: native['initial_identities']['/etc/os-release'][key] for key in ('sha256', 'bytes')},
                'cohort native recorded userspace identity')
        verify_input_identities(guard)
        return {'packet_sha256': info['sha256'], 'cohort_sha256': source['cohort_sha256'], 'profile': value['profile'],
                'producer_head': native_link['head'], 'records': projections, 'source_bytes_verified': True,
                'compiler_preflight_independently_reviewed': True, 'recorded_commands': len(parts['commands']),
                'recorded_stream_files': len(stream_names), 'admitted_sources': 0, 'additional_quota_examples': 0,
                **value['qualification']}
    except (ValueError, OSError, TypeError, KeyError, IndexError, RecursionError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('source cohort native packet rejected') from None


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
    parser.add_argument("command", choices=("historical-check", "limits", "sources-check", "api-check", "readiness", "external-source-check", "stage-gcc-inputs", "license-basis-check", "source-candidate-check", "selection-check", "ground-truth-candidate-check", "ground-truth-check", "retained-ground-truth-check", "source-cohort-check", "cohort-native-check", "platform-recipes-check", "platform-source-labels-check"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--historical-sources", type=Path, default=Path(
        "/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S04-U001/corpus-diagnostic-comparison"))
    parser.add_argument("--binding", type=Path, help="tracked binding manifest (absolute path)")
    parser.add_argument('--candidate', help='explicit repository-relative source-candidate record; source-candidate-check only')
    parser.add_argument('--ground-truth', help='explicit retained label record; ground-truth-candidate-check only')
    parser.add_argument('--cohort', help='explicit repository-relative source preparation shard; source-cohort-check only')
    parser.add_argument('--cohort-evidence', help='explicit repository-relative compiler packet; cohort-native-check only')
    parser.add_argument("--external-root", type=Path, help="explicit external snapshot root (absolute canonical path)")
    parser.add_argument("--evidence-root", type=Path, help="explicit external license-reference directory")
    args = parser.parse_args()
    try:
        require(args.command == 'source-candidate-check' or args.candidate is None,
                'candidate selector is only valid for source-candidate-check')
        require(args.command == 'ground-truth-candidate-check' or args.ground_truth is None,
                'ground-truth selector is only valid for ground-truth-candidate-check')
        require(args.command == 'source-cohort-check' or args.cohort is None,
                'cohort selector is only valid for source-cohort-check')
        require(args.command == 'cohort-native-check' or args.cohort_evidence is None,
                'cohort evidence selector is only valid for cohort-native-check')
        if args.command == "selection-check":
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "reviewed selection uses its explicit tracked roots")
        if args.command == 'cohort-native-check':
            require(args.cohort_evidence is not None and args.binding is None and args.evidence_root is None
                    and args.external_root is None and args.historical_sources == parser.get_default('historical_sources'),
                    'cohort native packet uses its explicit linked inputs')
            result = verify_cohort_native(args.root, args.cohort_evidence)
        elif args.command == 'source-cohort-check':
            require(args.cohort is not None and args.binding is None and args.evidence_root is None
                    and args.external_root is None, 'source cohort uses its explicit linked inputs')
            result = verify_source_cohort(args.root, args.cohort)
        elif args.command in ("platform-recipes-check", "platform-source-labels-check"):
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "native recipes use their fixed tracked roots")
            result = (verify_gcc_platform_recipes(args.root) if args.command == "platform-recipes-check"
                      else verify_gcc_platform_source_labels(args.root))
        elif args.command == 'retained-ground-truth-check':
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    'retained source labels use their explicit tracked roots')
            result = verify_retained_ground_truth_index(args.root)
        elif args.command in ("ground-truth-candidate-check", "ground-truth-check"):
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "all-rule source labels use their fixed tracked roots")
            if args.command == 'ground-truth-candidate-check':
                result = (verify_retained_ground_truth(args.root, args.ground_truth) if args.ground_truth is not None
                          else verify_gcc_ground_truth(args.root))
            else:
                result = verify_ground_truth_index(args.root)
        elif args.command == "source-candidate-check":
            require(args.binding is None and args.evidence_root is None and args.external_root is None,
                    "source candidate uses its explicit tracked roots")
            result = (verify_source_candidate(args.root, args.candidate) if args.candidate is not None
                      else verify_gcc_source_candidate(args.root))
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
