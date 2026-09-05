#!/usr/bin/env python3
"""Strict checkpoint evidence validation; checksums are not hosted attestation."""
from __future__ import annotations

import hashlib
import copy
import json
import math
import re
import shutil
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import compare_measurements as measurement
import run_realworld_campaign as campaign


class CheckpointError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CheckpointError(message)


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), f"{label}: wrong fields")


def integer(value, label, minimum=0):
    require(type(value) is int and value >= minimum, f"{label}: invalid integer")


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None,
            "invalid exact digest")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def json_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def regular(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), f"symlink evidence: {path}")
    require(path.is_file(), f"missing/nonregular evidence: {path}")
    return path


def file_digest(path):
    path = regular(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise CheckpointError(f"nonfinite JSON number: {value}")


def _float(value):
    result = float(value)
    require(math.isfinite(result), "nonfinite JSON number")
    return result


def load_json(path, root_type=dict):
    path = regular(path)
    require(path.stat().st_size <= 32 * 1024 * 1024, f"oversized JSON: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object,
                           parse_constant=_constant, parse_float=_float)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CheckpointError(f"invalid JSON: {path}: {error}") from error
    require(type(value) is root_type, f"wrong JSON root type: {path}")
    return value


def validate_config(value):
    require(type(value) is dict, "checkpoint request: not an object")
    require(value.get("schema") in ("codeskeptic-regression-checkpoint/v1",
                                     "codeskeptic-regression-checkpoint/v2"), "unsupported request schema")
    fields = {"schema", "enabled", "request_id", "base_sha", "inputs_sha", "profile", "manifest_sha256"}
    if value["schema"].endswith("/v2"):
        fields.add("adjudications_sha256")
    keys(value, fields, "checkpoint request")
    if "adjudications_sha256" in fields:
        digest(value["adjudications_sha256"])
    require(type(value["enabled"]) is bool, "enabled must be Boolean")
    require(type(value["request_id"]) is str and
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["request_id"]) is not None,
            "invalid request id")
    digest(value["base_sha"], 40)
    digest(value["inputs_sha"], 40)
    digest(value["manifest_sha256"])
    require(value["inputs_sha"] == value["base_sha"], "checkpoint inputs must use exact base")
    require(value["profile"] == "nightly-weekend-three-repeats", "unreviewed checkpoint profile")
    return value


def load_adjudications(config, path=None):
    """V2 binds exact canonical bytes; v1 cannot silently activate a sidecar."""
    validate_config(config)
    if config["schema"].endswith("/v1"):
        require(path is None, "v1 does not admit adjudications")
        return None
    require(path is not None, "v2 requires the bound adjudication file")
    path = regular(path)
    require(path.stat().st_size <= 512 * 1024, "oversized adjudications")
    value = load_json(path)
    require(path.read_bytes() == canonical(value), "adjudications must be exact canonical JSON")
    require(file_digest(path) == config["adjudications_sha256"], "adjudication file digest differs")
    return value


def _bounded_text(value, label, maximum=4096):
    require(type(value) is str and value.strip() and len(value) <= maximum and
            not any(ord(c) < 32 for c in value), f"invalid {label}")


def _source_path(value):
    _bounded_text(value, "evidence path", 512)
    require(re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None and not value.startswith("/") and
            all(p not in ("", ".", "..") for p in value.split("/")), "unsafe evidence path")


def derive_expectations(config, manifest, adjudications=None):
    """Keep immutable base inputs; derive only two head finding expectations.

    Review identities/evidence hashes are procedural references, not signatures
    or a runtime proof of the human classification. Exact-head independent review
    must inspect that evidence. This function enforces its precise multiset scope.
    """
    validate_config(config)
    require(campaign.digest_json(manifest) == config["manifest_sha256"], "wrong expected manifest")
    if config["schema"].endswith("/v1"):
        require(adjudications is None, "v1 does not admit adjudications")
        return {"base": manifest, "head": manifest}, {}
    require(type(adjudications) is dict and json_digest(adjudications) == config["adjudications_sha256"],
            "missing or unbound adjudications")
    keys(adjudications, ("schema", "base_sha", "manifest_sha256", "projects"), "adjudications")
    require(adjudications["schema"] == "codeskeptic-semantic-adjudications/v1" and
            adjudications["base_sha"] == config["base_sha"] and
            adjudications["manifest_sha256"] == config["manifest_sha256"], "adjudication baseline differs")
    records = adjudications["projects"]
    require(type(records) is list and 1 <= len(records) <= 8, "empty or oversized adjudication catalog")
    head = copy.deepcopy(manifest)
    deltas = {}
    for record in records:
        keys(record, ("project", "revision", "original_expected", "baseline_fingerprints", "changes"),
             "project adjudication")
        identity = record["project"]
        require(type(identity) is str and identity not in deltas and
                identity in {p["id"] for p in manifest["projects"]}, "duplicate or unknown adjudicated project")
        project = campaign.project_by_id(manifest, identity)
        require(record["revision"] == project["revision"], "adjudicated revision differs")
        expected = project["expected"]
        # Dict equality would accept False == 0 or 1.0 == 1 here.
        require(canonical(record["original_expected"]) == canonical(expected), "original expectation differs")
        baseline = record["baseline_fingerprints"]
        require(type(baseline) is list and len(baseline) <= 100000 and
                all(type(f) is str and re.fullmatch(r"csf1-[0-9a-f]{16}", f) for f in baseline),
                "invalid baseline fingerprint multiset")
        require(baseline == sorted(baseline) and len(baseline) == expected["findings"] and
                campaign.fingerprint_digest(baseline) == expected["fingerprint_sha256"],
                "baseline fingerprint count/digest differs")
        changes = record["changes"]
        require(type(changes) is list and 1 <= len(changes) <= 256, "empty or oversized changes")
        counts, removed, added, seen = Counter(baseline), Counter(), Counter(), set()
        for change in changes:
            keys(change, ("fingerprint", "count", "direction", "classification", "reason", "source",
                          "regression", "review"), "classified change")
            fingerprint = change["fingerprint"]
            require(type(fingerprint) is str and re.fullmatch(r"csf1-[0-9a-f]{16}", fingerprint) and
                    fingerprint not in seen, "invalid, duplicate or cancelling change")
            seen.add(fingerprint)
            integer(change["count"], "change occurrence count", 1)
            require(change["count"] <= 100000, "oversized change count")
            require((change["direction"], change["classification"]) in
                    (("remove", "false-positive"), ("add", "true-positive")), "unclassified semantic change")
            _bounded_text(change["reason"], "classification reason")
            source = change["source"]
            keys(source, ("path", "sha256", "line"), "source evidence")
            _source_path(source["path"])
            digest(source["sha256"])
            integer(source["line"], "source line", 1)
            regression = change["regression"]
            keys(regression, ("path", "test", "commit"), "regression evidence")
            _source_path(regression["path"])
            _bounded_text(regression["test"], "regression test", 256)
            digest(regression["commit"], 40)
            review = change["review"]
            keys(review, ("implementer", "verifier", "verdict", "evidence_sha256"), "semantic review")
            for field in ("implementer", "verifier"):
                _bounded_text(review[field], field, 256)
            require(review["implementer"] != review["verifier"] and review["verdict"] == "PASS",
                    "independent semantic review required")
            digest(review["evidence_sha256"])
            count = change["count"]
            if change["direction"] == "remove":
                # Counter subtraction otherwise silently drops negative counts.
                require(count <= counts[fingerprint], "removal exceeds baseline multiplicity")
                counts[fingerprint] -= count
                removed[fingerprint] = count
            else:
                counts[fingerprint] += count
                added[fingerprint] = count
        require(sum(counts.values()) <= 100000, "oversized head multiset")
        fingerprints = sorted(counts.elements())
        # Retain the legacy exit contract; this policy does not invent a new
        # interpretation for report-only findings or change exit classification.
        require(expected["exit_code"] == int(bool(fingerprints)), "adjudication changes exit classification")
        effective = campaign.project_by_id(head, identity)["expected"]
        effective["findings"] = len(fingerprints)
        effective["fingerprint_sha256"] = campaign.fingerprint_digest(fingerprints)
        deltas[identity] = {"base": baseline, "head": fingerprints,
                            "removed": dict(removed), "added": dict(added)}
    campaign.validate_manifest(head)
    return {"base": manifest, "head": head}, deltas


def validate_context(value):
    keys(value, ("head_sha", "workflow_sha", "run_id", "run_attempt", "repository", "ref", "lane"),
         "checkpoint context")
    for field in ("head_sha", "workflow_sha"):
        digest(value[field], 40)
    require(value["head_sha"] == value["workflow_sha"], "push workflow must be exact event head")
    for field in ("run_id", "run_attempt"):
        require(type(value[field]) is str and re.fullmatch(r"[1-9][0-9]*", value[field]) is not None,
                f"invalid {field}")
    require(value["repository"] == "tanzercakir-commits/CodeSkeptic", "wrong repository")
    require(type(value["ref"]) is str and
            re.fullmatch(r"refs/heads/agent/cs3-[a-z0-9-]+", value["ref"]) is not None,
            "not a scoped agent push ref")
    require(value["lane"] in ("measurement", "realworld"), "unreviewed lane")
    return value


def request_selected(config, changed_at_head):
    validate_config(config)
    require(type(changed_at_head) is bool, "changed-at-head must be Boolean")
    return config["enabled"] and changed_at_head


def validate_shard(receipt, manifest, project_id, repetition, binary_sha256):
    keys(receipt, ("schema", "status", "project", "repetition", "identity", "semantic", "execution",
                   "failures"), "shard receipt")
    integer(receipt["schema"], "schema", 1)
    integer(receipt["repetition"], "repetition", 1)
    require(receipt["schema"] == 1 and receipt["status"] == "accepted" and
            receipt["project"] == project_id and receipt["repetition"] == repetition and
            receipt["failures"] == [], "unavailable or wrong shard")
    project = campaign.project_by_id(manifest, project_id)
    digest(binary_sha256)
    expected = campaign.receipt_identity(manifest, project, repetition, binary_sha256,
                                         project["expected"]["translation_unit_sha256"])
    keys(receipt["identity"], expected, "shard identity")
    integer(receipt["identity"]["repetition"], "identity repetition", 1)
    require(receipt["identity"] == expected, "shard identity mismatch")
    keys(receipt["execution"], ("duration_seconds", "resumed"), "execution")
    duration = receipt["execution"]["duration_seconds"]
    require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0,
            "invalid shard duration")
    require(receipt["execution"]["resumed"] is False, "fresh checkpoint cannot reuse a cached run")
    require(type(receipt["semantic"]) is dict, "missing shard semantics")
    integer(receipt["semantic"].get("exit_code"), "semantic exit_code")
    try:
        campaign._validate_semantic(project, receipt["semantic"])
    except campaign.CampaignError as error:
        raise CheckpointError(str(error)) from error
    return receipt


COVERAGE = {"attempted_tus", "analyzed_tus", "broken_tus", "incomplete_functions"}
COUNTS = {"cases", "caught_cases", "floor_violations", "findings", "blocking_findings",
          "report_only_findings", "unavailable_runs"}


def _counts(mapping, label, fingerprints=False):
    require(type(mapping) is dict, f"{label}: not a counter")
    for key, value in mapping.items():
        require(type(key) is str and bool(key), f"{label}: invalid key")
        if fingerprints:
            require(re.fullmatch(r"csf1-[0-9a-f]{16}", key) is not None, "invalid fingerprint")
        integer(value, label, 1)


def validate_measurement(payload, revision, cases):
    keys(payload, ("schema_version", "revision", "analyzer_version", "corpora", "totals"), "measurement")
    integer(payload["schema_version"], "measurement schema", 1)
    require(payload["schema_version"] == 1 and payload["revision"] == revision, "measurement identity mismatch")
    require(type(payload["analyzer_version"]) is str and payload["analyzer_version"], "missing analyzer version")
    keys(payload["corpora"], measurement.CORPORA, "measurement corpora")
    keys(cases, measurement.CORPORA, "expected case catalogs")
    for name, corpus in payload["corpora"].items():
        keys(corpus, COUNTS | {"kind", "rules", "fingerprints", "coverage", "performance", "case_results"},
             f"{name} corpus")
        require(corpus["kind"] == ("real-repository" if name == "real_repo" else name), "wrong corpus kind")
        for field in COUNTS:
            integer(corpus[field], f"{name}.{field}")
        keys(corpus["coverage"], COVERAGE, "coverage")
        for field in COVERAGE:
            integer(corpus["coverage"][field], field)
        require(corpus["unavailable_runs"] == 0 and corpus["coverage"]["broken_tus"] == 0 and
                corpus["coverage"]["incomplete_functions"] == 0, "unavailable/incomplete measurement")
        require(corpus["coverage"]["attempted_tus"] >= len(cases[name]) and
                corpus["coverage"]["analyzed_tus"] >= corpus["coverage"]["attempted_tus"],
                "missing measurement TU coverage")
        if name != "real_repo":
            require(corpus["coverage"]["attempted_tus"] == len(cases[name]), "thesis TU coverage differs")
        keys(corpus["performance"], ("elapsed_ms", "peak_rss_kb"), "performance")
        integer(corpus["performance"]["elapsed_ms"], "elapsed_ms")
        if corpus["performance"]["peak_rss_kb"] is not None:
            integer(corpus["performance"]["peak_rss_kb"], "peak_rss_kb")
        _counts(corpus["rules"], "rules")
        _counts(corpus["fingerprints"], "fingerprints", fingerprints=True)
        require(type(corpus["case_results"]) is list, "missing case results")
        seen = set()
        fingerprints = Counter()
        total = caught = 0
        for case in corpus["case_results"]:
            keys(case, ("case", "floor", "findings", "complete", "fingerprints"), "case")
            identity = case["case"]
            require(type(identity) is str and identity in cases[name] and identity not in seen,
                    "missing/duplicate/substituted case")
            seen.add(identity)
            integer(case["floor"], "case floor")
            integer(case["findings"], "case findings")
            require(case["floor"] == cases[name][identity] and case["complete"] is True,
                    "wrong floor or incomplete case")
            require(case["findings"] >= case["floor"], "frozen defective floor violated")
            require(name != "clean" or case["findings"] == 0, "frozen clean case has findings")
            require(type(case["fingerprints"]) is list and
                    all(type(f) is str and re.fullmatch(r"csf1-[0-9a-f]{16}", f) for f in case["fingerprints"]),
                    "malformed case fingerprints")
            require(case["fingerprints"] == sorted(case["fingerprints"]) and
                    len(case["fingerprints"]) == case["findings"], "inconsistent case fingerprints")
            fingerprints.update(case["fingerprints"])
            total += case["findings"]
            caught += int(case["findings"] > 0)
        require(seen == set(cases[name]) and corpus["cases"] == len(seen), "case coverage mismatch")
        require(corpus["floor_violations"] == 0 and corpus["findings"] == total and
                corpus["caught_cases"] == caught and corpus["fingerprints"] == dict(fingerprints) and
                sum(corpus["rules"].values()) == total and
                corpus["blocking_findings"] + corpus["report_only_findings"] == total,
                "inconsistent corpus aggregates")
    values = list(payload["corpora"].values())
    expected = {"elapsed_ms": sum(c["performance"]["elapsed_ms"] for c in values),
                "peak_rss_kb": max(c["performance"]["peak_rss_kb"] or 0 for c in values) or None,
                "findings": sum(c["findings"] for c in values)}
    for field in ("attempted_tus", "analyzed_tus", "broken_tus"):
        expected[field] = sum(c["coverage"][field] for c in values)
    keys(payload["totals"], expected, "measurement totals")
    for field, value in payload["totals"].items():
        if field == "peak_rss_kb" and value is None:
            continue
        integer(value, field)
    require(payload["totals"] == expected, "inconsistent measurement totals")
    return payload


PROJECTS = {"nightly": ("libgit2", "rtp2httpd", "abseil", "libarchive"),
            "weekend": ("systemd", "curl", "redis", "lvgl")}


def full_matrix(manifest):
    require(set(manifest["campaigns"]) == set(PROJECTS), "checkpoint must cover both campaigns")
    require({p["id"] for p in manifest["projects"]} == set(sum(PROJECTS.values(), ())),
            "checkpoint must cover the eight pinned projects")
    result = []
    for tier, projects in PROJECTS.items():
        require(manifest["campaigns"][tier]["projects"] == list(projects) and
                manifest["campaigns"][tier]["repetitions"] == 3, "changed campaign profile")
        for side in ("base", "head"):
            for row in campaign.plan_matrix(manifest, tier)["include"]:
                result.append({"side": side, "tier": tier, **row})
    return result


def artifact_name(context, kind, side=None, project=None, repetition=None):
    validate_context(context)
    name = f"checkpoint-{context['lane']}-{context['run_id']}-{context['run_attempt']}-{kind}"
    for value in (side, project, repetition):
        if value is not None:
            name += f"-{value}"
    require(re.fullmatch(r"[a-z0-9-]+", name) is not None, "unsafe artifact name")
    return name


def artifact_files(root):
    root = Path(root).absolute()
    require(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), "unsafe artifact root")
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "symlink inside artifact")
        if path.is_dir():
            continue
        regular(path)
        relative = path.relative_to(root).as_posix()
        require(re.fullmatch(r"[A-Za-z0-9_./-]+", relative) is not None and
                all(p not in ("", ".", "..") for p in relative.split("/")), "unsafe artifact path")
        if relative != "envelope.json":
            files[relative] = file_digest(path)
    require(0 < len(files) <= 128, "missing or oversized artifact file catalog")
    return files


def load_artifact(root, config, context, inputs, kind):
    envelope = load_json(Path(root) / "envelope.json")
    keys(envelope, ("schema", "context", "config_sha256", "inputs", "kind", "details", "files"), "artifact envelope")
    require(envelope["schema"] == "codeskeptic-checkpoint-artifact/v1" and
            canonical(envelope["context"]) == canonical(validate_context(context)) and
            envelope["config_sha256"] == json_digest(validate_config(config)) and
            canonical(envelope["inputs"]) == canonical(inputs) and envelope["kind"] == kind,
            "artifact context/input identity mismatch")
    require(type(envelope["details"]) is dict and envelope["files"] == artifact_files(root),
            "artifact file/checksum mismatch")
    return envelope


SHARD_FILES = {"receipt.json", "receipt.json.sha256", "report.json", "translation-units.txt",
               "translation-units.relative.txt", "commands.log"}


def verify_raw_shard(root, manifest, project, repetition, binary_sha256):
    root = Path(root)
    receipt = load_json(root / "receipt.json")
    validate_shard(receipt, manifest, project, repetition, binary_sha256)
    # Existing exact-byte sidecar validation is retained, in addition to envelope hashes.
    try:
        require(campaign.load_verified_receipt(root / "receipt.json") == receipt, "receipt parser disagreement")
    except campaign.CampaignError as error:
        raise CheckpointError(str(error)) from error
    paths = regular(root / "translation-units.relative.txt").read_text(encoding="utf-8").splitlines()
    require(paths and paths == sorted(set(paths)) and
            all(p and not p.startswith("/") and "\\" not in p and
                all(c not in ("", ".", "..") for c in p.split("/")) for p in paths),
            "invalid or duplicated translation-unit list")
    absolute = regular(root / "translation-units.txt").read_text(encoding="utf-8").splitlines()
    require(len(absolute) == len(paths) and
            all(Path(a).is_absolute() and a.endswith("/" + p) for a, p in zip(absolute, paths)),
            "absolute and relative TU lists differ")
    report = load_json(root / "report.json")
    integer(report.get("exit_code"), "report exit code")
    try:
        semantic = campaign.semantic_from_report(campaign.project_by_id(manifest, project),
                                                receipt["semantic"]["exit_code"], report,
                                                len(paths), campaign.translation_unit_digest(paths))
    except campaign.CampaignError as error:
        raise CheckpointError(str(error)) from error
    require(semantic == receipt["semantic"], "raw report/TU list differs from accepted semantic receipt")
    return receipt


def verify_needs(needs, expected):
    keys(needs, expected, "required predecessor jobs")
    require(all(type(state) is str and state == "success" for state in needs.values()),
            "failed/skipped/cancelled/unavailable predecessor job")


def verify_realworld_bundle(root, config, context, inputs, manifest, needs, require_aggregate=False,
                            adjudications=None):
    require(context["lane"] == "realworld", "wrong bundle lane")
    verify_needs(needs, ("checkpoint-plan", "checkpoint-build", "checkpoint-scan"))
    manifests, allowed = derive_expectations(config, manifest, adjudications)
    root = Path(root)
    rows = full_matrix(manifest)
    expected_names = {artifact_name(context, "binary", side) for side in ("base", "head")}
    expected_names.update(artifact_name(context, "shard", r["side"], r["project"], r["repetition"]) for r in rows)
    if require_aggregate:
        expected_names.add(artifact_name(context, "aggregate"))
    require(root.is_dir() and {p.name for p in root.iterdir()} == expected_names, "missing/extra/duplicate artifact identity")
    binaries = {}
    for side in ("base", "head"):
        directory = root / artifact_name(context, "binary", side)
        envelope = load_artifact(directory, config, context, inputs, "binary")
        binary_sha = file_digest(directory / "codeskeptic")
        require(envelope["files"] == {"codeskeptic": binary_sha}, "binary artifact file set differs")
        require(envelope["details"] == {"side": side, "source_sha": config["base_sha"] if side == "base" else context["head_sha"],
                                        "binary_sha256": binary_sha}, "binary source/digest mismatch")
        binaries[side] = binary_sha
    receipts = {}
    with tempfile.TemporaryDirectory(prefix="codeskeptic-checkpoint-aggregate-") as temporary:
        staging = Path(temporary)
        for row in rows:
            side, project, repetition = row["side"], row["project"], row["repetition"]
            directory = root / artifact_name(context, "shard", side, project, repetition)
            envelope = load_artifact(directory, config, context, inputs, "shard")
            require(canonical(envelope["details"]) == canonical({"side": side, "project": project, "repetition": repetition,
                                                                 "binary_sha256": binaries[side]}), "wrong shard binding")
            require(set(envelope["files"]) == SHARD_FILES, "incomplete shard raw evidence")
            receipt = verify_raw_shard(directory, manifests[side], project, repetition, binaries[side])
            receipts[(side, project, repetition)] = receipt
            target = staging / side / project / f"repeat-{repetition}"
            target.mkdir(parents=True)
            for name in ("receipt.json", "receipt.json.sha256"):
                shutil.copyfile(directory / name, target / name)
        groups = {}
        for side in ("base", "head"):
            for tier in PROJECTS:
                try:
                    groups[f"{side}/{tier}"] = campaign.aggregate_receipts(manifests[side], tier, staging / side)
                except campaign.CampaignError as error:
                    raise CheckpointError(str(error)) from error
    deltas = {}
    for project in sum(PROJECTS.values(), ()):
        if adjudications is not None:
            classified = allowed.get(project, {"added": {}, "removed": {}})
            for repetition in (1, 2, 3):
                a = Counter(receipts[("base", project, repetition)]["semantic"]["fingerprints"])
                b = Counter(receipts[("head", project, repetition)]["semantic"]["fingerprints"])
                require(dict(b - a) == classified["added"] and dict(a - b) == classified["removed"],
                        "unclassified raw base/head multiset delta")
                if project in allowed:
                    require(a == Counter(classified["base"]) and b == Counter(classified["head"]),
                            "raw multiset differs from adjudicated baseline/head")
        old = receipts[("base", project, 1)]
        new = receipts[("head", project, 1)]
        a, b = Counter(old["semantic"]["fingerprints"]), Counter(new["semantic"]["fingerprints"])
        deltas[project] = {"fingerprints_added": dict(b - a), "fingerprints_removed": dict(a - b),
                           "base_seconds": [receipts[("base", project, r)]["execution"]["duration_seconds"] for r in (1, 2, 3)],
                           "head_seconds": [receipts[("head", project, r)]["execution"]["duration_seconds"] for r in (1, 2, 3)]}
    result = {"schema": "codeskeptic-checkpoint-result/v1", "context": context,
              "config_sha256": json_digest(config), "inputs": inputs, "status": "accepted",
              "scope": "artifact validation; hosted completion must be verified separately",
              "binary_sha256": binaries, "groups": groups, "deltas": deltas}
    if adjudications is not None:
        result["expectations"] = {"original_base_manifest_sha256": campaign.digest_json(manifests["base"]),
                                   "effective_head_manifest_sha256": campaign.digest_json(manifests["head"]),
                                   "adjudications_sha256": config["adjudications_sha256"]}
    if require_aggregate:
        directory = root / artifact_name(context, "aggregate")
        envelope = load_artifact(directory, config, context, inputs, "aggregate")
        require(set(envelope["files"]) == {"result.json"} and canonical(envelope["details"]) == canonical({"validated_shards": 48}) and
                canonical(load_json(directory / "result.json")) == canonical(result), "aggregate differs from revalidated raw evidence")
    return result


def verify_measurement_bundle(root, config, context, inputs, cases):
    require(context["lane"] == "measurement", "wrong measurement lane")
    root = Path(root)
    envelope = load_artifact(root, config, context, inputs, "measurement")
    require(set(envelope["files"]) == {"measurement-base.json", "measurement-head.json", "measurement-delta.json",
                                       "measurement-delta.md", "compile_commands.json", "builds.json"},
            "incomplete measurement artifact")
    keys(envelope["details"], ("base_binary_sha256", "head_binary_sha256", "compile_database_sha256"), "measurement binding")
    builds = load_json(root / "builds.json")
    keys(builds, ("base", "head"), "measurement builds")
    for side, sha in (("base", config["base_sha"]), ("head", context["head_sha"])):
        digest(envelope["details"][f"{side}_binary_sha256"])
        require(builds[side] == {"source_sha": sha, "binary_sha256": envelope["details"][f"{side}_binary_sha256"]},
                "measurement build binding mismatch")
    require(file_digest(root / "compile_commands.json") == envelope["details"]["compile_database_sha256"],
            "measurement compile database mismatch")
    database = load_json(root / "compile_commands.json", list)
    require(database and all(type(entry) is dict and type(entry.get("file")) is str and
                            Path(entry["file"]).is_absolute() and type(entry.get("directory")) is str and
                            Path(entry["directory"]).is_absolute() and
                            ((type(entry.get("command")) is str and bool(entry["command"])) or
                             (type(entry.get("arguments")) is list and entry["arguments"] and
                              all(type(item) is str for item in entry["arguments"]))) for entry in database),
            "missing/malformed bound compile database")
    base = validate_measurement(load_json(root / "measurement-base.json"), config["base_sha"], cases)
    head = validate_measurement(load_json(root / "measurement-head.json"), context["head_sha"], cases)
    for name in measurement.CORPORA:
        require(base["corpora"][name]["coverage"]["attempted_tus"] == head["corpora"][name]["coverage"]["attempted_tus"],
                "base/head attempted TU coverage differs")
    comparison, failures = measurement.compare(base, head)
    require(not failures, "measurement regression: " + "; ".join(failures))
    require(canonical(load_json(root / "measurement-delta.json")) == canonical(comparison),
            "comparison receipt was substituted")
    require((root / "measurement-delta.md").read_text(encoding="utf-8") == measurement.render(comparison),
            "comparison report differs")
    return comparison


def verify_hosted(run, jobs, context, expected_job_names):
    """Use externally fetched GitHub run/attempt jobs, never an artifact's self-claim."""
    validate_context(context)
    require(type(run) is dict and type(jobs) is dict, "missing hosted API evidence")
    require(type(run.get("repository")) is dict, "missing hosted repository identity")
    require(type(run.get("id")) is int and str(run["id"]) == context["run_id"] and
            type(run.get("run_attempt")) is int and str(run["run_attempt"]) == context["run_attempt"] and
            run.get("head_sha") == context["head_sha"] and run.get("head_branch") == context["ref"][11:] and
            run.get("event") == "push" and run.get("status") == "completed" and run.get("conclusion") == "success" and
            run.get("repository", {}).get("full_name") == context["repository"], "hosted run identity/conclusion mismatch")
    require(run.get("path") == f".github/workflows/{context['lane']}.yml", "wrong hosted workflow")
    require(type(jobs.get("jobs")) is list and type(jobs.get("total_count")) is int and
            jobs["total_count"] == len(jobs["jobs"]), "incomplete/paginated hosted job evidence")
    selected = {}
    ids = set()
    for job in jobs["jobs"]:
        require(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids,
                "duplicate/malformed hosted job")
        ids.add(job["id"])
        name = job.get("name")
        require(type(name) is str, "missing job name")
        if not name.startswith("checkpoint-"):
            continue  # Preserved legacy jobs are deliberately skipped on push.
        require(name not in selected, "duplicate checkpoint job")
        require(job.get("run_id") == run["id"] and type(job.get("run_id")) is int and
                type(job.get("run_attempt")) is int and str(job["run_attempt"]) == context["run_attempt"] and
                job.get("head_sha") == context["head_sha"] and
                job.get("status") == "completed" and job.get("conclusion") == "success",
                "failed/skipped/cancelled/unavailable checkpoint job")
        selected[name] = job
    require(set(selected) == set(expected_job_names), "missing/extra checkpoint jobs")
    return True


def expected_jobs(context, manifest):
    if context["lane"] == "measurement":
        return {"checkpoint-plan", "checkpoint-measurement"}
    result = {"checkpoint-plan", "checkpoint-build-base", "checkpoint-build-head", "checkpoint-aggregate"}
    result.update(f"checkpoint-scan-{r['side']}-{r['project']}-{r['repetition']}" for r in full_matrix(manifest))
    return result


def expected_artifacts(context, manifest):
    if context["lane"] == "measurement":
        return {artifact_name(context, "measurement")}
    result = {artifact_name(context, "binary", side) for side in ("base", "head")}
    result.update(artifact_name(context, "shard", r["side"], r["project"], r["repetition"]) for r in full_matrix(manifest))
    result.add(artifact_name(context, "aggregate"))
    return result


def verify_catalog(catalog, context, expected_names):
    require(type(catalog) is dict and type(catalog.get("artifacts")) is list and
            type(catalog.get("total_count")) is int and catalog["total_count"] == len(catalog["artifacts"]),
            "incomplete/paginated artifact catalog")
    selected, ids = {}, set()
    prefix = f"checkpoint-{context['lane']}-{context['run_id']}-{context['run_attempt']}-"
    for artifact in catalog["artifacts"]:
        require(type(artifact) is dict and type(artifact.get("id")) is int and artifact["id"] > 0 and
                artifact["id"] not in ids and type(artifact.get("name")) is str, "duplicate/malformed artifact catalog")
        ids.add(artifact["id"])
        name = artifact["name"]
        if not name.startswith(prefix):
            continue  # Other attempts/legacy artifacts cannot fill this attempt's set.
        require(name in expected_names and name not in selected, "unexpected/duplicate artifact identity")
        binding = artifact.get("workflow_run")
        require(type(binding) is dict and type(binding.get("id")) is int and str(binding["id"]) == context["run_id"] and
                binding.get("head_sha") == context["head_sha"] and binding.get("head_branch") == context["ref"][11:],
                "artifact belongs to another run/head")
        require(artifact.get("expired") is False and type(artifact.get("digest")) is str and
                re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is not None, "expired or undigested artifact")
        integer(artifact.get("size_in_bytes"), "artifact size", 1)
        require(artifact["size_in_bytes"] <= 2 * 1024**3, "oversized archive download")
        selected[name] = artifact
    require(set(selected) == set(expected_names), "missing artifact identities")
    require(sum(a["size_in_bytes"] for a in selected.values()) <= 8 * 1024**3, "artifact download budget exceeded")
    return selected


def unpack_archives(archives, destination, selected):
    """Verify API archive digests BEFORE extracting; no duplicate member overwrite."""
    destination = Path(destination).absolute()
    require(destination.is_dir() and not list(destination.iterdir()) and
            not any(p.is_symlink() for p in (destination, *destination.parents)), "extraction root must be fresh")
    total_size = 0
    for name, artifact in sorted(selected.items()):
        require(re.fullmatch(r"[a-z0-9-]+", name) is not None, "unsafe artifact directory")
        archive = regular(Path(archives) / f"{artifact['id']}.zip")
        require(archive.stat().st_size == artifact["size_in_bytes"] and "sha256:" + file_digest(archive) == artifact["digest"],
                "downloaded artifact archive digest/size mismatch")
        with zipfile.ZipFile(archive) as stream:
            members = stream.infolist()
            size = sum(m.file_size for m in members)
            total_size += size
            require(0 < len(members) <= 256 and size <= 2 * 1024**3 and total_size <= 8 * 1024**3,
                    "oversized/empty archive")
            paths = set()
            for member in members:
                path = member.filename.rstrip("/")
                require(path and not path.startswith("/") and "\\" not in path and
                        re.fullmatch(r"[A-Za-z0-9_./-]+", path) is not None and
                        all(p not in ("", ".", "..") for p in path.split("/")) and path not in paths,
                        "unsafe or duplicate archive member")
                paths.add(path)
                mode = (member.external_attr >> 16) & 0o170000
                require(mode in (0, 0o100000, 0o040000) and not member.flag_bits & 1, "nonregular/encrypted archive member")
            target = destination / name
            target.mkdir()
            for member in members:
                output = target / member.filename
                if member.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with stream.open(member) as source, output.open("xb") as sink:
                        shutil.copyfileobj(source, sink, length=1024 * 1024)


def main():
    import argparse
    import sys
    import run_regression_checkpoint as runner

    parser = argparse.ArgumentParser(description="Verify externally fetched exact-run checkpoint evidence; never run a campaign")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--adjudications", type=Path, help="exact canonical v2 head-adjudication file; forbidden for v1")
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--inputs-root", type=Path, required=True)
    parser.add_argument("--run-json", type=Path, required=True)
    parser.add_argument("--jobs-json", type=Path, required=True)
    parser.add_argument("--catalog-json", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True, help="exact API artifact-ID.zip downloads")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = validate_config(load_json(args.config))
        adjudications = load_adjudications(config, args.adjudications)
        require(config["enabled"], "disabled preparation cannot qualify")
        context = validate_context(load_json(args.context))
        inputs, manifest = runner.collect_inputs(args.inputs_root, config)
        derive_expectations(config, manifest, adjudications)  # Also validate control data in the measurement lane.
        verify_hosted(load_json(args.run_json), load_json(args.jobs_json), context, expected_jobs(context, manifest))
        selected = verify_catalog(load_json(args.catalog_json), context, expected_artifacts(context, manifest))
        with tempfile.TemporaryDirectory(prefix="codeskeptic-checkpoint-download-") as directory:
            root = Path(directory)
            unpack_archives(args.archives, root, selected)
            if context["lane"] == "realworld":
                result = verify_realworld_bundle(root, config, context, inputs, manifest,
                                                {name: "success" for name in ("checkpoint-plan", "checkpoint-build", "checkpoint-scan")},
                                                require_aggregate=True, adjudications=adjudications)
            else:
                result = verify_measurement_bundle(root / artifact_name(context, "measurement"), config, context,
                                                   inputs, runner.thesis_cases(args.inputs_root))
        source_digests = {name: file_digest(path) for name, path in (
            ("run", args.run_json), ("jobs", args.jobs_json), ("catalog", args.catalog_json))}
        if adjudications is not None:
            source_digests["adjudications"] = file_digest(args.adjudications)
        runner.write_json(args.output, {"schema": "codeskeptic-hosted-checkpoint-validation/v1", "context": context,
                                       "config_sha256": json_digest(config), "status": "accepted", "result": result,
                                       "source_digests": source_digests,
                                       "provenance": "caller must obtain API evidence from GitHub independently; not a signed attestation"})
        print("CHECKPOINT_VALIDATION_OK exact run/attempt, jobs, archive digests and raw evidence")
    except (ValueError, campaign.CampaignError, OSError, zipfile.BadZipFile) as error:
        print(f"CHECKPOINT_VALIDATION_FAIL {error}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
