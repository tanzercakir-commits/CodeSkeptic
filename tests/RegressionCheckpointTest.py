#!/usr/bin/env python3
"""Fail-closed checkpoint contracts; fixtures are never hosted qualification."""
from __future__ import annotations

import copy
import importlib.util
import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_regression_checkpoint as verify
import run_realworld_campaign as campaign
import run_measurement_lab as lab
import run_regression_checkpoint as runner

spec = importlib.util.spec_from_file_location("realworld_fixture", ROOT / "tests/RealworldCampaignTest.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def config():
    return {"schema": "codeskeptic-regression-checkpoint/v1", "enabled": True,
            "request_id": "qualification-001", "base_sha": "a" * 40, "inputs_sha": "a" * 40,
            "profile": "nightly-weekend-three-repeats", "manifest_sha256": "c" * 64}


def context(lane="realworld"):
    return {"head_sha": "b" * 40, "workflow_sha": "b" * 40, "run_id": "123",
            "run_attempt": "1", "repository": "tanzercakir-commits/CodeSkeptic",
            "ref": "refs/heads/agent/cs3-ch01-s07-u003-checkpoint", "lane": lane}


def measurement(revision):
    result = {"schema_version": 1, "revision": revision, "analyzer_version": "fixture-only",
              "corpora": {}, "totals": {}}
    for name, kind, case, floor, count in (
        ("clean", "clean", "safe.c", 0, 0),
        ("defective", "defective", "bug.c", 1, 1),
        ("real_repo", "real-repository", "codeskeptic/src", 0, 0),
    ):
        value = lab.new_corpus(kind)
        value.update(cases=1, caught_cases=int(count > 0), findings=count,
                     blocking_findings=count, rules={"fixture": count} if count else {},
                     fingerprints={"csf1-0000000000000001": count} if count else {},
                     case_results=[{"case": case, "floor": floor, "findings": count,
                                    "complete": True, "fingerprints": ["csf1-0000000000000001"] * count}])
        value["coverage"].update(attempted_tus=1, analyzed_tus=1)
        result["corpora"][name] = lab.finalize(value)
    result["totals"] = {"elapsed_ms": 0, "peak_rss_kb": None, "attempted_tus": 3,
                        "analyzed_tus": 3, "broken_tus": 0, "findings": 1}
    return result


CASES = {"clean": {"safe.c": 0}, "defective": {"bug.c": 1}, "real_repo": {"codeskeptic/src": 0}}


class InputContractTest(unittest.TestCase):
    def test_config_and_context_are_strict_and_same_input(self):
        self.assertEqual(verify.validate_config(config()), config())
        self.assertEqual(verify.validate_context(context()), context())
        for field, value in (("enabled", 1), ("base_sha", "main"), ("inputs_sha", "b" * 40),
                             ("request_id", "../x"), ("profile", "nightly-only"),
                             ("manifest_sha256", "x" * 64), ("unreviewed", True)):
            changed = config()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(verify.CheckpointError):
                verify.validate_config(changed)
        for field, value in (("run_id", 123), ("run_attempt", "0"), ("workflow_sha", "c" * 40),
                             ("ref", "refs/heads/main"), ("repository", "another/project"),
                             ("lane", "unreviewed")):
            changed = context()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(verify.CheckpointError):
                verify.validate_context(changed)

    def test_request_requires_explicit_enabled_changed_head_not_inherited_state(self):
        self.assertTrue(verify.request_selected(config(), True))
        self.assertFalse(verify.request_selected(config(), False))
        disabled = config()
        disabled["enabled"] = False
        self.assertFalse(verify.request_selected(disabled, True))
        with self.assertRaises(verify.CheckpointError):
            verify.request_selected(config(), 1)

    def test_json_rejects_duplicates_nonfinite_values_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}', '[]'):
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(verify.CheckpointError):
                    verify.load_json(path)
            path.write_text('{"a":1}')
            self.assertEqual(verify.load_json(path), {"a": 1})
            link = path.with_name("link.json")
            link.symlink_to(path)
            with self.assertRaises(verify.CheckpointError):
                verify.load_json(link)


class ShardContractTest(unittest.TestCase):
    def setUp(self):
        self.manifest = campaign.validate_manifest(fixtures.fixture_manifest())
        self.receipt = fixtures.accepted_receipt(self.manifest, 1)
        self.project = self.manifest["projects"][0]

    def check(self, receipt):
        return verify.validate_shard(receipt, self.manifest, "alpha", 1, "b" * 64)

    def test_valid_fixture_and_extra_analysis_tus_are_allowed(self):
        self.check(self.receipt)
        self.manifest["projects"][0]["expected"]["analyzed_tus"] = 3
        self.receipt = fixtures.accepted_receipt(self.manifest, 1)
        self.check(self.receipt)

    def test_strict_types_close_existing_bool_float_and_resume_gaps(self):
        for path, value in (("schema", True), ("schema", 1.0), ("repetition", True),
                            ("identity.repetition", True), ("semantic.exit_code", True),
                            ("semantic.exit_code", 1.0), ("execution.duration_seconds", True),
                            ("execution.duration_seconds", float("inf")),
                            ("execution.resumed", True), ("execution.resumed", 0)):
            changed = copy.deepcopy(self.receipt)
            node = changed
            parts = path.split(".")
            for key in parts[:-1]:
                node = node[key]
            node[parts[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(verify.CheckpointError):
                self.check(changed)

    def test_wrong_identity_unavailable_and_pin_drift_rejected(self):
        for path, value in (("status", "unavailable"), ("project", "substituted"),
                            ("identity.analyzer_sha256", "d" * 64),
                            ("identity.project_revision", "e" * 40),
                            ("identity.manifest_sha256", "f" * 64),
                            ("semantic.coverage.analyzed_tus", 1),
                            ("semantic.fingerprint_sha256", "a" * 64)):
            changed = copy.deepcopy(self.receipt)
            node = changed
            parts = path.split(".")
            for key in parts[:-1]:
                node = node[key]
            node[parts[-1]] = value
            with self.subTest(path=path), self.assertRaises(verify.CheckpointError):
                self.check(changed)


class MeasurementContractTest(unittest.TestCase):
    def check(self, payload):
        return verify.validate_measurement(payload, "a" * 40, CASES)

    def test_positive_and_report_only_timing(self):
        payload = measurement("a" * 40)
        self.check(payload)
        payload["corpora"]["real_repo"]["performance"]["elapsed_ms"] = 20000
        payload["totals"]["elapsed_ms"] = 20000
        self.check(payload)

    def test_wrong_revision_missing_same_length_case_and_counter_forgery(self):
        for mutation in ("revision", "case", "missing-case", "coverage", "boolean", "totals", "fingerprints",
                         "clean-fp", "floor", "unavailable", "incomplete"):
            payload = measurement("a" * 40)
            corpus = payload["corpora"]["defective"]
            if mutation == "revision":
                payload["revision"] = "b" * 40
            elif mutation == "case":
                corpus["case_results"][0]["case"] = "substituted.c"
            elif mutation == "missing-case":
                corpus["case_results"] = []
            elif mutation == "coverage":
                corpus["coverage"]["attempted_tus"] = 0
            elif mutation == "boolean":
                corpus["cases"] = True
            elif mutation == "totals":
                payload["totals"]["findings"] = 0
            elif mutation == "fingerprints":
                corpus["fingerprints"] = {"csf1-0000000000000002": 1}
            elif mutation == "clean-fp":
                payload["corpora"]["clean"]["findings"] = 1
            elif mutation == "floor":
                corpus["case_results"][0]["floor"] = 0
            elif mutation == "unavailable":
                corpus["unavailable_runs"] = 1
            elif mutation == "incomplete":
                corpus["coverage"]["incomplete_functions"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(verify.CheckpointError):
                self.check(payload)


def full_fixture_manifest():
    raw = fixtures.fixture_manifest()
    prototype = raw["projects"][0]
    raw["projects"] = []
    raw["campaigns"] = {tier: {"window_minutes": 720 if tier == "nightly" else 2880,
                               "repetitions": 3, "projects": list(projects)}
                        for tier, projects in verify.PROJECTS.items()}
    for index, identity in enumerate(sum(verify.PROJECTS.values(), ())):
        project = copy.deepcopy(prototype)
        project["id"] = identity
        project["revision"] = f"{index + 1:040x}"
        paths = [f"src/{identity}_one.c", f"src/{identity}_two.c"]
        fingerprints = [] if index == 1 else [f"csf1-{index + 1:016x}"]
        project["expected"].update(translation_unit_sha256=campaign.translation_unit_digest(paths),
                                   fingerprint_sha256=campaign.fingerprint_digest(fingerprints),
                                   findings=len(fingerprints), exit_code=int(bool(fingerprints)),
                                   analyzed_tus=3 if index == 0 else 2)
        raw["projects"].append(project)
    return campaign.validate_manifest(raw)


def make_bundle(root, cfg=None, ctx=None, inputs=None, manifest=None):
    manifest = full_fixture_manifest() if manifest is None else manifest
    cfg = config() if cfg is None else cfg
    ctx = context() if ctx is None else ctx
    cfg["manifest_sha256"] = campaign.digest_json(manifest)
    inputs = {"fixture_only": True, "source_sha": cfg["inputs_sha"]} if inputs is None else inputs
    binary_digests = {}
    for side in ("base", "head"):
        directory = root / verify.artifact_name(ctx, "binary", side)
        directory.mkdir()
        (directory / "codeskeptic").write_bytes(f"fixture-only-{side}".encode())
        binary_digests[side] = verify.file_digest(directory / "codeskeptic")
        runner.seal_artifact(directory, cfg, ctx, inputs, "binary",
                             {"side": side, "source_sha": cfg["base_sha"] if side == "base" else ctx["head_sha"],
                              "binary_sha256": binary_digests[side]})
    for row in verify.full_matrix(manifest):
        side, project, repetition = row["side"], row["project"], row["repetition"]
        index = next(i for i, p in enumerate(manifest["projects"]) if p["id"] == project)
        receipt = fixtures.accepted_receipt(manifest, repetition, index, binary_digests[side])
        fingerprints = [] if index == 1 else [f"csf1-{index + 1:016x}"]
        receipt["semantic"]["fingerprints"] = fingerprints
        directory = root / verify.artifact_name(ctx, "shard", side, project, repetition)
        directory.mkdir()
        campaign.write_receipt(directory / "receipt.json", receipt)
        paths = [f"src/{project}_one.c", f"src/{project}_two.c"]
        (directory / "translation-units.relative.txt").write_text("\n".join(paths) + "\n")
        (directory / "translation-units.txt").write_text("\n".join(f"/fixture/{project}/{p}" for p in paths) + "\n")
        (directory / "commands.log").write_text("synthetic test fixture, no execution\n")
        report = {"exit_code": receipt["semantic"]["exit_code"], "complete": True,
                  "coverage": receipt["semantic"]["coverage"], "total": len(fingerprints),
                  "diagnostics": [{"fingerprint": fingerprint} for fingerprint in fingerprints]}
        runner.write_json(directory / "report.json", report)
        runner.seal_artifact(directory, cfg, ctx, inputs, "shard",
                             {"side": side, "project": project, "repetition": repetition,
                              "binary_sha256": binary_digests[side]})
    return cfg, ctx, inputs, manifest


NEEDS = {name: "success" for name in ("checkpoint-plan", "checkpoint-build", "checkpoint-scan")}


def refresh_fixture_envelope(directory):
    path = directory / "envelope.json"
    payload = verify.load_json(path)
    payload["files"] = verify.artifact_files(directory)
    path.write_bytes(verify.canonical(payload))


class ArtifactBundleTest(unittest.TestCase):
    def test_all_48_fresh_cells_four_groups_and_distinct_side_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, ctx, inputs, manifest = make_bundle(root)
            result = verify.verify_realworld_bundle(root, cfg, ctx, inputs, manifest, NEEDS)
            self.assertEqual(len(verify.full_matrix(manifest)), 48)
            self.assertEqual(len(result["groups"]), 4)
            self.assertEqual(len(result["deltas"]), 8)
            self.assertNotEqual(result["binary_sha256"]["base"], result["binary_sha256"]["head"])
            self.assertEqual(result["status"], "accepted")
            self.assertIn("hosted completion must be verified separately", result["scope"])

    def test_external_aggregate_is_recomputed_including_rehashed_forgeries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, ctx, inputs, manifest = make_bundle(root)
            result = verify.verify_realworld_bundle(root, cfg, ctx, inputs, manifest, NEEDS)
            aggregate = root / verify.artifact_name(ctx, "aggregate")
            aggregate.mkdir()
            runner.write_json(aggregate / "result.json", result)
            runner.seal_artifact(aggregate, cfg, ctx, inputs, "aggregate", {"validated_shards": 48})
            self.assertEqual(verify.verify_realworld_bundle(root, cfg, ctx, inputs, manifest, NEEDS,
                                                           require_aggregate=True), result)
            original = verify.load_json(aggregate / "envelope.json")
            for mutation in ("status", "missing-group", "timing", "details"):
                changed = copy.deepcopy(result)
                envelope = copy.deepcopy(original)
                if mutation == "status":
                    changed["status"] = "forged-pass"
                elif mutation == "missing-group":
                    del changed["groups"]["head/weekend"]
                elif mutation == "timing":
                    changed["deltas"]["libgit2"]["head_seconds"][1] += 1
                else:
                    envelope["details"]["validated_shards"] = 48.0
                (aggregate / "result.json").write_bytes(verify.canonical(changed))
                (aggregate / "envelope.json").write_bytes(verify.canonical(envelope))
                refresh_fixture_envelope(aggregate)
                with self.subTest(mutation=mutation), self.assertRaises(verify.CheckpointError):
                    verify.verify_realworld_bundle(root, cfg, ctx, inputs, manifest, NEEDS, require_aggregate=True)

    def test_missing_corrupt_substituted_and_rehashed_raw_evidence_fail(self):
        mutations = ("missing-middle", "extra-repeat", "corrupt-binary", "checksum", "swapped-project",
                     "wrong-attempt", "wrong-head", "wrong-input", "bool-binding", "resumed", "bool-schema",
                     "report-coverage", "substituted-tu", "absolute-tu", "sidecar", "symlink", "extra-file")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cfg, ctx, inputs, manifest = make_bundle(root)
                shard = root / verify.artifact_name(ctx, "shard", "head", "libgit2", 2)
                envelope = shard / "envelope.json"
                if mutation == "missing-middle":
                    shutil.rmtree(shard)
                elif mutation == "extra-repeat":
                    shutil.copytree(shard, root / verify.artifact_name(ctx, "shard", "head", "libgit2", 4))
                elif mutation == "corrupt-binary":
                    binary = root / verify.artifact_name(ctx, "binary", "head") / "codeskeptic"
                    binary.write_bytes(b"different binary")
                elif mutation == "checksum":
                    (shard / "commands.log").write_text("corrupt bytes")
                elif mutation in ("wrong-attempt", "wrong-head", "wrong-input", "bool-binding"):
                    value = verify.load_json(envelope)
                    if mutation == "wrong-attempt":
                        value["context"]["run_attempt"] = "2"
                    elif mutation == "wrong-head":
                        value["context"]["head_sha"] = "d" * 40
                    elif mutation == "wrong-input":
                        value["inputs"]["source_sha"] = "d" * 40
                    else:
                        value["details"]["repetition"] = True
                    envelope.write_bytes(verify.canonical(value))
                elif mutation in ("swapped-project", "resumed", "bool-schema"):
                    value = verify.load_json(shard / "receipt.json")
                    if mutation == "swapped-project":
                        value["project"] = "curl"
                    elif mutation == "resumed":
                        value["execution"]["resumed"] = True
                    else:
                        value["schema"] = True
                    campaign.write_receipt(shard / "receipt.json", value)
                    refresh_fixture_envelope(shard)
                elif mutation == "report-coverage":
                    value = verify.load_json(shard / "report.json")
                    value["coverage"]["analyzed_tus"] = 2
                    (shard / "report.json").write_bytes(verify.canonical(value))
                    refresh_fixture_envelope(shard)
                elif mutation == "substituted-tu":
                    (shard / "translation-units.relative.txt").write_text("src/a.c\nsrc/b.c\n")
                    refresh_fixture_envelope(shard)
                elif mutation == "absolute-tu":
                    (shard / "translation-units.txt").write_text("/unrelated/a.c\n/unrelated/b.c\n")
                    refresh_fixture_envelope(shard)
                elif mutation == "sidecar":
                    (shard / "receipt.json.sha256").write_text("0" * 64 + "  receipt.json\n")
                    refresh_fixture_envelope(shard)
                elif mutation == "symlink":
                    target = shard / "commands.log"
                    target.unlink()
                    target.symlink_to(shard / "receipt.json")
                elif mutation == "extra-file":
                    (shard / "unexpected.json").write_text("{}")
                    refresh_fixture_envelope(shard)
                with self.assertRaises(verify.CheckpointError):
                    verify.verify_realworld_bundle(root, cfg, ctx, inputs, manifest, NEEDS)

    def test_failed_skipped_cancelled_missing_predecessors_are_not_success(self):
        for name in NEEDS:
            for state in ("failure", "skipped", "cancelled", "unavailable", True):
                value = {**NEEDS, name: state}
                with self.subTest(name=name, state=state), self.assertRaises(verify.CheckpointError):
                    verify.verify_needs(value, NEEDS)
        with self.assertRaises(verify.CheckpointError):
            verify.verify_needs({"checkpoint-scan": "success"}, NEEDS)


class ControllerContractTest(unittest.TestCase):
    def input_fixture(self, root):
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
        git("init", "-q", "--initial-branch=fixture")
        git("config", "user.name", "fixture")
        git("config", "user.email", "fixture@invalid.local")
        manifest = full_fixture_manifest()
        manifest["projects"][0]["copies"] = [{"from": "profiles/contracts/fixture.csk", "to": "fixture.csk"}]
        for relative, content in {
            "scripts/realworld_manifest.json": json.dumps(manifest),
            "profiles/contracts/fixture.csk": "original profile\n",
            "src/sample.c": "int sample(void) { return 0; }\n",
            "tests/thesis_corpus/thesis_expected.txt": "safe.c CLEAN 0\nbug.c BUG 1\n",
            "tests/thesis_corpus/safe.c": "int safe(void) { return 0; }\n",
            "tests/thesis_corpus/bug.c": "int bug(void) { int *p=0; return *p; }\n",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        git("add", ".")
        git("commit", "-qm", "immutable fixture inputs")
        cfg = config()
        cfg["base_sha"] = cfg["inputs_sha"] = git("rev-parse", "HEAD")
        cfg["manifest_sha256"] = campaign.digest_json(campaign.validate_manifest(manifest))
        return cfg, git

    def test_input_identity_binds_copied_profile_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, git = self.input_fixture(root)
            before, manifest = runner.collect_inputs(root, cfg)
            self.assertEqual(before["manifest_sha256"], campaign.digest_json(manifest))
            self.assertIn("profiles/contracts/fixture.csk", before["copied_profiles"])
            (root / "profiles/contracts/fixture.csk").write_text("changed profile\n")
            with self.assertRaises(verify.CheckpointError):
                runner.collect_inputs(root, cfg)
            git("add", ".")
            git("commit", "-qm", "changed fixture input")
            cfg["base_sha"] = cfg["inputs_sha"] = git("rev-parse", "HEAD")
            after, _ = runner.collect_inputs(root, cfg)
            self.assertNotEqual(before["tree_sha256"], after["tree_sha256"])
            self.assertNotEqual(before["copied_profiles"], after["copied_profiles"])

    def test_clean_status_cannot_hide_input_bytes_different_from_pinned_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, git = self.input_fixture(root)
            git("update-index", "--assume-unchanged", "profiles/contracts/fixture.csk")
            (root / "profiles/contracts/fixture.csk").write_text("hidden drift\n")
            self.assertEqual(git("status", "--porcelain"), "")
            with self.assertRaises(verify.CheckpointError):
                runner.collect_inputs(root, cfg)

    def test_ignored_extra_source_cannot_enter_the_fixed_input_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, git = self.input_fixture(root)
            (root / ".gitignore").write_text("ignored.c\n")
            git("add", ".gitignore")
            git("commit", "-qm", "fixture ignore policy")
            cfg["base_sha"] = cfg["inputs_sha"] = git("rev-parse", "HEAD")
            (root / "src/ignored.c").write_text("int unwanted(void) { return 1; }\n")
            self.assertEqual(git("status", "--porcelain"), "")
            with self.assertRaises(verify.CheckpointError):
                runner.collect_inputs(root, cfg)

    def test_existing_output_is_never_reused_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "keep").write_text("preserve")
            with self.assertRaises(FileExistsError):
                runner.fresh_dir(root)
            self.assertEqual((root / "keep").read_text(), "preserve")
            path = root / "receipt.json"
            runner.write_json(path, {"old": True})
            with self.assertRaises(verify.CheckpointError):
                runner.write_json(path, {"new": True})
            self.assertEqual(verify.load_json(path), {"old": True})

    def test_real_git_gate_requires_new_request_in_final_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
            git("init", "-q", "--initial-branch=fixture")
            git("config", "user.name", "fixture")
            git("config", "user.email", "fixture@invalid.local")
            (root / "input").write_text("fixture")
            git("add", "input")
            git("commit", "-qm", "fixture base")
            base = git("rev-parse", "HEAD")
            cfg = config()
            cfg["base_sha"] = cfg["inputs_sha"] = base
            (root / "ci").mkdir()
            request = root / runner.REQUEST
            request.write_bytes(verify.canonical(cfg))
            git("add", "ci")
            git("commit", "-qm", "explicit request")
            ctx = context()
            ctx["head_sha"] = ctx["workflow_sha"] = git("rev-parse", "HEAD")
            self.assertTrue(runner.request_at_head(root, cfg, ctx))
            (root / "ledger").write_text("ordinary push")
            git("add", "ledger")
            git("commit", "-qm", "ordinary ledger")
            ctx["head_sha"] = ctx["workflow_sha"] = git("rev-parse", "HEAD")
            self.assertFalse(runner.request_at_head(root, cfg, ctx))
            cfg["request_id"] = "qualification-002"
            request.write_bytes(verify.canonical(cfg))
            with self.assertRaises(verify.CheckpointError):
                runner.request_at_head(root, cfg, ctx)  # uncommitted request is never eligible
            git("add", "ci")
            git("commit", "-qm", "new exact checkpoint")
            ctx["head_sha"] = ctx["workflow_sha"] = git("rev-parse", "HEAD")
            self.assertTrue(runner.request_at_head(root, cfg, ctx))


class HostedContractTest(unittest.TestCase):
    def fixture(self):
        ctx = context("measurement")
        run = {"id": 123, "run_attempt": 1, "head_sha": ctx["head_sha"], "head_branch": ctx["ref"][11:],
               "repository": {"full_name": ctx["repository"]}, "event": "push", "status": "completed",
               "conclusion": "success", "path": ".github/workflows/measurement.yml"}
        names = {"checkpoint-plan", "checkpoint-measurement"}
        jobs = {"total_count": 2, "jobs": [{"id": index, "run_id": 123, "run_attempt": 1,
                                           "head_sha": ctx["head_sha"], "name": name,
                                           "status": "completed", "conclusion": "success"}
                                          for index, name in enumerate(sorted(names), 1)]}
        return ctx, run, jobs, names

    def test_same_head_complete_run_and_exact_jobs(self):
        ctx, run, jobs, names = self.fixture()
        self.assertTrue(verify.verify_hosted(run, jobs, ctx, names))

    def test_wrong_run_identity_missing_jobs_and_non_success_are_rejected(self):
        for mutation in ("run", "head", "workflow", "attempt", "job-attempt", "missing-job-attempt", "bool-job-attempt", "missing", "duplicate",
                         "skipped", "cancelled", "unavailable", "in_progress", "wrong-job"):
            ctx, run, jobs, names = self.fixture()
            if mutation == "run":
                run["id"] += 1
            elif mutation == "head":
                run["head_sha"] = "c" * 40
            elif mutation == "workflow":
                run["path"] = ".github/workflows/other.yml"
            elif mutation == "attempt":
                run["run_attempt"] = 2
            elif mutation == "job-attempt":
                jobs["jobs"][0]["run_attempt"] = 2
            elif mutation == "missing-job-attempt":
                del jobs["jobs"][0]["run_attempt"]
            elif mutation == "bool-job-attempt":
                jobs["jobs"][0]["run_attempt"] = True
            elif mutation == "missing":
                jobs["jobs"].pop()
            elif mutation == "duplicate":
                jobs["jobs"][1] = copy.deepcopy(jobs["jobs"][0])
            elif mutation == "in_progress":
                run["status"] = "in_progress"
            elif mutation == "wrong-job":
                jobs["jobs"][0]["name"] = "checkpoint-unrelated"
            else:
                jobs["jobs"][0]["conclusion"] = mutation
            with self.subTest(mutation=mutation), self.assertRaises(verify.CheckpointError):
                verify.verify_hosted(run, jobs, ctx, names)


class MeasurementArtifactTest(unittest.TestCase):
    def fixture(self, root, cfg=None, ctx=None, inputs=None):
        cfg = config() if cfg is None else cfg
        ctx = context("measurement") if ctx is None else ctx
        inputs = {"fixture_only": True} if inputs is None else inputs
        base, head = measurement(cfg["base_sha"]), measurement(ctx["head_sha"])
        comparison, failures = verify.measurement.compare(base, head)
        self.assertFalse(failures)
        runner.write_json(root / "measurement-base.json", base)
        runner.write_json(root / "measurement-head.json", head)
        runner.write_json(root / "measurement-delta.json", comparison)
        (root / "measurement-delta.md").write_text(verify.measurement.render(comparison))
        runner.write_json(root / "compile_commands.json", [{"directory": "/fixture", "file": "/fixture/src/a.c", "command": "clang-20 -c /fixture/src/a.c"}])
        runner.write_json(root / "builds.json", {"base": {"source_sha": cfg["base_sha"], "binary_sha256": "d" * 64},
                                                "head": {"source_sha": ctx["head_sha"], "binary_sha256": "e" * 64}})
        runner.seal_artifact(root, cfg, ctx, inputs, "measurement", {"base_binary_sha256": "d" * 64,
                            "head_binary_sha256": "e" * 64, "compile_database_sha256": verify.file_digest(root / "compile_commands.json")})
        return cfg, ctx, inputs

    def test_complete_measurement_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg, ctx, inputs = self.fixture(root)
            self.assertEqual(verify.verify_measurement_bundle(root, cfg, ctx, inputs, CASES)["gate"], "pass")

    def test_rehashed_delta_rejects_bool_float_equivalence(self):
        for value in (True, 1.0):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cfg, ctx, inputs = self.fixture(root)
                path = root / "measurement-delta.json"
                delta = verify.load_json(path)
                delta["schema_version"] = value
                path.write_bytes(verify.canonical(delta))
                refresh_fixture_envelope(root)
                with self.assertRaises(verify.CheckpointError):
                    verify.verify_measurement_bundle(root, cfg, ctx, inputs, CASES)

    def test_rehashed_build_identity_delta_and_compile_database_forgery(self):
        for mutation in ("build", "delta", "compile-db", "report", "coverage", "empty-db"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cfg, ctx, inputs = self.fixture(root)
                if mutation == "build":
                    value = verify.load_json(root / "builds.json")
                    value["base"]["source_sha"] = ctx["head_sha"]
                    (root / "builds.json").write_bytes(verify.canonical(value))
                elif mutation == "delta":
                    value = verify.load_json(root / "measurement-delta.json")
                    value["gate"] = "forged-pass"
                    (root / "measurement-delta.json").write_bytes(verify.canonical(value))
                elif mutation == "compile-db":
                    (root / "compile_commands.json").write_text("[]")
                elif mutation == "empty-db":
                    (root / "compile_commands.json").write_text("[]")
                    envelope = verify.load_json(root / "envelope.json")
                    envelope["details"]["compile_database_sha256"] = verify.file_digest(root / "compile_commands.json")
                    (root / "envelope.json").write_bytes(verify.canonical(envelope))
                elif mutation == "report":
                    (root / "measurement-delta.md").write_text("PASS invented")
                else:
                    head = verify.load_json(root / "measurement-head.json")
                    head["corpora"]["real_repo"]["coverage"].update(attempted_tus=2, analyzed_tus=2)
                    head["totals"].update(attempted_tus=4, analyzed_tus=4)
                    (root / "measurement-head.json").write_bytes(verify.canonical(head))
                refresh_fixture_envelope(root)
                with self.assertRaises(verify.CheckpointError):
                    verify.verify_measurement_bundle(root, cfg, ctx, inputs, CASES)


class ArchiveContractTest(unittest.TestCase):
    def fixture(self, archives, members=(("result.json", "{}"),)):
        ctx = context("measurement")
        name = verify.artifact_name(ctx, "measurement")
        path = archives / "77.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                for key, value in members:
                    archive.writestr(key, value)
        item = {"id": 77, "name": name, "digest": "sha256:" + verify.file_digest(path),
                "size_in_bytes": path.stat().st_size, "expired": False,
                "workflow_run": {"id": 123, "head_sha": ctx["head_sha"], "head_branch": ctx["ref"][11:]}}
        return ctx, {"total_count": 1, "artifacts": [item]}, {name}

    def test_archive_digest_and_exact_identity_before_unpack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archives, output = root / "archives", root / "output"
            archives.mkdir()
            output.mkdir()
            ctx, catalog, names = self.fixture(archives)
            selected = verify.verify_catalog(catalog, ctx, names)
            verify.unpack_archives(archives, output, selected)
            self.assertEqual((output / next(iter(names)) / "result.json").read_text(), "{}")

    def test_missing_expired_duplicate_wrong_run_and_digest_catalogs(self):
        for mutation in ("missing", "expired", "duplicate", "duplicate-name", "wrong-run", "wrong-head", "no-digest", "wrong-attempt", "oversized"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                ctx, catalog, names = self.fixture(Path(directory))
                item = catalog["artifacts"][0]
                if mutation == "missing":
                    catalog["artifacts"] = []
                    catalog["total_count"] = 0
                elif mutation == "expired":
                    item["expired"] = True
                elif mutation == "duplicate":
                    catalog["artifacts"].append(copy.deepcopy(item))
                    catalog["total_count"] = 2
                elif mutation == "duplicate-name":
                    catalog["artifacts"].append({**copy.deepcopy(item), "id": 78})
                    catalog["total_count"] = 2
                elif mutation == "wrong-run":
                    item["workflow_run"]["id"] = 124
                elif mutation == "wrong-head":
                    item["workflow_run"]["head_sha"] = "c" * 40
                elif mutation == "no-digest":
                    item["digest"] = None
                elif mutation == "wrong-attempt":
                    item["name"] = item["name"].replace("-123-1-", "-123-2-")
                else:
                    item["size_in_bytes"] = 2 * 1024**3 + 1
                with self.assertRaises(verify.CheckpointError):
                    verify.verify_catalog(catalog, ctx, names)

    def test_zip_slip_duplicate_symlink_and_archive_corruption(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        cases = ((("../outside", "x"),), (("/absolute", "x"),), (("dir\\file", "x"),),
                 (("duplicate", "1"), ("duplicate", "2")), ((link, "target"),), (("result.json", "{}"),))
        for index, members in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archives, output = root / "archives", root / "output"
                archives.mkdir()
                output.mkdir()
                ctx, catalog, names = self.fixture(archives, members)
                selected = verify.verify_catalog(catalog, ctx, names)
                if index == len(cases) - 1:
                    with (archives / "77.zip").open("ab") as stream:
                        stream.write(b"corrupt archive")
                with self.assertRaises(verify.CheckpointError):
                    verify.unpack_archives(archives, output, selected)
                self.assertFalse((root / "outside").exists())

    def test_same_size_corrupt_bytes_reach_archive_digest_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archives, output = root / "archives", root / "output"
            archives.mkdir()
            output.mkdir()
            ctx, catalog, names = self.fixture(archives)
            selected = verify.verify_catalog(catalog, ctx, names)
            path = archives / "77.zip"
            raw = bytearray(path.read_bytes())
            raw[-1] ^= 1
            path.write_bytes(raw)
            self.assertEqual(path.stat().st_size, catalog["artifacts"][0]["size_in_bytes"])
            with self.assertRaisesRegex(verify.CheckpointError, "digest/size mismatch"):
                verify.unpack_archives(archives, output, selected)
            self.assertEqual(list(output.iterdir()), [])


class ExternalVerifierCliTest(unittest.TestCase):
    def fixture(self, root, lane):
        inputs_root, bundle, archives = root / "inputs", root / "bundle", root / "archives"
        for directory in (inputs_root, bundle, archives):
            directory.mkdir()
        cfg, _ = ControllerContractTest().input_fixture(inputs_root)
        ctx = context(lane)
        inputs, manifest = runner.collect_inputs(inputs_root, cfg)
        if lane == "realworld":
            make_bundle(bundle, cfg, ctx, inputs, manifest)
            result = verify.verify_realworld_bundle(bundle, cfg, ctx, inputs, manifest, NEEDS)
            aggregate = bundle / verify.artifact_name(ctx, "aggregate")
            aggregate.mkdir()
            runner.write_json(aggregate / "result.json", result)
            runner.seal_artifact(aggregate, cfg, ctx, inputs, "aggregate", {"validated_shards": 48})
        else:
            output = bundle / verify.artifact_name(ctx, "measurement")
            output.mkdir()
            MeasurementArtifactTest().fixture(output, cfg, ctx, inputs)
        names = verify.expected_jobs(ctx, manifest)
        jobs = {"total_count": len(names), "jobs": [
            {"id": index, "run_id": 123, "run_attempt": 1, "head_sha": ctx["head_sha"],
             "name": name, "status": "completed", "conclusion": "success"}
            for index, name in enumerate(sorted(names), 1)]}
        run = {"id": 123, "run_attempt": 1, "head_sha": ctx["head_sha"], "head_branch": ctx["ref"][11:],
               "repository": {"full_name": ctx["repository"]}, "event": "push", "status": "completed",
               "conclusion": "success", "path": f".github/workflows/{lane}.yml"}
        artifacts = []
        for index, directory in enumerate(sorted(bundle.iterdir()), 100):
            path = archives / f"{index}.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for member in sorted(directory.rglob("*")):
                    if member.is_file():
                        archive.write(member, member.relative_to(directory).as_posix())
            artifacts.append({"id": index, "name": directory.name, "expired": False,
                              "digest": "sha256:" + verify.file_digest(path), "size_in_bytes": path.stat().st_size,
                              "workflow_run": {"id": 123, "head_sha": ctx["head_sha"], "head_branch": ctx["ref"][11:]}})
        catalog = {"total_count": len(artifacts), "artifacts": artifacts}
        for name, value in (("config", cfg), ("context", ctx), ("run", run), ("jobs", jobs), ("catalog", catalog)):
            runner.write_json(root / f"{name}.json", value)
        return [sys.executable, "-B", str(ROOT / "scripts/verify_regression_checkpoint.py"),
                "--config", str(root / "config.json"), "--context", str(root / "context.json"),
                "--inputs-root", str(inputs_root), "--run-json", str(root / "run.json"),
                "--jobs-json", str(root / "jobs.json"), "--catalog-json", str(root / "catalog.json"),
                "--archives", str(archives)]

    def test_complete_external_cli_composition_both_lanes_and_closed_failures(self):
        for lane in ("measurement", "realworld"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = self.fixture(root, lane)
                output = root / "accepted.json"
                process = subprocess.run([*command, "--output", str(output)], capture_output=True, text=True, timeout=30)
                self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
                result = verify.load_json(output)
                self.assertEqual(result["status"], "accepted")
                self.assertIn("not a signed attestation", result["provenance"])
                self.assertEqual(set(result["source_digests"]), {"run", "jobs", "catalog"})
                originals = {name: (root / f"{name}.json").read_bytes() for name in ("config", "run", "jobs", "catalog")}
                for mutation in ("disabled", "failed-job", "mixed-attempt", "wrong-digest", "missing-artifact", "null-repository"):
                    for name, raw in originals.items():
                        (root / f"{name}.json").write_bytes(raw)
                    target = "config" if mutation == "disabled" else "run" if mutation == "null-repository" else (
                        "jobs" if mutation in ("failed-job", "mixed-attempt") else "catalog")
                    path = root / f"{target}.json"
                    value = verify.load_json(path)
                    if mutation == "disabled":
                        value["enabled"] = False
                    elif mutation == "failed-job":
                        value["jobs"][0]["conclusion"] = "failure"
                    elif mutation == "mixed-attempt":
                        value["jobs"][0]["run_attempt"] = 2
                    elif mutation == "null-repository":
                        value["repository"] = None
                    elif mutation == "wrong-digest":
                        value["artifacts"][0]["digest"] = "sha256:" + "0" * 64
                    else:
                        value["artifacts"].pop(0)  # Realworld's first sorted artifact is the aggregate.
                        value["total_count"] -= 1
                    path.write_bytes(verify.canonical(value))
                    rejected = root / f"{mutation}.json"
                    process = subprocess.run([*command, "--output", str(rejected)], capture_output=True, text=True, timeout=30)
                    with self.subTest(mutation=mutation):
                        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
                        self.assertIn("CHECKPOINT_VALIDATION_FAIL", process.stderr)
                        self.assertFalse(rejected.exists())


class WorkflowCheckpointTest(unittest.TestCase):
    def test_only_additive_checkpoint_jobs_change_legacy_workflows(self):
        from WorkflowPolicyTest import StrictLoader, github_glob
        import yaml
        pins = {"measurement": "8745a0c552476c3b944aff338f1570d558beaa4bc4d5b2033c0865d076d8de6f",
                "realworld": "ec4abe24d8019967fc30fc17bdfb875a938131647a792c73b0edb491ab79200d"}
        for name, expected in pins.items():
            document = yaml.load((ROOT / f".github/workflows/{name}.yml").read_text(), Loader=StrictLoader)
            self.assertEqual(document["on"]["push"], {"branches": ["agent/cs3-*"], "paths": [runner.REQUEST]})
            for branch, selected in (("agent/cs3-x", True), ("agent/cs3-x/nested", False), ("main", False), ("feature", False)):
                self.assertEqual(github_glob(document["on"]["push"]["branches"][0], branch), selected)
            jobs = document["jobs"]
            self.assertEqual(jobs["checkpoint-plan"]["if"], "github.event_name == 'push'")
            self.assertEqual(jobs["checkpoint-plan"]["outputs"]["selected"], "${{ steps.request.outputs.selected }}")
            for key, job in jobs.items():
                if not key.startswith("checkpoint-") or key == "checkpoint-plan":
                    continue
                self.assertIn("needs.checkpoint-plan.outputs.selected == 'true'", job["if"])
                for step in job["steps"]:
                    self.assertNotIn("continue-on-error", step)
                    if "run" in step:
                        self.assertNotIn("git push", step["run"])
                        self.assertNotIn("--checkpoint", step["run"])
            if name == "realworld":
                self.assertEqual(jobs["checkpoint-scan"]["strategy"]["max-parallel"], "6")
                self.assertEqual(jobs["checkpoint-scan"]["timeout-minutes"], "355")
                self.assertEqual(jobs["checkpoint-build"]["strategy"]["matrix"]["side"], ["base", "head"])
                self.assertEqual(jobs["checkpoint-aggregate"]["if"], "always() && needs.checkpoint-plan.outputs.selected == 'true'")
            del document["on"]["push"]
            document["jobs"] = {key: value for key, value in jobs.items() if not key.startswith("checkpoint-")}
            if name == "measurement":
                self.assertEqual(document["concurrency"]["group"], "measurement-${{ github.event.pull_request.number || github.ref }}")
                document["concurrency"]["group"] = "measurement-${{ github.event.pull_request.number }}"
                self.assertEqual(document["jobs"]["base-head"].pop("if"), "github.event_name == 'pull_request'")
            else:
                for key in ("plan", "build-analyzer"):
                    self.assertEqual(document["jobs"][key].pop("if"), "github.event_name != 'push'")
                self.assertEqual(document["jobs"]["aggregate"]["if"], "always() && github.event_name != 'push'")
                document["jobs"]["aggregate"]["if"] = "always()"
            encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected)


@unittest.skipUnless(os.environ.get("CODESKEPTIC_CHECKPOINT_BINARY"), "explicit real CLI slice binary not provided")
class RealCliSliceTest(unittest.TestCase):
    def test_existing_runner_measures_same_real_inputs_twice_and_verifies_receipts(self):
        binary = Path(os.environ["CODESKEPTIC_CHECKPOINT_BINARY"]).resolve()
        with tempfile.TemporaryDirectory(prefix="codeskeptic-checkpoint-cli-") as directory:
            root = Path(directory)
            thesis, source, build, output = root / "tests/thesis_corpus", root / "src", root / "build", root / "output"
            thesis.mkdir(parents=True)
            source.mkdir()
            build.mkdir()
            output.mkdir()
            (thesis / "thesis_expected.txt").write_text("safe.c CLEAN 0\nbug.c BUG 1\n")
            (thesis / "safe.c").write_text("int safe(void) { return 0; }\n")
            (thesis / "bug.c").write_text("int bug(void) { int *p = 0; return *p; }\n")
            (source / "sample.c").write_text("int sample(void) { return 0; }\n")
            lab.write_compile_database([source / "sample.c"], build / "compile_commands.json")
            details = runner.measure_pair(binary, binary, root, build, "a" * 40, "b" * 40, output)
            cfg, ctx, inputs = config(), context("measurement"), {"fixture_only": True}
            runner.seal_artifact(output, cfg, ctx, inputs, "measurement", details)
            self.assertEqual(verify.verify_measurement_bundle(output, cfg, ctx, inputs, runner.thesis_cases(root))["gate"], "pass")
            self.assertEqual(details["base_binary_sha256"], details["head_binary_sha256"])
            print("REAL_CHECKPOINT_CLI_SLICE_OK same actual binary, same inputs, valid receipts; not hosted qualification")


if __name__ == "__main__":
    unittest.main()
