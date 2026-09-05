#!/usr/bin/env python3
"""Read actual YAML and pin the additive agent-push wiring (not hosted PASS)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
AGENT = "agent/cs3-*"
PREFIX = "refs/heads/agent/cs3-"
DENY = "!startsWith(github.ref, 'refs/heads/agent/cs3-')"
ALLOW = "startsWith(github.ref, 'refs/heads/agent/cs3-')"
COLLECTED = "steps.agent-evidence.outcome == 'success'"
CHECKPOINT = "ci/regression-checkpoint.json"
# Canonical YAML at verified pre-wiring POP 67ae920. Removing ONLY the
# explicitly allowed additions must reconstruct this exact old behavior.
BASELINE = {
    "ci": "c4c187e8683004da885405db7ec9325d0b900b2a64d56578e886383068a28089",
    "windows": "69e40dca1b8d7bd9bf89fd0a28dd10de18ad82abf18c6766d2f5b0b7dca78b97",
    "juliet": "600129a675ea2489a7373f7a1ea2b8b6bc7453a8a50c4436d7504c1fc5ceec9b",
}
ADDED_IDS = {"workflow-policy", "agent-evidence", "agent-upload"}


class StrictLoader(yaml.BaseLoader):
    """Keep `on` a string; reject duplicate keys rather than silently hiding one."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f"duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def workflows():
    return {name: yaml.load((ROOT / f".github/workflows/{name}.yml").read_text(),
                            Loader=StrictLoader) for name in BASELINE}


def steps(document):
    return next(iter(document["jobs"].values()))["steps"]


def github_glob(pattern, value):
    # Deliberately support only this contract's literal/*/** patterns. Unknown
    # syntax fails instead of being approximated by fnmatch's slash behavior.
    if re.search(r"[^A-Za-z0-9_./*\-]", pattern):
        raise ValueError(f"unsupported pattern: {pattern}")
    expression = re.escape(pattern).replace(r"\*\*", "\0").replace(r"\*", "[^/]*")
    return re.fullmatch(expression.replace("\0", ".*"), value) is not None


def selected(document, event, ref, paths=(), action="opened", draft=False):
    if event not in document["on"]:
        return False
    config = document["on"][event] or {}
    if event == "push":
        if not ref.startswith("refs/heads/"):
            return False  # all three workflows define branches, not tags
        if not any(github_glob(p, ref[11:]) for p in config["branches"]):
            return False
    if event == "pull_request":
        if action not in config.get("types", ["opened", "synchronize", "reopened"]):
            return False
    if "paths" in config and not any(github_glob(p, f) for p in config["paths"] for f in paths):
        return False
    job = next(iter(document["jobs"].values()))
    if "if" in job:
        condition = " ".join(job["if"].split())
        if condition != "github.event_name != 'pull_request' || github.event.pull_request.draft == false":
            raise ValueError(f"unreviewed job gate: {condition}")
        if event == "pull_request" and draft:
            return False
    return True


def step_selected(condition, ref, status, collector_outcome="success"):
    parts = condition.split(" && ")
    initial = {"always()": True, "failure()": status == "failure", "success()": status == "success"}
    if parts[0] not in initial or len(parts) > 3:
        raise ValueError(f"unreviewed status gate: {condition}")
    result = initial[parts[0]]
    if len(parts) >= 2:
        if parts[1] not in (ALLOW, DENY):
            raise ValueError(f"unreviewed ref guard: {condition}")
        is_agent = ref.lower().startswith(PREFIX)
        result = result and (is_agent if parts[1] == ALLOW else not is_agent)
    if len(parts) == 3:
        if parts[2] != COLLECTED:
            raise ValueError(f"unreviewed collector gate: {condition}")
        result = result and collector_outcome == "success"
    return result


def baseline_digest(document):
    old = copy.deepcopy(document)
    if AGENT in old["on"]["push"]["branches"]:
        old["on"]["push"]["branches"].remove(AGENT)
    if CHECKPOINT in old["on"]["push"].get("paths", []):
        old["on"]["push"]["paths"].remove(CHECKPOINT)
    job = next(iter(old["jobs"].values()))
    job["steps"] = [s for s in job["steps"] if s.get("id") not in ADDED_IDS]
    for step in job["steps"]:
        suffix = " && " + DENY
        if step.get("if", "").endswith(suffix):
            step["if"] = step["if"][:-len(suffix)]
    return hashlib.sha256(json.dumps(old, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


class WorkflowPolicyTest(unittest.TestCase):
    def setUp(self):
        self.docs = workflows()

    def test_real_yaml_on_and_duplicate_keys(self):
        self.assertEqual(yaml.load("on: {push: {}}", Loader=StrictLoader), {"on": {"push": {}}})
        with self.assertRaises(ValueError):
            yaml.load("on: push\non: pull_request", Loader=StrictLoader)

    def test_only_declared_additions_change_the_legacy_contract(self):
        for name, document in self.docs.items():
            with self.subTest(name=name):
                self.assertEqual(baseline_digest(document), BASELINE[name])

    def test_agent_push_source_test_checkpoint_and_docs_matrix(self):
        for name, document in self.docs.items():
            for path in ("src/rules/FdResourceRule.cpp", "tests/FdResourceRuleTest.cpp", CHECKPOINT,
                         "docs/TODO.md", "README.md", "src-lookalike/file.cpp"):
                with self.subTest(name=name, path=path):
                    expected = name != "juliet" or path.startswith(("src/", "tests/")) or path == CHECKPOINT
                    self.assertEqual(selected(document, "push", PREFIX + "ch01-s07-u001-example", [path]), expected)

    def test_unrelated_branches_tags_and_prefix_lookalikes_are_not_new_pushes(self):
        for document in self.docs.values():
            for ref in ("refs/heads/feature/x", "refs/heads/agent/cs30-x", "refs/heads/agent/cs3-x/nested",
                        "refs/heads/Agent/cs3-x", "refs/tags/agent/cs3-x", "refs/heads/archive/agent/cs3-x"):
                with self.subTest(ref=ref):
                    self.assertFalse(selected(document, "push", ref, ["src/x.cpp", CHECKPOINT]))

    def test_old_main_phase_and_pr_matrix(self):
        for name, document in self.docs.items():
            for branch in ("main", "phase", "phase-xyz"):
                self.assertEqual(selected(document, "push", "refs/heads/" + branch, ["src/x.cpp"]),
                                 name != "juliet" or branch != "main")
            self.assertTrue(selected(document, "pull_request", "refs/pull/9/merge", ["src/x.cpp"]))
            self.assertEqual(selected(document, "pull_request", "refs/pull/9/merge", ["src/x.cpp"], draft=True),
                             name != "juliet")
            self.assertFalse(selected(document, "pull_request", "refs/pull/9/merge", ["src/x.cpp"], action="closed"))

    def test_juliet_legacy_paths_ready_manual_and_schedule(self):
        document = self.docs["juliet"]
        for path in document["on"]["pull_request"]["paths"]:
            concrete = path.replace("**", "nested/x.cpp")
            self.assertTrue(selected(document, "pull_request", "refs/pull/2/merge", [concrete], action="ready_for_review"))
        self.assertFalse(selected(document, "pull_request", "refs/pull/2/merge", [CHECKPOINT]))
        self.assertFalse(selected(document, "push", PREFIX + "x", ["docs/TODO.md"]))
        for event in ("workflow_dispatch", "schedule"):
            self.assertTrue(selected(document, event, "refs/heads/main"))
        self.assertTrue(selected(document, "workflow_dispatch", PREFIX + "x"))

    def test_every_legacy_git_writer_is_excluded_on_agent_refs(self):
        for name, document in self.docs.items():
            writers = [s for s in steps(document) if "git push" in s.get("run", "")]
            self.assertEqual(len(writers), 2, name)
            for step in writers:
                self.assertIn(" && " + DENY, step["if"])
                for status in ("success", "failure", "cancelled"):
                    self.assertFalse(step_selected(step["if"], PREFIX + "x", status))
                    self.assertFalse(step_selected(step["if"], "refs/heads/AGENT/CS3-x", status))
                    for ref in ("refs/heads/main", "refs/heads/phase-x", "refs/pull/1/merge"):
                        self.assertEqual(step_selected(step["if"], ref, status),
                                         step_selected(step["if"].split(" && ")[0], ref, status))

    def test_agent_lanes_have_normal_bounded_artifacts(self):
        for name in ("ci", "windows"):
            found = {s.get("id"): s for s in steps(self.docs[name])}
            for identity in ("agent-evidence", "agent-upload"):
                self.assertIn(identity, found)
                extra = " && " + COLLECTED if identity == "agent-upload" else ""
                self.assertEqual(found[identity]["if"], "always() && " + ALLOW + extra)
                self.assertNotIn("continue-on-error", found[identity])
            upload = found["agent-upload"]
            self.assertEqual(upload["uses"], "actions/upload-artifact@v4")
            self.assertEqual(upload["with"]["if-no-files-found"], "error")
            self.assertEqual(upload["with"]["retention-days"], "14")
            self.assertEqual(upload["with"]["path"], found["agent-evidence"]["env"]["SNAPSHOT_DIR"])
            for status in ("success", "failure", "cancelled"):
                self.assertTrue(step_selected(upload["if"], PREFIX + "x", status))
                for ref in ("refs/heads/main", "refs/heads/phase-x", "refs/pull/1/merge"):
                    self.assertFalse(step_selected(upload["if"], ref, status))

    def collector(self, name):
        step = next(s for s in steps(self.docs[name]) if s.get("id") == "agent-evidence")
        self.assertEqual(step["shell"], "bash")
        lines = step["run"].splitlines()
        self.assertEqual(lines[0], ("python3" if name == "ci" else "python") + " - <<'PY'")
        self.assertEqual(lines[-1], "PY")
        return "\n".join(lines[1:-1])

    def test_failed_or_skipped_collection_never_uploads_a_rejected_target(self):
        for name in ("ci", "windows"):
            upload = next(s for s in steps(self.docs[name]) if s.get("id") == "agent-upload")
            for outcome in ("failure", "skipped", "cancelled"):
                for status in ("success", "failure", "cancelled"):
                    with self.subTest(name=name, outcome=outcome, status=status):
                        self.assertFalse(step_selected(upload["if"], PREFIX + "x", status, outcome))

    def run_collector(self, name, workspace, target):
        environment = {
            "PATH": os.environ["PATH"], "SNAPSHOT_DIR": str(target),
            "GITHUB_SHA": "a" * 40, "WORKFLOW_SHA": "b" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": name,
            "STEPS_JSON": json.dumps({"test": {"outcome": "failure", "conclusion": "failure",
                                               "outputs": {"private": "must-not-be-copied"}},
                                      "smoke": {"outcome": "skipped", "conclusion": "skipped"}}),
        }
        return subprocess.run([sys.executable, "-B", "-c", self.collector(name)], cwd=workspace,
                              env=environment, capture_output=True, text=True, timeout=10)

    def test_actual_collectors_bound_logs_and_do_not_copy_step_outputs(self):
        self.assertEqual(self.collector("ci"), self.collector("windows"))
        for name in ("ci", "windows"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                source = workspace / "build/Testing/Temporary/LastTest.log"
                source.parent.mkdir(parents=True)
                source.write_bytes(b"old" * 30000 + b"new-tail")
                (workspace / "probe_result.txt").write_text("probe failed", encoding="utf-8")
                (workspace / "unrelated-private.txt").write_text("not an artifact", encoding="utf-8")
                target = workspace / "snapshot"
                result = self.run_collector(name, workspace, target)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = (target / "snapshot.json").read_text(encoding="utf-8")
                data = json.loads(raw)
                self.assertEqual(data["event_sha"], "a" * 40)
                self.assertEqual(data["workflow_sha"], "b" * 40)
                self.assertEqual(data["run_id"], "123")
                self.assertEqual(data["run_attempt"], "2")
                self.assertIsNone(data["checkout_sha"])  # no checkout is not fabricated PASS
                self.assertIn("diagnostics-only", data["purpose"])
                self.assertNotIn("verdict", data)
                self.assertNotIn("must-not-be-copied", raw)
                self.assertEqual(data["steps"]["test"], {"outcome": "failure", "conclusion": "failure"})
                self.assertEqual(data["steps"]["smoke"]["outcome"], "skipped")
                self.assertEqual((target / "LastTest.log").read_bytes(), source.read_bytes()[-65536:])
                self.assertTrue(data["logs"]["build/Testing/Temporary/LastTest.log"]["truncated"])
                self.assertFalse(data["logs"]["build/Testing/Temporary/LastTestsFailed.log"]["available"])
                self.assertEqual({p.name for p in target.iterdir()}, {"snapshot.json", "LastTest.log", "probe_result.txt"})
                self.assertNotEqual(self.run_collector(name, workspace, target).returncode, 0)

    def test_actual_collectors_reject_symlinks_and_preserve_missing_evidence(self):
        for name in ("ci", "windows"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                private = workspace / "private"
                private.mkdir()
                (private / "private.txt").write_text("not for upload", encoding="utf-8")
                (workspace / "probe_result.txt").symlink_to(private / "private.txt")
                (workspace / "build").symlink_to(private, target_is_directory=True)
                nested = private / "Testing/Temporary/LastTest.log"
                nested.parent.mkdir(parents=True)
                nested.write_text("not for upload", encoding="utf-8")
                target = workspace / "snapshot"
                result = self.run_collector(name, workspace, target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual({p.name for p in target.iterdir()}, {"snapshot.json"})
                data = json.loads((target / "snapshot.json").read_text(encoding="utf-8"))
                self.assertTrue(all(not item["available"] for item in data["logs"].values()))
                linked_target = workspace / "linked-snapshot"
                linked_target.symlink_to(private, target_is_directory=True)
                self.assertNotEqual(self.run_collector(name, workspace, linked_target).returncode, 0)
                self.assertFalse((private / "snapshot.json").exists())

    def test_workflow_policy_is_executed_in_the_new_linux_lane(self):
        found = {s.get("id"): s for s in steps(self.docs["ci"])}
        self.assertIn("workflow-policy", found)
        self.assertEqual(found["workflow-policy"]["if"], "success() && " + ALLOW)
        self.assertIn("/usr/bin/python3 -B tests/WorkflowPolicyTest.py", found["workflow-policy"]["run"])
        self.assertIn("python3-yaml", found["workflow-policy"]["run"])

    def test_mutations_of_old_quality_steps_and_pins_are_rejected(self):
        for name, document in self.docs.items():
            changed = copy.deepcopy(document)
            next(iter(changed["jobs"].values()))["steps"][0]["uses"] = "actions/checkout@v3"
            self.assertNotEqual(baseline_digest(changed), BASELINE[name])
            changed = copy.deepcopy(document)
            next(iter(changed["jobs"].values()))["steps"].pop(2)
            self.assertNotEqual(baseline_digest(changed), BASELINE[name])

    def test_glob_and_status_helpers_reject_approximate_semantics(self):
        self.assertTrue(github_glob("src/**", "src/engine/x.cpp"))
        self.assertFalse(github_glob("phase*", "phase/x"))
        self.assertFalse(github_glob(AGENT, "agent/cs3-x/nested"))
        with self.assertRaises(ValueError):
            github_glob("!main", "main")
        with self.assertRaises(ValueError):
            step_selected("always() || " + DENY, PREFIX + "x", "failure")


if __name__ == "__main__":
    unittest.main()
