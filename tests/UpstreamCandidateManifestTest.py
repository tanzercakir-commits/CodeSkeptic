import ast
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize_upstream_candidates.py"
BASE = ROOT / "scripts" / "realworld_manifest.json"
HEADS = ROOT / "scripts" / "upstream_candidate_heads.json"
RUNNER = ROOT / "scripts" / "run_realworld_campaign.py"

SPEC = importlib.util.spec_from_file_location("materialize_upstream_candidates", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UpstreamCandidateManifestTest(unittest.TestCase):
    def setUp(self):
        self.base = json.loads(BASE.read_text(encoding="utf-8"))
        self.heads = json.loads(HEADS.read_text(encoding="utf-8"))

    def test_materializes_exact_frozen_batch(self):
        result = MODULE.materialize(self.base, self.heads, "2026-08-12-a")
        expected = self.heads["batches"][0]["projects"]
        self.assertEqual([project["id"] for project in result["projects"]], [item["id"] for item in expected])
        self.assertEqual([project["revision"] for project in result["projects"]], [item["head"] for item in expected])
        self.assertEqual(result["campaigns"]["upstream-candidates"]["repetitions"], 3)

    def test_repository_identity_cannot_drift(self):
        changed = copy.deepcopy(self.heads)
        changed["batches"][0]["projects"][0]["repository"] = "https://example.invalid/replaced.git"
        with self.assertRaises(MODULE.MaterializeError):
            MODULE.materialize(self.base, changed, "2026-08-12-a")

    def test_unknown_and_duplicate_projects_fail_closed(self):
        changed = copy.deepcopy(self.heads)
        changed["batches"][0]["projects"][0]["id"] = "missing"
        with self.assertRaises(MODULE.MaterializeError):
            MODULE.materialize(self.base, changed, "2026-08-12-a")
        changed = copy.deepcopy(self.heads)
        changed["batches"][0]["projects"].append(
            copy.deepcopy(changed["batches"][0]["projects"][0])
        )
        with self.assertRaises(MODULE.MaterializeError):
            MODULE.materialize(self.base, changed, "2026-08-12-a")

    def test_cli_output_is_accepted_by_campaign_planner(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            materialize = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--batch",
                    "2026-08-12-a",
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(materialize.returncode, 0, materialize.stderr)
            plan = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "plan",
                    "--manifest",
                    str(output),
                    "--tier",
                    "upstream-candidates",
                ],
                text=True,
                capture_output=True,
            )
        self.assertEqual(plan.returncode, 0, plan.stderr)
        shards = json.loads(plan.stdout)
        self.assertEqual(len(shards["include"]), 15)

    def test_runner_initializes_optional_target_commands(self):
        tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(item, ast.Name) and item.id == "target_commands"
                for item in ast.walk(node)
            )
        ]
        self.assertEqual(len(functions), 1)
        function = functions[0]
        parents = {
            child: parent
            for parent in ast.walk(function)
            for child in ast.iter_child_nodes(parent)
        }
        unconditional_stores = []
        for node in ast.walk(function):
            if not (
                isinstance(node, ast.Name)
                and node.id == "target_commands"
                and isinstance(node.ctx, ast.Store)
            ):
                continue
            ancestor = parents.get(node)
            conditional = False
            while ancestor is not None and ancestor is not function:
                conditional = conditional or isinstance(ancestor, ast.If)
                ancestor = parents.get(ancestor)
            if not conditional:
                unconditional_stores.append(node)
        loads = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Name)
            and node.id == "target_commands"
            and isinstance(node.ctx, ast.Load)
        ]
        self.assertTrue(unconditional_stores)
        self.assertTrue(loads)
        initializers = []
        for node in unconditional_stores:
            ancestor = parents.get(node)
            while ancestor is not None and not isinstance(ancestor, ast.Assign):
                ancestor = parents.get(ancestor)
            if isinstance(ancestor, ast.Assign):
                initializers.append(ancestor.value)
        self.assertTrue(
            any(
                isinstance(value, ast.Constant) and value.value == ""
                for value in initializers
            )
        )
        self.assertLess(
            min(node.lineno for node in unconditional_stores),
            min(node.lineno for node in loads),
        )
        filter_calls = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "filter_target_translation_units"
            and any(
                isinstance(argument, ast.Name)
                and argument.id == "target_commands"
                for argument in node.args
            )
        ]
        self.assertEqual(len(filter_calls), 1)
        ancestor = parents.get(filter_calls[0])
        guards = []
        while ancestor is not None and ancestor is not function:
            if isinstance(ancestor, ast.If):
                guards.append(ancestor)
            ancestor = parents.get(ancestor)
        self.assertTrue(
            any(
                isinstance(guard.test, ast.Name)
                and guard.test.id == "target_commands"
                for guard in guards
            )
        )


class DefaultRecipeSnapshotGuardTest(unittest.TestCase):
    def test_default_recipe_snapshot_check_is_guarded(self):
        runner = Path(__file__).resolve().parents[1] / "scripts" / "run_realworld_campaign.py"
        tree = ast.parse(runner.read_text(encoding="utf-8"))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node

        checks = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            names = {
                item.id
                for item in ast.walk(node.test)
                if isinstance(item, ast.Name)
            }
            names.update(
                item.attr
                for item in ast.walk(node.test)
                if isinstance(item, ast.Attribute)
            )
            if (
                any("observed" in name or "actual" in name for name in names)
                and any("count" in name or "len" in name for name in names)
                and any(
                    marker in name
                    for name in names
                    for marker in ("sha", "checksum", "digest")
                )
            ):
                checks.append(node)

        self.assertTrue(checks)
        for check in checks:
            current = parents.get(check)
            guarded = False
            while current is not None:
                if isinstance(current, ast.If) and any(
                    isinstance(item, ast.Name) and item.id == "target_commands"
                    for item in ast.walk(current.test)
                ):
                    guarded = True
                    break
                current = parents.get(current)
            self.assertTrue(guarded)


if __name__ == "__main__":
    unittest.main()
