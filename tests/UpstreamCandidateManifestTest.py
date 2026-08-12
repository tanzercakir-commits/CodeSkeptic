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
        self.assertEqual(len(shards["include"]), 9)


if __name__ == "__main__":
    unittest.main()
