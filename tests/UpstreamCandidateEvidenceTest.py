import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_upstream_candidate_evidence.py"
HEADS = ROOT / "scripts" / "upstream_candidate_heads.json"
TODO = ROOT / "docs" / "TODO.md"
CHANGELOG = ROOT / "docs" / "devlog" / "changelog.md"
ATTRIBUTES = ROOT / ".gitattributes"

SPEC = importlib.util.spec_from_file_location("check_upstream_candidate_evidence", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UpstreamCandidateEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = ROOT / "scripts" / "upstream_candidate_receipts"
        destination = self.root / "scripts" / "upstream_candidate_receipts"
        destination.parent.mkdir(parents=True)
        shutil.copytree(source, destination)
        self.heads = json.loads(HEADS.read_text(encoding="utf-8"))
        self.todo = TODO.read_text(encoding="utf-8")
        self.changelog = CHANGELOG.read_text(encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def validate(self, heads=None, todo=None, changelog=None):
        return MODULE.validate(
            self.root,
            heads if heads is not None else self.heads,
            "2026-08-12-a",
            todo if todo is not None else self.todo,
            changelog if changelog is not None else self.changelog,
        )

    def tensorflow(self, heads):
        return next(
            project
            for project in heads["batches"][0]["projects"]
            if project["id"] == "tensorflow-lite"
        )

    def write_json(self, path, value):
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    def mutate_receipts(self, heads, mutation):
        evidence = self.tensorflow(heads)["receipt_evidence"]
        for repetition, entry in enumerate(evidence["receipts"], start=1):
            path = self.root / entry["path"]
            receipt = json.loads(path.read_text(encoding="utf-8"))
            mutation(receipt, repetition)
            self.write_json(path, receipt)
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    def mutate_manifest(self, heads, mutation):
        evidence = self.tensorflow(heads)["receipt_evidence"]
        path = self.root / evidence["manifest"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        mutation(manifest)
        self.write_json(path, manifest)
        manifest_sha256 = MODULE.RUNNER.digest_json(manifest)
        self.mutate_receipts(
            heads,
            lambda receipt, _repetition: receipt["identity"].__setitem__(
                "manifest_sha256", manifest_sha256
            ),
        )

    def test_retained_receipts_match_snapshot_and_docs(self):
        self.assertEqual(self.validate(), 8)

    def test_retained_receipt_bytes_are_platform_invariant(self):
        attributes = ATTRIBUTES.read_text(encoding="utf-8").splitlines()
        self.assertIn("scripts/upstream_candidate_receipts/** -text", attributes)

    def test_transcribed_revision_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.tensorflow(changed)["head"] = "0" * 40
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_transcribed_finding_count_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.tensorflow(changed)["findings"] = 0
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_document_summary_drift_fails_closed(self):
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(todo=self.todo.replace("74 stable findings", "0 stable findings"))
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(changelog=self.changelog.replace("74 stable findings", "0 stable findings"))

    def test_document_repetition_drift_fails_closed(self):
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(
                todo=self.todo.replace(
                    "completed 3 fresh accepted repetitions",
                    "completed 2 fresh accepted repetitions",
                )
            )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(
                changelog=self.changelog.replace(
                    "with 3/3 accepted repetitions",
                    "with 2/3 accepted repetitions",
                )
            )

    def test_duplicate_document_summary_fails_closed(self):
        todo_line = next(
            line
            for line in self.todo.splitlines()
            if "TensorFlow Lite completed 3 fresh accepted repetitions" in line
        )
        changelog_line = next(
            line
            for line in self.changelog.splitlines()
            if "current TensorFlow Lite head with 3/3 accepted repetitions" in line
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(todo=f"{self.todo}\n{todo_line}\n")
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(changelog=f"{self.changelog}\n{changelog_line}\n")

    def test_receipt_checksum_drift_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        project = self.tensorflow(changed)
        project["receipt_evidence"]["receipts"][0]["sha256"] = "0" * 64
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_invalid_analyzer_identity_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["identity"].__setitem__(
                "analyzer_sha256", "not-a-sha"
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_wrong_recipe_identity_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["identity"].__setitem__(
                "recipe_sha256", "0" * 64
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_inconsistent_fingerprint_list_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["semantic"].__setitem__(
                "fingerprints", []
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_inconsistent_exit_verdict_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["semantic"].__setitem__(
                "exit_code", 0
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_wrong_submodule_identity_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["identity"].__setitem__(
                "submodules", {"mode": "none", "count": 1, "sha256": "0" * 64}
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_coordinated_finding_count_drift_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.tensorflow(changed)["findings"] = 75

        def change_manifest(manifest):
            project = next(
                item for item in manifest["projects"] if item["id"] == "tensorflow-lite"
            )
            project["expected"]["findings"] = 75

        self.mutate_manifest(changed, change_manifest)
        self.mutate_receipts(
            changed,
            lambda receipt, _repetition: receipt["semantic"].__setitem__(
                "findings", 75
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(
                heads=changed,
                todo=self.todo.replace("74 stable findings", "75 stable findings"),
                changelog=self.changelog.replace(
                    "74 stable findings", "75 stable findings"
                ),
            )

    def test_distinct_analyzed_count_is_preserved(self):
        heads = copy.deepcopy(self.heads)
        project = self.tensorflow(heads)
        project["analyzed_tus"] = 255

        def update_manifest(manifest):
            retained = next(
                item for item in manifest["projects"] if item["id"] == "tensorflow-lite"
            )
            retained["expected"]["analyzed_tus"] = 255

        self.mutate_manifest(heads, update_manifest)
        self.mutate_receipts(
            heads,
            lambda receipt, _repetition: receipt["semantic"]["coverage"].__setitem__(
                "analyzed_tus", 255
            ),
        )
        todo = self.todo.replace("240/240", "240/255")
        changelog = self.changelog.replace("240/240", "240/255")
        self.validate(heads, todo=todo, changelog=changelog)

        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads, todo=todo.replace("240/255", "240/254"), changelog=changelog)
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads, todo=todo, changelog=changelog.replace("240/255", "240/254"))
        for drift in ("1240/255", "240/2550"):
            with self.assertRaises(MODULE.EvidenceError):
                self.validate(heads, todo=todo.replace("240/255", drift), changelog=changelog)
            with self.assertRaises(MODULE.EvidenceError):
                self.validate(heads, todo=todo, changelog=changelog.replace("240/255", drift))

        project["attempted_tus"] = 239
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads, todo=todo, changelog=changelog)
        del project["attempted_tus"]

        project["analyzed_tus"] = 254
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads, todo=todo, changelog=changelog)

    def test_campaign_membership_drift_fails_closed(self):
        changed = copy.deepcopy(self.heads)

        def change_manifest(manifest):
            manifest["campaigns"]["release-candidate"]["projects"].remove(
                "tensorflow-lite"
            )
            manifest["campaigns"]["nightly"]["projects"].append("tensorflow-lite")

        self.mutate_manifest(changed, change_manifest)
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)

    def test_campaign_repetition_drift_fails_closed(self):
        changed = copy.deepcopy(self.heads)
        self.mutate_manifest(
            changed,
            lambda manifest: manifest["campaigns"]["release-candidate"].__setitem__(
                "repetitions", 2
            ),
        )
        with self.assertRaises(MODULE.EvidenceError):
            self.validate(heads=changed)


if __name__ == "__main__":
    unittest.main()
