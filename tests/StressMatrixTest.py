import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_stress_matrix as matrix

BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None
EVIDENCE_ROOT = (ROOT / "docs" / "evidence" / "phase10" / "stress" /
                 "2026-08-15-cache-linux-x86_64")


class StressMatrixContractTest(unittest.TestCase):
    def test_strict_json_rejects_duplicate_and_nonfinite_values(self):
        for raw in (
            b'{"schema":"first","schema":"second"}\n',
            b'{"duration_ms":NaN}\n',
        ):
            with self.subTest(raw=raw), self.assertRaises(matrix.MatrixError):
                matrix._strict_json(raw, "stress fixture")

    def test_source_manifest_binds_complete_stress_inputs_not_outputs(self):
        files = {
            path.relative_to(ROOT).as_posix()
            for path in matrix._regular_files(matrix.SOURCE_ROOTS)
        }
        for required in (
                "src/analyzer/StaticAnalyzer.cpp",
                "tests/BrokenTuTest.cpp",
                "tests/stress_corpus/manifest.json",
                "scripts/run_corpus.sh",
                "scripts/run_stress_matrix.py",
                "docs/PLAN.md",
                ".github/workflows/ci.yml"):
            self.assertIn(required, files)
        self.assertFalse(any(path.startswith("docs/evidence/") for path in files))
        self.assertNotIn("docs/devlog/changelog.md", files)

    def test_fixed_manifest_covers_every_plan_surface(self):
        manifest = matrix.load_manifest()
        categories = {case["category"] for case in manifest["cases"]}
        self.assertEqual(
            categories,
            {
                "broken-recovery",
                "high-cfg",
                "macro",
                "malformed-source",
                "missing-request",
                "mixed-coverage",
                "template",
            },
        )

    def test_fixture_checksum_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied_root = Path(tmp) / "repo"
            shutil.copytree(ROOT / "tests" / "stress_corpus",
                            copied_root / "tests" / "stress_corpus")
            manifest = copied_root / "tests" / "stress_corpus" / "manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            fixture = copied_root / payload["cases"][0]["sources"][0]["path"]
            fixture.write_text(fixture.read_text(encoding="utf-8") + "\n",
                               encoding="utf-8")
            with self.assertRaises(matrix.MatrixError):
                matrix.load_manifest(manifest, copied_root)

    def test_production_matrix_is_repeatable_and_receipt_verifies(self):
        if BINARY is None:
            self.skipTest("production binary supplied only by CTest")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence"
            receipt = matrix.run_matrix(BINARY, output=output)
            self.assertEqual(receipt["summary"]["accepted_cases"], 9)
            self.assertEqual(receipt["summary"]["repetitions_per_case"], 2)
            matrix.verify_receipt(output / "receipt.json", BINARY)
            matrix.verify_receipt_with_identity(
                output / "receipt.json", matrix._binary_identity(BINARY)
            )
            forged_identity = dict(matrix._binary_identity(BINARY))
            forged_identity["sha256"] = "f" * 64
            with self.assertRaisesRegex(matrix.MatrixError, "analyzer identity"):
                matrix.verify_receipt_with_identity(
                    output / "receipt.json", forged_identity
                )

            receipt_path = output / "receipt.json"
            tampered = json.loads(receipt_path.read_text(encoding="utf-8"))
            tampered["cases"][0]["runs"][0]["command"] = ["tampered"]
            receipt_path.write_bytes(matrix.canonical_json(tampered))
            with self.assertRaises(matrix.MatrixError):
                matrix.verify_receipt(receipt_path, BINARY)

            tampered = json.loads(matrix.canonical_json(receipt))
            tampered["duration_ms"] = -1
            receipt_path.write_bytes(matrix.canonical_json(tampered))
            with self.assertRaises(matrix.MatrixError):
                matrix.verify_receipt(receipt_path, BINARY)

            receipt_path.write_bytes(matrix.canonical_json(receipt))
            first_log = output / receipt["cases"][0]["runs"][0]["log"]
            first_log.write_bytes(first_log.read_bytes() + b"tamper\n")
            with self.assertRaises(matrix.MatrixError):
                matrix.verify_receipt(receipt_path, BINARY)

    def test_retained_receipt_binds_committed_source_and_complete_matrix(self):
        receipt_path = EVIDENCE_ROOT / "receipt.json"
        if not receipt_path.is_file():
            self.skipTest("stress evidence is not materialized")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        revision = matrix._resolve_source_manifest_revision(
            receipt["source"]["base_commit"],
            matrix._git_commit(),
            receipt["source"]["manifest"],
        )
        self.assertEqual(
            receipt["source"]["manifest"],
            matrix.source_manifest_at_revision(revision),
        )
        self.assertEqual(
            receipt["summary"],
            {
                "accepted_cases": 9,
                "repetitions_per_case": 2,
                "timeouts": 0,
                "crashes": 0,
            },
        )

    def test_external_manifest_pins_latest_retained_stress_tree(self):
        manifest = EVIDENCE_ROOT / "SHA256SUMS"
        if not manifest.is_file():
            self.skipTest("stress external manifest is not materialized")
        entries = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, separator, relative = line.partition("  ")
            self.assertTrue(separator)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotIn(relative, entries)
            entries[relative] = digest
        expected = {
            path.relative_to(EVIDENCE_ROOT.parent).as_posix()
            for path in EVIDENCE_ROOT.rglob("*")
            if path.is_file() and path != manifest
        }
        self.assertEqual(set(entries), expected)
        for relative, digest in entries.items():
            self.assertEqual(
                matrix.sha256_file(EVIDENCE_ROOT.parent / relative), digest)


if __name__ == "__main__":
    unittest.main()
