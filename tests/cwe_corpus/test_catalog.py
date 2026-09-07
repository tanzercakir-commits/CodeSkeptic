#!/usr/bin/env python3
"""Input-integrity regressions only; no analyzer or quality measurement."""
import copy
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cwe_quality", ROOT / "scripts/cwe_quality.py")
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = quality.read_json(ROOT, quality.CATALOG)
        self.inventory = quality.read_json(ROOT, quality.INVENTORY)

    def validate(self, root=ROOT):
        return quality.validate(root, self.catalog, self.inventory)

    def reject(self):
        with self.assertRaises((ValueError, TypeError)):
            self.validate()

    @contextmanager
    def copied_root(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-catalog-test-") as temporary:
            root = Path(temporary)
            paths = {row["path"] for row in self.inventory["inputs"]}
            paths.update(row["path"] for row in self.catalog["cases"])
            paths.update((quality.CATALOG, quality.INVENTORY))
            for name in paths:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            yield root

    def test_complete_frozen_input_catalog_is_not_a_quality_result(self):
        result = self.validate()
        self.assertEqual(result["rules"], 12)
        self.assertEqual(result["cases"], 52)
        self.assertEqual(result["protected_inputs"], 124)
        self.assertEqual(result["roles"], {"buggy": 24, "safe": 22, "unknown": 3, "unsupported": 3})
        self.assertIs(result["quality_measured"], False)

    def test_all_existing_source_tests_are_required(self):
        tests = [row for row in self.inventory["inputs"] if row["path"].startswith("tests/")]
        self.assertEqual(len(tests), 96)
        self.assertTrue({"tests/AllocSizeOverflowRuleTest.cpp", "tests/FdResourceRuleTest.cpp",
                         "tests/TestHelper.cpp", "tests/TestHelper.h", "tests/CMakeLists.txt",
                         "tests/RegressionCheckpointTest.py", "tests/WorkflowPolicyTest.py"}
                        <= {row["path"] for row in tests})

    def test_missing_rule_rejected(self):
        self.catalog["rules"].pop("uninit-scalar")
        self.reject()

    def test_tier_promotion_rejected(self):
        self.catalog["rules"]["bounds"]["tier_at_selection"] = "supported"
        self.reject()

    def test_noninteger_cwe_identity_rejected(self):
        self.catalog["rules"]["uninit-ptr"]["cwes"] = [824.0]
        self.reject()

    def test_omitted_fixture_rejected(self):
        self.catalog["cases"].pop()
        self.reject()

    def test_duplicate_id_rejected(self):
        self.catalog["cases"].append(copy.deepcopy(self.catalog["cases"][0]))
        self.reject()

    def test_missing_safe_pair_rejected(self):
        row = next(c for c in self.catalog["cases"] if c["rule"] == "uninit-ptr" and c["role"] == "safe")
        row.update(role="unsupported", expected_diagnostics=None)
        self.reject()

    def test_unknown_and_unsupported_cannot_be_counted_as_clean(self):
        for role in ("unknown", "unsupported"):
            with self.subTest(role=role):
                original = copy.deepcopy(self.catalog)
                next(c for c in self.catalog["cases"] if c["role"] == role)["expected_diagnostics"] = []
                self.reject()
                self.catalog = original

    def test_buggy_cannot_be_clean(self):
        self.catalog["cases"][0]["expected_diagnostics"] = []
        self.reject()

    def test_safe_cannot_contain_expected_findings(self):
        self.catalog["cases"][1]["expected_diagnostics"] = [["uninit-ptr", "f"]]
        self.reject()

    def test_wrong_rule_or_function_rejected(self):
        for value in (["bounds", "f"], ["uninit-ptr", "other"], ["uninit-ptr"], True):
            with self.subTest(value=value):
                self.catalog["cases"][0]["expected_diagnostics"] = [value]
                self.reject()

    def test_unfrozen_flags_and_source_config_rejected(self):
        self.catalog["cases"][0]["compile_flags"].append("-DRESULT_DEPENDENT=1")
        self.reject()
        self.catalog["cases"][0]["compile_flags"] = ["-std=c++17"]
        self.catalog["cases"][0]["untrusted_sources"] = ["--accept-partial-coverage"]
        self.reject()

    def test_extra_fields_bad_schema_and_bad_base_rejected(self):
        for key, value in (("schema", "other"), ("selection_base", "short"), ("extra", 1)):
            with self.subTest(key=key):
                original = copy.deepcopy(self.catalog)
                self.catalog[key] = value
                self.reject()
                self.catalog = original

    def test_inventory_removal_duplicate_and_digest_drift_rejected(self):
        original = copy.deepcopy(self.inventory)
        self.inventory["inputs"].pop()
        self.reject()
        self.inventory = copy.deepcopy(original)
        self.inventory["inputs"].append(copy.deepcopy(self.inventory["inputs"][0]))
        self.reject()
        self.inventory = original
        self.inventory["inputs"][0]["sha256"] = "0" * 64
        self.reject()

    def test_floor_bytes_cannot_be_rewritten_silently(self):
        with self.copied_root() as root:
            (root / "scripts/juliet_expected.txt").write_text("CWE476 0 0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected input changed"):
                self.validate(root)

    def test_test_deletion_or_edit_rejected(self):
        with self.copied_root() as root:
            (root / "tests/FdResourceRuleTest.cpp").write_text("// removed hard negatives\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected input changed"):
                self.validate(root)

    def test_new_source_test_requires_inventory_revision(self):
        with self.copied_root() as root:
            (root / "tests/NewCoreTest.cpp").write_text("// new regression\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "protected inputs"):
                self.validate(root)

    def test_new_corpus_source_cannot_be_silently_omitted(self):
        with self.copied_root() as root:
            (root / "tests/cwe_corpus/omitted.cpp").write_text("int f(){return 0;}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unlisted/missing corpus"):
                self.validate(root)

    def test_fixture_byte_drift_rejected(self):
        with self.copied_root() as root:
            (root / self.catalog["cases"][0]["path"]).write_text("int f(){return 0;}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fixture changed"):
                self.validate(root)

    def test_symlink_fixture_and_traversal_rejected(self):
        with self.copied_root() as root:
            fixture = root / self.catalog["cases"][0]["path"]
            fixture.unlink()
            fixture.symlink_to(ROOT / self.catalog["cases"][0]["path"])
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.validate(root)
            for name in ("../outside", "/tmp/input", "tests/../input", "tests//input", "tests\\input"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    quality.safe_file(root, name)

    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-catalog-json-") as directory:
            root = Path(directory)
            for raw in ('{"same":1,"same":2}', '{"number":NaN}', '{"number":Infinity}', '{"number":1e999}'):
                (root / "input.json").write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    quality.read_json(root, "input.json")

    def test_inventory_bytes_bound_to_catalog(self):
        with self.copied_root() as root:
            with (root / quality.INVENTORY).open("ab") as stream:
                stream.write(b"\n")
            with self.assertRaisesRegex(ValueError, "inventory digest"):
                self.validate(root)


if __name__ == "__main__":
    unittest.main()
