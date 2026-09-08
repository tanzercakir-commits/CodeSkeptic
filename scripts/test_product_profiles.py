#!/usr/bin/env python3
"""Synthetic manifest accounting checks; no sample or product quality claim."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import product_profiles as profiles


def quota_rows():
    rows = []
    for bucket in profiles.BUCKETS:
        family, separator, subtype = bucket.partition("/")
        for role in ("buggy", "safe"):
            for number in range(30):
                name = bucket.replace("/", "-") + "-" + role + "-" + str(number)
                rows.append({"id": name, "family": family, "subprofile": subtype if separator else None,
                             "role": role, "quota": True, "origin": "origin-" + str(number % 3),
                             "cluster": name, "sha256": format(len(rows) + 1, "064x"),
                             "selection": "independent-evaluation"})
    return rows


class QuotaTests(unittest.TestCase):
    def test_contract_has_sixteen_families_and_seventeen_disjoint_buckets(self):
        self.assertEqual(len(profiles.FAMILIES), 16)
        self.assertEqual(len(profiles.BUCKETS), 17)
        self.assertNotIn("bounds", profiles.BUCKETS)
        self.assertIn("bounds/cwe-121", profiles.BUCKETS)
        self.assertIn("bounds/cwe-122", profiles.BUCKETS)

    def test_synthetic_quota_accounting_not_provenance_qualification(self):
        result = profiles.quota_readiness(quota_rows(), {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(result["quota_examples"], 1020)
        self.assertEqual(result["deficits"], [])
        self.assertFalse(result["ground_truth_verified"])
        self.assertFalse(result["product_qualified"])

    def test_one_missing_role_blocks_its_exact_bucket(self):
        rows = quota_rows()
        removed = rows.pop(0)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(any(removed["family"] in item and "buggy" in item for item in result["deficits"]))

    def test_three_origins_required_per_bucket_not_only_global(self):
        rows = quota_rows()
        for row in rows[:60]:
            row["origin"] = "origin-0"
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(any("origins" in item for item in result["deficits"]))

    def test_three_origins_are_not_invented_from_ids(self):
        with self.assertRaises(ValueError):
            profiles.quota_readiness(quota_rows(), {"origin-0", "origin-1"})

    def test_duplicate_id_hash_and_semantic_cluster_rejected(self):
        for key in ("id", "sha256", "cluster"):
            rows = quota_rows()
            rows[1][key] = rows[0][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_cross_role_and_cross_family_cluster_reuse_rejected(self):
        for index in (30, 60):
            rows = quota_rows()
            rows[index]["cluster"] = rows[0]["cluster"]
            with self.subTest(index=index), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_supplemental_pair_cannot_rescue_missing_quota(self):
        rows = quota_rows()
        rows[0]["quota"] = False
        pair = copy.deepcopy(rows[0])
        pair.update(id="supplemental-fixed", role="safe", sha256="f"*64)
        rows.append(pair)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(result["quota_examples"], 1019)
        self.assertEqual(result["supplemental_examples"], 2)
        self.assertTrue(result["deficits"])

    def test_unknown_and_unsupported_never_supply_quota(self):
        for role in ("unknown", "unsupported"):
            rows = quota_rows()
            rows[0]["role"] = role
            with self.subTest(role=role), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
            rows[0]["quota"] = False
            self.assertTrue(profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})["deficits"])

    def test_training_cannot_be_renamed_evaluation(self):
        rows = quota_rows()
        rows[0]["selection"] = "known-fp-training"
        with self.assertRaises(ValueError):
            profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_bool_and_digest_types_are_strict(self):
        for key, value in (("quota", 1), ("sha256", "0"*64), ("sha256", "bad"),
                           ("cluster", ""), ("origin", None), ("family", "fake")):
            rows = quota_rows()
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_bounds_subtype_cannot_be_guessed_from_local_pointer_name(self):
        rows = quota_rows()
        stack = next(row for row in rows if row["subprofile"] == "cwe-121")
        stack["subprofile"] = None
        with self.assertRaises(ValueError):
            profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_generic_bounds_can_remain_supplemental(self):
        rows = quota_rows()
        stack = next(row for row in rows if row["subprofile"] == "cwe-121")
        stack.update(subprofile=None, quota=False)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(result["deficits"])

    def test_empty_selection_reports_deficits_never_success(self):
        result = profiles.quota_readiness([], set())
        self.assertEqual(result["quota_examples"], 0)
        self.assertTrue(result["deficits"])
        self.assertFalse(result["ground_truth_verified"])

    def test_inputs_not_mutated(self):
        rows = quota_rows()
        before = copy.deepcopy(rows)
        profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(rows, before)


class LimitsTests(unittest.TestCase):
    def test_finite_prospective_budget_and_quality_floors(self):
        result = profiles.validate_limits(copy.deepcopy(profiles.LIMITS))
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["family_precision_min"], "0.90")
        self.assertEqual(result["addressable_recall_min"], "0.70")
        self.assertEqual(result["safe_fp_max"], 0)

    def test_any_silent_limit_or_threshold_edit_rejected(self):
        for key in profiles.LIMITS:
            values = copy.deepcopy(profiles.LIMITS)
            values[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.validate_limits(values)

    def test_bool_numeric_and_extra_keys_rejected(self):
        for change in ({"safe_fp_max": False}, {"repetitions": 3.0}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                profiles.validate_limits(dict(profiles.LIMITS, **change))


class HistoricalBurdenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "tests/product_corpus/historical/measurement-index.json"
        cls.index = json.loads(path.read_text(encoding="utf-8"))

    def test_original_occurrences_and_duplicate_fingerprint_preserved(self):
        result = profiles.historical_summary(self.index)
        self.assertEqual(result["counts"], {"FP": 47, "TP": 9, "unknown": 10})
        self.assertEqual(result["projects"]["cjson"]["findings"], 54)
        self.assertEqual(result["projects"]["cjson"]["distinct_fingerprints"], 53)
        self.assertFalse(result["fresh_measurement"])
        self.assertFalse(result["raw_evidence_verified"])

    def test_lost_or_duplicate_occurrence_rejected(self):
        for mutation in ("drop", "duplicate-index", "fingerprint-dedupe"):
            index = copy.deepcopy(self.index)
            rows = index["projects"]["cjson"]["occurrences"]
            if mutation == "drop":
                rows.pop()
            elif mutation == "duplicate-index":
                rows[1]["occurrence_index"] = rows[0]["occurrence_index"]
            else:
                seen = set()
                index["projects"]["cjson"]["occurrences"] = [
                    row for row in rows if row["diagnostic"]["fingerprint"] not in seen
                    and not seen.add(row["diagnostic"]["fingerprint"])]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.historical_summary(index)

    def test_relabeling_old_unknown_is_not_a_historical_update(self):
        index = copy.deepcopy(self.index)
        row = next(row for row in index["projects"]["cjson"]["occurrences"] if row["classification"] == "unknown")
        row["classification"] = "FP"
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)

    def test_training_origin_cannot_be_declared_holdout(self):
        index = copy.deepcopy(self.index)
        index["selection"] = "independent-evaluation"
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)

    def test_missing_source_rationale_or_revision_rejected(self):
        for field, value in (("rationale", ""), ("source_refs", []),
                             ("occurrence_index", True)):
            index = copy.deepcopy(self.index)
            index["projects"]["cjson"]["occurrences"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.historical_summary(index)
        index = copy.deepcopy(self.index)
        index["source_revision"] = "f" * 40
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)


class SourceProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "scripts/product_profiles.json"
        cls.manifest = json.loads(path.read_text(encoding="utf-8"))

    def test_three_exact_source_inventories_not_configured_coverage(self):
        result = profiles.source_metadata(self.manifest)
        self.assertEqual(result["source_files"], 734)
        self.assertEqual(result["projects"], ["cjson", "tinyxml2", "googletest"])
        self.assertFalse(result["configured_coverage_verified"])
        self.assertFalse(result["actual_source_bytes_verified"])

    def test_different_source_versions_or_hashes_rejected(self):
        for key, value in (("version", "1.7.19"), ("revision", "e"*40),
                           ("archive_sha256", "e"*64), ("tree_inventory_sha256", "e"*64)):
            manifest = copy.deepcopy(self.manifest)
            manifest["projects"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_missing_duplicate_or_reordered_source_inventory_rejected(self):
        for mutation in ("missing", "duplicate", "reorder"):
            manifest = copy.deepcopy(self.manifest)
            files = manifest["projects"][0]["files"]
            if mutation == "missing":
                files.pop()
            elif mutation == "duplicate":
                files.append(copy.deepcopy(files[0]))
            else:
                files.reverse()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_same_hash_declaration_cannot_hide_different_file_records(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["projects"][0]["files"][0]["sha256"] = "e" * 64
        with self.assertRaises(ValueError):
            profiles.source_metadata(manifest)

    def test_unsafe_path_or_boolean_size_rejected(self):
        for key, value in (("path", "../escape"), ("path", "/absolute"),
                           ("path", "a//b"), ("bytes", True)):
            manifest = copy.deepcopy(self.manifest)
            manifest["projects"][0]["files"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_preliminary_state_is_not_completed_freeze(self):
        readiness = profiles.draft_readiness(self.manifest)
        self.assertEqual(readiness["state"], "DRAFT_NOT_FROZEN")
        self.assertFalse(readiness["task_ready"])
        self.assertFalse(readiness["product_qualified"])
        self.assertIn("independent evaluation selection and source-label review missing", readiness["gaps"])

    def test_historical_manifest_link_has_one_safe_path_and_digest(self):
        for field, value in (("historical_index", "../measurement-index.json"),
                             ("historical_index", "/tmp/measurement-index.json"),
                             ("historical_index_sha256", ""),
                             ("historical_index_sha256", "0" * 64),
                             ("historical_index_sha256", True)):
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_historical_reader_checks_manifest_against_actual_bytes(self):
        root = Path(__file__).resolve().parents[1]
        index = profiles.linked_historical_index(self.manifest, root)
        self.assertEqual(profiles.historical_summary(index)["counts"],
                         {"FP": 47, "TP": 9, "unknown": 10})
        manifest = copy.deepcopy(self.manifest)
        manifest["historical_index_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "historical index digest mismatch"):
            profiles.linked_historical_index(manifest, root)

    def test_historical_reader_rejects_missing_changed_and_symlink_bytes(self):
        root = Path(__file__).resolve().parents[1]
        original = (root / self.manifest["historical_index"]).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         self.manifest["historical_index_sha256"])
        with tempfile.TemporaryDirectory(prefix="codeskeptic-profile-link-") as directory:
            staged = Path(directory)
            index = staged / self.manifest["historical_index"]
            index.parent.mkdir(parents=True)
            with self.assertRaises(ValueError):
                profiles.linked_historical_index(self.manifest, staged)
            # Same parsed data, different bytes: canonicalization must not hide drift.
            index.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "historical index digest mismatch"):
                profiles.linked_historical_index(self.manifest, staged)
            index.unlink()
            index.symlink_to(root / self.manifest["historical_index"])
            with self.assertRaises(ValueError):
                profiles.linked_historical_index(self.manifest, staged)

    def test_all_profile_cli_commands_reject_stale_link_before_other_work(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="codeskeptic-profile-cli-link-") as directory:
            staged = Path(directory)
            manifest_path = staged / "scripts/product_profiles.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = copy.deepcopy(self.manifest)
            manifest["historical_index_sha256"] = "e" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            index_path = staged / manifest["historical_index"]
            index_path.parent.mkdir(parents=True)
            index_path.write_bytes((root / manifest["historical_index"]).read_bytes())
            for command in ("historical-check", "sources-check", "readiness"):
                with self.subTest(command=command):
                    result = subprocess.run(
                        [sys.executable, "-B", str(root / "scripts/product_profiles.py"),
                         command, "--root", str(staged)],
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("historical index digest mismatch", result.stderr)

    def test_claimed_quota_count_or_frozen_status_cannot_bypass_missing_data(self):
        for field, value in (("independent_quota_examples", 1020), ("state", "FROZEN")):
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.draft_readiness(manifest)


if __name__ == "__main__":
    unittest.main()
