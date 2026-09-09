#!/usr/bin/env python3
"""Synthetic manifest accounting checks; no sample or product quality claim."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

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


class NativeApiProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.model = json.loads((cls.root / "tests/product_corpus/native-api-models.json").read_text())

    def test_model_metadata_is_not_installed_or_native_qualification(self):
        result = profiles.native_api_metadata(self.model)
        self.assertEqual(result["sources"], 8)
        self.assertEqual(result["sinks"], 14)
        self.assertEqual(len(result["families"]), 4)
        self.assertFalse(result["product_qualified"])
        self.assertFalse(result["native_headers_verified"])
        self.assertFalse(result["installed"])

    def test_draft_cannot_claim_frozen_installed_or_measured(self):
        for mutation in ("state", *self.model["qualification"]):
            model = copy.deepcopy(self.model)
            if mutation == "state":
                model["state"] = "FROZEN"
            else:
                model["qualification"][mutation] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_exact_argument_indices_and_signature_roles_are_not_renameable(self):
        for field, value in (("argument_index", 1), ("argument_index", True),
                             ("family", "sql-injection"), ("symbol", "other_printf"),
                             ("header", "user.h"), ("platforms", ["windows-x64"])):
            model = copy.deepcopy(self.model)
            model["sinks"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["sinks"][0]["signature"]["parameters"] = ["int"]
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)

    def test_missing_duplicate_extra_or_reordered_api_rejected(self):
        for group in ("sources", "sinks"):
            for mutation in ("drop", "duplicate", "extra", "reorder"):
                model = copy.deepcopy(self.model)
                if mutation == "drop":
                    model[group].pop()
                elif mutation == "duplicate":
                    model[group].append(copy.deepcopy(model[group][0]))
                elif mutation == "extra":
                    row = copy.deepcopy(model[group][0])
                    row["id"] = "invented.api"
                    model[group].append(row)
                else:
                    model[group].reverse()
                with self.subTest(group=group, mutation=mutation), self.assertRaises(ValueError):
                    profiles.native_api_metadata(model)

    def test_output_buffer_return_and_native_socket_signatures_stay_distinct(self):
        for index, field, value in ((0, "kind", "output-buffer"),
                                     (1, "output_argument", 0),
                                     (4, "output_argument", 0),
                                     (7, "platforms", ["linux-x86_64"])):
            model = copy.deepcopy(self.model)
            model["sources"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_name_only_fake_header_and_user_body_trust_rejected(self):
        for field in ("name_only_allowed", "system_header_marker_alone_allowed",
                      "user_body_may_inherit_native_model", "invented_forward_declaration_allowed"):
            model = copy.deepcopy(self.model)
            model["declaration_identity"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_unknown_flow_and_mutation_cannot_be_declared_safe(self):
        for field in ("unknown_is_safe", "unknown_mutation_preserves_validation",
                      "existing_integer_or_nullness_domain_is_string_origin"):
            model = copy.deepcopy(self.model)
            model["flow"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_finite_flow_budgets_cannot_drift_or_accept_booleans(self):
        for field in self.model["flow"]["limits"]:
            for value in (0, True, self.model["flow"]["limits"][field] + 1):
                model = copy.deepcopy(self.model)
                model["flow"]["limits"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    profiles.native_api_metadata(model)

    def test_missing_helpers_trace_or_negative_boundary_rejected(self):
        for field in ("excluded_helpers", "trace_required", "required_behaviors"):
            model = copy.deepcopy(self.model)
            model["flow"][field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["required_negative_classes"].pop()
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)

    def test_category_platform_and_checked_value_trust_cannot_be_global(self):
        for field, value in (("generic_sanitizer_allowed", True),
                             ("mutation_invalidates", False),
                             ("ignored_or_failed_result_validates", True),
                             ("one_branch_validates_join", True)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["shared"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_sql_argument_parameter_and_bind_value_indices_are_different(self):
        for field, value in (("prepare_sanitizes_constructed_query", True),
                             ("bind_sanitizes_original_source", True),
                             ("sql_argument_index", 2), ("bind_value_argument_index", 1),
                             ("sql_parameter_index_base", 0)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["sql-injection"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_root_policy_and_containment_are_not_invented(self):
        for field, value in (("explicit_root_policy_required", False),
                             ("user_filename_alone_is_defect", True),
                             ("canonicalization_alone_is_containment", True),
                             ("string_prefix_alone_is_containment", True),
                             ("symlink_or_toctou_guarantee", True)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["path-traversal"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_format_data_role_and_shell_argv_boundaries_are_preserved(self):
        for group, field in (("format-string", "nonliteral_alone_is_defect"),
                             ("command-injection", "generic_quoting_allowed"),
                             ("command-injection", "separate_argv_is_automatic_shell_injection")):
            model = copy.deepcopy(self.model)
            model["category_validation"][group][field] = True
            with self.subTest(group=group, field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_missing_references_or_source_success_boundary_rejected(self):
        model = copy.deepcopy(self.model)
        model["sinks"][0]["references"] = ["nonexistent-reference"]
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["sources"][1]["failure"] = ""
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)


    def test_native_model_link_reads_actual_bytes_not_a_declared_count(self):
        manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
        model = profiles.linked_native_api_model(manifest, self.root)
        self.assertEqual(model, self.model)
        manifest["native_api_model_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "native API model digest mismatch"):
            profiles.linked_native_api_model(manifest, self.root)

    def test_native_model_path_and_digest_must_be_valid(self):
        original = profiles.read_json(self.root / "scripts/product_profiles.json")
        for key, value in (("native_api_model", "../model.json"),
                           ("native_api_model", "/tmp/model.json"),
                           ("native_api_model_sha256", "0" * 64),
                           ("native_api_model_sha256", True)):
            manifest = copy.deepcopy(original)
            manifest[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_all_manifest_cli_commands_reject_native_model_hash_drift(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-api-cli-link-") as directory:
            staged = Path(directory)
            manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
            for relative in (manifest["historical_index"], manifest["native_api_model"]):
                path = staged / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((self.root / relative).read_bytes())
            manifest["native_api_model_sha256"] = "e" * 64
            path = staged / "scripts/product_profiles.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")
            for command in ("api-check", "historical-check", "sources-check", "readiness"):
                with self.subTest(command=command):
                    result = subprocess.run(
                        [sys.executable, "-B", str(self.root / "scripts/product_profiles.py"),
                         command, "--root", str(staged)],
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("native API model digest mismatch", result.stderr)

    def test_native_model_reader_rejects_missing_changed_and_symlink_input(self):
        manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
        original = (self.root / manifest["native_api_model"]).read_bytes()
        with tempfile.TemporaryDirectory(prefix="codeskeptic-api-link-") as directory:
            staged = Path(directory)
            model = staged / manifest["native_api_model"]
            model.parent.mkdir(parents=True)
            with self.assertRaises(ValueError):
                profiles.linked_native_api_model(manifest, staged)
            model.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "native API model digest mismatch"):
                profiles.linked_native_api_model(manifest, staged)
            model.unlink()
            model.symlink_to(self.root / manifest["native_api_model"])
            with self.assertRaises(ValueError):
                profiles.linked_native_api_model(manifest, staged)


class ExternalInputTests(unittest.TestCase):
    """Synthetic file binding, never independent sample admission."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-external-input-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo, self.source = self.base / "repo", self.base / "source"
        self.repo.mkdir()
        self.source.mkdir()
        self.rows = []
        for role, path in (("candidate", "case.c"), ("origin", "origin.c"),
                           ("lineage", "lineage/parent.c"), ("notice", "notices/COPYING")):
            data = ("SOURCE_SENTINEL_" + role + "\n").encode()
            target = self.source / path
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(data)
            self.rows.append({"role": role, "path": path, "size_bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
        self.rows.sort(key=lambda row: row["path"])
        self.review = {"id": "synthetic-held-case",
                       "source": {"sha256": self.rows[0]["sha256"]},
                       "origin": {"sha256": next(r["sha256"] for r in self.rows if r["role"] == "origin")}}
        review_bytes = profiles.canonical(self.review).encode()
        (self.repo / "review.json").write_bytes(review_bytes)
        self.manifest = {"schema": "codeskeptic-product-external-inputs/v1",
                         "state": "SOURCE_BINDING_ONLY_NOT_FROZEN",
                         "id": self.review["id"],
                         "adjudication": {"path": "review.json", "sha256": hashlib.sha256(review_bytes).hexdigest()},
                         "inputs": self.rows}
        self.path = self.repo / "binding.json"
        self.save()

    def save(self):
        self.path.write_text(profiles.canonical(self.manifest), encoding="utf-8")

    def check(self):
        return profiles.verify_external_inputs(self.path, self.repo, self.source)

    def test_actual_bytes_bound_without_execution_or_admission(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("must not execute")):
            result = self.check()
        self.assertEqual(set(result), {"schema", "id", "binding_sha256", "adjudication_sha256",
                                     "source_bytes_verified", "verified_inputs", "verified_bytes",
                                     "independent_quota_examples", "task_ready", "product_qualified",
                                     "native_commands_bound", "license_qualified", "state"})
        self.assertTrue(result["source_bytes_verified"])
        self.assertEqual(result["verified_inputs"], 4)
        self.assertEqual(result["independent_quota_examples"], 0)
        for key in ("task_ready", "product_qualified", "native_commands_bound", "license_qualified"):
            self.assertIs(result[key], False)
        self.assertNotIn("SOURCE_SENTINEL", profiles.canonical(result))

    def test_missing_changed_and_extra_file_rejected(self):
        case = self.source / "case.c"
        original = case.read_bytes()
        for data in (None, b"x" * len(original), original + b"x"):
            if case.exists():
                case.unlink()
            if data is not None:
                case.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check()
        case.write_bytes(original)
        (self.source / "extra.c").write_bytes(b"x")
        with self.assertRaises(ValueError):
            self.check()

    def test_paths_roles_sizes_and_claims_reject_tampering(self):
        original = copy.deepcopy(self.manifest)
        for key, values in (("path", ("../escape", "/abs", "a/../case.c", "a//b", "a\\b", "a:stream", "CON.c", "case.c/child")),
                            ("role", ("header", "origin")), ("size_bytes", (True, -1, 16777217)),
                            ("sha256", ("0" * 64, "bad"))):
            for value in values:
                self.manifest = copy.deepcopy(original)
                self.manifest["inputs"][0][key] = value
                self.save()
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.check()
        for key, value in (("state", "FROZEN"), ("quota", True), ("id", "SOURCE_SENTINEL_BAD")):
            self.manifest = copy.deepcopy(original)
            self.manifest[key] = value
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()

    def test_duplicate_reordered_and_case_alias_inputs_rejected(self):
        original = copy.deepcopy(self.manifest)
        for operation in ("duplicate", "reorder", "case-alias"):
            self.manifest = copy.deepcopy(original)
            rows = self.manifest["inputs"]
            if operation == "duplicate":
                rows.append(copy.deepcopy(rows[0]))
            elif operation == "reorder":
                rows.reverse()
            else:
                row = copy.deepcopy(rows[0])
                row.update(path="CASE.c", role="lineage")
                rows.append(row)
                rows.sort(key=lambda item: item["path"])
            self.save()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.check()

    def test_changed_adjudication_or_candidate_origin_binding_rejected(self):
        for key in ("id", "source", "origin"):
            review = copy.deepcopy(self.review)
            review[key] = "different" if key == "id" else {"sha256": "e" * 64}
            data = profiles.canonical(review).encode()
            (self.repo / "review.json").write_bytes(data)
            self.manifest["adjudication"]["sha256"] = hashlib.sha256(data).hexdigest()
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()

    def test_stale_adjudication_digest_and_missing_cli_arguments_fail_closed(self):
        (self.repo / "review.json").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.check()
        script = Path(__file__).resolve().with_name("product_profiles.py")
        result = subprocess.run([sys.executable, "-B", str(script), "external-source-check"],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "PRODUCT_PROFILE_FAIL: external input binding rejected\n")

    def test_later_read_cannot_hide_change_to_earlier_input_or_manifest(self):
        original_read = profiles.external_read
        case = self.source / "case.c"
        original_case, original_manifest = case.read_bytes(), self.path.read_bytes()
        for operation in ("earlier-file", "manifest", "extra-file", "extra-directory"):
            case.write_bytes(original_case)
            self.path.write_bytes(original_manifest)
            changed = False
            def mutate(path, capture=False):
                nonlocal changed
                result = original_read(path, capture)
                if path == self.source / "origin.c":
                    changed = True
                    if operation == "earlier-file":
                        case.write_bytes(b"x" * len(original_case))
                    elif operation == "manifest":
                        self.path.write_bytes(original_manifest + b"\n")
                    elif operation == "extra-file":
                        (self.source / "extra").write_bytes(b"x")
                    else:
                        (self.source / "extra").mkdir()
                return result
            with self.subTest(operation=operation), mock.patch.object(profiles, "external_read", side_effect=mutate):
                with self.assertRaises(ValueError):
                    self.check()
            self.assertTrue(changed)
            extra = self.source / "extra"
            if extra.is_dir():
                extra.rmdir()
            elif extra.exists():
                extra.unlink()

    def test_duplicate_json_nonfinite_and_invalid_utf8_rejected(self):
        for payload in (b'{"state":1,"state":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff'):
            self.path.write_bytes(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.check()

    def test_root_containment_and_aliases_rejected(self):
        for source in (self.repo, self.base, self.repo / "absent", Path("source")):
            with self.subTest(source=source), self.assertRaises(ValueError):
                profiles.verify_external_inputs(self.path, self.repo, source)
        alias = self.base / "source-link"
        try:
            alias.symlink_to(self.source, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            profiles.verify_external_inputs(self.path, self.repo, alias)

    def test_leaf_intermediate_and_manifest_symlinks_rejected(self):
        leaf = self.source / "case.c"
        moved = self.base / "moved.c"
        leaf.rename(moved)
        try:
            leaf.symlink_to(moved)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            self.check()
        leaf.unlink()
        moved.rename(leaf)
        directory = self.source / "lineage"
        directory.rename(self.base / "moved-dir")
        directory.symlink_to(self.base / "moved-dir", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.check()
        directory.unlink()
        (self.base / "moved-dir").rename(directory)
        self.path.rename(self.repo / "moved.json")
        self.path.symlink_to(self.repo / "moved.json")
        with self.assertRaises(ValueError):
            self.check()

    def test_hardlinks_and_nonregular_files_rejected(self):
        leaf = self.source / "case.c"
        try:
            os.link(leaf, self.base / "hardlink")
        except OSError:
            self.skipTest("hardlinks unavailable")
        with self.assertRaises(ValueError):
            self.check()
        (self.base / "hardlink").unlink()
        leaf.unlink()
        leaf.mkdir()
        with self.assertRaises(ValueError):
            self.check()
        leaf.rmdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(leaf)
            with self.assertRaises(ValueError):
                self.check()

    def test_growth_rewrite_and_replacement_during_read_rejected(self):
        leaf = self.source / "case.c"
        original = leaf.read_bytes()
        for operation in ("growth", "rewrite", "replace"):
            leaf.write_bytes(original)
            read = os.read
            changed = False
            def mutate(fd, size):
                nonlocal changed
                data = read(fd, size)
                if not changed and data == original:
                    changed = True
                    if operation == "replace":
                        replacement = self.base / "replacement"
                        replacement.write_bytes(original)
                        replacement.replace(leaf)
                    else:
                        leaf.write_bytes(original + b"x" if operation == "growth" else b"x" * len(original))
                return data
            with self.subTest(operation=operation), mock.patch.object(os, "read", side_effect=mutate):
                with self.assertRaises(ValueError):
                    self.check()
            self.assertTrue(changed)

    def test_cli_success_and_failure_do_not_echo_source_or_parser_payload(self):
        script = Path(__file__).resolve().with_name("product_profiles.py")
        argv = [sys.executable, "-B", str(script), "external-source-check", "--root", str(self.repo),
                "--binding", str(self.path), "--external-root", str(self.source)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["source_bytes_verified"])
        self.path.write_text('{"x":SOURCE_SENTINEL_PRIVATE_PAYLOAD}', encoding="utf-8")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "PRODUCT_PROFILE_FAIL: external input binding rejected\n")
        self.assertNotIn("SOURCE_SENTINEL", result.stdout + result.stderr)


class GccStagingTests(unittest.TestCase):
    @staticmethod
    def stat_fixture(**changes):
        values = dict(st_dev=1, st_ino=2, st_mode=0o100600, st_nlink=1,
                      st_size=3, st_mtime_ns=5, st_ctime_ns=6, st_birthtime_ns=6)
        values.update(changes)
        return SimpleNamespace(**values)

    def read_stat_fixture(self, platform, before, opened, final=None, path_final=None):
        path = mock.Mock(spec=Path)
        path.is_absolute.return_value = True
        path.resolve.return_value = path
        path.lstat.side_effect = [before, path_final or before]
        with mock.patch.object(profiles.sys, 'platform', platform), \
                mock.patch.object(profiles.os, 'open', return_value=47), \
                mock.patch.object(profiles.os, 'fstat', side_effect=[opened, final or opened]), \
                mock.patch.object(profiles.os, 'read', side_effect=[b'abc', b'']), \
                mock.patch.object(profiles.os, 'close') as close:
            try:
                return profiles.external_read(path)
            finally:
                close.assert_called_once_with(47)

    def test_windows_creation_and_change_timestamps_are_distinct_queries(self):
        # CPython 3.12 Windows lstat exposes creation time as deprecated ctime;
        # fstat exposes ChangeTime. Both independently expose birthtime_ns.
        result = self.read_stat_fixture('win32', self.stat_fixture(),
                                       self.stat_fixture(st_ctime_ns=17))
        self.assertEqual(result[0], {'size_bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()})
        self.assertEqual(result[2], b'')

    def test_cross_query_normalization_keeps_all_other_identity_guards(self):
        for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_birthtime_ns'):
            opened = self.stat_fixture(st_ctime_ns=17, **{field: 99})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', self.stat_fixture(), opened)

    def test_raw_descriptor_and_path_ctime_drift_remain_rejected(self):
        for platform in ('win32', 'linux', 'darwin'):
            opened = self.stat_fixture(st_ctime_ns=17 if platform == 'win32' else 6)
            for query in ('descriptor', 'path'):
                changes = {'final': self.stat_fixture(st_ctime_ns=29)} if query == 'descriptor' else {
                    'path_final': self.stat_fixture(st_ctime_ns=29)}
                with self.subTest(platform=platform, query=query), self.assertRaises(ValueError):
                    self.read_stat_fixture(platform, self.stat_fixture(), opened, **changes)

    def test_final_descriptor_birthtime_drift_and_its_redacted_label(self):
        with self.assertRaises(profiles.ExternalIdentityError) as caught:
            self.read_stat_fixture('win32', self.stat_fixture(), self.stat_fixture(st_ctime_ns=17),
                                   final=self.stat_fixture(st_ctime_ns=17, st_birthtime_ns=876543210))
        message = profiles.gcc_stage_failure(caught.exception, 'verification')
        self.assertIn('identity=descriptor-final:birthtime_ns', message)
        self.assertNotIn('876543210', message)

    def test_birthtime_normalization_is_windows_only_and_requires_both_fields(self):
        for platform in ('linux', 'darwin'):
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                self.read_stat_fixture(platform, self.stat_fixture(), self.stat_fixture(st_ctime_ns=17))
        for field in ('before', 'opened', 'both'):
            before, opened = self.stat_fixture(), self.stat_fixture()
            if field in ('before', 'both'):
                del before.st_birthtime_ns
            if field in ('opened', 'both'):
                del opened.st_birthtime_ns
            if field == 'both':
                self.read_stat_fixture('win32', before, opened)
                opened.st_ctime_ns = 17
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', before, opened)
        for value in (None, True, '6'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', self.stat_fixture(), self.stat_fixture(st_birthtime_ns=value))

    def test_stat_rejection_diagnostics_contain_only_fixed_field_names(self):
        values = dict(st_dev=1, st_ino=2, st_mode=3, st_nlink=1, st_size=4, st_mtime_ns=5, st_ctime_ns=6)
        before = SimpleNamespace(**values)
        after = SimpleNamespace(**{**values, 'st_ino': 876543210})
        with self.assertRaises(profiles.ExternalIdentityError) as caught:
            profiles.check_external_identity(after, before, 'descriptor-open')
        message = profiles.gcc_stage_failure(caught.exception, 'verification')
        self.assertIn('identity=descriptor-open:inode', message)
        self.assertNotIn('876543210', message)
        forged = profiles.ExternalIdentityError('PRIVATE_SOURCE_SENTINEL', (1,), (2,))
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', profiles.gcc_stage_failure(forged, 'verification'))
        profiles.check_external_identity(before, before, 'descriptor-final')

    def test_staging_failure_location_never_contains_exception_payload(self):
        error = ValueError('PRIVATE_SOURCE_SENTINEL /private/location')
        message = profiles.gcc_stage_failure(error, 'destination')
        self.assertIn('destination', message)
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', message)
        self.assertNotIn('/private/location', message)
        message = profiles.gcc_stage_failure(error, 'PRIVATE_SOURCE_SENTINEL')
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', message)

    def test_adaptation_selects_only_frozen_lines_and_removes_instrumentation(self):
        lines = ["synthetic line " + str(i) for i in range(1, 67)]
        lines[7] = "static int __attribute__((noinline))"
        lines[64] = '  return synthetic; /* { dg-message "synthetic" } */'
        result = profiles.adapt_gcc_source(("\n".join(lines) + "\n").encode()).decode()
        self.assertEqual(len(result.splitlines()), 28)
        self.assertIn("static int\nsynthetic line 9", result)
        self.assertNotIn("noinline", result.split("*/", 1)[1])
        self.assertNotIn("synthetic line 59", result)
        self.assertNotIn("synthetic line 63", result)
        self.assertNotIn("synthetic line 33", result)
        self.assertTrue(result.endswith("  return synthetic;\nsynthetic line 66\n"))

    def test_adaptation_rejects_changed_structure_or_non_utf8(self):
        for payload in (b"short", b"\xff", b"unselected\n" * 66):
            with self.subTest(payload=payload[:10]), self.assertRaises(ValueError):
                profiles.adapt_gcc_source(payload)

    def test_download_is_bounded_hash_checked_and_never_follows_redirects(self):
        row = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        def response(payload):
            stream = io.BytesIO(payload)
            stream.status = 200
            return stream
        with mock.patch.object(profiles.urllib.request, "build_opener") as builder:
            opener = builder.return_value
            opener.open.return_value = response(b"abc")
            self.assertEqual(profiles.fetch_gcc_input("notices/COPYING3", row), b"abc")
            handler = builder.call_args.args[0]
            self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid"))
            argv = opener.open.call_args
            self.assertEqual(argv.kwargs, {"timeout": 30})
            self.assertEqual(argv.args[0], "https://raw.githubusercontent.com/gcc-mirror/gcc/5115c7e447fc07457443df874bf57840e8316d5f/COPYING3")
            for payload in (b"ab", b"abcd", b"xyz"):
                opener.open.return_value = response(payload)
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    profiles.fetch_gcc_input("notices/COPYING3", row)
            with self.assertRaises(ValueError):
                profiles.fetch_gcc_input("unapproved-source", row)

    def test_stage_refuses_existing_or_checkout_destination_before_network(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="codeskeptic-gcc-stage-") as directory:
            existing = Path(directory).resolve()
            marker = existing / "preserve"
            marker.write_bytes(b"original")
            with mock.patch.object(profiles.urllib.request, "build_opener", side_effect=AssertionError("no download")):
                for destination in (existing, root / "uncreated-case-stage", Path("relative")):
                    with self.subTest(destination=destination), self.assertRaises(ValueError):
                        profiles.stage_gcc_inputs(root, destination)
            self.assertEqual(marker.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
