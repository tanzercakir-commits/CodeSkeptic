#!/usr/bin/env python3
"""Product metric negatives; synthetic data is not analyzer qualification."""
import copy
import unittest

import product_quality as quality


def occurrence(rule="null-deref", function="f", line=7, cwes=None):
    return {"rule": rule, "function": function, "line": line,
            "cwes": [476] if cwes is None else cwes}


class OccurrenceTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(quality.score([occurrence()], [occurrence()]),
                         {"tp": 1, "fp": 0, "fn": 0, "expected": 1, "observed": 1})

    def test_same_line_multiplicity_is_not_deduplicated(self):
        self.assertEqual(quality.score([occurrence(), occurrence()], [occurrence()])["fn"], 1)
        self.assertEqual(quality.score([occurrence()], [occurrence(), occurrence()])["fp"], 1)

    def test_wrong_line_function_rule_or_mapping_cannot_claim_tp(self):
        for key, value in (("line", 8), ("function", "other"),
                           ("rule", "memory-leak"), ("cwes", [401])):
            with self.subTest(key=key):
                changed = dict(occurrence(), **{key: value})
                result = quality.score([occurrence()], [changed])
                self.assertEqual((result["tp"], result["fp"], result["fn"]), (0, 1, 1))

    def test_cwe_mapping_is_set_equivalent_but_not_numeric_lookalike(self):
        left = occurrence("int-overflow", cwes=[190, 191])
        right = occurrence("int-overflow", cwes=[191, 190])
        self.assertEqual(quality.score([left], [right])["tp"], 1)
        for invalid in ([True], [190.0], [190, 190], [], [0]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                quality.score([occurrence(cwes=invalid)], [])

    def test_location_is_positive_integer_not_bool(self):
        for line in (True, False, 0, -1, 7.0, "7"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                quality.score([occurrence(line=line)], [])

    def test_missing_extra_and_non_string_fields_rejected(self):
        for change in ({"extra": 1}, {"function": ""}, {"function": None}, {"rule": 3}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                quality.score([dict(occurrence(), **change)], [])
        missing = occurrence()
        del missing["cwes"]
        with self.assertRaises(ValueError):
            quality.score([], [missing])

    def test_non_array_occurrences_rejected(self):
        for value in (None, {}, "", (occurrence(),)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                quality.score(value, [])

    def test_zero_denominators_are_null(self):
        value = quality.metrics(quality.score([], []), safe_fp=0)
        self.assertIsNone(value["precision"])
        self.assertIsNone(value["addressable_recall"])
        self.assertFalse(value["passed"])

    def test_exact_threshold_inclusive(self):
        value = quality.metrics({"tp": 63, "fp": 7, "fn": 27,
                                 "expected": 90, "observed": 70}, safe_fp=0)
        self.assertEqual(value["precision"], 0.9)
        self.assertEqual(value["addressable_recall"], 0.7)
        self.assertTrue(value["passed"])

    def test_either_threshold_failure_is_red(self):
        for tp, fp, fn in ((62, 7, 27), (63, 8, 27), (63, 7, 28)):
            with self.subTest(counts=(tp, fp, fn)):
                self.assertFalse(quality.metrics({"tp": tp, "fp": fp, "fn": fn,
                                                  "expected": tp+fn, "observed": tp+fp}, 0)["passed"])

    def test_safe_false_positive_is_independent_gate(self):
        counts = {"tp": 99, "fp": 1, "fn": 0, "expected": 99, "observed": 100}
        self.assertTrue(quality.metrics(counts, 0)["passed"])
        self.assertFalse(quality.metrics(counts, 1)["passed"])

    def test_counter_conservation_and_types(self):
        base = {"tp": 3, "fp": 1, "fn": 2, "expected": 5, "observed": 4}
        for key, value in (("tp", True), ("fn", -1), ("expected", 4),
                           ("observed", 5), ("fp", 1.0), ("extra", 0)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                quality.metrics(dict(base, **{key: value}), 0)
        for safe_fp in (True, -1, 2, None):
            with self.subTest(safe_fp=safe_fp), self.assertRaises(ValueError):
                quality.metrics(base, safe_fp)


class ProductTests(unittest.TestCase):
    def cases(self):
        return [{"id": "positive", "family": "null-deref", "subprofile": None,
                 "role": "buggy", "expected": [occurrence()]},
                {"id": "safe", "family": "null-deref", "subprofile": None,
                 "role": "safe", "expected": []},
                {"id": "boundary", "family": "null-deref", "subprofile": None,
                 "role": "unknown", "expected": None}]

    def rows(self):
        return [{"id": "positive", "status": "MEASURED", "observed": [occurrence()]},
                {"id": "safe", "status": "MEASURED", "observed": []},
                {"id": "boundary", "status": "MEASURED", "observed": []}]

    def test_unknown_does_not_become_safe_or_enter_denominator(self):
        value = quality.summarize(self.cases(), self.rows())["null-deref"]
        self.assertEqual(value["metrics"]["expected"], 1)
        self.assertEqual(value["roles"], {"buggy": 1, "safe": 1, "unknown": 1})
        self.assertEqual(value["unscored_occurrences"], 0)

    def test_unknown_findings_remain_visible_without_becoming_fp(self):
        rows = self.rows()
        rows[-1]["observed"] = [occurrence()]
        value = quality.summarize(self.cases(), rows)["null-deref"]
        self.assertEqual(value["unscored_occurrences"], 1)
        self.assertEqual(value["metrics"]["fp"], 0)

    def test_crash_timeout_missing_family_and_partial_are_red_not_clean(self):
        for status in ("CRASH", "TIMEOUT", "INCOMPLETE", "PLANNED_NOT_IMPLEMENTED"):
            rows = self.rows()
            rows[0].update(status=status, observed=None)
            with self.subTest(status=status):
                value = quality.summarize(self.cases(), rows)["null-deref"]
                self.assertFalse(value["measurement_complete"])
                self.assertIsNone(value["metrics"])
                self.assertFalse(value["passed"])

    def test_failure_cannot_have_fabricated_empty_diagnostics(self):
        rows = self.rows()
        rows[0].update(status="TIMEOUT", observed=[])
        with self.assertRaises(ValueError):
            quality.summarize(self.cases(), rows)

    def test_exact_case_set_required(self):
        for rows in (self.rows()[:-1], self.rows()+[self.rows()[0]], []):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                quality.summarize(self.cases(), rows)
        rows = self.rows()
        rows[-1]["id"] = "ghost"
        with self.assertRaises(ValueError):
            quality.summarize(self.cases(), rows)

    def test_safe_cannot_contain_expected_bug(self):
        cases = self.cases()
        cases[1]["expected"] = [occurrence()]
        with self.assertRaises(ValueError):
            quality.summarize(cases, self.rows())

    def test_unknown_cannot_claim_zero_expected(self):
        cases = self.cases()
        cases[-1]["expected"] = []
        with self.assertRaises(ValueError):
            quality.summarize(cases, self.rows())

    def test_bad_status_or_role_rejected(self):
        rows = self.rows()
        rows[0]["status"] = "SKIPPED_PASS"
        with self.assertRaises(ValueError):
            quality.summarize(self.cases(), rows)
        cases = self.cases()
        cases[0]["role"] = "benign"
        with self.assertRaises(ValueError):
            quality.summarize(cases, self.rows())

    def test_other_family_alarm_cannot_count_for_target(self):
        rows = self.rows()
        rows[0]["observed"] = [occurrence("memory-leak", cwes=[401])]
        value = quality.summarize(self.cases(), rows)["null-deref"]
        self.assertEqual(value["metrics"]["tp"], 0)
        self.assertEqual(value["metrics"]["fn"], 1)
        self.assertEqual(value["metrics"]["fp"], 1)

    def test_bounds_subprofiles_are_scored_separately(self):
        cases, rows = self.cases()[:2], self.rows()[:2]
        for case in cases:
            case.update(family="bounds", subprofile="cwe-121")
        cases[0]["expected"] = [occurrence("bounds", cwes=[121, 787])]
        rows[0]["observed"] = copy.deepcopy(cases[0]["expected"])
        value = quality.summarize(cases, rows)
        self.assertEqual(set(value), {"bounds", "bounds/cwe-121"})
        self.assertTrue(value["bounds/cwe-121"]["passed"])

    def test_bad_subprofile_cannot_manufacture_quality_bucket(self):
        cases = self.cases()
        cases[0]["subprofile"] = "cwe-121"
        with self.assertRaises(ValueError):
            quality.summarize(cases, self.rows())

    def test_input_objects_not_mutated(self):
        cases, rows = self.cases(), self.rows()
        before = copy.deepcopy((cases, rows))
        quality.summarize(cases, rows)
        self.assertEqual((cases, rows), before)


if __name__ == "__main__":
    unittest.main()
