#!/usr/bin/env python3
"""Small deterministic measurement contracts, not real-project qualification."""
import copy
import importlib.util
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REVISION = '435d17922bf31d258580419c7f2deca8d60e74ea'
VERSION = '0.4.9-dev+g' + REVISION[:12]
EVIDENCE_FLAGS = ('no_inputs', 'no_rules', 'tool_failed', 'summary_load_failed',
                  'summary_stale', 'summary_save_failed', 'baseline_load_failed',
                  'baseline_write_failed', 'baseline_recorded', 'report_write_failed')
spec = importlib.util.spec_from_file_location('measure_product', ROOT / 'scripts/measure_product.py')
measurement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurement)


def profile():
    return {'id': 'example', 'commands': {'/inputs/example/a.cpp': 1}, 'skipped': {}}


def report():
    return {'schema': 'codeskeptic-report/v1', 'complete': True, 'exit_code': 0,
            'tool': 'CodeSkeptic', 'tool_version': VERSION,
            'evidence': dict.fromkeys(EVIDENCE_FLAGS, False),
            'status': 'clean', 'total': 0, 'diagnostics': [],
            'finding_counts': {'total': 0, 'blocking': 0, 'report_only': 0},
            'coverage': {'schema': 'codeskeptic-source-coverage/v1', 'complete': True,
                'accept_partial_coverage': False, 'analyze_broken_tus': False,
                'attempted_tus': 1, 'analyzed_tus': 1, 'broken_tus': 0,
                'skipped_tus': 0, 'failed_tus': 0, 'recovery_tus': 0,
                'attempted_commands': 1, 'analyzed_commands': 1,
                'skipped_commands': 0, 'failed_commands': 0, 'incomplete_functions': 0,
                'sources': [{'file': '/inputs/example/a.cpp', 'status': 'analyzed',
                    'reason': 'analyzed', 'commands': 1, 'analyzed_commands': 1,
                    'skipped_commands': 0, 'failed_commands': 0, 'recovery_commands': 0,
                    'prepass': {'status': 'not_requested', 'reason': '', 'recovery_commands': 0}}]}}


class ProductMeasurementTest(unittest.TestCase):
    def test_complete_empty_report_is_not_global_accuracy(self):
        value = measurement.summarize_report(report(), 0, profile(), VERSION)
        self.assertEqual(value['findings'], 0)
        self.assertEqual(value['coverage_class'], 'complete-selected-inputs')
        self.assertIsNone(value['false_positives'])

    def test_partial_is_only_the_predeclared_slice(self):
        expected = profile()
        expected['commands']['/inputs/example/b.cpp'] = 1
        expected['skipped'] = {'/inputs/example/b.cpp': 'broken_translation_unit'}
        raw = report()
        raw['status'] = 'partial-accepted'
        coverage = raw['coverage']
        coverage.update(complete=False, accept_partial_coverage=True, attempted_tus=2,
                        broken_tus=1, skipped_tus=1, attempted_commands=2, skipped_commands=1)
        row = copy.deepcopy(coverage['sources'][0])
        row.update(file='/inputs/example/b.cpp', status='skipped', reason='broken_translation_unit',
                   analyzed_commands=0, skipped_commands=1)
        coverage['sources'].append(row)
        value = measurement.summarize_report(raw, 0, expected, VERSION)
        self.assertEqual(value['coverage_class'], 'predeclared-partial')
        with self.assertRaises(ValueError):
            measurement.summarize_report(raw, 0, profile(), VERSION)
        coverage['complete'] = True
        with self.assertRaises(ValueError):
            measurement.summarize_report(raw, 0, expected, VERSION)

    def test_bad_process_or_report_exit_rejected(self):
        for code in (1, 2, -9, True):
            with self.subTest(code=code), self.assertRaises(ValueError):
                measurement.summarize_report(report(), code, profile(), VERSION)

    def test_report_only_findings_are_not_clean(self):
        raw = report()
        raw.update(status='report-only', total=1, diagnostics=[{'fingerprint': 'csf1-' + 'a' * 16,
            'rule_id': 'bounds', 'blocks_verdict': False, 'capability_tier': 'experimental',
            'file': '/inputs/example/a.cpp', 'line': 1, 'column': 1}])
        raw['finding_counts'].update(total=1, report_only=1)
        value = measurement.summarize_report(raw, 0, profile(), VERSION)
        self.assertEqual(value['findings'], 1)
        self.assertEqual(value['report_only'], 1)
        self.assertIsNone(value['false_positives'])

    def test_blocking_finding_exit_and_counters_match(self):
        raw = report()
        raw.update(exit_code=1, status='findings', total=1,
                   diagnostics=[{'fingerprint': 'csf1-' + 'b' * 16,
                      'rule_id': 'memory-leak', 'blocks_verdict': True,
                      'capability_tier': 'supported', 'file': '/inputs/example/a.cpp',
                      'line': 1, 'column': 1}])
        raw['finding_counts'].update(total=1, blocking=1)
        self.assertEqual(measurement.summarize_report(raw, 1, profile(), VERSION)['blocking'], 1)
        raw['finding_counts']['blocking'] = 0
        with self.assertRaises(ValueError):
            measurement.summarize_report(raw, 1, profile(), VERSION)

    def test_invalid_finding_location_rejected(self):
        raw = report()
        raw.update(total=1, diagnostics=[{'fingerprint': 'csf1-' + 'a' * 16,
            'rule_id': 'bounds', 'blocks_verdict': False, 'capability_tier': 'experimental',
            'file': '/inputs/example/a.cpp', 'line': 1, 'column': 1}])
        raw['finding_counts'].update(total=1, report_only=1)
        for key, value in (('file', 'relative.cpp'), ('line', True), ('column', 0), ('fingerprint', 'invalid')):
            changed = copy.deepcopy(raw)
            changed['diagnostics'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                measurement.summarize_report(changed, 0, profile(), VERSION)

    def test_missing_duplicate_or_different_source_rejected(self):
        for change in ('missing', 'duplicate', 'different'):
            raw = report()
            if change == 'missing': raw['coverage']['sources'] = []
            if change == 'duplicate': raw['coverage']['sources'] *= 2
            if change == 'different': raw['coverage']['sources'][0]['file'] = '/other.cpp'
            with self.subTest(change=change), self.assertRaises(ValueError):
                measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_typed_and_reconciled_counters(self):
        for key in ('analyzed_tus', 'attempted_commands', 'failed_tus', 'incomplete_functions'):
            for value in (True, -1, 0.5, 99):
                raw = report()
                raw['coverage'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_incomplete_or_missing_schema_is_not_success(self):
        for changes in ({'complete': False}, {'schema': 'legacy'}, {'total': True}):
            raw = report()
            raw.update(changes)
            with self.assertRaises(ValueError):
                measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_foreign_stale_or_missing_report_identity_rejected(self):
        for key, value in (('tool', 'foreign'), ('tool', None),
                           ('tool_version', '0.4.9-dev+g000000000000'), ('tool_version', None)):
            raw = report()
            raw[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_failed_or_inconsistent_status_rejected(self):
        for status in ('failed', 'findings', 'report-only', 'partial-accepted', None):
            raw = report()
            raw['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_version_parser_binds_branded_output_to_source(self):
        self.assertEqual(measurement.parse_version('CodeSkeptic ' + VERSION + '\n', REVISION), VERSION)
        for stdout in (VERSION, 'OtherTool ' + VERSION, 'CodeSkeptic 0.4.9-dev+g000000000000\n',
                       'CodeSkeptic ' + VERSION + '\nextra', None):
            with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                measurement.parse_version(stdout, REVISION)
        with self.assertRaises(ValueError):
            measurement.parse_version('CodeSkeptic ' + VERSION, REVISION[:12])

    def test_expected_version_is_external_to_report(self):
        with self.assertRaises(ValueError):
            measurement.summarize_report(report(), 0, profile(), '0.4.9-dev+g000000000000')
        with self.assertRaises(ValueError):
            measurement.summarize_report(report(), 0, profile(), None)

    def test_bad_failure_evidence_rejected(self):
        for name in EVIDENCE_FLAGS:
            for value in (True, 0, None):
                raw = report()
                raw['evidence'][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    measurement.summarize_report(raw, 0, profile(), VERSION)
        for evidence in (None, {}, {'unexpected': False}):
            raw = report()
            raw['evidence'] = evidence
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                measurement.summarize_report(raw, 0, profile(), VERSION)

    def test_run_accepts_actual_branded_cli_version(self):
        # Mock process output only: this is a version-gate regression, not a scan.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / 'plan.json'
            plan.write_text(json.dumps(self.make_plan(root)))
            binary = root / 'binary'
            binary.write_text('mock process only\n')
            source = root / 'repository'
            source.mkdir()
            def git_output(command, **kwargs):
                return '' if 'status' in command else REVISION
            version = {'reason': '', 'returncode': 0, 'elapsed_seconds': 0.01,
                       'stdout': 'CodeSkeptic ' + VERSION + '\n', 'stderr': ''}
            with patch.object(measurement, 'ROOT', source), \
                 patch.object(measurement.subprocess, 'check_output', side_effect=git_output), \
                 patch.object(measurement, 'capture', side_effect=[version, RuntimeError('scan reached')]) as capture:
                with self.assertRaisesRegex(RuntimeError, 'scan reached'):
                    measurement.run(plan, binary, REVISION, root / 'output')
                self.assertEqual(capture.call_count, 2)

    def test_gnu_time_numbers_and_exit(self):
        text = 'elapsed_seconds=0.25\nuser_seconds=0.10\nsystem_seconds=0.05\npeak_rss_kib=1234\nexit_code=1\n'
        value = measurement.parse_time(text, 1)
        self.assertEqual(value['peak_rss_kib'], 1234)
        for damaged in (text.replace('0.25', 'nan'), text.replace('1234', '-1'),
                        text.replace('1234', '0'), text.replace('exit_code=1', 'exit_code=0'),
                        text + 'peak_rss_kib=1234\n', text.replace('user_seconds=0.10\n', '')):
            with self.subTest(damaged=damaged), self.assertRaises(ValueError):
                measurement.parse_time(damaged, 1)

    def test_strict_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input.json'
            for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', '{'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    measurement.load_json(path)

    def test_input_hash_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'
            path.write_text('fixed input\n')
            expected = {str(path): measurement.sha(path)}
            measurement.verify_inputs(expected)
            path.write_text('changed input\n')
            with self.assertRaises(ValueError): measurement.verify_inputs(expected)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(ValueError): measurement.sha(link)

    def test_timeout_and_absent_program_are_not_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            timed = measurement.capture([sys.executable, '-c', 'import time; time.sleep(5)'],
                                        Path(temporary), 0.1)
            self.assertEqual(timed['reason'], 'timeout')
            with self.assertRaises(ValueError): measurement.valid_execution(timed)
            absent = measurement.capture(['/definitely-absent-measurement-tool'], Path(temporary), 1)
            self.assertEqual(absent['reason'], 'launch_or_capture_error')
            with self.assertRaises(ValueError): measurement.valid_execution(absent)

    def test_bad_elapsed_or_reason_is_not_a_measurement(self):
        for elapsed, reason in ((math.inf, ''), (-1, ''), (True, ''), (1, 'output_limit')):
            with self.assertRaises(ValueError):
                measurement.valid_execution({'reason': reason, 'returncode': 0,
                                             'elapsed_seconds': elapsed})

    def test_real_gnu_time_nonzero_exit_accounting(self):
        self.assertTrue(Path('/usr/bin/time').is_file(), 'Linux measurement requires GNU time')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            timer = root / 'time.txt'
            format_string = 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\npeak_rss_kib=%M\nexit_code=%x'
            observed = measurement.capture(['/usr/bin/time', '--quiet', '-f', format_string,
                '-o', str(timer), '--', sys.executable, '-c', 'raise SystemExit(1)'], root, 3)
            measurement.valid_execution(observed)
            self.assertEqual(observed['returncode'], 1)
            self.assertGreater(measurement.parse_time(timer.read_text(), 1)['peak_rss_kib'], 0)

    def make_plan(self, root):
        plan = {'schema': 'codeskeptic-product-measurement-plan/v1', 'repetitions': 3,
                'timeout_seconds': 10, 'inputs': {}, 'projects': []}
        for name in ('alpha', 'bravo', 'charlie'):
            project = root / name
            project.mkdir()
            source = project / 'input.cpp'
            source.write_text('int value() { return 7; }\n')
            database = project / 'compile_commands.json'
            database.write_text(json.dumps([{'directory': str(project), 'file': str(source),
                                             'arguments': ['clang++', '-c', str(source)]}]))
            for path in (source, database): plan['inputs'][str(path)] = measurement.sha(path)
            plan['projects'].append({'id': name, 'upstream': 'https://example.invalid/' + name,
                'version': 'fixture-1', 'scope': 'test-only fake plan; no product qualification',
                'source_root': str(project), 'build_path': str(project),
                'commands': {str(source): 1}, 'skipped': {}})
        return plan

    def test_valid_plan_and_distinct_project_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = self.make_plan(Path(temporary))
            self.assertIs(measurement.validate_plan(plan), plan)
            for field in ('id', 'source_root', 'upstream'):
                changed = copy.deepcopy(plan)
                changed['projects'][1][field] = changed['projects'][0][field]
                with self.subTest(field=field), self.assertRaises(ValueError):
                    measurement.validate_plan(changed)
            with self.assertRaises(ValueError):
                measurement.validate_plan(dict(plan, projects=plan['projects'][:2]))

    def test_unfrozen_header_missing_database_and_command_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.make_plan(root)
            changed = copy.deepcopy(plan)
            del changed['inputs'][str(root / 'alpha/compile_commands.json')]
            with self.assertRaises(ValueError): measurement.validate_plan(changed)
            changed = copy.deepcopy(plan)
            changed['projects'][0]['commands'][str(root / 'alpha/input.cpp')] = 2
            with self.assertRaises(ValueError): measurement.validate_plan(changed)
            (root / 'alpha/header.h').write_text('int declared_value();\n')
            with self.assertRaises(ValueError): measurement.validate_plan(plan)

    def test_invalid_plan_budgets_and_complete_exclusion_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = self.make_plan(Path(temporary))
            for field, value in (('repetitions', True), ('repetitions', 0),
                                 ('timeout_seconds', math.inf), ('timeout_seconds', 241)):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    measurement.validate_plan(dict(plan, **{field: value}))
            changed = copy.deepcopy(plan)
            changed['projects'][0]['skipped'] = dict.fromkeys(changed['projects'][0]['commands'], 'broken_translation_unit')
            with self.assertRaises(ValueError): measurement.validate_plan(changed)


if __name__ == '__main__':
    unittest.main()
