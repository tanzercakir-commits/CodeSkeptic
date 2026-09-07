#!/usr/bin/env python3
"""Supervisor/report regressions, including actual owned-process failures."""
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_resilience as runner

class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-resilience-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.version = '0.4.9-dev+g0123456789ab'

    def observation(self, target='contract'):
        count = {'contract': 16, 'worker': 5, 'identity': 6}[target]
        executed = runner.ITERATIONS + count + 10
        value = dict(schema='codeskeptic-resilience-seeds/v1', target=target, version=self.version,
                     seed=runner.SEED, iterations=runner.ITERATIONS, seed_sha256='a'*64,
                     seed_cases=count, prefix_executions=10, executions=executed, accepted=1,
                     rejected=executed*(1 if target == 'contract' else 2)-1,
                     boundaries=27 if target == 'contract' else 1)
        return dict(reason='', returncode=0, stdout=json.dumps(value), stderr='')

    def test_all_three_seed_profiles_need_both_decoder_branches(self):
        for target in ('contract', 'worker', 'identity'):
            runner.seed_result(self.observation(target), target, self.version)

    def test_seed_missing_wrong_duplicate_fields_fail(self):
        original = self.observation()
        for key, wrong in (('seed', 0), ('iterations', 0), ('executions', 0), ('accepted', 0),
                           ('boundaries', 0), ('prefix_executions', 0), ('seed_cases', 0),
                           ('version', 'wrong'), ('seed_sha256', ''), ('rejected', True)):
            value = json.loads(original['stdout']); value[key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.seed_result(dict(original, stdout=json.dumps(value)), 'contract', self.version)
        for text in ('', '{}', original['stdout'][:-1] + ',"seed":20260907}'):
            with self.assertRaises(ValueError):
                runner.seed_result(dict(original, stdout=text), 'contract', self.version)

    def test_zero_exit_with_sanitizer_diagnostic_is_not_success(self):
        for diagnostic in ('ERROR: AddressSanitizer: heap-buffer-overflow', 'runtime error: signed integer overflow',
                           'SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior'):
            with self.assertRaises(ValueError):
                runner.successful(dict(self.observation(), stderr=diagnostic))

    def test_failed_process_cannot_supply_passing_seed_json(self):
        for fields in ({'reason': 'timeout'}, {'returncode': 7}, {'returncode': -9}, {'reason': 'output_limit'}):
            with self.assertRaises(ValueError):
                runner.seed_result(dict(self.observation(), **fields), 'contract', self.version)

    def test_discovery_and_execution_identities_must_match(self):
        names = runner.discovered_tests('Suite.\n  First\n  Second/0 # parameter\n')
        text = ''.join('[ RUN      ] '+n+'\n[       OK ] '+n+' (0 ms)\n' for n in names)
        good = dict(reason='', returncode=0, stdout=text+'[  PASSED  ] 2 tests.\n', stderr='')
        runner.suite_result(good, names)
        for changed in (good['stdout'].replace('Second/0', 'Other'), good['stdout'].replace('[       OK ]', '[  SKIPPED ]'),
                        good['stdout'] + '[ RUN      ] Suite.First\n'):
            with self.assertRaises(ValueError):
                runner.suite_result(dict(good, stdout=changed), names)
        for listed in ('', 'Suite.\n  DISABLED_Test\n', 'Suite.\n  A\n  A\n'):
            with self.assertRaises(ValueError): runner.discovered_tests(listed)

    def test_actual_success_and_nonzero_exit(self):
        good = runner.capture([sys.executable, '-c', 'print("complete")'], self.root, 5)
        runner.successful(good)
        self.assertEqual(good['stdout'], 'complete\n')
        bad = runner.capture([sys.executable, '-c', 'raise SystemExit(7)'], self.root, 5)
        self.assertEqual(bad['returncode'], 7)
        with self.assertRaises(ValueError): runner.successful(bad)

    def test_missing_executable_is_failure(self):
        result = runner.capture([str(self.root/'missing')], self.root, 1)
        self.assertEqual(result['reason'], 'launch_or_capture_error')
        with self.assertRaises(ValueError): runner.successful(result)

    def test_timeout_kills_and_reaps_direct_child(self):
        result = runner.capture([sys.executable, '-c', 'import time; time.sleep(10)'], self.root, .15)
        self.assertEqual(result['reason'], 'timeout')
        self.assertEqual(result['returncode'], -signal.SIGKILL)
        self.assertLess(result['elapsed_seconds'], 3)

    def test_output_limit_is_enforced_during_execution(self):
        result = runner.capture([sys.executable, '-c', 'print("x"*100000)'], self.root, 5, limit=32)
        self.assertEqual(result['reason'], 'output_limit')
        self.assertEqual(len(result['stdout']), 32)
        with self.assertRaises(ValueError): runner.successful(result)

    def test_byte_envelope_preserves_actual_invalid_utf8_without_relaxing_caps(self):
        for payload in (b'abc', '\u2603'.encode('utf-8'), bytes([255, 254, 253]), '\ufffd'.encode('utf-8')):
            with self.subTest(payload_length=len(payload)):
                command = [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(bytes('+repr(list(payload))+'))']
                result = runner.capture(command, self.root, 5, limit=3)
                runner.successful(result)
                spec = {key: result[key] for key in ('command', 'timeout_seconds',
                        'output_limit_bytes_per_stream', 'sanitizer_options')}
                runner.validate_envelope(result, spec, self.root)
                if payload == bytes([255, 254, 253]):
                    self.assertEqual(runner.base64.b64decode(result['stdout_raw_base64']), payload)
                    self.assertEqual(result['stdout'], '\ufffd' * 3)
                else:
                    self.assertIsNone(result['stdout_raw_base64'])
                with self.assertRaises(ValueError):
                    runner.validate_envelope(dict(result, stdout='\u2603'*3, stdout_raw_base64=None), spec, self.root)

    def test_completed_parent_cannot_leave_a_quiet_owned_child_running(self):
        script = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"],'
                  'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print(p.pid)')
        result = runner.capture([sys.executable, '-c', script], self.root, 5)
        child = int(result['stdout'])
        status = Path('/proc') / str(child) / 'stat'
        # An already-killed orphan may await init's reap, but cannot run.
        # Never signal this bare PID after its owning parent has been reaped.
        until = time.monotonic() + 1
        while True:
            try: state = status.read_text().split()[2]
            except FileNotFoundError: state = 'X'
            if state in ('Z', 'X') or time.monotonic() >= until: break
            time.sleep(.01)
        self.assertIn(state, ('Z', 'X'))

    def test_every_source_test_identity_is_required(self):
        for profile, count in (('asan', 58), ('ubsan', 82), ('native', 1)):
            names = runner.source_tests(profile)
            self.assertEqual(len(names), count)
            runner.validate_discovery(names, names)
            for changed in (names[1:], names + names[:1], names[:-1] + ['Other.Test'], []):
                with self.assertRaises(ValueError): runner.validate_discovery(changed, names)
            for expression in runner.FILTERS.get(profile, runner.NATIVE_TEST).split(':'):
                reduced = [name for name in names if not runner.fnmatch.fnmatchcase(name, expression)]
                with self.assertRaises(ValueError): runner.validate_discovery(reduced, names)

    def test_partition_preserves_all_identities_and_only_reviewed_overlap(self):
        lanes = {p: set(names) for p, names in runner.source_manifest().items()}
        self.assertEqual(set(lanes), {'asan', 'ubsan', 'native'})
        self.assertEqual(len(set.union(*lanes.values())), 124)
        self.assertEqual(len(lanes['asan'] & lanes['ubsan']), 17)
        self.assertEqual(lanes['native'], {runner.NATIVE_TEST})
        self.assertFalse(lanes['native'] & (lanes['asan'] | lanes['ubsan']))
        self.assertEqual(lanes['asan'] & runner.AST_TESTS, set())
        self.assertTrue(runner.AST_TESTS <= lanes['ubsan'])
        self.assertIn('SidecarTest.ParseText_EntriesAndIssues', lanes['asan'])
        with mock.patch.object(runner, 'AST_TESTS', runner.AST_TESTS - {next(iter(runner.AST_TESTS))}):
            with self.assertRaises(ValueError): runner.source_manifest()

    def test_one_native_test_requires_actual_single_test_completion(self):
        name = runner.NATIVE_TEST
        good = dict(reason='', returncode=0, stderr='', stdout=
                    '[ RUN      ] '+name+'\n[       OK ] '+name+' (0 ms)\n[  PASSED  ] 1 test.\n')
        runner.suite_result(good, [name])
        for text in ('[  PASSED  ] 1 test.\n', good['stdout'].replace('[       OK ]', '[  SKIPPED ]'),
                     good['stdout'].replace(name, 'Another.Test')):
            with self.assertRaises(ValueError): runner.suite_result(dict(good, stdout=text), [name])

    def test_native_compilation_cannot_hide_instrumentation(self):
        paths = ['src/analyzer/WorkerProtocol.cpp', 'tests/WorkerProtocolTest.cpp',
                 'tests/ResourceBudgetTest.cpp', 'tests/UnitEvidenceStoreTest.cpp', 'fuzz/ResilienceSeeds.cpp']
        expected = runner.compilation_manifest(paths, with_seeds=False)
        self.assertFalse(any('ResilienceSeeds' in output for _, output in expected))
        rows = [{'file': source, 'output': output, 'directory': str(self.root),
                 'arguments': ['clang++', '-o', output, '-c', source]} for source, output in sorted(expected)]
        runner.compilation_rows(rows, expected, 'native', self.root)
        for flag in ('-fsanitize=undefined', '-fsanitize=address,undefined', '-fno-sanitize=all'):
            changed = [dict(rows[0], arguments=rows[0]['arguments'] + [flag])] + rows[1:]
            with self.assertRaises(ValueError): runner.compilation_rows(changed, expected, 'native', self.root)

    def test_compilation_requires_every_source_target_and_no_disabled_flags(self):
        paths = ['src/contracts/ContractParser.cpp', 'src/analyzer/WorkerProtocol.cpp',
                 'tests/WorkerProtocolTest.cpp', 'tests/ResourceBudgetTest.cpp',
                 'tests/UnitEvidenceStoreTest.cpp', 'fuzz/ResilienceSeeds.cpp']
        expected = runner.compilation_manifest(paths)
        rows = [{'file': source, 'output': output, 'directory': str(self.root), 'arguments':
                 ['clang++', '-fsanitize=undefined', '-fno-sanitize-recover=all', '-o', output, '-c', source]}
                for source, output in sorted(expected)]
        runner.compilation_rows(rows, expected, 'ubsan', self.root)
        for position in range(len(rows)):
            with self.assertRaises(ValueError): runner.compilation_rows(rows[:position]+rows[position+1:], expected, 'ubsan', self.root)
        for changed in (rows + rows[:1], [dict(rows[0], output='wrong')] + rows[1:]):
            with self.assertRaises(ValueError): runner.compilation_rows(changed, expected, 'ubsan', self.root)
        for flag in ('-fno-sanitize=undefined', '-fsanitize=none', '-fsanitize-recover=all'):
            changed = [dict(rows[0], arguments=rows[0]['arguments'] + [flag])] + rows[1:]
            with self.assertRaises(ValueError): runner.compilation_rows(changed, expected, 'ubsan', self.root)

    def test_invalid_limits_refuse_before_launch(self):
        for timeout in (0, -1, 901, float('nan'), float('inf')):
            with self.assertRaises(ValueError): runner.capture(['/missing'], self.root, timeout)

    def test_reduced_compile_and_test_sets_cannot_manufacture_profile_pass(self):
        # Reproduce the original false-PASS at the actual run() boundary:
        # only the two formerly required compile rows and one discovered test.
        build = self.root / 'build'; build.mkdir()
        for relative in ('src/codeskeptic', 'tests/codeskeptic_tests', 'fuzz/codeskeptic_resilience'):
            path = build / relative; path.parent.mkdir(exist_ok=True); path.write_text('binary fixture')
        commands = [{'file': str(runner.ROOT / path), 'command':
                     'clang++ -fsanitize=undefined -fno-sanitize-recover=all'}
                    for path in ('src/analyzer/WorkerProtocol.cpp', 'fuzz/ResilienceSeeds.cpp')]
        (build / 'compile_commands.json').write_text(json.dumps(commands))
        def observed(command, *args, **kwargs):
            if command[0] == 'nm': text = '0000 T __ubsan_handle_add_overflow_abort\n'
            elif '--version' in command: text = 'CodeSkeptic ' + self.version + '\n'
            elif '--gtest_list_tests' in command: text = 'ResourceBudgetTest.\n  OnlyOne\n'
            else: text = ('[ RUN      ] ResourceBudgetTest.OnlyOne\n'
                          '[       OK ] ResourceBudgetTest.OnlyOne (0 ms)\n[  PASSED  ] 1 tests.\n')
            return dict(command=command, reason='', returncode=0, stdout=text, stderr='', elapsed_seconds=.01)
        with mock.patch.object(runner, 'checkout', return_value='a'*40), mock.patch.object(runner, 'capture', side_effect=observed):
            try:
                result = runner.run('ubsan', build, '0123456789ab'+'0'*28, self.root / 'evidence')
            except ValueError:
                return  # Strict preflight refusal is also a correct failure.
        self.assertFalse(result['passed'], 'missing instrumented inputs and required test families became PASS')

if __name__ == '__main__':
    unittest.main()
