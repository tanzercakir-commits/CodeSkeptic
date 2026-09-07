#!/usr/bin/env python3
"""Supervisor/report regressions, including actual owned-process failures."""
import copy
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

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

    def test_completed_parent_cannot_leave_a_quiet_owned_child_running(self):
        script = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"],'
                  'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print(p.pid)')
        result = runner.capture([sys.executable, '-c', script], self.root, 5)
        child = int(result['stdout'])
        try:
            status = Path('/proc') / str(child) / 'stat'
            # An already-killed orphan may await init's reap, but cannot run.
            self.assertTrue(not status.exists() or status.read_text().split()[2] in ('Z', 'X'))
        finally:
            try: os.kill(child, signal.SIGKILL)
            except ProcessLookupError: pass

    def test_invalid_limits_refuse_before_launch(self):
        for timeout in (0, -1, 901, float('nan'), float('inf')):
            with self.assertRaises(ValueError): runner.capture(['/missing'], self.root, timeout)

if __name__ == '__main__':
    unittest.main()
