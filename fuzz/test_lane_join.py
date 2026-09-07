#!/usr/bin/env python3
"""Closed three-lane receipt regression tests; fixture records are not measurements."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run_resilience as runner
import verify_lanes
import test_runner


class LaneJoinTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-lane-join-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.revision = 'a' * 40
        self.tree = 'b' * 40
        self.version = '0.4.9-dev+g' + self.revision[:12]
        self.lanes = {p: self.root / p for p in runner.PROFILES}
        self.manifest = runner.source_manifest()
        self.records = {}
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=runner.ROOT).decode().split('\0')
        for profile, directory in self.lanes.items():
            directory.mkdir()
            executables = ['analyzer', 'tests', 'worker', 'resource', 'cache', 'corpus']
            if profile != 'native': executables.append('seeds')
            names = self.manifest[profile]
            objects = {output: 'c'*64 for _, output in runner.compilation_manifest(tracked, with_seeds=profile != 'native')}
            result = dict(schema='codeskeptic-resilience/v2', passed=True, profile=profile,
                source_revision=self.revision, source_tree=self.tree, lane_manifest=self.manifest,
                expected_tests=names, selected_tests=names, version=self.version, checks={},
                binary_sha256={name: 'd'*64 for name in executables+['runtime1', 'runtime2']},
                object_sha256=objects, compile_commands_sha256='e'*64, repository_compilation_commands=len(objects))
            self.records[profile] = result
            self.raw(profile, 'build-current', 'ninja: no work to do.\n')
            self.raw(profile, 'version', 'CodeSkeptic '+self.version+'\n')
            for name in executables:
                for symbol in ('__asan_init', '__ubsan_handle_add_overflow_abort'):
                    defined = profile == 'asan' or (profile == 'ubsan' and symbol != '__asan_init')
                    self.raw(profile, 'instrumentation-'+name+'-'+symbol, '0000 <'+symbol+'>:\n' if defined else '')
            self.raw(profile, 'test-discovery', ''.join(n.split('.')[0]+'.\n  '+n.split('.')[1]+'\n' for n in names))
            output = ''.join('[ RUN      ] '+n+'\n[       OK ] '+n+' (0 ms)\n' for n in names)
            self.raw(profile, 'suite', output+'[  PASSED  ] '+str(len(names))+(' test.\n' if len(names)==1 else ' tests.\n'))
            if profile == 'asan':
                fixture = test_runner.RunnerTest()
                fixture.version = self.version
                for target in ('contract', 'worker', 'identity'):
                    observed = fixture.observation(target)
                    self.raw(profile, 'seeds-'+target, observed['stdout'])
                    result['checks']['seeds-'+target]['summary'] = runner.seed_result(observed, target, self.version)
            self.flush(profile)

    def raw(self, profile, label, stdout, **changes):
        path = self.lanes[profile] / (label+'.json')
        value = dict(reason='', returncode=0, stdout=stdout, stderr='', elapsed_seconds=.01)
        value.update(changes)
        path.write_text(json.dumps(value))
        self.records[profile]['checks'][label] = {'evidence_sha256': runner.sha(path), 'elapsed_seconds': .01}

    def flush(self, profile):
        (self.lanes[profile] / 'results.json').write_text(json.dumps(self.records[profile]))

    def verify(self, lanes=None):
        with mock.patch.object(runner, 'checkout', return_value=self.tree):
            return verify_lanes.verify(self.lanes if lanes is None else lanes, self.revision, self.root/'joined.json')

    def test_complete_fixture_union_is_124_not_the_sum(self):
        result = self.verify()
        self.assertTrue(result['passed'])
        self.assertEqual(result['distinct_tests'], 124)
        self.assertEqual(result['lane_manifest'], self.manifest)

    def test_missing_lane_or_failed_lane_cannot_join(self):
        for profile in runner.PROFILES:
            with self.assertRaises(ValueError): self.verify({p: path for p, path in self.lanes.items() if p != profile})
            self.records[profile]['passed'] = False; self.flush(profile)
            with self.assertRaises(ValueError): self.verify()
            self.records[profile]['passed'] = True; self.flush(profile)

    def test_source_or_assignment_drift_fails_even_with_equal_counts(self):
        for profile in runner.PROFILES:
            original = copy.deepcopy(self.records[profile])
            for key, changed in (('source_revision', 'f'*40), ('source_tree', 'f'*40),
                                 ('selected_tests', ['Other.Test'] + self.manifest[profile][1:])):
                self.records[profile][key] = changed; self.flush(profile)
                with self.assertRaises(ValueError): self.verify()
                self.records[profile] = copy.deepcopy(original)
            self.flush(profile)

    def test_forged_native_success_without_actual_execution_fails(self):
        self.raw('native', 'suite', '[  PASSED  ] 1 test.\n'); self.flush('native')
        with self.assertRaises(ValueError): self.verify()

    def test_raw_failure_and_checksum_tampering_cannot_join(self):
        path = self.lanes['asan']/'suite.json'
        original = path.read_text()
        path.write_text(original+' ')
        with self.assertRaises(ValueError): self.verify()
        path.write_text(original)
        self.raw('asan', 'suite', json.loads(original)['stdout'], returncode=9); self.flush('asan')
        with self.assertRaises(ValueError): self.verify()

    def test_missing_build_object_and_check_are_rejected(self):
        result = self.records['ubsan']
        key = next(iter(result['object_sha256']))
        value = result['object_sha256'].pop(key); self.flush('ubsan')
        with self.assertRaises(ValueError): self.verify()
        result['object_sha256'][key] = value
        result['checks'].pop('version'); self.flush('ubsan')
        with self.assertRaises(ValueError): self.verify()

    def test_native_lane_with_sanitizer_symbols_is_rejected(self):
        self.raw('native', 'instrumentation-tests-__asan_init', '0000 <__asan_init>:\n'); self.flush('native')
        with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__':
    unittest.main()
