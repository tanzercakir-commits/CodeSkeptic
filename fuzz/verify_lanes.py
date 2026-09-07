#!/usr/bin/env python3
"""Join three exact-source resilience lanes; not a release or hosted-CI gate."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import run_resilience as runner


def verify(lanes, revision, out):
    tree = runner.checkout(revision)
    runner.require(set(lanes) == set(runner.PROFILES), 'all three lanes are mandatory')
    runner.require(out.is_absolute() and out.parent.resolve(strict=True) == out.parent
                   and runner.ROOT not in out.parents, 'unsafe combined evidence path')
    manifest = runner.source_manifest()
    observed_hashes = {}
    def read(path, expected_hash=None):
        digest = runner.sha(path)
        runner.require(expected_hash is None or digest == expected_hash, 'evidence digest mismatch')
        observed_hashes[path] = digest
        return json.loads(path.read_text(), object_pairs_hook=runner.unique)
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=runner.ROOT, timeout=10).decode().split('\0')
    records = {}
    for profile in runner.PROFILES:
        directory = lanes[profile]
        runner.require(directory.is_absolute() and directory.resolve(strict=True) == directory
                       and runner.ROOT not in directory.parents, 'unsafe lane directory')
        result = read(directory / 'results.json')
        runner.require(result['schema'] == 'codeskeptic-resilience/v2' and result['passed'] is True
                       and result['profile'] == profile and result['source_revision'] == revision
                       and result['source_tree'] == tree, 'failed or mismatched lane')
        runner.require(result['lane_manifest'] == manifest and result['expected_tests'] == manifest[profile]
                       and sorted(result['selected_tests']) == manifest[profile], 'lane identity assignment mismatch')
        executables = ['analyzer', 'tests', 'worker', 'resource', 'cache', 'corpus']
        if profile != 'native': executables.append('seeds')
        objects = {output for _, output in runner.compilation_manifest(tracked, with_seeds=profile != 'native')}
        runner.require(set(result['binary_sha256']) == set(executables) | {'runtime1', 'runtime2'}
                       and set(result['object_sha256']) == objects
                       and result['repository_compilation_commands'] == len(objects), 'incomplete build identity')
        digests = [result['compile_commands_sha256'], *result['binary_sha256'].values(), *result['object_sha256'].values()]
        runner.require(all(isinstance(d, str) and re.fullmatch('[0-9a-f]{64}', d) for d in digests),
                       'invalid build digest')
        symbols = ('__asan_init', '__ubsan_handle_add_overflow_abort')
        labels = {'build-current', 'version', 'test-discovery', 'suite'}
        labels.update('instrumentation-' + name + '-' + symbol for name in executables for symbol in symbols)
        if profile == 'asan': labels.update('seeds-' + target for target in ('contract', 'worker', 'identity'))
        runner.require(set(result['checks']) == labels, 'missing or unexpected lane check')
        raw = {}
        for label in sorted(labels):
            raw[label] = read(directory / (label + '.json'), result['checks'][label]['evidence_sha256'])
            runner.successful(raw[label])
        current = raw['build-current']['stdout']
        runner.require(current.splitlines()[-1:] == ['ninja: no work to do.']
                       and not re.search(r'^\[[0-9]+/', current, re.M), 'stale measured build')
        for name in executables:
            for symbol in symbols:
                defined = bool(re.search(r'^[0-9a-f]+ <' + symbol + r'>:$',
                    raw['instrumentation-' + name + '-' + symbol]['stdout'], re.M))
                required = profile == 'asan' or (profile == 'ubsan' and symbol != '__asan_init')
                runner.require(defined == required, 'lane instrumentation mismatch')
        version = raw['version']['stdout'].strip().removeprefix('CodeSkeptic ')
        runner.require(version == result['version'] and re.fullmatch(
            r'[0-9]+\.[0-9]+\.[0-9]+-dev\+g' + revision[:12], version), 'lane version mismatch')
        runner.validate_discovery(runner.discovered_tests(raw['test-discovery']['stdout']), manifest[profile])
        runner.suite_result(raw['suite'], manifest[profile])
        if profile == 'asan':
            for target in ('contract', 'worker', 'identity'):
                actual = runner.seed_result(raw['seeds-' + target], target, version)
                runner.require(actual == result['checks']['seeds-' + target]['summary'], 'mutation summary mismatch')
        records[profile] = {'directory': str(directory), 'result_sha256': observed_hashes[directory / 'results.json'],
                            'selected_tests': len(manifest[profile])}
    runner.require(runner.checkout(revision) == tree and all(runner.sha(path) == digest
                   for path, digest in observed_hashes.items()), 'source or evidence changed while joining')
    summary = {'schema': 'codeskeptic-resilience-combined/v1', 'source_revision': revision,
               'source_tree': tree, 'lane_manifest': manifest, 'lanes': records, 'passed': True,
               'distinct_tests': len(set().union(*map(set, manifest.values()))),
               'limitations': ['No ASan qualification of Clang AST execution or prebuilt LLVM/Clang.',
                               'The unchanged FD-exhaustion test has native coverage only.',
                               'Full normal Linux, corpus and hosted Windows gates remain separate.']}
    runner.save(out, summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--out', type=Path, required=True)
    for profile in runner.PROFILES: parser.add_argument('--' + profile, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify({p: getattr(args, p) for p in runner.PROFILES}, args.revision, args.out)
        print(json.dumps({'passed': result['passed'], 'distinct_tests': result['distinct_tests']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('LANE_JOIN_FAIL: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
