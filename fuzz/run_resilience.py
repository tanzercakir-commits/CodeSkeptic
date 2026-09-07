#!/usr/bin/env python3
"""Bounded Linux sanitizer gate, with strict execution/evidence validation."""
import argparse
import base64
import binascii
from collections import Counter
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SEED = 20260907
ITERATIONS = 4096
FILTERS = {
    'asan': 'ContractParserTest.*:SidecarTest.*:McpServerTest.Envelope*:WorkerProtocolTest.*:'
            'InputIdentityTest.*:InputCommandIdentityTest.*:RuntimeIdentityTest.*:DiskEvidenceStoreTest.*',
    'ubsan': 'AnalysisCoordinatorTest.*:AnalysisCacheTest.*:ResourceBudgetTest.*:DiskEvidenceStoreTest.*',
}
NATIVE_TEST = 'InputIdentityTest.TransientOpenFailureCannotBecomeReusableStatusOnlyEvidence'
AST_TESTS = frozenset('SidecarTest.' + name for name in (
    'RequiresFromSidecar_CallSiteViolation', 'RequiresFromSidecar_SeedsCalleeBody',
    'MalformedFileDoesNotPublishEarlierGuarantees', 'QualifiedAndUnmatchedAnchorsPreserveValidGuarantees',
    'RejectionReportsEveryIssueOnceAtAbsoluteLine', 'TextAndFileLimitsAreInclusiveAndDoNotPublishGuarantees',
    'EnsuresFromSidecar_ViolationPointsAtCskFile', 'ArityAnchor_Binds',
    'MalformedLines_AreContractSyntaxErrors', 'NoSidecarFile_NoEffect'))
PROFILES = ('asan', 'ubsan', 'native')

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(path):
    require(path.is_file() and not path.is_symlink(), 'nonregular artifact: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def capture(command, cwd, timeout, env=None, limit=2 * 1024 * 1024):
    require(os.name == 'posix', 'owned process-group supervisor requires POSIX')
    require(math.isfinite(timeout) and 0 < timeout <= 900 and type(limit) is int and 0 < limit <= 8 * 1024 * 1024,
            'invalid supervision budget')
    result = {'command': command, 'timeout_seconds': timeout, 'output_limit_bytes_per_stream': limit,
              'cwd': str(cwd), 'sanitizer_options': {key: (os.environ if env is None else env).get(key, '')
                       for key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')},
              'reason': '', 'returncode': None, 'stdout': '', 'stderr': ''}
    started = time.monotonic()
    data = {'stdout': bytearray(), 'stderr': bytearray()}
    process = None
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as events:
            for name in data:
                events.register(getattr(process, name), selectors.EVENT_READ, name)
            while events.get_map() and not result['reason']:
                if time.monotonic() - started >= timeout:
                    result['reason'] = 'timeout'
                    break
                for event, _ in events.select(min(.05, timeout)):
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    if not chunk:
                        events.unregister(event.fileobj)
                        continue
                    dest = data[event.data]
                    available = limit - len(dest)
                    dest.extend(chunk[:available])
                    if len(chunk) > available:
                        result['reason'] = 'output_limit'
                        break
            while not result['reason']:
                # Keep the exact parent waitable until group cleanup. Reaping
                # it early permits a successful quiet parent to leave children
                # running, and releases its PID before the final killpg.
                state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if state is not None:
                    break
                if time.monotonic() - started >= timeout:
                    result['reason'] = 'timeout'
                    break
                time.sleep(.01)
    except OSError as error:
        result['reason'] = 'launch_or_capture_error'
        data['stderr'].extend(str(error).encode()[:limit])
    finally:
        if process is not None:
            # Parent PID is still owned/unreaped: also stop descendants that
            # closed their inherited pipes before their parent returned zero.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            result['returncode'] = process.returncode
            for name in data:
                getattr(process, name).close()
        for name, value in data.items():
            decoded = value.decode('utf-8', errors='replace')
            result[name] = decoded
            # Ordinary UTF-8 is already lossless. Preserve original bytes only
            # where replacement decoding would otherwise erase their identity.
            result[name + '_raw_base64'] = (None if decoded.encode('utf-8') == value
                else base64.b64encode(value).decode('ascii'))
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
    return result

def successful(result):
    require(not result['reason'] and result['returncode'] == 0, 'process failed: ' + str(result['reason']))
    require(not re.search(r'(ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|SUMMARY: .*Sanitizer)',
                          result['stdout'] + result['stderr']), 'sanitizer diagnostic despite exit zero')

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value

def seed_result(result, target, version):
    successful(result)
    value = json.loads(result['stdout'], object_pairs_hook=unique)
    require(type(value) is dict and set(value) == set(
        'schema target version seed iterations seed_sha256 seed_cases prefix_executions executions accepted rejected boundaries'.split()),
        'seed evidence fields')
    require(value['schema'] == 'codeskeptic-resilience-seeds/v1' and value['target'] == target
            and value['version'] == version, 'seed identity')
    for key in ('seed', 'iterations', 'seed_cases', 'prefix_executions', 'executions', 'accepted', 'rejected', 'boundaries'):
        require(type(value[key]) is int and value[key] >= 0, 'seed typed counter')
    require(value['seed'] == SEED and value['iterations'] == ITERATIONS, 'seed budget mismatch')
    require(value['seed_cases'] == {'contract': 16, 'worker': 5, 'identity': 6}[target]
            and 1 <= value['prefix_executions'] <= 4096, 'seed set/prefix coverage')
    require(value['executions'] == ITERATIONS + value['seed_cases'] + value['prefix_executions'], 'seed executions missing')
    require(value['accepted'] > 0 and value['rejected'] > 0 and value['accepted'] + value['rejected'] ==
            value['executions'] * (1 if target == 'contract' else 2), 'seed branch coverage')
    require(value['boundaries'] == (27 if target == 'contract' else 1), 'boundary checks missing')
    require(type(value['seed_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['seed_sha256']), 'seed digest')
    return value

def discovered_tests(output):
    suite = None
    names = []
    for line in output.splitlines():
        item = line.split('#', 1)[0].strip()
        if item.endswith('.') and not line.startswith(' '):
            suite = item
        elif line.startswith('  ') and item:
            require(suite is not None, 'test without suite')
            names.append(suite + item)
    require(names and len(names) == len(set(names)), 'zero or duplicate discovered tests')
    require(not any('DISABLED_' in name for name in names), 'disabled test in selected profile')
    return names

def suite_result(result, names):
    successful(result)
    text = result['stdout']
    ran = re.findall(r'^\[ RUN      \] (\S+)\s*$', text, re.M)
    passed = re.findall(r'\[       OK \] (\S+) \([0-9]+ ms\)\s*$', text, re.M)
    require(Counter(ran) == Counter(passed) == Counter(names), 'discovered/run/pass test mismatch')
    completion = str(len(names)) + (' test.' if len(names) == 1 else ' tests.')
    require('[  PASSED  ] ' + completion in text, 'missing suite completion')
    require(not re.search(r'\[  (FAILED|SKIPPED)  \]', text), 'failed or skipped selected test')

def source_manifest(root=ROOT):
    # This explicit Linux profile uses ordinary TEST/TEST_F declarations only.
    # Unknown conditional/macro changes fail by discovery mismatch, not by
    # silently reducing the source contract to whatever the binary contains.
    inactive = {'DiskEvidenceStoreTest.UnsupportedPlatformNeverTouchesDisk',
                'AnalysisCacheTest.UnqualifiedRuntimePlatformKeepsOrdinaryFreshResults'}
    declared = []
    for path in sorted((root / 'tests').glob('*.cpp')):
        declared.extend(suite + '.' + name for suite, name in re.findall(
            r'^TEST(?:_F)?\(\s*(\w+)\s*,\s*(\w+)\s*\)', path.read_text(), re.M))
    require(all(declared.count(name) == 1 for name in inactive), 'Linux inactive declarations changed')
    original = {}
    for profile, expressions in FILTERS.items():
        expected = []
        for expression in expressions.split(':'):
            matched = [name for name in declared if name not in inactive and fnmatch.fnmatchcase(name, expression)]
            require(matched, 'required source test family missing: ' + expression)
            expected.extend(matched)
        require(len(expected) == len(set(expected)), 'duplicate source-selected tests')
        original[profile] = set(expected)
    sidecars = {name for name in declared if name.startswith('SidecarTest.')}
    require(sidecars == AST_TESTS | {'SidecarTest.ParseText_EntriesAndIssues'},
            'sidecar lane assignment needs explicit source review')
    require(NATIVE_TEST in original['asan'] and AST_TESTS <= original['asan']
            and not (AST_TESTS | {NATIVE_TEST}) & original['ubsan'], 'invalid lane reassignment')
    lanes = {'asan': original['asan'] - AST_TESTS - {NATIVE_TEST},
             'ubsan': original['ubsan'] | AST_TESTS, 'native': {NATIVE_TEST}}
    require(set.union(*lanes.values()) == set.union(*original.values()), 'unassigned source test')
    require(lanes['asan'] & lanes['ubsan'] == original['asan'] & original['ubsan'],
            'original intentional sanitizer overlap changed')
    return {profile: sorted(names) for profile, names in lanes.items()}

def source_tests(profile, root=ROOT):
    return source_manifest(root)[profile]

def execution_specs(profile, build, names):
    binaries = {name: build / relative for name, relative in {
        'analyzer': 'src/codeskeptic', 'tests': 'tests/codeskeptic_tests',
        'worker': 'tests/codeskeptic_worker_fixture', 'resource': 'tests/codeskeptic_resource_fixture',
        'cache': 'tests/codeskeptic_cache_fixture', 'corpus': 'src/codeskeptic_corpus_inputs',
        'seeds': 'fuzz/codeskeptic_resilience'}.items() if name != 'seeds' or profile != 'native'}
    options = {'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1',
               'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1:detect_leaks=1' if profile == 'asan' else ''}
    specs = {}
    def add(label, command, timeout, selected_options=options):
        specs[label] = {'command': command, 'timeout_seconds': timeout,
                        'output_limit_bytes_per_stream': 2 * 1024 * 1024, 'sanitizer_options': selected_options}
    targets = ['codeskeptic_tests'] + ([] if profile == 'native' else ['codeskeptic_resilience'])
    add('build-current', ['ninja', '-C', str(build), '-n'] + targets, 30)
    add('version', [str(binaries['analyzer']), '--version'], 10)
    for name, binary in binaries.items():
        for symbol in ('__asan_init', '__ubsan_handle_add_overflow_abort'):
            add('instrumentation-' + name + '-' + symbol,
                ['objdump', '-d', '--disassemble=' + symbol, str(binary)], 30)
    expression = '--gtest_filter=' + ':'.join(names)
    add('test-discovery', [str(binaries['tests']), expression, '--gtest_list_tests'], 30)
    add('suite', [str(binaries['tests']), expression], {'asan': 300, 'ubsan': 900, 'native': 60}[profile])
    if profile == 'asan':
        for target in ('contract', 'worker', 'identity'):
            add('seeds-' + target, [str(binaries['seeds']), '--target', target,
                '--seed', str(SEED), '--iterations', str(ITERATIONS)], 60,
                dict(options, ASAN_OPTIONS=options['ASAN_OPTIONS'] + ':hard_rss_limit_mb=1024'))
    return specs

def validate_envelope(observed, expected, directory):
    require(isinstance(observed, dict) and set(observed) == set(expected) |
            {'cwd', 'reason', 'returncode', 'stdout', 'stderr', 'stdout_raw_base64',
             'stderr_raw_base64', 'elapsed_seconds'},
            'missing or unexpected execution-envelope field')
    require(all(observed[key] == value for key, value in expected.items())
            and observed['cwd'] == str(directory), 'command, directory, options or budget mismatch')
    require(type(observed['returncode']) is int and observed['returncode'] == 0
            and type(observed['reason']) is str and observed['reason'] == ''
            and type(observed['timeout_seconds']) is int
            and type(observed['output_limit_bytes_per_stream']) is int, 'malformed success envelope')
    elapsed = observed['elapsed_seconds']
    require(type(elapsed) in (int, float) and math.isfinite(elapsed)
            and 0 <= elapsed <= expected['timeout_seconds'] + 5, 'invalid elapsed time')
    # Five seconds above is only post-exit cleanup/accounting. Output limits
    # always count original bytes, not decoded characters or replacement bytes.
    limit = expected['output_limit_bytes_per_stream']
    for key in ('stdout', 'stderr'):
        decoded, encoded = observed[key], observed[key + '_raw_base64']
        require(isinstance(decoded, str) and len(decoded) <= limit, 'invalid captured output')
        if encoded is None:
            raw = decoded.encode('utf-8')
        else:
            require(isinstance(encoded, str) and len(encoded) <= 4 * ((limit + 2) // 3),
                    'invalid lossless output size')
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError('invalid lossless output encoding') from error
            require(raw.decode('utf-8', errors='replace') == decoded and decoded.encode('utf-8') != raw,
                    'lossless bytes and replacement text disagree')
        require(len(raw) <= limit, 'captured byte budget exceeded')

def validate_discovery(names, expected):
    require(Counter(names) == Counter(expected), 'source/discovered test identity mismatch')

def compilation_manifest(paths, root=ROOT, with_seeds=True):
    expected = set()
    for name in paths:
        path = Path(name)
        if path.suffix != '.cpp': continue
        if name.startswith('src/'):
            target = 'codeskeptic' if name == 'src/main.cpp' else 'codeskeptic_core'
            output = 'src/CMakeFiles/' + target + '.dir/' + name[4:] + '.o'
        elif name.startswith('tests/') and len(path.parts) == 2:
            output = 'tests/CMakeFiles/codeskeptic_tests.dir/' + path.name + '.o'
        elif name == 'fuzz/ResilienceSeeds.cpp':
            if not with_seeds: continue
            output = 'fuzz/CMakeFiles/codeskeptic_resilience.dir/ResilienceSeeds.cpp.o'
        elif name == 'scripts/corpus_compile_commands.cpp':
            output = 'src/CMakeFiles/codeskeptic_corpus_inputs.dir/__/scripts/corpus_compile_commands.cpp.o'
        else: continue
        expected.add((str(root / name), output))
    for target, source in (('worker', 'WorkerProtocolTest.cpp'), ('resource', 'ResourceBudgetTest.cpp'),
                           ('cache', 'UnitEvidenceStoreTest.cpp'), ('runtime_1', 'UnitEvidenceStoreTest.cpp'),
                           ('runtime_2', 'UnitEvidenceStoreTest.cpp')):
        target = ('codeskeptic_runtime_fixture_' + target[-1] if target.startswith('runtime_')
                  else 'codeskeptic_' + target + '_fixture')
        require('tests/' + source in paths, 'required fixture source missing')
        expected.add((str(root / 'tests' / source), 'tests/CMakeFiles/' + target + '.dir/' + source + '.o'))
    seed_object = (str(root / 'fuzz/ResilienceSeeds.cpp'),
                   'fuzz/CMakeFiles/codeskeptic_resilience.dir/ResilienceSeeds.cpp.o')
    require(len(expected) > 5 and (seed_object in expected) == with_seeds,
            'incomplete source compilation manifest')
    return expected

def compilation_rows(commands, expected, profile, build, root=ROOT):
    selected = [row for row in commands if row['file'].startswith(str(root) + '/')]
    require(Counter((row['file'], row.get('output')) for row in selected) == Counter(expected),
            'source/target compilation manifest mismatch')
    flags = {'asan': ['-fsanitize=address,undefined'], 'ubsan': ['-fsanitize=undefined'], 'native': []}[profile]
    for row in selected:
        arguments = row.get('arguments') or shlex.split(row['command'])
        require(row['directory'] == str(build) and arguments.count('-o') == arguments.count('-c') == 1
                and arguments[arguments.index('-o') + 1] == row['output']
                and arguments[arguments.index('-c') + 1] == row['file'], 'compilation path mismatch')
        require([arg for arg in arguments if arg.startswith('-fsanitize=')] == flags
                and (profile == 'native' or '-fno-sanitize-recover=all' in arguments),
                'repository compilation profile mismatch')
        require(not any(arg.startswith(('-fno-sanitize=', '-fsanitize-recover=')) for arg in arguments),
                'disabled or recovering instrumentation')
    return selected

def checkout(revision):
    process = subprocess.run(['git', 'rev-parse', '--show-toplevel', 'HEAD', 'HEAD^{tree}'],
                             cwd=ROOT, capture_output=True, text=True, check=True, timeout=10)
    lines = process.stdout.splitlines()
    require(lines[:2] == [str(ROOT), revision], 'source checkout identity mismatch')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, timeout=10).strip(), 'dirty checkout')
    return lines[2]

def run(profile, build, revision, out):
    require(sys.platform.startswith('linux'), 'qualified supervisor profile requires Linux')
    require(re.fullmatch('[0-9a-f]{40}', revision), 'exact source revision required')
    tree = checkout(revision)
    require(out.is_absolute() and out.parent.resolve(strict=True) == out.parent, 'unsafe evidence parent')
    require(ROOT not in out.parents, 'evidence must be outside source checkout')
    require(build.is_absolute() and build.resolve(strict=True) == build, 'unsafe build directory')
    binaries = {'analyzer': build / 'src/codeskeptic', 'tests': build / 'tests/codeskeptic_tests',
                'seeds': build / 'fuzz/codeskeptic_resilience',
                'worker': build / 'tests/codeskeptic_worker_fixture',
                'resource': build / 'tests/codeskeptic_resource_fixture',
                'cache': build / 'tests/codeskeptic_cache_fixture',
                'corpus': build / 'src/codeskeptic_corpus_inputs',
                'runtime1': build / 'tests/runtime-fixture-1/libcodeskeptic_runtime_fixture.so',
                'runtime2': build / 'tests/runtime-fixture-2/libcodeskeptic_runtime_fixture.so'}
    if profile == 'native': del binaries['seeds']
    hashes = {name: sha(path) for name, path in binaries.items()}
    commands = json.loads((build / 'compile_commands.json').read_text())
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT, timeout=10).decode().split('\0')
    expected = compilation_manifest(tracked, with_seeds=profile != 'native')
    selected = compilation_rows(commands, expected, profile, build)
    objects = {output: sha(build / output) for _, output in sorted(expected)}
    manifest = source_manifest()
    expected_tests = manifest[profile]
    out.mkdir()
    result = {'schema': 'codeskeptic-resilience/v2', 'profile': profile, 'source_revision': revision, 'source_tree': tree,
              'build_directory': str(build), 'execution_directory': str(out),
              'binary_sha256': hashes, 'compile_commands_sha256': sha(build / 'compile_commands.json'),
              'repository_compilation_commands': len(selected), 'prebuilt_compiler_libraries_instrumented': False,
              'object_sha256': objects, 'expected_tests': expected_tests, 'lane_manifest': manifest,
              'checks': {}, 'passed': False}
    specs = execution_specs(profile, build, expected_tests)
    env = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1', ASAN_OPTIONS='')
    if profile == 'asan':
        env['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:detect_leaks=1'
    def execute(label, command, timeout, environment=env):
        observed = capture(command, out, timeout, environment)
        save(out / (label + '.json'), observed)
        successful(observed)
        validate_envelope(observed, specs[label], out)
        result['checks'][label] = {'evidence_sha256': sha(out / (label + '.json')),
                                   'elapsed_seconds': observed['elapsed_seconds']}
        return observed
    try:
        targets = ['codeskeptic_tests'] + ([] if profile == 'native' else ['codeskeptic_resilience'])
        current_build = execute('build-current', ['ninja', '-C', str(build), '-n'] + targets, 30)['stdout']
        require(current_build.splitlines()[-1:] == ['ninja: no work to do.']
                and not re.search(r'^\[[0-9]+/', current_build, re.M), 'build is stale or incomplete')
        for name in ('analyzer', 'tests', 'seeds', 'worker', 'resource', 'cache', 'corpus'):
            if name not in binaries: continue
            for symbol in ('__asan_init', '__ubsan_handle_add_overflow_abort'):
                symbols = execute('instrumentation-' + name + '-' + symbol,
                                  ['objdump', '-d', '--disassemble=' + symbol, str(binaries[name])], 30)['stdout']
                defined = bool(re.search(r'^[0-9a-f]+ <' + symbol + r'>:$', symbols, re.M))
                instrumented = profile == 'asan' or (profile == 'ubsan' and symbol != '__asan_init')
                require(defined == instrumented, 'binary sanitizer profile mismatch')
        version = execute('version', [str(binaries['analyzer']), '--version'], 10)['stdout'].strip().removeprefix('CodeSkeptic ')
        require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-dev\+g' + revision[:12], version), 'binary/source mismatch')
        result['version'] = version
        if profile == 'asan':
            for target in ('contract', 'worker', 'identity'):
                seeded_env = dict(env, ASAN_OPTIONS=env['ASAN_OPTIONS'] + ':hard_rss_limit_mb=1024')
                observed = execute('seeds-' + target, [str(binaries['seeds']), '--target', target,
                                   '--seed', str(SEED), '--iterations', str(ITERATIONS)], 60, seeded_env)
                result['checks']['seeds-' + target]['summary'] = seed_result(observed, target, version)
        expression = '--gtest_filter=' + ':'.join(expected_tests)
        listed = execute('test-discovery', [str(binaries['tests']), expression, '--gtest_list_tests'], 30)
        names = discovered_tests(listed['stdout'])
        validate_discovery(names, expected_tests)
        result['selected_tests'] = names
        actual = execute('suite', [str(binaries['tests']), expression],
                         {'asan': 300, 'ubsan': 900, 'native': 60}[profile])
        suite_result(actual, names)
        require(checkout(revision) == tree and {name: sha(path) for name, path in binaries.items()} == hashes,
                'source or binaries changed during qualification')
        require(sha(build / 'compile_commands.json') == result['compile_commands_sha256']
                and {output: sha(build / output) for _, output in sorted(expected)} == objects,
                'compilation metadata or objects changed during qualification')
        result['passed'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    save(out / 'results.json', result)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, choices=PROFILES)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.profile, args.build, args.revision, args.out)
        print(json.dumps({key: result[key] for key in ('profile', 'passed', 'error') if key in result}, sort_keys=True))
        return 0 if result['passed'] else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('RESILIENCE_FAIL: ' + str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
