#!/usr/bin/env python3
"""Bounded Linux sanitizer gate, with strict execution/evidence validation."""
import argparse
from collections import Counter
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
        result.update({name: value.decode('utf-8', errors='replace') for name, value in data.items()})
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
    require('[  PASSED  ] ' + str(len(names)) + ' tests.' in text, 'missing suite completion')
    require(not re.search(r'\[  (FAILED|SKIPPED)  \]', text), 'failed or skipped selected test')

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
                'seeds': build / 'fuzz/codeskeptic_resilience'}
    hashes = {name: sha(path) for name, path in binaries.items()}
    commands = json.loads((build / 'compile_commands.json').read_text())
    flags = '-fsanitize=address,undefined' if profile == 'asan' else '-fsanitize=undefined'
    selected = [row for row in commands if str(ROOT / 'src') + '/' in row['file'] or
                str(ROOT / 'tests') + '/' in row['file'] or str(ROOT / 'fuzz') + '/' in row['file']]
    require(selected and any(row['file'].endswith('/fuzz/ResilienceSeeds.cpp') for row in selected), 'missing driver compilation')
    require(any(row['file'].endswith('/src/analyzer/WorkerProtocol.cpp') for row in selected), 'missing instrumented core')
    for row in selected:
        arguments = row.get('arguments') or shlex.split(row['command'])
        require(flags in arguments and '-fno-sanitize-recover=all' in arguments, 'uninstrumented repository compilation')
        require(not any(arg.startswith('-fno-sanitize=') for arg in arguments), 'disabled instrumentation')
    out.mkdir()
    result = {'schema': 'codeskeptic-resilience/v1', 'profile': profile, 'source_revision': revision, 'source_tree': tree,
              'binary_sha256': hashes, 'compile_commands_sha256': sha(build / 'compile_commands.json'),
              'instrumented_repository_commands': len(selected), 'prebuilt_compiler_libraries_instrumented': False,
              'checks': {}, 'passed': False}
    env = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    if profile == 'asan':
        env['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:detect_leaks=1'
    def execute(label, command, timeout, environment=env):
        observed = capture(command, out, timeout, environment)
        save(out / (label + '.json'), observed)
        successful(observed)
        result['checks'][label] = {'evidence_sha256': sha(out / (label + '.json')),
                                   'elapsed_seconds': observed['elapsed_seconds']}
        return observed
    try:
        for name, binary in binaries.items():
            symbols = execute('instrumentation-' + name, ['nm', '--defined-only', str(binary)], 30)['stdout']
            require(bool(re.search(r'\b__asan_init\b', symbols)) == (profile == 'asan'), 'ASan binary profile mismatch')
            require(re.search(r'\b__ubsan_handle_[A-Za-z0-9_]+_abort\b', symbols), 'missing nonrecovering UBSan runtime')
        version = execute('version', [str(binaries['analyzer']), '--version'], 10)['stdout'].strip().removeprefix('CodeSkeptic ')
        require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-dev\+g' + revision[:12], version), 'binary/source mismatch')
        result['version'] = version
        if profile == 'asan':
            for target in ('contract', 'worker', 'identity'):
                seeded_env = dict(env, ASAN_OPTIONS=env['ASAN_OPTIONS'] + ':hard_rss_limit_mb=1024')
                observed = execute('seeds-' + target, [str(binaries['seeds']), '--target', target,
                                   '--seed', str(SEED), '--iterations', str(ITERATIONS)], 60, seeded_env)
                result['checks']['seeds-' + target]['summary'] = seed_result(observed, target, version)
        expression = '--gtest_filter=' + FILTERS[profile]
        listed = execute('test-discovery', [str(binaries['tests']), expression, '--gtest_list_tests'], 30)
        names = discovered_tests(listed['stdout'])
        result['selected_tests'] = names
        actual = execute('suite', [str(binaries['tests']), expression], 300 if profile == 'asan' else 900)
        suite_result(actual, names)
        require(checkout(revision) == tree and {name: sha(path) for name, path in binaries.items()} == hashes,
                'source or binaries changed during qualification')
        result['passed'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    save(out / 'results.json', result)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, choices=tuple(FILTERS))
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
