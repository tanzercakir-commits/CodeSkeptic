#!/usr/bin/env python3
"""Offline fixed-input Linux CLI measurements; never an accuracy/release verdict."""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'fuzz'))
from run_resilience import capture, save

NUMERIC = {'attempted_tus', 'analyzed_tus', 'broken_tus', 'skipped_tus',
           'failed_tus', 'recovery_tus', 'attempted_commands', 'analyzed_commands',
           'skipped_commands', 'failed_commands', 'incomplete_functions'}
ROW_NUMERIC = {'commands', 'analyzed_commands', 'skipped_commands',
               'failed_commands', 'recovery_commands'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and not path.is_symlink(), 'artifact must be an absolute regular nonsymlink')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_json(path):
    path = Path(path)
    sha(path)
    require(path.stat().st_size <= 16 * 1024 * 1024, 'JSON size limit')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def number(text):
        value = float(text)
        require(math.isfinite(value), 'nonfinite JSON number')
        return value
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
                      parse_float=number, parse_constant=number)


def verify_inputs(inputs):
    require(type(inputs) is dict and 1 <= len(inputs) <= 20000, 'input inventory size')
    for name, expected in inputs.items():
        require(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected)
                and sha(Path(name)) == expected, 'input identity changed')


def finite(value, positive=False):
    return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)


def valid_execution(record):
    require(record.get('reason') == '' and type(record.get('returncode')) is int
            and record['returncode'] in (0, 1) and finite(record.get('elapsed_seconds'), True),
            'execution did not produce a bounded available measurement')


def parse_time(text, exit_code):
    keys = {'elapsed_seconds', 'user_seconds', 'system_seconds', 'peak_rss_kib', 'exit_code'}
    lines = text.splitlines()
    require(len(lines) == len(keys), 'time record fields')
    values = {}
    for line in lines:
        key, separator, raw = line.partition('=')
        require(separator and key in keys and key not in values, 'time record keys')
        if key in ('peak_rss_kib', 'exit_code'):
            require(re.fullmatch('[0-9]+', raw), 'time record integer')
            values[key] = int(raw)
        else:
            values[key] = float(raw)
            require(finite(values[key]), 'time record finite nonnegative seconds')
    require(type(exit_code) is int and values['exit_code'] == exit_code
            and exit_code in (0, 1) and values['peak_rss_kib'] > 0, 'time record exit/RSS')
    return values


def summarize_report(report, exit_code, project):
    require(type(report) is dict and report.get('schema') == 'codeskeptic-report/v1'
            and report.get('complete') is True and type(exit_code) is int
            and exit_code in (0, 1) and type(report.get('exit_code')) is int
            and report['exit_code'] == exit_code, 'unavailable or inconsistent report')
    commands, skipped = project['commands'], project['skipped']
    require(type(commands) is dict and commands and type(skipped) is dict
            and set(skipped) < set(commands)
            and all(type(n) is int and n > 0 for n in commands.values()), 'declared command scope')
    coverage = report.get('coverage')
    require(type(coverage) is dict and set(coverage) == NUMERIC | {
        'schema', 'complete', 'accept_partial_coverage', 'analyze_broken_tus', 'sources'},
        'coverage schema fields')
    require(coverage['schema'] == 'codeskeptic-source-coverage/v1'
            and coverage['complete'] is (not bool(skipped))
            and coverage['accept_partial_coverage'] is bool(skipped)
            and coverage['analyze_broken_tus'] is False, 'coverage completeness/profile mismatch')
    require(all(type(coverage[k]) is int and coverage[k] >= 0 for k in NUMERIC), 'typed coverage counters')
    sources = coverage['sources']
    require(type(sources) is list and len(sources) == len(commands), 'source row count')
    seen = set()
    for row in sources:
        require(type(row) is dict and set(row) == ROW_NUMERIC | {'file', 'status', 'reason', 'prepass'},
                'source row fields')
        name = row['file']
        require(type(name) is str and name in commands and name not in seen, 'source row identity')
        seen.add(name)
        excluded = name in skipped
        expected = dict(commands=commands[name], analyzed_commands=0 if excluded else commands[name],
                        skipped_commands=commands[name] if excluded else 0, failed_commands=0, recovery_commands=0)
        require(all(type(row[k]) is int and row[k] == v for k, v in expected.items()), 'source command accounting')
        require(row['status'] == ('skipped' if excluded else 'analyzed')
                and row['reason'] == (skipped[name] if excluded else 'analyzed'), 'source status drift')
        require(row['prepass'] == {'status': 'not_requested', 'reason': '', 'recovery_commands': 0}
                and type(row['prepass']['recovery_commands']) is int, 'unexpected prepass')
    expected = dict.fromkeys(NUMERIC, 0)
    skipped_commands = sum(commands[name] for name in skipped)
    expected.update(attempted_tus=len(commands), analyzed_tus=len(commands)-len(skipped),
                    broken_tus=len(skipped), skipped_tus=len(skipped), attempted_commands=sum(commands.values()),
                    analyzed_commands=sum(commands.values())-skipped_commands, skipped_commands=skipped_commands)
    require(all(coverage[k] == value for k, value in expected.items()), 'coverage aggregate drift')
    diagnostics, total, counts = report.get('diagnostics'), report.get('total'), report.get('finding_counts')
    require(type(total) is int and total >= 0 and type(diagnostics) is list and len(diagnostics) == total,
            'finding count mismatch')
    identities, rules, tiers = Counter(), Counter(), Counter()
    blocking = 0
    for diagnostic in diagnostics:
        require(type(diagnostic) is dict and type(diagnostic.get('fingerprint')) is str
                and re.fullmatch('csf1-[0-9a-f]{16}', diagnostic['fingerprint'])
                and type(diagnostic.get('blocks_verdict')) is bool
                and type(diagnostic.get('rule_id')) is str
                and re.fullmatch('[a-z][a-z0-9-]*', diagnostic['rule_id'])
                and diagnostic.get('capability_tier') in ('supported', 'experimental')
                and type(diagnostic.get('file')) is str and Path(diagnostic['file']).is_absolute()
                and not any(c in diagnostic['file'] for c in '\r\n\0')
                and all(type(diagnostic.get(k)) is int and diagnostic[k] > 0 for k in ('line', 'column')),
                'finding identity/tier/location')
        require(not diagnostic['blocks_verdict'] or diagnostic['capability_tier'] == 'supported',
                'experimental blocking finding')
        blocking += diagnostic['blocks_verdict']
        rules[diagnostic['rule_id']] += 1
        tiers[diagnostic['capability_tier']] += 1
        identities[(diagnostic['fingerprint'], diagnostic['rule_id'], diagnostic['blocks_verdict'])] += 1
    require(type(counts) is dict and set(counts) == {'total', 'blocking', 'report_only'}
            and all(type(n) is int for n in counts.values())
            and counts == {'total': total, 'blocking': blocking, 'report_only': total-blocking}
            and exit_code == int(blocking > 0), 'finding verdict/counters mismatch')
    identity = json.dumps(sorted((list(key), count) for key, count in identities.items()), separators=(',', ':'))
    return {'coverage_class': 'predeclared-partial' if skipped else 'complete-selected-inputs',
            'coverage': coverage, 'findings': total, 'blocking': blocking, 'report_only': total-blocking,
            'rules': dict(sorted(rules.items())), 'tiers': dict(sorted(tiers.items())),
            'finding_identity_sha256': hashlib.sha256(identity.encode()).hexdigest(),
            'false_positives': None, 'accuracy_note': 'Finding burden only; source-bound independent adjudication required.'}


def validate_plan(plan):
    require(type(plan) is dict and set(plan) == {'schema', 'repetitions', 'timeout_seconds', 'inputs', 'projects'}
            and plan['schema'] == 'codeskeptic-product-measurement-plan/v1', 'measurement plan schema')
    require(type(plan['repetitions']) is int and plan['repetitions'] == 3
            and finite(plan['timeout_seconds'], True) and plan['timeout_seconds'] <= 240, 'measurement budget')
    verify_inputs(plan['inputs'])
    projects = plan['projects']
    require(type(projects) is list and 3 <= len(projects) <= 6, 'three distinct projects required')
    ids, roots, upstreams = set(), set(), set()
    for project in projects:
        require(type(project) is dict and set(project) == {
            'id', 'upstream', 'version', 'scope', 'source_root', 'build_path', 'commands', 'skipped'}, 'project fields')
        require(type(project['id']) is str and re.fullmatch('[a-z][a-z0-9-]{1,30}', project['id'])
                and project['id'] not in ids, 'project identifier')
        ids.add(project['id'])
        require(type(project['upstream']) is str and project['upstream'].startswith('https://')
                and project['upstream'] not in upstreams, 'distinct declared upstream identities')
        upstreams.add(project['upstream'])
        require(all(type(project[k]) is str and project[k].strip() for k in ('version', 'scope')), 'project scope/version')
        root = Path(project['source_root'])
        require(root.is_absolute() and root.resolve() == root and root.is_dir() and root not in roots,
                'distinct source root')
        roots.add(root)
        for path in root.rglob('*'):
            require(not path.is_symlink(), 'source tree symlink')
            if path.is_file(): require(str(path) in plan['inputs'], 'source tree missing from freeze')
        database = Path(project['build_path']) / 'compile_commands.json'
        require(str(database) in plan['inputs'], 'compilation database not frozen')
        rows = load_json(database)
        require(type(rows) is list and 1 <= len(rows) <= 20000, 'compilation database rows')
        selected = Counter()
        for row in rows:
            require(type(row) is dict and type(row.get('directory')) is str and type(row.get('file')) is str,
                    'compilation database row')
            name = str((Path(row['directory']) / row['file']).resolve())
            if name in project['commands']: selected[name] += 1
        require(type(project['commands']) is dict and 1 <= len(project['commands']) <= 500
                and selected == project['commands'], 'selected compilation commands differ')
        require(all(str(Path(name)) == name and Path(name).is_relative_to(root)
                    and name in plan['inputs'] and not any(c in name for c in '\r\n\0')
                    and type(count) is int and count > 0 for name, count in project['commands'].items()), 'source selection')
        require(type(project['skipped']) is dict and set(project['skipped']) < set(project['commands'])
                and all(type(reason) is str and reason for reason in project['skipped'].values()), 'partial declaration')
    return plan


def hardware():
    values = {'platform': platform.platform(), 'machine': platform.machine(),
              'logical_cpu_count': os.cpu_count(), 'gnu_time_rss_semantics':
              'GNU time %M as reported; not simultaneous process-tree or cgroup peak memory.'}
    for name, path in {'cpu_info': '/proc/cpuinfo', 'host_meminfo': '/proc/meminfo',
                       'cgroup_cpu_max': '/sys/fs/cgroup/cpu.max',
                       'cgroup_memory_max': '/sys/fs/cgroup/memory.max',
                       'cgroup_pids_max': '/sys/fs/cgroup/pids.max'}.items():
        try: values[name] = Path(path).read_text()[:32768]
        except OSError: values[name] = None
    return values


def run(plan_path, binary, revision, output):
    require(sys.platform.startswith('linux'), 'Linux measurement profile required')
    require(re.fullmatch('[0-9a-f]{40}', revision), 'exact source revision required')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, timeout=15, text=True).strip()
    require(git('rev-parse', 'HEAD') == revision and not git('status', '--porcelain'), 'clean exact source required')
    plan_digest, binary_digest, timer_digest = sha(plan_path), sha(binary), sha(Path('/usr/bin/time'))
    plan = validate_plan(load_json(plan_path))
    require(output.is_absolute() and output.parent.resolve() == output.parent and not output.exists()
            and ROOT not in output.parents, 'fresh evidence output outside repository required')
    output.mkdir()
    result = {'schema': 'codeskeptic-product-measurement/v1', 'measurement_valid': False,
              'revision': revision, 'tree': git('rev-parse', 'HEAD^{tree}'), 'binary_sha256': binary_digest,
              'plan_path': str(plan_path), 'plan_sha256': plan_digest, 'gnu_time_sha256': timer_digest,
              'hardware': hardware(), 'projects': {}, 'failure': None,
              'limits': {'per_run_timeout_seconds': plan['timeout_seconds'], 'stdout_stderr_bytes_each': 2097152},
              'method': 'Three sequential fresh CLI processes; default rules, no analysis cache or whole-program mode. '
                        'Wall interval includes process launch/reporting/cleanup, excludes plan hashing. '
                        'No cold-filesystem-cache or market-accuracy claim. External container limits recorded separately.'}
    try:
        version = capture([str(binary), '--version'], output, 10)
        save(output / 'version-execution.json', version)
        valid_execution(version)
        require(version['returncode'] == 0 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-dev\+g' + revision[:12],
                                                        version['stdout'].strip()), 'binary/source version mismatch')
        result['version'] = version['stdout'].strip()
        for project in plan['projects']:
            runs = []
            for repetition in range(1, plan['repetitions'] + 1):
                verify_inputs(plan['inputs'])
                directory = output / (project['id'] + '-' + str(repetition))
                directory.mkdir()
                files, report_path, time_path = directory / 'files.txt', directory / 'report.json', directory / 'time.txt'
                with files.open('x') as stream: stream.write(''.join(name + '\n' for name in sorted(project['commands'])))
                command = [str(binary), '--files', str(files), '--build-path', project['build_path'],
                           '--no-analysis-cache', '--json', str(report_path)]
                if project['skipped']: command.append('--accept-partial-coverage')
                format_string = 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\npeak_rss_kib=%M\nexit_code=%x'
                observed = capture(['/usr/bin/time', '--quiet', '-f', format_string, '-o', str(time_path), '--', *command],
                                   directory, plan['timeout_seconds'])
                save(directory / 'execution.json', observed)
                valid_execution(observed)
                require(time_path.stat().st_size <= 4096, 'time record size')
                metrics = parse_time(time_path.read_text(), observed['returncode'])
                raw_report = load_json(report_path)
                semantic = summarize_report(raw_report, observed['returncode'], project)
                require(all(item['file'] in plan['inputs'] for item in raw_report['diagnostics']),
                        'diagnostic source missing from input freeze')
                verify_inputs(plan['inputs'])
                runs.append({'repetition': repetition, 'wall_seconds': observed['elapsed_seconds'],
                             'gnu_time': metrics, 'semantic': semantic, 'command': command,
                             'report_path': str(report_path), 'report_sha256': sha(report_path),
                             'execution_sha256': sha(directory / 'execution.json'), 'time_sha256': sha(time_path),
                             'files_sha256': sha(files)})
                if len(runs) > 1: require(runs[0]['semantic'] == semantic, 'repeat semantic/coverage drift')
                print('MEASURED project=' + project['id'] + ' repetition=' + str(repetition), flush=True)
            wall = [item['wall_seconds'] for item in runs]
            rss = [item['gnu_time']['peak_rss_kib'] for item in runs]
            result['projects'][project['id']] = {'upstream': project['upstream'], 'version': project['version'],
                'scope': project['scope'], 'runs': runs,
                'wall_seconds': {'min': min(wall), 'median': statistics.median(wall), 'max': max(wall)},
                'peak_rss_kib': {'min': min(rss), 'median': statistics.median(rss), 'max': max(rss)}}
        validate_plan(plan)
        require(sha(plan_path) == plan_digest and sha(binary) == binary_digest
                and sha(Path('/usr/bin/time')) == timer_digest and git('rev-parse', 'HEAD') == revision
                and not git('status', '--porcelain'), 'measurement identity changed')
        result['measurement_valid'] = True
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        save(output / 'results.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.plan, args.binary, args.revision, args.out)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('PRODUCT_MEASUREMENT_FAILED ' + type(error).__name__ + '; retain raw evidence, no success claim', file=sys.stderr)
        return 2
    print('PRODUCT_MEASUREMENT_VALID: timing/coverage/finding burden only; independent FP adjudication still required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
