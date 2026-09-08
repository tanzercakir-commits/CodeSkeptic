#!/usr/bin/env python3
"""Observe selected compiler/SDK/header bytes, without analyzer or quality runs.

This is a source-bound metadata collector, not an immutable runner provisioner,
native qualification, API signature adjudicator or remote attestation verifier.
It uses installed tools only. Native SDK/header content is hashed, not exported.
The fixed Clang -M probes preprocess declarations; they emit no object or executable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import stat
import subprocess
import sys


MAX_OUTPUT = 2 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_HEADERS = 4096
MAX_HEADER_BYTES = 256 * 1024 * 1024
TOOL_ROLES = ('cc', 'cxx', 'clang', 'clangxx')
SOURCE_FILES = {'collector_sha256': 'scripts/product_identity.py',
                'workflow_sha256': '.github/workflows/product-identity.yml',
                'profiles_sha256': 'scripts/product_profiles.json',
                'api_models_sha256': 'tests/product_corpus/native-api-models.json'}
ENV_KEYS = ('ImageOS', 'ImageVersion', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
            'GITHUB_REF', 'GITHUB_SHA', 'RUNNER_OS', 'RUNNER_ARCH',
            'INCLUDE', 'VCToolsInstallDir', 'VCToolsVersion', 'VSINSTALLDIR',
            'WindowsSdkDir', 'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion',
            'DEVELOPER_DIR', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET')
FORBIDDEN_ENV = ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
                 'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'CCC_OVERRIDE_OPTIONS', 'CL', '_CL_')
WINDOWS_OS_QUERY = ('[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); '
                    'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,'
                    'BuildNumber,OSArchitecture | ConvertTo-Json -Compress')
DARWIN_QUERIES = {'developer_directory': ['/usr/bin/xcode-select', '-p'],
                  'sdk_path_query': ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'],
                  'sdk_version': ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'],
                  'sdk_build': ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-build-version'],
                  'os_version': ['/usr/bin/sw_vers', '-productVersion'],
                  'os_build': ['/usr/bin/sw_vers', '-buildVersion']}


class IdentityError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise IdentityError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n'


def nonempty(value):
    return type(value) is str and bool(value.strip()) and '\x00' not in value


def digest(value, length=64):
    return (type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value)
            and value != '0' * length)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()), label + ' fields')


def checked_environment(environment):
    require(not any(environment.get(key) for key in FORBIDDEN_ENV),
            'ambient include/compiler override is not admitted')
    return dict(environment)


def observed_environment(environment):
    return {key: environment[key] for key in ENV_KEYS if key in environment}


def run(argv, source=None, allowed=(0,), cwd=None):
    """Trusted fixed metadata commands, with timeout and post-capture size limits.

    This is not a hard RSS/output-production or descendant-process budget.
    Product worker budgets are separate and are not exercised by this collector.
    """
    try:
        result = subprocess.run(argv, input=None if source is None else source.encode('utf-8'),
                                capture_output=True, timeout=30, cwd=cwd,
                                env=checked_environment(os.environ), check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IdentityError('metadata command unavailable or timed out: ' + str(argv[0])) from error
    require(len(result.stdout) <= MAX_OUTPUT and len(result.stderr) <= MAX_OUTPUT,
            'metadata command output too large')
    require(result.returncode in allowed, 'metadata command failed (exit ' + str(result.returncode)
            + '): ' + str(argv) + '; stderr=' + repr(result.stderr[:1024]))
    # Native Windows version tools can emit their active code page. Never silently
    # replace undecodable bytes in an identity. The lane sets VSLANG=1033, UTF-8.
    try:
        stdout, stderr = result.stdout.decode('utf-8'), result.stderr.decode('utf-8')
    except UnicodeError as error:
        raise IdentityError('metadata command is not UTF-8: ' + str(argv[0])) from error
    return {'argv': list(argv), 'exit_code': result.returncode, 'stdout': stdout, 'stderr': stderr}


def file_identity(path, maximum=MAX_FILE):
    path = Path(path)
    require(path.is_absolute(), 'identity file must be absolute')
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat()
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                'identity input is not a bounded regular file')
        hasher, count = hashlib.sha256(), 0
        with resolved.open('rb') as stream:
            while block := stream.read(1024 * 1024):
                count += len(block)
                require(count <= maximum, 'identity file grew beyond its bound')
                hasher.update(block)
        after = resolved.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and count == before.st_size and path.resolve(strict=True) == resolved,
                'identity input changed during capture')
    except (OSError, RuntimeError) as error:
        raise IdentityError('missing or unreadable identity file: ' + str(path)) from error
    return {'path': str(path), 'resolved_path': str(resolved), 'bytes': count,
            'sha256': hasher.hexdigest()}


def dependency_paths(raw, flavor):
    """Parse the one fixed -MT rule, including make escaping and Windows drives."""
    require(flavor in ('posix', 'windows') and type(raw) is str
            and len(raw.encode('utf-8')) <= MAX_OUTPUT and '\x00' not in raw,
            'dependency format/size')
    raw = raw.replace('\\\r\n', ' ').replace('\\\n', ' ').replace('\r\n', '\n').strip()
    require(raw.startswith('identity-probe:') and '\n' not in raw and '\r' not in raw,
            'expected exactly one fixed dependency rule')
    text, result, token, index = raw[len('identity-probe:'):], [], [], 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            if token:
                result.append(''.join(token))
                token = []
        elif char == '\\':
            index += 1
            require(index < len(text) and text[index] in (' ', '\t', '#', '\\'),
                    'unsupported dependency escape')
            token.append(text[index])
        elif char == '$':
            index += 1
            require(index < len(text) and text[index] == '$', 'dependency variable is not a filename')
            token.append('$')
        elif char == '#':
            raise IdentityError('unescaped dependency comment')
        else:
            token.append(char)
        index += 1
    if token:
        result.append(''.join(token))
    path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
    require(0 < len(result) <= MAX_HEADERS and all(path_type(path).is_absolute() for path in result),
            'empty, excessive or relative header dependency')
    require(len({str(path_type(path)) for path in result}) == len(result), 'duplicate dependency path')
    return result


def probe_command(compiler, language, system, sdk_root):
    require(language in ('c', 'c++') and system in ('Linux', 'Windows', 'Darwin'),
            'unsupported probe language/platform')
    headers = (['winsock2.h', 'io.h'] if system == 'Windows'
               else ['sys/types.h', 'sys/socket.h', 'unistd.h', 'fcntl.h'])
    headers += ['stdio.h', 'stdlib.h', 'string.h', 'stdint.h', 'stddef.h', 'errno.h']
    if language == 'c++':
        headers += ['string', 'vector', 'iostream', 'fstream', 'filesystem']
    source = ''.join('#include <' + header + '>\n' for header in headers)
    argv = [str(compiler), '--no-default-config', '-fno-modules', '-M', '-MT', 'identity-probe',
            '-x', language, '-std=' + ('c++17' if language == 'c++' else 'c17')]
    if system == 'Darwin':
        require(nonempty(sdk_root), 'selected macOS SDK is required')
        argv += ['-isysroot', sdk_root]
    return argv + ['-'], source


def source_identity(root, expected):
    root = Path(root).resolve(strict=True)
    require(digest(expected, 40), 'expected source SHA')
    head = run(['git', 'rev-parse', 'HEAD'], cwd=root)['stdout'].strip()
    require(head == expected and not run(['git', 'status', '--porcelain'], cwd=root)['stdout'],
            'capture requires the exact clean source checkout')
    value = {'head': head, 'tree': run(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root)['stdout'].strip()}
    for field, relative in SOURCE_FILES.items():
        path = root / relative
        require(not path.is_symlink() and path.resolve() == path, 'source helper alias is not admitted')
        value[field] = file_identity(path)['sha256']
    require(Path(__file__).resolve() == root / SOURCE_FILES['collector_sha256'],
            'collector must run from the selected checkout')
    return value


def native_metadata(system):
    if system == 'Linux':
        release = platform.freedesktop_os_release()
        package_tool = shutil.which('dpkg-query') or shutil.which('rpm')
        require(package_tool, 'native package metadata tool missing')
        if Path(package_tool).name == 'dpkg-query':
            argv = [package_tool, '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n',
                    'libc6', 'libc6-dev', 'gcc-*', 'g++-*', 'libstdc++*-dev']
        else:
            argv = [package_tool, '-q', 'glibc', 'glibc-headers', 'glibc-devel',
                    'gcc', 'gcc-c++', 'libstdc++', 'libstdc++-devel']
        return {'os_release': release, 'os_release_file': file_identity(Path('/etc/os-release')),
                'package_query': run(argv, allowed=(0, 1))}
    if system == 'Darwin':
        result = {key: run(argv) for key, argv in DARWIN_QUERIES.items()}
        result['sdk_root'] = result['sdk_path_query']['stdout'].strip()
        result['clt_package'] = run(['/usr/sbin/pkgutil', '--pkg-info',
                                     'com.apple.pkg.CLTools_Executables'], allowed=(0, 1))
        developer = result['developer_directory']['stdout'].strip()
        result['xcode_version'] = (run(['/usr/bin/xcodebuild', '-version'])
                                   if '.app/Contents/Developer' in developer else None)
        settings = Path(result['sdk_root']) / 'SDKSettings.json'
        result['sdk_settings'] = file_identity(settings if settings.is_file()
                                               else settings.with_suffix('.plist'))
        return result
    require(system == 'Windows', 'native metadata platform unsupported')
    required = ('VSINSTALLDIR', 'VCToolsInstallDir', 'VCToolsVersion', 'WindowsSdkDir',
                'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion', 'INCLUDE')
    require(all(nonempty(os.environ.get(key)) for key in required), 'selected MSVC/SDK environment missing')
    locator = Path(os.environ.get('ProgramFiles(x86)', '')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    query = run([str(locator), '-all', '-products', '*', '-format', 'json', '-utf8'])
    installations = json.loads(query['stdout'])
    selected = Path(os.environ['VSINSTALLDIR']).resolve(strict=True)
    matches = [item for item in installations
               if Path(item['installationPath']).resolve(strict=True) == selected]
    require(len(matches) == 1, 'MSVC environment does not identify one installed Visual Studio')
    installation = {key: matches[0][key] for key in ('instanceId', 'installationPath',
                                                   'installationVersion', 'productId')}
    roots = {key: str(Path(os.environ[key]).resolve(strict=True))
             for key in ('VCToolsInstallDir', 'WindowsSdkDir', 'UniversalCRTSdkDir')}
    require(all(Path(path).is_dir() for path in roots.values()), 'SDK/toolset root is not a directory')
    os_query = run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', WINDOWS_OS_QUERY])
    return {'installation': installation, 'locator': file_identity(locator),
            'selected_roots': roots, 'versions': {key: os.environ[key].rstrip('\\/')
                                                for key in ('VCToolsVersion', 'WindowsSDKVersion', 'UCRTVersion')},
            'os_query': os_query, 'os': json.loads(os_query['stdout'])}


def capture_tool(path, role, system):
    item = file_identity(Path(path))
    require('ccache' not in item['resolved_path'].lower(), 'select the compiler, not a cache wrapper')
    msvc = system == 'Windows' and role in ('cc', 'cxx')
    version = run([str(path), '/Bv'] if msvc else [str(path), '--version'], allowed=(0, 2) if msvc else (0,))
    if msvc:
        require('Compiler Version' in version['stdout'] + version['stderr']
                and 'for x64' in version['stdout'] + version['stderr'], 'selected compiler is not x64 MSVC')
        require(Path(item['resolved_path']).is_relative_to(Path(os.environ['VCToolsInstallDir']).resolve()),
                'cl.exe does not belong to the selected VC toolset')
        target, resource = None, None
    else:
        target = run([str(path), '-dumpmachine'])['stdout'].strip()
        resource = (run([str(path), '--no-default-config', '-print-resource-dir'])['stdout'].strip()
                    if role in ('clang', 'clangxx') else None)
        require(nonempty(target) and (resource is None or Path(resource).is_dir()), 'compiler target/resource missing')
    return {'file': item, 'version': version, 'target': target, 'resource_dir': resource}


def validate_file(item, flavor):
    fields(item, 'path resolved_path bytes sha256', 'file identity')
    path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
    require(all(nonempty(item[key]) and path_type(item[key]).is_absolute() for key in ('path', 'resolved_path'))
            and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_FILE and digest(item['sha256']),
            'invalid file identity')


def validate_command(item, allowed=(0,)):
    fields(item, 'argv exit_code stdout stderr', 'command')
    require(type(item['argv']) is list and item['argv'] and all(nonempty(arg) for arg in item['argv'])
            and type(item['exit_code']) is int and item['exit_code'] in allowed
            and all(type(item[key]) is str and '\x00' not in item[key]
                    and len(item[key].encode('utf-8')) <= MAX_OUTPUT for key in ('stdout', 'stderr')),
            'invalid command evidence')


def validate_document(value):
    fields(value, 'schema source platform tools probes metadata_only native_qualified immutable_image '
           'product_qualified external_dependencies', 'observed identity')
    require(value['schema'] == 'codeskeptic-observed-product-identity/v1'
            and value['metadata_only'] is True and value['native_qualified'] is False
            and value['immutable_image'] is False and value['product_qualified'] is False,
            'observation must not claim native/product qualification or immutable replay')
    source = value['source']
    fields(source, 'head tree collector_sha256 workflow_sha256 profiles_sha256 api_models_sha256', 'source')
    require(all(digest(source[key], 40 if key in ('head', 'tree') else 64) for key in source), 'source identity digest')
    host = value['platform']
    fields(host, 'system machine release version python environment metadata', 'platform')
    require(host['system'] in ('Linux', 'Windows', 'Darwin')
            and all(nonempty(host[key]) for key in ('machine', 'release', 'version', 'python'))
            and type(host['environment']) is dict and set(host['environment']) <= set(ENV_KEYS)
            and all(type(item) is str for item in host['environment'].values()), 'platform/environment identity')
    if 'GITHUB_SHA' in host['environment']:
        require(host['environment']['GITHUB_SHA'] == source['head'], 'event/source SHA mismatch')
    if 'RUNNER_OS' in host['environment']:
        require(host['environment']['RUNNER_OS'] == {'Linux': 'Linux', 'Windows': 'Windows', 'Darwin': 'macOS'}[host['system']],
                'runner/platform mismatch')
    flavor = 'windows' if host['system'] == 'Windows' else 'posix'
    metadata = host['metadata']
    require(type(metadata) is dict and metadata, 'native metadata missing')
    if host['system'] == 'Linux':
        fields(metadata, 'os_release os_release_file package_query', 'Linux metadata')
        require(type(metadata['os_release']) is dict and nonempty(metadata['os_release'].get('ID')),
                'Linux distribution missing')
        validate_file(metadata['os_release_file'], flavor)
        validate_command(metadata['package_query'], allowed=(0, 1))
    elif host['system'] == 'Darwin':
        fields(metadata, 'developer_directory sdk_path_query sdk_version sdk_build os_version os_build '
               'sdk_root clt_package xcode_version sdk_settings', 'Darwin metadata')
        for key, argv in DARWIN_QUERIES.items():
            validate_command(metadata[key])
            require(metadata[key]['argv'] == argv and nonempty(metadata[key]['stdout']),
                    'missing or relabelled Darwin metadata observation')
        require(type(metadata['sdk_root']) is str and PurePosixPath(metadata['sdk_root']).is_absolute()
                and metadata['sdk_root'] == metadata['sdk_path_query']['stdout'].strip(), 'SDK path mismatch')
        for key in ('sdk_version', 'os_version'):
            require(re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', metadata[key]['stdout'].strip()),
                    'invalid Darwin version observation')
        validate_command(metadata['clt_package'], allowed=(0, 1))
        require(metadata['clt_package']['argv'] == ['/usr/sbin/pkgutil', '--pkg-info',
                                                    'com.apple.pkg.CLTools_Executables'], 'CLT package query identity')
        if metadata['xcode_version'] is not None:
            validate_command(metadata['xcode_version'])
            require(metadata['xcode_version']['argv'] == ['/usr/bin/xcodebuild', '-version']
                    and nonempty(metadata['xcode_version']['stdout']), 'Xcode version query identity')
        validate_file(metadata['sdk_settings'], flavor)
        require(PurePosixPath(metadata['sdk_settings']['path']) in
                {PurePosixPath(metadata['sdk_root']) / name for name in ('SDKSettings.json', 'SDKSettings.plist')},
                'SDK settings file is not in the selected SDK')
    else:
        fields(metadata, 'installation locator selected_roots versions os_query os', 'Windows metadata')
        fields(metadata['installation'], 'instanceId installationPath installationVersion productId', 'VS installation')
        require(all(nonempty(item) for item in metadata['installation'].values()), 'VS installation identity')
        fields(metadata['selected_roots'], 'VCToolsInstallDir WindowsSdkDir UniversalCRTSdkDir', 'SDK roots')
        fields(metadata['versions'], 'VCToolsVersion WindowsSDKVersion UCRTVersion', 'SDK versions')
        require(all(nonempty(item) and PureWindowsPath(item).is_absolute()
                    for item in metadata['selected_roots'].values())
                and all(nonempty(item) for item in metadata['versions'].values()), 'native Windows SDK identity')
        validate_file(metadata['locator'], flavor)
        validate_command(metadata['os_query'])
        require(metadata['os_query']['argv'] == ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', WINDOWS_OS_QUERY]
                and json.loads(metadata['os_query']['stdout']) == metadata['os'], 'Windows OS query mismatch')
        fields(metadata['os'], 'Caption Version BuildNumber OSArchitecture', 'Windows OS identity')
        require(all(nonempty(item) for item in metadata['os'].values()), 'Windows OS identity missing')
        environment = host['environment']
        require(nonempty(environment.get('INCLUDE')) and nonempty(environment.get('VSINSTALLDIR'))
                and PureWindowsPath(environment['VSINSTALLDIR']) == PureWindowsPath(metadata['installation']['installationPath']),
                'selected Visual Studio environment mismatch')
        for key, path in metadata['selected_roots'].items():
            require(nonempty(environment.get(key)) and PureWindowsPath(environment[key]) == PureWindowsPath(path),
                    'selected SDK root environment mismatch')
        for key, version in metadata['versions'].items():
            require(nonempty(environment.get(key)) and environment[key].rstrip('\\/') == version
                    and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', version), 'selected SDK version environment mismatch')
    fields(value['tools'], ' '.join(TOOL_ROLES), 'selected compiler roles')
    for role, tool in value['tools'].items():
        fields(tool, 'file version target resource_dir', 'compiler')
        validate_file(tool['file'], flavor)
        msvc = host['system'] == 'Windows' and role in ('cc', 'cxx')
        validate_command(tool['version'], allowed=(0, 2) if msvc else (0,))
        require(nonempty(tool['version']['stdout']) or nonempty(tool['version']['stderr']), 'empty compiler version')
        require(tool['version']['argv'] == [tool['file']['path'], '/Bv' if msvc else '--version'],
                'version command does not belong to selected tool')
        require(tool['target'] is None if msvc else nonempty(tool['target']), 'compiler target')
        path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
        require((nonempty(tool['resource_dir']) and path_type(tool['resource_dir']).is_absolute())
                if role in ('clang', 'clangxx') else tool['resource_dir'] is None,
                'compiler resource directory')
    fields(value['probes'], 'c c++', 'header probes')
    for language, probe in value['probes'].items():
        fields(probe, 'language source_sha256 command headers dependency_count', 'probe')
        tool = value['tools']['clang' if language == 'c' else 'clangxx']['file']['path']
        argv, source_text = probe_command(tool, language, host['system'], metadata.get('sdk_root'))
        validate_command(probe['command'])
        require(probe['language'] == language and probe['source_sha256'] == hashlib.sha256(source_text.encode()).hexdigest()
                and probe['command']['argv'] == argv, 'fixed probe command/source identity')
        expected = dependency_paths(probe['command']['stdout'], flavor)
        require(type(probe['headers']) is list and type(probe['dependency_count']) is int
                and probe['dependency_count'] == len(expected) == len(probe['headers']), 'header closure count')
        path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
        for record, path in zip(probe['headers'], expected):
            validate_file(record, flavor)
            require(str(path_type(record['path'])) == str(path_type(path)), 'header dependency order/path mismatch')
        require(sum(record['bytes'] for record in probe['headers']) <= MAX_HEADER_BYTES, 'header byte bound')
    require(value['external_dependencies'] == {'sqlite': 'NOT_SELECTED_OR_CAPTURED'},
            'external dependency selection is not established by this collector')
    return {'metadata_only': True, 'local_native_bytes_verified': False, 'native_qualified': False,
            'immutable_image': False, 'product_qualified': False,
            'headers': {language: len(probe['headers']) for language, probe in value['probes'].items()}}


def capture(args):
    initial_source = source_identity(args.root, args.source_sha)
    system = platform.system()
    metadata = native_metadata(system)
    tools = {role: capture_tool(getattr(args, role), role, system) for role in TOOL_ROLES}
    probes = {}
    for language, role in (('c', 'clang'), ('c++', 'clangxx')):
        argv, source = probe_command(tools[role]['file']['path'], language, system, metadata.get('sdk_root'))
        command = run(argv, source=source)
        paths = dependency_paths(command['stdout'], 'windows' if system == 'Windows' else 'posix')
        headers, total = [], 0
        for path in paths:
            item = file_identity(Path(path), maximum=MAX_HEADER_BYTES - total)
            total += item['bytes']
            headers.append(item)
        probes[language] = {'language': language, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                            'command': command, 'headers': headers, 'dependency_count': len(headers)}
    value = {'schema': 'codeskeptic-observed-product-identity/v1', 'source': initial_source,
             'platform': {'system': system, 'machine': platform.machine(), 'release': platform.release(),
                          'version': platform.version(), 'python': platform.python_version(),
                          'environment': observed_environment(os.environ), 'metadata': metadata},
             'tools': tools, 'probes': probes, 'metadata_only': True, 'native_qualified': False,
             'immutable_image': False, 'product_qualified': False,
             'external_dependencies': {'sqlite': 'NOT_SELECTED_OR_CAPTURED'}}
    validate_document(value)
    # Recheck every selected byte identity after all probes, not only its own hash.
    for record in ([tool['file'] for tool in tools.values()]
                   + [header for probe in probes.values() for header in probe['headers']]):
        require(file_identity(Path(record['path'])) == record, 'native input changed across capture')
    require(native_metadata(system) == metadata, 'native SDK/package observations changed across capture')
    require(source_identity(args.root, args.source_sha) == initial_source, 'source changed across capture')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='structural metadata check, not native byte verification')
    check.add_argument('input', type=Path)
    collect = commands.add_parser('capture', help='installed-tool metadata only; writes one new external JSON')
    collect.add_argument('--root', type=Path, required=True)
    collect.add_argument('--source-sha', required=True)
    for role in TOOL_ROLES:
        collect.add_argument('--' + role, type=Path, required=True)
    collect.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'check':
            require(not args.input.is_symlink() and args.input.resolve() == args.input
                    and args.input.is_file() and args.input.stat().st_size <= 16 * MAX_OUTPUT,
                    'metadata input must be a bounded absolute regular file')
            result = validate_document(json.loads(args.input.read_text(encoding='utf-8')))
        else:
            root = args.root.resolve(strict=True)
            require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent
                    and not args.output.exists() and not args.output.is_symlink()
                    and not args.output.is_relative_to(root), 'output must be new and outside the checkout')
            value = capture(args)
            with args.output.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(canonical(value))
            result = {**validate_document(value), 'output_sha256': file_identity(args.output)['sha256']}
        print(canonical(result), end='')
        return 0
    except (IdentityError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print('IDENTITY_INVALID ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
