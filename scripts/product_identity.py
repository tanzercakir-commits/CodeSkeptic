#!/usr/bin/env python3
"""Observe selected compiler/SDK/header bytes, without analyzer or quality runs.

This is a source-bound metadata collector, not an immutable runner provisioner,
native qualification, API signature adjudicator or remote attestation verifier.
It uses installed tools only. Native SDK/header content is hashed, not exported.
The fixed Clang -M probes preprocess declarations; they emit no object or executable.
"""
import argparse
from contextlib import contextmanager
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
import tempfile
import time


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


def linux_package_command(tool):
    require(type(tool) is str and PurePosixPath(tool).is_absolute(), 'package tool path')
    if PurePosixPath(tool).name == 'dpkg-query':
        return [tool, '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n',
                'libc6', 'libc6-dev', 'gcc-*', 'g++-*', 'libstdc++*-dev']
    require(PurePosixPath(tool).name == 'rpm', 'unrecognized native package query tool')
    return [tool, '-q', 'glibc', 'glibc-headers', 'glibc-devel',
            'gcc', 'gcc-c++', 'libstdc++', 'libstdc++-devel']


def requires_xcode_version(developer):
    require(nonempty(developer) and PurePosixPath(developer).is_absolute(), 'active developer directory')
    # Only the explicit standalone CLT location omits Xcode. Other selections,
    # including a nonstandard/aliased Xcode path, must query instead of guessing.
    return PurePosixPath(developer) != PurePosixPath('/Library/Developer/CommandLineTools')


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
    """Read the fixed Clang Make rule, not arbitrary Make/shell escaping.

    LLVM 20.1.8 DependencyFile.cpp PrintFilename leaves ordinary backslashes
    literal, emits 2n+1 before a space and n+1 before #. Tabs and ambiguous
    trailing-backslash names are outside this regular-header subset.
    """
    require(flavor in ('posix', 'windows') and type(raw) is str
            and len(raw.encode('utf-8')) <= MAX_OUTPUT and '\x00' not in raw and '\t' not in raw,
            'dependency format/size')
    # Only the writer's separated, indented continuation form is admitted.
    raw = re.sub(r' \\\r?\n +(?=\S)', ' ', raw).replace('\r\n', '\n').strip(' \r\n')
    require(raw.startswith('identity-probe:') and '\n' not in raw and '\r' not in raw,
            'expected exactly one fixed dependency rule')
    text, result, token, index = raw[len('identity-probe:'):], [], [], 0
    while index < len(text):
        char = text[index]
        if char == ' ':
            if token:
                result.append(''.join(token))
                token = []
        elif char == '\\':
            start = index
            while index < len(text) and text[index] == '\\':
                index += 1
            count = index - start
            require(index < len(text), 'trailing dependency backslash is unsupported')
            if text[index] == ' ':
                require(count % 2 == 1 and index + 1 < len(text)
                        and not re.match(r'(?:[A-Za-z]:[\\/]|/|\\\\)', text[index + 1:]),
                        'ambiguous trailing-backslash dependency name')
                token.extend(('\\' * ((count - 1) // 2), ' '))
                index += 1
            elif text[index] == '#':
                token.extend(('\\' * (count - 1), '#'))
                index += 1
            else:
                token.append('\\' * count)
            continue
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
    require(not any(path.endswith(('\\', '/')) for path in result), 'trailing header separator')
    require(len({path_type(path) for path in result}) == len(result), 'duplicate dependency path')
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
        # A Git-clean worktree may still contain CRLF or smudge-filtered bytes.
        # Bind the observed helper bytes to the actual committed blob as well.
        committed = run(['git', 'cat-file', 'blob', head + ':' + relative], cwd=root)['stdout']
        require(value[field] == hashlib.sha256(committed.encode('utf-8')).hexdigest(),
                'source helper bytes differ from the committed blob: ' + relative)
    require(Path(__file__).resolve() == root / SOURCE_FILES['collector_sha256'],
            'collector must run from the selected checkout')
    return value


def native_metadata(system):
    if system == 'Linux':
        release = platform.freedesktop_os_release()
        package_tool = shutil.which('dpkg-query') or shutil.which('rpm')
        require(package_tool, 'native package metadata tool missing')
        return {'os_release': release, 'os_release_file': file_identity(Path('/etc/os-release')),
                'package_query': run(linux_package_command(package_tool), allowed=(0, 1))}
    if system == 'Darwin':
        result = {key: run(argv) for key, argv in DARWIN_QUERIES.items()}
        result['sdk_root'] = result['sdk_path_query']['stdout'].strip()
        result['clt_package'] = run(['/usr/sbin/pkgutil', '--pkg-info',
                                     'com.apple.pkg.CLTools_Executables'], allowed=(0, 1))
        developer = result['developer_directory']['stdout'].strip()
        result['xcode_version'] = (run(['/usr/bin/xcodebuild', '-version'])
                                   if requires_xcode_version(developer) else None)
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
        require(metadata['package_query']['argv'] == linux_package_command(metadata['package_query']['argv'][0]),
                'Linux package query identity')
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
        require((metadata['xcode_version'] is not None) == requires_xcode_version(
                metadata['developer_directory']['stdout'].strip()), 'Xcode query missing or inconsistent with developer selection')
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
        if msvc:
            require(PureWindowsPath(tool['file']['resolved_path']).is_relative_to(
                    PureWindowsPath(metadata['selected_roots']['VCToolsInstallDir']))
                    and 'Compiler Version' in tool['version']['stdout'] + tool['version']['stderr']
                    and 'for x64' in tool['version']['stdout'] + tool['version']['stderr'],
                    'MSVC identity does not belong to selected x64 VC toolset')
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
    # Repeated compiler/header inputs are identities, not independent records that
    # can disagree between C and C++ or between a logical name and its SDK alias.
    all_files = ([tool['file'] for tool in value['tools'].values()]
                 + [record for probe in value['probes'].values() for record in probe['headers']])
    all_files.append(metadata[{'Linux': 'os_release_file', 'Darwin': 'sdk_settings', 'Windows': 'locator'}[host['system']]])
    bindings = {}
    path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
    for record in all_files:
        path, resolved = path_type(record['path']), path_type(record['resolved_path'])
        require('..' not in resolved.parts, 'resolved identity path is not canonical')
        identity = (resolved, record['bytes'], record['sha256'])
        for name in (path, resolved):
            require(name not in bindings or bindings[name] == identity,
                    'logical/resolved input names carry inconsistent identities')
            bindings[name] = identity
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


CASE_SHA = '5c5563b8ed6e5715cb1913e223276146bc4c8799c11ee4dace55cf6e8a5e4b0a'
CASE_CLT = '/Library/Developer/CommandLineTools'
CASE_TARGETS = {'Linux': 'x86_64-unknown-linux-gnu', 'Windows': 'x86_64-pc-windows-msvc',
                'Darwin': 'arm64-apple-macos14.0'}
CASE_ENV_KEYS = (*ENV_KEYS, 'PATH', 'SystemRoot', 'SystemDrive', 'WINDIR', 'COMSPEC',
                 'TEMP', 'TMP', 'TMPDIR', 'ProgramFiles', 'ProgramFiles(x86)', 'LANG', 'LC_ALL', 'VSLANG')
CASE_WINDOWS_ENV_KEYS = ('USERPROFILE', 'APPDATA', 'LOCALAPPDATA')
CASE_SOURCE_FILES = ('scripts/product_profiles.py', 'scripts/product_quality.py',
                     'tests/product_corpus/candidates/gcc-mixed-storage-binding.json',
                     'tests/product_corpus/candidates/gcc-mixed-storage-selection.json')


def case_environment(environment, system):
    """Only this opt-in capture uses a minimal environment, never ambient secrets."""
    require(system in CASE_TARGETS, 'case platform')
    keys = CASE_ENV_KEYS + (CASE_WINDOWS_ENV_KEYS if system == 'Windows' else ())
    if system == 'Windows':
        folded = {}
        for key, value in environment.items():
            require(key.upper() not in folded or folded[key.upper()] == value, 'conflicting environment keys')
            folded[key.upper()] = value
        environment = {key: folded[key.upper()] for key in (*keys, *FORBIDDEN_ENV,
                       'LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH') if key.upper() in folded}
        # Windows PowerShell uses the native profile/cache paths even with
        # -NoProfile. Preserve these paths, not the caller's full environment.
        for key in CASE_WINDOWS_ENV_KEYS:
            if key in environment:
                value = environment[key]
                require(nonempty(value) and PureWindowsPath(value).is_absolute()
                        and '..' not in PureWindowsPath(value).parts, 'case Windows runtime profile path')
    checked_environment(environment)
    require(not any(environment.get(key) for key in
                    ('LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH')),
            'case loader/library override')
    result = {key: environment[key] for key in keys if key in environment}
    result.update(LANG='C', LC_ALL='C', VSLANG='1033')
    return result


@contextmanager
def selected_case_environment(environment):
    # This CLI is single-threaded. Restore the caller even when a probe fails.
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(environment)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def case_abi_sources():
    source = ('#include <limits.h>\n#include <stdlib.h>\n'
              '_Static_assert(CHAR_BIT == 8, "selected byte width");\n'
              '_Static_assert(sizeof(int) == 4, "selected int width");\n'
              '_Static_assert(sizeof(size_t) == 8, "selected size width");\n'
              '_Static_assert(sizeof(void *) == 8, "selected pointer width");\n'
              '_Static_assert(_Generic(&malloc, void *(*)(size_t): 1, default: 0), "selected malloc declaration");\n')
    return {'abi': source, 'bad-width': source.replace('sizeof(int) == 4', 'sizeof(int) == 8'),
            'bad-signature': source.replace('void *(*)(size_t)', 'int *(*)(size_t)')}


def case_command(native, source, dependencies=False):
    system = native['platform']['system']
    tool = native['tools']['clang']
    argv = [tool['file']['path'], '--no-default-config', '-fno-modules',
            '-resource-dir', tool['resource_dir'], '-x', 'c', '-std=c17', '--target=' + CASE_TARGETS[system]]
    if system == 'Darwin':
        argv += ['-isysroot', native['platform']['metadata']['sdk_root']]
    return argv + (['-M', '-MT', 'identity-probe'] if dependencies else ['-fsyntax-only']) + [source]


def resolve_case_resources(native):
    """Use physical resource directories for the new case, not v1 reinterpretation."""
    for role in ('clang', 'clangxx'):
        resource = Path(native['tools'][role]['resource_dir']).resolve(strict=True)
        require(resource.is_dir(), 'case resource is not a directory')
        native['tools'][role]['resource_dir'] = str(resource)


def validate_case_selection(native, environment):
    """Bind the effective case selection; legacy v1 remains observational."""
    validate_document(native)
    require(all(probe['command']['stderr'] == '' for probe in native['probes'].values()),
            'case nested header diagnostics may contain source text')
    host, tools = native['platform'], native['tools']
    system, metadata = host['system'], host['metadata']
    require(type(environment) is dict and all(type(value) is str for value in environment.values())
            and case_environment(environment, system) == environment
            and observed_environment(environment) == host['environment'], 'case child environment mismatch')
    require(host['machine'].lower() in ({'arm64', 'aarch64'} if system == 'Darwin' else {'x86_64', 'amd64'}),
            'case native architecture')
    path_type = PureWindowsPath if system == 'Windows' else PurePosixPath
    tool = tools['clang']
    require(('clang version ' in tool['version']['stdout']) and
            (tool['target'].startswith(('arm64-apple-', 'aarch64-apple-')) if system == 'Darwin'
             else re.fullmatch(r'x86_64-[a-z0-9_-]*linux-gnu', tool['target']) if system == 'Linux'
             else tool['target'] == CASE_TARGETS[system]), 'case native compiler target')
    resource = path_type(tool['resource_dir'])
    require('..' not in resource.parts, 'case resource path')
    if system == 'Darwin':
        developer, sdk = PurePosixPath(CASE_CLT), PurePosixPath(metadata['sdk_root'])
        require(environment.get('DEVELOPER_DIR') == CASE_CLT
                and environment.get('SDKROOT') == str(sdk)
                and environment.get('MACOSX_DEPLOYMENT_TARGET') == '14.0'
                and metadata['developer_directory']['stdout'].strip() == CASE_CLT
                and metadata['xcode_version'] is None and metadata['clt_package']['exit_code'] == 0
                and nonempty(metadata['clt_package']['stdout'])
                and sdk.is_relative_to(developer / 'SDKs') and resource.is_relative_to(developer / 'usr/lib/clang')
                and PurePosixPath(metadata['sdk_settings']['resolved_path']).parent.is_relative_to(developer / 'SDKs')
                and PurePosixPath(metadata['sdk_settings']['resolved_path']).name in ('SDKSettings.json', 'SDKSettings.plist'),
                'case requires explicit standalone CLT SDK selection')
        for role, selected in tools.items():
            expected = developer / 'usr/bin' / ('clang++' if role in ('cxx', 'clangxx') else 'clang')
            require(PurePosixPath(selected['file']['path']) == expected
                    and PurePosixPath(selected['file']['resolved_path']).is_relative_to(developer / 'usr/bin'),
                    'case compiler is not the selected standalone CLT')
    else:
        require(not any(environment.get(key) for key in ('SDKROOT', 'DEVELOPER_DIR', 'MACOSX_DEPLOYMENT_TARGET')),
                'foreign case SDK environment')
    if system == 'Windows':
        roots, versions = metadata['selected_roots'], metadata['versions']
        vc = PureWindowsPath(roots['VCToolsInstallDir'])
        sdk = PureWindowsPath(roots['WindowsSdkDir']) / 'Include' / versions['WindowsSDKVersion']
        ucrt = PureWindowsPath(roots['UniversalCRTSdkDir']) / 'Include' / versions['UCRTVersion']
        includes = [PureWindowsPath(path) for path in environment['INCLUDE'].split(';') if path]
        require(includes and len(includes) == len(set(includes))
                and vc.name == versions['VCToolsVersion']
                and vc.is_relative_to(PureWindowsPath(metadata['installation']['installationPath']))
                and vc / 'include' in includes and ucrt / 'ucrt' in includes
                and all(path.is_absolute() and '..' not in path.parts
                        and any(path.is_relative_to(root) for root in (vc / 'include', vc / 'atlmfc/include', sdk, ucrt))
                        for path in includes), 'case include roots/toolset selection mismatch')


def case_record(command, marker=None):
    """Do not export compiler diagnostics, which can quote source or SDK bytes."""
    require(command['exit_code'] == (1 if marker else 0) and command['stdout'] == ''
            and (('static assertion failed' in command['stderr'] and marker in command['stderr'])
                 if marker else command['stderr'] == ''), 'case syntax/negative probe failed')
    if marker:
        diagnostics = re.findall(r'(?m)^(?:.*?: )?(fatal error|error|warning): (.*)$', command['stderr'])
        require(len(diagnostics) == 1 and diagnostics[0][0] == 'error'
                and diagnostics[0][1].startswith('static assertion failed') and marker in diagnostics[0][1]
                and command['stderr'].rstrip().endswith('1 error generated.'),
                'case negative contains unrelated or unrecognized diagnostics')
    return {'argv': command['argv'], 'exit_code': command['exit_code'], 'expected_negative_marker': marker,
            **{key: {'bytes': len(command[key].encode()), 'sha256': hashlib.sha256(command[key].encode()).hexdigest()}
               for key in ('stdout', 'stderr')}}


def validate_case_document(value):
    fields(value, 'schema native_identity environment source_files binding input probes '
           'syntax_checked native_qualified license_qualified independent_quota_examples task_ready product_qualified', 'case')
    require(value['schema'] == 'codeskeptic-native-case-observation/v1' and value['syntax_checked'] is True
            and all(value[key] is False for key in ('native_qualified', 'license_qualified', 'task_ready', 'product_qualified'))
            and type(value['independent_quota_examples']) is int and value['independent_quota_examples'] == 0,
            'case observation cannot qualify the product or corpus')
    native = value['native_identity']
    validate_case_selection(native, value['environment'])
    system = native['platform']['system']
    flavor = 'windows' if system == 'Windows' else 'posix'
    path_type = PureWindowsPath if system == 'Windows' else PurePosixPath
    fields(value['source_files'], ' '.join(CASE_SOURCE_FILES), 'case source files')
    require(all(digest(sha) for sha in value['source_files'].values()), 'case helper digests')
    binding = value['binding']
    fields(binding, 'schema id binding_sha256 adjudication_sha256 source_bytes_verified verified_inputs verified_bytes '
           'independent_quota_examples task_ready product_qualified native_commands_bound license_qualified state', 'case binding')
    require(binding['schema'] == 'codeskeptic-product-external-input-check/v1'
            and binding['id'] == 'gcc-mixed-storage-local-loss'
            and binding['state'] == 'SOURCE_BINDING_ONLY_NOT_FROZEN' and binding['source_bytes_verified'] is True
            and type(binding['verified_inputs']) is int and binding['verified_inputs'] == 5
            and type(binding['verified_bytes']) is int and binding['verified_bytes'] == 43256
            and type(binding['independent_quota_examples']) is int and binding['independent_quota_examples'] == 0
            and all(binding[key] is False for key in ('task_ready', 'product_qualified', 'native_commands_bound', 'license_qualified'))
            and binding['binding_sha256'] == value['source_files'][CASE_SOURCE_FILES[2]]
            and binding['adjudication_sha256'] == value['source_files'][CASE_SOURCE_FILES[3]], 'case source binding')
    validate_file(value['input'], flavor)
    require(value['input']['sha256'] == CASE_SHA and value['input']['bytes'] == 636
            and path_type(value['input']['path']).name == 'case.c', 'reviewed case input')
    fields(value['probes'], 'candidate abi bad-width bad-signature', 'case probes')
    identities = [value['input'], *[tool['file'] for tool in native['tools'].values()],
                  *[header for probe in native['probes'].values() for header in probe['headers']]]
    for name, probe in value['probes'].items():
        fields(probe, 'source_sha256 command dependencies headers', 'case probe')
        command = probe['command']
        fields(command, 'argv exit_code expected_negative_marker stdout stderr', 'case command')
        require(type(command['argv']) is list and command['argv']
                and path_type(command['argv'][-1]).is_absolute(), 'case source path')
        source_path = command['argv'][-1]
        expected_sha = CASE_SHA if name == 'candidate' else hashlib.sha256(case_abi_sources()[name].encode()).hexdigest()
        marker = {'bad-width': 'selected int width', 'bad-signature': 'selected malloc declaration'}.get(name)
        require(command['argv'] == case_command(native, source_path) and probe['source_sha256'] == expected_sha
                and (source_path == value['input']['path'] if name == 'candidate' else path_type(source_path).name == name + '.c')
                and type(command['exit_code']) is int and command['exit_code'] == (1 if marker else 0)
                and command['expected_negative_marker'] == marker, 'case probe recipe/result')
        for key in ('stdout', 'stderr'):
            item = command[key]
            fields(item, 'bytes sha256', 'case stream')
            require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_OUTPUT
                    and digest(item['sha256']), 'case stream metadata')
            require((item['bytes'] > 0 and item['sha256'] != hashlib.sha256(b'').hexdigest())
                    if marker and key == 'stderr' else
                    item == {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}, 'case unexpected stream')
        if marker:
            require(probe['dependencies'] is None and probe['headers'] == [], 'negative probe dependencies')
            continue
        dependency = probe['dependencies']
        validate_command(dependency)
        require(dependency['argv'] == case_command(native, source_path, dependencies=True)
                and dependency['stderr'] == '', 'case dependency command')
        paths = dependency_paths(dependency['stdout'], flavor)
        require(type(probe['headers']) is list and len(paths) == len(probe['headers'])
                and path_type(paths[0]) == path_type(source_path), 'case dependency closure')
        for record, path in zip(probe['headers'], paths):
            validate_file(record, flavor)
            require(path_type(record['path']) == path_type(path), 'case dependency path')
        require(probe['headers'][0]['sha256'] == expected_sha
                and sum(row['bytes'] for row in probe['headers']) <= MAX_HEADER_BYTES, 'case dependency bytes')
        identities.extend(probe['headers'])
        header_paths = [path_type(row['resolved_path']) for row in probe['headers'][1:]]
        resource = path_type(native['tools']['clang']['resource_dir']) / 'include'
        if system == 'Darwin':
            sdk = path_type(native['platform']['metadata']['sdk_settings']['resolved_path']).parent
            require(any(path == sdk / 'usr/include/stdlib.h' for path in header_paths)
                    and all(path.is_relative_to(sdk) or path.is_relative_to(resource) for path in header_paths),
                    'case headers escaped selected CLT/SDK')
        elif system == 'Windows':
            metadata = native['platform']['metadata']
            roots, versions = metadata['selected_roots'], metadata['versions']
            ucrt = path_type(roots['UniversalCRTSdkDir']) / 'Include' / versions['UCRTVersion'] / 'ucrt'
            admitted = [path_type(path) for path in value['environment']['INCLUDE'].split(';') if path] + [resource]
            require(ucrt / 'stdlib.h' in header_paths and all(any(path.is_relative_to(root) for root in admitted)
                    for path in header_paths), 'case headers escaped selected Windows SDK')
    bindings = {}
    for record in identities:
        path, resolved = path_type(record['path']), path_type(record['resolved_path'])
        require('..' not in resolved.parts, 'case noncanonical resolved input')
        entry = (resolved, record['bytes'], record['sha256'])
        for key in (path, resolved):
            require(key not in bindings or bindings[key] == entry, 'case input identity disagreement')
            bindings[key] = entry
    return {'syntax_checked': True, 'local_native_bytes_verified': False, 'native_qualified': False,
            'license_qualified': False, 'independent_quota_examples': 0, 'task_ready': False, 'product_qualified': False}


def capture_case(args):
    import product_profiles as profiles
    root = args.root.resolve(strict=True)
    require(Path(profiles.__file__).resolve() == root / CASE_SOURCE_FILES[0], 'case materializer source')
    environment = case_environment(os.environ, platform.system())
    with selected_case_environment(environment):
        native = capture(args)
        resolve_case_resources(native)
        validate_case_selection(native, environment)
        source_files = {}
        for relative in CASE_SOURCE_FILES:
            actual = file_identity(root / relative)
            committed = run(['git', 'cat-file', 'blob', args.source_sha + ':' + relative], cwd=root)['stdout']
            require(actual['sha256'] == hashlib.sha256(committed.encode()).hexdigest(), 'case helper differs from commit')
            source_files[relative] = actual['sha256']
        binding = profiles.verify_external_inputs(root / profiles.GCC_BINDING, root, args.external_root)
        candidate = file_identity(args.external_root / 'case.c')
        require(candidate['sha256'] == CASE_SHA and candidate['bytes'] == 636, 'case source selection')
        probes = {}
        with tempfile.TemporaryDirectory(prefix='codeskeptic-case-', dir=args.output.parent) as directory:
            temporary = Path(directory).resolve(strict=True)
            for name, source in case_abi_sources().items():
                with (temporary / (name + '.c')).open('x', encoding='utf-8', newline='\n') as stream:
                    stream.write(source)
            paths = {'candidate': Path(candidate['path']), **{name: temporary / (name + '.c') for name in case_abi_sources()}}
            for name, path in paths.items():
                marker = {'bad-width': 'selected int width', 'bad-signature': 'selected malloc declaration'}.get(name)
                command = run(case_command(native, str(path)), allowed=(1,) if marker else (0,))
                dependency = None if marker else run(case_command(native, str(path), dependencies=True))
                headers, total = [], 0
                if dependency:
                    for dependency_path in dependency_paths(dependency['stdout'], 'windows' if platform.system() == 'Windows' else 'posix'):
                        item = file_identity(Path(dependency_path), maximum=MAX_HEADER_BYTES - total)
                        total += item['bytes']
                        headers.append(item)
                probes[name] = {'source_sha256': file_identity(path)['sha256'], 'command': case_record(command, marker),
                                'dependencies': dependency, 'headers': headers}
            value = {'schema': 'codeskeptic-native-case-observation/v1', 'native_identity': native,
                     'environment': environment, 'source_files': source_files, 'binding': binding,
                     'input': candidate, 'probes': probes, 'syntax_checked': True,
                     'native_qualified': False, 'license_qualified': False, 'independent_quota_examples': 0,
                     'task_ready': False, 'product_qualified': False}
            validate_case_document(value)
            for record in ([tool['file'] for tool in native['tools'].values()]
                           + [row for probe in native['probes'].values() for row in probe['headers']]
                           + [row for probe in probes.values() for row in probe['headers']]):
                require(file_identity(Path(record['path'])) == record, 'case native input changed')
            require(profiles.verify_external_inputs(root / profiles.GCC_BINDING, root, args.external_root) == binding
                    and native_metadata(platform.system()) == native['platform']['metadata']
                    and source_identity(root, args.source_sha) == native['source']
                    and all(file_identity(root / relative)['sha256'] == sha for relative, sha in source_files.items()),
                    'case final input/source identity changed')
        return value


def case_observation_failure(error):
    """Only fixed module names and source line numbers, never native diagnostics."""
    modules = {__file__: 'identity', str(Path(__file__).with_name('product_profiles.py')): 'profile'}
    checks, seen = [], set()
    while error is not None and id(error) not in seen and len(seen) < 8:
        seen.add(id(error))
        trace = error.__traceback__
        while trace is not None and len(checks) < 24:
            module = modules.get(trace.tb_frame.f_code.co_filename)
            if module:
                checks.append(module + ':' + str(trace.tb_lineno))
            trace = trace.tb_next
        error = error.__context__
    return 'case observation rejected; checks=' + (','.join(checks) if checks else 'unknown')


def case_failure_kind(error):
    """Fixed categories from the bounded cause chain; never exception text."""
    seen = set()
    while error is not None and id(error) not in seen and len(seen) < 8:
        seen.add(id(error))
        if isinstance(error, subprocess.TimeoutExpired):
            return 'TIMEOUT'
        if isinstance(error, OSError):
            return 'OS_ERROR'
        error = error.__context__
    return 'INVALID'


WINDOWS_DIAGNOSTIC_PREFIX = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                             "[Console]::WriteLine('STARTED'); ")
WINDOWS_DIAGNOSTIC_PROBES = {
    'startup': WINDOWS_DIAGNOSTIC_PREFIX,
    'modules': WINDOWS_DIAGNOSTIC_PREFIX + "try { Import-Module CimCmdlets -ErrorAction Stop; "
               "[Console]::WriteLine('CIM_LOADED'); "
               "Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop; "
               "[Console]::WriteLine('UTILITY_LOADED') } catch { exit 21 }",
    'query': WINDOWS_DIAGNOSTIC_PREFIX + 'try { $identityOs = & { ' + WINDOWS_OS_QUERY
             + " }; if (-not $identityOs) { exit 22 }; [Console]::WriteLine('QUERY_DONE') } catch { exit 21 }"}
WINDOWS_DIAGNOSTIC_MARKERS = {'startup': ['STARTED'], 'modules': ['STARTED', 'CIM_LOADED', 'UTILITY_LOADED'],
                             'query': ['STARTED', 'QUERY_DONE']}
WINDOWS_DIAGNOSTIC_ORDER = [(variant, probe) for probe in WINDOWS_DIAGNOSTIC_PROBES
                          for variant in ('selected', 'system_module_path_only')]


def windows_diagnostic_probe(shell, probe, environment):
    """One fixed installed-tool probe, no retry and no raw native output export.

    Like run(), the 30s subprocess timeout and post-capture bound are not hard
    descendant-process/RSS/output-production limits. This is not a product worker.
    """
    require(probe in WINDOWS_DIAGNOSTIC_PROBES, 'unknown Windows diagnostic probe')
    argv = [shell, '-NoProfile', '-NonInteractive', '-Command', WINDOWS_DIAGNOSTIC_PROBES[probe]]
    started = time.monotonic()
    code, outcome, stdout, stderr = None, 'OK', b'', b''
    try:
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False,
                                env=checked_environment(environment))
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
        if code != 0:
            outcome = 'NONZERO'
    except subprocess.TimeoutExpired as error:
        outcome, stdout, stderr = 'TIMEOUT', error.stdout or b'', error.stderr or b''
    except OSError:
        outcome = 'OS_ERROR'
    elapsed = max(0, round((time.monotonic() - started) * 1000))
    lines = stdout[:MAX_OUTPUT].splitlines()
    accepted = [marker.encode('ascii') for marker in WINDOWS_DIAGNOSTIC_MARKERS[probe]]
    markers = [line.decode('ascii') for line in lines if line in accepted][:8]
    unexpected = bool(stderr) or any(line not in accepted for line in lines)
    if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
        if outcome == 'OK':
            outcome = 'OUTPUT_LIMIT'
        unexpected = True
    if outcome == 'OK' and (unexpected or markers != WINDOWS_DIAGNOSTIC_MARKERS[probe]):
        outcome = 'UNEXPECTED_OUTPUT'
    return {'probe': probe, 'outcome': outcome, 'exit_code': code, 'elapsed_ms': elapsed,
            'markers': markers, 'unexpected_output': unexpected}


def validate_windows_diagnostic(value):
    fields(value, 'schema source shell module_directory runner probes diagnostic_only task_ready '
           'native_qualified product_qualified timeout_seconds', 'Windows diagnostic')
    require(value['schema'] == 'codeskeptic-windows-query-diagnostic/v1'
            and value['diagnostic_only'] is True and value['timeout_seconds'] == 30
            and type(value['timeout_seconds']) is int
            and all(value[key] is False for key in ('task_ready', 'native_qualified', 'product_qualified')),
            'diagnostic is not qualification')
    fields(value['source'], 'head tree collector_sha256 workflow_sha256 profiles_sha256 api_models_sha256', 'source')
    require(all(digest(item, 40 if key in ('head', 'tree') else 64)
                for key, item in value['source'].items()), 'diagnostic source identity')
    validate_file(value['shell'], 'windows')
    module = PureWindowsPath(value['module_directory'])
    require(module == PureWindowsPath(value['shell']['path']).parent / 'Modules', 'diagnostic system modules')
    fields(value['runner'], 'run_id attempt head image_os image_version', 'diagnostic runner')
    require(all(nonempty(item) for item in value['runner'].values())
            and value['runner']['head'] == value['source']['head'], 'diagnostic runner identity')
    require(type(value['probes']) is list and len(value['probes']) == len(WINDOWS_DIAGNOSTIC_ORDER),
            'diagnostic probe matrix')
    for row, (variant, probe) in zip(value['probes'], WINDOWS_DIAGNOSTIC_ORDER):
        fields(row, 'variant probe outcome exit_code elapsed_ms markers unexpected_output', 'diagnostic probe')
        require(row['variant'] == variant and row['probe'] == probe
                and row['outcome'] in ('OK', 'NONZERO', 'TIMEOUT', 'OS_ERROR', 'OUTPUT_LIMIT', 'UNEXPECTED_OUTPUT')
                and type(row['elapsed_ms']) is int and 0 <= row['elapsed_ms'] <= 300000
                and type(row['unexpected_output']) is bool and type(row['markers']) is list
                and len(row['markers']) <= 8
                and all(marker in WINDOWS_DIAGNOSTIC_MARKERS[probe] for marker in row['markers']),
                'diagnostic fixed observations')
        require((row['exit_code'] is None) == (row['outcome'] in ('TIMEOUT', 'OS_ERROR'))
                and (row['exit_code'] is None or type(row['exit_code']) is int), 'diagnostic process status')
        if row['outcome'] == 'OK':
            require(row['exit_code'] == 0 and row['markers'] == WINDOWS_DIAGNOSTIC_MARKERS[probe]
                    and row['unexpected_output'] is False, 'diagnostic success markers')
        if row['outcome'] == 'NONZERO':
            require(row['exit_code'] != 0, 'diagnostic failed exit')
        if row['outcome'] == 'OS_ERROR':
            require(row['markers'] == [] and row['unexpected_output'] is False, 'unstarted diagnostic output')
        if row['outcome'] in ('OUTPUT_LIMIT', 'UNEXPECTED_OUTPUT'):
            require(row['exit_code'] == 0, 'diagnostic output-only failure exit')
            require(row['unexpected_output'] or (row['outcome'] == 'UNEXPECTED_OUTPUT'
                    and row['markers'] != WINDOWS_DIAGNOSTIC_MARKERS[probe]), 'diagnostic output-only failure')
    return {'diagnostic_only': True, 'task_ready': False, 'native_qualified': False, 'product_qualified': False}


def windows_diagnostic_variants(environment, module_directory):
    environment = case_environment(environment, 'Windows')
    native_root = PureWindowsPath(environment['SystemRoot'])
    require(native_root.is_absolute() and re.fullmatch('[A-Za-z]:', native_root.drive)
            and '..' not in native_root.parts, 'diagnostic requires a local Windows system root')
    require(PureWindowsPath(module_directory) == native_root / 'System32/WindowsPowerShell/v1.0/Modules',
            'only installed system module search is contrasted')
    return {'selected': environment,
            'system_module_path_only': {**environment, 'PSModulePath': str(module_directory)}}


def capture_windows_diagnostic(args):
    require(platform.system() == 'Windows', 'diagnostic requires actual Windows')
    source = source_identity(args.root, args.source_sha)
    environment = case_environment(os.environ, 'Windows')
    modules = Path(environment['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules'
    variants = windows_diagnostic_variants(os.environ, modules)
    system_root = Path(environment['SystemRoot']).resolve(strict=True)
    shell = system_root / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    require(modules.is_dir() and not modules.is_symlink() and modules.resolve() == modules,
            'installed Windows system module directory')
    require(Path(shutil.which('powershell.exe', path=environment.get('PATH', '')) or '').resolve(strict=True)
            == shell.resolve(strict=True), 'diagnostic must use the original Windows shell')
    shell_identity = file_identity(shell)
    rows = [{**windows_diagnostic_probe(str(shell), probe, variants[variant]), 'variant': variant}
            for variant, probe in WINDOWS_DIAGNOSTIC_ORDER]
    value = {'schema': 'codeskeptic-windows-query-diagnostic/v1', 'source': source,
             'shell': shell_identity, 'module_directory': str(modules),
             'runner': {field: environment.get(key, '') for field, key in
                        (('run_id', 'GITHUB_RUN_ID'), ('attempt', 'GITHUB_RUN_ATTEMPT'), ('head', 'GITHUB_SHA'),
                         ('image_os', 'ImageOS'), ('image_version', 'ImageVersion'))},
             'probes': rows, 'diagnostic_only': True, 'timeout_seconds': 30,
             'task_ready': False, 'native_qualified': False, 'product_qualified': False}
    validate_windows_diagnostic(value)
    require(file_identity(shell) == shell_identity and source_identity(args.root, args.source_sha) == source,
            'diagnostic shell/source changed')
    return value


WINDOWS_STAGE_NAMES = ('STARTED', 'CIM_LOADED', 'UTILITY_LOADED', 'CIM_QUERY_DONE', 'QUERY_DONE')


def windows_stage_script():
    def marker(name):
        return ("[Console]::WriteLine('" + name + ":' + $identityClock.ElapsedMilliseconds.ToString("
                "[Globalization.CultureInfo]::InvariantCulture)); [Console]::Out.Flush(); ")
    return ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
            "$identityClock=[Diagnostics.Stopwatch]::StartNew(); " + marker('STARTED')
            + "try { Import-Module CimCmdlets -ErrorAction Stop; " + marker('CIM_LOADED')
            + "Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop; " + marker('UTILITY_LOADED')
            + "$identityOs=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; " + marker('CIM_QUERY_DONE')
            + "$identityJson=$identityOs | Select-Object Caption,Version,BuildNumber,OSArchitecture "
            "| ConvertTo-Json -Compress; if (-not $identityJson) { exit 22 }; " + marker('QUERY_DONE')
            + '} catch { exit 21 }')


def parse_windows_stage_output(stdout, parent_elapsed_ms):
    """Keep only a complete, ordered prefix. Invalid bytes are flags, not output."""
    require(type(stdout) is bytes and type(parent_elapsed_ms) is int
            and 0 <= parent_elapsed_ms <= 300000, 'staged diagnostic input bound')
    limited = len(stdout) > MAX_OUTPUT
    data = stdout[:MAX_OUTPUT]
    lines = data.split(b'\n')
    trailing = bool(lines.pop())
    stages, malformed, previous = [], limited, 0
    for line in lines:
        if line.endswith(b'\r'):
            line = line[:-1]
        match = re.fullmatch(rb'([A-Z_]+):(0|[1-9][0-9]{0,5})', line)
        if (not match or len(stages) >= len(WINDOWS_STAGE_NAMES)
                or match[1].decode('ascii') != WINDOWS_STAGE_NAMES[len(stages)]):
            malformed = True
            break
        elapsed = int(match[2])
        # The parent includes process startup/shutdown; allow only its 1ms rounding.
        if not previous <= elapsed <= parent_elapsed_ms + 1:
            malformed = True
            break
        stages.append({'name': WINDOWS_STAGE_NAMES[len(stages)], 'elapsed_ms': elapsed})
        previous = elapsed
    return {'stages': stages, 'malformed_output': malformed, 'trailing_output': trailing}


def windows_stage_probe(shell, environment):
    """One 30s process for all stages; no per-stage deadline reset or retry."""
    argv = [shell, '-NoProfile', '-NonInteractive', '-Command', windows_stage_script()]
    started = time.monotonic()
    outcome, code, stdout, stderr = 'OK', None, b'', b''
    try:
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False,
                                env=checked_environment(environment))
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
        if code != 0:
            outcome = 'NONZERO'
    except subprocess.TimeoutExpired as error:
        outcome, stdout, stderr = 'TIMEOUT', error.stdout or b'', error.stderr or b''
    except OSError:
        outcome = 'OS_ERROR'
    elapsed = max(0, round((time.monotonic() - started) * 1000))
    parsed = parse_windows_stage_output(stdout, elapsed)
    excessive = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
    if outcome == 'OK' and excessive:
        outcome = 'OUTPUT_LIMIT'
    if outcome == 'OK' and (stderr or parsed['malformed_output'] or parsed['trailing_output']
                            or len(parsed['stages']) != len(WINDOWS_STAGE_NAMES)):
        outcome = 'UNEXPECTED_OUTPUT'
    return {'outcome': outcome, 'exit_code': code, 'elapsed_ms': elapsed, **parsed,
            'stderr_present': bool(stderr), 'output_limit_exceeded': excessive}


def validate_windows_stages(value):
    fields(value, 'schema source shell runner observation diagnostic_only task_ready native_qualified '
           'product_qualified timeout_seconds', 'Windows staged diagnostic')
    require(value['schema'] == 'codeskeptic-windows-query-diagnostic/v2'
            and value['diagnostic_only'] is True and type(value['timeout_seconds']) is int
            and value['timeout_seconds'] == 30
            and all(value[key] is False for key in ('task_ready', 'native_qualified', 'product_qualified')),
            'staged diagnostic is not qualification')
    fields(value['source'], 'head tree collector_sha256 workflow_sha256 profiles_sha256 api_models_sha256', 'source')
    require(all(digest(item, 40 if key in ('head', 'tree') else 64)
                for key, item in value['source'].items()), 'staged source identity')
    validate_file(value['shell'], 'windows')
    fields(value['runner'], 'run_id attempt head image_os image_version', 'staged runner')
    require(all(nonempty(item) for item in value['runner'].values())
            and value['runner']['head'] == value['source']['head'], 'staged runner identity')
    row = value['observation']
    fields(row, 'outcome exit_code elapsed_ms stages malformed_output trailing_output stderr_present '
           'output_limit_exceeded', 'staged observation')
    require(row['outcome'] in ('OK', 'NONZERO', 'TIMEOUT', 'OS_ERROR', 'OUTPUT_LIMIT', 'UNEXPECTED_OUTPUT')
            and type(row['elapsed_ms']) is int and 0 <= row['elapsed_ms'] <= 300000
            and type(row['stages']) is list and len(row['stages']) <= len(WINDOWS_STAGE_NAMES), 'staged observations')
    flags = ('malformed_output', 'trailing_output', 'stderr_present', 'output_limit_exceeded')
    require(all(type(row[key]) is bool for key in flags), 'staged output flags')
    require((row['exit_code'] is None) == (row['outcome'] in ('TIMEOUT', 'OS_ERROR'))
            and (row['exit_code'] is None or type(row['exit_code']) is int), 'staged process status')
    previous = 0
    for stage, expected in zip(row['stages'], WINDOWS_STAGE_NAMES):
        fields(stage, 'name elapsed_ms', 'completed stage')
        require(stage['name'] == expected and type(stage['elapsed_ms']) is int
                and previous <= stage['elapsed_ms'] <= row['elapsed_ms'] + 1, 'staged ordered clock prefix')
        previous = stage['elapsed_ms']
    if row['outcome'] == 'OK':
        require(row['exit_code'] == 0 and len(row['stages']) == len(WINDOWS_STAGE_NAMES)
                and not any(row[key] for key in flags), 'staged completed process')
    elif row['outcome'] == 'NONZERO':
        require(row['exit_code'] != 0, 'staged failed process')
    elif row['outcome'] == 'OS_ERROR':
        require(row['stages'] == [] and not any(row[key] for key in flags), 'staged unavailable process')
    elif row['outcome'] == 'OUTPUT_LIMIT':
        require(row['exit_code'] == 0 and row['output_limit_exceeded'], 'staged output bound failure')
    elif row['outcome'] == 'UNEXPECTED_OUTPUT':
        require(row['exit_code'] == 0 and not row['output_limit_exceeded']
                and (any(row[key] for key in flags) or len(row['stages']) != len(WINDOWS_STAGE_NAMES)),
                'staged incomplete or malformed protocol')
    return {'diagnostic_only': True, 'task_ready': False, 'native_qualified': False, 'product_qualified': False}


def capture_windows_stages(args):
    require(platform.system() == 'Windows', 'staged diagnostic requires actual Windows')
    source = source_identity(args.root, args.source_sha)
    environment = case_environment(os.environ, 'Windows')
    native_root = PureWindowsPath(environment['SystemRoot'])
    require(native_root.is_absolute() and re.fullmatch('[A-Za-z]:', native_root.drive)
            and '..' not in native_root.parts, 'staged diagnostic requires local Windows')
    root = Path(environment['SystemRoot']).resolve(strict=True)
    shell = root / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    require(Path(shutil.which('powershell.exe', path=environment.get('PATH', '')) or '').resolve(strict=True)
            == shell.resolve(strict=True), 'staged diagnostic must use original Windows shell')
    shell_identity = file_identity(shell)
    row = windows_stage_probe(str(shell), environment)
    value = {'schema': 'codeskeptic-windows-query-diagnostic/v2', 'source': source, 'shell': shell_identity,
             'runner': {field: environment.get(key, '') for field, key in
                        (('run_id', 'GITHUB_RUN_ID'), ('attempt', 'GITHUB_RUN_ATTEMPT'), ('head', 'GITHUB_SHA'),
                         ('image_os', 'ImageOS'), ('image_version', 'ImageVersion'))},
             'observation': row, 'diagnostic_only': True, 'timeout_seconds': 30,
             'task_ready': False, 'native_qualified': False, 'product_qualified': False}
    validate_windows_stages(value)
    require(file_identity(shell) == shell_identity and source_identity(args.root, args.source_sha) == source,
            'staged diagnostic shell/source changed')
    return value


WINDOWS_POLICY_VALUES = ('AllSigned', 'Bypass', 'Default', 'RemoteSigned', 'Restricted', 'Undefined', 'Unrestricted')
WINDOWS_POLICY_SCOPES = ('MachinePolicy', 'UserPolicy', 'Process', 'CurrentUser', 'LocalMachine')
WINDOWS_POLICY_NAMES = ('STARTED', 'ENGINE', 'EFFECTIVE', *WINDOWS_POLICY_SCOPES, 'POLICY_DONE')


def windows_policy_preference(environment):
    values = [value for key, value in environment.items() if key.casefold() == 'psexecutionpolicypreference']
    if not values:
        return {'state': 'absent', 'value': None}
    recognized = {value.casefold(): value for value in WINDOWS_POLICY_VALUES}
    value = recognized.get(values[0].casefold()) if len(values) == 1 and type(values[0]) is str else None
    return {'state': 'recognized' if value else 'unrecognized', 'value': value}


def windows_policy_script():
    def marker(name, expression):
        return "[Console]::WriteLine('" + name + ":' + (" + expression + ")); [Console]::Out.Flush(); "
    return ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); " + marker('STARTED', "'OK'")
            + 'try { ' + marker('ENGINE', '$PSVersionTable.PSVersion.ToString()')
            + marker('EFFECTIVE', '(Microsoft.PowerShell.Security\\Get-ExecutionPolicy -ErrorAction Stop).ToString()')
            + ''.join(marker(scope, '(Microsoft.PowerShell.Security\\Get-ExecutionPolicy -Scope ' + scope
                             + ' -ErrorAction Stop).ToString()') for scope in WINDOWS_POLICY_SCOPES)
            + marker('POLICY_DONE', "'OK'") + '} catch { exit 21 }')


def valid_windows_policy_record(name, value):
    if type(value) is not str:
        return False
    if name in ('STARTED', 'POLICY_DONE'):
        return value == 'OK'
    if name == 'ENGINE':
        return re.fullmatch(r'(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){1,3}', value) is not None
    return name in ('EFFECTIVE', *WINDOWS_POLICY_SCOPES) and value in WINDOWS_POLICY_VALUES


def parse_windows_policy_output(stdout):
    require(type(stdout) is bytes, 'policy diagnostic bytes required')
    limited = len(stdout) > MAX_OUTPUT
    lines = stdout[:MAX_OUTPUT].split(b'\n')
    trailing = bool(lines.pop())
    records, malformed = [], limited
    for line in lines:
        if line.endswith(b'\r'):
            line = line[:-1]
        match = re.fullmatch(rb'([A-Za-z_]+):([A-Za-z0-9.]+)', line)
        if (not match or len(records) >= len(WINDOWS_POLICY_NAMES)
                or match[1].decode('ascii') != WINDOWS_POLICY_NAMES[len(records)]
                or not valid_windows_policy_record(match[1].decode('ascii'), match[2].decode('ascii'))):
            malformed = True
            break
        records.append({'name': match[1].decode('ascii'), 'value': match[2].decode('ascii')})
    return {'records': records, 'malformed_output': malformed, 'trailing_output': trailing}


def windows_policy_probe(shell, environment):
    argv = [shell, '-NoProfile', '-NonInteractive', '-Command', windows_policy_script()]
    started = time.monotonic()
    outcome, code, stdout, stderr = 'OK', None, b'', b''
    try:
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False,
                                env=checked_environment(environment))
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
        if code != 0:
            outcome = 'NONZERO'
    except subprocess.TimeoutExpired as error:
        outcome, stdout, stderr = 'TIMEOUT', error.stdout or b'', error.stderr or b''
    except OSError:
        outcome = 'OS_ERROR'
    elapsed = max(0, round((time.monotonic() - started) * 1000))
    parsed = parse_windows_policy_output(stdout)
    excessive = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
    if outcome == 'OK' and excessive:
        outcome = 'OUTPUT_LIMIT'
    if outcome == 'OK' and (stderr or parsed['malformed_output'] or parsed['trailing_output']
                            or len(parsed['records']) != len(WINDOWS_POLICY_NAMES)):
        outcome = 'UNEXPECTED_OUTPUT'
    return {'outcome': outcome, 'exit_code': code, 'elapsed_ms': elapsed, **parsed,
            'stderr_present': bool(stderr), 'output_limit_exceeded': excessive}


def validate_windows_context(value):
    require(type(value) is dict and value.get('schema') == 'codeskeptic-windows-query-diagnostic/v3',
            'Windows context diagnostic schema')
    # V3 adds a later observation; the original V2 projection keeps its meaning.
    stages = {key: item for key, item in value.items() if key != 'policy'}
    stages['schema'] = 'codeskeptic-windows-query-diagnostic/v2'
    result = validate_windows_stages(stages)
    policy = value['policy']
    fields(policy, 'inherited_preference case_preference observation', 'policy context')
    for key in ('inherited_preference', 'case_preference'):
        preference = policy[key]
        fields(preference, 'state value', 'policy preference')
        require(preference['state'] in ('absent', 'recognized', 'unrecognized')
                and (preference['value'] in WINDOWS_POLICY_VALUES if preference['state'] == 'recognized'
                     else preference['value'] is None), 'classified policy preference')
    require(policy['case_preference'] == {'state': 'absent', 'value': None}, 'unchanged filtered case preference')
    row = policy['observation']
    fields(row, 'outcome exit_code elapsed_ms records malformed_output trailing_output stderr_present '
           'output_limit_exceeded', 'policy observation')
    require(row['outcome'] in ('OK', 'NONZERO', 'TIMEOUT', 'OS_ERROR', 'OUTPUT_LIMIT', 'UNEXPECTED_OUTPUT')
            and type(row['elapsed_ms']) is int and 0 <= row['elapsed_ms'] <= 300000
            and type(row['records']) is list and len(row['records']) <= len(WINDOWS_POLICY_NAMES), 'policy observations')
    flags = ('malformed_output', 'trailing_output', 'stderr_present', 'output_limit_exceeded')
    require(all(type(row[key]) is bool for key in flags), 'policy output flags')
    require((row['exit_code'] is None) == (row['outcome'] in ('TIMEOUT', 'OS_ERROR'))
            and (row['exit_code'] is None or type(row['exit_code']) is int), 'policy process status')
    for record, expected in zip(row['records'], WINDOWS_POLICY_NAMES):
        fields(record, 'name value', 'policy record')
        require(record['name'] == expected and valid_windows_policy_record(expected, record['value']),
                'policy ordered allowed-value prefix')
    if row['outcome'] == 'OK':
        require(row['exit_code'] == 0 and len(row['records']) == len(WINDOWS_POLICY_NAMES)
                and not any(row[key] for key in flags), 'policy completed process')
    elif row['outcome'] == 'NONZERO':
        require(row['exit_code'] != 0, 'policy failed process')
    elif row['outcome'] == 'OS_ERROR':
        require(row['records'] == [] and not any(row[key] for key in flags), 'policy unavailable process')
    elif row['outcome'] == 'OUTPUT_LIMIT':
        require(row['exit_code'] == 0 and row['output_limit_exceeded'], 'policy output bound failure')
    elif row['outcome'] == 'UNEXPECTED_OUTPUT':
        require(row['exit_code'] == 0 and not row['output_limit_exceeded']
                and (any(row[key] for key in flags) or len(row['records']) != len(WINDOWS_POLICY_NAMES)),
                'policy incomplete or malformed protocol')
    return result


def capture_windows_context(args):
    inherited = windows_policy_preference(os.environ)
    # Never inspect policy in the timed module process or before its attempt.
    value = capture_windows_stages(args)
    environment = case_environment(os.environ, 'Windows')
    preference = windows_policy_preference(environment)
    shell = Path(value['shell']['path'])
    require(file_identity(shell) == value['shell'], 'context shell changed before policy probe')
    row = windows_policy_probe(str(shell), environment)
    value['schema'] = 'codeskeptic-windows-query-diagnostic/v3'
    value['policy'] = {'inherited_preference': inherited, 'case_preference': preference, 'observation': row}
    validate_windows_context(value)
    require(file_identity(shell) == value['shell'] and source_identity(args.root, args.source_sha) == value['source'],
            'context diagnostic shell/source changed')
    return value


DECLARATION_PLATFORM = {'Linux': 'linux-x86_64', 'Windows': 'windows-x64', 'Darwin': 'macos-arm64'}
DECLARATION_PRODUCERS = ('scripts/product_profiles.py',)
POSIX_DECLARATION_PROFILE = 'c17-posix2008/v1'
DECLARATION_MACROS = ('__STRICT_ANSI__', '_POSIX_C_SOURCE', '_POSIX_SOURCE', '_ATFILE_SOURCE',
                      '__USE_POSIX', '__USE_POSIX2', '__USE_ATFILE', '__USE_MISC', '__USE_XOPEN2K8')
DECLARATION_TYPES = {'Void', 'Bool', 'Char_S', 'Char_U', 'SChar', 'UChar', 'Short', 'UShort',
                     'Int', 'UInt', 'Long', 'ULong', 'LongLong', 'ULongLong', 'Float', 'Double', 'LongDouble'}


def declaration_requests(model, system):
    """The fixed draft requests; omitted SQLite is a gap, not a smaller denominator."""
    from product_profiles import native_api_metadata
    native_api_metadata(model)
    require(system in DECLARATION_PLATFORM, 'declaration platform')
    return [row for row in model['sources'] + model['sinks']
            if row['header'] not in (None, 'sqlite3.h') and DECLARATION_PLATFORM[system] in row['platforms']]


def declaration_coverage(model):
    declaration_requests(model, 'Linux')
    return {'required_library_pairs': sum(len(row['platforms']) for row in model['sources'] + model['sinks']
                                          if row['header'] is not None),
            'required_entry_pairs': sum(len(row['platforms']) for row in model['sources'] if row['header'] is None),
            'qualified_library_pairs': 0, 'qualified_entry_pairs': 0}


def declaration_profile(profile, system):
    require(system in DECLARATION_PLATFORM, 'declaration profile platform')
    if profile is None:
        return None
    require(profile == POSIX_DECLARATION_PROFILE and system in ('Linux', 'Darwin'),
            'unsupported declaration visibility profile/platform')
    return {'id': POSIX_DECLARATION_PROFILE, 'language': 'c17',
            'feature_macros': {'_POSIX_C_SOURCE': '200809L'}}


def declaration_source(model, system, profile=None):
    selected = declaration_profile(profile, system)
    rows = declaration_requests(model, system)
    headers = (['winsock2.h', 'io.h', 'fcntl.h'] if system == 'Windows'
               else ['sys/types.h', 'sys/socket.h', 'unistd.h', 'fcntl.h']) + ['stdio.h', 'stdlib.h']
    lines = (['#define _POSIX_C_SOURCE 200809L'] if selected is not None else [])
    lines += ['#include <' + header + '>' for header in headers]
    for row in rows:
        symbol, signature = row['symbol'], row['signature']
        parameters = signature['parameters'] + (['...'] if signature['variadic'] else [])
        lines += ['typedef ' + signature['result'] + ' (*cs_expected_' + symbol + ')(' +
                  ', '.join(parameters or ['void']) + ');',
                  '_Static_assert(_Generic(&' + symbol + ', cs_expected_' + symbol +
                  ': 1, default: 0), "native signature ' + symbol + '");',
                  '__typeof__(&' + symbol + ') cs_native_' + symbol + ' = &' + symbol + ';']
    return '\n'.join(lines + ['int main(int argc, char **argv) { return argc == 0 || argv == 0; }', ''])


def declaration_command(compiler, system, metadata, source, dependencies=False):
    require(system in DECLARATION_PLATFORM, 'declaration command platform')
    argv = [compiler['file']['resolved_path'], '--no-default-config', '-fno-modules',
            '-resource-dir', compiler['resource_dir'], '-x', 'c', '-std=c17', '--target=' + compiler['target']]
    if system == 'Darwin':
        argv += ['-isysroot', metadata['sdk_root']]
    return argv + (['-M', '-MT', 'identity-probe'] if dependencies else ['-fsyntax-only']) + [source]


def declaration_type_key(value):
    """Type identity is separate from declaration-level qualifiers/spelling."""
    if type(value) is list:
        return [declaration_type_key(item) for item in value]
    if type(value) is not dict:
        return value
    return {key: declaration_type_key(item) for key, item in value.items()
            if key not in ('spelling', 'canonical_spelling', 'qualifiers')}


def declaration_parameter_key(value):
    result = declaration_type_key(value)
    # C function-type identity discards top-level parameter qualifiers. Their
    # separately captured declaration values are retained, never reconstructed.
    result['canonical_qualifiers'] = dict.fromkeys(('const', 'volatile', 'restrict'), False)
    return result


def declaration_type_incomplete(value):
    if type(value) is list:
        return any(declaration_type_incomplete(item) for item in value)
    if type(value) is not dict:
        return False
    return (value.get('unsupported') is True
            or any(type(value.get(k)) is int and value[k] < 0 for k in ('size', 'alignment'))
            or ('declaration' in value and value['declaration'] is None)
            or any(declaration_type_incomplete(item) for item in value.values()))


def declaration_backend(library):
    """Instantiate only inside the bounded capture child, never a metadata reader.

    Public CIndex layouts/prototypes: clang-c/Index.h, CXString.h and
    CXSourceLocation.h. The supported adapter ABI is 64-bit pointers/32-bit
    int/unsigned. This does not establish parser/driver or hosted equivalence.
    """
    import ctypes as c

    class String(c.Structure):
        _fields_ = [('data', c.c_void_p), ('flags', c.c_uint)]

    class Cursor(c.Structure):
        _fields_ = [('kind', c.c_int), ('xdata', c.c_int), ('data', c.c_void_p * 3)]

    class Type(c.Structure):
        _fields_ = [('kind', c.c_int), ('data', c.c_void_p * 2)]

    class Location(c.Structure):
        _fields_ = [('data', c.c_void_p * 2), ('offset_data', c.c_uint)]

    require(c.sizeof(c.c_void_p) == 8 and c.sizeof(c.c_int) == c.sizeof(c.c_uint) == 4
            and [c.sizeof(t) for t in (String, Cursor, Type, Location)] == [16, 32, 24, 24],
            'unsupported declaration adapter ABI')
    visitor = c.CFUNCTYPE(c.c_uint, Cursor, Cursor, c.c_void_p)
    inclusion = c.CFUNCTYPE(None, c.c_void_p, c.POINTER(Location), c.c_uint, c.c_void_p)
    library = Path(library)
    require(library.is_absolute() and library.resolve(strict=True) == library and library.is_file(),
            'declaration library must be explicit and physical')
    lib = c.CDLL(str(library))
    signatures = {
        'createIndex': (c.c_void_p, c.c_int, c.c_int), 'disposeIndex': (None, c.c_void_p),
        'disposeTranslationUnit': (None, c.c_void_p),
        'parseTranslationUnit2FullArgv': (c.c_int, c.c_void_p, c.c_char_p, c.POINTER(c.c_char_p),
            c.c_int, c.c_void_p, c.c_uint, c.c_uint, c.POINTER(c.c_void_p)),
        'getCString': (c.c_char_p, String), 'disposeString': (None, String), 'getClangVersion': (String,),
        'getTranslationUnitCursor': (Cursor, c.c_void_p), 'visitChildren': (c.c_uint, Cursor, visitor, c.c_void_p),
        'getCursorSpelling': (String, Cursor), 'getCursorUSR': (String, Cursor),
        'getCursorKindSpelling': (String, c.c_int), 'getCursorReferenced': (Cursor, Cursor),
        'getCanonicalCursor': (Cursor, Cursor), 'getCursorDefinition': (Cursor, Cursor),
        'Cursor_isNull': (c.c_int, Cursor), 'isCursorDefinition': (c.c_uint, Cursor),
        'getCursorLinkage': (c.c_int, Cursor), 'getCursorLanguage': (c.c_int, Cursor),
        'Cursor_getMangling': (String, Cursor), 'getCursorLocation': (Location, Cursor),
        'getSpellingLocation': (None, Location, c.POINTER(c.c_void_p), c.POINTER(c.c_uint),
                                c.POINTER(c.c_uint), c.POINTER(c.c_uint)),
        'getExpansionLocation': (None, Location, c.POINTER(c.c_void_p), c.POINTER(c.c_uint),
                                 c.POINTER(c.c_uint), c.POINTER(c.c_uint)),
        'getFileName': (String, c.c_void_p), 'getCursorType': (Type, Cursor),
        'getCanonicalType': (Type, Type), 'getTypeSpelling': (String, Type),
        'getTypeKindSpelling': (String, c.c_int), 'isConstQualifiedType': (c.c_uint, Type),
        'isVolatileQualifiedType': (c.c_uint, Type), 'isRestrictQualifiedType': (c.c_uint, Type),
        'getPointeeType': (Type, Type), 'getResultType': (Type, Type),
        'getNumArgTypes': (c.c_int, Type), 'getArgType': (Type, Type, c.c_uint),
        'isFunctionTypeVariadic': (c.c_uint, Type), 'getFunctionTypeCallingConv': (c.c_int, Type),
        'getTypeDeclaration': (Cursor, Type), 'Type_getSizeOf': (c.c_longlong, Type),
        'Type_getAlignOf': (c.c_longlong, Type), 'Cursor_getNumArguments': (c.c_int, Cursor),
        'Cursor_getArgument': (Cursor, Cursor, c.c_uint),
        'getNumDiagnostics': (c.c_uint, c.c_void_p), 'getDiagnostic': (c.c_void_p, c.c_void_p, c.c_uint),
        'getDiagnosticSeverity': (c.c_int, c.c_void_p), 'getDiagnosticSpelling': (String, c.c_void_p),
        'disposeDiagnostic': (None, c.c_void_p), 'getInclusions': (None, c.c_void_p, inclusion, c.c_void_p)}
    for name, (result, *arguments) in signatures.items():
        function = getattr(lib, 'clang_' + name)
        function.restype, function.argtypes = result, arguments
        setattr(lib, name, function)

    class Backend:
        def text(self, value):
            try:
                raw = lib.getCString(value) or b''
                require(len(raw) <= 8192, 'CIndex string bound')
                return raw.decode('utf-8')
            finally:
                lib.disposeString(value)

        def children(self, cursor, recursive=False):
            children, errors = [], []
            @visitor
            def visit(child, parent, data):
                try:
                    require(len(children) < 16384, 'CIndex child bound')
                    children.append(child)
                    return 2 if recursive else 1
                except BaseException as error:
                    errors.append(error)
                    return 0
            lib.visitChildren(cursor, visit, None)
            if errors:
                raise errors[0]
            return children

        def location(self, cursor):
            result = {}
            for name, function in (('spelling', lib.getSpellingLocation), ('expansion', lib.getExpansionLocation)):
                file, line, column, offset = c.c_void_p(), c.c_uint(), c.c_uint(), c.c_uint()
                function(lib.getCursorLocation(cursor), c.byref(file), c.byref(line), c.byref(column), c.byref(offset))
                result[name] = {'file': self.text(lib.getFileName(file)) if file else None,
                                'line': line.value, 'column': column.value, 'offset': offset.value}
            return result

        def qualifiers(self, type_):
            return {name: bool(function(type_)) for name, function in (
                ('const', lib.isConstQualifiedType), ('volatile', lib.isVolatileQualifiedType),
                ('restrict', lib.isRestrictQualifiedType))}

        def cursor(self, cursor):
            if lib.Cursor_isNull(cursor):
                return None
            result = {'name': self.text(lib.getCursorSpelling(cursor)),
                      'kind': self.text(lib.getCursorKindSpelling(cursor.kind)),
                      'usr': self.text(lib.getCursorUSR(cursor)), 'location': self.location(cursor),
                      'linkage_kind': lib.getCursorLinkage(cursor), 'language_kind': lib.getCursorLanguage(cursor),
                      'mangling': self.text(lib.Cursor_getMangling(cursor)),
                      'is_definition': bool(lib.isCursorDefinition(cursor)), 'parameters': None}
            if cursor.kind == 8:  # CXCursor_FunctionDecl, not a printed-name match.
                count = lib.Cursor_getNumArguments(cursor)
                require(0 <= count <= 32, 'CIndex declared parameter bound')
                result['parameters'] = []
                for index in range(count):
                    parameter = lib.Cursor_getArgument(cursor, index)
                    require(parameter.kind == 10, 'CIndex parameter declaration missing')
                    result['parameters'].append({'name': self.text(lib.getCursorSpelling(parameter)),
                        'location': self.location(parameter), 'type': self.type(lib.getCursorType(parameter))})
            return result

        def type(self, original, depth=0):
            require(depth < 12, 'CIndex type depth')
            value = lib.getCanonicalType(original)
            kind = self.text(lib.getTypeKindSpelling(value.kind))
            result = {'kind': kind, 'spelling': self.text(lib.getTypeSpelling(original)),
                      'canonical_spelling': self.text(lib.getTypeSpelling(value)),
                      'qualifiers': self.qualifiers(original), 'canonical_qualifiers': self.qualifiers(value),
                      'size': None, 'alignment': None, 'detail': None}
            if kind == 'Pointer':
                result['detail'] = {'pointee': self.type(lib.getPointeeType(value), depth + 1)}
            elif kind == 'FunctionProto':
                count = lib.getNumArgTypes(value)
                require(0 <= count <= 32, 'CIndex type parameter bound')
                result['detail'] = {'result': self.type(lib.getResultType(value), depth + 1),
                    'parameters': [self.type(lib.getArgType(value, i), depth + 1) for i in range(count)],
                    'variadic': bool(lib.isFunctionTypeVariadic(value)),
                    'calling_convention': lib.getFunctionTypeCallingConv(value)}
            elif kind in ('Record', 'Enum'):
                result['detail'] = {'declaration': self.cursor(lib.getCanonicalCursor(lib.getTypeDeclaration(value)))}
            elif kind not in DECLARATION_TYPES:
                result['detail'] = {'unsupported': True}
            if kind not in ('Void', 'FunctionProto'):
                result.update(size=lib.Type_getSizeOf(value), alignment=lib.Type_getAlignOf(value))
            return result

        def observe(self, argv, requests):
            index, unit = lib.createIndex(0, 0), c.c_void_p()
            require(bool(index), 'CIndex index unavailable')
            try:
                arguments = (c.c_char_p * len(argv))(*(arg.encode('utf-8') for arg in argv))
                status = lib.parseTranslationUnit2FullArgv(index, None, arguments, len(argv), None, 0, 0, c.byref(unit))
                require(status == 0 and unit, 'CIndex translation unit unavailable')
                diagnostics = []
                require(lib.getNumDiagnostics(unit) <= 128, 'CIndex diagnostic bound')
                for i in range(lib.getNumDiagnostics(unit)):
                    diagnostic = lib.getDiagnostic(unit, i)
                    try:
                        raw = self.text(lib.getDiagnosticSpelling(diagnostic)).encode('utf-8')
                        diagnostics.append({'severity': lib.getDiagnosticSeverity(diagnostic),
                                            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                    finally:
                        lib.disposeDiagnostic(diagnostic)
                nodes = self.children(lib.getTranslationUnitCursor(unit))
                rows = []
                for request in requests:
                    symbol = request['symbol']
                    typedefs = [node for node in nodes if node.kind == 20 and
                                self.text(lib.getCursorSpelling(node)) == 'cs_expected_' + symbol]
                    variables = [node for node in nodes if node.kind == 9 and
                                 self.text(lib.getCursorSpelling(node)) == 'cs_native_' + symbol]
                    require(len(typedefs) <= 1 and len(variables) <= 1, 'duplicate CIndex request declaration')
                    targets = []
                    for variable in variables:
                        for child in self.children(variable, recursive=True):
                            if child.kind == 101:  # CXCursor_DeclRefExpr
                                target = lib.getCursorReferenced(child)
                                targets.append({'reference': self.cursor(target),
                                    'canonical': self.cursor(lib.getCanonicalCursor(target)),
                                    'definition': self.cursor(lib.getCursorDefinition(target)),
                                    'type': self.type(lib.getCursorType(target))})
                    rows.append({'id': request['id'], 'symbol': symbol,
                                 'expected_type': self.type(lib.getCursorType(typedefs[0])) if typedefs else None,
                                 'variable_location': self.location(variables[0]) if variables else None,
                                 'targets': targets})
                included, errors = set(), []
                @inclusion
                def include(file, stack, length, data):
                    try:
                        included.add(self.text(lib.getFileName(file)))
                        require(len(included) <= MAX_HEADERS, 'CIndex include bound')
                    except BaseException as error:
                        errors.append(error)
                lib.getInclusions(unit, include, None)
                if errors:
                    raise errors[0]
                return {'parse_status': status, 'library_version': self.text(lib.getClangVersion()),
                        'diagnostics': diagnostics, 'requests': rows, 'inclusions': sorted(included),
                        'entry': [self.cursor(node) for node in nodes if node.kind == 8 and
                                  self.text(lib.getCursorSpelling(node)) == 'main']}
            finally:
                if unit:
                    lib.disposeTranslationUnit(unit)
                lib.disposeIndex(index)
    return Backend()


def declaration_model(root):
    from product_profiles import parse_json
    path = Path(root) / SOURCE_FILES['api_models_sha256']
    require(not path.is_symlink() and path.stat().st_size <= MAX_OUTPUT, 'declaration model file')
    raw = path.read_bytes()
    model = parse_json(raw.decode('utf-8'))
    declaration_coverage(model)
    return model, hashlib.sha256(raw).hexdigest()


def declaration_streams(command):
    return {'argv': command['argv'], 'exit_code': command['exit_code'],
            **{key: {'bytes': len(command[key].encode('utf-8')),
                     'sha256': hashlib.sha256(command[key].encode('utf-8')).hexdigest()}
               for key in ('stdout', 'stderr')}}


def declaration_preprocessor_command(compiler, system, metadata, source):
    argv = declaration_command(compiler, system, metadata, source)
    return argv[:-2] + ['-dM', '-E', source]


def declaration_macro_projection(stdout):
    require(type(stdout) is str and len(stdout.encode('utf-8')) <= MAX_OUTPUT and '\x00' not in stdout,
            'declaration macro output')
    selected, seen = dict.fromkeys(DECLARATION_MACROS), set()
    for line in stdout.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'#define ([A-Za-z_][A-Za-z_0-9]*)(.*)', line)
        require(match is not None, 'declaration macro definition')
        name, suffix = match.groups()
        require(not suffix or suffix[0].isspace() or suffix[0] == '(', 'declaration macro separator')
        if name in selected:
            require(name not in seen and not suffix.startswith('('), 'ambiguous selected declaration macro')
            seen.add(name)
            selected[name] = suffix.strip()
    return selected


def capture_declaration_preprocessor(argv):
    """Later preprocessing failure is retained separately from earlier syntax RED."""
    failure = None
    try:
        result = subprocess.run(argv, env=checked_environment(os.environ), capture_output=True, timeout=30, check=False)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
        if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
            failure = 'OUTPUT_LIMIT'
        elif code != 0:
            failure = 'PROCESS_FAILED'
        else:
            try:
                command = {'argv': list(argv), 'exit_code': code,
                           'stdout': stdout.decode('utf-8'), 'stderr': stderr.decode('utf-8')}
                validate_command(command)
                require(not command['stderr'], 'declaration macro diagnostics')
                selected = declaration_macro_projection(command['stdout'])
                return {'argv': list(argv), 'command': command, 'failure': None, 'selected_macros': selected}
            except (ValueError, TypeError, KeyError):
                failure = 'INVALID_RESULT'
    except subprocess.TimeoutExpired as error:
        failure, stdout, stderr, code = 'TIMEOUT', error.stdout or b'', error.stderr or b'', None
    except OSError:
        failure, stdout, stderr, code = 'START_FAILED', b'', b'', None
    return {'argv': list(argv), 'command': None, 'selected_macros': None,
            'failure': {'kind': failure, 'exit_code': code,
                        **{key: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                           for key, raw in (('stdout', stdout), ('stderr', stderr))}}}


def validate_declaration_preprocessor(value, argv):
    fields(value, 'argv command failure selected_macros', 'declaration preprocessor')
    require(value['argv'] == argv, 'declaration preprocessor command identity')
    failure = value['failure']
    if failure is not None:
        require(value['command'] is None and value['selected_macros'] is None, 'failed declaration preprocessing')
        fields(failure, 'kind exit_code stdout stderr', 'declaration preprocessor failure')
        kind, code = failure['kind'], failure['exit_code']
        require(kind in ('TIMEOUT', 'START_FAILED', 'PROCESS_FAILED', 'OUTPUT_LIMIT', 'INVALID_RESULT')
                and (code is None or type(code) is int)
                and (code is None) == (kind in ('TIMEOUT', 'START_FAILED'))
                and (kind != 'PROCESS_FAILED' or code != 0)
                and (kind != 'INVALID_RESULT' or code == 0), 'declaration preprocessor failure outcome')
        for key in ('stdout', 'stderr'):
            item = failure[key]
            fields(item, 'bytes sha256', 'declaration preprocessor stream')
            require(type(item['bytes']) is int and item['bytes'] >= 0 and digest(item['sha256'])
                    and (item['bytes'] != 0 or item['sha256'] == hashlib.sha256(b'').hexdigest()),
                    'declaration preprocessor stream identity')
        require(kind != 'START_FAILED' or all(failure[key]['bytes'] == 0 for key in ('stdout', 'stderr')),
                'declaration preprocessor startup streams')
        require(kind != 'OUTPUT_LIMIT' or any(failure[key]['bytes'] > MAX_OUTPUT for key in ('stdout', 'stderr')),
                'declaration preprocessor output limit')
        return ['PREPROCESSOR_FAILED']
    command = value['command']
    validate_command(command)
    require(command['argv'] == argv and command['stderr'] == '', 'declaration preprocessor observed command')
    selected = declaration_macro_projection(command['stdout'])
    require(value['selected_macros'] == selected, 'declaration macro projection mismatch')
    return ([] if selected['_POSIX_C_SOURCE'] == '200809L' and selected['__STRICT_ANSI__'] == '1'
            else ['VISIBILITY_NOT_OBSERVED'])


def validate_declaration_document(value, model, model_sha256):
    """Pure consistency checking. Never opens native paths, loads a library or runs argv."""
    require(type(value) is dict, 'declaration observation object')
    version2 = value.get('schema') == 'codeskeptic-native-declarations/v2'
    fields(value, 'schema native_identity environment producer_files library probe metadata_only '
           'native_qualified task_ready product_qualified' + (' profile' if version2 else ''), 'declaration observation')
    require(value['schema'] in ('codeskeptic-native-declarations/v1', 'codeskeptic-native-declarations/v2')
            and value['metadata_only'] is True
            and all(value[key] is False for key in ('native_qualified', 'task_ready', 'product_qualified')),
            'declaration observation cannot claim qualification')
    native = value['native_identity']
    validate_case_selection(native, value['environment'])
    require(digest(model_sha256) and native['source']['api_models_sha256'] == model_sha256,
            'declaration model bytes mismatch')
    fields(value['producer_files'], ' '.join(DECLARATION_PRODUCERS), 'declaration producers')
    require(all(digest(sha) for sha in value['producer_files'].values()), 'declaration producer digest')
    system = native['platform']['system']
    profile = None
    if version2:
        fields(value['profile'], 'id language feature_macros', 'declaration profile')
        profile = value['profile']['id']
        require(profile is not None and value['profile'] == declaration_profile(profile, system),
                'declaration profile descriptor')
    flavor = 'windows' if system == 'Windows' else 'posix'
    path_type = PureWindowsPath if flavor == 'windows' else PurePosixPath
    validate_file(value['library'], flavor)
    require(value['library']['path'] == value['library']['resolved_path'], 'physical declaration library')
    probe = value['probe']
    fields(probe, 'input dependency headers syntax cindex backend_failure' + (' preprocessor' if version2 else ''),
           'declaration probe')
    validate_file(probe['input'], flavor)
    source = declaration_source(model, system, profile).encode('utf-8')
    require(probe['input']['sha256'] == hashlib.sha256(source).hexdigest()
            and probe['input']['bytes'] == len(source), 'declaration fixed source mismatch')
    input_path = probe['input']['path']
    compiler, metadata = native['tools']['clang'], native['platform']['metadata']
    dependency = probe['dependency']
    validate_command(dependency)
    require(dependency['argv'] == declaration_command(compiler, system, metadata, input_path, True)
            and dependency['stderr'] == '', 'declaration dependency command')
    paths = dependency_paths(dependency['stdout'], flavor)
    headers = probe['headers']
    require(type(headers) is list and 0 < len(headers) <= MAX_HEADERS, 'declaration header count')
    for header in headers:
        validate_file(header, flavor)
    require([h['path'] for h in headers] == paths and sum(h['bytes'] for h in headers) <= MAX_HEADER_BYTES,
            'declaration header closure')
    by_path = {path_type(h['path']): h for h in headers}
    require(by_path.get(path_type(input_path)) == probe['input'], 'declaration source absent from closure')
    bindings = {}
    for record in [value['library'], probe['input'], *headers,
                   *[tool['file'] for tool in native['tools'].values()],
                   *[h for p in native['probes'].values() for h in p['headers']]]:
        path, resolved = path_type(record['path']), path_type(record['resolved_path'])
        require('..' not in resolved.parts, 'noncanonical declaration identity')
        entry = (resolved, record['bytes'], record['sha256'])
        for name in (path, resolved):
            require(name not in bindings or bindings[name] == entry, 'declaration identity disagreement')
            bindings[name] = entry
    syntax = probe['syntax']
    fields(syntax, 'argv exit_code stdout stderr', 'declaration syntax command')
    require(syntax['argv'] == declaration_command(compiler, system, metadata, input_path)
            and type(syntax['exit_code']) is int and syntax['exit_code'] in (0, 1), 'declaration syntax identity')
    for stream in ('stdout', 'stderr'):
        item = syntax[stream]
        fields(item, 'bytes sha256', 'declaration stream')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_OUTPUT and digest(item['sha256'])
                and (item['bytes'] != 0 or item['sha256'] == hashlib.sha256(b'').hexdigest()),
                'declaration stream identity')
    require(syntax['stdout']['bytes'] == 0, 'syntax-only declaration stdout')
    visibility_issues = (validate_declaration_preprocessor(probe['preprocessor'],
                         declaration_preprocessor_command(compiler, system, metadata, input_path)) if version2 else [])
    observed = probe['cindex']
    failure = probe['backend_failure']
    if failure is not None:
        fields(failure, 'kind exit_code stdout stderr', 'declaration backend failure')
        require(observed is None and failure['kind'] in ('TIMEOUT', 'START_FAILED', 'PROCESS_FAILED', 'OUTPUT_LIMIT', 'INVALID_RESULT')
                and (failure['exit_code'] is None or type(failure['exit_code']) is int), 'declaration backend outcome')
        require((failure['exit_code'] is None) == (failure['kind'] in ('TIMEOUT', 'START_FAILED'))
                and (failure['kind'] != 'PROCESS_FAILED' or failure['exit_code'] != 0), 'declaration backend exit')
        for key in ('stdout', 'stderr'):
            fields(failure[key], 'bytes sha256', 'declaration backend stream')
            require(type(failure[key]['bytes']) is int and failure[key]['bytes'] >= 0
                    and digest(failure[key]['sha256']), 'declaration backend stream values')
        issues = ['BACKEND_FAILED'] + (['SYNTAX_FAILED'] if syntax['exit_code'] else [])
        result = {'metadata_only': True, 'syntax_pass': False, 'requests': [
                    {'id': row['id'], 'issues': issues, 'state': 'INCOMPLETE'} for row in declaration_requests(model, system)],
                'coverage': declaration_coverage(model), 'local_native_bytes_verified': False,
                'native_qualified': False, 'task_ready': False, 'product_qualified': False}
    else:
        result = validate_declaration_observation(observed, model, native, probe)
    if version2:
        result.update(profile_id=profile, visibility_pass=not visibility_issues)
        if visibility_issues:
            result['syntax_pass'] = False
            for row in result['requests']:
                row['issues'] = row['issues'] + visibility_issues
                row['state'] = 'INCOMPLETE'
    return result


def validate_declaration_observation(observed, model, native, probe):
    """Validate only child-owned output against the separately checked capture inputs."""
    system = native['platform']['system']
    path_type = PureWindowsPath if system == 'Windows' else PurePosixPath
    by_path = {path_type(h['path']): h for h in probe['headers']}
    input_path, syntax, compiler = probe['input']['path'], probe['syntax'], native['tools']['clang']
    fields(observed, 'parse_status library_version diagnostics requests inclusions entry', 'CIndex observation')
    require(type(observed['parse_status']) is int and observed['parse_status'] == 0
            and nonempty(observed['library_version']) and len(observed['library_version'].encode('utf-8')) <= 8192,
            'CIndex parser observation')
    require(type(observed['inclusions']) is list and observed['inclusions'] == sorted(set(observed['inclusions']))
            and {path_type(path) for path in observed['inclusions']} == set(by_path), 'CIndex include closure')
    diagnostics = observed['diagnostics']
    require(type(diagnostics) is list and len(diagnostics) <= 128, 'CIndex diagnostic count')
    for diagnostic in diagnostics:
        fields(diagnostic, 'severity bytes sha256', 'CIndex diagnostic')
        require(type(diagnostic['severity']) is int and 0 <= diagnostic['severity'] <= 4
                and type(diagnostic['bytes']) is int and 0 <= diagnostic['bytes'] <= 8192
                and digest(diagnostic['sha256']), 'CIndex diagnostic values')

    nodes = [0]
    def text(value, empty=False):
        require(type(value) is str and '\x00' not in value and len(value.encode('utf-8')) <= 8192
                and (empty or bool(value)), 'CIndex text')

    def location(value):
        fields(value, 'spelling expansion', 'CIndex location')
        for position in value.values():
            fields(position, 'file line column offset', 'CIndex physical position')
            require(all(type(position[k]) is int and position[k] >= 0 for k in ('line', 'column', 'offset')),
                    'CIndex position values')
            if position['file'] is None:
                require(all(position[k] == 0 for k in ('line', 'column', 'offset')), 'CIndex absent file position')
            else:
                text(position['file'])
                header = by_path.get(path_type(position['file']))
                require(header is not None and position['line'] > 0 and position['column'] > 0
                        and position['offset'] <= header['bytes'], 'CIndex location outside hashed closure')

    def qualifiers(value):
        fields(value, 'const volatile restrict', 'CIndex qualifiers')
        require(all(type(item) is bool for item in value.values()), 'CIndex qualifier flags')

    def cursor(value, depth=0):
        if value is None:
            return
        require(depth < 12, 'CIndex declaration depth')
        fields(value, 'name kind usr location linkage_kind language_kind mangling is_definition parameters', 'CIndex cursor')
        for key in ('name', 'kind', 'usr', 'mangling'):
            text(value[key], empty=key != 'kind')
        location(value['location'])
        require(type(value['is_definition']) is bool and type(value['linkage_kind']) is int
                and 0 <= value['linkage_kind'] <= 4 and type(value['language_kind']) is int
                and 0 <= value['language_kind'] <= 3, 'CIndex cursor flags')
        if value['kind'] == 'FunctionDecl':
            require(type(value['parameters']) is list and len(value['parameters']) <= 32, 'CIndex declared parameters')
            for parameter in value['parameters']:
                fields(parameter, 'name location type', 'CIndex parameter')
                text(parameter['name'], empty=True)
                location(parameter['location'])
                type_record(parameter['type'], depth + 1)
        else:
            require(value['parameters'] is None, 'non-function CIndex parameters')

    def type_record(value, depth=0):
        nodes[0] += 1
        require(depth < 12 and nodes[0] <= 16384, 'CIndex type metadata budget')
        fields(value, 'kind spelling canonical_spelling qualifiers canonical_qualifiers size alignment detail', 'CIndex type')
        for key in ('kind', 'spelling', 'canonical_spelling'):
            text(value[key], empty=key != 'kind')
        qualifiers(value['qualifiers'])
        qualifiers(value['canonical_qualifiers'])
        kind, detail = value['kind'], value['detail']
        if kind in ('Void', 'FunctionProto'):
            require(value['size'] is None and value['alignment'] is None, 'unsized CIndex type')
        else:
            require(all(type(value[k]) is int and -10 <= value[k] <= MAX_FILE for k in ('size', 'alignment')),
                    'CIndex type layout bounds')
        if kind == 'Pointer':
            fields(detail, 'pointee', 'CIndex pointer')
            type_record(detail['pointee'], depth + 1)
        elif kind == 'FunctionProto':
            fields(detail, 'result parameters variadic calling_convention', 'CIndex function type')
            require(type(detail['parameters']) is list and len(detail['parameters']) <= 32
                    and type(detail['variadic']) is bool and type(detail['calling_convention']) is int
                    and 0 <= detail['calling_convention'] <= 200, 'CIndex function type values')
            type_record(detail['result'], depth + 1)
            for parameter in detail['parameters']:
                type_record(parameter, depth + 1)
        elif kind in ('Record', 'Enum'):
            fields(detail, 'declaration', 'CIndex named type')
            cursor(detail['declaration'], depth + 1)
        elif kind in DECLARATION_TYPES:
            require(detail is None, 'CIndex primitive detail')
        else:
            require(detail == {'unsupported': True}, 'unknown CIndex type must remain unsupported')

    requests = declaration_requests(model, system)
    require(type(observed['requests']) is list and len(observed['requests']) == len(requests), 'CIndex request inventory')
    syntax_pass = syntax['exit_code'] == 0 and not any(d['severity'] >= 3 for d in diagnostics)
    driver_version = re.search(r'clang version (\d+\.\d+\.\d+)', compiler['version']['stdout'])
    parser_version = re.search(r'clang version (\d+\.\d+\.\d+)', observed['library_version'])
    versions_match = (driver_version is not None and parser_version is not None
                      and driver_version.group(1) == parser_version.group(1))
    results = []
    for actual, expected in zip(observed['requests'], requests):
        fields(actual, 'id symbol expected_type variable_location targets', 'CIndex request')
        require((actual['id'], actual['symbol']) == (expected['id'], expected['symbol']), 'CIndex request identity')
        issues = [] if syntax_pass else ['SYNTAX_FAILED']
        if not versions_match:
            issues.append('PARSER_DRIVER_VERSION_MISMATCH')
        if actual['variable_location'] is not None:
            location(actual['variable_location'])
            require(all(p['file'] == input_path for p in actual['variable_location'].values()), 'CIndex fixed variable location')
        if actual['expected_type'] is not None:
            type_record(actual['expected_type'])
        require(type(actual['targets']) is list and len(actual['targets']) <= 8, 'CIndex reference count')
        if not actual['targets'] or actual['variable_location'] is None:
            issues.append('MISSING_REFERENCE')
        if actual['expected_type'] is None or actual['expected_type']['kind'] != 'Pointer':
            issues.append('MISSING_EXPECTED_TYPE')
        for target in actual['targets']:
            fields(target, 'reference canonical definition type', 'CIndex reference target')
            for key in ('reference', 'canonical', 'definition'):
                cursor(target[key])
            type_record(target['type'])
            reference, canonical_cursor = target['reference'], target['canonical']
            if any(item is None or item['kind'] != 'FunctionDecl' or item['name'] != expected['symbol']
                   for item in (reference, canonical_cursor)):
                issues.append('REQUEST_TARGET_MISMATCH')
            if reference and canonical_cursor and reference['usr'] != canonical_cursor['usr']:
                issues.append('CANONICAL_IDENTITY_MISMATCH')
            if any(item and (not item['usr'] or item['language_kind'] != 1 or item['linkage_kind'] != 4)
                   for item in (reference, canonical_cursor)):
                issues.append('LINKAGE_NOT_ADJUDICATED')
            if target['definition'] is not None or any(item and item['is_definition'] for item in (reference, canonical_cursor)):
                issues.append('DEFINITION_PRESENT')
            if canonical_cursor:
                positions = canonical_cursor['location']
                if any(p['file'] in (None, input_path) for p in positions.values()):
                    issues.append('MISSING_NATIVE_HEADER')
                if positions['spelling'] != positions['expansion']:
                    issues.append('REDIRECTION_NOT_ADJUDICATED')
            expected_type = actual['expected_type']
            if expected_type and expected_type['kind'] == 'Pointer' and declaration_type_key(
                    expected_type['detail']['pointee']) != declaration_type_key(target['type']):
                issues.append('SIGNATURE_MISMATCH')
            if target['type']['kind'] != 'FunctionProto':
                issues.append('UNSUPPORTED_FUNCTION_TYPE')
            else:
                parameters = target['type']['detail']['parameters']
                for declaration in (reference, canonical_cursor, target['definition']):
                    if declaration and declaration['kind'] == 'FunctionDecl' and (
                            len(declaration['parameters']) != len(parameters) or any(
                                declaration_parameter_key(actual['type']) != declaration_parameter_key(expected)
                                for actual, expected in zip(declaration['parameters'], parameters))):
                        issues.append('DECLARED_PARAMETER_MISMATCH')
            if declaration_type_incomplete(target) or declaration_type_incomplete(expected_type):
                issues.append('UNSUPPORTED_TYPE')
        results.append({'id': expected['id'], 'issues': sorted(set(issues)),
                        'state': 'INCOMPLETE' if issues else 'OBSERVED_UNADJUDICATED'})
    require(type(observed['entry']) is list and len(observed['entry']) <= 1, 'CIndex entry count')
    for entry in observed['entry']:
        cursor(entry)
        require(entry is not None and entry['kind'] == 'FunctionDecl' and entry['name'] == 'main'
                and entry['is_definition'] and all(p['file'] == input_path for p in entry['location'].values()),
                'CIndex actual entry identity')
    return {'metadata_only': True, 'syntax_pass': syntax_pass, 'requests': results,
            'coverage': declaration_coverage(model), 'local_native_bytes_verified': False,
            'native_qualified': False, 'task_ready': False, 'product_qualified': False}


def declaration_worker(config):
    """Private child input is fixed-source metadata, never arbitrary source/flags."""
    require(type(config) is dict, 'declaration worker object')
    selected = 'profile' in config
    fields(config, 'native_identity environment library input' + (' profile' if selected else ''), 'declaration worker')
    profile = None
    if selected:
        fields(config['profile'], 'id language feature_macros', 'declaration worker profile')
        profile = config['profile']['id']
        require(profile is not None and config['profile'] == declaration_profile(profile, platform.system()),
                'declaration worker profile descriptor')
    native, environment = config['native_identity'], config['environment']
    validate_case_selection(native, environment)
    require(environment == case_environment(os.environ, platform.system())
            and native['platform']['system'] == platform.system(), 'declaration worker environment')
    root = Path(__file__).resolve().parents[1]
    require(source_identity(root, native['source']['head']) == native['source'], 'declaration worker source')
    model, sha = declaration_model(root)
    require(sha == native['source']['api_models_sha256'], 'declaration worker model')
    source = declaration_source(model, platform.system(), profile).encode('utf-8')
    input_, library = config['input'], config['library']
    require(file_identity(Path(input_['path'])) == input_ and input_['bytes'] == len(source)
            and input_['sha256'] == hashlib.sha256(source).hexdigest(), 'declaration worker fixed input')
    require(file_identity(Path(library['path'])) == library, 'declaration worker library changed')
    argv = declaration_command(native['tools']['clang'], platform.system(), native['platform']['metadata'], input_['path'])
    result = declaration_backend(library['resolved_path']).observe(argv, declaration_requests(model, platform.system()))
    require(file_identity(Path(library['path'])) == library and file_identity(Path(input_['path'])) == input_,
            'declaration worker bytes changed')
    return result


def run_declaration_worker(config, validate_result):
    """Retain a later extraction failure without discarding earlier syntax RED."""
    from product_profiles import parse_json
    command = [sys.executable, '-B', str(Path(__file__).resolve()), '_declaration-worker']
    failure = None
    try:
        run_ = subprocess.run(command, input=canonical(config).encode('utf-8'),
                              env=checked_environment(os.environ), capture_output=True, timeout=30, check=False)
        stdout, stderr, code = run_.stdout, run_.stderr, run_.returncode
        if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
            failure = 'OUTPUT_LIMIT'
        elif code != 0:
            failure = 'PROCESS_FAILED'
        elif stderr:
            failure = 'INVALID_RESULT'
        else:
            try:
                observed = parse_json(stdout.decode('utf-8'))
                validate_result(observed)
                require(len(canonical(observed).encode('utf-8')) <= MAX_OUTPUT, 'declaration result serialization bound')
                return observed, None
            except (ValueError, TypeError, KeyError, RecursionError):
                failure = 'INVALID_RESULT'
    except subprocess.TimeoutExpired as error:
        failure, stdout, stderr, code = 'TIMEOUT', error.stdout or b'', error.stderr or b'', None
    except OSError:
        failure, stdout, stderr, code = 'START_FAILED', b'', b'', None
    return None, {'kind': failure, 'exit_code': code,
                  'stdout': {'bytes': len(stdout), 'sha256': hashlib.sha256(stdout).hexdigest()},
                  'stderr': {'bytes': len(stderr), 'sha256': hashlib.sha256(stderr).hexdigest()}}


def capture_declarations(args):
    profile = declaration_profile(getattr(args, 'declaration_profile', None), platform.system())
    root = args.root.resolve(strict=True)
    environment = case_environment(os.environ, platform.system())
    with selected_case_environment(environment):
        native = capture(args)
        resolve_case_resources(native)
        validate_case_selection(native, environment)
        model, model_sha = declaration_model(root)
        library = file_identity(args.libclang)
        require(library['path'] == library['resolved_path'], 'select physical libclang explicitly')
        producers = {}
        for relative in DECLARATION_PRODUCERS:
            actual = file_identity(root / relative)
            committed = run(['git', 'cat-file', 'blob', args.source_sha + ':' + relative], cwd=root)['stdout']
            require(actual['sha256'] == hashlib.sha256(committed.encode('utf-8')).hexdigest(), 'declaration producer differs from commit')
            producers[relative] = actual['sha256']
        system, compiler = platform.system(), native['tools']['clang']
        with tempfile.TemporaryDirectory(prefix='codeskeptic-declarations-', dir=args.output.parent) as directory:
            path = Path(directory).resolve(strict=True) / 'declarations.c'
            with path.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(declaration_source(model, system, None if profile is None else profile['id']))
            input_ = file_identity(path)
            dependency = run(declaration_command(compiler, system, native['platform']['metadata'], str(path), True))
            headers, total = [], 0
            for filename in dependency_paths(dependency['stdout'], 'windows' if system == 'Windows' else 'posix'):
                item = file_identity(Path(filename), maximum=MAX_HEADER_BYTES - total)
                total += item['bytes']
                headers.append(item)
            syntax = declaration_streams(run(declaration_command(compiler, system, native['platform']['metadata'], str(path)), allowed=(0, 1)))
            config = {'native_identity': native, 'environment': environment, 'library': library, 'input': input_}
            value = {'schema': 'codeskeptic-native-declarations/v1', 'native_identity': native,
                     'environment': environment, 'producer_files': producers, 'library': library,
                     'probe': {'input': input_, 'dependency': dependency, 'headers': headers, 'syntax': syntax,
                               'cindex': None, 'backend_failure': None},
                     'metadata_only': True, 'native_qualified': False, 'task_ready': False, 'product_qualified': False}
            if profile is not None:
                config['profile'] = profile
                value.update(schema='codeskeptic-native-declarations/v2', profile=profile)
                value['probe']['preprocessor'] = capture_declaration_preprocessor(
                    declaration_preprocessor_command(compiler, system, native['platform']['metadata'], str(path)))
            observed, failure = run_declaration_worker(config, lambda observed:
                validate_declaration_observation(observed, model, native, value['probe']))
            value['probe'].update(cindex=observed, backend_failure=failure)
            validate_declaration_document(value, model, model_sha)
            for record in [library, *headers, *[tool['file'] for tool in native['tools'].values()],
                           *[item for probe in native['probes'].values() for item in probe['headers']]]:
                require(file_identity(Path(record['path'])) == record, 'declaration capture bytes changed')
            require(source_identity(root, args.source_sha) == native['source'] and declaration_model(root)[1] == model_sha
                    and native_metadata(system) == native['platform']['metadata']
                    and all(file_identity(root / name)['sha256'] == sha for name, sha in producers.items()),
                    'declaration capture source/platform changed')
        return value


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ['_declaration-worker']:
        try:
            from product_profiles import parse_json
            raw = sys.stdin.buffer.read(MAX_OUTPUT + 1)
            require(len(raw) <= MAX_OUTPUT, 'declaration worker input bound')
            output = canonical(declaration_worker(parse_json(raw.decode('utf-8'))))
            require(len(output.encode('utf-8')) <= MAX_OUTPUT, 'declaration worker output bound')
            print(output, end='')
            return 0
        except (ValueError, OSError, KeyError, TypeError, RuntimeError, AttributeError) as error:
            print('DECLARATION_WORKER_INVALID ' + case_observation_failure(error), file=sys.stderr)
            return 2
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='structural metadata check, not native byte verification')
    check.add_argument('input', type=Path)
    case_check = commands.add_parser('check-case', help='structural case metadata check, not remote attestation')
    case_check.add_argument('input', type=Path)
    declarations_check = commands.add_parser('check-declarations', help='pure declaration metadata check; never executes retained commands')
    declarations_check.add_argument('input', type=Path)
    declarations_check.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    collect = commands.add_parser('capture', help='installed-tool metadata only; writes one new external JSON')
    collect.add_argument('--root', type=Path, required=True)
    collect.add_argument('--source-sha', required=True)
    for role in TOOL_ROLES:
        collect.add_argument('--' + role, type=Path, required=True)
    collect.add_argument('--output', type=Path, required=True)
    case_collect = commands.add_parser('capture-case', help='opt-in pinned case syntax/ABI checks; new metadata JSON only')
    case_collect.add_argument('--root', type=Path, required=True)
    case_collect.add_argument('--source-sha', required=True)
    case_collect.add_argument('--external-root', type=Path, required=True)
    case_collect.add_argument('--output', type=Path, required=True)
    for role in TOOL_ROLES:
        case_collect.add_argument('--' + role, type=Path, required=True)
    declarations = commands.add_parser('capture-declarations', help='opt-in fixed declaration/signature observation; errors remain unqualified')
    declarations.add_argument('--root', type=Path, required=True)
    declarations.add_argument('--source-sha', required=True)
    declarations.add_argument('--libclang', type=Path, required=True)
    declarations.add_argument('--declaration-profile', choices=(POSIX_DECLARATION_PROFILE,),
                              help='explicit separate POSIX visibility v2 observation; default preserves legacy v1')
    declarations.add_argument('--output', type=Path, required=True)
    for role in TOOL_ROLES:
        declarations.add_argument('--' + role, type=Path, required=True)
    diagnostic = commands.add_parser('diagnose-windows', help='post-attempt startup/module/query observations, not a retry')
    diagnostic.add_argument('--root', type=Path, required=True)
    diagnostic.add_argument('--source-sha', required=True)
    diagnostic.add_argument('--output', type=Path, required=True)
    diagnostic_check = commands.add_parser('check-windows-diagnostic', help='structural diagnostic check only')
    diagnostic_check.add_argument('input', type=Path)
    stages = commands.add_parser('diagnose-windows-stages', help='one post-attempt process with clocked stages')
    stages.add_argument('--root', type=Path, required=True)
    stages.add_argument('--source-sha', required=True)
    stages.add_argument('--output', type=Path, required=True)
    stages_check = commands.add_parser('check-windows-stages', help='structural staged diagnostic check only')
    stages_check.add_argument('input', type=Path)
    context = commands.add_parser('diagnose-windows-context', help='staged observation then separate read-only policy probe')
    context.add_argument('--root', type=Path, required=True)
    context.add_argument('--source-sha', required=True)
    context.add_argument('--output', type=Path, required=True)
    context_check = commands.add_parser('check-windows-context', help='structural context diagnostic check only')
    context_check.add_argument('input', type=Path)
    args = parser.parse_args(argv)
    try:
        validator = validate_case_document if args.command in ('check-case', 'capture-case') else validate_document
        if args.command in ('diagnose-windows', 'check-windows-diagnostic'):
            validator = validate_windows_diagnostic
        if args.command in ('diagnose-windows-stages', 'check-windows-stages'):
            validator = validate_windows_stages
        if args.command in ('diagnose-windows-context', 'check-windows-context'):
            validator = validate_windows_context
        if args.command in ('capture-declarations', 'check-declarations'):
            validator = lambda value: validate_declaration_document(value, *declaration_model(args.root))
        if args.command in ('check', 'check-case', 'check-windows-diagnostic', 'check-windows-stages', 'check-windows-context', 'check-declarations'):
            require(not args.input.is_symlink() and args.input.resolve() == args.input
                    and args.input.is_file() and args.input.stat().st_size <= 16 * MAX_OUTPUT,
                    'metadata input must be a bounded absolute regular file')
            if args.command in ('check-case', 'check-windows-diagnostic', 'check-windows-stages', 'check-windows-context', 'check-declarations'):
                from product_profiles import parse_json
                result = validator(parse_json(args.input.read_text(encoding='utf-8')))
            else:
                result = validator(json.loads(args.input.read_text(encoding='utf-8')))
        else:
            root = args.root.resolve(strict=True)
            require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent
                    and not args.output.exists() and not args.output.is_symlink()
                    and not args.output.is_relative_to(root), 'output must be new and outside the checkout')
            collector = {'capture-case': capture_case, 'capture': capture,
                         'capture-declarations': capture_declarations,
                         'diagnose-windows': capture_windows_diagnostic,
                         'diagnose-windows-stages': capture_windows_stages,
                         'diagnose-windows-context': capture_windows_context}[args.command]
            value = collector(args)
            with args.output.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(canonical(value))
            result = {**validator(value), 'output_sha256': file_identity(args.output)['sha256']}
        print(canonical(result), end='')
        return 2 if args.command == 'capture-declarations' and not result['syntax_pass'] else 0
    except (IdentityError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        private = args.command in ('check-case', 'capture-case', 'diagnose-windows', 'check-windows-diagnostic',
                                   'diagnose-windows-stages', 'check-windows-stages',
                                   'diagnose-windows-context', 'check-windows-context',
                                   'capture-declarations', 'check-declarations')
        print('IDENTITY_INVALID ' + (case_observation_failure(error) if private else str(error)), file=sys.stderr)
        if args.command == 'capture-case':
            print('CASE_FAILURE_KIND ' + case_failure_kind(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
