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
CASE_SOURCE_FILES = ('scripts/product_profiles.py', 'scripts/product_quality.py',
                     'tests/product_corpus/candidates/gcc-mixed-storage-binding.json',
                     'tests/product_corpus/candidates/gcc-mixed-storage-selection.json')


def case_environment(environment, system):
    """Only this opt-in capture uses a minimal environment, never ambient secrets."""
    require(system in CASE_TARGETS, 'case platform')
    if system == 'Windows':
        folded = {}
        for key, value in environment.items():
            require(key.upper() not in folded or folded[key.upper()] == value, 'conflicting environment keys')
            folded[key.upper()] = value
        environment = {key: folded[key.upper()] for key in (*CASE_ENV_KEYS, *FORBIDDEN_ENV,
                       'LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH') if key.upper() in folded}
    checked_environment(environment)
    require(not any(environment.get(key) for key in
                    ('LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH')),
            'case loader/library override')
    result = {key: environment[key] for key in CASE_ENV_KEYS if key in environment}
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check', help='structural metadata check, not native byte verification')
    check.add_argument('input', type=Path)
    case_check = commands.add_parser('check-case', help='structural case metadata check, not remote attestation')
    case_check.add_argument('input', type=Path)
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
    args = parser.parse_args(argv)
    try:
        validator = validate_case_document if args.command in ('check-case', 'capture-case') else validate_document
        if args.command in ('check', 'check-case'):
            require(not args.input.is_symlink() and args.input.resolve() == args.input
                    and args.input.is_file() and args.input.stat().st_size <= 16 * MAX_OUTPUT,
                    'metadata input must be a bounded absolute regular file')
            if args.command == 'check-case':
                from product_profiles import parse_json
                result = validator(parse_json(args.input.read_text(encoding='utf-8')))
            else:
                result = validator(json.loads(args.input.read_text(encoding='utf-8')))
        else:
            root = args.root.resolve(strict=True)
            require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent
                    and not args.output.exists() and not args.output.is_symlink()
                    and not args.output.is_relative_to(root), 'output must be new and outside the checkout')
            value = capture_case(args) if args.command == 'capture-case' else capture(args)
            with args.output.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(canonical(value))
            result = {**validator(value), 'output_sha256': file_identity(args.output)['sha256']}
        print(canonical(result), end='')
        return 0
    except (IdentityError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print('IDENTITY_INVALID ' + ('case observation rejected' if args.command in ('check-case', 'capture-case') else str(error)), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
