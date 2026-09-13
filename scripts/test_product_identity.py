#!/usr/bin/env python3
"""Focused metadata tests; no analyzer or native qualification is performed."""
import copy
from contextlib import contextmanager, ExitStack
import hashlib
import io
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import product_identity as identity


class DependencyTests(unittest.TestCase):
    def test_posix_dependencies_include_system_headers_and_escaped_names(self):
        raw = ('identity-probe: /usr/include/a.h ' + '\\' + '\n'
               ' /sdk/with\\ space/b.h /sdk/hash\\#name.h /sdk/dollar$$name.h\n')
        self.assertEqual(identity.dependency_paths(raw, 'posix'),
                         ['/usr/include/a.h', '/sdk/with space/b.h',
                          '/sdk/hash#name.h', '/sdk/dollar$name.h'])

    def test_windows_drive_paths_and_continuations(self):
        raw = 'identity-probe: C:/SDK/a.h \\\r\n C:/Program\\ Files/VC/b.h\r\n'
        self.assertEqual(identity.dependency_paths(raw, 'windows'),
                         ['C:/SDK/a.h', 'C:/Program Files/VC/b.h'])

    def test_clang_native_windows_separators_and_unc_are_literal(self):
        raw = (r'identity-probe: C:\SDK\stdio.h C:\Program\ Files\VC\vector '
               r'\\server\SDK\include\stddef.h' + '\n')
        self.assertEqual(identity.dependency_paths(raw, 'windows'),
                         [r'C:\SDK\stdio.h', r'C:\Program Files\VC\vector',
                          r'\\server\SDK\include\stddef.h'])

    def test_clang_backslash_runs_around_make_metacharacters(self):
        # LLVM 20.1.8 DependencyFile.cpp PrintFilename, not shell escaping:
        # n slashes before space => 2n+1; before # => n+1; otherwise literal.
        for flavor, prefix in (('posix', '/sdk/p'), ('windows', 'C:\\SDK\\p')):
            for count in range(4):
                for character in (' ', '#', '$', 'z'):
                    original = prefix + '\\' * count + character + 'q.h'
                    if character == ' ':
                        encoded = '\\' * (2 * count + 1) + ' '
                    elif character == '#':
                        encoded = '\\' * (count + 1) + '#'
                    else:
                        encoded = '\\' * count + ('$$' if character == '$' else character)
                    raw = 'identity-probe: ' + prefix + encoded + 'q.h\n'
                    with self.subTest(flavor=flavor, count=count, character=character):
                        self.assertEqual(identity.dependency_paths(raw, flavor), [original])

    def test_native_separator_paths_support_both_line_endings(self):
        for ending in ('\n', '\r\n'):
            raw = 'identity-probe: C:\\SDK\\a.h \\' + ending + '  C:\\SDK\\b.h' + ending
            with self.subTest(ending=ending):
                self.assertEqual(identity.dependency_paths(raw, 'windows'),
                                 [r'C:\SDK\a.h', r'C:\SDK\b.h'])

    def test_tab_and_ambiguous_trailing_separator_inputs_are_not_admitted(self):
        for raw in ('identity-probe: /sdk/has\ttab.h\n',
                    'identity-probe: /sdk/tail\\ /sdk/next.h\n',
                    'identity-probe: /sdk/tail\\\\ /sdk/next.h\n',
                    'identity-probe: /sdk/tail\\\n'):
            with self.subTest(raw=raw), self.assertRaises(identity.IdentityError):
                identity.dependency_paths(raw, 'posix')

    def test_wrong_target_relative_missing_and_malformed_dependencies_fail(self):
        for raw in ('other: /sdk/a.h\n', 'identity-probe:',
                    'identity-probe: relative.h\n', 'identity-probe: /a.h\nother: /b.h\n',
                    'identity-probe: /a.h $variable\n', 'identity-probe: /a.h\\',
                    'identity-probe: /a.h\x00\n'):
            with self.subTest(raw=raw), self.assertRaises(identity.IdentityError):
                identity.dependency_paths(raw, 'posix')

    def test_duplicate_dependency_paths_do_not_inflate_inventory(self):
        with self.assertRaises(identity.IdentityError):
            identity.dependency_paths('identity-probe: /a.h /a.h\n', 'posix')

    def test_windows_case_aliases_are_duplicate_dependencies(self):
        with self.assertRaises(identity.IdentityError):
            identity.dependency_paths('identity-probe: C:/SDK/a.h c:/sdk/A.h\n', 'windows')

    def test_dependency_flavor_and_limit_are_enforced(self):
        with self.assertRaises(identity.IdentityError):
            identity.dependency_paths('identity-probe: C:/a.h\n', 'posix')
        with self.assertRaises(identity.IdentityError):
            identity.dependency_paths('identity-probe: /a.h\n', 'invented')
        with self.assertRaises(identity.IdentityError):
            identity.dependency_paths('identity-probe: ' + 'a' * identity.MAX_OUTPUT, 'posix')


class FileIdentityTests(unittest.TestCase):
    def test_selected_header_bytes_and_resolved_identity_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native header.h'
            path.write_bytes(b'int native_function(void);\n')
            result = identity.file_identity(path)
            self.assertEqual(result, {'path': str(path), 'resolved_path': str(path.resolve()),
                                     'bytes': 27, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

    def test_native_sdk_alias_preserves_both_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path, alias = Path(directory) / 'real.h', Path(directory) / 'alias.h'
            path.write_bytes(b'header')
            try:
                alias.symlink_to(path)
            except OSError as error:
                self.skipTest('host does not allow creating this symlink fixture: ' + str(error))
            record = identity.file_identity(alias)
            self.assertEqual(record['path'], str(alias))
            self.assertEqual(record['resolved_path'], str(path.resolve()))
            self.assertEqual(record['sha256'], identity.file_identity(path)['sha256'])

    def test_missing_directory_relative_and_oversized_file_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'a.h'
            for invalid in (path, Path(directory), Path('relative.h')):
                with self.subTest(invalid=invalid), self.assertRaises(identity.IdentityError):
                    identity.file_identity(invalid)
            path.write_bytes(b'12345')
            with self.assertRaises(identity.IdentityError):
                identity.file_identity(path, maximum=4)


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-identity-source-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.git('init', '-q')
        for key, value in (('core.autocrlf', 'true'), ('core.safecrlf', 'false'),
                           ('core.hooksPath', str(self.root / 'no-hooks')),
                           ('commit.gpgsign', 'false'), ('user.name', 'Identity fixture'),
                           ('user.email', 'identity-fixture@example.invalid')):
            self.git('config', '--local', key, value)
        for relative in identity.SOURCE_FILES.values():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'first line\nsecond line\n')
        self.git('add', '--', *identity.SOURCE_FILES.values())
        self.git('commit', '-q', '-m', 'Isolated identity source fixture')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()

    def git(self, *arguments):
        return subprocess.check_output(['git', *arguments], cwd=self.root,
                                       stderr=subprocess.PIPE, timeout=15)

    def observe(self):
        with mock.patch.object(identity, '__file__',
                               str(self.root / identity.SOURCE_FILES['collector_sha256'])):
            return identity.source_identity(self.root, self.head)

    def test_committed_source_bytes_are_accepted_with_autocrlf_enabled(self):
        self.git('config', '--local', 'core.autocrlf', 'true')
        result = self.observe()
        for field, relative in identity.SOURCE_FILES.items():
            self.assertEqual(result[field], hashlib.sha256(
                self.git('cat-file', 'blob', self.head + ':' + relative)).hexdigest())

    def test_git_clean_crlf_conversion_cannot_change_any_source_identity(self):
        self.git('config', '--local', 'core.autocrlf', 'true')
        for relative in identity.SOURCE_FILES.values():
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original.replace(b'\n', b'\r\n'))
            try:
                # Git normalizes the CRLF bytes to the unchanged committed blob.
                # Refreshing this isolated index also removes racy stat effects.
                self.git('add', '--', relative)
                self.git('diff', '--cached', '--exit-code')
                self.assertEqual(self.git('status', '--porcelain'), b'',
                                 self.git('ls-files', '--eol').decode())
                with self.subTest(relative=relative), self.assertRaises(identity.IdentityError):
                    self.observe()
            finally:
                path.write_bytes(original)
                self.git('add', '--', relative)

    def test_dirty_or_wrong_head_source_is_rejected(self):
        with self.assertRaises(identity.IdentityError):
            identity.source_identity(self.root, 'a' * 40)
        path = self.root / identity.SOURCE_FILES['collector_sha256']
        path.write_bytes(path.read_bytes() + b'changed\n')
        with self.assertRaises(identity.IdentityError):
            self.observe()


class InvocationTests(unittest.TestCase):
    def test_command_failure_timeout_size_and_invalid_utf8_fail_closed(self):
        outcomes = [subprocess.CompletedProcess(['/tool'], 1, b'', b'failed'),
                    subprocess.CompletedProcess(['/tool'], 0, b'x' * (identity.MAX_OUTPUT + 1), b''),
                    subprocess.CompletedProcess(['/tool'], 0, b'\xff', b''),
                    subprocess.TimeoutExpired(['/tool'], 30), OSError('missing')]
        for outcome in outcomes:
            with self.subTest(kind=type(outcome).__name__):
                kwargs = {'side_effect': outcome} if isinstance(outcome, Exception) else {'return_value': outcome}
                with mock.patch.object(identity.subprocess, 'run', **kwargs), \
                     self.assertRaises(identity.IdentityError):
                    identity.run(['/tool'])

    def test_fixed_probe_has_no_codegen_analyzer_or_missing_header_fallback(self):
        for system in ('Linux', 'Windows', 'Darwin'):
            for language in ('c', 'c++'):
                argv, source = identity.probe_command('/selected/clang', language, system, '/sdk')
                self.assertIn('-M', argv)
                self.assertIn('-MT', argv)
                self.assertIn('--no-default-config', argv)
                self.assertIn('-fno-modules', argv)
                self.assertNotIn('-MG', argv)
                self.assertNotIn('-MM', argv)
                self.assertNotIn('--analyze', argv)
                self.assertNotIn('-c', argv)
                self.assertNotIn('-o', argv)
                self.assertNotIn('main(', source)
                self.assertIn('#include <stdio.h>', source)
                self.assertEqual('-isysroot' in argv, system == 'Darwin')
                if system == 'Windows':
                    self.assertIn('#include <winsock2.h>', source)
                    self.assertNotIn('#include <unistd.h>', source)
                else:
                    self.assertIn('#include <sys/socket.h>', source)
                if language == 'c++':
                    self.assertIn('-std=c++17', argv)
                    self.assertIn('#include <filesystem>', source)

    def test_probe_rejects_unknown_language_platform_and_missing_mac_sdk(self):
        for arguments in (('/clang', 'c#', 'Linux', None),
                          ('/clang', 'c', 'unknown', None),
                          ('/clang', 'c', 'Darwin', None)):
            with self.subTest(arguments=arguments), self.assertRaises(identity.IdentityError):
                identity.probe_command(*arguments)

    def test_environment_allowlist_never_captures_credentials(self):
        result = identity.observed_environment({'ImageOS': 'ubuntu24', 'ImageVersion': '123',
                    'GITHUB_TOKEN': 'do-not-copy', 'AWS_SECRET_ACCESS_KEY': 'do-not-copy',
                    'GITHUB_RUN_ID': '456', 'INCLUDE': 'C:/SDK/include', 'HOME': '/private'})
        self.assertEqual(result, {'ImageOS': 'ubuntu24', 'ImageVersion': '123',
                                 'GITHUB_RUN_ID': '456', 'INCLUDE': 'C:/SDK/include'})

    def test_ambient_include_overrides_fail_instead_of_changing_the_probe(self):
        for key in identity.FORBIDDEN_ENV:
            with self.subTest(key=key), self.assertRaises(identity.IdentityError):
                identity.checked_environment({key: '/unreviewed'})
        self.assertEqual(identity.checked_environment({'PATH': '/bin'}), {'PATH': '/bin'})


class DocumentTests(unittest.TestCase):
    def setUp(self):
        header = {'path': '/sdk/stdio.h', 'resolved_path': '/sdk/stdio.h',
                  'bytes': 4, 'sha256': 'd' * 64}
        command = {'argv': ['/tool/cc', '--version'], 'exit_code': 0,
                   'stdout': 'test compiler version 1', 'stderr': ''}
        tool = {'file': {**header, 'path': '/tool/cc', 'resolved_path': '/tool/cc'},
                'version': command, 'target': 'x86_64-test-linux-gnu', 'resource_dir': None}
        self.document = {
            'schema': 'codeskeptic-observed-product-identity/v1',
            'source': {'head': 'a' * 40, 'tree': 'b' * 40,
                       'collector_sha256': 'c' * 64, 'workflow_sha256': 'd' * 64,
                       'profiles_sha256': 'e' * 64, 'api_models_sha256': 'f' * 64},
            'platform': {'system': 'Linux', 'machine': 'x86_64', 'release': 'test-kernel',
                         'version': 'test-version', 'python': '3.12.0', 'environment': {},
                         'metadata': {'os_release': {'ID': 'test', 'VERSION_ID': '1'},
                                      'os_release_file': header,
                                      'package_query': {**command, 'argv': ['/usr/bin/dpkg-query', '-W',
                                          '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n',
                                          'libc6', 'libc6-dev', 'gcc-*', 'g++-*', 'libstdc++*-dev']}}},
            'tools': {role: copy.deepcopy(tool) for role in identity.TOOL_ROLES},
            'probes': {}, 'metadata_only': True, 'native_qualified': False,
            'immutable_image': False, 'product_qualified': False,
            'external_dependencies': {'sqlite': 'NOT_SELECTED_OR_CAPTURED'},
        }
        for role in ('clang', 'clangxx'):
            self.document['tools'][role]['resource_dir'] = '/tool/resource'
        for language in ('c', 'c++'):
            argv, source = identity.probe_command('/tool/cc', language, 'Linux', None)
            self.document['probes'][language] = {
                'language': language, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                'command': {**command, 'argv': argv, 'stdout': 'identity-probe: /sdk/stdio.h\n'},
                'headers': [copy.deepcopy(header)], 'dependency_count': 1}

    def native_document(self, system):
        value = copy.deepcopy(self.document)
        value['platform']['system'] = system
        query = lambda argv, stdout: {'argv': argv, 'exit_code': 0, 'stdout': stdout, 'stderr': ''}
        if system == 'Darwin':
            value['platform']['machine'] = 'arm64'
            metadata = {
                'developer_directory': query(['/usr/bin/xcode-select', '-p'], '/Applications/Xcode.app/Contents/Developer'),
                'sdk_path_query': query(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], '/sdk'),
                'sdk_version': query(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'], '14.5'),
                'sdk_build': query(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-build-version'], '23F73'),
                'os_version': query(['/usr/bin/sw_vers', '-productVersion'], '14.8.9'),
                'os_build': query(['/usr/bin/sw_vers', '-buildVersion'], '23J731'),
                'sdk_root': '/sdk',
                'clt_package': query(['/usr/sbin/pkgutil', '--pkg-info', 'com.apple.pkg.CLTools_Executables'], 'version: 15.3'),
                'xcode_version': query(['/usr/bin/xcodebuild', '-version'], 'Xcode 15.4\nBuild version 15F31d'),
                'sdk_settings': {'path': '/sdk/SDKSettings.json', 'resolved_path': '/sdk/SDKSettings.json',
                                 'bytes': 4, 'sha256': 'd' * 64}}
            header_path = '/sdk/stdio.h'
        else:
            environment = {'VSINSTALLDIR': 'C:/VS/', 'VCToolsInstallDir': 'C:/VS/Tools/14.0/',
                           'VCToolsVersion': '14.0', 'WindowsSdkDir': 'C:/SDK/',
                           'WindowsSDKVersion': '10.0.1.0/', 'UniversalCRTSdkDir': 'C:/SDK/',
                           'UCRTVersion': '10.0.1.0', 'INCLUDE': 'C:/VS/Tools/14.0/include;C:/SDK/Include/10.0.1.0/ucrt'}
            value['platform']['environment'] = environment
            os_info = {'Caption': 'Microsoft Windows Server 2025 Datacenter', 'Version': '10.0.26100',
                       'BuildNumber': '26100', 'OSArchitecture': '64-bit'}
            metadata = {'installation': {'instanceId': 'test', 'installationPath': 'C:/VS',
                        'installationVersion': '17.14.0', 'productId': 'test-product'},
                        'locator': {'path': 'C:/Installer/vswhere.exe', 'resolved_path': 'C:/Installer/vswhere.exe',
                                    'bytes': 4, 'sha256': 'd' * 64},
                        'selected_roots': {key: environment[key].rstrip('/') for key in
                                           ('VCToolsInstallDir', 'WindowsSdkDir', 'UniversalCRTSdkDir')},
                        'versions': {key: environment[key].rstrip('/') for key in
                                     ('VCToolsVersion', 'WindowsSDKVersion', 'UCRTVersion')},
                        'os_query': query(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                          identity.WINDOWS_OS_QUERY], json.dumps(os_info)), 'os': os_info}
            header_path = 'C:/SDK/Include/10.0.1.0/ucrt/stdio.h'
            for role, tool in value['tools'].items():
                path = 'C:/VS/Tools/14.0/bin/cl.exe' if role in ('cc', 'cxx') else 'C:/LLVM/bin/' + role + '.exe'
                tool['file'].update(path=path, resolved_path=path)
                msvc = role in ('cc', 'cxx')
                tool['version'] = query([path, '/Bv' if msvc else '--version'],
                                        'Microsoft C/C++ Optimizing Compiler Version 19.0 for x64' if msvc else 'clang version 20.1.8')
                tool['target'] = None if msvc else 'x86_64-pc-windows-msvc'
                tool['resource_dir'] = None if msvc else 'C:/LLVM/lib/clang/20'
        value['platform']['metadata'] = metadata
        for language, probe in value['probes'].items():
            role = 'clang' if language == 'c' else 'clangxx'
            argv, source = identity.probe_command(value['tools'][role]['file']['path'], language,
                                                   system, metadata.get('sdk_root'))
            probe['source_sha256'] = hashlib.sha256(source.encode()).hexdigest()
            probe['command'] = query(argv, 'identity-probe: ' + header_path + '\n')
            probe['headers'][0].update(path=header_path, resolved_path=header_path)
        return value

    def test_both_foreign_native_shapes_remain_observations(self):
        for system in ('Windows', 'Darwin'):
            with self.subTest(system=system):
                result = identity.validate_document(self.native_document(system))
                self.assertFalse(result['native_qualified'])
                self.assertFalse(result['local_native_bytes_verified'])

    def test_native_query_identity_or_sdk_environment_cannot_be_relabelled(self):
        for mutation in ('sdk-query', 'sdk-version', 'sdk-settings', 'win-os', 'win-environment'):
            value = self.native_document('Windows' if mutation.startswith('win') else 'Darwin')
            metadata = value['platform']['metadata']
            if mutation == 'sdk-query':
                metadata['sdk_version']['argv'] = metadata['os_build']['argv']
            elif mutation == 'sdk-version':
                metadata['sdk_version']['stdout'] = '/not-a-version'
            elif mutation == 'sdk-settings':
                metadata['sdk_settings']['path'] = '/other/SDKSettings.json'
            elif mutation == 'win-os':
                metadata['os'], metadata['os_query']['stdout'] = None, 'null'
            else:
                value['platform']['environment']['UCRTVersion'] = '9.9.9.9'
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(value)

    def test_independent_review_contradictions_are_rejected(self):
        for mutation in ('linux-package-query', 'msvc-outside-toolset', 'header-hash', 'xcode-omitted'):
            value = (self.native_document('Windows') if mutation == 'msvc-outside-toolset'
                     else self.native_document('Darwin') if mutation == 'xcode-omitted'
                     else copy.deepcopy(self.document))
            if mutation == 'linux-package-query':
                value['platform']['metadata']['package_query']['argv'] = ['/unrelated/tool', '--not-a-package-query']
            elif mutation == 'msvc-outside-toolset':
                for role in ('cc', 'cxx'):
                    value['tools'][role]['file'].update(path='C:/unrelated/cl.exe', resolved_path='C:/unrelated/cl.exe')
                    value['tools'][role]['version']['argv'] = ['C:/unrelated/cl.exe', '/Bv']
            elif mutation == 'header-hash':
                value['probes']['c++']['headers'][0]['sha256'] = 'e' * 64
            else:
                value['platform']['metadata']['xcode_version'] = None
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(value)

    def test_explicit_standalone_clt_may_omit_xcode_but_unknown_selection_may_not(self):
        value = self.native_document('Darwin')
        metadata = value['platform']['metadata']
        metadata['developer_directory']['stdout'] = '/Library/Developer/CommandLineTools'
        metadata['xcode_version'] = None
        self.assertTrue(identity.validate_document(value)['metadata_only'])
        metadata['developer_directory']['stdout'] = '/unresolved/Developer'
        with self.assertRaises(identity.IdentityError):
            identity.validate_document(value)

    def test_prefix_collision_alias_content_and_package_argument_variants_fail(self):
        for mutation in ('toolset-prefix', 'header-alias', 'header-retarget', 'package-arguments', 'compiler-hash'):
            value = self.native_document('Windows') if mutation == 'toolset-prefix' else copy.deepcopy(self.document)
            if mutation == 'toolset-prefix':
                value['tools']['cc']['file']['resolved_path'] = 'C:/VS/Tools/14.0-unrelated/cl.exe'
            elif mutation == 'header-alias':
                value['probes']['c++']['headers'][0].update(path='/alias/stdio.h', sha256='e' * 64)
                value['probes']['c++']['command']['stdout'] = 'identity-probe: /alias/stdio.h\n'
            elif mutation == 'header-retarget':
                value['probes']['c++']['headers'][0]['resolved_path'] = '/other/stdio.h'
            elif mutation == 'package-arguments':
                value['platform']['metadata']['package_query']['argv'] = ['/usr/bin/rpm', '--not-a-query']
            else:
                value['tools']['cxx']['file']['sha256'] = 'e' * 64
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(value)

    def test_resolved_targets_cannot_also_be_aliases_in_either_order(self):
        for reverse in (False, True):
            for same_contents in (False, True):
                value = copy.deepcopy(self.document)
                records = [('/alias/a.h', '/sdk/b.h', 'd' * 64),
                           ('/sdk/b.h', '/sdk/c.h', ('d' if same_contents else 'e') * 64)]
                if reverse:
                    records.reverse()
                for language, (path, resolved, sha) in zip(('c', 'c++'), records):
                    value['probes'][language]['headers'][0].update(path=path, resolved_path=resolved, sha256=sha)
                    value['probes'][language]['command']['stdout'] = 'identity-probe: ' + path + '\n'
                with self.subTest(reverse=reverse, same_contents=same_contents), self.assertRaises(identity.IdentityError):
                    identity.validate_document(value)

    def test_stable_aliases_and_direct_target_share_one_identity(self):
        for paths in (('/alias/a.h', '/sdk/b.h'), ('/sdk/b.h', '/alias/a.h'), ('/alias/a.h', '/alias/c.h')):
            value = copy.deepcopy(self.document)
            for language, path in zip(('c', 'c++'), paths):
                value['probes'][language]['headers'][0].update(path=path, resolved_path='/sdk/b.h')
                value['probes'][language]['command']['stdout'] = 'identity-probe: ' + path + '\n'
            with self.subTest(paths=paths):
                self.assertTrue(identity.validate_document(value)['metadata_only'])

    def test_structural_check_is_not_native_or_product_qualification(self):
        result = identity.validate_document(self.document)
        self.assertTrue(result['metadata_only'])
        self.assertFalse(result['local_native_bytes_verified'])
        self.assertFalse(result['native_qualified'])
        self.assertFalse(result['immutable_image'])
        self.assertFalse(result['product_qualified'])

    def test_missing_extra_and_bool_integer_substitutions_fail(self):
        for key in list(self.document):
            altered = copy.deepcopy(self.document)
            del altered[key]
            with self.subTest(missing=key), self.assertRaises(identity.IdentityError):
                identity.validate_document(altered)
        for alteration in ({'extra': True}, {'schema': 'fake'}, {'metadata_only': 1},
                           {'native_qualified': True}, {'immutable_image': True},
                           {'product_qualified': 0}):
            with self.subTest(alteration=alteration), self.assertRaises(identity.IdentityError):
                identity.validate_document({**self.document, **alteration})

    def test_wrong_source_hash_or_missing_role_or_probe_fails(self):
        for mutation in ('source', 'role', 'probe', 'header', 'hash', 'bytes', 'count', 'empty-output'):
            altered = copy.deepcopy(self.document)
            if mutation == 'source':
                altered['source']['head'] = '0' * 40
            elif mutation == 'role':
                del altered['tools']['cxx']
            elif mutation == 'probe':
                del altered['probes']['c++']
            elif mutation == 'header':
                altered['probes']['c']['headers'] = []
            elif mutation == 'hash':
                altered['probes']['c']['headers'][0]['sha256'] = '0' * 64
            elif mutation == 'bytes':
                altered['probes']['c']['headers'][0]['bytes'] = True
            elif mutation == 'count':
                altered['probes']['c']['dependency_count'] = 7
            else:
                altered['tools']['cc']['version']['stdout'] = ''
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(altered)

    def test_command_or_probe_source_tampering_is_detected(self):
        for mutation in ('argv', 'source', 'duplicate', 'language'):
            altered = copy.deepcopy(self.document)
            probe = altered['probes']['c']
            if mutation == 'argv':
                probe['command']['argv'].append('-MG')
            elif mutation == 'source':
                probe['source_sha256'] = 'e' * 64
            elif mutation == 'duplicate':
                probe['headers'].append(copy.deepcopy(probe['headers'][0]))
                probe['dependency_count'] += 1
            else:
                probe['language'] = 'c++'
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(altered)

    def test_malformed_nested_commands_or_event_identity_fail(self):
        for mutation in ('command', 'runner', 'event', 'version-argv', 'resource'):
            altered = copy.deepcopy(self.document)
            if mutation == 'command':
                altered['probes']['c']['command'] = None
            elif mutation == 'runner':
                altered['platform']['environment']['RUNNER_OS'] = 'Windows'
            elif mutation == 'event':
                altered['platform']['environment']['GITHUB_SHA'] = 'e' * 40
            elif mutation == 'version-argv':
                altered['tools']['cc']['version']['argv'] = ['/different/compiler', '--version']
            else:
                altered['tools']['clang']['resource_dir'] = 'relative-resource'
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_document(altered)

    def test_positive_cli_fixture_uses_canonical_temporary_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            actual, alias = parent / 'actual', parent / 'temporary alias'
            actual.mkdir()
            try:
                alias.symlink_to(actual, target_is_directory=True)
            except OSError as error:
                self.skipTest('host does not allow this temporary alias fixture: ' + str(error))
            unresolved = alias / 'metadata.json'
            unresolved.write_text(json.dumps(self.document))
            result = subprocess.run([sys.executable, '-B', str(Path(identity.__file__)),
                                     'check', str(unresolved)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'metadata input must be a bounded absolute regular file', result.stderr)
            with mock.patch.object(tempfile, 'tempdir', str(alias)):
                self.test_check_cli_accepts_metadata_but_rejects_unknown_secret_fields()

    def test_check_cli_accepts_metadata_but_rejects_unknown_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'identity.json'
            path.write_text(json.dumps(self.document))
            command = [sys.executable, '-B', str(Path(identity.__file__)), 'check', str(path)]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['product_qualified'])
            self.document['platform']['environment']['GITHUB_TOKEN'] = 'do-not-copy'
            path.write_text(json.dumps(self.document))
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 2)

    def test_capture_cli_refuses_existing_output_before_executing_any_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'preserved.json'
            path.write_bytes(b'preserved')
            command = [sys.executable, '-B', str(Path(identity.__file__)), 'capture',
                       '--root', directory, '--source-sha', 'a' * 40, '--output', str(path)]
            for role in identity.TOOL_ROLES:
                command += ['--' + role, str(Path(directory) / 'not-a-tool')]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'output must be new', result.stderr)
            self.assertEqual(path.read_bytes(), b'preserved')


    def test_check_cli_rejects_malformed_and_false_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'identity.json'
            path.write_text(json.dumps({**self.document, 'native_qualified': True}))
            result = subprocess.run([sys.executable, '-B', str(Path(identity.__file__)),
                                     'check', str(path)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'observation must not claim native/product qualification', result.stderr)


class CaseCaptureTests(unittest.TestCase):
    def case_document(self, system):
        fixture = DocumentTests()
        fixture.setUp()
        native = fixture.native_document(system) if system != 'Linux' else copy.deepcopy(fixture.document)
        host, tools = native['platform'], native['tools']
        if system == 'Darwin':
            sdk = identity.CASE_CLT + '/SDKs/MacOSX14.5.sdk'
            metadata = host['metadata']
            metadata['developer_directory']['stdout'] = identity.CASE_CLT
            metadata['xcode_version'] = None
            metadata['sdk_path_query']['stdout'] = metadata['sdk_root'] = sdk
            metadata['sdk_settings'].update(path=sdk + '/SDKSettings.json', resolved_path=sdk + '/SDKSettings.json')
            host['environment'] = {'DEVELOPER_DIR': identity.CASE_CLT, 'SDKROOT': sdk, 'MACOSX_DEPLOYMENT_TARGET': '14.0'}
            for role, tool in tools.items():
                path = identity.CASE_CLT + '/usr/bin/' + ('clang++' if role in ('cxx', 'clangxx') else 'clang')
                tool['file'].update(path=path, resolved_path=path)
                tool['version'].update(argv=[path, '--version'], stdout='Apple clang version 16.0.0')
                tool['target'] = 'arm64-apple-darwin23.6.0'
                if role in ('clang', 'clangxx'):
                    tool['resource_dir'] = identity.CASE_CLT + '/usr/lib/clang/16'
            header_path = sdk + '/usr/include/stdlib.h'
            for language, probe in native['probes'].items():
                role = 'clang' if language == 'c' else 'clangxx'
                probe['command'].update(argv=identity.probe_command(tools[role]['file']['path'], language, system, sdk)[0],
                                        stdout='identity-probe: ' + header_path + '\n')
                probe['headers'][0].update(path=header_path, resolved_path=header_path)
        elif system == 'Windows':
            header_path = 'C:/SDK/Include/10.0.1.0/ucrt/stdlib.h'
        else:
            tools['clang']['version']['stdout'] = 'clang version 22.1.0'
            header_path = '/sdk/stdlib.h'
        environment = identity.case_environment({**host['environment'], 'PATH': 'C:/bin' if system == 'Windows' else '/bin'}, system)
        host['environment'] = identity.observed_environment(environment)
        root = 'C:/case-stage' if system == 'Windows' else '/case-stage'
        probe_root = 'C:/probe-temp' if system == 'Windows' else '/probe-temp'
        input_file = {'path': root + '/case.c', 'resolved_path': root + '/case.c', 'bytes': 636, 'sha256': identity.CASE_SHA}
        value = {'schema': 'codeskeptic-native-case-observation/v1', 'native_identity': native, 'environment': environment,
                 'source_files': {name: 'a' * 64 for name in identity.CASE_SOURCE_FILES},
                 'binding': {'schema': 'codeskeptic-product-external-input-check/v1', 'id': 'gcc-mixed-storage-local-loss',
                             'binding_sha256': 'a' * 64, 'adjudication_sha256': 'a' * 64, 'source_bytes_verified': True,
                             'verified_inputs': 5, 'verified_bytes': 43256, 'independent_quota_examples': 0,
                             'task_ready': False, 'product_qualified': False, 'native_commands_bound': False,
                             'license_qualified': False, 'state': 'SOURCE_BINDING_ONLY_NOT_FROZEN'},
                 'input': input_file, 'probes': {}, 'syntax_checked': True, 'native_qualified': False,
                 'license_qualified': False, 'independent_quota_examples': 0, 'task_ready': False, 'product_qualified': False}
        for name in ('candidate', 'abi', 'bad-width', 'bad-signature'):
            path = input_file['path'] if name == 'candidate' else probe_root + '/' + name + '.c'
            source = None if name == 'candidate' else identity.case_abi_sources()[name].encode()
            source_file = input_file if source is None else {'path': path, 'resolved_path': path, 'bytes': len(source),
                                                           'sha256': hashlib.sha256(source).hexdigest()}
            marker = {'bad-width': 'selected int width', 'bad-signature': 'selected malloc declaration'}.get(name)
            command = {'argv': identity.case_command(native, path), 'exit_code': 1 if marker else 0, 'stdout': '',
                       'stderr': 'probe.c:4:1: error: static assertion failed: ' + marker + '\n1 error generated.\n' if marker else ''}
            headers = [] if marker else [copy.deepcopy(source_file), {'path': header_path, 'resolved_path': header_path,
                                                                     'bytes': 4, 'sha256': 'd' * 64}]
            dependency = None if marker else {'argv': identity.case_command(native, path, dependencies=True), 'exit_code': 0,
                                              'stdout': 'identity-probe: ' + path + ' ' + header_path + '\n', 'stderr': ''}
            value['probes'][name] = {'source_sha256': source_file['sha256'], 'command': identity.case_record(command, marker),
                                    'dependencies': dependency, 'headers': headers}
        identity.validate_case_document(value)
        return value

    def test_case_environment_drops_credentials_and_blocks_overrides(self):
        selected = identity.case_environment({'PATH': '/bin', 'GITHUB_TOKEN': 'secret',
                                               'SystemRoot': 'C:/Windows'}, 'Windows')
        self.assertEqual(selected, {'PATH': '/bin', 'SystemRoot': 'C:/Windows',
                                     'LANG': 'C', 'LC_ALL': 'C', 'VSLANG': '1033'})
        for key in (*identity.FORBIDDEN_ENV, 'LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            with self.subTest(key=key), self.assertRaises(identity.IdentityError):
                identity.case_environment({'PATH': '/bin', key: 'override'}, 'Linux')
        with self.assertRaises(identity.IdentityError):
            identity.case_environment({'Path': 'one', 'PATH': 'two'}, 'Windows')

    def test_abi_probes_are_fixed_c17_with_two_controlled_negatives(self):
        probes = identity.case_abi_sources()
        self.assertEqual(set(probes), {'abi', 'bad-width', 'bad-signature'})
        self.assertIn('sizeof(int) == 4', probes['abi'])
        self.assertIn('sizeof(int) == 8', probes['bad-width'])
        self.assertIn('void *(*)(size_t)', probes['abi'])
        self.assertIn('int *(*)(size_t)', probes['bad-signature'])
        self.assertEqual(probes['bad-width'], probes['abi'].replace('sizeof(int) == 4', 'sizeof(int) == 8'))
        self.assertEqual(probes['bad-signature'], probes['abi'].replace('void *(*)(size_t)', 'int *(*)(size_t)'))

    def test_observed_relative_segments_resolve_before_case_command_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            (base / 'bin').mkdir()
            resource = base / 'lib' / 'clang' / '22'
            resource.mkdir(parents=True)
            observed = str(base / 'bin' / '..' / 'lib' / 'clang' / '22')
            native = {'tools': {role: {'resource_dir': observed} for role in ('clang', 'clangxx')}}
            identity.resolve_case_resources(native)
            for tool in native['tools'].values():
                self.assertEqual(tool['resource_dir'], str(resource))
            resource.rmdir()
            with self.assertRaises(FileNotFoundError):
                identity.resolve_case_resources(native)

    def test_three_coherent_case_shapes_are_nonqualifying_observations(self):
        for system in ('Linux', 'Windows', 'Darwin'):
            with self.subTest(system=system):
                value = self.case_document(system)
                result = identity.validate_case_document(value)
                self.assertTrue(result['syntax_checked'])
                self.assertFalse(result['native_qualified'])
                self.assertFalse(result['local_native_bytes_verified'])
                with self.assertRaises(identity.IdentityError):
                    identity.validate_document(value)
                with self.assertRaises(identity.IdentityError):
                    identity.validate_case_document(value['native_identity'])

    def test_case_environment_and_native_architecture_must_match(self):
        for system in ('Windows', 'Darwin'):
            for mutation in ('environment', 'architecture', 'target'):
                value = self.case_document(system)
                if mutation == 'environment':
                    value['environment']['INCLUDE' if system == 'Windows' else 'DEVELOPER_DIR'] = 'foreign'
                elif mutation == 'architecture':
                    value['native_identity']['platform']['machine'] = 'x86'
                else:
                    value['native_identity']['tools']['clang']['target'] = 'i686-pc-windows-msvc' if system == 'Windows' else 'x86_64-apple-darwin'
                with self.subTest(system=system, mutation=mutation), self.assertRaisesRegex(identity.IdentityError, 'case child|case native'):
                    identity.validate_case_document(value)

    def test_effective_clt_cannot_escape_to_xcode_or_prefix_collision(self):
        for mutation in ('sdk', 'settings', 'compiler', 'developer', 'deployment'):
            value = self.case_document('Darwin')
            host = value['native_identity']['platform']
            if mutation == 'sdk':
                sdk = identity.CASE_CLT + '-evil/SDKs/MacOSX14.5.sdk'
                host['metadata']['sdk_root'] = host['metadata']['sdk_path_query']['stdout'] = sdk
                host['metadata']['sdk_settings'].update(path=sdk + '/SDKSettings.json', resolved_path=sdk + '/SDKSettings.json')
                value['environment']['SDKROOT'] = host['environment']['SDKROOT'] = sdk
                for language, probe in value['native_identity']['probes'].items():
                    role = 'clang' if language == 'c' else 'clangxx'
                    probe['command']['argv'] = identity.probe_command(value['native_identity']['tools'][role]['file']['path'], language, 'Darwin', sdk)[0]
            elif mutation == 'settings':
                host['metadata']['sdk_settings']['resolved_path'] = '/Applications/Xcode.app/SDKs/MacOSX14.5.sdk/SDKSettings.json'
            elif mutation == 'compiler':
                for role in ('cc', 'clang'):
                    value['native_identity']['tools'][role]['file']['resolved_path'] = identity.CASE_CLT + '-evil/usr/bin/clang'
            else:
                key = 'DEVELOPER_DIR' if mutation == 'developer' else 'MACOSX_DEPLOYMENT_TARGET'
                value['environment'][key] = host['environment'][key] = '/Applications/Xcode.app' if mutation == 'developer' else '13.0'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(identity.IdentityError, 'case requires|case compiler'):
                identity.validate_case_document(value)

    def test_windows_include_roots_and_version_subtrees_are_not_interchangeable(self):
        for mutation in ('leading-include', 'missing-vc', 'missing-ucrt', 'vc-version', 'ucrt-version', 'header'):
            value = self.case_document('Windows')
            host = value['native_identity']['platform']
            if 'include' in mutation or mutation.startswith('missing'):
                selected = value['environment']['INCLUDE']
                selected = 'C:/Unreviewed;' + selected if mutation == 'leading-include' else selected.split(';')[1 if mutation == 'missing-vc' else 0]
                value['environment']['INCLUDE'] = host['environment']['INCLUDE'] = selected
            elif mutation in ('vc-version', 'ucrt-version'):
                key = 'VCToolsVersion' if mutation == 'vc-version' else 'UCRTVersion'
                value['environment'][key] = host['environment'][key] = host['metadata']['versions'][key] = '99.0'
            else:
                probe = value['probes']['candidate']
                row = probe['headers'][1]
                old = row['path']
                row['path'] = row['resolved_path'] = old.replace('10.0.1.0', '99.0')
                probe['dependencies']['stdout'] = probe['dependencies']['stdout'].replace(old, row['path'])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(identity.IdentityError, 'case include|case headers'):
                identity.validate_case_document(value)

    def test_case_bytes_commands_negative_proofs_and_claims_are_bound(self):
        for mutation in ('input', 'command', 'negative', 'header-hash', 'binding', 'quota', 'qualification'):
            value = self.case_document('Linux')
            if mutation == 'input':
                value['input']['sha256'] = 'e' * 64
            elif mutation == 'command':
                value['probes']['candidate']['command']['argv'].insert(1, '-nostdinc')
            elif mutation == 'negative':
                value['probes']['bad-width']['command']['exit_code'] = 0
            elif mutation == 'header-hash':
                value['probes']['abi']['headers'][1]['sha256'] = 'f' * 64
            elif mutation == 'binding':
                value['binding']['binding_sha256'] = 'f' * 64
            elif mutation == 'quota':
                value['independent_quota_examples'] = True
            else:
                value['native_qualified'] = True
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_case_document(value)

    def test_case_streams_never_retain_compiler_source_diagnostics(self):
        command = {'argv': ['/clang', 'probe.c'], 'exit_code': 1, 'stdout': '',
                   'stderr': 'probe.c:4:1: error: static assertion failed: selected int width\nPRIVATE_SOURCE_SENTINEL\n1 error generated.\n'}
        record = identity.case_record(command, 'selected int width')
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', json.dumps(record))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'invalid.json'
            path.write_text('{"bad":PRIVATE_SOURCE_SENTINEL}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-case', str(path)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertRegex(result.stderr.replace(b'\r\n', b'\n'),
                             rb'^IDENTITY_INVALID case observation rejected; checks=(?:identity|profile):[0-9]+(?:,(?:identity|profile):[0-9]+)*\n$')

    def test_case_failure_locations_are_bounded_and_source_free(self):
        self.assertEqual(identity.case_observation_failure(ValueError('PRIVATE_SOURCE_SENTINEL')),
                         'case observation rejected; checks=unknown')
        try:
            identity.require(False, 'PRIVATE_SOURCE_SENTINEL /private/SDK/header.h')
        except identity.IdentityError as error:
            error.__context__ = error
            result = identity.case_observation_failure(error)
        self.assertRegex(result, r'^case observation rejected; checks=identity:[0-9]+$')
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', result)
        self.assertNotIn('/private', result)

    def test_windows_runtime_profile_paths_survive_without_secrets_or_overrides(self):
        paths = {'USERPROFILE': r'C:\Users\runner', 'APPDATA': r'C:\Users\runner\AppData\Roaming',
                 'LOCALAPPDATA': r'C:\Users\runner\AppData\Local'}
        source = {**paths, 'GITHUB_TOKEN': 'PRIVATE_CREDENTIAL_SENTINEL', 'UNRELATED_SECRET': 'private'}
        selected = identity.case_environment(source, 'Windows')
        self.assertEqual({key: selected.get(key) for key in paths}, paths)
        self.assertNotIn('PRIVATE_CREDENTIAL_SENTINEL', json.dumps(selected))
        self.assertNotIn('UNRELATED_SECRET', selected)
        for system in ('Linux', 'Darwin'):
            self.assertTrue(set(paths).isdisjoint(identity.case_environment(source, system)))
        for field in paths:
            for value in ('', 'relative', r'C:\Users\runner\..\other', None):
                with self.subTest(field=field, value=value), self.assertRaises(identity.IdentityError):
                    identity.case_environment({**source, field: value}, 'Windows')
        with self.assertRaises(identity.IdentityError):
            identity.case_environment({**source, 'CPATH': 'unreviewed'}, 'Windows')

    def test_clt_sdk_alias_and_compiler_alias_preserve_resolved_identity(self):
        value = self.case_document('Darwin')
        native = value['native_identity']
        host = native['platform']
        old_sdk = host['metadata']['sdk_root']
        sdk_alias = identity.CASE_CLT + '/SDKs/MacOSX.sdk'
        host['metadata']['sdk_root'] = host['metadata']['sdk_path_query']['stdout'] = sdk_alias
        host['metadata']['sdk_settings']['path'] = sdk_alias + '/SDKSettings.json'
        value['environment']['SDKROOT'] = host['environment']['SDKROOT'] = sdk_alias
        for role in ('cxx', 'clangxx'):
            native['tools'][role]['file']['resolved_path'] = native['tools']['clang']['file']['resolved_path']
        for probe in native['probes'].values():
            probe['command']['argv'] = [sdk_alias if arg == old_sdk else arg for arg in probe['command']['argv']]
        for probe in value['probes'].values():
            probe['command']['argv'] = [sdk_alias if arg == old_sdk else arg for arg in probe['command']['argv']]
            if probe['dependencies']:
                probe['dependencies']['argv'] = [sdk_alias if arg == old_sdk else arg for arg in probe['dependencies']['argv']]
        identity.validate_case_document(value)

    def test_negative_probe_rejects_unrelated_errors_or_warnings(self):
        intended = 'probe.c:4:1: error: static assertion failed: selected int width\n'
        for contamination in ('probe.c:1:1: fatal error: unrelated header missing\n',
                              'probe.c:2:1: error: unrelated name\n',
                              'probe.c:2:1: warning: unrelated warning\n'):
            command = {'argv': ['/clang', 'probe.c'], 'exit_code': 1, 'stdout': '',
                       'stderr': intended + contamination + '1 error generated.\n'}
            with self.subTest(contamination=contamination), self.assertRaises(identity.IdentityError):
                identity.case_record(command, 'selected int width')

    def test_new_case_rejects_nested_include_diagnostics_legacy_stays_readable(self):
        value = self.case_document('Linux')
        value['native_identity']['probes']['c']['command']['stderr'] = 'header: warning: PRIVATE_SDK_SOURCE_SENTINEL\n'
        identity.validate_document(value['native_identity'])
        with self.assertRaises(identity.IdentityError):
            identity.validate_case_document(value)

    def test_windows_workflow_explicitly_selects_case_only_include(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        selected = "$env:INCLUDE = $identityCaseIncludes -join ';'"
        self.assertIn(selected, workflow)
        self.assertLess(workflow.index('--output "$env:RUNNER_TEMP/codeskeptic-product-identity.json"'), workflow.index(selected))
        self.assertLess(workflow.index(selected), workflow.index('& $identityPython -B scripts/product_identity.py capture-case'))

    def test_windows_first_dependency_accepts_equivalent_separators_and_case(self):
        for name in ('candidate', 'abi'):
            for style in ('separator', 'case'):
                value = self.case_document('Windows')
                probe = value['probes'][name]
                original = probe['command']['argv'][-1]
                equivalent = original.replace('/', '\\') if style == 'separator' else original.swapcase()
                probe['dependencies']['stdout'] = probe['dependencies']['stdout'].replace(original, equivalent, 1)
                with self.subTest(name=name, style=style):
                    identity.validate_case_document(value)

    def test_first_dependency_rejects_different_translation_unit(self):
        for system in ('Linux', 'Windows', 'Darwin'):
            for name in ('candidate', 'abi'):
                value = self.case_document(system)
                probe = value['probes'][name]
                original = probe['command']['argv'][-1]
                probe['dependencies']['stdout'] = probe['dependencies']['stdout'].replace(original, original + '.different.c', 1)
                with self.subTest(system=system, name=name), self.assertRaisesRegex(identity.IdentityError, 'case dependency closure'):
                    identity.validate_case_document(value)


class WindowsDiagnosticTests(unittest.TestCase):
    def document(self):
        return {'schema': 'codeskeptic-windows-query-diagnostic/v1',
                'source': {key: 'a' * (40 if key in ('head', 'tree') else 64) for key in
                           ('head', 'tree', *identity.SOURCE_FILES)},
                'shell': {'path': 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
                          'resolved_path': 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
                          'bytes': 123, 'sha256': 'a' * 64},
                'module_directory': 'C:/Windows/System32/WindowsPowerShell/v1.0/Modules',
                'runner': {'run_id': '123', 'attempt': '1', 'head': 'a' * 40,
                           'image_os': 'win25', 'image_version': '20260824.214.3'},
                'probes': [{'variant': variant, 'probe': probe, 'outcome': 'OK', 'exit_code': 0,
                            'elapsed_ms': 12, 'markers': identity.WINDOWS_DIAGNOSTIC_MARKERS[probe][:],
                            'unexpected_output': False} for variant, probe in identity.WINDOWS_DIAGNOSTIC_ORDER],
                'diagnostic_only': True, 'timeout_seconds': 30, 'task_ready': False,
                'native_qualified': False, 'product_qualified': False}

    def test_original_failure_kind_never_exports_exception_text(self):
        for cause, expected in ((subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30), 'TIMEOUT'),
                                (OSError('PRIVATE_SENTINEL'), 'OS_ERROR'),
                                (ValueError('PRIVATE_SENTINEL'), 'INVALID')):
            wrapper = identity.IdentityError('PRIVATE_SENTINEL')
            wrapper.__context__ = cause
            self.assertEqual(identity.case_failure_kind(wrapper), expected)
        wrapper.__context__ = wrapper
        self.assertEqual(identity.case_failure_kind(wrapper), 'INVALID')

    def test_fixed_probe_records_timeout_and_allowlisted_markers_only(self):
        failure = subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30,
                    output=b'STARTED\r\nPRIVATE_SENTINEL\nCIM_LOADED\n', stderr=b'PRIVATE_SENTINEL')
        with mock.patch.object(identity.subprocess, 'run', side_effect=failure) as execute:
            result = identity.windows_diagnostic_probe('C:/Windows/powershell.exe', 'modules', {'PATH': 'C:/bin'})
        self.assertEqual(result['outcome'], 'TIMEOUT')
        self.assertEqual(result['markers'], ['STARTED', 'CIM_LOADED'])
        self.assertTrue(result['unexpected_output'])
        self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))
        self.assertEqual(execute.call_args.kwargs['timeout'], 30)
        self.assertEqual(execute.call_args.kwargs['env'], {'PATH': 'C:/bin'})
        self.assertNotIn('shell', execute.call_args.kwargs)

    def test_fixed_probe_outcomes_and_empty_partial_timeout(self):
        for response, expected in (
                (subprocess.CompletedProcess([], 0, b'STARTED\r\n', b''), 'OK'),
                (subprocess.CompletedProcess([], 21, b'STARTED\n', b''), 'NONZERO'),
                (subprocess.CompletedProcess([], 0, b'STARTED\n', b'PRIVATE_SENTINEL'), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'', b''), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'\xffPRIVATE_SENTINEL', b''), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'x' * (identity.MAX_OUTPUT + 1), b''), 'OUTPUT_LIMIT'),
                (subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30), 'TIMEOUT'),
                (OSError('PRIVATE_SENTINEL'), 'OS_ERROR')):
            option = {'side_effect': response} if isinstance(response, Exception) else {'return_value': response}
            with self.subTest(outcome=expected), mock.patch.object(identity.subprocess, 'run', **option) as execute:
                result = identity.windows_diagnostic_probe('C:/Windows/powershell.exe', 'startup', {})
            self.assertEqual(result['outcome'], expected)
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))
            self.assertEqual(execute.call_count, 1)
        with mock.patch.object(identity.subprocess, 'run') as execute, self.assertRaises(identity.IdentityError):
            identity.windows_diagnostic_probe('C:/Windows/powershell.exe', 'unregistered', {})
        execute.assert_not_called()

    def test_only_fixed_scripts_and_system_module_contrast_are_admitted(self):
        self.assertEqual(len(identity.WINDOWS_DIAGNOSTIC_ORDER), 6)
        self.assertEqual(set(identity.WINDOWS_DIAGNOSTIC_PROBES), {'startup', 'modules', 'query'})
        self.assertIn('Import-Module CimCmdlets', identity.WINDOWS_DIAGNOSTIC_PROBES['modules'])
        self.assertIn('Import-Module Microsoft.PowerShell.Utility', identity.WINDOWS_DIAGNOSTIC_PROBES['modules'])
        self.assertIn(identity.WINDOWS_OS_QUERY, identity.WINDOWS_DIAGNOSTIC_PROBES['query'])
        for script in identity.WINDOWS_DIAGNOSTIC_PROBES.values():
            for forbidden in ('Install-Module', 'Get-ChildItem', '$env:', 'Restart-Service', 'Remove-Item'):
                self.assertNotIn(forbidden, script)

    def test_variants_differ_only_by_local_system_module_path_and_drop_secrets(self):
        source = {'PATH': 'C:/bin', 'SystemRoot': 'C:/Windows', 'USERPROFILE': 'C:/Users/runner',
                  'PSModulePath': r'\\foreign\modules', 'GITHUB_TOKEN': 'PRIVATE_SENTINEL',
                  'UNKNOWN_SECRET': 'PRIVATE_SENTINEL'}
        modules = 'C:/Windows/System32/WindowsPowerShell/v1.0/Modules'
        variants = identity.windows_diagnostic_variants(source, modules)
        self.assertEqual(variants['selected'], identity.case_environment(source, 'Windows'))
        self.assertEqual(variants['system_module_path_only'], {**variants['selected'], 'PSModulePath': modules})
        self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(variants))
        self.assertNotIn('foreign', identity.canonical(variants))
        self.assertEqual(source['GITHUB_TOKEN'], 'PRIVATE_SENTINEL')
        for root, selected in ((r'\\server\share', r'\\server\share\System32\WindowsPowerShell\v1.0\Modules'),
                               ('relative', 'relative/System32/WindowsPowerShell/v1.0/Modules'),
                               ('C:/Windows/../other', modules), ('C:/Windows', 'C:/other/Modules')):
            with self.subTest(root=root), self.assertRaises(identity.IdentityError):
                identity.windows_diagnostic_variants({**source, 'SystemRoot': root}, selected)
        with self.assertRaises(identity.IdentityError):
            identity.windows_diagnostic_variants({**source, 'CPATH': 'unreviewed'}, modules)

    def test_diagnostic_validation_never_promotes_or_accepts_raw_streams(self):
        value = self.document()
        self.assertEqual(identity.validate_windows_diagnostic(value),
                         {'diagnostic_only': True, 'task_ready': False, 'native_qualified': False,
                          'product_qualified': False})
        for mutation in ('qualified', 'source', 'runner', 'count', 'order', 'raw-stream', 'raw-marker',
                         'timeout', 'code', 'boolean-code', 'missing-marker', 'unexpected', 'module-root'):
            value = self.document()
            if mutation == 'qualified': value['native_qualified'] = True
            elif mutation == 'source': value['source']['head'] = '0' * 40
            elif mutation == 'runner': value['runner']['head'] = 'b' * 40
            elif mutation == 'count': value['probes'].pop()
            elif mutation == 'order': value['probes'].reverse()
            elif mutation == 'raw-stream': value['probes'][0]['stderr'] = 'PRIVATE_SENTINEL'
            elif mutation == 'raw-marker': value['probes'][0]['markers'] = ['PRIVATE_SENTINEL']
            elif mutation == 'timeout': value['timeout_seconds'] = 60
            elif mutation == 'code': value['probes'][0]['exit_code'] = None
            elif mutation == 'boolean-code': value['probes'][0]['exit_code'] = False
            elif mutation == 'missing-marker': value['probes'][0]['markers'] = []
            elif mutation == 'unexpected': value['probes'][0]['unexpected_output'] = True
            elif mutation == 'module-root': value['module_directory'] = 'C:/foreign'
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_windows_diagnostic(value)

    def test_failed_probes_are_observations_not_a_green_native_gate(self):
        for outcome in ('TIMEOUT', 'OS_ERROR', 'NONZERO', 'OUTPUT_LIMIT', 'UNEXPECTED_OUTPUT'):
            value = self.document()
            row = value['probes'][0]
            row.update(outcome=outcome, exit_code=None if outcome in ('TIMEOUT', 'OS_ERROR') else (21 if outcome == 'NONZERO' else 0),
                       markers=[], unexpected_output=outcome != 'OS_ERROR')
            with self.subTest(outcome=outcome):
                self.assertFalse(identity.validate_windows_diagnostic(value)['native_qualified'])
        for outcome, code, markers, unexpected in (('OS_ERROR', None, ['STARTED'], False),
                 ('NONZERO', 0, [], False), ('OUTPUT_LIMIT', 21, [], True),
                 ('OUTPUT_LIMIT', 0, [], False), ('UNEXPECTED_OUTPUT', 0, ['STARTED'], False)):
            value = self.document()
            value['probes'][0].update(outcome=outcome, exit_code=code, markers=markers, unexpected_output=unexpected)
            with self.subTest(outcome=outcome), self.assertRaises(identity.IdentityError):
                identity.validate_windows_diagnostic(value)

    def test_collector_rejects_non_windows_before_executing_anything(self):
        with mock.patch.object(identity.platform, 'system', return_value='Linux'), \
             mock.patch.object(identity, 'source_identity') as source, \
             mock.patch.object(identity.subprocess, 'run') as execute, self.assertRaises(identity.IdentityError):
            identity.capture_windows_diagnostic(None)
        source.assert_not_called()
        execute.assert_not_called()

    def test_diagnostic_cli_is_read_only_and_duplicate_keys_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'diagnostic.json'
            path.write_text(identity.canonical(self.document()), encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-windows-diagnostic', str(path)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['native_qualified'])
            path.write_text('{"schema":"PRIVATE_SENTINEL","schema":null}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-windows-diagnostic', str(path)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)

    def test_workflow_diagnostics_follow_case_and_never_replace_failure(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        case = workflow.index('& $identityPython -B scripts/product_identity.py capture-case')
        save = workflow.index('$identityCaseExit = $LASTEXITCODE')
        diagnostic = workflow.index('& $identityPython -B scripts/product_identity.py diagnose-windows-context `')
        self.assertNotIn('& $identityPython -B scripts/product_identity.py diagnose-windows `', workflow)
        self.assertNotIn('& $identityPython -B scripts/product_identity.py diagnose-windows-stages `', workflow)
        failure = workflow.index("if ($identityCaseExit -ne 0) { throw 'Native case observation failed;")
        self.assertLess(case, save)
        self.assertLess(save, diagnostic)
        self.assertLess(diagnostic, failure)
        self.assertIn('$PSNativeCommandUseErrorActionPreference = $false', workflow)
        self.assertIn("if: always() && runner.os == 'Windows'", workflow)
        # Three unchanged legacy uploads plus the separate declaration metadata upload.
        self.assertEqual(workflow.count('if: always()'), 4)

    def test_case_cli_retains_failure_with_fixed_cause_and_no_output_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'repo'
            root.mkdir()
            output = root.parent / 'case.json'
            error = identity.IdentityError('PRIVATE_SENTINEL')
            error.__context__ = subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30)
            argv = ['capture-case', '--root', str(root), '--source-sha', 'a' * 40,
                    '--external-root', str(root.parent), '--output', str(output)]
            for role in identity.TOOL_ROLES:
                argv += ['--' + role, '/compiler']
            stream = io.StringIO()
            with mock.patch.object(identity, 'capture_case', side_effect=error), \
                 mock.patch.object(identity.sys, 'stderr', stream), \
                 mock.patch.object(identity.subprocess, 'run') as execute:
                self.assertEqual(identity.main(argv), 2)
            self.assertIn('CASE_FAILURE_KIND TIMEOUT', stream.getvalue())
            self.assertNotIn('PRIVATE_SENTINEL', stream.getvalue())
            self.assertFalse(output.exists())
            execute.assert_not_called()

    def test_diagnostic_cli_refuses_existing_or_in_checkout_output_before_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'repo'
            root.mkdir()
            existing = root.parent / 'keep.json'
            existing.write_text('preserve', encoding='utf-8')
            for output in (existing, root / 'forbidden.json'):
                with mock.patch.object(identity, 'capture_windows_diagnostic') as collect, \
                     mock.patch.object(identity.sys, 'stderr', io.StringIO()):
                    self.assertEqual(identity.main(['diagnose-windows', '--root', str(root),
                             '--source-sha', 'a' * 40, '--output', str(output)]), 2)
                collect.assert_not_called()
            self.assertEqual(existing.read_text(encoding='utf-8'), 'preserve')


class WindowsStageDiagnosticTests(unittest.TestCase):
    def document(self):
        old = WindowsDiagnosticTests().document()
        value = {key: old[key] for key in ('source', 'shell', 'runner', 'diagnostic_only',
                                          'timeout_seconds', 'task_ready', 'native_qualified', 'product_qualified')}
        value['schema'] = 'codeskeptic-windows-query-diagnostic/v2'
        value['observation'] = {'outcome': 'OK', 'exit_code': 0, 'elapsed_ms': 200,
              'stages': [{'name': name, 'elapsed_ms': index * 20} for index, name in enumerate(identity.WINDOWS_STAGE_NAMES)],
              'malformed_output': False, 'trailing_output': False, 'stderr_present': False, 'output_limit_exceeded': False}
        return value

    def test_stage_parser_keeps_only_completed_ordered_prefix(self):
        result = identity.parse_windows_stage_output(b'STARTED:0\r\nCIM_LOADED:120\r\nUTILITY_LOA', 130)
        self.assertEqual(result['stages'], [{'name': 'STARTED', 'elapsed_ms': 0},
                                           {'name': 'CIM_LOADED', 'elapsed_ms': 120}])
        self.assertTrue(result['trailing_output'])
        self.assertFalse(result['malformed_output'])

    def test_stage_parser_never_recovers_after_malformed_or_out_of_order_line(self):
        for data in (b'STARTED:0\nPRIVATE_SENTINEL\nCIM_LOADED:12\n',
                     b'STARTED:0\nUTILITY_LOADED:12\nCIM_LOADED:12\n'):
            result = identity.parse_windows_stage_output(data, 20)
            self.assertEqual(result['stages'], [{'name': 'STARTED', 'elapsed_ms': 0}])
            self.assertTrue(result['malformed_output'])
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))

    def test_stage_parser_rejects_invalid_clocks_duplicates_and_suffixes(self):
        for suffix in (b'STARTED:0\n', b'CIM_LOADED:-1\n', b'CIM_LOADED:01\n',
                       b'CIM_LOADED:1.2\n', b'CIM_LOADED:true\n', b'CIM_LOADED:32\n',
                       b'CIM_LOADED:1000000\n', b'PRIVATE_SENTINEL\n', b'\xff\n', b'\n'):
            result = identity.parse_windows_stage_output(b'STARTED:0\n' + suffix, 30)
            self.assertEqual(result['stages'], [{'name': 'STARTED', 'elapsed_ms': 0}])
            self.assertTrue(result['malformed_output'])
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))
        result = identity.parse_windows_stage_output(b'STARTED:1\nCIM_LOADED:0\n', 30)
        self.assertEqual(len(result['stages']), 1)
        self.assertTrue(result['malformed_output'])
        result = identity.parse_windows_stage_output(b'STARTED:0\n' + b'x' * identity.MAX_OUTPUT, 30)
        self.assertTrue(result['malformed_output'])
        self.assertTrue(result['trailing_output'])
        self.assertEqual(len(result['stages']), 1)
        for elapsed in (-1, True, 300001):
            with self.subTest(elapsed=elapsed), self.assertRaises(identity.IdentityError):
                identity.parse_windows_stage_output(b'', elapsed)

    def test_stage_probe_is_one_process_one_deadline_with_no_raw_stream_export(self):
        environment = {'PATH': 'C:/bin', 'LANG': 'C'}
        timeout = subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30,
                  output=b'STARTED:0\nCIM_LOADED:12000\nUTILITY_', stderr=b'PRIVATE_SENTINEL')
        with mock.patch.object(identity.subprocess, 'run', side_effect=timeout) as execute, \
             mock.patch.object(identity.time, 'monotonic', side_effect=[1, 31.1]):
            row = identity.windows_stage_probe('C:/Windows/powershell.exe', environment)
        self.assertEqual(row['outcome'], 'TIMEOUT')
        self.assertIsNone(row['exit_code'])
        self.assertEqual(row['elapsed_ms'], 30100)
        self.assertEqual([stage['name'] for stage in row['stages']], ['STARTED', 'CIM_LOADED'])
        self.assertTrue(row['trailing_output'])
        self.assertTrue(row['stderr_present'])
        self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(row))
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs['timeout'], 30)
        self.assertEqual(execute.call_args.kwargs['env'], environment)
        self.assertNotIn('shell', execute.call_args.kwargs)
        script = execute.call_args.args[0][-1]
        self.assertEqual(script, identity.windows_stage_script())
        self.assertEqual(script.count('Get-CimInstance Win32_OperatingSystem'), 1)
        self.assertEqual(script.count('[Diagnostics.Stopwatch]::StartNew()'), 1)
        self.assertEqual(script.count('[Console]::Out.Flush()'), 5)
        self.assertLess(script.index('Import-Module CimCmdlets'), script.index('Import-Module Microsoft.PowerShell.Utility'))
        self.assertLess(script.index('CIM_QUERY_DONE:'), script.index('$identityJson='))
        for forbidden in ('Install-Module', '$env:', 'Set-ExecutionPolicy', 'Restart-Service', 'Measure-Command'):
            self.assertNotIn(forbidden, script)

    def test_stage_process_error_outcomes_are_nonqualifying(self):
        complete = b''.join((name + ':' + str(index) + '\n').encode()
                            for index, name in enumerate(identity.WINDOWS_STAGE_NAMES))
        for response, expected in ((subprocess.CompletedProcess([], 0, complete, b''), 'OK'),
                (subprocess.CompletedProcess([], 21, b'STARTED:0\n', b''), 'NONZERO'),
                (subprocess.CompletedProcess([], 0, complete, b'PRIVATE_SENTINEL'), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'STARTED:0\n', b''), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'x' * (identity.MAX_OUTPUT + 1), b''), 'OUTPUT_LIMIT'),
                (OSError('PRIVATE_SENTINEL'), 'OS_ERROR'),
                (subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30, output=complete), 'TIMEOUT')):
            option = {'side_effect': response} if isinstance(response, Exception) else {'return_value': response}
            with self.subTest(outcome=expected), mock.patch.object(identity.subprocess, 'run', **option), \
                 mock.patch.object(identity.time, 'monotonic', side_effect=[1, 31]):
                row = identity.windows_stage_probe('C:/Windows/powershell.exe', {})
            self.assertEqual(row['outcome'], expected)
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(row))
            value = self.document()
            value['observation'] = row
            self.assertFalse(identity.validate_windows_stages(value)['native_qualified'])

    def test_stage_validator_rejects_forged_completion_and_clock_shapes(self):
        for mutation in ('qualified', 'schema', 'raw-output', 'marker-order', 'decreasing-clock', 'oversized-clock',
                         'bool-clock', 'missing-stage', 'extra-stage', 'none-exit', 'malformed-success',
                         'timeout-exit', 'os-error-stage', 'false-output-limit', 'false-unexpected'):
            value = self.document()
            row = value['observation']
            if mutation == 'qualified': value['task_ready'] = True
            elif mutation == 'schema': value['schema'] = 'codeskeptic-windows-query-diagnostic/v1'
            elif mutation == 'raw-output': row['stdout'] = 'PRIVATE_SENTINEL'
            elif mutation == 'marker-order': row['stages'].reverse()
            elif mutation == 'decreasing-clock': row['stages'][2]['elapsed_ms'] = 0
            elif mutation == 'oversized-clock': row['stages'][-1]['elapsed_ms'] = 202
            elif mutation == 'bool-clock': row['stages'][0]['elapsed_ms'] = False
            elif mutation == 'missing-stage': row['stages'].pop()
            elif mutation == 'extra-stage': row['stages'].append(row['stages'][-1])
            elif mutation == 'none-exit': row['exit_code'] = None
            elif mutation == 'malformed-success': row['malformed_output'] = True
            elif mutation == 'timeout-exit': row['outcome'] = 'TIMEOUT'
            elif mutation == 'os-error-stage': row.update(outcome='OS_ERROR', exit_code=None)
            elif mutation == 'false-output-limit': row['outcome'] = 'OUTPUT_LIMIT'
            elif mutation == 'false-unexpected': row['outcome'] = 'UNEXPECTED_OUTPUT'
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_windows_stages(value)

    def test_both_cli_versions_preserve_schema_boundaries_and_private_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'diagnostic.json'
            for document, accepted in ((self.document(), 'check-windows-stages'),
                     (WindowsDiagnosticTests().document(), 'check-windows-diagnostic')):
                path.write_text(identity.canonical(document), encoding='utf-8')
                for command in ('check-windows-stages', 'check-windows-diagnostic'):
                    result = subprocess.run([sys.executable, '-B', identity.__file__, command, str(path)],
                                            capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0 if command == accepted else 2, result.stderr)
            path.write_text('{"schema":"PRIVATE_SENTINEL","schema":null}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-windows-stages', str(path)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)

    def test_staged_capture_uses_unchanged_filtered_environment_and_one_mocked_probe(self):
        value = self.document()
        native_env = {'PATH': 'C:/bin', 'SystemRoot': 'C:/Windows', 'GITHUB_SHA': value['source']['head'],
                      'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'ImageOS': 'win25',
                      'ImageVersion': '20260824.214.3', 'GITHUB_TOKEN': 'PRIVATE_SENTINEL',
                      'PSModulePath': 'PRIVATE_SENTINEL'}
        root, shell = mock.MagicMock(), mock.MagicMock()
        root.resolve.return_value = root
        root.__truediv__.return_value = shell
        shell.resolve.return_value = shell
        shell.__str__.return_value = value['shell']['path']
        with mock.patch.dict(identity.os.environ, native_env, clear=True), \
             mock.patch.object(identity.platform, 'system', return_value='Windows'), \
             mock.patch.object(identity, 'source_identity', return_value=value['source']) as source, \
             mock.patch.object(identity, 'file_identity', return_value=value['shell']) as files, \
             mock.patch.object(identity, 'Path', side_effect=lambda path: root if path == 'C:/Windows' else shell), \
             mock.patch.object(identity.shutil, 'which', return_value=value['shell']['path']), \
             mock.patch.object(identity, 'windows_stage_probe', return_value=value['observation']) as probe:
            result = identity.capture_windows_stages(SimpleNamespace(root='/repo', source_sha=value['source']['head']))
        self.assertEqual(result, value)
        probe.assert_called_once_with(value['shell']['path'], identity.case_environment(native_env, 'Windows'))
        self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(probe.call_args.args[1]))
        self.assertEqual(source.call_count, 2)
        self.assertEqual(files.call_count, 2)

    def test_staged_cli_checks_output_and_platform_before_native_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'repo'
            root.mkdir()
            existing = root.parent / 'keep.json'
            existing.write_text('preserve', encoding='utf-8')
            for output in (existing, root / 'forbidden.json'):
                with mock.patch.object(identity, 'capture_windows_stages') as collect, \
                     mock.patch.object(identity.sys, 'stderr', io.StringIO()):
                    self.assertEqual(identity.main(['diagnose-windows-stages', '--root', str(root),
                             '--source-sha', 'a' * 40, '--output', str(output)]), 2)
                collect.assert_not_called()
            self.assertEqual(existing.read_text(encoding='utf-8'), 'preserve')
        with mock.patch.object(identity.platform, 'system', return_value='Linux'), \
             mock.patch.object(identity.subprocess, 'run') as execute, self.assertRaises(identity.IdentityError):
            identity.capture_windows_stages(None)
        execute.assert_not_called()


class WindowsContextDiagnosticTests(unittest.TestCase):
    def protocol(self):
        return (b'STARTED:OK\nENGINE:5.1.26100.0\nEFFECTIVE:RemoteSigned\n'
                b'MachinePolicy:Undefined\nUserPolicy:Undefined\nProcess:Undefined\n'
                b'CurrentUser:Undefined\nLocalMachine:RemoteSigned\nPOLICY_DONE:OK\n')

    def document(self):
        value = WindowsStageDiagnosticTests().document()
        value['schema'] = 'codeskeptic-windows-query-diagnostic/v3'
        value['policy'] = {'inherited_preference': {'state': 'recognized', 'value': 'Bypass'},
                           'case_preference': {'state': 'absent', 'value': None},
                           'observation': {'outcome': 'OK', 'exit_code': 0, 'elapsed_ms': 100,
                             **identity.parse_windows_policy_output(self.protocol()),
                             'stderr_present': False, 'output_limit_exceeded': False}}
        return value

    def test_preference_classification_never_exports_unknown_environment_values(self):
        for environment, expected in (({}, {'state': 'absent', 'value': None}),
                ({'psexecutionpolicypreference': 'rEmOtEsIgNeD'}, {'state': 'recognized', 'value': 'RemoteSigned'}),
                ({'PSExecutionPolicyPreference': 'PRIVATE_SENTINEL'}, {'state': 'unrecognized', 'value': None}),
                ({'PSExecutionPolicyPreference': 'Bypass', 'PSEXECUTIONPOLICYPREFERENCE': 'Bypass'},
                 {'state': 'unrecognized', 'value': None})):
            self.assertEqual(identity.windows_policy_preference(environment), expected)

    def test_policy_parser_is_ordered_bounded_and_never_resynchronizes(self):
        result = identity.parse_windows_policy_output(self.protocol().replace(b'\n', b'\r\n'))
        self.assertEqual(len(result['records']), 9)
        self.assertFalse(result['malformed_output'])
        self.assertFalse(result['trailing_output'])
        for suffix in (b'ENGINE:PRIVATE_SENTINEL\n', b'ENGINE:5.01\n', b'EFFECTIVE:Bypass\n',
                       b'ENGINE:5.1\nEFFECTIVE:PRIVATE_SENTINEL\n', b'\xff\n', b'STARTED:OK\n'):
            result = identity.parse_windows_policy_output(b'STARTED:OK\n' + suffix + self.protocol())
            self.assertLessEqual(len(result['records']), 2)
            self.assertTrue(result['malformed_output'])
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))
        result = identity.parse_windows_policy_output(b'STARTED:OK\nENGINE:5.')
        self.assertEqual(len(result['records']), 1)
        self.assertTrue(result['trailing_output'])
        self.assertFalse(result['malformed_output'])
        self.assertTrue(identity.parse_windows_policy_output(b'x' * (identity.MAX_OUTPUT + 1))['malformed_output'])

    def test_policy_probe_preserves_failures_and_only_fixed_records(self):
        for response, expected in ((subprocess.CompletedProcess([], 0, self.protocol(), b''), 'OK'),
                (subprocess.CompletedProcess([], 21, b'STARTED:OK\n', b''), 'NONZERO'),
                (subprocess.CompletedProcess([], 0, self.protocol(), b'PRIVATE_SENTINEL'), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'STARTED:OK\n', b''), 'UNEXPECTED_OUTPUT'),
                (subprocess.CompletedProcess([], 0, b'x' * (identity.MAX_OUTPUT + 1), b''), 'OUTPUT_LIMIT'),
                (OSError('PRIVATE_SENTINEL'), 'OS_ERROR'),
                (subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30, output=self.protocol()), 'TIMEOUT'),
                (subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30, output=b'STARTED:OK\nENGINE:5.',
                                          stderr=b'PRIVATE_SENTINEL'), 'TIMEOUT')):
            option = {'side_effect': response} if isinstance(response, Exception) else {'return_value': response}
            with self.subTest(outcome=expected), mock.patch.object(identity.subprocess, 'run', **option) as execute, \
                 mock.patch.object(identity.time, 'monotonic', side_effect=[1, 31]):
                row = identity.windows_policy_probe('C:/Windows/powershell.exe', {'PATH': 'C:/bin'})
            self.assertEqual(row['outcome'], expected)
            self.assertEqual(row['elapsed_ms'], 30000)
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(row))
            execute.assert_called_once()
            self.assertEqual(execute.call_args.kwargs['timeout'], 30)
            self.assertEqual(execute.call_args.kwargs['env'], {'PATH': 'C:/bin'})
            self.assertNotIn('shell', execute.call_args.kwargs)
            self.assertEqual(execute.call_args.args[0], ['C:/Windows/powershell.exe', '-NoProfile',
                             '-NonInteractive', '-Command', identity.windows_policy_script()])
            value = self.document()
            value['policy']['observation'] = row
            self.assertFalse(identity.validate_windows_context(value)['native_qualified'])

    def test_policy_script_only_reads_actual_child_engine_and_policy(self):
        script = identity.windows_policy_script()
        self.assertIn('$PSVersionTable.PSVersion.ToString()', script)
        self.assertEqual(script.count('Microsoft.PowerShell.Security\\Get-ExecutionPolicy'), 6)
        self.assertEqual(script.count('[Console]::Out.Flush()'), 9)
        self.assertLess(script.index('ENGINE:'), script.index('Get-ExecutionPolicy'))
        for scope in identity.WINDOWS_POLICY_SCOPES:
            self.assertEqual(script.count('-Scope ' + scope + ' '), 1)
        for forbidden in ('Set-ExecutionPolicy', '$env:', 'Get-CimInstance', 'CimCmdlets',
                          'Get-AuthenticodeSignature', 'Unblock-File', 'ConvertTo-Json', 'Restart-Service'):
            self.assertNotIn(forbidden, script)

    def test_context_validator_rejects_forged_status_fields_and_raw_values(self):
        for mutation in ('unknown-top', 'unknown-policy', 'qualified', 'schema', 'raw-parent', 'empty-parent',
                         'forwarded-case', 'missing-record', 'wrong-order', 'bool-value', 'unknown-policy-value',
                         'none-exit', 'nonzero-success', 'bool-time', 'negative-time', 'oversized-time',
                         'malformed-success', 'timeout-exit', 'os-error-records', 'false-output-limit',
                         'false-unexpected', 'stage-clock'):
            value = self.document()
            policy, row = value['policy'], value['policy']['observation']
            if mutation == 'unknown-top': value['stdout'] = 'PRIVATE_SENTINEL'
            elif mutation == 'unknown-policy': policy['stdout'] = 'PRIVATE_SENTINEL'
            elif mutation == 'qualified': value['task_ready'] = True
            elif mutation == 'schema': value['schema'] = 'codeskeptic-windows-query-diagnostic/v2'
            elif mutation == 'raw-parent': policy['inherited_preference']['value'] = 'PRIVATE_SENTINEL'
            elif mutation == 'empty-parent': policy['inherited_preference']['state'] = 'absent'
            elif mutation == 'forwarded-case': policy['case_preference'] = policy['inherited_preference']
            elif mutation == 'missing-record': row['records'].pop()
            elif mutation == 'wrong-order': row['records'].reverse()
            elif mutation == 'bool-value': row['records'][1]['value'] = True
            elif mutation == 'unknown-policy-value': row['records'][2]['value'] = 'PRIVATE_SENTINEL'
            elif mutation == 'none-exit': row['exit_code'] = None
            elif mutation == 'nonzero-success': row['exit_code'] = 21
            elif mutation == 'bool-time': row['elapsed_ms'] = True
            elif mutation == 'negative-time': row['elapsed_ms'] = -1
            elif mutation == 'oversized-time': row['elapsed_ms'] = 300001
            elif mutation == 'malformed-success': row['malformed_output'] = True
            elif mutation == 'timeout-exit': row['outcome'] = 'TIMEOUT'
            elif mutation == 'os-error-records': row.update(outcome='OS_ERROR', exit_code=None)
            elif mutation == 'false-output-limit': row['outcome'] = 'OUTPUT_LIMIT'
            elif mutation == 'false-unexpected': row['outcome'] = 'UNEXPECTED_OUTPUT'
            elif mutation == 'stage-clock': value['observation']['stages'][-1]['elapsed_ms'] = 300000
            with self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.validate_windows_context(value)

    def test_context_capture_runs_stage_then_policy_once_with_original_environment(self):
        value = self.document()
        stages = WindowsStageDiagnosticTests().document()
        stages['observation'].update(outcome='TIMEOUT', exit_code=None)
        native_env = {'SystemRoot': 'C:/Windows', 'PATH': 'C:/bin', 'PSExecutionPolicyPreference': 'Bypass',
                      'GITHUB_TOKEN': 'PRIVATE_SENTINEL', 'PSModulePath': 'PRIVATE_SENTINEL'}
        calls = []
        def stage_probe(args):
            calls.append('stages')
            return copy.deepcopy(stages)
        def policy_probe(shell, environment):
            calls.append('policy')
            self.assertEqual(environment, identity.case_environment(native_env, 'Windows'))
            self.assertNotIn('PSExecutionPolicyPreference', environment)
            self.assertEqual(shell, str(Path(value['shell']['path'])))
            return value['policy']['observation']
        with mock.patch.dict(identity.os.environ, native_env, clear=True), \
             mock.patch.object(identity, 'capture_windows_stages', side_effect=stage_probe) as stage, \
             mock.patch.object(identity, 'windows_policy_probe', side_effect=policy_probe) as policy, \
             mock.patch.object(identity, 'file_identity', return_value=value['shell']) as files, \
             mock.patch.object(identity, 'source_identity', return_value=value['source']) as source:
            result = identity.capture_windows_context(SimpleNamespace(root='/repo', source_sha=value['source']['head']))
        self.assertEqual(calls, ['stages', 'policy'])
        self.assertEqual(result['observation']['outcome'], 'TIMEOUT')
        self.assertEqual(result['policy'], value['policy'])
        self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(result))
        stage.assert_called_once()
        policy.assert_called_once()
        self.assertEqual(files.call_count, 2)
        source.assert_called_once()
        original = copy.deepcopy(result)
        identity.validate_windows_context(result)
        self.assertEqual(original, result)

    def test_context_capture_refuses_changed_shell_before_policy_probe(self):
        with mock.patch.object(identity, 'capture_windows_stages', return_value=WindowsStageDiagnosticTests().document()), \
             mock.patch.object(identity, 'case_environment', return_value={}), \
             mock.patch.object(identity, 'file_identity', return_value={}), \
             mock.patch.object(identity, 'windows_policy_probe') as probe, self.assertRaises(identity.IdentityError):
            identity.capture_windows_context(None)
        probe.assert_not_called()

    def test_context_capture_rechecks_shell_and_source_after_policy(self):
        for mutation in ('shell', 'source'):
            value = self.document()
            with mock.patch.object(identity, 'capture_windows_stages',
                                   return_value=WindowsStageDiagnosticTests().document()), \
                 mock.patch.object(identity, 'case_environment', return_value={}), \
                 mock.patch.object(identity, 'file_identity',
                                   side_effect=[value['shell'], {} if mutation == 'shell' else value['shell']]), \
                 mock.patch.object(identity, 'source_identity', return_value={} if mutation == 'source' else value['source']), \
                 mock.patch.object(identity, 'windows_policy_probe', return_value=value['policy']['observation']) as probe, \
                 self.subTest(mutation=mutation), self.assertRaises(identity.IdentityError):
                identity.capture_windows_context(SimpleNamespace(root='/repo', source_sha=value['source']['head']))
            probe.assert_called_once()

    def test_all_three_cli_schemas_and_private_parse_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'diagnostic.json'
            documents = ((self.document(), 'check-windows-context'),
                         (WindowsStageDiagnosticTests().document(), 'check-windows-stages'),
                         (WindowsDiagnosticTests().document(), 'check-windows-diagnostic'))
            for document, accepted in documents:
                path.write_text(identity.canonical(document), encoding='utf-8')
                for _, command in documents:
                    result = subprocess.run([sys.executable, '-B', identity.__file__, command, str(path)],
                                            capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0 if command == accepted else 2, result.stderr)
            path.write_text('{"schema":"PRIVATE_SENTINEL","schema":null}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-windows-context', str(path)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)

    def test_context_cli_protects_output_and_rejects_non_windows_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'repo'
            root.mkdir()
            existing = root.parent / 'keep.json'
            existing.write_text('preserve', encoding='utf-8')
            for output in (existing, root / 'forbidden.json'):
                with mock.patch.object(identity, 'capture_windows_context') as collect, \
                     mock.patch.object(identity.sys, 'stderr', io.StringIO()):
                    self.assertEqual(identity.main(['diagnose-windows-context', '--root', str(root),
                             '--source-sha', 'a' * 40, '--output', str(output)]), 2)
                collect.assert_not_called()
            self.assertEqual(existing.read_text(encoding='utf-8'), 'preserve')
        with mock.patch.object(identity.platform, 'system', return_value='Linux'), \
             mock.patch.object(identity.subprocess, 'run') as execute, self.assertRaises(identity.IdentityError):
            identity.capture_windows_context(None)
        execute.assert_not_called()


class DeclarationTests(unittest.TestCase):
    def setUp(self):
        self.model = json.loads((Path(__file__).resolve().parents[1] /
                                'tests/product_corpus/native-api-models.json').read_text())

    def packet(self):
        old = CaseCaptureTests().case_document('Linux')
        native = old['native_identity']
        model_sha = identity.declaration_model(Path(identity.__file__).resolve().parents[1])[1]
        native['source']['api_models_sha256'] = model_sha
        source = identity.declaration_source(self.model, 'Linux').encode()
        input_ = {'path': '/probe/declarations.c', 'resolved_path': '/probe/declarations.c',
                  'bytes': len(source), 'sha256': hashlib.sha256(source).hexdigest()}
        header = {'path': '/sdk/stdlib.h', 'resolved_path': '/sdk/stdlib.h', 'bytes': 100000, 'sha256': 'b' * 64}
        compiler = native['tools']['clang']
        empty = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
        requests = [{'id': r['id'], 'symbol': r['symbol'], 'expected_type': None,
                     'variable_location': None, 'targets': []} for r in identity.declaration_requests(self.model, 'Linux')]
        value = {'schema': 'codeskeptic-native-declarations/v1', 'native_identity': native,
                 'environment': old['environment'], 'producer_files': {'scripts/product_profiles.py': 'c' * 64},
                 'library': {'path': '/lib/libclang.so', 'resolved_path': '/lib/libclang.so', 'bytes': 100, 'sha256': 'd' * 64},
                 'probe': {'input': input_, 'headers': [input_, header],
                     'dependency': {'argv': identity.declaration_command(compiler, 'Linux', {}, input_['path'], True),
                                    'exit_code': 0, 'stdout': 'identity-probe: /probe/declarations.c /sdk/stdlib.h\n', 'stderr': ''},
                     'syntax': {'argv': identity.declaration_command(compiler, 'Linux', {}, input_['path']),
                                'exit_code': 0, 'stdout': empty, 'stderr': copy.deepcopy(empty)},
                     'backend_failure': None,
                     'cindex': {'parse_status': 0, 'library_version': 'clang version 22.1.0', 'diagnostics': [],
                                'requests': requests, 'inclusions': ['/probe/declarations.c', '/sdk/stdlib.h'], 'entry': []}},
                 'metadata_only': True, 'native_qualified': False, 'task_ready': False, 'product_qualified': False}
        return value, model_sha

    def position(self, file='/sdk/stdlib.h'):
        return {key: {'file': file, 'line': 1, 'column': 1, 'offset': 0} for key in ('spelling', 'expansion')}

    def type_node(self, kind, detail=None, const=False):
        qualifiers = {'const': const, 'volatile': False, 'restrict': False}
        return {'kind': kind, 'spelling': kind, 'canonical_spelling': kind,
                'qualifiers': qualifiers, 'canonical_qualifiers': copy.deepcopy(qualifiers),
                'size': None if kind in ('Void', 'FunctionProto') else 8,
                'alignment': None if kind in ('Void', 'FunctionProto') else 8, 'detail': detail}

    def populated(self):
        value, sha = self.packet()
        return_pointer = self.type_node('Pointer', {'pointee': self.type_node('Char_S')})
        parameter = self.type_node('Pointer', {'pointee': self.type_node('Char_S', const=True)})
        function = self.type_node('FunctionProto', {'result': return_pointer, 'parameters': [parameter],
                                                  'variadic': False, 'calling_convention': 1})
        declaration = {'name': 'getenv', 'kind': 'FunctionDecl', 'usr': 'c:@F@getenv',
                       'location': self.position(), 'linkage_kind': 4, 'language_kind': 1,
                       'mangling': 'getenv', 'is_definition': False,
                       'parameters': [{'name': 'name', 'location': self.position(), 'type': copy.deepcopy(parameter)}]}
        row = next(r for r in value['probe']['cindex']['requests'] if r['symbol'] == 'getenv')
        row.update(expected_type=self.type_node('Pointer', {'pointee': copy.deepcopy(function)}),
                   variable_location=self.position('/probe/declarations.c'),
                   targets=[{'reference': declaration, 'canonical': copy.deepcopy(declaration),
                             'definition': None, 'type': function}])
        return value, sha, row

    def summary(self, value, sha):
        return identity.validate_declaration_document(value, self.model, sha)

    def issues(self, value, sha):
        return next(r['issues'] for r in self.summary(value, sha)['requests'] if r['id'] == 'c.getenv')

    def test_positive_metadata_never_counts_as_native_qualification(self):
        value, sha, row = self.populated()
        self.assertEqual(self.issues(value, sha), [])
        result = self.summary(value, sha)
        self.assertFalse(result['native_qualified'])
        self.assertEqual(result['coverage']['qualified_library_pairs'], 0)

    def test_whole_tu_error_blocks_a_plausible_reference(self):
        value, sha, row = self.populated()
        value['probe']['cindex']['diagnostics'] = [{'severity': 3, 'bytes': 5, 'sha256': 'a' * 64}]
        self.assertFalse(self.summary(value, sha)['syntax_pass'])
        self.assertIn('SYNTAX_FAILED', self.issues(value, sha))
        value['probe']['cindex']['diagnostics'] = []
        value['probe']['syntax']['exit_code'] = 1
        self.assertIn('SYNTAX_FAILED', self.issues(value, sha))

    def test_wrong_target_and_same_name_user_body_remain_explicit_gaps(self):
        value, sha, row = self.populated()
        row['targets'][0]['reference']['name'] = 'open'
        self.assertIn('REQUEST_TARGET_MISMATCH', self.issues(value, sha))
        value, sha, row = self.populated()
        definition = copy.deepcopy(row['targets'][0]['reference'])
        definition.update(is_definition=True, location=self.position('/probe/declarations.c'))
        row['targets'][0]['definition'] = definition
        self.assertIn('DEFINITION_PRESENT', self.issues(value, sha))

    def test_variadic_calling_convention_and_nested_type_drift(self):
        for mutation in ('variadic', 'calling_convention', 'const'):
            value, sha, row = self.populated()
            detail = row['targets'][0]['type']['detail']
            if mutation == 'const':
                detail['parameters'][0]['detail']['pointee']['canonical_qualifiers']['const'] = False
            else:
                detail[mutation] = True if mutation == 'variadic' else 2
            self.assertIn('SIGNATURE_MISMATCH', self.issues(value, sha))

    def test_declared_parameter_is_bound_without_erasing_its_restrict(self):
        value, sha, row = self.populated()
        parameter = row['targets'][0]['reference']['parameters'][0]['type']
        parameter['qualifiers']['restrict'] = parameter['canonical_qualifiers']['restrict'] = True
        self.assertEqual(self.issues(value, sha), [])
        parameter['detail']['pointee']['canonical_qualifiers']['const'] = False
        self.assertIn('DECLARED_PARAMETER_MISMATCH', self.issues(value, sha))
        row['targets'][0]['canonical']['parameters'] = []
        self.assertIn('DECLARED_PARAMETER_MISMATCH', self.issues(value, sha))

    def test_nested_unsupported_types_and_parser_version_drift_are_gaps(self):
        value, sha, row = self.populated()
        for function in (row['expected_type']['detail']['pointee'], row['targets'][0]['type']):
            function['detail']['result'] = self.type_node('UnknownThing', {'unsupported': True})
        self.assertIn('UNSUPPORTED_TYPE', self.issues(value, sha))
        value['probe']['cindex']['library_version'] = 'clang version 19.0.0'
        self.assertIn('PARSER_DRIVER_VERSION_MISMATCH', self.issues(value, sha))

    def test_header_closure_source_model_and_inventory_forgery_are_rejected(self):
        for mutation in ('header', 'source', 'model', 'missing', 'duplicate', 'macro', 'qualify'):
            value, sha, row = self.populated()
            if mutation == 'header':
                row['targets'][0]['canonical']['location'] = self.position('/elsewhere/stdlib.h')
            elif mutation == 'source':
                value['probe']['input']['sha256'] = 'f' * 64
            elif mutation == 'model':
                sha = 'f' * 64
            elif mutation == 'missing':
                value['probe']['cindex']['requests'].pop()
            elif mutation == 'duplicate':
                value['probe']['cindex']['requests'][1] = copy.deepcopy(row)
            elif mutation == 'macro':
                value['probe']['syntax']['argv'].insert(1, '-D_POSIX_C_SOURCE=200809L')
            else:
                value['native_qualified'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.summary(value, sha)

    def test_duplicate_reference_occurrences_do_not_inflate_coverage(self):
        value, sha, row = self.populated()
        row['targets'].append(copy.deepcopy(row['targets'][0]))
        result = self.summary(value, sha)
        self.assertEqual(len(result['requests']), 14)
        self.assertEqual(result['coverage']['required_library_pairs'], 50)

    def test_metadata_reader_never_loads_libraries_or_runs_native_commands(self):
        value, sha, row = self.populated()
        with (mock.patch.object(identity, 'declaration_backend', side_effect=AssertionError('library load')),
              mock.patch.object(identity.subprocess, 'run', side_effect=AssertionError('execution'))):
            self.assertEqual(self.issues(value, sha), [])

    def test_shared_physical_identity_cannot_have_conflicting_bytes(self):
        value, sha, row = self.populated()
        old_header = value['native_identity']['probes']['c']['headers'][0]
        value['library'].update(path=old_header['resolved_path'], resolved_path=old_header['resolved_path'])
        with self.assertRaisesRegex(ValueError, 'identity disagreement'):
            self.summary(value, sha)

    def test_empty_usr_and_unsupported_linkage_cannot_be_issue_free(self):
        for field, replacement in (('usr', ''), ('language_kind', 0), ('linkage_kind', 0)):
            value, sha, row = self.populated()
            for target in ('reference', 'canonical'):
                row['targets'][0][target][field] = replacement
            self.assertIn('LINKAGE_NOT_ADJUDICATED', self.issues(value, sha))

    def test_backend_failure_retains_the_earlier_syntax_failure(self):
        value, sha, row = self.populated()
        value['probe']['syntax']['exit_code'] = 1
        value['probe']['cindex'] = None
        empty = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
        value['probe']['backend_failure'] = {'kind': 'TIMEOUT', 'exit_code': None, 'stdout': empty, 'stderr': empty}
        self.assertEqual(self.issues(value, sha), ['BACKEND_FAILED', 'SYNTAX_FAILED'])
        self.assertFalse(self.summary(value, sha)['syntax_pass'])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'failed.json'
            argv = ['capture-declarations', '--root', str(Path(identity.__file__).resolve().parents[1]),
                    '--source-sha', 'a' * 40, '--libclang', '/not-loaded', '--output', str(output)]
            for role in identity.TOOL_ROLES:
                argv += ['--' + role, '/not-executed']
            with (mock.patch.object(identity, 'capture_declarations', return_value=value),
                  mock.patch('sys.stdout', new_callable=io.StringIO)):
                self.assertEqual(identity.main(argv), 2)
            self.assertEqual(json.loads(output.read_text()), value)

    def test_worker_timeout_crash_bad_json_and_oversize_are_explicit(self):
        cases = [(subprocess.TimeoutExpired(['fixed'], 30, output=b'partial'), 'TIMEOUT'),
                 (OSError('unavailable'), 'START_FAILED'),
                 (SimpleNamespace(returncode=-11, stdout=b'', stderr=b''), 'PROCESS_FAILED'),
                 (SimpleNamespace(returncode=0, stdout=b'not-json', stderr=b''), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=0, stdout=b'x' * (identity.MAX_OUTPUT + 1), stderr=b''), 'OUTPUT_LIMIT')]
        for result, kind in cases:
            option = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
            with self.subTest(kind=kind), mock.patch.object(identity.subprocess, 'run', **option) as command:
                observed, failure = identity.run_declaration_worker({}, lambda observed: self.fail('invalid output accepted'))
            self.assertIsNone(observed)
            self.assertEqual(failure['kind'], kind)
            self.assertEqual(command.call_args.kwargs['timeout'], 30)

    def test_worker_result_shape_validation_is_pure_and_platform_independent(self):
        value, sha, row = self.populated()
        observation = value['probe']['cindex']
        nested = copy.deepcopy(observation)
        nested['requests'][0]['targets'] = [None]
        bad_inclusion = copy.deepcopy(observation)
        bad_inclusion['inclusions'] = [{}]
        bad_unicode = copy.deepcopy(observation)
        bad_unicode['library_version'] = '\udcff'
        oversized_unicode = copy.deepcopy(observation)
        oversized_unicode['library_version'] = 'é' * 5000
        valid_unicode = copy.deepcopy(observation)
        valid_unicode['library_version'] += ' — native'
        for result in ({}, None, [], nested, bad_inclusion, bad_unicode, oversized_unicode, observation, valid_unicode):
            raw = json.dumps(result, ensure_ascii=True).encode()
            valid = result is observation or result is valid_unicode
            with (self.subTest(valid=valid, shape=type(result).__name__),
                  mock.patch.object(identity.subprocess, 'run', return_value=SimpleNamespace(
                      returncode=0, stdout=raw, stderr=b'')),
                  mock.patch.object(identity, 'file_identity', side_effect=AssertionError('native file read')),
                  mock.patch.object(identity, 'declaration_backend', side_effect=AssertionError('native load'))):
                observed, failure = identity.run_declaration_worker({}, lambda observed:
                    identity.validate_declaration_observation(observed, self.model, value['native_identity'], value['probe']))
            if valid:
                self.assertIsNone(failure)
                self.assertEqual(observed, result)
            else:
                self.assertIsNone(observed)
                self.assertEqual(failure['kind'], 'INVALID_RESULT')
                self.assertEqual(failure['stdout'], {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    @contextmanager
    def mocked_declaration_capture(self, output, worker_stdout, changed=None, after_serialization=None,
                                   syntax_exit=1, preprocessor_response=None, worker_result=None,
                                   fixture=None, trace_response=None):
        """Real capture/writer orchestration; synthetic native I/O, never native execution."""
        value, sha = self.packet() if fixture is None else fixture
        native = value['native_identity']
        system = native['platform']['system']
        root = Path(identity.__file__).resolve().parents[1]
        real_file_identity = identity.file_identity
        records = {record['path']: record for record in [value['library'], *value['probe']['headers'][1:],
                   *[tool['file'] for tool in native['tools'].values()],
                   *[header for probe in native['probes'].values() for header in probe['headers']]]}
        producer = root / 'scripts/product_profiles.py'
        records[str(producer)] = {'path': str(producer), 'resolved_path': str(producer), 'bytes': 8,
                                 'sha256': hashlib.sha256(b'producer').hexdigest()}
        worker_finished = False
        emitted = {}

        def file_identity(path, **kwargs):
            if str(path) not in records:
                return real_file_identity(path, **kwargs)
            result = copy.deepcopy(records[str(path)])
            if worker_finished and changed == str(path):
                result['sha256'] = 'f' * 64
            return result

        def run(argv, **kwargs):
            if argv[:3] == ['git', 'cat-file', 'blob']:
                return {'stdout': 'producer'}
            if '-M' in argv:
                escaped = identity.re.sub(r'(\\*) ', lambda match: match[1] * 2 + '\\ ', argv[-1])
                escaped = escaped.replace('#', '\\#').replace('$', '$$')
                return {'argv': argv, 'exit_code': 0,
                        'stdout': 'identity-probe: ' + escaped + ' ' +
                                  ' '.join(h['path'] for h in value['probe']['headers'][1:]) + '\n', 'stderr': ''}
            emitted['syntax_argv'] = argv[:]
            return {'argv': argv, 'exit_code': syntax_exit, 'stdout': '',
                    'stderr': 'earlier syntax RED' if syntax_exit else ''}

        def worker(*args, **kwargs):
            nonlocal worker_finished
            if '-H' in args[0]:
                self.assertEqual(args[0], identity.declaration_header_trace_command(
                    native['tools']['clang'], system, native['platform']['metadata'], args[0][-1]))
                self.assertEqual(kwargs, {'env': identity.checked_environment(identity.os.environ),
                                         'capture_output': True, 'timeout': 30, 'check': False})
                emitted['trace_argv'] = args[0][:]
                if isinstance(trace_response, BaseException):
                    raise trace_response
                return trace_response if trace_response is not None else SimpleNamespace(
                    returncode=0, stdout=b'', stderr=value['probe']['header_trace']['command']['stderr'].encode())
            if '-dM' in args[0]:
                self.assertEqual(args[0], identity.declaration_preprocessor_command(
                    native['tools']['clang'], 'Linux', native['platform']['metadata'], args[0][-1]))
                emitted['preprocessor_argv'] = args[0]
                if isinstance(preprocessor_response, BaseException):
                    raise preprocessor_response
                return (preprocessor_response if preprocessor_response is not None else SimpleNamespace(
                    returncode=0, stdout=b'#define _POSIX_C_SOURCE 200809L\n#define __STRICT_ANSI__ 1\n', stderr=b''))
            worker_finished = True
            emitted['config'] = json.loads(kwargs['input'])
            if worker_result is not None:
                emitted['stdout'] = worker_result.stdout
                return worker_result
            path = emitted['config']['input']['path']
            emitted['stdout'] = worker_stdout.replace(json.dumps(value['probe']['input']['path']).encode(), json.dumps(path).encode())
            observed = json.loads(emitted['stdout'])
            if (type(observed) is dict and type(observed.get('inclusions')) is list
                    and all(type(item) is str for item in observed['inclusions'])):
                observed['inclusions'].sort()
                emitted['stdout'] = identity.canonical(observed).encode()
            if after_serialization is not None:
                emitted['stdout'] = after_serialization(emitted['stdout'])
            return SimpleNamespace(returncode=0, stdout=emitted['stdout'], stderr=b'')

        source = copy.deepcopy(native['source'])
        if changed == 'source':
            source['head'] = 'f' * 40
        with ExitStack() as stack:
            for name, options in (
                    ('capture', {'return_value': native}),
                    ('resolve_case_resources', {'return_value': None}),
                    ('case_environment', {'return_value': value['environment']}),
                    ('file_identity', {'side_effect': file_identity}),
                    ('run', {'side_effect': run}),
                    ('source_identity', {'return_value': source}),
                    ('native_metadata', {'return_value': native['platform']['metadata']})):
                stack.enter_context(mock.patch.object(identity, name, **options))
            stack.enter_context(mock.patch.object(identity.platform, 'system', return_value=system))
            stack.enter_context(mock.patch.object(identity.subprocess, 'run', side_effect=worker))
            stack.enter_context(mock.patch.object(identity, 'declaration_backend', side_effect=AssertionError('native load')))
            stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            stderr = stack.enter_context(mock.patch('sys.stderr', new_callable=io.StringIO))
            argv = ['capture-declarations', '--root', str(root), '--source-sha', native['source']['head'],
                    '--libclang', value['library']['path'], '--output', str(output)]
            for role in identity.TOOL_ROLES:
                argv += ['--' + role, '/not-executed']
            yield argv, stderr, emitted

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux capture/writer fixture requires POSIX paths; Windows native capture is not exercised.')
    def test_valid_worker_shape_remains_observed_even_after_syntax_red(self):
        value, sha, row = self.populated()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'observed.json'
            with self.mocked_declaration_capture(output, identity.canonical(value['probe']['cindex']).encode()) as (
                    argv, stderr, emitted):
                self.assertEqual(identity.main(argv), 2)
                self.assertEqual(stderr.getvalue(), '')
            retained = json.loads(output.read_text())
            self.assertIsNone(retained['probe']['backend_failure'])
            self.assertEqual(retained['probe']['cindex'], json.loads(emitted['stdout']))
            self.assertFalse(self.summary(retained, sha)['syntax_pass'])

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux capture/writer fixture requires POSIX paths; Windows native capture is not exercised.')
    def test_worker_escaped_unicode_error_cannot_leave_empty_red_output(self):
        value, sha, row = self.populated()
        raw = identity.canonical(value['probe']['cindex']).encode()
        for encoded in (b'\\udcff', b'\\ud800'):
            with self.subTest(encoded=encoded), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'failed.json'
                def inject(stdout):
                    marker = b'"library_version":"clang version 22.1.0"'
                    self.assertEqual(stdout.count(marker), 1)
                    return stdout.replace(marker, b'"library_version":"' + encoded + b'"')
                with self.mocked_declaration_capture(output, raw, after_serialization=inject) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv), 2)
                    diagnostic_log = stderr.getvalue()
                retained = json.loads(output.read_text())
                DeclarationResultDiagnosticTests().diagnostic(diagnostic_log, retained['probe']['backend_failure'], 'VALIDATE')
                self.assertIsNone(retained['probe']['cindex'])
                self.assertEqual(retained['probe']['backend_failure']['kind'], 'INVALID_RESULT')
                self.assertEqual(retained['probe']['backend_failure']['stdout'],
                                 {'bytes': len(emitted['stdout']), 'sha256': hashlib.sha256(emitted['stdout']).hexdigest()})
                self.assertEqual(retained['probe']['syntax']['exit_code'], 1)
                self.assertFalse(self.summary(retained, sha)['syntax_pass'])

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux capture/writer fixture requires POSIX paths; Windows native capture is not exercised.')
    def test_malformed_worker_shape_preserves_red_through_actual_capture_writer(self):
        value, sha, row = self.populated()
        nested = copy.deepcopy(value['probe']['cindex'])
        nested['requests'][0]['targets'] = [None]
        bad_inclusion = copy.deepcopy(value['probe']['cindex'])
        bad_inclusion['inclusions'] = [{}]
        for raw in (b'{}', b'null', b'[]', identity.canonical(nested).encode(),
                    identity.canonical(bad_inclusion).encode()):
            with self.subTest(raw=raw[:40]), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'failed.json'
                with self.mocked_declaration_capture(output, raw) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv), 2)
                    diagnostic_log = stderr.getvalue()
                retained = json.loads(output.read_text())
                failure = retained['probe']['backend_failure']
                DeclarationResultDiagnosticTests().diagnostic(diagnostic_log, failure, 'VALIDATE')
                self.assertEqual(failure['kind'], 'INVALID_RESULT')
                self.assertEqual(failure['exit_code'], 0)
                self.assertEqual(failure['stdout'], {'bytes': len(emitted['stdout']),
                                                    'sha256': hashlib.sha256(emitted['stdout']).hexdigest()})
                self.assertIsNone(retained['probe']['cindex'])
                self.assertEqual(retained['probe']['syntax']['exit_code'], 1)
                self.assertEqual(retained['probe']['syntax']['stderr']['sha256'],
                                 hashlib.sha256(b'earlier syntax RED').hexdigest())
                summary = self.summary(retained, sha)
                self.assertFalse(summary['syntax_pass'])
                self.assertTrue(all(r['issues'] == ['BACKEND_FAILED', 'SYNTAX_FAILED'] for r in summary['requests']))

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux capture/writer fixture requires POSIX paths; Windows native capture is not exercised.')
    def test_invalid_worker_result_cannot_mask_independent_identity_drift(self):
        for changed in ('/sdk/stdlib.h', 'source'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'must-not-exist.json'
                with self.mocked_declaration_capture(output, b'{}', changed) as (argv, stderr, emitted):
                    args = SimpleNamespace(root=Path(argv[2]), source_sha=argv[4], libclang=Path(argv[6]), output=output)
                    with self.assertRaisesRegex(ValueError, 'declaration capture ' + (
                            'source/platform' if changed == 'source' else 'bytes') + ' changed'):
                        identity.capture_declarations(args)
                self.assertFalse(output.exists())
                with self.mocked_declaration_capture(output, b'{}', changed) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv), 2)
                    lines = stderr.getvalue().splitlines()
                    self.assertEqual(len(lines), 3)
                    self.assertTrue(lines[0].startswith('DECLARATION_RESULT_DIAGNOSTIC '))
                    self.assertTrue(lines[1].startswith('IDENTITY_INVALID '))
                    self.assertEqual(lines[2], 'DECLARATION_FAILURE_KIND INVALID')
                self.assertFalse(output.exists())

    def test_capture_exception_keeps_fixed_failure_kind_without_private_text(self):
        causes = [(subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30), 'TIMEOUT'),
                  (OSError('PRIVATE_SENTINEL'), 'OS_ERROR'),
                  (ValueError('PRIVATE_SENTINEL'), 'INVALID')]
        for cause, expected in causes:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve() / 'repo'
                root.mkdir()
                output = root.parent / 'declaration.json'
                error = identity.IdentityError('PRIVATE_SENTINEL')
                error.__context__ = cause
                argv = ['capture-declarations', '--root', str(root), '--source-sha', 'a' * 40,
                        '--libclang', '/not-loaded', '--output', str(output)]
                for role in identity.TOOL_ROLES:
                    argv += ['--' + role, '/not-executed']
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(identity, 'capture_declarations', side_effect=error), \
                        mock.patch.object(identity.sys, 'stdout', stdout), \
                        mock.patch.object(identity.sys, 'stderr', stderr), \
                        mock.patch.object(identity.subprocess, 'run') as execute:
                    self.assertEqual(identity.main(argv), 2)
                execute.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(stdout.getvalue(), '')
                self.assertNotIn('PRIVATE_SENTINEL', stderr.getvalue())
                self.assertTrue(stderr.getvalue().startswith('IDENTITY_INVALID '))
                self.assertIn('DECLARATION_FAILURE_KIND ' + expected + '\n', stderr.getvalue())

    def test_capture_rejects_existing_output_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'preserved.json'
            output.write_bytes(b'preserved')
            argv = ['capture-declarations', '--root', str(Path(directory).resolve()), '--source-sha', 'a' * 40,
                    '--libclang', '/not-loaded', '--output', str(output)]
            for role in identity.TOOL_ROLES:
                argv += ['--' + role, '/not-executed']
            with (mock.patch.object(identity, 'capture_declarations', side_effect=AssertionError('collection')),
                  mock.patch('sys.stderr', new_callable=io.StringIO)):
                self.assertEqual(identity.main(argv), 2)
            self.assertEqual(output.read_bytes(), b'preserved')

    def test_fixed_requests_cover_each_applicable_non_sqlite_model(self):
        for system, count in (('Linux', 14), ('Darwin', 14), ('Windows', 13)):
            with self.subTest(system=system):
                rows = identity.declaration_requests(self.model, system)
                self.assertEqual(len(rows), count)
                self.assertEqual(len({r['id'] for r in rows}), count)
                self.assertNotIn('sqlite3.h', {r['header'] for r in rows})
        self.assertEqual(identity.declaration_coverage(self.model),
                         {'required_library_pairs': 50, 'required_entry_pairs': 3,
                          'qualified_library_pairs': 0, 'qualified_entry_pairs': 0})

    def test_source_has_independent_signature_checks_and_no_visibility_macros(self):
        source = identity.declaration_source(self.model, 'Linux')
        self.assertIn('typedef char* (*cs_expected_getenv)(const char*);', source)
        self.assertIn('_Generic(&getenv, cs_expected_getenv: 1, default: 0)', source)
        self.assertIn('__typeof__(&openat) cs_native_openat = &openat;', source)
        self.assertNotIn('#define', source)
        self.assertNotIn('sqlite3.h', source)
        self.assertEqual(source.count('int main('), 1)

    def test_model_drift_and_unknown_platform_are_rejected(self):
        self.model['sources'][1]['symbol'] = 'invented'
        with self.assertRaises(ValueError):
            identity.declaration_requests(self.model, 'Linux')
        with self.assertRaises(ValueError):
            identity.declaration_source(self.model, 'Other')

    def test_command_preserves_observed_target_and_explicit_resource(self):
        compiler = {'file': {'resolved_path': '/usr/bin/clang-22'},
                    'resource_dir': '/usr/lib/clang/22', 'target': 'x86_64-redhat-linux-gnu'}
        command = identity.declaration_command(compiler, 'Linux', {}, '/probe/declarations.c')
        self.assertEqual(command, ['/usr/bin/clang-22', '--no-default-config', '-fno-modules',
            '-resource-dir', '/usr/lib/clang/22', '-x', 'c', '-std=c17',
            '--target=x86_64-redhat-linux-gnu', '-fsyntax-only', '/probe/declarations.c'])
        self.assertEqual(identity.declaration_command(compiler, 'Linux', {}, '/probe/declarations.c', True),
                         command[:-2] + ['-M', '-MT', 'identity-probe', command[-1]])

    def test_type_identity_compares_nested_qualifiers_not_typedef_spelling(self):
        left = {'kind': 'Pointer', 'spelling': 'alias', 'canonical_spelling': 'const char *',
                'qualifiers': {'const': False, 'volatile': False, 'restrict': False},
                'canonical_qualifiers': {'const': False, 'volatile': False, 'restrict': False},
                'detail': {'pointee': {'kind': 'Char_S', 'spelling': 'char',
                    'canonical_spelling': 'const char', 'qualifiers': {'const': True},
                    'canonical_qualifiers': {'const': True}, 'detail': None}}}
        right = copy.deepcopy(left)
        right['spelling'] = 'another_alias'
        self.assertEqual(identity.declaration_type_key(left), identity.declaration_type_key(right))
        right['detail']['pointee']['canonical_qualifiers']['const'] = False
        self.assertNotEqual(identity.declaration_type_key(left), identity.declaration_type_key(right))


class DeclarationWorkerDiagnosticTests(unittest.TestCase):
    MARKER = b'DECLARATION_WORKER_INVALID case observation rejected; checks='
    KIND = b'DECLARATION_WORKER_FAILURE_KIND '
    LOG = 'DECLARATION_WORKER_DIAGNOSTIC '

    def child_stderr(self, checks=b'identity:123,profile:456', kind=b'INVALID', newline=b'\n'):
        return self.MARKER + checks + newline + self.KIND + kind + newline

    def run_worker(self, result):
        options = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
        captured, callback = io.StringIO(), mock.Mock()
        with mock.patch.object(identity.subprocess, 'run', **options) as execute, \
                mock.patch.object(identity.sys, 'stderr', captured):
            observed, failure = identity.run_declaration_worker({}, callback)
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[0],
                         [sys.executable, '-B', str(Path(identity.__file__).resolve()), '_declaration-worker'])
        self.assertEqual(execute.call_args.kwargs, {'input': identity.canonical({}).encode(),
                         'env': identity.checked_environment(identity.os.environ), 'capture_output': True,
                         'timeout': 30, 'check': False})
        return observed, failure, captured.getvalue(), callback

    def diagnostic(self, log):
        self.assertTrue(log.startswith(self.LOG), 'missing sanitized parent worker diagnostic')
        self.assertEqual(len(log.splitlines()), 1)
        value = json.loads(log[len(self.LOG):])
        self.assertEqual(set(value), {'schema', 'origin', 'child_failure_kind', 'checks', 'parent_failure'})
        self.assertEqual(value['schema'], 'codeskeptic-declaration-worker-diagnostic/v1')
        return value

    def test_child_reported_provenance_and_category_keep_exact_parent_failure(self):
        for newline in (b'\n', b'\r\n'):
            for kind in (b'TIMEOUT', b'OS_ERROR', b'INVALID'):
                stderr = self.child_stderr(kind=kind, newline=newline)
                with self.subTest(kind=kind, newline=newline):
                    observed, failure, log, callback = self.run_worker(SimpleNamespace(
                        returncode=2, stdout=b'', stderr=stderr))
                    callback.assert_not_called()
                    self.assertIsNone(observed)
                    self.assertEqual(failure, {'kind': 'PROCESS_FAILED', 'exit_code': 2,
                        'stdout': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()},
                        'stderr': {'bytes': len(stderr), 'sha256': hashlib.sha256(stderr).hexdigest()}})
                    diagnostic = self.diagnostic(log)
                    self.assertEqual(diagnostic['parent_failure'], failure)
                    self.assertEqual(diagnostic['origin'], 'CHILD_REPORTED')
                    self.assertEqual(diagnostic['checks'], ['identity:123', 'profile:456'])
                    self.assertEqual(diagnostic['child_failure_kind'], kind.decode())

    def test_unknown_and_maximum_allowed_check_count(self):
        for raw, checks in ((b'unknown', []), (b','.join([b'identity:999999'] * 24), ['identity:999999'] * 24)):
            observed, failure, log, callback = self.run_worker(SimpleNamespace(
                returncode=2, stdout=b'', stderr=self.child_stderr(checks=raw)))
            callback.assert_not_called()
            diagnostic = self.diagnostic(log)
            self.assertEqual(diagnostic['origin'], 'CHILD_REPORTED')
            self.assertEqual(diagnostic['checks'], checks)

    def test_private_malformed_conflicting_and_oversized_child_text_is_not_echoed(self):
        good = self.child_stderr()
        cases = [b'', b'PRIVATE_SENTINEL', b'\xef\xbb\xbf' + good, good + b'PRIVATE_SENTINEL\n',
                 b'PRIVATE_SENTINEL\n' + good, good + good, good.replace(b'identity:', b'private:'),
                 good.replace(b'123', b'0'), good.replace(b'123', b'000123'),
                 good.replace(b'123', b'1234567'), good.replace(b'INVALID', b'\x1b[31mINVALID', 1),
                 good.replace(b'profile', b'pr\xc3\xb6file'), good.replace(b'checks=', b'checks= '),
                 self.child_stderr(kind=b'PRIVATE_SENTINEL'), self.child_stderr(checks=b'unknown,identity:1'),
                 self.child_stderr(checks=b','.join([b'identity:1'] * 25)),
                 self.child_stderr(checks=b'x' * 4096), self.MARKER + b'identity:1\n', good[:-1],
                 good.replace(b'\n', b'\r'), good.replace(b'checks=', b'checks=\x00')]
        for stderr in cases:
            with self.subTest(stderr=stderr[:32]):
                _, failure, log, callback = self.run_worker(SimpleNamespace(returncode=2, stdout=b'', stderr=stderr))
                callback.assert_not_called()
                diagnostic = self.diagnostic(log)
                self.assertEqual(diagnostic['parent_failure'], failure)
                self.assertEqual(diagnostic['origin'], 'UNRECOGNIZED')
                self.assertEqual(diagnostic['checks'], [])
                self.assertIsNone(diagnostic['child_failure_kind'])
                self.assertNotIn('PRIVATE_SENTINEL', log)
                self.assertNotIn('\x1b', log)
                self.assertTrue(log.isascii())

    def test_marker_cannot_claim_child_handler_with_wrong_exit_or_partial_stdout(self):
        for code, stdout in ((-11, b''), (1, b''), (2, b'PRIVATE_SENTINEL')):
            with self.subTest(code=code):
                _, failure, log, callback = self.run_worker(SimpleNamespace(
                    returncode=code, stdout=stdout, stderr=self.child_stderr()))
                callback.assert_not_called()
                diagnostic = self.diagnostic(log)
                self.assertEqual(diagnostic['origin'], 'UNRECOGNIZED')
                self.assertIsNone(diagnostic['child_failure_kind'])
                self.assertEqual(diagnostic['checks'], [])
                self.assertEqual(diagnostic['parent_failure'], failure)
                self.assertNotIn('PRIVATE_SENTINEL', log)

    def test_other_classifications_and_success_do_not_emit_child_diagnostics(self):
        for result, kind in ((subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30, stderr=self.child_stderr()), 'TIMEOUT'),
                             (OSError('PRIVATE_SENTINEL'), 'START_FAILED'),
                             (SimpleNamespace(returncode=0, stdout=b'{}', stderr=self.child_stderr()), 'INVALID_RESULT'),
                             (SimpleNamespace(returncode=0, stdout=b'not-json', stderr=b''), 'INVALID_RESULT'),
                             (SimpleNamespace(returncode=2, stdout=b'x' * (identity.MAX_OUTPUT + 1),
                                              stderr=self.child_stderr()), 'OUTPUT_LIMIT')):
            with self.subTest(kind=kind):
                observed, failure, log, callback = self.run_worker(result)
                callback.assert_not_called()
                self.assertEqual(failure['kind'], kind)
                self.assertIsNone(observed)
                self.assertNotIn(self.LOG, log)
                if kind == 'INVALID_RESULT':
                    DeclarationResultDiagnosticTests().diagnostic(log, failure,
                        'NONEMPTY_STDERR' if result.stderr else 'PARSE')
                else:
                    self.assertEqual(log, '')
        observed, failure, log, callback = self.run_worker(SimpleNamespace(returncode=0, stdout=b'{}', stderr=b''))
        callback.assert_called_once_with({})
        self.assertEqual((observed, failure, log), ({}, None, ''))

    def test_child_handler_emits_only_fixed_categories_and_allowlisted_provenance(self):
        for cause, kind in ((subprocess.TimeoutExpired('PRIVATE_SENTINEL', 30), 'TIMEOUT'),
                            (OSError('PRIVATE_SENTINEL'), 'OS_ERROR'), (ValueError('PRIVATE_SENTINEL'), 'INVALID')):
            error = identity.IdentityError('PRIVATE_SENTINEL')
            error.__context__ = cause
            stdin, stdout, stderr = SimpleNamespace(buffer=io.BytesIO(b'{}')), io.StringIO(), io.StringIO()
            with self.subTest(kind=kind), mock.patch.object(identity, 'declaration_worker', side_effect=error), \
                    mock.patch.object(identity.sys, 'stdin', stdin), mock.patch.object(identity.sys, 'stdout', stdout), \
                    mock.patch.object(identity.sys, 'stderr', stderr), mock.patch.object(identity.subprocess, 'run') as execute:
                self.assertEqual(identity.main(['_declaration-worker']), 2)
            execute.assert_not_called()
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn('PRIVATE_SENTINEL', stderr.getvalue())
            self.assertEqual(len(stderr.getvalue().splitlines()), 2)
            self.assertIn('DECLARATION_WORKER_FAILURE_KIND ' + kind + '\n', stderr.getvalue())
            _, failure, log, callback = self.run_worker(SimpleNamespace(returncode=2, stdout=b'',
                                                                       stderr=stderr.getvalue().encode()))
            callback.assert_not_called()
            self.assertEqual(self.diagnostic(log)['child_failure_kind'], kind)
            self.assertEqual(failure['kind'], 'PROCESS_FAILED')

    def test_parent_diagnostic_write_failure_cannot_replace_process_failure(self):
        raw = self.child_stderr()
        for error in (OSError('PRIVATE_SENTINEL'), ValueError('PRIVATE_SENTINEL')):
            broken = mock.Mock()
            broken.write.side_effect = error
            callback = mock.Mock()
            with self.subTest(error=type(error).__name__), mock.patch.object(identity.sys, 'stderr', broken), \
                    mock.patch.object(identity.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=2, stdout=b'', stderr=raw)) as execute:
                observed, failure = identity.run_declaration_worker({}, callback)
            execute.assert_called_once()
            callback.assert_not_called()
            broken.write.assert_called()
            self.assertIsNone(observed)
            self.assertEqual((failure['kind'], failure['exit_code']), ('PROCESS_FAILED', 2))
            self.assertEqual(failure['stderr'], {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def test_optional_child_kind_write_failure_keeps_original_exit_two(self):
        error = identity.IdentityError('PRIVATE_SENTINEL')
        for write_error in (OSError('PRIVATE_SENTINEL'), ValueError('PRIVATE_SENTINEL')):
            with self.subTest(error=type(write_error).__name__), \
                    mock.patch.object(identity.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'{}'))), \
                    mock.patch.object(identity, 'declaration_worker', side_effect=error), \
                    mock.patch('builtins.print', side_effect=[None, write_error]) as output:
                self.assertEqual(identity.main(['_declaration-worker']), 2)
            self.assertEqual(output.call_count, 2)
            self.assertTrue(output.call_args_list[0].args[0].startswith('DECLARATION_WORKER_INVALID '))
            self.assertEqual(output.call_args_list[1].args[0], 'DECLARATION_WORKER_FAILURE_KIND INVALID')

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux writer fixture requires POSIX paths, not native Windows evidence.')
    def test_diagnostic_does_not_change_written_packet_or_syntax_red(self):
        fixture = DeclarationTests()
        fixture.setUp()
        for syntax_exit in (0, 1):
            for raw_stderr in (self.child_stderr(kind=b'TIMEOUT'), b'PRIVATE_SENTINEL'):
                with self.subTest(syntax_exit=syntax_exit), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory).resolve() / 'failed.json'
                    worker = SimpleNamespace(returncode=2, stdout=b'', stderr=raw_stderr)
                    with fixture.mocked_declaration_capture(output, b'', syntax_exit=syntax_exit,
                                                            worker_result=worker) as (argv, stderr, emitted):
                        self.assertEqual(identity.main(argv), 2)
                        diagnostic = self.diagnostic(stderr.getvalue())
                    retained = json.loads(output.read_bytes())
                    self.assertNotIn('diagnostic', retained)
                    self.assertEqual(set(retained['probe']), {'input', 'dependency', 'headers', 'syntax', 'cindex', 'backend_failure'})
                    self.assertEqual(retained['probe']['backend_failure'], diagnostic['parent_failure'])
                    self.assertEqual(retained['probe']['syntax']['exit_code'], syntax_exit)
                    self.assertIsNone(retained['probe']['cindex'])
                    checked = fixture.summary(retained, identity.declaration_model(Path(identity.__file__).resolve().parents[1])[1])
                    self.assertTrue(all(row['issues'] == ['BACKEND_FAILED'] + (['SYNTAX_FAILED'] if syntax_exit else [])
                                        for row in checked['requests']))
                    self.assertTrue(all(checked[key] is False for key in ('syntax_pass', 'native_qualified', 'task_ready', 'product_qualified')))
                    self.assertNotIn('PRIVATE_SENTINEL', output.read_text())

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux writer fixture requires POSIX paths, not native Windows evidence.')
    def test_diagnostic_cannot_mask_independent_parent_identity_drift(self):
        fixture = DeclarationTests()
        fixture.setUp()
        for changed in ('/sdk/stdlib.h', 'source'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'must-not-exist.json'
                worker = SimpleNamespace(returncode=2, stdout=b'', stderr=self.child_stderr())
                with fixture.mocked_declaration_capture(output, b'', changed=changed,
                                                        worker_result=worker) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv), 2)
                    self.assertIn(self.LOG, stderr.getvalue())
                    self.assertIn('IDENTITY_INVALID ', stderr.getvalue())
                self.assertFalse(output.exists())


class DeclarationResultDiagnosticTests(unittest.TestCase):
    LOG = 'DECLARATION_RESULT_DIAGNOSTIC '

    def run_result(self, stdout=b'{}', stderr=b'', code=0, validator=None):
        result = SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        output = io.StringIO()
        callback = validator if validator is not None else mock.Mock()
        with ExitStack() as stack:
            execute = stack.enter_context(mock.patch.object(identity.subprocess, 'run', return_value=result))
            stack.enter_context(mock.patch.object(identity.sys, 'stderr', output))
            observed, failure = identity.run_declaration_worker({}, callback)
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args, ([sys.executable, '-B',
            str(Path(identity.__file__).resolve()), '_declaration-worker'],))
        self.assertEqual(execute.call_args.kwargs, {'input': b'{}\n',
            'env': identity.checked_environment(identity.os.environ), 'capture_output': True,
            'timeout': 30, 'check': False})
        self.assertEqual(execute.call_args.kwargs['timeout'], 30)
        return observed, failure, output.getvalue(), callback

    def diagnostic(self, log, failure, phase):
        self.assertTrue(log.startswith(self.LOG), 'missing parent result diagnostic')
        self.assertEqual(len(log.splitlines()), 1)
        self.assertTrue(log.isascii())
        self.assertLessEqual(len(log), 1024)
        value = json.loads(log[len(self.LOG):])
        self.assertEqual(set(value), {'schema', 'origin', 'phase', 'checks', 'parent_failure'})
        self.assertEqual(value['schema'], 'codeskeptic-declaration-result-diagnostic/v1')
        self.assertEqual(value['origin'], 'PARENT_REPORTED')
        self.assertEqual(value['phase'], phase)
        self.assertEqual(value['parent_failure'], failure)
        self.assertLessEqual(len(value['checks']), 24)
        for check in value['checks']:
            self.assertRegex(check, r'^(identity|profile):[1-9][0-9]{0,5}$')
        return value

    def test_decode_parse_validate_and_serialization_rejections_are_distinct(self):
        for phase in ('DECODE', 'PARSE', 'VALIDATE', 'SERIALIZE'):
            with self.subTest(phase=phase):
                callback = mock.Mock()
                stdout = b'\xff' if phase == 'DECODE' else b'PRIVATE_SENTINEL' if phase == 'PARSE' else b'{}'
                if phase == 'VALIDATE':
                    callback.side_effect = lambda _: identity.require(False, 'PRIVATE_SENTINEL /private/path')
                if phase == 'SERIALIZE':
                    def cyclic(value):
                        value['PRIVATE_SENTINEL'] = value
                    callback.side_effect = cyclic
                observed, failure, log, _ = self.run_result(stdout=stdout, validator=callback)
                self.assertIsNone(observed)
                self.assertEqual(failure, {'kind': 'INVALID_RESULT', 'exit_code': 0,
                    'stdout': {'bytes': len(stdout), 'sha256': hashlib.sha256(stdout).hexdigest()},
                    'stderr': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}})
                value = self.diagnostic(log, failure, phase)
                self.assertTrue(value['checks'])
                self.assertNotIn('PRIVATE_SENTINEL', log)
                self.assertNotIn('/private/path', log)
                if phase in ('DECODE', 'PARSE'):
                    callback.assert_not_called()
                else:
                    callback.assert_called_once()

    def test_nonempty_stderr_has_no_exception_hints_or_raw_content(self):
        observed, failure, log, callback = self.run_result(stdout=b'{}', stderr=b'PRIVATE_SENTINEL\x1b[31m')
        self.assertIsNone(observed)
        callback.assert_not_called()
        value = self.diagnostic(log, failure, 'NONEMPTY_STDERR')
        self.assertEqual(value['checks'], [])
        self.assertNotIn('PRIVATE_SENTINEL', log)
        self.assertNotIn('\\u001b', log)

    def test_duplicate_json_and_surrogate_serialization_keep_existing_rejection(self):
        for raw, phase in ((b'{"a":1,"a":2}', 'PARSE'), (b'"\\udcff"', 'SERIALIZE')):
            with self.subTest(phase=phase):
                observed, failure, log, _ = self.run_result(stdout=raw)
                self.assertIsNone(observed)
                self.diagnostic(log, failure, phase)

    def test_serialization_size_guard_is_reported_without_relaxation(self):
        def expand(value):
            value['payload'] = 'x' * identity.MAX_OUTPUT
        observed, failure, log, _ = self.run_result(validator=expand)
        self.assertIsNone(observed)
        self.diagnostic(log, failure, 'SERIALIZE')

    def test_source_hint_is_allowlisted_bounded_and_never_echoes_forgery(self):
        for hint, expected in (([], []),
            (['identity:1', 'profile:999999'], ['identity:1', 'profile:999999']),
            (['identity:999999'] * 24, ['identity:999999'] * 24),
            (['identity:1'] * 25, []), (['identity:0'], []), (['identity:1000000'], []),
            (['private:2'], []), (['identity:2\nPRIVATE_SENTINEL'], []),
            ('PRIVATE_SENTINEL', []), (['é' * 1100], []), ([None], []), (None, [])):
            with self.subTest(hint=repr(hint)[:60]), mock.patch.object(
                    identity, 'declaration_result_checks', return_value=hint, create=True):
                _, failure, log, _ = self.run_result(stdout=b'bad JSON')
                self.assertEqual(self.diagnostic(log, failure, 'PARSE')['checks'], expected)
                self.assertNotIn('PRIVATE_SENTINEL', log)

    def test_source_hint_or_log_failure_cannot_relabel_original_result(self):
        expected = {'kind': 'INVALID_RESULT', 'exit_code': 0,
            'stdout': {'bytes': 3, 'sha256': hashlib.sha256(b'bad').hexdigest()},
            'stderr': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}}
        for error in (OSError('PRIVATE_SENTINEL'), ValueError('PRIVATE_SENTINEL'),
                      TypeError('PRIVATE_SENTINEL'), RuntimeError('PRIVATE_SENTINEL')):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(identity, 'declaration_result_checks', side_effect=error, create=True):
                observed, failure, log, _ = self.run_result(stdout=b'bad')
                self.assertIsNone(observed)
                self.assertEqual(failure, expected)
                self.assertNotIn('PRIVATE_SENTINEL', log)
        for error in (OSError('PRIVATE_SENTINEL'), ValueError('PRIVATE_SENTINEL')):
            broken = mock.Mock()
            broken.write.side_effect = error
            with mock.patch.object(identity.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=b'bad', stderr=b'')) as execute, \
                    mock.patch.object(identity.sys, 'stderr', broken):
                observed, failure = identity.run_declaration_worker({}, mock.Mock())
            execute.assert_called_once()
            broken.write.assert_called()
            self.assertIsNone(observed)
            self.assertEqual(failure, expected)

    def test_diagnostic_serialization_failure_does_not_erase_original_streams(self):
        original = identity.canonical
        for error in (OSError('PRIVATE_SENTINEL'), ValueError('PRIVATE_SENTINEL'),
                      TypeError('PRIVATE_SENTINEL'), RuntimeError('PRIVATE_SENTINEL')):
            serialized = []
            def canonical(value):
                if type(value) is dict and value.get('schema') == 'codeskeptic-declaration-result-diagnostic/v1':
                    serialized.append(value)
                    raise error
                return original(value)
            with self.subTest(error=type(error).__name__), mock.patch.object(identity, 'canonical', side_effect=canonical):
                observed, failure, log, _ = self.run_result(stdout=b'PRIVATE_SENTINEL')
            self.assertEqual(len(serialized), 1)
            self.assertIsNone(observed)
            self.assertEqual(serialized[0]['parent_failure'], failure)
            self.assertEqual(failure['kind'], 'INVALID_RESULT')
            self.assertEqual(failure['stdout'], {'bytes': 16, 'sha256': hashlib.sha256(b'PRIVATE_SENTINEL').hexdigest()})
            self.assertEqual(log, '')

    def test_actual_traceback_traversal_has_context_frame_and_hint_limits(self):
        inspected = []
        class Frame:
            def __init__(self, filename, line, following=None):
                self.filename, self.tb_lineno, self.tb_next = filename, line, following
            @property
            def tb_frame(self):
                inspected.append(self.tb_lineno)
                return SimpleNamespace(f_code=SimpleNamespace(co_filename=self.filename))
        def frames(count, filename, following=None):
            for line in reversed(range(1, count + 1)):
                following = Frame(filename, line, following)
            return following
        def error(traceback, context=None):
            return SimpleNamespace(__traceback__=traceback, __context__=context)
        own = identity.__file__
        profile = str(Path(own).with_name('product_profiles.py'))
        self.assertEqual(identity.declaration_result_checks(error(Frame(profile, 999999))), ['profile:999999'])
        for line in (0, -1, 1000000, True, '12'):
            self.assertEqual(identity.declaration_result_checks(error(Frame(own, line))), [])
        self.assertEqual(identity.declaration_result_checks(error(Frame(own + '.PRIVATE_SENTINEL', 1))), [])
        inspected.clear()
        self.assertEqual(identity.declaration_result_checks(error(frames(25, own))),
                         ['identity:' + str(line) for line in range(1, 25)])
        self.assertEqual(len(inspected), 24)
        for ineligible, expected in ((63, ['identity:7']), (64, []), (1000, [])):
            inspected.clear()
            self.assertEqual(identity.declaration_result_checks(error(
                frames(ineligible, 'PRIVATE_SENTINEL', Frame(own, 7)))), expected)
            self.assertEqual(len(inspected), 64)
        context = None
        for line in reversed(range(1, 10)):
            context = error(Frame(own, line), context)
        self.assertEqual(identity.declaration_result_checks(context), ['identity:' + str(line) for line in range(1, 9)])
        context.__context__ = context
        self.assertEqual(identity.declaration_result_checks(context), ['identity:1'])
        frame = Frame('PRIVATE_SENTINEL', 1)
        frame.tb_next = frame
        inspected.clear()
        self.assertEqual(identity.declaration_result_checks(error(frame)), [])
        self.assertEqual(len(inspected), 64)
        context = None
        for _ in range(8):
            context = error(frames(10, 'PRIVATE_SENTINEL'), context)
        inspected.clear()
        self.assertEqual(identity.declaration_result_checks(context), [])
        self.assertEqual(len(inspected), 64)

    def test_exact_serialized_byte_boundary_and_one_byte_over(self):
        for extra in (0, 1):
            def expand(value):
                value['payload'] = 'x' * (64 - len(identity.canonical({'payload': ''}).encode()) + extra)
            with self.subTest(extra=extra), mock.patch.object(identity, 'MAX_OUTPUT', 64):
                observed, failure, log, _ = self.run_result(validator=expand)
            if extra:
                self.assertIsNone(observed)
                self.diagnostic(log, failure, 'SERIALIZE')
            else:
                self.assertIsNone(failure)
                self.assertEqual(len(identity.canonical(observed).encode()), 64)
                self.assertEqual(log, '')

    def test_stderr_and_output_limit_precedence_do_not_trust_child_markers(self):
        child = DeclarationWorkerDiagnosticTests().child_stderr()
        _, failure, log, callback = self.run_result(stdout=b'\xff', stderr=child)
        self.assertEqual(self.diagnostic(log, failure, 'NONEMPTY_STDERR')['checks'], [])
        callback.assert_not_called()
        self.assertNotIn('CHILD_REPORTED', log)
        for code in (0, 2):
            _, failure, log, callback = self.run_result(stderr=b'x' * (identity.MAX_OUTPUT + 1), code=code)
            self.assertEqual(failure['kind'], 'OUTPUT_LIMIT')
            self.assertEqual(log, '')
            callback.assert_not_called()

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux writer fixture requires POSIX paths, not native Windows evidence.')
    def test_parent_diagnostic_preserves_actual_writer_packet_and_syntax_red(self):
        fixture = DeclarationTests()
        fixture.setUp()
        cases = ((b'\xff', b'', 'DECODE'), (b'PRIVATE_SENTINEL', b'', 'PARSE'),
                 (b'{}', b'', 'VALIDATE'), (b'{}', b'PRIVATE_SENTINEL', 'NONEMPTY_STDERR'))
        for syntax_exit in (0, 1):
            for stdout, stderr, phase in cases:
                with self.subTest(syntax_exit=syntax_exit, phase=phase), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory).resolve() / 'failed.json'
                    worker = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
                    with fixture.mocked_declaration_capture(output, b'', syntax_exit=syntax_exit,
                            worker_result=worker) as (argv, log, emitted):
                        self.assertEqual(identity.main(argv), 2)
                        raw_log = log.getvalue()
                    retained = json.loads(output.read_bytes())
                    self.diagnostic(raw_log, retained['probe']['backend_failure'], phase)
                    self.assertNotIn('diagnostic', retained)
                    self.assertEqual(set(retained['probe']), {'input', 'dependency', 'headers', 'syntax', 'cindex', 'backend_failure'})
                    self.assertIsNone(retained['probe']['cindex'])
                    self.assertEqual(retained['probe']['syntax']['exit_code'], syntax_exit)
                    self.assertEqual(retained['probe']['syntax']['stderr']['sha256'],
                        hashlib.sha256(b'earlier syntax RED' if syntax_exit else b'').hexdigest())
                    summary = fixture.summary(retained, identity.declaration_model(Path(identity.__file__).resolve().parents[1])[1])
                    self.assertTrue(all(row['issues'] == ['BACKEND_FAILED'] + (['SYNTAX_FAILED'] if syntax_exit else [])
                                        for row in summary['requests']))
                    self.assertTrue(all(summary[key] is False for key in ('syntax_pass', 'native_qualified', 'task_ready', 'product_qualified')))
                    self.assertNotIn('PRIVATE_SENTINEL', raw_log + output.read_text())

    def test_success_other_failure_classes_and_child_marker_stay_separate(self):
        observed, failure, log, callback = self.run_result(stdout=b'{"good":true}')
        self.assertEqual(observed, {'good': True})
        self.assertIsNone(failure)
        self.assertEqual(log, '')
        callback.assert_called_once()
        _, failure, log, callback = self.run_result(stdout=b'{}', code=2)
        self.assertEqual(failure['kind'], 'PROCESS_FAILED')
        self.assertTrue(log.startswith('DECLARATION_WORKER_DIAGNOSTIC '))
        self.assertNotIn(self.LOG, log)
        callback.assert_not_called()
        _, failure, log, callback = self.run_result(stdout=b'x' * (identity.MAX_OUTPUT + 1))
        self.assertEqual(failure['kind'], 'OUTPUT_LIMIT')
        self.assertEqual(log, '')
        callback.assert_not_called()

    def test_existing_outer_oserror_and_uncaught_validator_errors_are_unchanged(self):
        _, failure, log, _ = self.run_result(validator=mock.Mock(side_effect=OSError('PRIVATE_SENTINEL')))
        self.assertEqual(failure, {'kind': 'START_FAILED', 'exit_code': None,
            'stdout': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()},
            'stderr': {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}})
        self.assertEqual(log, '')
        with self.assertRaises(RuntimeError):
            self.run_result(validator=mock.Mock(side_effect=RuntimeError('PRIVATE_SENTINEL')))


class DeclarationInclusionDiagnosticTests(unittest.TestCase):
    LOG = 'DECLARATION_INCLUSION_DIAGNOSTIC '

    def setUp(self):
        self.fixture = DeclarationTests()
        self.fixture.setUp()

    def packet(self, inclusions, paths=None, system='Linux'):
        value, _ = self.fixture.packet()
        value['native_identity']['platform']['system'] = system
        value['probe']['cindex']['inclusions'] = inclusions
        if paths is not None:
            value['probe']['headers'] = [{'path': path, 'resolved_path': path,
                'bytes': 1, 'sha256': 'b' * 64} for path in paths]
        return value

    def validate(self, value, observed):
        return identity.validate_declaration_observation(observed, self.fixture.model,
                                                        value['native_identity'], value['probe'])

    def run_packet(self, value):
        raw = identity.canonical(value['probe']['cindex']).encode()
        result = DeclarationResultDiagnosticTests().run_result(stdout=raw,
            validator=lambda observed: self.validate(value, observed))
        return result[:3]

    def diagnostic(self, log, failure, reason, headers):
        lines = log.splitlines(keepends=True)
        self.assertEqual(len(lines), 2, 'missing bounded inclusion diagnostic')
        DeclarationResultDiagnosticTests().diagnostic(lines[0], failure, 'VALIDATE')
        self.assertTrue(lines[1].startswith(self.LOG))
        self.assertTrue(lines[1].isascii())
        self.assertLessEqual(len(lines[1]), 4096)
        value = json.loads(lines[1][len(self.LOG):])
        self.assertEqual(set(value), {'schema', 'origin', 'guard', 'system', 'status',
            'reason', 'header_array_sha256', 'details', 'parent_failure'})
        self.assertEqual(value['schema'], 'codeskeptic-declaration-inclusion-diagnostic/v1')
        self.assertEqual(value['origin'], 'PARENT_REPORTED')
        self.assertEqual(value['guard'], 'CINDEX_INCLUDE_CLOSURE')
        self.assertEqual(value['parent_failure'], failure)
        self.assertEqual(value['reason'], reason)
        self.assertEqual(value['status'], 'UNAVAILABLE' if reason == 'INPUT_BUDGET_OR_SHAPE' else 'AVAILABLE')
        if headers is not None:
            self.assertEqual(value['header_array_sha256'],
                hashlib.sha256(identity.canonical(headers).encode()).hexdigest())
        return value

    def test_each_guard_conjunct_reports_only_its_first_failure(self):
        for inclusions, reason in ((None, 'NOT_LIST'),
                (['/sdk/stdlib.h', '/probe/declarations.c'], 'NOT_SORTED_UNIQUE'),
                (['/probe/declarations.c', '/probe/declarations.c', '/sdk/stdlib.h'], 'NOT_SORTED_UNIQUE'),
                (['/probe/declarations.c'], 'PATH_SET_MISMATCH')):
            with self.subTest(reason=reason, inclusions=inclusions):
                value = self.packet(inclusions)
                observed, failure, log = self.run_packet(value)
                self.assertIsNone(observed)
                self.assertEqual(failure['kind'], 'INVALID_RESULT')
                self.assertEqual(failure['exit_code'], 0)
                raw = identity.canonical(value['probe']['cindex']).encode()
                self.assertEqual(failure['stdout'], {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                report = self.diagnostic(log, failure, reason, value['probe']['headers'])
                if reason != 'PATH_SET_MISMATCH':
                    self.assertIsNone(report['details'])

    def test_mismatch_indices_are_bound_to_ordered_headers_without_raw_paths(self):
        paths = ['/PRIVATE_SENTINEL/z.h', '/PRIVATE_SENTINEL/a.h', '/PRIVATE_SENTINEL/b.h']
        value = self.packet(['/PRIVATE_SENTINEL/a.h', '/PRIVATE_SENTINEL/extra.h'], paths)
        _, failure, log = self.run_packet(value)
        report = self.diagnostic(log, failure, 'PATH_SET_MISMATCH', value['probe']['headers'])
        details = report['details']
        expected_hash = hashlib.sha256(identity.canonical(
            ['codeskeptic-purepath-key/v1', 'Linux', '/PRIVATE_SENTINEL/extra.h']).encode()).hexdigest()
        self.assertEqual(details, {'path_key_schema': 'codeskeptic-purepath-key/v1',
            'expected_paths': 3, 'observed_paths': 2, 'missing_paths': 2,
            'missing_header_indices': [0, 2], 'missing_indices_truncated': False,
            'unexpected_paths': 1, 'unexpected_path_sha256': [expected_hash], 'unexpected_hashes_truncated': False})
        self.assertNotIn('PRIVATE_SENTINEL', log)
        before = report['header_array_sha256']
        value['probe']['headers'].reverse()
        _, failure, log = self.run_packet(value)
        report = self.diagnostic(log, failure, 'PATH_SET_MISMATCH', value['probe']['headers'])
        self.assertNotEqual(report['header_array_sha256'], before)
        self.assertEqual(report['details']['missing_header_indices'], [0, 2])

    def test_missing_extra_and_duplicate_normalized_headers_have_exact_counts(self):
        for included, expected in (([], (1, 0, [0, 1])),
                (['C:/SDK/a.h', 'C:/SDK/extra.h'], (0, 1, [])),
                (['C:/SDK/extra.h'], (1, 1, [0, 1]))):
            value = self.packet(included, ['C:/SDK/a.h', 'c:\\sdk\\a.h'], 'Windows')
            _, failure, log = self.run_packet(value)
            details = self.diagnostic(log, failure, 'PATH_SET_MISMATCH', value['probe']['headers'])['details']
            self.assertEqual(details['expected_paths'], 1)
            self.assertEqual((details['missing_paths'], details['unexpected_paths'],
                              details['missing_header_indices']), expected)

    def test_path_keys_follow_purepath_not_filesystem_or_casefold(self):
        pairs = (('Windows', 'C:/SDK/./A.h', 'c:\\sdk\\a.h', True),
                 ('Windows', 'C:/SDK/ß.h', 'c:/sdk/ss.h', False),
                 ('Windows', 'C:/SDK/a/../b.h', 'C:/SDK/b.h', False),
                 ('Windows', 'C:SDK/a.h', 'C:/SDK/a.h', False),
                 ('Windows', '\\\\?\\C:\\SDK\\a.h', 'C:/SDK/a.h', False),
                 ('Linux', '/sdk/./a.h', '/sdk/a.h', True),
                 ('Linux', '/sdk/A.h', '/sdk/a.h', False),
                 ('Darwin', '/sdk/A.h', '/sdk/a.h', False))
        for system, expected, observed, equal in pairs:
            with self.subTest(system=system, expected=expected, observed=observed):
                value = self.packet(sorted([observed, '/always-extra']), [expected], system)
                _, failure, log = self.run_packet(value)
                details = self.diagnostic(log, failure, 'PATH_SET_MISMATCH', value['probe']['headers'])['details']
                self.assertEqual(details['missing_paths'], int(not equal))
                self.assertEqual(details['unexpected_paths'], 1 if equal else 2)
                rendered = str(identity.PureWindowsPath(observed)).lower() if system == 'Windows' else str(identity.PurePosixPath(observed))
                hashed = hashlib.sha256(identity.canonical(['codeskeptic-purepath-key/v1', system, rendered]).encode()).hexdigest()
                self.assertEqual(hashed in details['unexpected_path_sha256'], not equal)

    def test_report_caps_do_not_truncate_counts(self):
        value = self.packet(['/extra/' + str(n) for n in range(10)],
                            ['/expected/' + str(n) for n in range(40)])
        value['probe']['cindex']['inclusions'].sort()
        _, failure, log = self.run_packet(value)
        details = self.diagnostic(log, failure, 'PATH_SET_MISMATCH', value['probe']['headers'])['details']
        self.assertEqual(details['missing_paths'], 40)
        self.assertEqual(details['missing_header_indices'], list(range(32)))
        self.assertTrue(details['missing_indices_truncated'])
        self.assertEqual(details['unexpected_paths'], 10)
        self.assertEqual(len(details['unexpected_path_sha256']), 8)
        self.assertEqual(details['unexpected_path_sha256'], sorted(details['unexpected_path_sha256']))
        self.assertTrue(details['unexpected_hashes_truncated'])

    def test_budget_or_shape_is_unavailable_not_a_guessed_difference(self):
        for inclusions in ([str(n) for n in range(4097)], ['x' * 8193], ['\udcff'],
                           ['x' * 8192] * 257):
            value = self.packet(inclusions)
            with self.assertRaises(identity.IdentityError) as caught:
                self.validate(value, value['probe']['cindex'])
            report = identity.declaration_inclusion_diagnostic(caught.exception, {})
            self.assertEqual(report['status'], 'UNAVAILABLE')
            self.assertEqual(report['reason'], 'INPUT_BUDGET_OR_SHAPE')
            self.assertIsNone(report['details'])

    def test_only_actual_guard_rejection_is_annotated(self):
        value = self.packet([])
        original_require = identity.require
        raised = []
        def require(condition, message):
            if not condition and message == 'CIndex include closure':
                error = identity.IdentityError(message)
                raised.append(error)
                raise error
            return original_require(condition, message)
        with mock.patch.object(identity, 'require', side_effect=require), self.assertRaises(identity.IdentityError) as caught:
            self.validate(value, value['probe']['cindex'])
        self.assertIs(caught.exception, raised[0])
        self.assertIs(type(caught.exception), identity.IdentityError)
        self.assertEqual(caught.exception.args, ('CIndex include closure',))
        self.assertIsNotNone(identity.declaration_inclusion_diagnostic(caught.exception, {}))
        for error in (identity.IdentityError('CIndex include closure'), TypeError('CIndex include closure')):
            error.__context__ = caught.exception
            self.assertIsNone(identity.declaration_inclusion_diagnostic(error, {}))
        forged = identity.IdentityError('CIndex include closure')
        forged._inclusion_rejection = (object(), 'Linux', [], [])
        self.assertIsNone(identity.declaration_inclusion_diagnostic(forged, {}))
        class ForeignError:
            def __getattribute__(self, key):
                raise AssertionError('foreign attribute access')
        self.assertIsNone(identity.declaration_inclusion_diagnostic(ForeignError(), {}))

    def test_header_digest_budget_shape_and_changed_context_fail_closed(self):
        value = self.packet([])
        with self.assertRaises(identity.IdentityError) as caught:
            self.validate(value, value['probe']['cindex'])
        error = caught.exception
        original = copy.deepcopy(value['probe']['headers'])
        for mutate in (lambda headers: headers.extend([headers[0]] * 4096),
                       lambda headers: headers[0].update(extra='PRIVATE_SENTINEL'),
                       lambda headers: headers[0].update(resolved_path='x' * 8193),
                       lambda headers: headers[0].update(resolved_path='\udcff'),
                       lambda headers: headers[0].update(bytes=True),
                       lambda headers: headers[0].update(sha256='PRIVATE_SENTINEL')):
            headers = value['probe']['headers']
            headers[:] = copy.deepcopy(original)
            mutate(headers)
            report = identity.declaration_inclusion_diagnostic(error, {})
            self.assertEqual(report['status'], 'UNAVAILABLE')
            self.assertEqual(report['reason'], 'INPUT_BUDGET_OR_SHAPE')
            self.assertIsNone(report['header_array_sha256'])
            self.assertIsNone(report['details'])
            self.assertNotIn('PRIVATE_SENTINEL', identity.canonical(report))
        headers[:] = copy.deepcopy(original)
        class ForeignKey(str):
            pass
        headers[0] = {ForeignKey(key): item for key, item in headers[0].items()}
        with mock.patch.object(identity, 'fields', wraps=identity.fields) as fields:
            report = identity.declaration_inclusion_diagnostic(error, {})
        fields.assert_not_called()
        self.assertEqual(report['status'], 'UNAVAILABLE')
        headers[:] = copy.deepcopy(original)
        size = len(identity.canonical(headers).encode())
        for limit, available in ((size, True), (size - 1, False)):
            with mock.patch.object(identity, 'MAX_OUTPUT', limit):
                report = identity.declaration_inclusion_diagnostic(error, {})
            self.assertEqual(report['status'], 'AVAILABLE' if available else 'UNAVAILABLE')
        # Header/path inspection itself is allowed at exactly 8192 UTF-8 bytes.
        headers[0]['resolved_path'] = 'é' * 4096
        self.assertEqual(identity.declaration_inclusion_diagnostic(error, {})['status'], 'AVAILABLE')
        headers[0]['resolved_path'] += 'x'
        self.assertEqual(identity.declaration_inclusion_diagnostic(error, {})['status'], 'UNAVAILABLE')
        headers[:] = copy.deepcopy(original)
        value['probe']['cindex']['inclusions'][:] = sorted(header['path'] for header in headers)
        report = identity.declaration_inclusion_diagnostic(error, {})
        self.assertEqual((report['status'], report['reason']), ('UNAVAILABLE', 'NO_REPRODUCIBLE_REJECTION'))
        self.assertIsNone(report['details'])

    def test_final_log_has_exact_ascii_byte_limit(self):
        original = identity.canonical
        value = self.packet([])
        for suffix, size, printed in (('', 4096, True), ('', 4097, False), ('é', 4096, False)):
            def canonical(item):
                if type(item) is dict and item.get('schema') == 'codeskeptic-declaration-inclusion-diagnostic/v1':
                    return 'x' * (size - len(self.LOG) - len(suffix) - 1) + suffix + '\n'
                return original(item)
            with mock.patch.object(identity, 'canonical', side_effect=canonical):
                observed, failure, log = self.run_packet(value)
            self.assertIsNone(observed)
            self.assertEqual(failure['kind'], 'INVALID_RESULT')
            self.assertEqual(self.LOG in log, printed)
            if printed:
                self.assertEqual(len(log.splitlines(keepends=True)[1]), 4096)

    def test_predicate_errors_and_other_guards_remain_unmarked(self):
        calls = []
        path_error = identity.IdentityError('CIndex include closure')
        class ExplodingPath:
            def __fspath__(self):
                calls.append('path')
                raise path_error
        for inclusions, expected_type in (([[]], TypeError), ([1, 'x'], TypeError),
                ([None], TypeError), ([ExplodingPath()], identity.IdentityError)):
            value = self.packet(inclusions)
            with self.assertRaises(expected_type) as caught:
                self.validate(value, value['probe']['cindex'])
            self.assertIsNone(identity.declaration_inclusion_diagnostic(caught.exception, {}))
        self.assertEqual(calls, ['path'])
        for field, invalid in (('parse_status', 1), ('diagnostics', None)):
            value, _ = self.fixture.packet()
            value['probe']['cindex'][field] = invalid
            with self.assertRaises(identity.IdentityError) as caught:
                self.validate(value, value['probe']['cindex'])
            self.assertIsNone(identity.declaration_inclusion_diagnostic(caught.exception, {}))

    def test_optional_annotation_extraction_serialization_and_write_failures_keep_red(self):
        value = self.packet([])
        _, expected, _ = self.run_packet(value)
        original = identity.canonical
        def broken_serialization(item):
            if type(item) is dict and item.get('schema') == 'codeskeptic-declaration-inclusion-diagnostic/v1':
                raise OSError('PRIVATE_SENTINEL')
            return original(item)
        for patch in (mock.patch.object(identity.IdentityError, '__setattr__', side_effect=OSError('PRIVATE_SENTINEL')),
                      mock.patch.object(identity, 'declaration_inclusion_diagnostic', side_effect=RuntimeError('PRIVATE_SENTINEL')),
                      mock.patch.object(identity, 'canonical', side_effect=broken_serialization)):
            with patch:
                observed, failure, log = self.run_packet(value)
            self.assertIsNone(observed)
            self.assertEqual(failure, expected)
            self.assertNotIn(self.LOG, log)
            self.assertNotIn('PRIVATE_SENTINEL', log)
        class BrokenLog(io.StringIO):
            def write(self, text):
                if text.startswith(DeclarationInclusionDiagnosticTests.LOG):
                    raise OSError('PRIVATE_SENTINEL')
                return super().write(text)
        raw = original(value['probe']['cindex']).encode()
        with mock.patch.object(identity.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=raw, stderr=b'')) as execute, \
                mock.patch.object(identity.sys, 'stderr', BrokenLog()):
            observed, failure = identity.run_declaration_worker({}, lambda observed: self.validate(value, observed))
        execute.assert_called_once()
        self.assertIsNone(observed)
        self.assertEqual(failure, expected)
        # No marker can leak to a later invocation or a non-VALIDATE phase.
        observed, failure, log, _ = DeclarationResultDiagnosticTests().run_result()
        self.assertIsNone(failure)
        self.assertEqual(log, '')

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux writer paths; not native Windows evidence.')
    def test_actual_writer_keeps_packet_schema_and_syntax_red(self):
        value = self.packet(['/sdk/stdlib.h'])
        raw = identity.canonical(value['probe']['cindex']).encode()
        for syntax_exit in (0, 1):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'failed.json'
                with self.fixture.mocked_declaration_capture(output, raw, syntax_exit=syntax_exit) as (argv, log, emitted):
                    self.assertEqual(identity.main(argv), 2)
                retained = json.loads(output.read_bytes())
                self.diagnostic(log.getvalue(), retained['probe']['backend_failure'], 'PATH_SET_MISMATCH', retained['probe']['headers'])
                self.assertEqual(set(retained['probe']), {'input', 'dependency', 'headers', 'syntax', 'cindex', 'backend_failure'})
                self.assertIsNone(retained['probe']['cindex'])
                self.assertEqual(retained['probe']['syntax']['exit_code'], syntax_exit)
                summary = self.fixture.summary(retained, identity.declaration_model(Path(identity.__file__).resolve().parents[1])[1])
                self.assertTrue(all(row['issues'] == ['BACKEND_FAILED'] + (['SYNTAX_FAILED'] if syntax_exit else []) for row in summary['requests']))
                self.assertTrue(all(summary[key] is False for key in ('syntax_pass', 'native_qualified', 'task_ready', 'product_qualified')))


class PosixDeclarationProfileTests(unittest.TestCase):
    PROFILE = 'c17-posix2008/v1'
    PREFIX = '#define _POSIX_C_SOURCE 200809L\n'
    MACROS = ('__STRICT_ANSI__', '_POSIX_C_SOURCE', '_POSIX_SOURCE', '_ATFILE_SOURCE',
              '__USE_POSIX', '__USE_POSIX2', '__USE_ATFILE', '__USE_MISC', '__USE_XOPEN2K8')

    def setUp(self):
        self.legacy = DeclarationTests()
        self.legacy.setUp()
        self.model = self.legacy.model

    def packet(self):
        value, sha, row = self.legacy.populated()
        value['schema'] = 'codeskeptic-native-declarations/v2'
        value['profile'] = {'id': self.PROFILE, 'language': 'c17',
                            'feature_macros': {'_POSIX_C_SOURCE': '200809L'}}
        source = (self.PREFIX + identity.declaration_source(self.model, 'Linux')).encode()
        value['probe']['input'].update(bytes=len(source), sha256=hashlib.sha256(source).hexdigest())
        argv = value['probe']['syntax']['argv'][:-2] + ['-dM', '-E', value['probe']['input']['path']]
        selected = dict.fromkeys(self.MACROS)
        selected.update(__STRICT_ANSI__='1', _POSIX_C_SOURCE='200809L')
        value['probe']['preprocessor'] = {
            'argv': argv, 'failure': None, 'selected_macros': selected,
            'command': {'argv': argv, 'exit_code': 0, 'stderr': '',
                        'stdout': '#define __STRICT_ANSI__ 1\n#define _POSIX_C_SOURCE 200809L\n'}}
        return value, sha

    def check(self, value, sha):
        return identity.validate_declaration_document(value, self.model, sha)

    def test_explicit_profile_source_and_platform_contract(self):
        for system in ('Linux', 'Darwin'):
            old = identity.declaration_source(self.model, system)
            self.assertEqual(identity.declaration_source(self.model, system, self.PROFILE), self.PREFIX + old)
            self.assertNotIn('#define', old)
        for system, profile in (('Windows', self.PROFILE), ('Linux', 'unknown'), ('Linux', ''), ('Other', self.PROFILE)):
            with self.subTest(system=system, profile=profile), self.assertRaises(ValueError):
                identity.declaration_source(self.model, system, profile)

    def test_legacy_source_bytes_match_independent_exact_1168_snapshots(self):
        for system, count, sha in (
                ('Linux', 3013, '12b406293cf60e286a05925676d2f67a00343a324ff1818a39cf6718913801f0'),
                ('Darwin', 3013, '12b406293cf60e286a05925676d2f67a00343a324ff1818a39cf6718913801f0'),
                ('Windows', 2795, 'e9ea1cc82cebc69878c5e8fb4a44b46c459647b58af755e3dd2f982bf5bf378e')):
            raw = identity.declaration_source(self.model, system).encode()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (count, sha))
        value, sha = self.legacy.packet()
        self.assertEqual(value['schema'], 'codeskeptic-native-declarations/v1')
        self.assertNotIn('profile', value)
        self.assertNotIn('preprocessor', value['probe'])
        self.assertNotIn('visibility_pass', self.check(value, sha))

    def test_darwin_preprocessing_preserves_selected_sdk_and_c17_command(self):
        compiler = {'file': {'resolved_path': '/usr/bin/clang'}, 'resource_dir': '/clt/lib/clang/20',
                    'target': 'arm64-apple-darwin24.0.0'}
        self.assertEqual(identity.declaration_preprocessor_command(compiler, 'Darwin',
                         {'sdk_root': '/clt/SDKs/MacOSX.sdk'}, '/probe/declarations.c'),
                         ['/usr/bin/clang', '--no-default-config', '-fno-modules', '-resource-dir',
                          '/clt/lib/clang/20', '-x', 'c', '-std=c17', '--target=arm64-apple-darwin24.0.0',
                          '-isysroot', '/clt/SDKs/MacOSX.sdk', '-dM', '-E', '/probe/declarations.c'])

    def test_v2_pure_reader_preserves_missing_references_and_zero_qualification(self):
        value, sha = self.packet()
        with (mock.patch.object(identity.subprocess, 'run', side_effect=AssertionError('execution')),
              mock.patch.object(identity, 'file_identity', side_effect=AssertionError('native read')),
              mock.patch.object(identity, 'declaration_backend', side_effect=AssertionError('native load'))):
            result = self.check(value, sha)
        self.assertTrue(result['visibility_pass'])
        self.assertEqual(result['profile_id'], self.PROFILE)
        self.assertEqual(result['requests'][0]['issues'], [])
        self.assertIn('MISSING_REFERENCE', next(r['issues'] for r in result['requests'] if r['id'] == 'posix.popen'))
        self.assertEqual(result['coverage'], {'required_library_pairs': 50, 'required_entry_pairs': 3,
                                            'qualified_library_pairs': 0, 'qualified_entry_pairs': 0})
        self.assertFalse(result['native_qualified'] or result['task_ready'] or result['product_qualified'])

    def test_schema_profile_and_source_cross_bindings_reject_downgrades(self):
        for mutation in ('schema', 'strip', 'profile', 'language', 'macro', 'source', 'projection', 'argv', 'extra'):
            value, sha = self.packet()
            if mutation == 'schema': value['schema'] = 'codeskeptic-native-declarations/v1'
            elif mutation == 'strip':
                value['schema'] = 'codeskeptic-native-declarations/v1'
                del value['profile'], value['probe']['preprocessor']
            elif mutation == 'profile': value['profile']['id'] = 'unknown'
            elif mutation == 'language': value['profile']['language'] = 'gnu17'
            elif mutation == 'macro': value['profile']['feature_macros']['_GNU_SOURCE'] = '1'
            elif mutation == 'source': value['probe']['input']['sha256'] = 'a' * 64
            elif mutation == 'projection': value['probe']['preprocessor']['selected_macros']['__USE_MISC'] = '1'
            elif mutation == 'argv': value['probe']['preprocessor']['argv'].insert(1, '-D_GNU_SOURCE')
            else: value['probe']['preprocessor']['extra'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(value, sha)

    def test_projection_is_recomputed_and_missing_visibility_is_a_gap(self):
        value, sha = self.packet()
        probe = value['probe']['preprocessor']
        probe['command']['stdout'] = '#define EMPTY\n#define FN(x) ((x) + 1)\n#define __STRICT_ANSI__ 1\n'
        probe['selected_macros']['_POSIX_C_SOURCE'] = None
        result = self.check(value, sha)
        self.assertFalse(result['visibility_pass'])
        self.assertFalse(result['syntax_pass'])
        self.assertTrue(all('VISIBILITY_NOT_OBSERVED' in r['issues'] and r['state'] == 'INCOMPLETE'
                            for r in result['requests']))

    def test_projection_rejects_ambiguous_selected_definitions_and_invalid_utf8(self):
        for suffix in ('#define _POSIX_C_SOURCE 1\n', '#define __STRICT_ANSI__(x) x\n', '\udcff', 'not a macro\n'):
            value, sha = self.packet()
            value['probe']['preprocessor']['command']['stdout'] += suffix
            with self.subTest(suffix=repr(suffix)), self.assertRaises(ValueError):
                self.check(value, sha)

    def test_projection_and_full_packet_preserve_physical_directive_boundaries(self):
        for separator in ('\n', '\r\n', '\f', '\v', '\x85', '\u2028', '\u2029', '\r'):
            with self.subTest(separator=repr(separator)):
                value, sha = self.packet()
                raw = '#define __STRICT_ANSI__ 1' + separator + '#define _POSIX_C_SOURCE 200809L\n'
                value['probe']['preprocessor']['command']['stdout'] = raw
                physical_newline = separator in ('\n', '\r\n')
                projection = identity.declaration_macro_projection(raw)
                self.assertEqual(projection['__STRICT_ANSI__'] == '1' and projection['_POSIX_C_SOURCE'] == '200809L',
                                 physical_newline)
                if physical_newline:
                    self.assertTrue(self.check(value, sha)['visibility_pass'])
                else:
                    with self.assertRaisesRegex(ValueError, 'projection mismatch'):
                        self.check(value, sha)
                    value['probe']['preprocessor']['selected_macros'] = projection
                    result = self.check(value, sha)
                    self.assertFalse(result['visibility_pass'])
                    self.assertTrue(all('VISIBILITY_NOT_OBSERVED' in row['issues'] for row in result['requests']))

    def test_macro_whitespace_is_ascii_and_unicode_replacements_are_not_normalized(self):
        cases = [(' ', '', '', '\n', True), ('\t', '', '\t ', '\r\n', True),
                 (' \t', '', '', '\n', True)]
        for character in ('\xa0', '\x85', '\u2028', '\u2029', '\u2007', '\u202f'):
            cases += [(character, '', '', '\n', False), (' ', character, '', '\n', False),
                      (' ', '', character, '\n', False)]
        for separator, prefix, suffix, ending, valid in cases:
            with self.subTest(separator=repr(separator), prefix=repr(prefix), suffix=repr(suffix)):
                value, sha = self.packet()
                raw = ('#define __STRICT_ANSI__' + separator + prefix + '1' + suffix + ending +
                       '#define _POSIX_C_SOURCE' + separator + prefix + '200809L' + suffix + ending)
                value['probe']['preprocessor']['command']['stdout'] = raw
                try:
                    projection = identity.declaration_macro_projection(raw)
                except ValueError:
                    self.assertFalse(valid)
                    with self.assertRaises(ValueError):
                        self.check(value, sha)
                    continue
                self.assertEqual(projection['__STRICT_ANSI__'] == '1' and projection['_POSIX_C_SOURCE'] == '200809L', valid)
                if valid:
                    self.assertTrue(self.check(value, sha)['visibility_pass'])
                else:
                    with self.assertRaisesRegex(ValueError, 'projection mismatch'):
                        self.check(value, sha)
                    value['probe']['preprocessor']['selected_macros'] = projection
                    self.assertFalse(self.check(value, sha)['visibility_pass'])

    def test_empty_ascii_lines_and_definitions_do_not_discard_non_ascii_data(self):
        result = identity.declaration_macro_projection('\t \r\n#define _POSIX_SOURCE \t\r\n#define FN(x) \n')
        self.assertEqual(result['_POSIX_SOURCE'], '')
        for nonascii in ('\xa0', '\x85', '\u2028'):
            with self.subTest(character=repr(nonascii)), self.assertRaises(ValueError):
                identity.declaration_macro_projection(nonascii + '\n')

    def test_later_preprocessor_timeout_retains_prior_syntax_red(self):
        value, sha = self.packet()
        probe = value['probe']['preprocessor']
        empty = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
        probe.update(command=None, selected_macros=None,
                     failure={'kind': 'TIMEOUT', 'exit_code': None, 'stdout': empty, 'stderr': copy.deepcopy(empty)})
        value['probe']['syntax']['exit_code'] = 1
        result = self.check(value, sha)
        self.assertFalse(result['visibility_pass'])
        self.assertTrue(all('PREPROCESSOR_FAILED' in r['issues'] and 'SYNTAX_FAILED' in r['issues']
                            for r in result['requests']))

    def test_unsupported_platform_rejected_before_native_capture(self):
        args = SimpleNamespace(declaration_profile=self.PROFILE)
        with (mock.patch.object(identity.platform, 'system', return_value='Windows'),
              mock.patch.object(identity, 'capture', side_effect=AssertionError('native capture')),
              mock.patch.object(identity, 'file_identity', side_effect=AssertionError('native read')),
              self.assertRaises(ValueError)):
            identity.capture_declarations(args)

    def test_preprocessor_capture_has_fixed_failure_and_projection_outcomes(self):
        argv = ['/clang', '-dM', '-E', '/input.c']
        valid = b'#define _POSIX_C_SOURCE 200809L\n#define __STRICT_ANSI__ 1\n'
        cases = [(SimpleNamespace(returncode=0, stdout=valid, stderr=b''), None),
                 (SimpleNamespace(returncode=0, stdout=b'\xff', stderr=b''), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=0, stdout=valid, stderr=b'warning'), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=0, stdout=b'#define _POSIX_C_SOURCE(x) x\n', stderr=b''), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=1, stdout=b'partial', stderr=b'error'), 'PROCESS_FAILED'),
                 (SimpleNamespace(returncode=0, stdout=b'x' * (identity.MAX_OUTPUT + 1), stderr=b''), 'OUTPUT_LIMIT'),
                 (subprocess.TimeoutExpired(argv, 30, output=b'partial'), 'TIMEOUT'),
                 (OSError('not started'), 'START_FAILED')]
        for returned, expected in cases:
            options = {'side_effect': returned} if isinstance(returned, BaseException) else {'return_value': returned}
            with self.subTest(expected=expected), mock.patch.object(identity.subprocess, 'run', **options) as run:
                result = identity.capture_declaration_preprocessor(argv)
            self.assertEqual(run.call_args.args[0], argv)
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
            self.assertEqual(identity.validate_declaration_preprocessor(result, argv),
                             [] if expected is None else ['PREPROCESSOR_FAILED'])
            if expected is None:
                self.assertEqual(result['command']['stdout'].encode(), valid)
            else:
                self.assertIsNone(result['command'])
                self.assertEqual(result['failure']['kind'], expected)

    def test_preprocessor_forged_failure_shapes_are_rejected(self):
        for mutation in ('exit', 'streams', 'missing', 'output', 'kind', 'projection'):
            value, sha = self.packet()
            preprocessor = value['probe']['preprocessor']
            empty = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
            preprocessor.update(command=None, selected_macros=None, failure={
                'kind': 'TIMEOUT', 'exit_code': None, 'stdout': empty, 'stderr': copy.deepcopy(empty)})
            failure = preprocessor['failure']
            if mutation == 'exit': failure['exit_code'] = 0
            elif mutation == 'streams': failure['stdout']['sha256'] = 'a' * 64
            elif mutation == 'missing': del failure['stderr']
            elif mutation == 'output': failure.update(kind='OUTPUT_LIMIT', exit_code=0)
            elif mutation == 'kind': failure['kind'] = 'SUCCESS'
            else: preprocessor['selected_macros'] = {}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(value, sha)

    def test_combined_failures_add_each_visibility_issue_only_once_per_request(self):
        value, sha = self.packet()
        empty = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
        failure = {'kind': 'TIMEOUT', 'exit_code': None, 'stdout': empty, 'stderr': copy.deepcopy(empty)}
        value['probe']['preprocessor'].update(command=None, selected_macros=None, failure=failure)
        value['probe'].update(cindex=None, backend_failure=copy.deepcopy(failure))
        value['probe']['syntax']['exit_code'] = 1
        before = copy.deepcopy(value)
        result = self.check(value, sha)
        self.assertEqual(value, before)
        self.assertEqual(len(result['requests']), 14)
        for row in result['requests']:
            self.assertEqual(row['issues'], ['BACKEND_FAILED', 'SYNTAX_FAILED', 'PREPROCESSOR_FAILED'])

    def test_child_reconstructs_explicit_profile_before_backend_loading(self):
        value, sha = self.packet()
        config = {key: value[key] for key in ('native_identity', 'environment', 'library', 'profile')}
        config['input'] = value['probe']['input']
        native = config['native_identity']
        files = {Path(row['path']): row for row in (config['input'], config['library'])}
        for mutation in (None, 'missing', 'unknown', 'extra', 'prefix', 'windows'):
            candidate = copy.deepcopy(config)
            if mutation == 'missing': del candidate['profile']
            elif mutation == 'unknown': candidate['profile']['id'] = 'unknown'
            elif mutation == 'extra': candidate['profile']['flags'] = []
            elif mutation == 'prefix': candidate['input']['sha256'] = 'f' * 64
            with (self.subTest(mutation=mutation),
                  mock.patch.object(identity.platform, 'system', return_value='Windows' if mutation == 'windows' else 'Linux'),
                  mock.patch.object(identity, 'case_environment', return_value=value['environment']),
                  mock.patch.object(identity, 'source_identity', return_value=native['source']),
                  mock.patch.object(identity, 'file_identity', side_effect=lambda path: files[path]),
                  mock.patch.object(identity, 'declaration_backend') as backend):
                backend.return_value.observe.return_value = {'child': 'observed'}
                if mutation is None:
                    self.assertEqual(identity.declaration_worker(candidate), {'child': 'observed'})
                    self.assertEqual(backend.return_value.observe.call_args.args[0], value['probe']['syntax']['argv'])
                    self.assertEqual(len(backend.return_value.observe.call_args.args[1]), 14)
                else:
                    with self.assertRaises(ValueError):
                        identity.declaration_worker(candidate)
                    backend.assert_not_called()

    def test_child_profile_fixture_supports_both_lexical_path_flavors(self):
        value, _ = self.packet()
        synthetic_paths = {value['probe']['input']['path'], value['library']['path']}
        native_path = Path
        for flavor in (PurePosixPath, PureWindowsPath):
            def fixture_path(path):
                # Only synthetic identities change flavor; repository reads remain native.
                if isinstance(path, str) and path in synthetic_paths:
                    return flavor(path)
                return native_path(path)

            with (self.subTest(path_flavor=flavor.__name__),
                  mock.patch.object(identity, 'Path', side_effect=fixture_path),
                  mock.patch.object(sys.modules[__name__], 'Path', side_effect=fixture_path)):
                self.test_child_reconstructs_explicit_profile_before_backend_loading()

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux v2 writer requires POSIX paths; no Windows native claim.')
    def test_explicit_v2_writer_propagates_profile_and_preserves_both_failures(self):
        value, sha = self.packet()
        raw = identity.canonical(value['probe']['cindex']).encode()
        for syntax_exit, worker_raw, preprocess_failure in ((0, raw, None), (1, b'{}', None),
                (1, raw, subprocess.TimeoutExpired(['/clang'], 30, output=b'partial'))):
            with self.subTest(syntax_exit=syntax_exit, worker_valid=worker_raw == raw), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'observed.json'
                with self.legacy.mocked_declaration_capture(output, worker_raw, syntax_exit=syntax_exit,
                        preprocessor_response=preprocess_failure) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv + ['--declaration-profile', self.PROFILE]), 2 if syntax_exit else 0)
                    diagnostic_log = stderr.getvalue()
                retained = json.loads(output.read_text())
                self.assertEqual(retained['schema'], 'codeskeptic-native-declarations/v2')
                self.assertEqual(emitted['config']['profile'], retained['profile'])
                self.assertEqual(retained['probe']['preprocessor']['argv'], emitted['preprocessor_argv'])
                self.assertEqual(retained['probe']['syntax']['exit_code'], syntax_exit)
                self.assertEqual(self.check(retained, sha)['visibility_pass'], preprocess_failure is None)
                if worker_raw == b'{}':
                    self.assertEqual(retained['probe']['backend_failure']['kind'], 'INVALID_RESULT')
                    DeclarationResultDiagnosticTests().diagnostic(diagnostic_log, retained['probe']['backend_failure'], 'VALIDATE')
                else:
                    self.assertEqual(diagnostic_log, '')

    def test_public_cli_rejects_windows_and_unknown_profile_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'not-written.json'
            argv = ['capture-declarations', '--root', str(Path(directory).resolve()), '--source-sha', 'a' * 40,
                    '--libclang', '/not-loaded', '--output', str(output)]
            for role in identity.TOOL_ROLES:
                argv += ['--' + role, '/not-executed']
            with (mock.patch.object(identity.platform, 'system', return_value='Windows'),
                  mock.patch.object(identity, 'capture', side_effect=AssertionError('capture')),
                  mock.patch.object(identity.subprocess, 'run', side_effect=AssertionError('execution')),
                  mock.patch('sys.stderr', new_callable=io.StringIO)):
                self.assertEqual(identity.main(argv + ['--declaration-profile', self.PROFILE]), 2)
                with self.assertRaises(SystemExit) as error:
                    identity.main(argv + ['--declaration-profile', 'unknown'])
                self.assertEqual(error.exception.code, 2)
            self.assertFalse(output.exists())

    def test_public_pure_reader_accepts_each_explicit_schema_and_rejects_cross_binding(self):
        root = Path(identity.__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory).resolve() / 'metadata.json'
            for value, _ in (self.legacy.packet(), self.packet()):
                packet.write_text(identity.canonical(value), encoding='utf-8')
                result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-declarations', str(packet),
                                         '--root', str(root)], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(json.loads(result.stdout)['native_qualified'])
            value['profile']['language'] = 'gnu17'
            packet.write_text(identity.canonical(value), encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-declarations', str(packet),
                                     '--root', str(root)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 2)

    @unittest.skipIf(sys.platform == 'win32', 'Synthetic Linux v2 writer requires POSIX paths; no Windows native claim.')
    def test_v2_unicode_child_failure_and_independent_drift_keep_existing_boundaries(self):
        value, sha = self.packet()
        raw = identity.canonical(value['probe']['cindex']).encode()
        for changed in (None, '/sdk/stdlib.h', 'source'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'metadata.json'
                def inject(stdout):
                    marker = b'"library_version":"clang version 22.1.0"'
                    self.assertEqual(stdout.count(marker), 1)
                    return stdout.replace(marker, b'"library_version":"\\udcff"')
                with self.legacy.mocked_declaration_capture(output, raw, changed=changed,
                        after_serialization=inject) as (argv, stderr, emitted):
                    self.assertEqual(identity.main(argv + ['--declaration-profile', self.PROFILE]), 2)
                    diagnostic_log = stderr.getvalue()
                if changed is not None:
                    self.assertFalse(output.exists())
                    lines = diagnostic_log.splitlines()
                    self.assertEqual(len(lines), 3)
                    self.assertTrue(lines[0].startswith('DECLARATION_RESULT_DIAGNOSTIC '))
                    self.assertTrue(lines[1].startswith('IDENTITY_INVALID '))
                    self.assertEqual(lines[2], 'DECLARATION_FAILURE_KIND INVALID')
                else:
                    retained = json.loads(output.read_text())
                    DeclarationResultDiagnosticTests().diagnostic(diagnostic_log, retained['probe']['backend_failure'], 'VALIDATE')
                    self.assertEqual(retained['probe']['backend_failure']['kind'], 'INVALID_RESULT')
                    self.assertEqual(retained['probe']['syntax']['exit_code'], 1)
                    self.assertFalse(self.check(retained, sha)['syntax_pass'])


class WorkflowTests(unittest.TestCase):
    def test_every_native_lane_runs_external_input_staging_ground_truth_and_recipe_tests(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        self.assertEqual(workflow.count('-k GccStaging -k ExternalInput -k AllRuleGroundTruthTests '
                                       '-k NativeRecipeTests -k RetainedCandidateTests -k RetainedGroundTruthTests '
                                       '-k SourceCohortTests -k SourceCohortNativeTests -k SourceCohortGroundTruthTests '
                                       '-k ReviewedFilesTests -q'), 2)
        self.assertIn("throw 'External input safety tests failed'", workflow)

    def test_each_lane_uses_one_explicit_python_for_tests_and_capture(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        self.assertIn('identity_python="$(command -v python3)"', workflow)
        self.assertIn('"$identity_python" -B -m unittest', workflow)
        self.assertIn('"$identity_python" -B scripts/product_identity.py capture', workflow)
        self.assertIn('$identityPython = (Get-Command python.exe -ErrorAction Stop).Source', workflow)
        self.assertIn('& $identityPython -B -m unittest', workflow)
        self.assertIn('& $identityPython -B scripts/product_identity.py capture', workflow)
        self.assertLess(workflow.index('$identityPython ='), workflow.index('$identitySetup ='))
        # The separate declaration job also pins one interpreter per native shell lane.
        self.assertEqual(workflow.count('sys.version_info >= (3, 10)'), 4)

    def test_identity_lane_has_narrow_push_and_readonly_permissions(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        self.assertIn('branches: [agent/cs3-ch08-s01-u003-frozen-product-profiles]', workflow)
        self.assertIn('contents: read', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('runner: [ubuntu-24.04, windows-2025, macos-14]', workflow)
        self.assertIn('timeout-minutes: 10', workflow)
        self.assertLess(workflow.index('git config --global core.autocrlf false'),
                        workflow.index('uses: actions/checkout@'))
        self.assertIn('path: ${{ runner.temp }}/codeskeptic-product-identity.json', workflow)
        for forbidden in ('sudo ', 'apt-get ', 'brew install', 'cmake ', 'ctest ',
                          'git push', 'contents: write', 'id-token: write', 'pull_request_target:'):
            self.assertNotIn(forbidden, workflow)


class HostedDeclarationWorkflowTests(unittest.TestCase):
    def job(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        self.assertEqual(workflow.count('\n  declarations:\n'), 1)
        legacy, job = workflow.split('  declarations:\n', 1)
        self.assertEqual(hashlib.sha256(legacy.encode()).hexdigest(),
                         'b4b3ab7fd3a5181edcf286708a2e6884cc14c45835d8c1fe8e5cb9f881d9f765')
        return job.split('\n# Success means', 1)[0]

    def test_separate_three_platform_job_preserves_legacy_lane_and_budget(self):
        job = self.job()
        self.assertIn('runner: [ubuntu-24.04, windows-2025, macos-14]', job)
        self.assertIn('timeout-minutes: 10', job)
        self.assertIn('fail-fast: false', job)
        self.assertNotIn('needs:', job)
        self.assertIn('persist-credentials: false', job)
        self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683', job)
        self.assertLess(job.index('git config --global core.autocrlf false'), job.index('uses: actions/checkout@'))
        for forbidden in ('continue-on-error', 'stage-gcc-inputs', 'capture-case', 'sudo ',
                          'apt-get ', 'brew install', 'pip install', 'curl ', 'wget ', 'git push'):
            self.assertNotIn(forbidden, job)

    def test_selected_installed_libclang_and_profiles_are_explicit(self):
        job = self.job()
        posix, windows = job.split('      - name: Capture installed Windows declarations\n', 1)
        self.assertIn("parent.parent / 'lib/libclang.so.1'", posix)
        self.assertIn('/Library/Developer/CommandLineTools/usr/lib/libclang.dylib', posix)
        self.assertIn('resolve(strict=True)', posix)
        self.assertIn('--declaration-profile c17-posix2008/v1', posix)
        self.assertIn('export DEVELOPER_DIR=/Library/Developer/CommandLineTools', posix)
        self.assertIn('export MACOSX_DEPLOYMENT_TARGET=14.0', posix)
        self.assertIn("with_name('libclang.dll').resolve(strict=True)", windows)
        self.assertNotIn('--declaration-profile', windows)
        self.assertIn('--declaration-inclusion-mode windows-entered-headers/v1', windows)
        self.assertNotIn('--declaration-inclusion-mode', posix)
        self.assertIn('$env:INCLUDE = $declarationIncludes -join', windows)
        self.assertEqual(job.count('scripts/product_identity.py capture-declarations'), 2)
        self.assertEqual(job.count('--libclang '), 2)

    def test_declaration_tests_and_capture_failures_are_not_masked(self):
        job = self.job()
        self.assertEqual(job.count('-m unittest discover -s scripts -p test_product_identity.py -q'), 2)
        self.assertEqual(job.count('-p test_product_profiles.py -k NativeDeclarationReaderTests -q'), 2)
        self.assertEqual(job.count('sys.version_info >= (3, 10)'), 2)
        self.assertIn('set -euo pipefail', job)
        self.assertIn("throw 'Declaration observation failed; retained RED is not qualification'", job)
        self.assertIn("throw 'Declaration reader tests failed'", job)
        self.assertIn("throw 'Selected installed libclang is unavailable'", job)
        for forbidden in ('|| true', 'exit 0', 'continue-on-error', '-ExecutionPolicy Bypass'):
            self.assertNotIn(forbidden, job)

    def test_only_declaration_metadata_is_retained_even_after_failure(self):
        job = self.job()
        self.assertEqual(job.count('if: always()'), 1)
        self.assertEqual(job.count('uses: actions/upload-artifact@'), 1)
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', job)
        self.assertIn('name: native-declarations-${{ matrix.runner }}-${{ github.sha }}', job)
        self.assertIn('path: ${{ runner.temp }}/codeskeptic-native-declarations.json', job)
        self.assertIn('if-no-files-found: error', job)
        self.assertIn('retention-days: 30', job)

    @unittest.skipIf(sys.platform == 'win32', 'Bash SDK selection belongs only to the Linux/macOS shell lane.')
    def test_sdk_selector_nonzero_with_plausible_stdout_stops_capture(self):
        lines = [line.strip() for line in self.job().splitlines()]
        selector = '/usr/bin/xcrun --sdk macosx --show-sdk-path'
        indexes = [index for index, line in enumerate(lines) if selector in line]
        self.assertEqual(len(indexes), 1)
        index = indexes[0]
        selection = [lines[index]]
        if lines[index + 1].startswith('export SDKROOT='):
            selection.append(lines[index + 1])
        fragment = '\n'.join(selection).replace(selector, 'select_sdk')
        self.assertNotIn('/usr/bin/xcrun', fragment)
        for status in (0, 7):
            script = ("set -euo pipefail\nselect_sdk() { printf '%s\\n' '/fixture/SDK'; return "
                      + str(status) + '; }\n' + fragment
                      + '\nprintf \'CONTINUED:%s\\n\' "$SDKROOT"\n')
            with self.subTest(selector_exit=status):
                result = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                                        timeout=5, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                self.assertEqual(result.returncode, status)
                self.assertEqual(result.stdout, 'CONTINUED:/fixture/SDK\n' if status == 0 else '')
                self.assertEqual(result.stderr, '')


class FakeCIndexLibrary:
    """Explicit fake CDLL driving the real adapter's ctypes callbacks, not native I/O."""

    def __init__(self):
        self.functions, self.handlers, self.nodes, self.strings = {}, {}, {}, {}
        self.next_string = 1
        self.visits, self.disposed_strings, self.disposed = [], [], []
        self.parse_calls, self.index_calls = [], []
        self.references, self.canonical, self.definitions = {}, {}, {}
        self.diagnostics = [(2, b'whole TU warning'), (3, b'whole TU error')]
        self.files = {901: b'/fixture/probe.c', 902: b'/fixture/sdk.h'}
        self.inclusions = [902, 901, 902]
        self.forced_visit_result = 0
        self.tu = self.node(300, 'translation unit')
        self.handlers.update({
            'getCString': lambda value: self.strings[value.data],
            'disposeString': self.dispose_string,
            'getCursorSpelling': lambda cursor: self.string(self.nodes[cursor.xdata]['name']),
            'visitChildren': self.visit_children,
            'createIndex': lambda *args: self.index_calls.append(args) or 222,
            'parseTranslationUnit2FullArgv': self.parse,
            'getTranslationUnitCursor': lambda unit: self.cursor(self.tu),
            'disposeTranslationUnit': lambda unit: self.disposed.append(('unit', unit.value)),
            'disposeIndex': lambda index: self.disposed.append(('index', index)),
            'getNumDiagnostics': lambda unit: len(self.diagnostics),
            'getDiagnostic': lambda unit, index: index,
            'getDiagnosticSeverity': lambda index: self.diagnostics[index][0],
            'getDiagnosticSpelling': lambda index: self.string(self.diagnostics[index][1]),
            'disposeDiagnostic': lambda index: self.disposed.append(('diagnostic', index)),
            'getInclusions': self.get_inclusions,
            'getFileName': lambda file: self.string(self.files[file.value if hasattr(file, 'value') else file]),
            'getClangVersion': lambda: self.string(b'clang version 20.1.8 (synthetic adapter fixture)'),
            'getCursorReferenced': lambda cursor: self.cursor(self.references[cursor.xdata]),
            'getCanonicalCursor': lambda cursor: self.cursor(self.canonical.get(cursor.xdata, cursor.xdata)),
            'getCursorDefinition': lambda cursor: self.cursor(self.definitions.get(cursor.xdata, 0)),
            'Cursor_isNull': lambda cursor: int(cursor.xdata == 0),
            'getCursorKindSpelling': lambda kind: self.string({8: 'FunctionDecl', 20: 'TypedefDecl'}.get(kind, 'Other')),
            'getCursorUSR': lambda cursor: self.string('fixture:' + str(cursor.xdata)),
            'getCursorLinkage': lambda cursor: 4,
            'getCursorLanguage': lambda cursor: 1,
            'Cursor_getMangling': lambda cursor: self.string('fixture_mangling_' + str(cursor.xdata)),
            'isCursorDefinition': lambda cursor: int(cursor.xdata in self.definitions.values()),
            'Cursor_getNumArguments': lambda cursor: 0,
            'getCursorLocation': self.location,
            'getSpellingLocation': self.position,
            'getExpansionLocation': self.position,
            'getCursorType': lambda cursor: self.functions['getCursorType'].restype(17),
            'getCanonicalType': lambda value: value,
            'getTypeKindSpelling': lambda kind: self.string('Int'),
            'getTypeSpelling': lambda value: self.string('int'),
            'isConstQualifiedType': lambda value: 0,
            'isVolatileQualifiedType': lambda value: 0,
            'isRestrictQualifiedType': lambda value: 0,
            'Type_getSizeOf': lambda value: 4,
            'Type_getAlignOf': lambda value: 4,
        })

    def __getattr__(self, name):
        if not name.startswith('clang_'):
            raise AttributeError(name)
        key = name[6:]
        if key not in self.functions:
            def function(*args):
                if key not in self.handlers:
                    raise AssertionError('unimplemented fake CIndex call: ' + key)
                return self.handlers[key](*args)
            self.functions[key] = function
        return self.functions[key]

    def node(self, kind, name, children=()):
        number = len(self.nodes) + 1
        self.nodes[number] = {'kind': kind, 'name': name, 'children': list(children)}
        return number

    def cursor(self, number):
        type_ = self.functions['visitChildren'].argtypes[0]
        return type_(self.nodes[number]['kind'] if number else 0, number)

    def string(self, raw):
        number = self.next_string
        self.next_string += 1
        self.strings[number] = raw.encode() if isinstance(raw, str) else raw
        return self.functions['getCursorSpelling'].restype(number, 0)

    def dispose_string(self, value):
        self.disposed_strings.append(value.data)
        del self.strings[value.data]

    def visit_children(self, parent, callback, data):
        import ctypes
        assert isinstance(callback, ctypes._CFuncPtr)
        assert type(parent) is self.functions['visitChildren'].argtypes[0]

        def walk(cursor):
            for number in self.nodes[cursor.xdata]['children']:
                child = self.cursor(number)
                code = callback(child, cursor, data)
                self.visits.append((number, code))
                if code == 0:
                    return 1
                if code == 2:
                    if walk(child):
                        return 1
                elif code != 1:
                    raise AssertionError('invalid visitor result')
            return 0
        return walk(parent) or self.forced_visit_result

    def parse(self, *args):
        index, source, argv, count, unsaved, unsaved_count, options, output = args
        self.parse_calls.append({'index': index, 'source': source,
            'argv': [argv[i].decode('utf-8') for i in range(count)],
            'unsaved': unsaved, 'unsaved_count': unsaved_count, 'options': options})
        args[-1]._obj.value = 111
        return 0

    def location(self, cursor):
        result = self.functions['getCursorLocation'].restype()
        result.offset_data = cursor.xdata
        return result

    def position(self, location, file, line, column, offset):
        file._obj.value = 901
        line._obj.value = 1
        column._obj.value = location.offset_data + 1
        offset._obj.value = location.offset_data

    def get_inclusions(self, unit, callback, data):
        for file in self.inclusions:
            callback(file, None, 0, data)

    def backend(self):
        # An existing regular file satisfies path checks but is NEVER loaded.
        path = Path(identity.__file__).resolve()
        with mock.patch('ctypes.CDLL', return_value=self) as load:
            result = identity.declaration_backend(path)
        load.assert_called_once_with(str(path))
        return result


class DeclarationTraversalTests(unittest.TestCase):
    selected = {20: frozenset({'cs_expected_probe'}),
                9: frozenset({'cs_native_probe'}), 8: frozenset({'main'})}
    requests = [{'id': 'fixture.probe', 'symbol': 'probe'}]

    def fixture(self):
        library = FakeCIndexLibrary()
        typedef = library.node(20, 'cs_expected_probe')
        target = library.node(8, 'probe')
        reference = library.node(101, 'probe')
        library.references[reference] = target
        variable = library.node(9, 'cs_native_probe', [reference])
        main = library.node(8, 'main')
        library.nodes[library.tu]['children'] = [typedef, variable, main]
        return library, library.backend(), typedef, variable, main

    def observe(self, backend):
        return backend.observe(['fixture-clang', '-fsyntax-only', '/fixture/probe.c'], self.requests)

    def test_large_unrelated_prefix_preserves_complete_observation(self):
        library, backend, typedef, variable, main = self.fixture()
        baseline = self.observe(backend)
        prefix = [library.node(8 if n % 2 else 20, 'unrelated_' + str(n)) for n in range(17000)]
        library.nodes[library.tu]['children'] = prefix + [typedef, variable, main] + prefix
        library.visits.clear()
        observed = self.observe(backend)
        self.assertEqual(observed, baseline)
        self.assertEqual(len(library.visits), 34004)  # 34003 TU siblings, one recursive reference.
        self.assertEqual(observed['inclusions'], ['/fixture/probe.c', '/fixture/sdk.h'])
        self.assertEqual(observed['diagnostics'], [
            {'severity': severity, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            for severity, raw in library.diagnostics])
        self.assertEqual([row['reference']['name'] for row in observed['requests'][0]['targets']], ['probe'])
        self.assertEqual([row['name'] for row in observed['entry']], ['main'])
        self.assertFalse(library.strings)
        self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_exact_kind_and_name_selection_never_recurses_into_discarded_nodes(self):
        library, backend, typedef, variable, main = self.fixture()
        wrong = [library.node(kind, name, [typedef]) for kind, name in (
            (8, 'cs_expected_probe'), (20, 'cs_native_probe'), (9, 'main'),
            (20, 'cs_expected_probe_suffix'), (9, 'cs_native_other'), (8, 'main_extra'))]
        library.nodes[library.tu]['children'] = wrong + [typedef, variable, main]
        nodes = backend.children(library.cursor(library.tu), selected=self.selected)
        self.assertEqual([node.xdata for node in nodes], [typedef, variable, main])
        self.assertEqual(library.visits, [(number, 1) for number in wrong + [typedef, variable, main]])
        self.assertFalse(library.strings)

    def test_missing_probes_remain_missing_after_selection(self):
        library, backend, typedef, variable, main = self.fixture()
        library.nodes[library.tu]['children'] = [library.node(20, 'cs_expected_other'), main]
        row = self.observe(backend)['requests'][0]
        self.assertIsNone(row['expected_type'])
        self.assertIsNone(row['variable_location'])
        self.assertEqual(row['targets'], [])

    def test_late_duplicate_typedef_or_variable_is_not_deduplicated(self):
        for kind, name in ((20, 'cs_expected_probe'), (9, 'cs_native_probe')):
            for same_identity in (False, True):
                with self.subTest(kind=kind, same_identity=same_identity):
                    library, backend, typedef, variable, main = self.fixture()
                    duplicate = (typedef if kind == 20 else variable) if same_identity else library.node(kind, name)
                    other = library.node(8, 'unrelated')
                    library.nodes[library.tu]['children'] = [typedef, variable, main] + [other] * 17000 + [duplicate] + [other] * 17000
                    with self.assertRaisesRegex(identity.IdentityError, 'duplicate CIndex request declaration'):
                        self.observe(backend)
                    self.assertEqual(len(library.visits), 34004)
                    self.assertEqual(library.visits[-1], (other, 1))
                    self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_all_main_occurrences_survive_large_prefix_and_suffix(self):
        library, backend, typedef, variable, main = self.fixture()
        other = library.node(8, 'unrelated')
        second = library.node(8, 'main')
        library.nodes[library.tu]['children'] = [other] * 17000 + [typedef, variable, main, second, main] + [other] * 17000
        entries = self.observe(backend)['entry']
        self.assertEqual([row['usr'] for row in entries], ['fixture:' + str(n) for n in (main, second, main)])

    def test_direct_visit_bound_counts_discarded_kinds_and_names_even_after_probes(self):
        for probes_first in (False, True):
            for count in (65536, 65537):
                with self.subTest(probes_first=probes_first, count=count):
                    library, backend, typedef, variable, main = self.fixture()
                    discard = [library.node(101, 'main'), library.node(8, 'unrequested')]
                    prefix = [typedef, variable, main] if probes_first else []
                    library.nodes[library.tu]['children'] = prefix + [discard[n % 2] for n in range(count - len(prefix))]
                    if count == 65536:
                        nodes = backend.children(library.cursor(library.tu), selected=self.selected)
                        self.assertEqual([node.xdata for node in nodes], prefix)
                        self.assertTrue(all(code == 1 for _, code in library.visits))
                    else:
                        with self.assertRaisesRegex(identity.IdentityError, 'CIndex TU visit bound'):
                            backend.children(library.cursor(library.tu), selected=self.selected)
                        self.assertEqual(library.visits[-1][1], 0)
                    self.assertEqual(len(library.visits), count)
                    self.assertFalse(library.strings)

    def test_stored_and_unfiltered_recursive_cursor_bounds_remain_16384(self):
        for mode in ('selected', 'recursive', 'direct'):
            for count in (16384, 16385):
                with self.subTest(mode=mode, count=count):
                    library, backend, typedef, variable, main = self.fixture()
                    leaf = typedef if mode == 'selected' else library.node(101, 'reference')
                    parent = library.node(9, 'parent', [leaf] * count)
                    kwargs = {'selected': self.selected} if mode == 'selected' else {'recursive': mode == 'recursive'}
                    if count == 16384:
                        result = backend.children(library.cursor(parent), **kwargs)
                        self.assertEqual(len(result), count)
                        self.assertTrue(all(code == (2 if mode == 'recursive' else 1) for _, code in library.visits))
                    else:
                        with self.assertRaisesRegex(identity.IdentityError, 'CIndex child bound'):
                            backend.children(library.cursor(parent), **kwargs)
                        self.assertEqual(library.visits[-1][1], 0)
                    self.assertEqual(len(library.visits), count)

    def test_recursive_nested_repeated_and_conflicting_targets_keep_order(self):
        library, backend, typedef, variable, main = self.fixture()
        original = library.nodes[variable]['children'][0]
        other_target = library.node(8, 'conflicting_target')
        canonical = library.node(8, 'canonical_other')
        definition = library.node(8, 'definition_other')
        library.canonical[other_target] = canonical
        library.definitions[other_target] = definition
        other_ref = library.node(101, 'conflicting_target')
        library.references[other_ref] = other_target
        wrapper = library.node(100, 'wrapper', [original, other_ref, original])
        library.nodes[variable]['children'] = [original, wrapper, other_ref]
        targets = self.observe(backend)['requests'][0]['targets']
        self.assertEqual([row['reference']['name'] for row in targets],
                         ['probe', 'probe', 'conflicting_target', 'probe', 'conflicting_target'])
        self.assertEqual(targets[2]['canonical']['name'], 'canonical_other')
        self.assertEqual(targets[2]['definition']['name'], 'definition_other')
        self.assertEqual(targets[0], targets[1])
        self.assertEqual([number for number, code in library.visits if code == 2],
                         [original, wrapper, original, other_ref, original, other_ref])

    def test_recursive_selection_is_rejected_before_any_callback(self):
        library, backend, *_ = self.fixture()
        with self.assertRaisesRegex(identity.IdentityError, 'CIndex selection must be direct'):
            backend.children(library.cursor(library.tu), recursive=True, selected=self.selected)
        self.assertEqual(library.visits, [])

    def test_callback_spelling_failures_break_dispose_and_propagate_original_error(self):
        for failure in ('oversize', 'utf8', 'getter', 'spelling'):
            with self.subTest(failure=failure):
                library, backend, typedef, variable, main = self.fixture()
                sentinel = RuntimeError('fake getter sentinel')
                if failure == 'oversize':
                    library.nodes[typedef]['name'] = b'x' * 8193
                    expected = identity.IdentityError
                elif failure == 'utf8':
                    library.nodes[typedef]['name'] = b'\xff'
                    expected = UnicodeDecodeError
                else:
                    expected = RuntimeError
                    library.diagnostics = []
                    def fail(*args):
                        raise sentinel
                    library.handlers['getCString' if failure == 'getter' else 'getCursorSpelling'] = fail
                with self.assertRaises(expected) as raised:
                    self.observe(backend)
                if failure in ('getter', 'spelling'):
                    self.assertIs(raised.exception, sentinel)
                    self.assertEqual(len(library.disposed_strings), 1 if failure == 'getter' else 0)
                self.assertEqual(library.visits, [(typedef, 0)])
                self.assertFalse(library.strings)
                self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_unexpected_traversal_interruption_fails_closed(self):
        library, backend, *_ = self.fixture()
        library.forced_visit_result = 1
        with self.assertRaisesRegex(identity.IdentityError, 'CIndex traversal interrupted'):
            self.observe(backend)
        self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_traversal_binding_exception_still_disposes_unit_and_index(self):
        library, backend, *_ = self.fixture()
        sentinel = RuntimeError('fake traversal sentinel')
        def fail(*args):
            raise sentinel
        library.handlers['visitChildren'] = fail
        with self.assertRaises(RuntimeError) as raised:
            self.observe(backend)
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(library.visits, [])
        self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_observation_bounds_break_before_tail_and_dispose_resources(self):
        for mode, limit in (('visited', 65536), ('stored', 16384), ('recursive', 16384)):
            with self.subTest(mode=mode):
                library, backend, typedef, variable, main = self.fixture()
                leaf = library.node(101, 'irrelevant') if mode != 'stored' else typedef
                if mode == 'recursive':
                    wrapper = library.node(100, 'wrapper', [leaf] * (limit + 5))
                    library.nodes[variable]['children'] = [wrapper]
                    visited_before = 3  # TU siblings precede unfiltered DFS.
                else:
                    library.nodes[library.tu]['children'] = [leaf] * (limit + 5)
                    visited_before = 0
                message = 'CIndex TU visit bound' if mode == 'visited' else 'CIndex child bound'
                with self.assertRaisesRegex(identity.IdentityError, message):
                    self.observe(backend)
                self.assertEqual(len(library.visits), visited_before + limit + 1)
                self.assertEqual(library.visits[-1][1], 0)
                self.assertFalse(library.strings)
                self.assertEqual(library.disposed[-2:], [('unit', 111), ('index', 222)])

    def test_exact_string_bound_and_unselected_kind_do_not_lose_disposal(self):
        library, backend, *_ = self.fixture()
        names = ['', 'x' * 8192]
        nodes = [library.node(8, name) for name in names]
        # This invalid spelling must not be read for a kind outside the filter.
        nodes.append(library.node(101, b'\xff'))
        library.nodes[library.tu]['children'] = nodes
        self.assertEqual(backend.children(library.cursor(library.tu), selected=self.selected), [])
        self.assertEqual(library.visits, [(number, 1) for number in nodes])
        self.assertEqual(len(library.disposed_strings), 2)
        self.assertFalse(library.strings)


class EnteredHeaderProjectionTests(unittest.TestCase):
    def fixture(self, system='Linux'):
        prefix = 'C:/sdk/' if system == 'Windows' else '/sdk/'
        headers = [{'path': prefix + name, 'resolved_path': prefix + name,
                    'bytes': 10, 'sha256': str(index + 1) * 64}
                   for index, name in enumerate(('probe.c', 'wrapper.h', 'query-only.h', 'nested.h'))]
        return headers, prefix

    def project(self, raw, system='Linux', headers=None):
        default, prefix = self.fixture(system)
        return identity.declaration_entered_header_projection(
            raw, default if headers is None else headers, system, prefix + 'probe.c')

    def test_entered_trace_does_not_drop_unentered_dependency_records(self):
        headers, prefix = self.fixture()
        before = copy.deepcopy(headers)
        value = self.project('. /sdk/wrapper.h\n.. /sdk/nested.h\n. /sdk/wrapper.h\n', headers=headers)
        self.assertEqual(value, {'schema': 'codeskeptic-entered-header-projection/v1',
            'input_header_index': 0, 'events': [{'depth': 1, 'header_index': 1},
                {'depth': 2, 'header_index': 3}, {'depth': 1, 'header_index': 1}],
            'entered_header_indices': [0, 1, 3], 'non_entered_dependency_indices': [2]})
        self.assertEqual(headers, before)

    def test_physical_lf_crlf_and_windows_path_equivalence(self):
        value = self.project('. c:\\SDK\\wrapper.h\r\n.. C:/sdk/nested.h\r\n', 'Windows')
        self.assertEqual(value['entered_header_indices'], [0, 1, 3])
        value = self.project('. /sdk/wrapper.h\n', 'Darwin')
        self.assertEqual(value['non_entered_dependency_indices'], [2, 3])

    def test_malformed_diagnostic_or_incomplete_record_never_projects(self):
        for raw in ('', '. /sdk/wrapper.h', '\n', '. /sdk/wrapper.h\n\n',
                    'warning: . /sdk/wrapper.h\n', '. /sdk/wrapper.h\r',
                    '. /sdk/wrapper.h\nsource text\n', '. /sdk/wrapper.h\x00\n',
                    '. /sdk/wrapper.h\u2028. /sdk/nested.h\n',
                    '. /sdk/wrapper.h\v. /sdk/nested.h\n', '.\t/sdk/wrapper.h\n',
                    '.  /sdk/wrapper.h\n', '. relative.h\n', '. /sdk/../sdk/wrapper.h\n'):
            with self.subTest(raw=repr(raw)), self.assertRaises(ValueError):
                self.project(raw)

    def test_missing_unexpected_and_main_file_trace_entries_reject(self):
        for raw in ('. /sdk/unknown.h\n', '. /sdk/probe.c\n', '. /SDK/wrapper.h\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.project(raw)
        headers, _ = self.fixture()
        for altered in (headers[1:], headers + [copy.deepcopy(headers[1])]):
            with self.assertRaises(ValueError):
                self.project('. /sdk/wrapper.h\n', headers=altered)
        headers, _ = self.fixture('Windows')
        headers += [{**headers[1], 'path': 'c:/SDK/WRAPPER.h'}]
        with self.assertRaises(ValueError):
            self.project('. C:/sdk/wrapper.h\n', 'Windows', headers)

    def test_depth_events_and_bytes_are_bounded(self):
        for raw in ('.. /sdk/wrapper.h\n', '. /sdk/wrapper.h\n... /sdk/nested.h\n',
                    '.' * 257 + ' /sdk/wrapper.h\n',
                    '. /sdk/wrapper.h\n' * (identity.MAX_HEADERS + 1),
                    'x' * (identity.MAX_OUTPUT + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.project(raw)

    def test_invalid_shapes_and_hostile_path_characters_reject(self):
        for raw in (None, [], {}, 1, True, '\udcff\n'):
            with self.subTest(raw=repr(raw)), self.assertRaises(ValueError):
                self.project(raw)
        for system in ('Unknown', '', None):
            with self.assertRaises(ValueError):
                self.project('. /sdk/wrapper.h\n', system)
        headers, _ = self.fixture()
        headers[1]['path'] = '/sdk/evil\n.h'
        with self.assertRaises(ValueError):
            self.project('. /sdk/wrapper.h\n', headers=headers)
        headers, _ = self.fixture()
        headers[1]['bytes'] = True
        with self.assertRaises(ValueError):
            self.project('. /sdk/wrapper.h\n', headers=headers)


class WindowsEnteredHeaderTests(unittest.TestCase):
    MODE = 'windows-entered-headers/v1'

    def setUp(self):
        self.legacy = DeclarationTests()
        self.legacy.setUp()
        self.model = self.legacy.model

    def packet(self):
        value, sha, _ = self.legacy.populated()
        def windows(item):
            if type(item) is dict:
                return {key: windows(child) for key, child in item.items()}
            if type(item) is list:
                return [windows(child) for child in item]
            return 'C:' + item if type(item) is str and item.startswith('/') else item
        value = windows(value)
        old = CaseCaptureTests().case_document('Windows')
        native = value['native_identity'] = old['native_identity']
        native['source']['api_models_sha256'] = sha
        value.update(environment=old['environment'], schema='codeskeptic-native-declarations/v3',
                     inclusion_mode=self.MODE)
        probe = value['probe']
        source = identity.declaration_source(self.model, 'Windows').encode()
        for record in (probe['input'], probe['headers'][0]):
            record.update(bytes=len(source), sha256=hashlib.sha256(source).hexdigest())
        probe['headers'].append({'path': 'C:/sdk/non-entered.h', 'resolved_path': 'C:/sdk/non-entered.h',
                                'bytes': 100, 'sha256': 'e' * 64})
        compiler, metadata = native['tools']['clang'], native['platform']['metadata']
        path = probe['input']['path']
        probe['dependency'].update(argv=identity.declaration_command(compiler, 'Windows', metadata, path, True),
            stdout='identity-probe: ' + ' '.join(h['path'] for h in probe['headers']) + '\n')
        probe['syntax']['argv'] = identity.declaration_command(compiler, 'Windows', metadata, path)
        observed = probe['cindex']
        populated = next(row for row in observed['requests'] if row['id'] == 'c.getenv')
        observed['requests'] = [populated if row['id'] == 'c.getenv' else
            {'id': row['id'], 'symbol': row['symbol'], 'expected_type': None,
             'variable_location': None, 'targets': []}
            for row in identity.declaration_requests(self.model, 'Windows')]
        observed['library_version'] = compiler['version']['stdout']
        argv = probe['syntax']['argv'][:-2] + ['-w', '-H'] + probe['syntax']['argv'][-2:]
        raw = '. C:/sdk/stdlib.h\r\n'
        probe.update(backend_not_run=None, header_trace={'argv': argv,
            'command': {'argv': argv[:], 'exit_code': 0, 'stdout': '', 'stderr': raw}, 'failure': None,
            'projection': identity.declaration_entered_header_projection(raw, probe['headers'], 'Windows', path)})
        return value, sha

    def check(self, value, sha):
        return identity.validate_declaration_document(value, self.model, sha)

    def test_entered_equality_preserves_full_dependencies_and_pure_reader(self):
        value, sha = self.packet()
        original = copy.deepcopy(value)
        with (mock.patch.object(identity.subprocess, 'run', side_effect=AssertionError('execution')),
              mock.patch.object(identity, 'file_identity', side_effect=AssertionError('native read')),
              mock.patch.object(identity, 'declaration_backend', side_effect=AssertionError('native load'))):
            result = self.check(value, sha)
        self.assertEqual(value, original)
        self.assertTrue(result['syntax_pass'] and result['header_trace_pass'])
        self.assertEqual(result['inclusion_mode'], self.MODE)
        self.assertIsNone(result['backend_not_run'])
        self.assertEqual(next(r['issues'] for r in result['requests'] if r['id'] == 'c.getenv'), [])
        self.assertEqual(result['coverage']['qualified_library_pairs'], 0)
        self.assertFalse(result['native_qualified'] or result['product_qualified'] or result['task_ready'])

    def test_legacy_packet_still_requires_full_dependency_equality(self):
        value, sha = self.packet()
        value['schema'] = 'codeskeptic-native-declarations/v1'
        del value['inclusion_mode'], value['probe']['header_trace'], value['probe']['backend_not_run']
        with self.assertRaisesRegex(ValueError, 'CIndex include closure'):
            self.check(value, sha)
        value['probe']['cindex']['inclusions'] = sorted(h['path'] for h in value['probe']['headers'])
        result = self.check(value, sha)
        self.assertTrue(result['syntax_pass'])
        self.assertNotIn('header_trace_pass', result)

    def test_versions_modes_and_observation_fields_cannot_be_relabelled(self):
        for mutation in ('v1', 'v2', 'v4', 'missing-mode', 'mode', 'profile', 'trace', 'extra', 'not-run'):
            value, sha = self.packet()
            if mutation.startswith('v'): value['schema'] = 'codeskeptic-native-declarations/' + mutation
            elif mutation == 'missing-mode': del value['inclusion_mode']
            elif mutation == 'mode': value['inclusion_mode'] = 'unknown'
            elif mutation == 'profile': value['profile'] = {'id': 'c17-posix2008/v1'}
            elif mutation == 'trace': del value['probe']['header_trace']
            elif mutation == 'not-run': value['probe']['backend_not_run'] = 'HEADER_TRACE_FAILED'
            else: value['probe']['header_trace']['extra'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(value, sha)

    def test_argv_source_environment_and_raw_projection_are_bound(self):
        for mutation in ('argv', 'observed-argv', 'source', 'environment', 'projection', 'raw', 'stdout', 'exit'):
            value, sha = self.packet()
            trace = value['probe']['header_trace']
            if mutation == 'argv': trace['argv'].insert(1, '-DOTHER=1')
            elif mutation == 'observed-argv': trace['command']['argv'].insert(1, '-fshow-skipped-includes')
            elif mutation == 'source': value['probe']['input']['sha256'] = 'a' * 64
            elif mutation == 'environment': value['environment']['INCLUDE'] = 'C:/elsewhere'
            elif mutation == 'projection': trace['projection']['entered_header_indices'].append(2)
            elif mutation == 'raw': trace['command']['stderr'] += 'source snippet\n'
            elif mutation == 'stdout': trace['command']['stdout'] = 'unexpected'
            else: trace['command']['exit_code'] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(value, sha)

    def test_exact_entered_comparison_rejects_missing_extra_and_full_event_omission(self):
        for paths in (['C:/probe/declarations.c'], ['C:/sdk/stdlib.h'],
                      ['C:/probe/declarations.c', 'C:/sdk/non-entered.h', 'C:/sdk/stdlib.h']):
            value, sha = self.packet()
            value['probe']['cindex']['inclusions'] = paths
            with self.subTest(paths=paths), self.assertRaisesRegex(ValueError, 'CIndex entered-header closure') as caught:
                self.check(value, sha)
            self.assertFalse(hasattr(caught.exception, '_inclusion_rejection'))
        value, sha = self.packet()
        probe = value['probe']
        probe['cindex']['inclusions'] = sorted(h['path'] for h in probe['headers'])
        # A whole omitted final event still has legal LF framing. Exact equality rejects it.
        with self.assertRaisesRegex(ValueError, 'CIndex entered-header closure'):
            self.check(value, sha)

    def test_header_trace_capture_retains_only_successful_path_text(self):
        value, _ = self.packet()
        probe = value['probe']
        argv, raw = probe['header_trace']['argv'], probe['header_trace']['command']['stderr'].encode()
        cases = [(SimpleNamespace(returncode=0, stdout=b'', stderr=raw), None),
                 (SimpleNamespace(returncode=0, stdout=b'', stderr=raw + b'secret-source\n'), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=0, stdout=b'', stderr=b'\xff'), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=0, stdout=b'secret-source', stderr=raw), 'INVALID_RESULT'),
                 (SimpleNamespace(returncode=1, stdout=b'', stderr=raw + b'secret-source'), 'PROCESS_FAILED'),
                 (SimpleNamespace(returncode=0, stdout=b'', stderr=b'x' * (identity.MAX_OUTPUT + 1)), 'OUTPUT_LIMIT'),
                 (subprocess.TimeoutExpired(argv, 30, output=b'secret-source', stderr=raw), 'TIMEOUT'),
                 (OSError('secret-source'), 'START_FAILED')]
        for process, kind in cases:
            with self.subTest(kind=kind), mock.patch.object(identity.subprocess, 'run') as run:
                if isinstance(process, BaseException): run.side_effect = process
                else: run.return_value = process
                result = identity.capture_declaration_header_trace(argv, probe['headers'], 'Windows', probe['input']['path'])
            self.assertEqual(run.call_args.args, (argv,))
            self.assertEqual(run.call_args.kwargs, {'env': identity.checked_environment(identity.os.environ),
                                                   'capture_output': True, 'timeout': 30, 'check': False})
            selected = identity.validate_declaration_header_trace(result, argv, probe['headers'], 'Windows', probe['input']['path'])
            if kind is None:
                self.assertEqual(result, probe['header_trace'])
                self.assertEqual(selected, result['projection'])
            else:
                self.assertEqual(result['failure']['kind'], kind)
                self.assertIsNone(result['command'])
                self.assertIsNone(result['projection'])
                self.assertIsNone(selected)
                self.assertNotIn('secret-source', identity.canonical(result))

    def test_trace_failure_requires_explicit_unstarted_backend_and_preserves_syntax_red(self):
        value, sha = self.packet()
        probe = value['probe']
        with mock.patch.object(identity.subprocess, 'run', side_effect=OSError('private')):
            probe['header_trace'] = identity.capture_declaration_header_trace(
                probe['header_trace']['argv'], probe['headers'], 'Windows', probe['input']['path'])
        probe.update(cindex=None, backend_not_run='HEADER_TRACE_FAILED')
        for code in (0, 1):
            probe['syntax']['exit_code'] = code
            result = self.check(value, sha)
            self.assertFalse(result['syntax_pass'] or result['header_trace_pass'])
            for row in result['requests']:
                self.assertEqual(row['issues'], ['HEADER_TRACE_FAILED', 'BACKEND_NOT_RUN'] + (['SYNTAX_FAILED'] if code else []))
                self.assertEqual(row['state'], 'INCOMPLETE')
        for mutation in ('not-run', 'observed', 'failure'):
            changed = copy.deepcopy(value)
            if mutation == 'not-run': changed['probe']['backend_not_run'] = None
            elif mutation == 'observed': changed['probe']['cindex'] = self.packet()[0]['probe']['cindex']
            else: changed['probe']['backend_failure'] = copy.deepcopy(probe['header_trace']['failure'])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(changed, sha)

    def test_unsupported_mode_platform_and_profile_stop_before_native_capture(self):
        for system, mode, profile in (('Linux', self.MODE, None), ('Darwin', self.MODE, None),
                                      ('Windows', 'unknown', None), ('Windows', self.MODE, 'c17-posix2008/v1')):
            args = SimpleNamespace(declaration_inclusion_mode=mode, declaration_profile=profile)
            with (self.subTest(system=system, mode=mode, profile=profile),
                  mock.patch.object(identity.platform, 'system', return_value=system),
                  mock.patch.object(identity, 'capture', side_effect=AssertionError('native capture')),
                  self.assertRaises(ValueError)):
                identity.capture_declarations(args)

    @contextmanager
    def writer(self, output, value, sha, **options):
        """Actual writer with synthetic Windows native I/O on either host path flavor."""
        native_path = Path
        aliases = {}

        class ProbePath:
            def __init__(self, actual, lexical):
                self.actual, self.lexical = actual, lexical
                aliases[lexical] = self

            def __str__(self):
                return self.lexical

            def __truediv__(self, name):
                return ProbePath(self.actual / name, self.lexical + '/' + name)

            def resolve(self, strict=False):
                self.actual.resolve(strict=strict)
                return self

            def is_absolute(self):
                return True

            def stat(self):
                return self.actual.stat()

            def open(self, *args, **kwargs):
                return self.actual.open(*args, **kwargs)

        def paths(path):
            if isinstance(path, ProbePath):
                return path
            if str(path) in aliases:
                return aliases[str(path)]
            actual = native_path(path)
            if actual.name.startswith('codeskeptic-declarations-'):
                return ProbePath(actual, 'C:/synthetic-probe')
            return actual

        raw = identity.canonical(value['probe']['cindex']).encode()
        with mock.patch.object(identity, 'Path', side_effect=paths):
            with self.legacy.mocked_declaration_capture(output, raw, fixture=(value, sha), **options) as result:
                yield result

    def test_actual_v3_writer_selects_trace_and_keeps_original_worker_config(self):
        for syntax_exit, response in ((0, None), (1, None),
                (1, SimpleNamespace(returncode=1, stdout=b'', stderr=b'private-source\n')),
                (0, subprocess.TimeoutExpired(['/clang'], 30, output=b'private-source'))):
            value, sha = self.packet()
            with self.subTest(syntax_exit=syntax_exit, response=response), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve() / 'v3.json'
                with self.writer(output, value, sha, syntax_exit=syntax_exit, trace_response=response) as (argv, stderr, emitted):
                    status = identity.main(argv + ['--declaration-inclusion-mode', self.MODE])
                    self.assertEqual(status, 2 if syntax_exit or response is not None else 0, stderr.getvalue())
                    self.assertEqual(stderr.getvalue(), '')
                retained = json.loads(output.read_text())
                probe = retained['probe']
                result = self.check(retained, sha)
                self.assertEqual(probe['header_trace']['argv'], emitted['trace_argv'])
                self.assertEqual(probe['syntax']['argv'], emitted['syntax_argv'])
                self.assertNotIn('-w', probe['syntax']['argv'])
                self.assertEqual(probe['syntax']['exit_code'], syntax_exit)
                self.assertEqual(len(probe['headers']), 3)
                self.assertNotIn('private-source', output.read_text())
                if response is None:
                    self.assertEqual(set(emitted['config']), {'native_identity', 'environment', 'library', 'input'})
                    self.assertEqual(emitted['config']['input'], probe['input'])
                    self.assertEqual(probe['header_trace']['projection']['non_entered_dependency_indices'], [2])
                    self.assertIsNone(probe['backend_failure'])
                else:
                    self.assertNotIn('config', emitted)
                    self.assertIsNone(probe['cindex'])
                    self.assertIsNone(probe['backend_failure'])
                    self.assertEqual(probe['backend_not_run'], 'HEADER_TRACE_FAILED')
                    self.assertFalse(result['syntax_pass'])

    def test_actual_v3_writer_rejects_worker_extra_include_without_legacy_annotation(self):
        value, sha = self.packet()
        value['probe']['cindex']['inclusions'].append('C:/sdk/non-entered.h')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'failed.json'
            with self.writer(output, value, sha, syntax_exit=1) as (argv, stderr, emitted):
                self.assertEqual(identity.main(argv + ['--declaration-inclusion-mode', self.MODE]), 2)
                log = stderr.getvalue()
            retained = json.loads(output.read_text())
            self.assertEqual(retained['probe']['backend_failure']['kind'], 'INVALID_RESULT')
            self.assertIsNone(retained['probe']['backend_not_run'])
            self.assertNotIn('DECLARATION_INCLUSION_DIAGNOSTIC', log)
            DeclarationResultDiagnosticTests().diagnostic(log, retained['probe']['backend_failure'], 'VALIDATE')
            self.assertTrue(all(row['issues'] == ['BACKEND_FAILED', 'SYNTAX_FAILED']
                                for row in self.check(retained, sha)['requests']))

    def test_v3_child_and_cindex_adapter_keep_original_full_argv_and_zero_parse_options(self):
        value, _ = self.packet()
        native, probe = value['native_identity'], value['probe']
        config = {key: value[key] for key in ('native_identity', 'environment', 'library')}
        config['input'] = probe['input']
        files = {str(Path(record['path'])): record for record in (probe['input'], value['library'])}
        with (mock.patch.object(identity.platform, 'system', return_value='Windows'),
              mock.patch.object(identity, 'case_environment', return_value=value['environment']),
              mock.patch.object(identity, 'source_identity', return_value=native['source']),
              mock.patch.object(identity, 'file_identity', side_effect=lambda path: files[str(path)]),
              mock.patch.object(identity, 'declaration_backend') as backend):
            backend.return_value.observe.return_value = {'synthetic': True}
            self.assertEqual(identity.declaration_worker(config), {'synthetic': True})
            self.assertEqual(backend.return_value.observe.call_args.args[0], probe['syntax']['argv'])
        library = FakeCIndexLibrary()
        library.backend().observe(probe['syntax']['argv'], [])
        self.assertEqual(library.index_calls, [(0, 0)])
        self.assertEqual(library.parse_calls, [{'index': 222, 'source': None, 'argv': probe['syntax']['argv'],
                                              'unsaved': None, 'unsaved_count': 0, 'options': 0}])

    def test_forged_trace_failures_and_projection_scalar_types_reject(self):
        for mutation in ('zero-exit', 'bool-exit', 'negative-bytes', 'empty-hash', 'extra', 'kind',
                         'oversize', 'startup-stream', 'retained-command', 'retained-projection'):
            value, sha = self.packet()
            probe = value['probe']
            with mock.patch.object(identity.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 30)):
                trace = identity.capture_declaration_header_trace(probe['header_trace']['argv'],
                    probe['headers'], 'Windows', probe['input']['path'])
            if mutation == 'zero-exit': trace['failure']['exit_code'] = 0
            elif mutation == 'bool-exit': trace['failure'].update(kind='PROCESS_FAILED', exit_code=True)
            elif mutation == 'negative-bytes': trace['failure']['stderr']['bytes'] = -1
            elif mutation == 'empty-hash': trace['failure']['stderr']['sha256'] = 'a' * 64
            elif mutation == 'extra': trace['failure']['secret'] = 'unexpected'
            elif mutation == 'kind': trace['failure']['kind'] = 'SUCCESS'
            elif mutation == 'oversize': trace['failure'].update(kind='OUTPUT_LIMIT', exit_code=0)
            elif mutation == 'startup-stream':
                trace['failure'].update(kind='START_FAILED')
                trace['failure']['stderr'] = {'bytes': 1, 'sha256': 'a' * 64}
            elif mutation == 'retained-command': trace['command'] = probe['header_trace']['command']
            else: trace['projection'] = probe['header_trace']['projection']
            probe.update(header_trace=trace, cindex=None, backend_not_run='HEADER_TRACE_FAILED')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(value, sha)
        for scalar in (False, 0.0):
            value, sha = self.packet()
            value['probe']['header_trace']['projection']['input_header_index'] = scalar
            with self.assertRaisesRegex(ValueError, 'projection mismatch'):
                self.check(value, sha)

    def test_public_v3_reader_cli_and_unknown_mode_fail_closed(self):
        root = Path(identity.__file__).resolve().parents[1]
        value, _ = self.packet()
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory).resolve() / 'packet.json'
            packet.write_text(identity.canonical(value), encoding='utf-8')
            command = [sys.executable, '-B', identity.__file__, 'check-declarations', str(packet), '--root', str(root)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['header_trace_pass'])
            value['probe']['header_trace']['command']['stderr'] += 'private-source\n'
            packet.write_text(identity.canonical(value), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'private-source', result.stderr)
            args = ['capture-declarations', '--root', str(root), '--source-sha', 'a' * 40,
                    '--libclang', '/not-loaded', '--output', str(packet.parent / 'not-written.json')]
            for role in identity.TOOL_ROLES:
                args += ['--' + role, '/not-executed']
            with (mock.patch.object(identity, 'capture', side_effect=AssertionError('capture')),
                  mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as caught):
                identity.main(args + ['--declaration-inclusion-mode', 'unknown'])
            self.assertEqual(caught.exception.code, 2)

    def test_location_checks_keep_full_hashed_universe_and_warnings_remain_visible(self):
        value, sha = self.packet()
        probe = value['probe']
        row = next(r for r in probe['cindex']['requests'] if r['id'] == 'c.getenv')
        row['targets'][0]['canonical']['location'] = self.legacy.position('C:/sdk/non-entered.h')
        probe['syntax']['stderr'] = {'bytes': 13, 'sha256': hashlib.sha256(b'prior warning').hexdigest()}
        probe['cindex']['diagnostics'] = [{'severity': 2, 'bytes': 13, 'sha256': hashlib.sha256(b'prior warning').hexdigest()}]
        before = copy.deepcopy(value)
        self.assertTrue(self.check(value, sha)['syntax_pass'])
        self.assertEqual(value, before)
        probe['cindex']['diagnostics'][0]['severity'] = 3
        self.assertFalse(self.check(value, sha)['syntax_pass'])
        row['targets'][0]['canonical']['location'] = self.legacy.position('C:/unhashed.h')
        with self.assertRaisesRegex(ValueError, 'outside hashed closure'):
            self.check(value, sha)


if __name__ == '__main__':
    unittest.main()
