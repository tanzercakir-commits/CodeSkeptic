#!/usr/bin/env python3
"""Focused metadata tests; no analyzer or native qualification is performed."""
import copy
import hashlib
import io
import json
from pathlib import Path
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
        self.assertEqual(workflow.count('if: always()'), 3)

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


class WorkflowTests(unittest.TestCase):
    def test_every_native_lane_runs_external_input_staging_ground_truth_and_recipe_tests(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/product-identity.yml').read_text()
        self.assertEqual(workflow.count('-k GccStaging -k ExternalInput -k AllRuleGroundTruthTests '
                                       '-k NativeRecipeTests -k RetainedCandidateTests -k RetainedGroundTruthTests -q'), 2)
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
        self.assertEqual(workflow.count('sys.version_info >= (3, 10)'), 2)

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


if __name__ == '__main__':
    unittest.main()
