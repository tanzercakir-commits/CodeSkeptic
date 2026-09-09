#!/usr/bin/env python3
"""Focused metadata tests; no analyzer or native qualification is performed."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
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
                       'stderr': 'static assertion failed: ' + marker if marker else ''}
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
                   'stderr': 'static assertion failed selected int width\nPRIVATE_SOURCE_SENTINEL'}
        record = identity.case_record(command, 'selected int width')
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', json.dumps(record))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'invalid.json'
            path.write_text('{"bad":PRIVATE_SOURCE_SENTINEL}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-B', identity.__file__, 'check-case', str(path)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'IDENTITY_INVALID case observation rejected\n')

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


class WorkflowTests(unittest.TestCase):
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
