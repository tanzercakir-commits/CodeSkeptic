#!/usr/bin/env python3
"""Synthetic manifest accounting checks; no sample or product quality claim."""
import copy
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import product_profiles as profiles


def quota_rows():
    rows = []
    for bucket in profiles.BUCKETS:
        family, separator, subtype = bucket.partition("/")
        for role in ("buggy", "safe"):
            for number in range(30):
                name = bucket.replace("/", "-") + "-" + role + "-" + str(number)
                rows.append({"id": name, "family": family, "subprofile": subtype if separator else None,
                             "role": role, "quota": True, "origin": "origin-" + str(number % 3),
                             "cluster": name, "sha256": format(len(rows) + 1, "064x"),
                             "selection": "independent-evaluation"})
    return rows


class NativeRecipeTests(unittest.TestCase):
    def platform_source_review_fixture(self):
        staged = self.staged_fixture()
        recipes = [{'path': path, 'sha256': profiles.file_sha(staged.repo / path)}
                   for path in profiles.GCC_PLATFORM_FILES.values()]
        ground_truth = {'path': profiles.GCC_GROUND_TRUTH,
                        'sha256': profiles.file_sha(staged.repo / profiles.GCC_GROUND_TRUTH)}
        staged.review = {'schema': 'codeskeptic-platform-source-applicability-review/v1',
                         'repository_head': 'd' * 40, 'implementer': '/root',
                         'verifier': '/root/synthetic_reviewer',
                         'verdict': 'ACCEPT_CONDITIONAL_PLATFORM_SOURCE_LABELS', 'findings': [],
                         'source_sha256': profiles.GCC_CASE_SHA,
                         'recipes': copy.deepcopy(recipes), 'ground_truth': copy.deepcopy(ground_truth),
                         'additional_quota_examples': 0,
                         'conditions': ['Synthetic conditional review; no real platform qualification.'],
                         'rationale': 'Synthetic metadata fixture, not an independent source judgment.',
                         'qualification': {key: False for key in profiles.GCC_PLATFORM_QUALIFICATION
                                           if key != 'platform_source_labels_reviewed'}}
        staged.review_path = staged.repo.parent / 'platform-review.json'
        staged.index_path = staged.repo / 'tests/product_corpus/platform_source_labels.json'
        staged.index = {'schema': 'codeskeptic-product-reviewed-platform-source-labels/v1',
                        'state': 'CONDITIONAL_PLATFORM_SOURCE_LABELS_NOT_NATIVE_QUALIFIED',
                        'recipes': recipes, 'ground_truth': ground_truth,
                        'review': {'path': str(staged.review_path),
                                   'sha256': staged.write(staged.review_path, staged.review)},
                        'boundary': 'Synthetic index; no task or native qualification.'}
        staged.write(staged.index_path, staged.index)
        return staged

    def test_platform_source_review_metadata_is_conditional_and_adds_no_quota(self):
        staged = self.platform_source_review_fixture()
        result = profiles.gcc_platform_source_review_metadata(
            staged.review, staged.index['recipes'], staged.index['ground_truth'])
        self.assertTrue(result['platform_source_labels_reviewed'])
        self.assertTrue(result['conditional_only'])
        self.assertFalse(result['conditions_satisfied'])
        self.assertEqual(result['additional_quota_examples'], 0)
        self.assertEqual(result['conditions'], staged.review['conditions'])
        self.assertTrue(all(result[key] is False for key in staged.review['qualification']))

    def test_platform_source_review_metadata_rejects_forged_identity_or_qualification(self):
        staged = self.platform_source_review_fixture()
        replacements = [('schema', 'other'), ('repository_head', 'HEAD'), ('repository_head', '0' * 40),
                        ('verdict', 'PASS'), ('verdict', 'HOLD'), ('findings', ['unresolved']),
                        ('implementer', '/root/synthetic_reviewer'), ('verifier', 'invalid'),
                        ('source_sha256', 'e' * 64), ('additional_quota_examples', False),
                        ('additional_quota_examples', 1), ('rationale', ''), ('rationale', 'x' * 8193),
                        ('conditions', []), ('conditions', ['']), ('conditions', [True]),
                        ('conditions', ['x' * 2049]), ('conditions', ['x'] * 33), ('conditions', 'text'),
                        ('recipes', list(reversed(staged.index['recipes']))),
                        ('ground_truth', {'path': profiles.GCC_GROUND_TRUTH, 'sha256': 'e' * 64})]
        for key in staged.review['qualification']:
            for bad in (True, 0):
                replacements.append(('qualification', {**staged.review['qualification'], key: bad}))
        replacements.append(('qualification', {**staged.review['qualification'], 'platform_source_labels_reviewed': True}))
        for key, replacement in replacements:
            review = copy.deepcopy(staged.review)
            review[key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                profiles.gcc_platform_source_review_metadata(review, staged.index['recipes'], staged.index['ground_truth'])

    def test_platform_source_review_reader_reopens_recipes_and_does_not_execute_native_tools(self):
        staged = self.platform_source_review_fixture()
        with mock.patch.object(profiles, 'verify_ground_truth_index', return_value=staged.accepted), \
             mock.patch.object(profiles, 'verify_reviewed_files') as objects, \
             mock.patch.object(profiles.subprocess, 'run') as execute, \
             mock.patch.object(profiles.urllib.request, 'urlopen') as download:
            before = profiles.verify_gcc_platform_recipes(staged.repo)
            result = profiles.verify_gcc_platform_source_labels(staged.repo)
            after = profiles.verify_gcc_platform_recipes(staged.repo)
        self.assertEqual(before, after)
        self.assertFalse(after['platform_source_labels_reviewed'])
        self.assertTrue(result['platform_source_labels_reviewed'])
        self.assertTrue(result['conditional_only'])
        self.assertFalse(result['conditions_satisfied'])
        self.assertEqual(result['recipe_count'], 2)
        self.assertEqual(result['unique_source_count'], 1)
        self.assertEqual(result['source_selection_quota_examples'], 1)
        self.assertEqual(result['additional_quota_examples'], 0)
        for recipe in result['recipes']:
            self.assertTrue(recipe['platform_source_labels_reviewed'])
            self.assertFalse(recipe['conditions_satisfied'])
        for key in staged.review['qualification']:
            self.assertIs(result[key], False)
        review_calls = [call for call in objects.call_args_list if call.args[1] == 'd' * 40]
        self.assertEqual(len(review_calls), 1)
        self.assertEqual(len(review_calls[0].args[2]), 8)
        execute.assert_not_called()
        download.assert_not_called()

    def test_platform_source_review_reader_rejects_missing_stale_or_changed_evidence_privately(self):
        mutations = ('missing-index', 'missing-review', 'review-hash', 'review-in-repo', 'review-symlink',
                     'duplicate-recipe', 'missing-recipe', 'wrong-path', 'recipe-hash', 'cdb-hash', 'labels-hash',
                     'held-review', 'same-agent', 'empty-conditions', 'stale-head', 'source-unavailable',
                     'native-hash', 'final-index', 'final-review', 'final-recipe')
        for mutation in mutations:
            staged = self.platform_source_review_fixture()
            recipe_path = staged.repo / profiles.GCC_PLATFORM_FILES['Windows']
            if mutation == 'missing-review': staged.review_path.unlink()
            elif mutation == 'review-hash': staged.review_path.write_bytes(b'PRIVATE_SENTINEL')
            elif mutation == 'review-in-repo': staged.index['review']['path'] = str(staged.repo / 'private.json')
            elif mutation == 'review-symlink':
                saved = staged.review_path.with_suffix('.saved')
                staged.review_path.rename(saved)
                try:
                    staged.review_path.symlink_to(saved)
                except OSError as error:
                    with self.subTest(mutation=mutation):
                        self.skipTest('temporary symlink unavailable: ' + str(error))
                    continue
            elif mutation == 'duplicate-recipe': staged.index['recipes'] *= 2
            elif mutation == 'missing-recipe': staged.index['recipes'].pop()
            elif mutation == 'wrong-path': staged.index['recipes'][0]['path'] = '../PRIVATE_SENTINEL'
            elif mutation == 'recipe-hash': recipe_path.write_bytes(b'PRIVATE_SENTINEL')
            elif mutation == 'cdb-hash':
                (staged.repo / staged.rows['Windows'].value['compilation_database']['path']).write_bytes(b'PRIVATE_SENTINEL')
            elif mutation == 'labels-hash': (staged.repo / profiles.GCC_GROUND_TRUTH).write_bytes(b'PRIVATE_SENTINEL')
            elif mutation in ('held-review', 'same-agent', 'empty-conditions'):
                key, replacement = {'held-review': ('verdict', 'HOLD'), 'same-agent': ('verifier', '/root'),
                                    'empty-conditions': ('conditions', [])}[mutation]
                staged.review[key] = replacement
                staged.index['review']['sha256'] = staged.write(staged.review_path, staged.review)
            elif mutation == 'native-hash':
                Path(staged.rows['Windows'].value['native_evidence']['case']['path']).write_bytes(b'PRIVATE_SENTINEL')
            staged.write(staged.index_path, staged.index)
            if mutation == 'missing-index': staged.index_path.unlink()
            def reviewed(repo, head, links, **kwargs):
                if mutation == 'stale-head' and head == 'd' * 40:
                    raise ValueError('PRIVATE_SENTINEL')
                if mutation.startswith('final-'):
                    target = {'final-index': staged.index_path, 'final-review': staged.review_path,
                              'final-recipe': recipe_path}[mutation]
                    target.write_bytes(b'PRIVATE_SENTINEL')
            with mock.patch.object(profiles, 'verify_ground_truth_index', return_value=staged.accepted,
                                   side_effect=ValueError('PRIVATE_SENTINEL') if mutation == 'source-unavailable' else None), \
                 mock.patch.object(profiles, 'verify_reviewed_files', side_effect=reviewed), \
                 self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^reviewed GCC platform source labels rejected$'):
                profiles.verify_gcc_platform_source_labels(staged.repo)

    def test_platform_source_review_recipe_and_cdb_links_require_actual_commit_bytes(self):
        repo = Path(__file__).resolve().parents[1]
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
        links = [{'path': path, 'sha256': profiles.file_sha(repo / path)} for path in profiles.GCC_PLATFORM_FILES.values()]
        links += [profiles.read_json(repo / link['path'])['compilation_database'] for link in list(links)]
        links += [{'path': profiles.GCC_GROUND_TRUTH, 'sha256': profiles.file_sha(repo / profiles.GCC_GROUND_TRUTH)}]
        profiles.verify_reviewed_files(repo, head, links)
        for offset in range(len(links)):
            changed = copy.deepcopy(links)
            changed[offset]['sha256'] = 'e' * 64
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, head, changed)

    def test_platform_source_review_cli_is_private_and_has_no_root_override(self):
        with tempfile.TemporaryDirectory(prefix='codeskeptic-platform-review-cli-') as temporary:
            root = Path(temporary).resolve()
            for suffix in ([], ['--binding', str(root / 'PRIVATE_SENTINEL')], ['--external-root', str(root)],
                           ['--evidence-root', str(root)]):
                result = subprocess.run([sys.executable, '-B', profiles.__file__, 'platform-source-labels-check',
                                         '--root', str(root), *suffix], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)

    def fixture(self, system):
        import product_identity as identity
        from test_product_identity import CaseCaptureTests
        repo = Path(__file__).resolve().parents[1]
        value = profiles.read_json(repo / profiles.GCC_PLATFORM_FILES[system])
        candidate = profiles.read_json(repo / profiles.GCC_SOURCE_CANDIDATE)
        labels = profiles.read_json(repo / profiles.GCC_GROUND_TRUTH)
        native = CaseCaptureTests().case_document(system)
        native['binding']['binding_sha256'] = candidate['links']['source_binding']['sha256']
        native['binding']['adjudication_sha256'] = candidate['links']['source_review']['sha256']
        native['source_files'][identity.CASE_SOURCE_FILES[2]] = native['binding']['binding_sha256']
        native['source_files'][identity.CASE_SOURCE_FILES[3]] = native['binding']['adjudication_sha256']
        native['environment'].update(GITHUB_SHA=native['native_identity']['source']['head'],
                                     GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        native['native_identity']['platform']['environment'] = identity.observed_environment(native['environment'])
        parts = profiles.gcc_platform_recipe_parts(native)
        cdb = parts.pop('compilation_database')
        value['recipe'] = copy.deepcopy(parts)
        value['native_evidence'].update(run_id=123, producer_source=copy.deepcopy(native['native_identity']['source']))
        return SimpleNamespace(value=value, cdb=copy.deepcopy(cdb), native=native, candidate=candidate, labels=labels)

    def staged_fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-native-recipe-')
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        repo = base / 'repo'
        original_repo = Path(__file__).resolve().parents[1]
        def write(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(profiles.canonical(value).encode())
            return profiles.file_sha(path)
        for relative in (profiles.GCC_SOURCE_CANDIDATE, profiles.GCC_GROUND_TRUTH, profiles.GROUND_TRUTH_INDEX,
                         profiles.GCC_CANDIDATE_LINKS['analysis_profile']):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((original_repo / relative).read_bytes())
        rows = {}
        for system, relative in profiles.GCC_PLATFORM_FILES.items():
            row = self.fixture(system)
            row.run = {'id': 123, 'run_attempt': 1, 'head_sha': row.native['native_identity']['source']['head'],
                       'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/product-identity.yml',
                       'event': 'push', 'head_branch': 'agent/cs3-ch08-s01-u003-frozen-product-profiles',
                       'repository': {'full_name': 'tanzercakir-commits/CodeSkeptic'}}
            for key, document in (('case', row.native), ('run', row.run)):
                path = base / (system + '-' + key + '.json')
                row.value['native_evidence'][key] = {'path': str(path), 'sha256': write(path, document)}
            row.value['compilation_database']['sha256'] = write(repo / row.value['compilation_database']['path'], row.cdb)
            write(repo / relative, row.value)
            rows[system] = row
        accepted = {'source_sha256': profiles.GCC_CASE_SHA,
                    'candidate_sha256': profiles.file_sha(repo / profiles.GCC_SOURCE_CANDIDATE),
                    'record_sha256': profiles.file_sha(repo / profiles.GCC_GROUND_TRUTH),
                    'source_selection_quota_examples': 1, 'source_labels_independently_reviewed': True}
        return SimpleNamespace(repo=repo, rows=rows, accepted=accepted, write=write)

    def test_native_source_mapping_is_exact_and_does_not_relocate_headers(self):
        for system, path in (('Windows', r'D:\case input\case.c'), ('Darwin', '/case input/case.c')):
            mapping = {'kind': 'EXACT_SOURCE_ONLY', 'logical_path': '/input/case.c', 'native_path': path}
            self.assertEqual(profiles.map_gcc_native_source(system, mapping, path), '/input/case.c')
            with self.assertRaises(ValueError):
                profiles.map_gcc_native_source(system, mapping, path + '.other')

    def test_prospective_commands_preserve_isolated_and_all_current_selections(self):
        from test_product_identity import CaseCaptureTests
        for system in ('Windows', 'Darwin'):
            native = CaseCaptureTests().case_document(system)
            parts = profiles.gcc_platform_recipe_parts(native)
            self.assertEqual(parts['compilation_database'][0]['arguments'], native['probes']['candidate']['command']['argv'])
            analyzer = parts['analyzer']
            self.assertEqual(analyzer['repetitions'], 3)
            self.assertEqual(analyzer['outer_case_timeout_seconds'], 30)
            self.assertIsNone(analyzer['executable_sha256'])
            self.assertIn('--disable-rule', analyzer['memory_leak_only'])
            self.assertIn('--assumptions', analyzer['all_current_rules_including_assumptions'])
            self.assertNotIn('--enable-rule', analyzer['all_current_rules_including_assumptions'])

    def test_mapping_rejects_other_sources_traversal_devices_and_host_confusion(self):
        for system, native, bad_paths in (
                ('Windows', r'D:\case input\case.c', ('case.c', r'\case input\case.c', r'D:case.c',
                  r'D:\case input\..\case input\case.c', r'D:\case input\case.c:stream',
                  r'\\server\share\case.c', r'\\?\D:\case input\case.c', r'D:\case input\case.c.other',
                  r'D:\case input\sdk\stdlib.h', '/case input/case.c', 'PRIVATE\nSENTINEL')),
                ('Darwin', '/case input/case.c', ('case.c', '/case input/../case input/case.c',
                  '/case input/./case.c', '//case input/case.c', '/case input2/case.c', '/sdk/stdlib.h',
                  r'C:\case input\case.c', '/case input/CASE.C'))):
            mapping = {'kind': 'EXACT_SOURCE_ONLY', 'logical_path': '/input/case.c', 'native_path': native}
            for path in bad_paths:
                with self.subTest(system=system, path=path), self.assertRaises(ValueError):
                    profiles.map_gcc_native_source(system, mapping, path)
        mapping = {'kind': 'EXACT_SOURCE_ONLY', 'logical_path': '/input/case.c', 'native_path': r'D:\case input\case.c'}
        self.assertEqual(profiles.map_gcc_native_source('Windows', mapping, 'd:/CASE INPUT/CASE.C'), '/input/case.c')
        for key, replacement in (('kind', 'PREFIX_REPLACE'), ('logical_path', '/other.c'), ('native_path', 'relative')):
            changed = {**mapping, key: replacement}
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.map_gcc_native_source('Windows', changed, mapping['native_path'])

    def test_both_recipe_shapes_are_pending_and_do_not_add_sources(self):
        for system in profiles.GCC_PLATFORM_FILES:
            row = self.fixture(system)
            result = profiles.gcc_platform_recipe_metadata(row.value, row.cdb, row.native, row.candidate, row.labels)
            self.assertEqual(result['command_count'], 1)
            self.assertEqual(result['candidate_input_count'], 2)  # Synthetic metadata, not observed real headers.
            self.assertEqual(result['additional_quota_examples'], 0)
            self.assertTrue(all(result[key] is False for key in profiles.GCC_PLATFORM_QUALIFICATION))

    def test_recipe_rejects_commands_models_links_closure_references_and_false_qualification(self):
        mutations = ('source', 'cdb-empty', 'cdb-duplicate', 'cdb-c17', 'cdb-resource', 'cdb-target', 'cdb-compiler',
                     'cdb-extra-source', 'cdb-directory', 'compiler-hash', 'closure', 'closure-count-bool', 'abi-width',
                     'environment-resource', 'environment-extra', 'environment-path', 'environment-inherit', 'cwd', 'binary', 'binary-hash',
                     'isolated-selection', 'all-current-selection', 'fake-enable', 'cache', 'timeout', 'repeat-bool',
                     'frontend-state', 'frontend-argument', 'reference-missing', 'reference-file', 'reference-hash',
                     'label-link', 'linux-link', 'quota', 'quota-bool', 'qualification', 'applicability', 'observed')
        for system in profiles.GCC_PLATFORM_FILES:
            for mutation in mutations:
                row = self.fixture(system)
                value, cdb = row.value, row.cdb
                recipe = value['recipe']
                if mutation == 'source': recipe['source_mapping']['native_path'] += '.other'
                elif mutation == 'cdb-empty': cdb.clear()
                elif mutation == 'cdb-duplicate': cdb *= 2
                elif mutation == 'cdb-c17': cdb[0]['arguments'][7] = '-std=c11'
                elif mutation == 'cdb-resource': cdb[0]['arguments'][4] += '-other'
                elif mutation == 'cdb-target': cdb[0]['arguments'][8] = '--target=i686-pc-windows-msvc'
                elif mutation == 'cdb-compiler': cdb[0]['arguments'][0] += '-other'
                elif mutation == 'cdb-extra-source': cdb[0]['arguments'].append('other.c')
                elif mutation == 'cdb-directory': cdb[0]['directory'] += '-other'
                elif mutation == 'compiler-hash': recipe['compiler']['file']['sha256'] = 'e' * 64
                elif mutation == 'closure': recipe['header_closures']['candidate']['records_sha256'] = 'e' * 64
                elif mutation == 'closure-count-bool': recipe['header_closures']['abi']['input_count'] = True
                elif mutation == 'abi-width': recipe['abi_preflight']['size_t_bytes'] = 4
                elif mutation == 'environment-resource': recipe['analyzer']['environment']['CODESKEPTIC_RESOURCE_DIR'] += '-other'
                elif mutation == 'environment-extra': recipe['analyzer']['environment']['CPATH'] = 'PRIVATE_SENTINEL'
                elif mutation == 'environment-path': recipe['analyzer']['environment']['PATH'] += ':other'
                elif mutation == 'environment-inherit': recipe['analyzer']['inherit_environment'] = True
                elif mutation == 'cwd': recipe['analyzer']['cwd'] += '-other'
                elif mutation == 'binary': recipe['analyzer']['executable'] += '-other'
                elif mutation == 'binary-hash': recipe['analyzer']['executable_sha256'] = 'e' * 64
                elif mutation == 'isolated-selection': recipe['analyzer']['memory_leak_only'][-1] = 'bounds'
                elif mutation == 'all-current-selection': recipe['analyzer']['all_current_rules_including_assumptions'].pop()
                elif mutation == 'fake-enable': recipe['analyzer']['all_current_rules_including_assumptions'] += ['--enable-rule', 'sql-injection']
                elif mutation == 'cache': recipe['analyzer']['memory_leak_only'].remove('--no-analysis-cache')
                elif mutation == 'timeout': recipe['analyzer']['outer_case_timeout_seconds'] += 1
                elif mutation == 'repeat-bool': recipe['analyzer']['repetitions'] = True
                elif mutation == 'frontend-state': recipe['frontend']['state'] = 'VERIFIED'
                elif mutation == 'frontend-argument': recipe['frontend']['begin_adjusters_in_registration_order'].pop()
                elif mutation == 'reference-missing': value['reference']['files'].pop()
                elif mutation == 'reference-file': value['reference']['files'][0]['path'] = 'src/main.cpp'
                elif mutation == 'reference-hash': value['reference']['files'][0]['sha256'] = '0' * 64
                elif mutation == 'label-link': value['ground_truth']['path'] = 'other.json'
                elif mutation == 'linux-link': value['linux_recipe']['sha256'] = 'e' * 64
                elif mutation == 'quota': value['additional_quota_examples'] = 1
                elif mutation == 'quota-bool': value['additional_quota_examples'] = False
                elif mutation == 'qualification': value['qualification']['native_bytes_reopened'] = True
                elif mutation == 'applicability': value['source_label_applicability'] = 'REVIEWED'
                elif mutation == 'observed': value['observed'] = []
                with self.subTest(system=system, mutation=mutation), self.assertRaises(ValueError):
                    profiles.gcc_platform_recipe_metadata(value, cdb, row.native, row.candidate, row.labels)

    def test_native_probe_forgery_cannot_become_recipe_preflight(self):
        for system in profiles.GCC_PLATFORM_FILES:
            for mutation in ('positive-fail', 'negative-pass', 'abi-source', 'target', 'dependency-missing',
                             'sdk-root', 'include-root', 'platform', 'source-hash', 'qualified'):
                row = self.fixture(system)
                native = row.native
                if mutation == 'positive-fail': native['probes']['candidate']['command']['exit_code'] = 1
                elif mutation == 'negative-pass': native['probes']['bad-width']['command']['exit_code'] = 0
                elif mutation == 'abi-source': native['probes']['abi']['source_sha256'] = 'e' * 64
                elif mutation == 'target': native['probes']['candidate']['command']['argv'][8] = '--target=i686-linux-gnu'
                elif mutation == 'dependency-missing': native['probes']['candidate']['headers'].pop()
                elif mutation == 'sdk-root': native['native_identity']['platform']['metadata']['selected_roots' if system == 'Windows' else 'sdk_root'] = 'other'
                elif mutation == 'include-root': native['environment']['INCLUDE' if system == 'Windows' else 'SDKROOT'] += '-other'
                elif mutation == 'platform': native['native_identity']['platform']['system'] = 'Linux'
                elif mutation == 'source-hash': native['input']['sha256'] = 'e' * 64
                elif mutation == 'qualified': native['native_qualified'] = True
                with self.subTest(system=system, mutation=mutation), self.assertRaises((ValueError, TypeError)):
                    profiles.gcc_platform_recipe_metadata(row.value, row.cdb, native, row.candidate, row.labels)

    def test_reader_reopens_both_bound_shapes_without_native_execution(self):
        staged = self.staged_fixture()
        with mock.patch.object(profiles, 'verify_ground_truth_index', return_value=staged.accepted), \
             mock.patch.object(profiles, 'verify_reviewed_files') as objects, \
             mock.patch.object(profiles.subprocess, 'run') as execute, \
             mock.patch.object(profiles.urllib.request, 'urlopen') as download:
            result = profiles.verify_gcc_platform_recipes(staged.repo)
        self.assertEqual(result['recipe_count'], 2)
        self.assertEqual(result['unique_source_count'], 1)
        self.assertEqual(result['source_selection_quota_examples'], 1)
        self.assertEqual(result['additional_quota_examples'], 0)
        self.assertFalse(result['platform_source_labels_reviewed'])
        self.assertEqual(objects.call_count, 4)
        for call in (objects.call_args_list[0], objects.call_args_list[2]):
            self.assertIn('expected_tree', call.kwargs)
            self.assertEqual(len(call.args[2]), 8)
        execute.assert_not_called()
        download.assert_not_called()

    def test_reader_rejects_missing_hash_alias_held_or_changed_inputs_privately(self):
        mutations = ('missing-recipe', 'missing-native', 'native-hash', 'native-symlink', 'native-in-repo',
                     'cdb-hash', 'candidate-hash', 'labels-hash', 'run-hash', 'run-failure', 'run-head', 'run-repository',
                     'run-id-bool', 'run-attempt-bool', 'run-workflow', 'producer-tree', 'reference-head',
                     'original-labels-unavailable', 'original-source-drift', 'final-native-change', 'final-record-change')
        for mutation in mutations:
            staged = self.staged_fixture()
            row = staged.rows['Windows']
            record_path = staged.repo / profiles.GCC_PLATFORM_FILES['Windows']
            native_path = Path(row.value['native_evidence']['case']['path'])
            if mutation == 'missing-recipe': record_path.unlink()
            elif mutation == 'missing-native': native_path.unlink()
            elif mutation == 'native-hash': native_path.write_bytes(b'PRIVATE_SENTINEL')
            elif mutation == 'native-in-repo':
                alias = staged.repo / 'native.json'
                row.value['native_evidence']['case'].update(path=str(alias), sha256=staged.write(alias, row.native))
            elif mutation == 'native-symlink':
                target = native_path.with_suffix('.saved')
                native_path.rename(target)
                try:
                    native_path.symlink_to(target)
                except OSError as error:
                    with self.subTest(mutation=mutation):
                        self.skipTest('temporary symlink unavailable: ' + str(error))
                    continue
            elif mutation in ('cdb-hash', 'candidate-hash', 'labels-hash'):
                key = {'cdb-hash': 'compilation_database', 'candidate-hash': 'candidate', 'labels-hash': 'ground_truth'}[mutation]
                (staged.repo / row.value[key]['path']).write_bytes(b'PRIVATE_SENTINEL')
            elif mutation == 'run-hash': Path(row.value['native_evidence']['run']['path']).write_bytes(b'PRIVATE_SENTINEL')
            elif mutation.startswith('run-'):
                key, replacement = {'run-failure': ('conclusion', 'failure'), 'run-head': ('head_sha', 'e' * 40),
                                    'run-repository': ('repository', {'full_name': 'other/repo'}),
                                    'run-id-bool': ('id', True), 'run-attempt-bool': ('run_attempt', True),
                                    'run-workflow': ('path', '.github/workflows/ci.yml')}[mutation]
                row.run[key] = replacement
                row.value['native_evidence']['run']['sha256'] = staged.write(Path(row.value['native_evidence']['run']['path']), row.run)
            elif mutation == 'original-source-drift': staged.accepted['source_sha256'] = 'e' * 64
            if mutation != 'missing-recipe': staged.write(record_path, row.value)
            def check_objects(repo, head, links, **kwargs):
                if (mutation == 'producer-tree' and kwargs) or (mutation == 'reference-head' and not kwargs):
                    raise ValueError('PRIVATE_SENTINEL')
                if mutation == 'final-native-change': native_path.write_bytes(b'PRIVATE_SENTINEL')
                if mutation == 'final-record-change': record_path.write_bytes(b'PRIVATE_SENTINEL')
            with mock.patch.object(profiles, 'verify_ground_truth_index', return_value=staged.accepted,
                                   side_effect=ValueError('PRIVATE_SENTINEL') if mutation == 'original-labels-unavailable' else None), \
                 mock.patch.object(profiles, 'verify_reviewed_files', side_effect=check_objects), \
                 self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^GCC prospective platform recipes rejected$'):
                profiles.verify_gcc_platform_recipes(staged.repo)

    def test_producer_tree_and_exact_workflow_git_blob_are_bound_without_external_grammar_relaxation(self):
        repo = Path(__file__).resolve().parents[1]
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=repo, text=True).strip()
        path = '.github/workflows/product-identity.yml'
        sha = hashlib.sha256(subprocess.check_output(['git', 'show', head + ':' + path], cwd=repo)).hexdigest()
        profiles.verify_reviewed_files(repo, head, [{'path': path, 'sha256': sha}], expected_tree=tree)
        for bad_tree in ('e' * 40, 'HEAD', True):
            with self.subTest(tree=bad_tree), self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, head, [{'path': path, 'sha256': sha}], expected_tree=bad_tree)
        for bad_path in ('.github/workflows/ci.yml', '.git/config', '../src/main.cpp'):
            with self.subTest(path=bad_path), self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, head, [{'path': bad_path, 'sha256': sha}])
        with self.assertRaises(ValueError):
            profiles.external_relative(path)

    def test_cli_is_private_and_rejects_external_root_override(self):
        with tempfile.TemporaryDirectory(prefix='codeskeptic-native-cli-') as temporary:
            root = Path(temporary).resolve()
            for suffix in ([], ['--binding', str(root / 'PRIVATE_SENTINEL')], ['--external-root', str(root)]):
                process = subprocess.run([sys.executable, '-B', profiles.__file__, 'platform-recipes-check',
                                          '--root', str(root), *suffix], capture_output=True, timeout=10)
                self.assertEqual(process.returncode, 2)
                self.assertEqual(process.stdout, b'')
                self.assertNotIn(b'PRIVATE_SENTINEL', process.stderr)


class AllRuleGroundTruthTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[1]
        self.value = profiles.read_json(self.repo / 'tests/product_corpus/candidates/gcc-mixed-storage-ground-truth.json')
        self.candidate = profiles.read_json(self.repo / profiles.GCC_SOURCE_CANDIDATE)

    def test_complete_source_labels_remain_unmeasured_and_add_no_quota(self):
        result = profiles.gcc_ground_truth_metadata(self.value, self.candidate)
        self.assertEqual(result['family_labels'], 16)
        self.assertEqual(result['project_diagnostics'], 3)
        self.assertEqual(result['expected_occurrences'], 1)
        self.assertEqual(result['additional_quota_examples'], 0)
        self.assertFalse(result['source_labels_independently_reviewed'])
        self.assertFalse(result['evaluation_frozen'])

    def test_source_labels_reject_omitted_family_or_changed_target(self):
        for mutation in ('missing-family', 'wrong-target'):
            value = copy.deepcopy(self.value)
            if mutation == 'missing-family':
                value['families'].pop()
            else:
                next(row for row in value['families'] if row['rule'] == 'memory-leak')['expected'][0]['cwes'] = [476]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.gcc_ground_truth_metadata(value, self.candidate)

    def test_label_metadata_rejects_forged_coverage_status_counts_and_occurrences(self):
        for mutation in ('family-duplicate', 'family-order', 'unknown-family', 'planned-installed', 'safe-buggy',
                         'unknown-role', 'safe-expected', 'target-line', 'target-column', 'target-multiplicity',
                         'bool-line', 'bool-column', 'bool-multiplicity', 'source-hash', 'source-lines', 'model-bool',
                         'model-width', 'model-limit', 'reference-missing', 'reference-path', 'reference-hash',
                         'project-missing', 'project-duplicate', 'project-cwe', 'project-observed', 'raw-observed',
                         'qualified', 'quota', 'quota-bool', 'empty-basis', 'bad-ref-line', 'duplicate-ref-line'):
            value = copy.deepcopy(self.value)
            target = next(row for row in value['families'] if row['rule'] == 'memory-leak')
            first = value['families'][0]
            if mutation == 'family-duplicate': value['families'][-1] = first
            elif mutation == 'family-order': value['families'].reverse()
            elif mutation == 'unknown-family': first['rule'] = 'PRIVATE_SENTINEL'
            elif mutation == 'planned-installed':
                next(row for row in value['families'] if row['rule'] == 'sql-injection')['availability'] = 'INSTALLED_AT_REFERENCE_HEAD'
            elif mutation == 'safe-buggy': first['role'] = 'buggy'
            elif mutation == 'unknown-role': target['role'] = 'unsupported'
            elif mutation == 'safe-expected': first['expected'] = target['expected']
            elif mutation == 'target-line': target['expected'][0]['line'] = 21
            elif mutation == 'target-column': target['expected'][0]['column'] = 2
            elif mutation == 'target-multiplicity': target['expected'][0]['multiplicity'] = 2
            elif mutation == 'bool-line': target['expected'][0]['line'] = True
            elif mutation == 'bool-column': target['expected'][0]['column'] = True
            elif mutation == 'bool-multiplicity': target['expected'][0]['multiplicity'] = True
            elif mutation == 'source-hash': value['source']['sha256'] = 'e' * 64
            elif mutation == 'source-lines': value['source']['line_count'] = 29
            elif mutation == 'model-bool': value['data_model']['char_bit'] = True
            elif mutation == 'model-width': value['data_model']['size_t_bits'] = 32
            elif mutation == 'model-limit': value['data_model']['allocation_bytes_max'] += 1
            elif mutation == 'reference-missing': value['references'].pop()
            elif mutation == 'reference-path': value['references'][0]['path'] = '../PRIVATE_SENTINEL'
            elif mutation == 'reference-hash': value['references'][0]['sha256'] = '0' * 64
            elif mutation == 'project-missing': value['project_diagnostics'].pop()
            elif mutation == 'project-duplicate': value['project_diagnostics'][1] = value['project_diagnostics'][0]
            elif mutation == 'project-cwe': value['project_diagnostics'][0]['expected'] = target['expected']
            elif mutation == 'project-observed': value['project_diagnostics'][0]['observed'] = []
            elif mutation == 'raw-observed': value['observed'] = []
            elif mutation == 'qualified': value['qualification']['evaluation_frozen'] = True
            elif mutation == 'quota': value['additional_quota_examples'] = 15
            elif mutation == 'quota-bool': value['additional_quota_examples'] = False
            elif mutation == 'empty-basis': first['rationale'] = ''
            elif mutation == 'bad-ref-line': first['source_lines'] = [True]
            elif mutation == 'duplicate-ref-line': first['source_lines'] = [20, 20]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.gcc_ground_truth_metadata(value, self.candidate)

    def review_fixture(self, value=None, record_sha='d' * 64):
        value = value or self.value
        return {'schema': 'codeskeptic-all-rule-source-review/v1', 'repository_head': 'd' * 40,
                'record': {'path': profiles.GCC_GROUND_TRUTH, 'sha256': record_sha},
                'candidate': value['candidate'], 'source_sha256': value['source']['sha256'],
                'implementer': '/root', 'verifier': '/root/synthetic_source_reviewer',
                'verdict': 'ACCEPT_SOURCE_LABELS', 'findings': [], 'rationale': 'Synthetic schema test, not source review.',
                'additional_quota_examples': 0, 'qualification': value['qualification']}

    def test_source_review_is_separate_exact_and_nonqualifying(self):
        review = self.review_fixture()
        profiles.ground_truth_review_metadata(review, self.value, 'd' * 64)
        for key, replacement in (('repository_head', 'HEAD'), ('verifier', '/root'), ('verdict', 'HOLD'),
                                 ('source_sha256', 'e' * 64), ('findings', ['unresolved']),
                                 ('additional_quota_examples', True), ('additional_quota_examples', 1),
                                 ('rationale', ''), ('record', {'path': profiles.GCC_GROUND_TRUTH, 'sha256': 'e' * 64}),
                                 ('candidate', {'path': profiles.GCC_SOURCE_CANDIDATE, 'sha256': 'e' * 64})):
            forged = copy.deepcopy(review)
            forged[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.ground_truth_review_metadata(forged, self.value, 'd' * 64)

    def staged_fixture(self, native_size_t_bytes=8):
        temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-all-rule-source-')
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        repo, inputs = base / 'repo', base / 'inputs'
        inputs.mkdir()
        source = b'/* Synthetic IO fixture, not an evaluation source. */\n' * 28
        (inputs / 'case.c').write_bytes(source)
        source_sha = hashlib.sha256(source).hexdigest()
        candidate, value = copy.deepcopy(self.candidate), copy.deepcopy(self.value)
        candidate['source'].update(sha256=source_sha, snapshot_root=str(inputs))
        def write(path, document):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(profiles.canonical(document), encoding='utf-8')
            return profiles.file_sha(path)
        recipe = {'native_evidence': {'char_bit': 8, 'int_bytes': 4,
                                      'size_t_bytes': native_size_t_bytes, 'pointer_bytes': 8}}
        candidate['links']['analysis_profile']['sha256'] = write(
            repo / candidate['links']['analysis_profile']['path'], recipe)
        candidate_sha = write(repo / profiles.GCC_SOURCE_CANDIDATE, candidate)
        value['candidate']['sha256'] = candidate_sha
        value['source']['sha256'] = source_sha
        record_sha = write(repo / profiles.GCC_GROUND_TRUTH, value)
        review = self.review_fixture(value, record_sha)
        review_path = base / 'review.json'
        review_sha = write(review_path, review)
        index = {'schema': 'codeskeptic-product-reviewed-ground-truth/v1',
                 'state': 'PARTIAL_REVIEWED_SOURCE_LABELS_NOT_FROZEN',
                 'entries': [{'record': {'path': profiles.GCC_GROUND_TRUTH, 'sha256': record_sha},
                              'review': {'path': str(review_path), 'sha256': review_sha}}],
                 'boundary': 'Synthetic metadata test, no source admission.'}
        write(repo / profiles.GROUND_TRUTH_INDEX, index)
        selection_sha = write(repo / profiles.SOURCE_SELECTION, {'admissions': [{'candidate': value['candidate']}]})
        manifest = profiles.read_json(self.repo / 'scripts/product_profiles.json')
        manifest['source_selection']['sha256'] = selection_sha
        # This isolated fixture has one source, irrespective of live cohort growth.
        manifest['independent_quota_examples'] = 1
        for project in manifest['projects']:
            project['local_snapshot'] = str(base / 'source-projects' / project['id'])
        write(repo / 'scripts/product_profiles.json', manifest)
        return SimpleNamespace(repo=repo, inputs=inputs, source_sha=source_sha, candidate_sha=candidate_sha,
                               value=value, record_sha=record_sha, index=index, review_path=review_path, write=write)

    def test_actual_reader_uses_bound_source_and_reference_objects_without_native_execution(self):
        staged = self.staged_fixture()
        with mock.patch.object(profiles, 'GCC_CASE_SHA', staged.source_sha), \
             mock.patch.object(profiles, 'verify_gcc_source_candidate', return_value={'candidate_sha256': staged.candidate_sha}), \
             mock.patch.object(profiles, 'verify_reviewed_files') as objects, \
             mock.patch.object(profiles.subprocess, 'run') as execute:
            result = profiles.verify_gcc_ground_truth(staged.repo)
        self.assertEqual(result['record_sha256'], staged.record_sha)
        self.assertTrue(result['source_bytes_verified'])
        self.assertFalse(result['source_labels_independently_reviewed'])
        objects.assert_called_once_with(staged.repo, self.value['reference_head'], self.value['references'])
        execute.assert_not_called()

    def test_staged_manifest_uses_synthetic_native_snapshot_roots(self):
        staged = self.staged_fixture()
        manifest = profiles.read_json(staged.repo / 'scripts/product_profiles.json')
        self.assertEqual(manifest['independent_quota_examples'], 1)
        for project in manifest['projects']:
            self.assertEqual(project['local_snapshot'], str(staged.repo.parent / 'source-projects' / project['id']))
            self.assertTrue(Path(project['local_snapshot']).is_absolute())
        profiles.source_metadata(manifest)
        # Exercise Windows path semantics on every host without running tools
        # or weakening the production host-absolute snapshot requirement.
        windows_manifest = copy.deepcopy(manifest)
        with mock.patch.object(profiles, 'Path', PureWindowsPath):
            for project in windows_manifest['projects']:
                project['local_snapshot'] = '/synthetic-posix-only/' + project['id']
            with self.assertRaisesRegex(ValueError, '^source archive/selection metadata$'):
                profiles.source_metadata(windows_manifest)
            for project in windows_manifest['projects']:
                project['local_snapshot'] = str(PureWindowsPath('C:/synthetic-sources') / project['id'])
            profiles.source_metadata(windows_manifest)

    def test_bound_native_recipe_cannot_disagree_with_label_arithmetic_model(self):
        for width in (4, True, 8.0):
            staged = self.staged_fixture(native_size_t_bytes=width)
            with mock.patch.object(profiles, 'GCC_CASE_SHA', staged.source_sha), \
                 mock.patch.object(profiles, 'verify_gcc_source_candidate', return_value={'candidate_sha256': staged.candidate_sha}), \
                 mock.patch.object(profiles, 'verify_reviewed_files'), \
                 self.subTest(width=width), self.assertRaisesRegex(ValueError, '^GCC all-rule source binding rejected$'):
                profiles.verify_gcc_ground_truth(staged.repo)

    def test_reader_rejects_changed_source_candidate_reference_or_final_identity(self):
        for mutation in ('source', 'source-symlink', 'candidate', 'reference', 'final-identity'):
            staged = self.staged_fixture()
            def check_refs(*args):
                if mutation == 'reference':
                    raise ValueError('PRIVATE_SENTINEL')
                if mutation == 'final-identity':
                    (staged.repo / profiles.GCC_GROUND_TRUTH).write_text('PRIVATE_SENTINEL')
            if mutation == 'source': (staged.inputs / 'case.c').write_text('PRIVATE_SENTINEL')
            elif mutation == 'source-symlink':
                target = staged.inputs / 'case.c'
                target.rename(staged.inputs / 'saved.c')
                try:
                    target.symlink_to(staged.inputs / 'saved.c')
                except OSError:
                    continue
            elif mutation == 'candidate': (staged.repo / profiles.GCC_SOURCE_CANDIDATE).write_text('PRIVATE_SENTINEL')
            with mock.patch.object(profiles, 'GCC_CASE_SHA', staged.source_sha), \
                 mock.patch.object(profiles, 'verify_gcc_source_candidate', return_value={'candidate_sha256': staged.candidate_sha}), \
                 mock.patch.object(profiles, 'verify_reviewed_files', side_effect=check_refs), \
                 self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^GCC all-rule source binding rejected$'):
                profiles.verify_gcc_ground_truth(staged.repo)

    def test_reviewed_reader_binds_procedural_review_without_extra_quota(self):
        staged = self.staged_fixture()
        with mock.patch.object(profiles, 'GCC_CASE_SHA', staged.source_sha), \
             mock.patch.object(profiles, 'verify_gcc_source_candidate', return_value={'candidate_sha256': staged.candidate_sha}), \
             mock.patch.object(profiles, 'verify_reviewed_files') as objects, \
             mock.patch.object(profiles, 'verify_source_selection', return_value={'quota_examples': 1}):
            result = profiles.verify_ground_truth_index(staged.repo)
        self.assertTrue(result['source_labels_independently_reviewed'])
        self.assertEqual(result['source_selection_quota_examples'], 1)
        self.assertEqual(result['additional_quota_examples'], 0)
        self.assertFalse(result['evaluation_frozen'])
        self.assertEqual(objects.call_args_list[0].args,
                         (staged.repo, 'd' * 40, [staged.index['entries'][0]['record'], staged.value['candidate']]))
        self.assertEqual(objects.call_count, 2)

    def test_reviewed_reader_rejects_missing_stale_changed_duplicate_or_unadmitted_links(self):
        for mutation in ('missing-review', 'changed-review', 'in-repo-review', 'duplicate-entry', 'held-review',
                         'stale-head', 'unadmitted', 'index-final-change'):
            staged = self.staged_fixture()
            def check_refs(repo, head, links):
                if mutation == 'stale-head': raise ValueError('PRIVATE_SENTINEL')
                if mutation == 'index-final-change':
                    (staged.repo / profiles.GROUND_TRUTH_INDEX).write_text('PRIVATE_SENTINEL')
            if mutation == 'missing-review': staged.review_path.unlink()
            elif mutation == 'changed-review': staged.review_path.write_text('PRIVATE_SENTINEL')
            elif mutation == 'in-repo-review':
                staged.index['entries'][0]['review']['path'] = str(staged.repo / 'review.json')
            elif mutation == 'duplicate-entry': staged.index['entries'] *= 2
            elif mutation == 'held-review':
                review = self.review_fixture(staged.value, staged.record_sha)
                review['verdict'] = 'HOLD'
                staged.index['entries'][0]['review']['sha256'] = staged.write(staged.review_path, review)
            staged.write(staged.repo / profiles.GROUND_TRUTH_INDEX, staged.index)
            with mock.patch.object(profiles, 'GCC_CASE_SHA', staged.source_sha), \
                 mock.patch.object(profiles, 'verify_gcc_source_candidate', return_value={'candidate_sha256': staged.candidate_sha}), \
                 mock.patch.object(profiles, 'verify_reviewed_files', side_effect=check_refs), \
                 mock.patch.object(profiles, 'verify_source_selection', return_value={'quota_examples': 0 if mutation == 'unadmitted' else 1}), \
                 self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^reviewed all-rule source labels rejected$'):
                profiles.verify_ground_truth_index(staged.repo)

    def test_cli_missing_or_duplicate_key_record_fails_privately(self):
        with tempfile.TemporaryDirectory(prefix='codeskeptic-all-rule-cli-') as temporary:
            repo = Path(temporary).resolve()
            record = repo / profiles.GCC_GROUND_TRUTH
            record.parent.mkdir(parents=True)
            for command in ('ground-truth-candidate-check', 'ground-truth-check'):
                for data in (None, '{"schema":"PRIVATE_SENTINEL","schema":null}'):
                    path = repo / (profiles.GCC_GROUND_TRUTH if command == 'ground-truth-candidate-check' else profiles.GROUND_TRUTH_INDEX)
                    if data is not None: path.write_text(data)
                    result = subprocess.run([sys.executable, '-B', str(self.repo / 'scripts/product_profiles.py'),
                                             command, '--root', str(repo)], capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b'')
                    self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)


class ProfileV2Tests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[1]
        self.manifest = profiles.read_json(self.repo / "scripts/product_profiles.json")
        self.manifest.update(schema="codeskeptic-product-profiles/v2", independent_quota_examples=1,
                             evaluation_state="PARTIAL_INDEPENDENT_SOURCE_SELECTION_NOT_FROZEN",
                             native_environment_state="PARTIAL_NATIVE_OBSERVATIONS_NOT_FINAL_PROFILE",
                             source_selection={"path": "tests/product_corpus/selection.json", "sha256": "e" * 64})
        self.result = {"quota_examples": 1, "source_admission_reviews_bound": 1,
                       "evaluation_frozen": False, "task_ready": False, "product_qualified": False}

    def test_v2_count_requires_actual_selection_reader_and_stays_partial(self):
        with mock.patch.object(profiles, "verify_source_selection", return_value=self.result) as checked:
            result = profiles.draft_readiness(self.manifest, self.repo)
        checked.assert_called_once_with(self.repo, self.manifest["source_selection"])
        self.assertEqual(result["independent_quota_examples"], 1)
        self.assertFalse(result["task_ready"])
        self.assertFalse(result["product_qualified"])

    def test_v2_missing_root_invalid_link_and_declared_count_disagreement_rejected(self):
        with self.assertRaises(ValueError):
            profiles.draft_readiness(self.manifest)
        with mock.patch.object(profiles, "verify_source_selection", return_value=self.result):
            for count in (True, 0, 1020):
                value = copy.deepcopy(self.manifest)
                value["independent_quota_examples"] = count
                with self.subTest(count=count), self.assertRaises(ValueError):
                    profiles.draft_readiness(value, self.repo)
        for key, replacement in (("path", "../selection.json"), ("sha256", "0" * 64)):
            value = copy.deepcopy(self.manifest)
            value["source_selection"][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.source_metadata(value)

    def test_v1_cannot_acquire_selection_fields_or_admitted_count(self):
        value = copy.deepcopy(self.manifest)
        value["schema"] = "codeskeptic-product-profiles/v1"
        with self.assertRaises(ValueError):
            profiles.source_metadata(value)
        del value["source_selection"]
        value.update(evaluation_state="SELECTION_AND_INDEPENDENT_LABEL_REVIEW_PENDING",
                     native_environment_state="PROSPECTIVE_REQUIREMENTS_ONLY_ACTUAL_IDENTITY_CAPTURE_PENDING")
        with self.assertRaises(ValueError):
            profiles.draft_readiness(value)
        value["independent_quota_examples"] = 0
        result = profiles.draft_readiness(value)
        self.assertEqual(result["independent_quota_examples"], 0)
        self.assertNotIn("source_selection", result)


class SourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[1]
        self.candidate = profiles.read_json(self.repo / profiles.GCC_SOURCE_CANDIDATE)
        self.candidate_sha = profiles.file_sha(self.repo / profiles.GCC_SOURCE_CANDIDATE)
        self.review = {"schema": "codeskeptic-source-admission-review/v1", "repository_head": "d" * 40,
                       "candidate_path": profiles.GCC_SOURCE_CANDIDATE, "candidate_sha256": self.candidate_sha,
                       "source_sha256": self.candidate["source"]["sha256"], "implementer": "/root",
                       "verifier": "/root/synthetic_reviewer", "verdict": "ADMIT_ONE_SOURCE", "admitted_source_count": 1,
                       "projection": {**profiles.gcc_candidate_metadata(self.candidate), "quota": True},
                       "reviewed_links": copy.deepcopy(self.candidate["links"]), "rationale": "Synthetic review schema test only.",
                       "remaining_gaps": ["No real review or admission is created by this fixture."],
                       "qualification": copy.deepcopy(self.candidate["qualification"])}

    def test_admitting_review_matches_exact_candidate_projection(self):
        result = profiles.admission_review_metadata(self.review, self.candidate, self.candidate_sha)
        self.assertEqual(result, self.review["projection"])
        self.assertTrue(result["quota"])

    def test_held_forged_or_inconsistent_review_cannot_admit(self):
        variants = []
        for key, replacement in (("verdict", "HOLD"), ("admitted_source_count", True), ("admitted_source_count", 2),
                                 ("verifier", "/root"), ("candidate_path", "../candidate.json"),
                                 ("candidate_sha256", "e" * 64), ("source_sha256", "e" * 64),
                                 ("repository_head", "HEAD"), ("rationale", ""), ("remaining_gaps", [])):
            value = copy.deepcopy(self.review)
            value[key] = replacement
            variants.append(value)
        for key, replacement in (("role", "safe"), ("origin", "second-origin"), ("cluster", "second-cluster"),
                                 ("sha256", "e" * 64), ("quota", False)):
            value = copy.deepcopy(self.review)
            value["projection"][key] = replacement
            variants.append(value)
        for key in self.review["qualification"]:
            value = copy.deepcopy(self.review)
            value["qualification"][key] = True
            variants.append(value)
        value = copy.deepcopy(self.review)
        value["reviewed_links"]["compiler_commands"]["sha256"] = "e" * 64
        variants.append(value)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                profiles.admission_review_metadata(value, self.candidate, self.candidate_sha)

    def selection_fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-admission-selection-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        repo, evidence = base / "repo", base / "review.json"
        path = repo / profiles.GCC_SOURCE_CANDIDATE
        path.parent.mkdir(parents=True)
        path.write_bytes((self.repo / profiles.GCC_SOURCE_CANDIDATE).read_bytes())
        evidence.write_text(profiles.canonical(self.review))
        index = {"schema": "codeskeptic-product-reviewed-source-selection/v1",
                 "state": "PARTIAL_REVIEWED_SOURCE_SELECTION_NOT_FROZEN",
                 "origins": {"gcc-analyzer-testsuite": "https://github.com/gcc-mirror/gcc"},
                 "admissions": [{"candidate": {"path": profiles.GCC_SOURCE_CANDIDATE, "sha256": self.candidate_sha},
                                 "review": {"path": str(evidence), "sha256": profiles.file_sha(evidence)}}],
                 "boundary": "Synthetic linkage test only."}
        path = repo / profiles.SOURCE_SELECTION
        path.write_text(profiles.canonical(index))
        return repo, evidence, index

    def selection_check(self, repo):
        link = {"path": profiles.SOURCE_SELECTION, "sha256": profiles.file_sha(repo / profiles.SOURCE_SELECTION)}
        observed = {"candidate_sha256": self.candidate_sha, "projection": profiles.gcc_candidate_metadata(self.candidate)}
        with mock.patch.object(profiles, "verify_reviewed_files"), \
                mock.patch.object(profiles, "verify_gcc_source_candidate", return_value=observed):
            return profiles.verify_source_selection(repo, link)

    def test_actual_review_link_read_before_producing_partial_count(self):
        repo, _, _ = self.selection_fixture()
        result = self.selection_check(repo)
        self.assertEqual(result["quota_examples"], 1)
        self.assertEqual(result["source_admission_reviews_bound"], 1)
        self.assertEqual(result["buckets"]["memory-leak"], {"buggy": 1, "safe": 0, "origins": ["gcc-analyzer-testsuite"]})
        self.assertTrue(result["deficits"])
        self.assertFalse(result["evaluation_frozen"])
        self.assertFalse(result["product_qualified"])

    def test_missing_digest_changed_held_or_duplicate_key_review_rejected(self):
        for mutation in ("missing", "changed", "held", "duplicate-key", "oversized"):
            repo, evidence, index = self.selection_fixture()
            if mutation == "missing":
                evidence.unlink()
            elif mutation == "changed":
                evidence.write_bytes(b"PRIVATE_EVIDENCE_SENTINEL")
            else:
                value = copy.deepcopy(self.review)
                value["verdict"] = "HOLD" if mutation == "held" else "ADMIT_ONE_SOURCE"
                raw = profiles.canonical(value)
                if mutation == "duplicate-key":
                    raw = raw.replace('"verdict":', '"verdict":"HOLD","verdict":')
                elif mutation == "oversized":
                    raw += " " * 65536
                evidence.write_text(raw)
                index["admissions"][0]["review"]["sha256"] = profiles.file_sha(evidence)
                (repo / profiles.SOURCE_SELECTION).write_text(profiles.canonical(index))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "^reviewed source selection rejected$"):
                self.selection_check(repo)

    def test_duplicate_source_or_failed_later_entry_never_returns_partial_count(self):
        for mutation in ("duplicate", "later-missing-review", "origin-alias"):
            repo, _, index = self.selection_fixture()
            if mutation == "origin-alias":
                index["origins"]["gcc-second-origin"] = "https://github.com/gcc-mirror/gcc"
            else:
                index["admissions"].append(copy.deepcopy(index["admissions"][0]))
                if mutation == "later-missing-review":
                    index["admissions"][1]["review"]["path"] += ".missing"
            (repo / profiles.SOURCE_SELECTION).write_text(profiles.canonical(index))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.selection_check(repo)

    def test_git_or_actual_source_failure_and_rehashed_candidate_cannot_admit(self):
        for mutation in ("git-failure", "source-failure", "source-mismatch", "candidate-changed"):
            repo, _, index = self.selection_fixture()
            link = {"path": profiles.SOURCE_SELECTION, "sha256": profiles.file_sha(repo / profiles.SOURCE_SELECTION)}
            if mutation == "candidate-changed":
                path = repo / profiles.GCC_SOURCE_CANDIDATE
                path.write_text(profiles.canonical(self.candidate) + "\n")
                index["admissions"][0]["candidate"]["sha256"] = profiles.file_sha(path)
                (repo / profiles.SOURCE_SELECTION).write_text(profiles.canonical(index))
                link["sha256"] = profiles.file_sha(repo / profiles.SOURCE_SELECTION)
            observed = {"candidate_sha256": "e" * 64 if mutation == "source-mismatch" else self.candidate_sha,
                        "projection": profiles.gcc_candidate_metadata(self.candidate)}
            with self.subTest(mutation=mutation), \
                    mock.patch.object(profiles, "verify_reviewed_files", side_effect=ValueError("PRIVATE_GIT_SENTINEL")
                                      if mutation == "git-failure" else None), \
                    mock.patch.object(profiles, "verify_gcc_source_candidate", return_value=observed,
                                      side_effect=ValueError("PRIVATE_SOURCE_SENTINEL") if mutation == "source-failure" else None), \
                    self.assertRaisesRegex(ValueError, "^reviewed source selection rejected$"):
                profiles.verify_source_selection(repo, link)

    def test_missing_changed_or_symlinked_selection_and_review_rejected(self):
        repo, evidence, index = self.selection_fixture()
        path = repo / profiles.SOURCE_SELECTION
        link = {"path": profiles.SOURCE_SELECTION, "sha256": profiles.file_sha(path)}
        path.unlink()
        with self.assertRaises(ValueError):
            profiles.verify_source_selection(repo, link)
        path.write_text(profiles.canonical(index) + "\n")
        with self.assertRaises(ValueError):
            profiles.verify_source_selection(repo, link)
        path.write_text(profiles.canonical(index))
        target = evidence.with_name("target.json")
        evidence.rename(target)
        try:
            evidence.symlink_to(target)
        except OSError:
            self.skipTest("host cannot create symlinks")
        with self.assertRaises(ValueError):
            self.selection_check(repo)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            profiles.verify_source_selection(repo, link)

    def test_git_anchor_allows_later_head_but_rejects_wrong_or_nonancestor_bytes(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-admission-git-") as directory:
            repo = Path(directory).resolve()
            hooks = repo / "disabled-hooks"
            hooks.mkdir()
            def git(*args):
                return subprocess.run(["git", "-C", str(repo), "-c", "user.name=Synthetic Test",
                                       "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                                       "-c", "core.hooksPath=" + str(hooks), *args], check=True,
                                      capture_output=True, text=True, timeout=10).stdout.strip()
            git("init", "--initial-branch=source-review-test", "--quiet")
            path = repo / "candidate.json"
            path.write_text("{\"synthetic\":true}\n")
            git("add", "--", path.name)
            git("commit", "--no-gpg-sign", "-qm", "synthetic source review")
            reviewed = git("rev-parse", "HEAD")
            links = [{"path": path.name, "sha256": profiles.file_sha(path)}]
            (repo / "integration.txt").write_text("metadata-only later integration\n")
            git("add", "--", "integration.txt")
            git("commit", "--no-gpg-sign", "-qm", "synthetic integration")
            self.assertNotEqual(reviewed, git("rev-parse", "HEAD"))
            with mock.patch.dict(os.environ, {"GIT_DIR": str(repo / "missing-git-dir")}):
                profiles.verify_reviewed_files(repo, reviewed, links)
            for head in ("f" * 40, "HEAD"):
                with self.subTest(head=head), self.assertRaises(ValueError):
                    profiles.verify_reviewed_files(repo, head, links)
            with self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, reviewed, [{**links[0], "sha256": "e" * 64}])
            path.write_text("{\"synthetic\":false}\n")
            git("add", "--", path.name)
            git("commit", "--no-gpg-sign", "-qm", "different candidate")
            with self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, git("rev-parse", "HEAD"), links)
            detached = git("commit-tree", git("rev-parse", reviewed + "^{tree}"), "-m", "unrelated root")
            with self.assertRaises(ValueError):
                profiles.verify_reviewed_files(repo, detached, links)


class SourceCandidateTests(unittest.TestCase):
    def test_candidate_link_drift_rejected_before_external_source_read(self):
        original_repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="codeskeptic-candidate-links-") as directory:
            repo = Path(directory).resolve()
            for relative in (profiles.GCC_SOURCE_CANDIDATE, *profiles.GCC_CANDIDATE_LINKS.values()):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((original_repo / relative).read_bytes())
            for key, relative in profiles.GCC_CANDIDATE_LINKS.items():
                path = repo / relative
                original = path.read_bytes()
                path.write_bytes(b"PRIVATE_INPUT_SENTINEL")
                with self.subTest(link=key), \
                        mock.patch.object(profiles, "verify_gcc_license_basis", side_effect=AssertionError("must reject first")), \
                        self.assertRaisesRegex(ValueError, "^source candidate binding rejected$"):
                    profiles.verify_gcc_source_candidate(repo)
                path.write_bytes(original)

    def test_candidate_missing_or_malformed_record_has_fixed_failure(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-candidate-failure-") as directory:
            repo = Path(directory).resolve()
            with self.assertRaisesRegex(ValueError, "^source candidate binding rejected$"):
                profiles.verify_gcc_source_candidate(repo)
            path = repo / profiles.GCC_SOURCE_CANDIDATE
            path.parent.mkdir(parents=True)
            for raw in (b'{"PRIVATE_SOURCE_SENTINEL":', b"[]", b"null"):
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "^source candidate binding rejected$"):
                    profiles.verify_gcc_source_candidate(repo)

    def test_candidate_projection_requires_fresh_admission(self):
        repo = Path(__file__).resolve().parents[1]
        value = profiles.read_json(repo / "tests/product_corpus/candidates/gcc-mixed-storage-source-candidate.json")
        result = profiles.gcc_candidate_metadata(value)
        self.assertEqual(result["family"], "memory-leak")
        self.assertEqual(result["origin"], "gcc-analyzer-testsuite")
        self.assertFalse(result["quota"])
        self.assertEqual(result["sha256"], value["source"]["sha256"])

    def test_changed_label_cluster_recipe_budget_or_qualification_rejected(self):
        repo = Path(__file__).resolve().parents[1]
        original = profiles.read_json(repo / "tests/product_corpus/candidates/gcc-mixed-storage-source-candidate.json")
        variants = []
        for key, replacement in (("role", "safe"), ("family", "bounds"), ("cluster", "second-cluster"),
                                 ("origin", "gcc-second-origin"), ("selection", "training")):
            value = copy.deepcopy(original)
            value[key] = replacement
            variants.append(value)
        for key in original["qualification"]:
            value = copy.deepcopy(original)
            value["qualification"][key] = True
            variants.append(value)
        for key, replacement in (("line", 27), ("column", True), ("multiplicity", 2)):
            value = copy.deepcopy(original)
            value["expected"][0][key] = replacement
            variants.append(value)
        for group, key, replacement in (("source", "sha256", "e" * 64),
                                         ("limits", "repetitions", 1), ("boundaries", "addressability", "")):
            value = copy.deepcopy(original)
            value[group][key] = replacement
            variants.append(value)
        value = copy.deepcopy(original)
        value["links"]["compiler_commands"]["path"] = "../compile_commands.json"
        variants.append(value)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                profiles.gcc_candidate_metadata(value)


class LicenseBasisTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-license-binding-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        repo, source, evidence = (base / name for name in ("repo", "source", "evidence"))
        for path in (repo, source, evidence):
            path.mkdir()
        checkout = Path(__file__).resolve().parents[1]
        value = profiles.read_json(checkout / profiles.GCC_LICENSE_BASIS)
        for row in value["references"]:
            raw = ("LICENSE_SENTINEL_" + row["role"]).encode()
            (evidence / row["path"]).write_bytes(raw)
            row.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        inputs = []
        for role, relative in (("candidate", "case.c"), ("origin", "origin.c"),
                               ("lineage", "lineage.c"), ("notice", "notices/COPYING3")):
            raw = (evidence / "COPYING3").read_bytes() if role == "notice" else ("SOURCE_SENTINEL_" + role).encode()
            path = source / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            inputs.append({"role": role, "path": relative, "size_bytes": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest()})
        candidate_sha = inputs[0]["sha256"]
        review = {"id": value["id"], "source": {"sha256": candidate_sha},
                  "origin": {"sha256": inputs[1]["sha256"]}}
        raw = profiles.canonical(review).encode()
        (repo / "review.json").write_bytes(raw)
        binding = {"schema": "codeskeptic-product-external-inputs/v1", "state": "SOURCE_BINDING_ONLY_NOT_FROZEN",
                   "id": value["id"], "adjudication": {"path": "review.json", "sha256": hashlib.sha256(raw).hexdigest()},
                   "inputs": sorted(inputs, key=lambda row: row["path"])}
        raw = profiles.canonical(binding).encode()
        path = repo / profiles.GCC_BINDING
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        value["source_binding"]["sha256"] = hashlib.sha256(raw).hexdigest()
        value["source_sha256"] = candidate_sha
        (repo / profiles.GCC_LICENSE_BASIS).write_text(profiles.canonical(value))
        return repo, source, evidence

    def test_actual_reference_and_source_bytes_read_without_execution_or_export(self):
        repo, source, evidence = self.fixture()
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no execution")), \
                mock.patch.object(profiles.urllib.request, "build_opener", side_effect=AssertionError("no network")):
            result = profiles.verify_gcc_license_basis(repo, evidence, source)
        self.assertTrue(result["reference_bytes_verified"])
        self.assertTrue(result["source_bytes_verified"])
        self.assertFalse(result["license_qualified"])
        self.assertNotIn("SENTINEL", profiles.canonical(result))

    def test_actual_reference_source_and_record_drift_rejected(self):
        for target in ("reference", "source", "binding", "notice"):
            repo, source, evidence = self.fixture()
            if target in ("reference", "source"):
                path = evidence / "root-README" if target == "reference" else source / "case.c"
                path.write_bytes(b"MUTATED_PRIVATE_SENTINEL")
            else:
                path = repo / profiles.GCC_LICENSE_BASIS
                value = profiles.read_json(path)
                if target == "binding":
                    value["source_binding"]["sha256"] = "f" * 64
                else:
                    value["references"][0]["sha256"] = "f" * 64
                path.write_text(profiles.canonical(value))
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "^GCC license reference binding rejected$"):
                profiles.verify_gcc_license_basis(repo, evidence, source)

    def test_private_guard_retains_legacy_source_and_reference_identities_without_export(self):
        for target in ('source', 'reference'):
            repo, source, evidence = self.fixture()
            guard = {}
            result = profiles.verify_gcc_license_basis(repo, evidence, source, _input_guard=guard)
            path = source / 'case.c' if target == 'source' else evidence / 'root-README'
            self.assertIn(path, guard)
            self.assertIn(source, guard)
            self.assertNotIn(str(source), profiles.canonical(result))
            profiles.verify_input_identities(guard)
            path.write_bytes(b'Changed previously verified legacy input\n')
            with self.subTest(target=target), self.assertRaises(ValueError):
                profiles.verify_input_identities(guard)

    def test_legacy_license_reader_rejects_retained_protocol_result(self):
        repo, source, evidence = self.fixture()
        observed = profiles.verify_external_inputs(repo / profiles.GCC_BINDING, repo, source)
        observed['schema'] = 'codeskeptic-product-retained-github-input-check/v1'
        with mock.patch.object(profiles, 'verify_external_inputs', return_value=observed):
            with self.assertRaisesRegex(ValueError, '^GCC license reference binding rejected$'):
                profiles.verify_gcc_license_basis(repo, evidence, source)

    def test_reference_symlink_and_checkout_overlap_rejected(self):
        repo, source, evidence = self.fixture()
        path = evidence / "root-README"
        destination = evidence / "notice-target"
        path.rename(destination)
        try:
            path.symlink_to(destination)
        except OSError:
            self.skipTest("host cannot create symlinks")
        with self.assertRaises(ValueError):
            profiles.verify_gcc_license_basis(repo, evidence, source)
        for invalid in (repo, repo / "inside", Path("relative")):
            with self.subTest(root=invalid), self.assertRaises(ValueError):
                profiles.verify_gcc_license_basis(repo, invalid, source)

    def test_reference_metadata_preserves_nonqualification(self):
        repo = Path(__file__).resolve().parents[1]
        value = profiles.read_json(repo / profiles.GCC_LICENSE_BASIS)
        result = profiles.gcc_license_metadata(value)
        self.assertEqual(result["upstream_project_spdx"], "GPL-3.0-or-later")
        self.assertFalse(result["license_qualified"])
        self.assertFalse(result["redistribution_approved"])
        self.assertEqual(result["independent_quota_examples"], 0)

    def test_forged_status_paths_roles_and_source_rejected(self):
        repo = Path(__file__).resolve().parents[1]
        original = profiles.read_json(repo / profiles.GCC_LICENSE_BASIS)
        variants = []
        for key in ("license_qualified", "redistribution_approved", "author_completeness_verified"):
            value = copy.deepcopy(original)
            value["assessment"][key] = True
            variants.append(value)
        for key, replacement in (("state", "FROZEN"), ("revision", "f" * 40),
                                 ("source_sha256", "0" * 64)):
            value = copy.deepcopy(original)
            value[key] = replacement
            variants.append(value)
        for key, replacement in (("path", "../COPYING3"), ("role", "root-notice"),
                                 ("url", "https://example.invalid/COPYING3"),
                                 ("size_bytes", True), ("sha256", "0" * 64)):
            value = copy.deepcopy(original)
            value["references"][0][key] = replacement
            variants.append(value)
        value = copy.deepcopy(original)
        value["independent_quota_examples"] = 1
        variants.append(value)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                profiles.gcc_license_metadata(value)


class QuotaTests(unittest.TestCase):
    def test_contract_has_sixteen_families_and_seventeen_disjoint_buckets(self):
        self.assertEqual(len(profiles.FAMILIES), 16)
        self.assertEqual(len(profiles.BUCKETS), 17)
        self.assertNotIn("bounds", profiles.BUCKETS)
        self.assertIn("bounds/cwe-121", profiles.BUCKETS)
        self.assertIn("bounds/cwe-122", profiles.BUCKETS)

    def test_synthetic_quota_accounting_not_provenance_qualification(self):
        result = profiles.quota_readiness(quota_rows(), {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(result["quota_examples"], 1020)
        self.assertEqual(result["deficits"], [])
        self.assertFalse(result["ground_truth_verified"])
        self.assertFalse(result["product_qualified"])

    def test_one_missing_role_blocks_its_exact_bucket(self):
        rows = quota_rows()
        removed = rows.pop(0)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(any(removed["family"] in item and "buggy" in item for item in result["deficits"]))

    def test_three_origins_required_per_bucket_not_only_global(self):
        rows = quota_rows()
        for row in rows[:60]:
            row["origin"] = "origin-0"
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(any("origins" in item for item in result["deficits"]))

    def test_three_origins_are_not_invented_from_ids(self):
        with self.assertRaises(ValueError):
            profiles.quota_readiness(quota_rows(), {"origin-0", "origin-1"})

    def test_duplicate_id_hash_and_semantic_cluster_rejected(self):
        for key in ("id", "sha256", "cluster"):
            rows = quota_rows()
            rows[1][key] = rows[0][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_cross_role_and_cross_family_cluster_reuse_rejected(self):
        for index in (30, 60):
            rows = quota_rows()
            rows[index]["cluster"] = rows[0]["cluster"]
            with self.subTest(index=index), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_supplemental_pair_cannot_rescue_missing_quota(self):
        rows = quota_rows()
        rows[0]["quota"] = False
        pair = copy.deepcopy(rows[0])
        pair.update(id="supplemental-fixed", role="safe", sha256="f"*64)
        rows.append(pair)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(result["quota_examples"], 1019)
        self.assertEqual(result["supplemental_examples"], 2)
        self.assertTrue(result["deficits"])

    def test_unknown_and_unsupported_never_supply_quota(self):
        for role in ("unknown", "unsupported"):
            rows = quota_rows()
            rows[0]["role"] = role
            with self.subTest(role=role), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
            rows[0]["quota"] = False
            self.assertTrue(profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})["deficits"])

    def test_training_cannot_be_renamed_evaluation(self):
        rows = quota_rows()
        rows[0]["selection"] = "known-fp-training"
        with self.assertRaises(ValueError):
            profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_bool_and_digest_types_are_strict(self):
        for key, value in (("quota", 1), ("sha256", "0"*64), ("sha256", "bad"),
                           ("cluster", ""), ("origin", None), ("family", "fake")):
            rows = quota_rows()
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_bounds_subtype_cannot_be_guessed_from_local_pointer_name(self):
        rows = quota_rows()
        stack = next(row for row in rows if row["subprofile"] == "cwe-121")
        stack["subprofile"] = None
        with self.assertRaises(ValueError):
            profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})

    def test_generic_bounds_can_remain_supplemental(self):
        rows = quota_rows()
        stack = next(row for row in rows if row["subprofile"] == "cwe-121")
        stack.update(subprofile=None, quota=False)
        result = profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertTrue(result["deficits"])

    def test_empty_selection_reports_deficits_never_success(self):
        result = profiles.quota_readiness([], set())
        self.assertEqual(result["quota_examples"], 0)
        self.assertTrue(result["deficits"])
        self.assertFalse(result["ground_truth_verified"])

    def test_inputs_not_mutated(self):
        rows = quota_rows()
        before = copy.deepcopy(rows)
        profiles.quota_readiness(rows, {"origin-0", "origin-1", "origin-2"})
        self.assertEqual(rows, before)


class LimitsTests(unittest.TestCase):
    def test_finite_prospective_budget_and_quality_floors(self):
        result = profiles.validate_limits(copy.deepcopy(profiles.LIMITS))
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["family_precision_min"], "0.90")
        self.assertEqual(result["addressable_recall_min"], "0.70")
        self.assertEqual(result["safe_fp_max"], 0)

    def test_any_silent_limit_or_threshold_edit_rejected(self):
        for key in profiles.LIMITS:
            values = copy.deepcopy(profiles.LIMITS)
            values[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.validate_limits(values)

    def test_bool_numeric_and_extra_keys_rejected(self):
        for change in ({"safe_fp_max": False}, {"repetitions": 3.0}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                profiles.validate_limits(dict(profiles.LIMITS, **change))


class HistoricalBurdenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "tests/product_corpus/historical/measurement-index.json"
        cls.index = json.loads(path.read_text(encoding="utf-8"))

    def test_original_occurrences_and_duplicate_fingerprint_preserved(self):
        result = profiles.historical_summary(self.index)
        self.assertEqual(result["counts"], {"FP": 47, "TP": 9, "unknown": 10})
        self.assertEqual(result["projects"]["cjson"]["findings"], 54)
        self.assertEqual(result["projects"]["cjson"]["distinct_fingerprints"], 53)
        self.assertFalse(result["fresh_measurement"])
        self.assertFalse(result["raw_evidence_verified"])

    def test_lost_or_duplicate_occurrence_rejected(self):
        for mutation in ("drop", "duplicate-index", "fingerprint-dedupe"):
            index = copy.deepcopy(self.index)
            rows = index["projects"]["cjson"]["occurrences"]
            if mutation == "drop":
                rows.pop()
            elif mutation == "duplicate-index":
                rows[1]["occurrence_index"] = rows[0]["occurrence_index"]
            else:
                seen = set()
                index["projects"]["cjson"]["occurrences"] = [
                    row for row in rows if row["diagnostic"]["fingerprint"] not in seen
                    and not seen.add(row["diagnostic"]["fingerprint"])]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.historical_summary(index)

    def test_relabeling_old_unknown_is_not_a_historical_update(self):
        index = copy.deepcopy(self.index)
        row = next(row for row in index["projects"]["cjson"]["occurrences"] if row["classification"] == "unknown")
        row["classification"] = "FP"
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)

    def test_training_origin_cannot_be_declared_holdout(self):
        index = copy.deepcopy(self.index)
        index["selection"] = "independent-evaluation"
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)

    def test_missing_source_rationale_or_revision_rejected(self):
        for field, value in (("rationale", ""), ("source_refs", []),
                             ("occurrence_index", True)):
            index = copy.deepcopy(self.index)
            index["projects"]["cjson"]["occurrences"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.historical_summary(index)
        index = copy.deepcopy(self.index)
        index["source_revision"] = "f" * 40
        with self.assertRaises(ValueError):
            profiles.historical_summary(index)


class SourceProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "scripts/product_profiles.json"
        cls.manifest = json.loads(path.read_text(encoding="utf-8"))
        # Preserve the legacy v1 contract as a synthetic compatibility fixture;
        # v2 evidence-dependent behavior is exercised separately above.
        cls.manifest.pop("source_selection", None)
        cls.manifest.update(schema="codeskeptic-product-profiles/v1", independent_quota_examples=0,
                            evaluation_state="SELECTION_AND_INDEPENDENT_LABEL_REVIEW_PENDING",
                            native_environment_state="PROSPECTIVE_REQUIREMENTS_ONLY_ACTUAL_IDENTITY_CAPTURE_PENDING")

    def test_three_exact_source_inventories_not_configured_coverage(self):
        result = profiles.source_metadata(self.manifest)
        self.assertEqual(result["source_files"], 734)
        self.assertEqual(result["projects"], ["cjson", "tinyxml2", "googletest"])
        self.assertFalse(result["configured_coverage_verified"])
        self.assertFalse(result["actual_source_bytes_verified"])

    def test_different_source_versions_or_hashes_rejected(self):
        for key, value in (("version", "1.7.19"), ("revision", "e"*40),
                           ("archive_sha256", "e"*64), ("tree_inventory_sha256", "e"*64)):
            manifest = copy.deepcopy(self.manifest)
            manifest["projects"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_missing_duplicate_or_reordered_source_inventory_rejected(self):
        for mutation in ("missing", "duplicate", "reorder"):
            manifest = copy.deepcopy(self.manifest)
            files = manifest["projects"][0]["files"]
            if mutation == "missing":
                files.pop()
            elif mutation == "duplicate":
                files.append(copy.deepcopy(files[0]))
            else:
                files.reverse()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_same_hash_declaration_cannot_hide_different_file_records(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["projects"][0]["files"][0]["sha256"] = "e" * 64
        with self.assertRaises(ValueError):
            profiles.source_metadata(manifest)

    def test_unsafe_path_or_boolean_size_rejected(self):
        for key, value in (("path", "../escape"), ("path", "/absolute"),
                           ("path", "a//b"), ("bytes", True)):
            manifest = copy.deepcopy(self.manifest)
            manifest["projects"][0]["files"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_preliminary_state_is_not_completed_freeze(self):
        readiness = profiles.draft_readiness(self.manifest)
        self.assertEqual(readiness["state"], "DRAFT_NOT_FROZEN")
        self.assertFalse(readiness["task_ready"])
        self.assertFalse(readiness["product_qualified"])
        self.assertIn("independent evaluation selection and source-label review missing", readiness["gaps"])

    def test_historical_manifest_link_has_one_safe_path_and_digest(self):
        for field, value in (("historical_index", "../measurement-index.json"),
                             ("historical_index", "/tmp/measurement-index.json"),
                             ("historical_index_sha256", ""),
                             ("historical_index_sha256", "0" * 64),
                             ("historical_index_sha256", True)):
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_historical_reader_checks_manifest_against_actual_bytes(self):
        root = Path(__file__).resolve().parents[1]
        index = profiles.linked_historical_index(self.manifest, root)
        self.assertEqual(profiles.historical_summary(index)["counts"],
                         {"FP": 47, "TP": 9, "unknown": 10})
        manifest = copy.deepcopy(self.manifest)
        manifest["historical_index_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "historical index digest mismatch"):
            profiles.linked_historical_index(manifest, root)

    def test_historical_reader_rejects_missing_changed_and_symlink_bytes(self):
        root = Path(__file__).resolve().parents[1]
        original = (root / self.manifest["historical_index"]).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         self.manifest["historical_index_sha256"])
        with tempfile.TemporaryDirectory(prefix="codeskeptic-profile-link-") as directory:
            staged = Path(directory)
            index = staged / self.manifest["historical_index"]
            index.parent.mkdir(parents=True)
            with self.assertRaises(ValueError):
                profiles.linked_historical_index(self.manifest, staged)
            # Same parsed data, different bytes: canonicalization must not hide drift.
            index.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "historical index digest mismatch"):
                profiles.linked_historical_index(self.manifest, staged)
            index.unlink()
            index.symlink_to(root / self.manifest["historical_index"])
            with self.assertRaises(ValueError):
                profiles.linked_historical_index(self.manifest, staged)

    def test_all_profile_cli_commands_reject_stale_link_before_other_work(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="codeskeptic-profile-cli-link-") as directory:
            staged = Path(directory)
            manifest_path = staged / "scripts/product_profiles.json"
            manifest_path.parent.mkdir(parents=True)
            manifest = copy.deepcopy(self.manifest)
            manifest["historical_index_sha256"] = "e" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            index_path = staged / manifest["historical_index"]
            index_path.parent.mkdir(parents=True)
            index_path.write_bytes((root / manifest["historical_index"]).read_bytes())
            for command in ("historical-check", "sources-check", "readiness"):
                with self.subTest(command=command):
                    result = subprocess.run(
                        [sys.executable, "-B", str(root / "scripts/product_profiles.py"),
                         command, "--root", str(staged)],
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("historical index digest mismatch", result.stderr)

    def test_claimed_quota_count_or_frozen_status_cannot_bypass_missing_data(self):
        for field, value in (("independent_quota_examples", 1020), ("state", "FROZEN")):
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.draft_readiness(manifest)


class NativeApiProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.model = json.loads((cls.root / "tests/product_corpus/native-api-models.json").read_text())

    def test_model_metadata_is_not_installed_or_native_qualification(self):
        result = profiles.native_api_metadata(self.model)
        self.assertEqual(result["sources"], 8)
        self.assertEqual(result["sinks"], 14)
        self.assertEqual(len(result["families"]), 4)
        self.assertFalse(result["product_qualified"])
        self.assertFalse(result["native_headers_verified"])
        self.assertFalse(result["installed"])

    def test_draft_cannot_claim_frozen_installed_or_measured(self):
        for mutation in ("state", *self.model["qualification"]):
            model = copy.deepcopy(self.model)
            if mutation == "state":
                model["state"] = "FROZEN"
            else:
                model["qualification"][mutation] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_exact_argument_indices_and_signature_roles_are_not_renameable(self):
        for field, value in (("argument_index", 1), ("argument_index", True),
                             ("family", "sql-injection"), ("symbol", "other_printf"),
                             ("header", "user.h"), ("platforms", ["windows-x64"])):
            model = copy.deepcopy(self.model)
            model["sinks"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["sinks"][0]["signature"]["parameters"] = ["int"]
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)

    def test_missing_duplicate_extra_or_reordered_api_rejected(self):
        for group in ("sources", "sinks"):
            for mutation in ("drop", "duplicate", "extra", "reorder"):
                model = copy.deepcopy(self.model)
                if mutation == "drop":
                    model[group].pop()
                elif mutation == "duplicate":
                    model[group].append(copy.deepcopy(model[group][0]))
                elif mutation == "extra":
                    row = copy.deepcopy(model[group][0])
                    row["id"] = "invented.api"
                    model[group].append(row)
                else:
                    model[group].reverse()
                with self.subTest(group=group, mutation=mutation), self.assertRaises(ValueError):
                    profiles.native_api_metadata(model)

    def test_output_buffer_return_and_native_socket_signatures_stay_distinct(self):
        for index, field, value in ((0, "kind", "output-buffer"),
                                     (1, "output_argument", 0),
                                     (4, "output_argument", 0),
                                     (7, "platforms", ["linux-x86_64"])):
            model = copy.deepcopy(self.model)
            model["sources"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_name_only_fake_header_and_user_body_trust_rejected(self):
        for field in ("name_only_allowed", "system_header_marker_alone_allowed",
                      "user_body_may_inherit_native_model", "invented_forward_declaration_allowed"):
            model = copy.deepcopy(self.model)
            model["declaration_identity"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_unknown_flow_and_mutation_cannot_be_declared_safe(self):
        for field in ("unknown_is_safe", "unknown_mutation_preserves_validation",
                      "existing_integer_or_nullness_domain_is_string_origin"):
            model = copy.deepcopy(self.model)
            model["flow"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_finite_flow_budgets_cannot_drift_or_accept_booleans(self):
        for field in self.model["flow"]["limits"]:
            for value in (0, True, self.model["flow"]["limits"][field] + 1):
                model = copy.deepcopy(self.model)
                model["flow"]["limits"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    profiles.native_api_metadata(model)

    def test_missing_helpers_trace_or_negative_boundary_rejected(self):
        for field in ("excluded_helpers", "trace_required", "required_behaviors"):
            model = copy.deepcopy(self.model)
            model["flow"][field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["required_negative_classes"].pop()
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)

    def test_category_platform_and_checked_value_trust_cannot_be_global(self):
        for field, value in (("generic_sanitizer_allowed", True),
                             ("mutation_invalidates", False),
                             ("ignored_or_failed_result_validates", True),
                             ("one_branch_validates_join", True)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["shared"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_sql_argument_parameter_and_bind_value_indices_are_different(self):
        for field, value in (("prepare_sanitizes_constructed_query", True),
                             ("bind_sanitizes_original_source", True),
                             ("sql_argument_index", 2), ("bind_value_argument_index", 1),
                             ("sql_parameter_index_base", 0)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["sql-injection"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_root_policy_and_containment_are_not_invented(self):
        for field, value in (("explicit_root_policy_required", False),
                             ("user_filename_alone_is_defect", True),
                             ("canonicalization_alone_is_containment", True),
                             ("string_prefix_alone_is_containment", True),
                             ("symlink_or_toctou_guarantee", True)):
            model = copy.deepcopy(self.model)
            model["category_validation"]["path-traversal"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_format_data_role_and_shell_argv_boundaries_are_preserved(self):
        for group, field in (("format-string", "nonliteral_alone_is_defect"),
                             ("command-injection", "generic_quoting_allowed"),
                             ("command-injection", "separate_argv_is_automatic_shell_injection")):
            model = copy.deepcopy(self.model)
            model["category_validation"][group][field] = True
            with self.subTest(group=group, field=field), self.assertRaises(ValueError):
                profiles.native_api_metadata(model)

    def test_missing_references_or_source_success_boundary_rejected(self):
        model = copy.deepcopy(self.model)
        model["sinks"][0]["references"] = ["nonexistent-reference"]
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)
        model = copy.deepcopy(self.model)
        model["sources"][1]["failure"] = ""
        with self.assertRaises(ValueError):
            profiles.native_api_metadata(model)


    def test_native_model_link_reads_actual_bytes_not_a_declared_count(self):
        manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
        model = profiles.linked_native_api_model(manifest, self.root)
        self.assertEqual(model, self.model)
        manifest["native_api_model_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "native API model digest mismatch"):
            profiles.linked_native_api_model(manifest, self.root)

    def test_native_model_path_and_digest_must_be_valid(self):
        original = profiles.read_json(self.root / "scripts/product_profiles.json")
        for key, value in (("native_api_model", "../model.json"),
                           ("native_api_model", "/tmp/model.json"),
                           ("native_api_model_sha256", "0" * 64),
                           ("native_api_model_sha256", True)):
            manifest = copy.deepcopy(original)
            manifest[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                profiles.source_metadata(manifest)

    def test_all_manifest_cli_commands_reject_native_model_hash_drift(self):
        with tempfile.TemporaryDirectory(prefix="codeskeptic-api-cli-link-") as directory:
            staged = Path(directory)
            manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
            for relative in (manifest["historical_index"], manifest["native_api_model"]):
                path = staged / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((self.root / relative).read_bytes())
            manifest["native_api_model_sha256"] = "e" * 64
            path = staged / "scripts/product_profiles.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")
            for command in ("api-check", "historical-check", "sources-check", "readiness"):
                with self.subTest(command=command):
                    result = subprocess.run(
                        [sys.executable, "-B", str(self.root / "scripts/product_profiles.py"),
                         command, "--root", str(staged)],
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("native API model digest mismatch", result.stderr)

    def test_native_model_reader_rejects_missing_changed_and_symlink_input(self):
        manifest = profiles.read_json(self.root / "scripts/product_profiles.json")
        original = (self.root / manifest["native_api_model"]).read_bytes()
        with tempfile.TemporaryDirectory(prefix="codeskeptic-api-link-") as directory:
            staged = Path(directory)
            model = staged / manifest["native_api_model"]
            model.parent.mkdir(parents=True)
            with self.assertRaises(ValueError):
                profiles.linked_native_api_model(manifest, staged)
            model.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "native API model digest mismatch"):
                profiles.linked_native_api_model(manifest, staged)
            model.unlink()
            model.symlink_to(self.root / manifest["native_api_model"])
            with self.assertRaises(ValueError):
                profiles.linked_native_api_model(manifest, staged)


class ExternalInputTests(unittest.TestCase):
    """Synthetic file binding, never independent sample admission."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeskeptic-external-input-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo, self.source = self.base / "repo", self.base / "source"
        self.repo.mkdir()
        self.source.mkdir()
        self.rows = []
        for role, path in (("candidate", "case.c"), ("origin", "origin.c"),
                           ("lineage", "lineage/parent.c"), ("notice", "notices/COPYING")):
            data = ("SOURCE_SENTINEL_" + role + "\n").encode()
            target = self.source / path
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(data)
            self.rows.append({"role": role, "path": path, "size_bytes": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
        self.rows.sort(key=lambda row: row["path"])
        self.review = {"id": "synthetic-held-case",
                       "source": {"sha256": self.rows[0]["sha256"]},
                       "origin": {"sha256": next(r["sha256"] for r in self.rows if r["role"] == "origin")}}
        review_bytes = profiles.canonical(self.review).encode()
        (self.repo / "review.json").write_bytes(review_bytes)
        self.manifest = {"schema": "codeskeptic-product-external-inputs/v1",
                         "state": "SOURCE_BINDING_ONLY_NOT_FROZEN",
                         "id": self.review["id"],
                         "adjudication": {"path": "review.json", "sha256": hashlib.sha256(review_bytes).hexdigest()},
                         "inputs": self.rows}
        self.path = self.repo / "binding.json"
        self.save()

    def save(self):
        self.path.write_text(profiles.canonical(self.manifest), encoding="utf-8")

    def check(self):
        return profiles.verify_external_inputs(self.path, self.repo, self.source)

    def test_actual_bytes_bound_without_execution_or_admission(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("must not execute")):
            result = self.check()
        self.assertEqual(set(result), {"schema", "id", "binding_sha256", "adjudication_sha256",
                                     "source_bytes_verified", "verified_inputs", "verified_bytes",
                                     "independent_quota_examples", "task_ready", "product_qualified",
                                     "native_commands_bound", "license_qualified", "state"})
        self.assertTrue(result["source_bytes_verified"])
        self.assertEqual(result["verified_inputs"], 4)
        self.assertEqual(result["independent_quota_examples"], 0)
        for key in ("task_ready", "product_qualified", "native_commands_bound", "license_qualified"):
            self.assertIs(result[key], False)
        self.assertNotIn("SOURCE_SENTINEL", profiles.canonical(result))

    def test_missing_changed_and_extra_file_rejected(self):
        case = self.source / "case.c"
        original = case.read_bytes()
        for data in (None, b"x" * len(original), original + b"x"):
            if case.exists():
                case.unlink()
            if data is not None:
                case.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check()
        case.write_bytes(original)
        (self.source / "extra.c").write_bytes(b"x")
        with self.assertRaises(ValueError):
            self.check()

    def test_paths_roles_sizes_and_claims_reject_tampering(self):
        original = copy.deepcopy(self.manifest)
        for key, values in (("path", ("../escape", "/abs", "a/../case.c", "a//b", "a\\b", "a:stream", "CON.c", "case.c/child")),
                            ("role", ("header", "origin")), ("size_bytes", (True, -1, 16777217)),
                            ("sha256", ("0" * 64, "bad"))):
            for value in values:
                self.manifest = copy.deepcopy(original)
                self.manifest["inputs"][0][key] = value
                self.save()
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.check()
        for key, value in (("state", "FROZEN"), ("quota", True), ("id", "SOURCE_SENTINEL_BAD")):
            self.manifest = copy.deepcopy(original)
            self.manifest[key] = value
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()

    def test_duplicate_reordered_and_case_alias_inputs_rejected(self):
        original = copy.deepcopy(self.manifest)
        for operation in ("duplicate", "reorder", "case-alias"):
            self.manifest = copy.deepcopy(original)
            rows = self.manifest["inputs"]
            if operation == "duplicate":
                rows.append(copy.deepcopy(rows[0]))
            elif operation == "reorder":
                rows.reverse()
            else:
                row = copy.deepcopy(rows[0])
                row.update(path="CASE.c", role="lineage")
                rows.append(row)
                rows.sort(key=lambda item: item["path"])
            self.save()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.check()

    def test_changed_adjudication_or_candidate_origin_binding_rejected(self):
        for key in ("id", "source", "origin"):
            review = copy.deepcopy(self.review)
            review[key] = "different" if key == "id" else {"sha256": "e" * 64}
            data = profiles.canonical(review).encode()
            (self.repo / "review.json").write_bytes(data)
            self.manifest["adjudication"]["sha256"] = hashlib.sha256(data).hexdigest()
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()

    def test_stale_adjudication_digest_and_missing_cli_arguments_fail_closed(self):
        (self.repo / "review.json").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.check()
        script = Path(__file__).resolve().with_name("product_profiles.py")
        result = subprocess.run([sys.executable, "-B", str(script), "external-source-check"],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "PRODUCT_PROFILE_FAIL: external input binding rejected\n")

    def test_later_read_cannot_hide_change_to_earlier_input_or_manifest(self):
        original_read = profiles.external_read
        case = self.source / "case.c"
        original_case, original_manifest = case.read_bytes(), self.path.read_bytes()
        for operation in ("earlier-file", "manifest", "extra-file", "extra-directory"):
            case.write_bytes(original_case)
            self.path.write_bytes(original_manifest)
            changed = False
            def mutate(path, capture=False):
                nonlocal changed
                result = original_read(path, capture)
                if path == self.source / "origin.c":
                    if operation == "earlier-file":
                        case.write_bytes(b"x" * len(original_case))
                    elif operation == "manifest":
                        self.path.write_bytes(original_manifest + b"\n")
                    elif operation == "extra-file":
                        (self.source / "extra").write_bytes(b"x")
                    else:
                        (self.source / "extra").mkdir()
                    changed = True
                return result
            with self.subTest(operation=operation), mock.patch.object(profiles, "external_read", side_effect=mutate):
                with self.assertRaises(ValueError):
                    self.check()
            self.assertTrue(changed)
            extra = self.source / "extra"
            if extra.is_dir():
                extra.rmdir()
            elif extra.exists():
                extra.unlink()

    def test_duplicate_json_nonfinite_and_invalid_utf8_rejected(self):
        for payload in (b'{"state":1,"state":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff'):
            self.path.write_bytes(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.check()

    def test_root_containment_and_aliases_rejected(self):
        for source in (self.repo, self.base, self.repo / "absent", Path("source")):
            with self.subTest(source=source), self.assertRaises(ValueError):
                profiles.verify_external_inputs(self.path, self.repo, source)
        alias = self.base / "source-link"
        try:
            alias.symlink_to(self.source, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            profiles.verify_external_inputs(self.path, self.repo, alias)

    def test_leaf_intermediate_and_manifest_symlinks_rejected(self):
        leaf = self.source / "case.c"
        moved = self.base / "moved.c"
        leaf.rename(moved)
        try:
            leaf.symlink_to(moved)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            self.check()
        leaf.unlink()
        moved.rename(leaf)
        directory = self.source / "lineage"
        directory.rename(self.base / "moved-dir")
        directory.symlink_to(self.base / "moved-dir", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.check()
        directory.unlink()
        (self.base / "moved-dir").rename(directory)
        self.path.rename(self.repo / "moved.json")
        self.path.symlink_to(self.repo / "moved.json")
        with self.assertRaises(ValueError):
            self.check()

    def test_hardlinks_and_nonregular_files_rejected(self):
        leaf = self.source / "case.c"
        try:
            os.link(leaf, self.base / "hardlink")
        except OSError:
            self.skipTest("hardlinks unavailable")
        with self.assertRaises(ValueError):
            self.check()
        (self.base / "hardlink").unlink()
        leaf.unlink()
        leaf.mkdir()
        with self.assertRaises(ValueError):
            self.check()
        leaf.rmdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(leaf)
            with self.assertRaises(ValueError):
                self.check()

    def test_growth_rewrite_and_replacement_during_read_rejected(self):
        leaf = self.source / "case.c"
        original = leaf.read_bytes()
        self.mutation_outcomes = {}
        for operation in ("growth", "rewrite", "replace"):
            leaf.write_bytes(original)
            before = profiles.external_identity(leaf.lstat())
            read = os.read
            outcome = {"attempted": False, "completed": False, "os_denied": False}
            def mutate(fd, size):
                data = read(fd, size)
                if not outcome["attempted"] and data == original:
                    outcome["attempted"] = True
                    try:
                        if operation == "replace":
                            replacement = self.base / "replacement"
                            replacement.write_bytes(original)
                            replacement.replace(leaf)
                        else:
                            leaf.write_bytes(original + b"x" if operation == "growth" else b"x" * len(original))
                    except PermissionError:
                        outcome["os_denied"] = True
                        raise
                    outcome["completed"] = True
                return data
            with self.subTest(operation=operation), mock.patch.object(os, "read", side_effect=mutate):
                with self.assertRaises(ValueError) as caught:
                    self.check()
            self.assertTrue(outcome["attempted"])
            if outcome["os_denied"]:
                # Windows can prohibit replacing an open file. That is I/O
                # rejection evidence, never completed-mutation guard coverage.
                self.assertFalse(outcome["completed"])
                self.assertIsInstance(caught.exception.__context__, PermissionError)
                self.assertEqual(leaf.read_bytes(), original)
                self.assertEqual(profiles.external_identity(leaf.lstat()), before)
            else:
                self.assertTrue(outcome["completed"])
            self.mutation_outcomes[operation] = outcome

    def test_os_denied_replacement_is_not_counted_as_completed_mutation(self):
        with mock.patch.object(Path, "replace", side_effect=PermissionError("synthetic denied replacement")) as denied:
            self.test_growth_rewrite_and_replacement_during_read_rejected()
        denied.assert_called_once()
        self.assertEqual(self.mutation_outcomes["replace"],
                         {"attempted": True, "completed": False, "os_denied": True})

    def test_actual_replacement_between_lstat_and_open_is_rejected(self):
        leaf = self.source / "case.c"
        original, before, completed = leaf.read_bytes(), leaf.lstat(), False
        open_file = os.open
        def replace_then_open(path, flags, *args, **kwargs):
            nonlocal completed
            if path == leaf and not completed:
                replacement = self.base / "replacement-before-open"
                replacement.write_bytes(original)
                replacement.replace(leaf)
                completed = True
            return open_file(path, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=replace_then_open):
            with self.assertRaises(ValueError) as caught:
                self.check()
        self.assertTrue(completed)
        self.assertIsInstance(caught.exception.__context__, profiles.ExternalIdentityError)
        self.assertIn("inode", caught.exception.__context__.changed_fields)
        self.assertNotEqual(before.st_ino, leaf.lstat().st_ino)
        self.assertEqual(leaf.read_bytes(), original)

    def test_cli_success_and_failure_do_not_echo_source_or_parser_payload(self):
        script = Path(__file__).resolve().with_name("product_profiles.py")
        argv = [sys.executable, "-B", str(script), "external-source-check", "--root", str(self.repo),
                "--binding", str(self.path), "--external-root", str(self.source)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["source_bytes_verified"])
        self.path.write_text('{"x":SOURCE_SENTINEL_PRIVATE_PAYLOAD}', encoding="utf-8")
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "PRODUCT_PROFILE_FAIL: external input binding rejected\n")
        self.assertNotIn("SOURCE_SENTINEL", result.stdout + result.stderr)


class RetainedExternalInputTests(ExternalInputTests):
    """New byte-binding protocol; synthetic evidence is never source admission."""
    def setUp(self):
        super().setUp()
        self.manifest['schema'] = 'codeskeptic-product-retained-github-inputs/v1'
        self.manifest['genetic_history'] = 'UNKNOWN_NOT_ASSERTED'
        comparison = next(row for row in self.rows if row['role'] == 'lineage')
        comparison['role'] = 'semantic-comparison'
        original = (self.source / 'origin.c').read_bytes()
        self.review['source']['adaptation'] = 'Synthetic retained extraction description.'
        self.review['origin'].update(
            repository='https://github.com/example/project', revision='a' * 40,
            path='tests/c++/original.c', lines=[[1, 1]],
            git_blob=hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest(),
            source_specific_genetic_lineage_established=False, tag_signature_authenticated=False)
        self.review['independence'] = {'same_cluster_comparison': {'sha256': comparison['sha256']}}
        self.api = {'type': 'file', 'encoding': 'base64', 'path': self.review['origin']['path'],
                    'sha': self.review['origin']['git_blob'], 'size': len(original),
                    'url': 'https://api.github.com/repos/example/project/contents/tests/c%2B%2B/original.c?ref=' + 'a' * 40,
                    'content': base64.b64encode(original).decode()}
        self.extraction = {'schema': 'codeskeptic-reviewed-extraction-description/v1',
                           'source_sha256': self.review['source']['sha256'],
                           'origin_sha256': self.review['origin']['sha256'],
                           'lines': self.review['origin']['lines'],
                           'adaptation': self.review['source']['adaptation'],
                           'equivalence': 'INDEPENDENT_REVIEW_REQUIRED_NOT_EXECUTED'}
        for role, name, value in (('provenance', 'metadata.json', self.api),
                                  ('extraction', 'extraction.json', self.extraction)):
            self.rows.append({'role': role, 'path': name})
            self.save_evidence(role, value)
        self.rows.sort(key=lambda row: row['path'])
        self.save_review()

    def save_evidence(self, role, value):
        row = next(row for row in self.manifest['inputs'] if row['role'] == role)
        raw = profiles.canonical(value).encode()
        (self.source / row['path']).write_bytes(raw)
        row.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.save()

    def save_review(self):
        raw = profiles.canonical(self.review).encode()
        (self.repo / 'review.json').write_bytes(raw)
        self.manifest['adjudication']['sha256'] = hashlib.sha256(raw).hexdigest()
        self.save()

    def test_actual_bytes_bound_without_execution_or_admission(self):
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
            result = self.check()
        self.assertEqual(result['schema'], 'codeskeptic-product-retained-github-input-check/v1')
        self.assertEqual(result['verified_inputs'], 6)
        self.assertTrue(result['source_bytes_verified'])
        self.assertEqual(result['independent_quota_examples'], 0)
        for key in ('task_ready', 'product_qualified', 'native_commands_bound', 'license_qualified',
                    'genetic_lineage_established', 'upstream_authenticated',
                    'extraction_equivalence_verified', 'semantic_independence_verified'):
            self.assertIs(result[key], False)
        self.assertNotIn('SOURCE_SENTINEL', profiles.canonical(result))

    def test_old_schema_still_requires_lineage_and_rejects_new_claims(self):
        self.manifest['schema'] = 'codeskeptic-product-external-inputs/v1'
        self.save()
        with self.assertRaises(ValueError):
            self.check()
        del self.manifest['genetic_history']
        self.save()
        with self.assertRaises(ValueError):
            self.check()

    def test_history_claim_and_evidence_roles_are_not_interchangeable(self):
        original = copy.deepcopy(self.manifest)
        for value in ('ESTABLISHED', None, True, 0):
            self.manifest = copy.deepcopy(original)
            self.manifest['genetic_history'] = value
            self.save()
            with self.subTest(history=value), self.assertRaises(ValueError):
                self.check()
        for role in ('provenance', 'extraction', 'semantic-comparison', 'notice'):
            for replacement in ('lineage', 'origin', 'candidate'):
                self.manifest = copy.deepcopy(original)
                next(row for row in self.manifest['inputs'] if row['role'] == role)['role'] = replacement
                self.save()
                with self.subTest(role=role, replacement=replacement), self.assertRaises(ValueError):
                    self.check()

    def test_unknown_schema_and_missing_or_duplicate_evidence_rejected(self):
        original = copy.deepcopy(self.manifest)
        for schema in ('codeskeptic-product-retained-github-inputs/v2', None, 1):
            self.manifest = copy.deepcopy(original)
            self.manifest['schema'] = schema
            self.save()
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.check()
        for role in ('provenance', 'extraction', 'semantic-comparison'):
            for operation in ('missing', 'duplicate'):
                self.manifest = copy.deepcopy(original)
                rows = self.manifest['inputs']
                row = next(row for row in rows if row['role'] == role)
                if operation == 'missing':
                    rows.remove(row)
                else:
                    rows.append(copy.deepcopy(row))
                    rows.sort(key=lambda row: row['path'])
                self.save()
                with self.subTest(role=role, operation=operation), self.assertRaises(ValueError):
                    self.check()

    def test_provenance_bytes_cannot_disagree_even_with_updated_inventory_hash(self):
        for key, value in (('type', 'dir'), ('encoding', 'utf-8'), ('path', 'other.c'),
                           ('sha', 'b' * 40), ('size', True), ('size', 1),
                           ('url', self.api['url'].replace('a' * 40, 'main')),
                           ('url', self.api['url'].replace('example/project', 'other/project')),
                           ('content', 'not-base64'), ('content', base64.b64encode(b'other').decode())):
            changed = {**self.api, key: value}
            self.save_evidence('provenance', changed)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check()

    def test_extraction_range_and_source_links_must_match_review(self):
        for key, value in (('source_sha256', 'c' * 64), ('origin_sha256', 'd' * 64),
                           ('lines', [[2, 2]]), ('lines', [[True, 1]]), ('lines', []),
                           ('adaptation', 'other'), ('equivalence', 'VERIFIED'), ('extra', True)):
            self.save_evidence('extraction', {**self.extraction, key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check()

    def test_reviewed_origin_and_comparison_identity_checked(self):
        original = copy.deepcopy(self.review)
        mutations = [('origin', 'revision', 'main'), ('origin', 'revision', 'b' * 40),
                     ('origin', 'repository', 'https://github.com/example/project.git'),
                     ('origin', 'git_blob', 'b' * 40), ('origin', 'path', '../escape.c'),
                     ('origin', 'lines', [[True, 1]]), ('origin', 'lines', [[1.0, 1]]),
                     ('origin', 'source_specific_genetic_lineage_established', True),
                     ('origin', 'tag_signature_authenticated', True),
                     ('independence', 'same_cluster_comparison', {'sha256': 'e' * 64})]
        for section, key, value in mutations:
            self.review = copy.deepcopy(original)
            self.review[section][key] = value
            self.save_review()
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.check()

    def test_self_consistent_but_impossible_ranges_are_rejected(self):
        for ranges in ([], [[0, 1]], [[1, 2]], [[True, 1]], [[1, 1], [1, 1]], [[2, 1]]):
            self.review['origin']['lines'] = ranges
            self.save_review()
            self.save_evidence('extraction', {**self.extraction, 'lines': ranges})
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                self.check()


class RetainedCandidateFixture:
    """Synthetic bytes and Git objects only; never native execution or admission.

    Compose the existing input fixture instead of inheriting and rerunning its
    tests. Every transitive file is temporary; no user's retained packet is read.
    """
    def __init__(self, owner, name='synthetic-retained-one', repo=None):
        inputs = RetainedExternalInputTests('test_actual_bytes_bound_without_execution_or_admission')
        owner.addCleanup(inputs.doCleanups)
        inputs.setUp()
        self.base, self.source = inputs.base, inputs.source
        self.repo = repo or inputs.repo
        inputs.repo = self.repo
        self.inputs = inputs
        self.prefix = 'tests/product_corpus/candidates/' + name
        self.path = self.prefix + '-candidate.json'
        original_repo = Path(__file__).resolve().parents[1]
        template = original_repo / 'tests/product_corpus/candidates'
        self.candidate = profiles.read_json(template / 'gcc-parent-child-source-candidate.json')
        self.recipe = profiles.read_json(template / 'gcc-parent-child-linux.json')
        self.rights = profiles.read_json(template / 'gcc-parent-child-rights-basis.json')
        self.review = profiles.read_json(template / 'gcc-parent-child-selection.json')
        self.candidate.update(id=name, origin='synthetic-origin',
                              origin_repository='https://github.com/example/project', cluster=name + '-cluster')
        source = self.source / 'case.c'
        source.write_bytes(('SOURCE_SENTINEL_' + name + '\n').encode())
        source_row = next(row for row in inputs.rows if row['role'] == 'candidate')
        source_row.update(self.content(source))
        inputs.review['source']['sha256'] = source_row['sha256']
        inputs.extraction['source_sha256'] = source_row['sha256']
        inputs.save_evidence('extraction', inputs.extraction)
        self.candidate['source'].update(sha256=source_row['sha256'], snapshot_root=str(self.source))
        self.review.update(id=name)
        self.review['source'].update(inputs.review['source'], local_evidence=str(source), line_count=1)
        self.review['origin'].update(inputs.review['origin'], id='synthetic-origin',
                                     local_evidence=str(self.source / 'origin.c'))
        self.review['independence'].update(cluster=name + '-cluster')
        self.review['independence']['same_cluster_comparison'].update(
            inputs.review['independence']['same_cluster_comparison'],
            local_evidence=str(self.source / 'lineage/parent.c'))
        self.review['review'].update(source_sha256=source_row['sha256'], reviewer='/root/synthetic_source_reviewer')
        for key in ('proof_evidence', 'initial_review', 'addressability_proposal', 'supplement'):
            path = self.base / (key + '.json')
            self.write(path, {'synthetic': key, 'boundary': 'No real review or source judgment.'})
            self.review['review'][key] = str(path)
            self.review['review'][key + '_sha256'] = profiles.file_sha(path)
        self.manifest = inputs.manifest
        self.manifest['id'] = name
        self.manifest['adjudication']['path'] = self.prefix + '-review.json'
        for key, suffix in (('source_binding', '-binding.json'), ('source_review', '-review.json'),
                            ('license_basis', '-rights.json'), ('analysis_profile', '-native.json'),
                            ('compiler_commands', '/compile_commands.json')):
            self.candidate['links'][key] = {'path': self.prefix + suffix, 'sha256': 'a' * 64}
        self.rights.update(id=name, source_sha256=source_row['sha256'], origin_revision='a' * 40)
        self.rights['references'] = []
        notice = self.source / 'notices/COPYING'
        for role in ('license-text', 'project-statement', 'root-notice'):
            path = self.base / (role + '.txt')
            path.write_bytes(notice.read_bytes() if role != 'project-statement' else b'Synthetic project statement\n')
            self.rights['references'].append({'role': role, 'path': str(path),
                                             'url': 'https://example.invalid/' + role, **self.content(path)})
        definitions = ('src/source_manager/SourceManager.cpp', 'src/main.cpp', 'src/core/RuleCapabilities.def')
        helpers = ('scripts/product_profiles.py', 'scripts/product_identity.py', 'scripts/product_quality.py')
        if not (self.repo / '.git').exists():
            for relative in (*definitions, *helpers):
                path = self.repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Synthetic reviewed producer ' + relative + '\n', encoding='utf-8')
            self.git('init', '--initial-branch=synthetic-retained-tests', '--quiet')
            self.git('add', '--', *definitions, *helpers)
            self.git('commit', '--no-gpg-sign', '-qm', 'synthetic producer definition')
        self.head = self.git('rev-parse', 'HEAD')
        self.recipe.update(id=name, source={key: self.candidate['source'][key] for key in ('path', 'sha256', 'language')})
        self.recipe['definition_reference'] = {'head': self.head,
            'files': [{'path': relative, 'sha256': profiles.file_sha(self.repo / relative)} for relative in definitions]}
        self.recipe['preflight']['head'] = self.head
        self.cdb = profiles.read_json(template / 'gcc-parent-child-linux/compile_commands.json')
        self.observation = self.base / 'observation'
        self.observation.mkdir()
        resource = self.recipe['environment']['resource_directory']
        compiler = '/usr/bin/clang-20'
        argv = self.cdb[0]['arguments']
        adjusted = [compiler, '-resource-dir', resource, '-fparse-all-comments', *argv[1:]]
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': '/tmp'}
        commands = []
        for label, option in (('resource-directory', '-print-resource-dir'), ('compiler-version', '--version')):
            commands.append({'name': label, 'argv': [compiler, '--no-default-config', option],
                             'cwd': '/input', 'environment': environment, 'exit_code': 0,
                             'expected_exit': 0, 'stderr_marker': None})
        for form, selected in (('cdb', argv), ('frontend-adjusted', adjusted)):
            for suffix in ('candidate-dependencies-before', 'abi-dependencies-before', 'candidate-syntax',
                           'abi-syntax', 'wrong-width', 'wrong-malloc', 'wrong-free',
                           'candidate-dependencies-after', 'abi-dependencies-after'):
                bad = suffix.startswith('wrong-')
                source_path = '/runner/' + suffix + '.c' if bad else (
                    '/runner/probe.c' if suffix.startswith('abi-') else '/input/case.c')
                selected_argv = ([arg for arg in selected[:-1] if arg != '-fsyntax-only']
                    + ['-M', '-MT', 'identity-probe', source_path] if 'dependencies' in suffix
                    else [*selected[:-1], source_path])
                commands.append({'name': form + '-' + suffix, 'argv': selected_argv, 'cwd': '/input',
                                 'environment': {**environment, 'CODESKEPTIC_RESOURCE_DIR': resource},
                                 'exit_code': int(bad), 'expected_exit': int(bad),
                                 'stderr_marker': 'parent-child-' + suffix + '-control' if bad else None})
        for command in commands:
            for suffix in ('.stdout', '.stderr'):
                payload = ((command['stderr_marker'] + '\n').encode()
                           if suffix == '.stderr' and command['stderr_marker'] else b'')
                (self.observation / (command['name'] + suffix)).write_bytes(payload)
        self.write(self.observation / 'compile_commands.json', self.cdb)
        self.native = {'schema': 'codeskeptic-retained-linux-native-preflight/v1',
                       'source_sha256': source_row['sha256'], 'commands': commands,
                       'compilation_database': self.cdb, 'compilation_database_sha256': profiles.file_sha(
                           self.observation / 'compile_commands.json'),
                       'frontend_adjusted_arguments': adjusted, 'resource_directory': resource,
                       'observed_kernel': 'synthetic-unexecuted-kernel',
                       'initial_identities': {'/usr/bin/clang-20': {
                           'path': compiler, 'resolved_path': '/usr/lib/llvm-20/bin/clang',
                           'sha256': 'a' * 64, 'bytes': 100}, '/etc/os-release': {
                           'path': '/etc/os-release', 'resolved_path': '/usr/lib/os-release',
                           'sha256': 'b' * 64, 'bytes': 100}},
                       'candidate_and_abi_syntax_verified': True, 'same_header_closure_verified': True,
                       'before_after_input_identity_verified': True, 'files': []}
        self.native.update({key: False for key in ('analyzer_run', 'candidate_executed', 'native_product_qualified',
                                                  'quota_credit', 'task_ready')})
        self.native['files'] = [{'file': path.name, **self.content(path)} for path in sorted(self.observation.iterdir())]
        producer_inputs = {}
        for relative in helpers:
            path = self.repo / relative
            producer_inputs[str(path)] = {'content': self.content(path)}
        for name in ('run.py', 'observe.py', 'probe.c', 'wrong-width.c', 'wrong-malloc.c', 'wrong-free.c'):
            path = self.base / name
            path.write_text('Synthetic producer ' + name + '\n', encoding='utf-8')
            producer_inputs[str(path)] = {'content': self.content(path)}
        self.wrapper = {'schema': 'codeskeptic-retained-linux-native-preflight-driver/v1',
                        'head': self.head, 'exit_code': 0, 'producer_inputs': producer_inputs,
                        'image': 'c' * 64, 'image_manifest_digest': 'sha256:' + 'd' * 64}
        self.native_review = {'schema': 'codeskeptic-native-preflight-review/v1',
            'task_id': 'CS3-CH08-S01-U003', 'head': self.head, 'source_sha256': source_row['sha256'],
            'verdict': 'PASS_WITH_STATED_BOUNDARIES', 'findings': [],
            'implementer': '/root', 'verifier': '/root/synthetic_native_reviewer',
            'compilation_database_sha256': self.native['compilation_database_sha256'],
            'qualification': {key: False for key in ('admission_ready allocator_noninterposition_verified analyzer_run '
                'calling_abi_verified candidate_executed compiler_runtime_closure_verified embedded_frontend_verified '
                'evaluation_frozen hosted_qualification_verified image_signature_authenticated implemented_emission_verified '
                'license_qualified native_product_qualified pop_authorized product_qualified publication_approved '
                'quota_credit redistribution_approved runtime_allocator_semantics_verified source_admitted task_ready '
                'upstream_authenticated').split()}}
        self.recipe['environment'].update(image_id=self.wrapper['image'],
            image_manifest_digest=self.wrapper['image_manifest_digest'],
            compiler=self.native['initial_identities'][compiler],
            os_release=self.native['initial_identities']['/etc/os-release'], observed_kernel=self.native['observed_kernel'])
        self.sync()

    @staticmethod
    def content(path):
        data = path.read_bytes()
        return {'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    @staticmethod
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(profiles.canonical(value), encoding='utf-8')
        return profiles.file_sha(path)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Synthetic Test',
            '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=' + str(self.base / 'disabled-hooks'), *args],
            capture_output=True, text=True, check=True, timeout=10).stdout.strip()

    def tracked(self, key, value):
        link = self.candidate['links'][key]
        link['sha256'] = self.write(self.repo / link['path'], value)
        return copy.deepcopy(link)

    def sync(self):
        """Rehash outer links while leaving intentionally mutated inner facts."""
        self.manifest['adjudication'] = self.tracked('source_review', self.review)
        binding_link = self.tracked('source_binding', self.manifest)
        self.rights['source_binding'] = binding_link
        self.tracked('license_basis', self.rights)
        self.recipe['source_binding'] = binding_link
        self.recipe['compiler_commands'] = self.tracked('compiler_commands', self.cdb)
        self.wrapper['source_binding'] = profiles.verify_external_inputs(
            self.repo / binding_link['path'], self.repo, self.source)
        observation_path = self.observation / 'summary.json'
        observation_sha = self.write(observation_path, self.native)
        self.wrapper['observation_sha256'] = observation_sha
        wrapper_path = self.base / 'wrapper.json'
        wrapper_sha = self.write(wrapper_path, self.wrapper)
        self.native_review.update(wrapper_summary_sha256=wrapper_sha, observation_summary_sha256=observation_sha)
        review_path = self.base / 'native-review.json'
        review_sha = self.write(review_path, self.native_review)
        self.recipe['preflight'].update(wrapper={'path': str(wrapper_path), 'sha256': wrapper_sha},
            observation={'path': str(observation_path), 'sha256': observation_sha},
            review={'path': str(review_path), 'sha256': review_sha})
        self.tracked('analysis_profile', self.recipe)
        self.write(self.repo / self.path, self.candidate)

    def check(self):
        return profiles.verify_source_candidate(self.repo, self.path)

    def admission(self, head):
        return {'schema': 'codeskeptic-source-admission-review/v2', 'repository_head': head,
                'candidate_path': self.path, 'candidate_sha256': profiles.file_sha(self.repo / self.path),
                'source_sha256': self.candidate['source']['sha256'], 'implementer': '/root',
                'verifier': '/root/synthetic_source_reviewer', 'verdict': 'ADMIT_ONE_SOURCE',
                'admitted_source_count': 1, 'projection': {**profiles.retained_candidate_metadata(self.candidate), 'quota': True},
                'reviewed_links': copy.deepcopy(self.candidate['links']), 'rationale': 'Synthetic protocol test only.',
                'remaining_gaps': ['No actual source admission, native execution, rights clearance or product qualification.'],
                'qualification': copy.deepcopy(self.candidate['qualification'])}


class RetainedGroundTruthFixture:
    """Synthetic labels over a real temporary candidate packet and Git history."""
    index_path = 'tests/product_corpus/retained_ground_truth.json'

    def __init__(self, owner):
        self.fixture = fixture = RetainedCandidateFixture(owner)
        self.repo, self.base = fixture.repo, fixture.base
        self.path = fixture.prefix + '-ground-truth.json'
        # The candidate fixture is one line, not the real 15-line GCC case.
        fixture.candidate['expected'][0]['line'] = 1
        fixture.review['prospective_mapping']['line'] = 1
        fixture.recipe['expected'][0]['line'] = 1
        fixture.sync()
        original_repo = Path(__file__).resolve().parents[1]
        self.value = profiles.read_json(original_repo / 'tests/product_corpus/candidates/gcc-parent-child-ground-truth.json')
        for relative in profiles.GROUND_TRUTH_REFERENCES:
            path = self.repo / relative
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Synthetic label reference ' + relative + '\n', encoding='utf-8')
        fixture.git('add', '--', *profiles.GROUND_TRUTH_REFERENCES)
        fixture.git('commit', '--no-gpg-sign', '-qm', 'synthetic label reference objects')
        self.value.update(id=fixture.candidate['id'],
            candidate={'path': fixture.path, 'sha256': profiles.file_sha(self.repo / fixture.path)},
            source={**{key: fixture.candidate['source'][key] for key in ('path', 'sha256', 'language')}, 'line_count': 1},
            reference_head=fixture.git('rev-parse', 'HEAD'),
            references=[{'path': path, 'sha256': profiles.file_sha(self.repo / path)}
                        for path in profiles.GROUND_TRUTH_REFERENCES],
            analysis_profile=copy.deepcopy(fixture.candidate['links']['analysis_profile']))
        self.value['assumptions'] = ['Synthetic labels only; source semantics and native execution are not asserted.']
        self.value['boundary'] = 'Synthetic protocol fixture, never an independent semantic judgment or source admission.'
        for row in self.value['families']:
            row['source_lines'] = [1]
            row['rationale'] = 'Synthetic per-family schema test only.'
            row['expected'] = copy.deepcopy(fixture.candidate['expected']) if row['rule'] == 'memory-leak' else []
        for row in self.value['project_diagnostics']:
            row['source_lines'] = [1]
            row['rationale'] = 'Synthetic report-only schema test only.'
        self.write_record()
        fixture.git('add', '--', 'tests/product_corpus/candidates')
        fixture.git('commit', '--no-gpg-sign', '-qm', 'synthetic label and candidate proposal')
        self.head = fixture.git('rev-parse', 'HEAD')
        source_review = fixture.admission(self.head)
        source_review_path = self.base / 'source-admission.json'
        self.selection = {'schema': 'codeskeptic-product-reviewed-source-selection/v1',
            'state': 'PARTIAL_REVIEWED_SOURCE_SELECTION_NOT_FROZEN',
            'origins': {'synthetic-origin': 'https://github.com/example/project'},
            'admissions': [{'candidate': copy.deepcopy(self.value['candidate']),
                'review': {'path': str(source_review_path), 'sha256': fixture.write(source_review_path, source_review)}}],
            'boundary': 'Synthetic procedural source-count fixture, not actual admission.'}
        selection_sha = fixture.write(self.repo / profiles.SOURCE_SELECTION, self.selection)
        self.manifest = profiles.read_json(original_repo / 'scripts/product_profiles.json')
        self.manifest.update(source_selection={'path': profiles.SOURCE_SELECTION, 'sha256': selection_sha},
                             independent_quota_examples=1)
        # The template retains real Linux snapshot paths. This synthetic
        # metadata fixture must use this host's paths, including on Windows;
        # these empty directories are not qualified project source snapshots.
        for project in self.manifest['projects']:
            snapshot = self.base / 'project-snapshots' / project['id']
            snapshot.mkdir(parents=True)
            project['local_snapshot'] = str(snapshot)
        fixture.write(self.repo / 'scripts/product_profiles.json', self.manifest)
        self.review_path = self.base / 'all-rule-review.json'
        self.review = {'schema': 'codeskeptic-retained-all-rule-source-review/v1', 'repository_head': self.head,
            'record': {'path': self.path, 'sha256': profiles.file_sha(self.repo / self.path)},
            'candidate': copy.deepcopy(self.value['candidate']), 'source_sha256': self.value['source']['sha256'],
            'implementer': '/root', 'verifier': '/root/synthetic_all_rule_reviewer',
            'verdict': 'ACCEPT_SOURCE_LABELS', 'findings': [], 'rationale': 'Synthetic review protocol, not source judgment.',
            'additional_quota_examples': 0, 'qualification': copy.deepcopy(self.value['qualification'])}
        self.index = {'schema': 'codeskeptic-product-reviewed-retained-ground-truth/v1',
            'state': 'PARTIAL_REVIEWED_SOURCE_LABELS_NOT_FROZEN',
            'entries': [{'record': copy.deepcopy(self.review['record']),
                         'review': {'path': str(self.review_path), 'sha256': 'a' * 64}}],
            'boundary': 'Synthetic separately reviewed label linkage only; no additional source quota.'}
        self.write_review()

    def write_record(self):
        return self.fixture.write(self.repo / self.path, self.value)

    def write_review(self):
        self.index['entries'][0]['review']['sha256'] = self.fixture.write(self.review_path, self.review)
        self.fixture.write(self.repo / self.index_path, self.index)

    def check(self):
        return profiles.verify_retained_ground_truth(self.repo, self.path)

    def index_check(self):
        return profiles.verify_retained_ground_truth_index(self.repo)


class RetainedGroundTruthTests(unittest.TestCase):
    def setUp(self):
        self.labels = RetainedGroundTruthFixture(self)

    def test_fixture_project_snapshots_are_host_local_and_foreign_paths_still_reject(self):
        labels = self.labels
        for project in labels.manifest['projects']:
            snapshot = Path(project['local_snapshot'])
            self.assertEqual(snapshot, labels.base / 'project-snapshots' / project['id'])
            self.assertTrue(snapshot.is_absolute() and snapshot.is_dir())
        self.assertEqual(labels.index_check()['reviewed_sources'], 1)
        # These paths are metadata only in this synthetic fixture. Preserve
        # the production rejection of another host's non-absolute spelling.
        foreign = '/foreign/project' if os.name == 'nt' else 'Z:\\foreign\\project'
        self.assertFalse(Path(foreign).is_absolute())
        original = copy.deepcopy(labels.manifest)
        for index, project in enumerate(original['projects']):
            changed = copy.deepcopy(original)
            changed['projects'][index]['local_snapshot'] = foreign
            labels.fixture.write(labels.repo / 'scripts/product_profiles.json', changed)
            with self.subTest(project=project['id']), self.assertRaises(ValueError):
                labels.index_check()
        labels.fixture.write(labels.repo / 'scripts/product_profiles.json', original)
        self.assertEqual(labels.index_check()['reviewed_sources'], 1)

    def test_actual_packet_labels_and_index_remain_source_only_with_no_extra_quota(self):
        labels = self.labels
        run = subprocess.run
        def git_only(argv, *args, **kwargs):
            self.assertEqual(argv[0], 'git', 'label readers must not run native tools')
            return run(argv, *args, **kwargs)
        with mock.patch.object(profiles.subprocess, 'run', side_effect=git_only), \
                mock.patch.object(profiles.urllib.request, 'urlopen', side_effect=AssertionError('no network')):
            metadata = profiles.retained_ground_truth_metadata(labels.value, labels.fixture.candidate)
            candidate = labels.check()
            reviewed = labels.index_check()
        for result in (metadata, candidate):
            self.assertEqual(result['family_labels'], 16)
            self.assertEqual(result['project_diagnostics'], 3)
            self.assertEqual(result['expected_occurrences'], 1)
            self.assertEqual(result['additional_quota_examples'], 0)
            self.assertFalse(result['source_labels_independently_reviewed'])
        self.assertTrue(candidate['source_bytes_verified'])
        self.assertEqual(candidate['record_sha256'], profiles.file_sha(labels.repo / labels.path))
        self.assertTrue(reviewed['source_labels_independently_reviewed'])
        self.assertEqual(reviewed['source_selection_quota_examples'], 1)
        self.assertEqual(reviewed['additional_quota_examples'], 0)
        for key in labels.value['qualification']:
            self.assertIs(reviewed[key], False)
        self.assertNotIn('SOURCE_SENTINEL', profiles.canonical(reviewed))

    def test_generic_nonselected_labels_allow_unknown_unsupported_and_another_buggy_family(self):
        labels = self.labels
        for role in ('unknown', 'unsupported', 'buggy'):
            value = copy.deepcopy(labels.value)
            row = next(row for row in value['families'] if row['rule'] == 'null-deref')
            row['role'] = role
            if role == 'buggy':
                row['expected'] = [{'rule': 'null-deref', 'function': 'synthetic', 'line': 1, 'column': 1,
                                    'cwes': [476], 'multiplicity': 1}]
            with self.subTest(role=role):
                result = profiles.retained_ground_truth_metadata(value, labels.fixture.candidate)
                self.assertEqual(result['expected_occurrences'], 2 if role == 'buggy' else 1)
                self.assertEqual(result['additional_quota_examples'], 0)

    def test_metadata_rejects_bad_coverage_typed_fields_selected_labels_and_quota(self):
        labels = self.labels
        variants = [('source', ('line_count',), True), ('source', ('sha256',), 'f' * 64),
                    ('candidate', ('path',), '../outside.json'), ('data_model', ('char_bit',), True),
                    ('qualification', ('evaluation_frozen',), 0), ('qualification', ('product_qualified',), True),
                    ('families', (0, 'source_lines'), [True]), ('families', (0, 'source_lines'), [2]),
                    ('families', (0, 'role'), 'observed-safe'), ('families', (0, 'rationale'), ''),
                    ('project_diagnostics', (0, 'expected'), [{'rule': 'assumption'}])]
        for section, keys, replacement in variants:
            value = copy.deepcopy(labels.value)
            target = value[section]
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = replacement
            with self.subTest(section=section, keys=keys), self.assertRaises(ValueError):
                profiles.retained_ground_truth_metadata(value, labels.fixture.candidate)
        for mutation in ('missing-family', 'duplicate-family', 'reordered-families', 'selected-role', 'selected-target',
                         'cross-family-expected', 'bool-quota', 'extra-quota', 'unexpected-field', 'missing-reference'):
            value = copy.deepcopy(labels.value)
            selected = next(row for row in value['families'] if row['rule'] == 'memory-leak')
            if mutation == 'missing-family': value['families'].pop()
            elif mutation == 'duplicate-family': value['families'][-1] = value['families'][0]
            elif mutation == 'reordered-families': value['families'].reverse()
            elif mutation == 'selected-role': selected['role'] = 'unknown'
            elif mutation == 'selected-target': selected['expected'][0]['column'] = 2
            elif mutation == 'cross-family-expected':
                value['families'][0].update(role='buggy', expected=copy.deepcopy(selected['expected']))
            elif mutation == 'bool-quota': value['additional_quota_examples'] = False
            elif mutation == 'extra-quota': value['additional_quota_examples'] = 1
            elif mutation == 'unexpected-field': value['observed'] = []
            elif mutation == 'missing-reference': value['references'].pop()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                profiles.retained_ground_truth_metadata(value, labels.fixture.candidate)

    def test_actual_reader_rejects_wrong_line_count_link_identity_and_reference_bytes(self):
        labels = self.labels
        original = copy.deepcopy(labels.value)
        variants = [('source', 'line_count', 2), ('candidate', 'sha256', 'f' * 64),
                    ('candidate', 'path', '../outside.json'), ('analysis_profile', 'sha256', 'f' * 64),
                    ('analysis_profile', 'path', profiles.GCC_CANDIDATE_LINKS['analysis_profile'])]
        for section, key, replacement in variants:
            labels.value = copy.deepcopy(original)
            labels.value[section][key] = replacement
            labels.write_record()
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                labels.check()
        labels.value = original
        labels.write_record()
        labels.value['references'][1]['sha256'] = 'f' * 64
        labels.write_record()
        with self.assertRaises(ValueError):
            labels.check()

    def test_historical_reference_blobs_survive_later_docs_but_cannot_be_rebound_silently(self):
        labels = self.labels
        path = labels.repo / 'docs/product-quality-contract.md'
        path.write_text('Later documentation after the source-label reference snapshot\n', encoding='utf-8')
        labels.fixture.git('add', '--', 'docs/product-quality-contract.md')
        labels.fixture.git('commit', '--no-gpg-sign', '-qm', 'later independent documentation')
        # The source-label decision refers to actual ancestor blobs, not to
        # bytes in whatever later implementation is now checked out.
        self.assertTrue(labels.check()['source_bytes_verified'])
        self.assertEqual(labels.index_check()['reviewed_sources'], 1)
        self.assertNotEqual(labels.value['references'][-1]['sha256'], profiles.file_sha(path))
        labels.value['references'][-1]['sha256'] = profiles.file_sha(path)
        labels.write_record()
        with self.assertRaises(ValueError):
            labels.check()  # New bytes do not belong to the declared old head.
        labels.value['reference_head'] = labels.fixture.git('rev-parse', 'HEAD')
        labels.write_record()
        self.assertTrue(labels.check()['source_bytes_verified'])
        with self.assertRaises(ValueError):
            labels.index_check()  # A new proposed record has no matching review.

    def test_index_rejects_missing_stale_self_review_and_cross_source_receipts(self):
        labels = self.labels
        original_review, original_index = copy.deepcopy(labels.review), copy.deepcopy(labels.index)
        for key, replacement in (('schema', 'codeskeptic-all-rule-source-review/v1'), ('verifier', '/root'),
                                 ('verdict', 'HOLD'), ('source_sha256', 'f' * 64), ('repository_head', 'f' * 40),
                                 ('findings', ['Unresolved synthetic finding']), ('additional_quota_examples', False),
                                 ('candidate', {'path': 'tests/product_corpus/candidates/other.json', 'sha256': 'f' * 64})):
            labels.review = {**copy.deepcopy(original_review), key: replacement}
            labels.write_review()
            with self.subTest(key=key), self.assertRaises(ValueError):
                labels.index_check()
        labels.review, labels.index = original_review, original_index
        labels.write_review()
        for mutation in ('missing-review', 'stale-review', 'duplicate-entry', 'stale-record', 'traversal', 'no-admission'):
            original_bytes = labels.review_path.read_bytes()
            index = copy.deepcopy(original_index)
            if mutation == 'missing-review': labels.review_path.unlink()
            elif mutation == 'stale-review': labels.review_path.write_bytes(b'PRIVATE_REVIEW_SENTINEL')
            elif mutation == 'duplicate-entry': index['entries'].append(copy.deepcopy(index['entries'][0]))
            elif mutation == 'stale-record': index['entries'][0]['record']['sha256'] = 'f' * 64
            elif mutation == 'traversal': index['entries'][0]['record']['path'] = '../outside.json'
            elif mutation == 'no-admission':
                (labels.repo / profiles.SOURCE_SELECTION).write_text('{}\n', encoding='utf-8')
            labels.fixture.write(labels.repo / labels.index_path, index)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                labels.index_check()
            labels.review_path.write_bytes(original_bytes)

    def test_label_reader_keeps_candidate_transitive_inputs_guarded_after_candidate_returns(self):
        labels = self.labels
        actual = profiles.verify_retained_source_candidate
        paths = [labels.fixture.source / 'case.c', labels.fixture.base / 'project-statement.txt',
                 labels.fixture.observation / 'cdb-wrong-width.stderr']
        for path in paths:
            original = path.read_bytes()
            mutated = []
            def mutate(*args, **kwargs):
                result = actual(*args, **kwargs)
                if not mutated:
                    path.write_bytes(original + b'\n')
                    mutated.append(True)
                return result
            with self.subTest(path=path.name), \
                    mock.patch.object(profiles, 'verify_retained_source_candidate', side_effect=mutate):
                with self.assertRaises(ValueError):
                    labels.check()
                self.assertTrue(mutated)
            path.write_bytes(original)

    def test_index_keeps_earlier_label_inputs_guarded_through_source_selection(self):
        labels = self.labels
        actual = profiles.verify_source_selection
        paths = [labels.fixture.source / 'case.c', labels.fixture.base / 'project-statement.txt',
                 labels.fixture.observation / 'cdb-wrong-width.stderr']
        for path in paths:
            original = path.read_bytes()
            mutated = []
            def mutate(*args, **kwargs):
                result = actual(*args, **kwargs)
                if not mutated:
                    path.write_bytes(original + b'\n')
                    mutated.append(True)
                return result
            with self.subTest(path=path.name), mock.patch.object(profiles, 'verify_source_selection', side_effect=mutate):
                with self.assertRaises(ValueError):
                    labels.index_check()
                self.assertTrue(mutated)
            path.write_bytes(original)

    def test_explicit_cli_dispatch_and_legacy_selector_remain_separate(self):
        labels = self.labels
        script = Path(__file__).resolve().with_name('product_profiles.py')
        base = [sys.executable, '-B', str(script)]
        commands = [['ground-truth-candidate-check', '--root', str(labels.repo), '--ground-truth', labels.path],
                    ['retained-ground-truth-check', '--root', str(labels.repo)]]
        for args in commands:
            result = subprocess.run(base + args, capture_output=True, text=True, timeout=30)
            with self.subTest(command=args[0]):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['additional_quota_examples'], 0)
        for args in (['limits', '--ground-truth', labels.path],
                     ['ground-truth-candidate-check', '--root', str(labels.repo), '--ground-truth', '../outside.json'],
                     ['retained-ground-truth-check', '--root', str(labels.repo), '--ground-truth', labels.path]):
            result = subprocess.run(base + args, capture_output=True, text=True, timeout=30)
            with self.subTest(args=args):
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('SOURCE_SENTINEL', result.stderr)
        # No new flag still dispatches to the unchanged legacy reader. This
        # dispatch-only mock does not replace any proof in the positives above.
        with mock.patch.object(profiles, 'verify_gcc_ground_truth', return_value={'legacy': True}) as legacy, \
                mock.patch.object(sys, 'argv', ['product_profiles.py', 'ground-truth-candidate-check', '--root', str(labels.repo)]), \
                mock.patch.object(sys, 'stdout', io.StringIO()):
            self.assertEqual(profiles.main(), 0)
        legacy.assert_called_once_with(labels.repo)


class RetainedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RetainedCandidateFixture(self)

    def test_actual_synthetic_packet_and_git_ancestors_are_read_without_native_execution(self):
        fixture = self.fixture
        execute = subprocess.run
        calls = []
        def git_only(argv, *args, **kwargs):
            self.assertEqual(argv[0], 'git', 'reader must not launch a compiler, analyzer or shell')
            calls.append(argv)
            return execute(argv, *args, **kwargs)
        with mock.patch.object(profiles.subprocess, 'run', side_effect=git_only), \
                mock.patch.object(profiles.urllib.request, 'urlopen', side_effect=AssertionError('no network')):
            result = fixture.check()
        self.assertTrue(calls)
        self.assertTrue(result['source_bytes_verified'])
        self.assertTrue(result['pre_result_recipe_bound'])
        self.assertTrue(result['fresh_independent_admission_required'])
        self.assertFalse(result['projection']['quota'])
        self.assertEqual(result['independent_quota_examples'], 0)
        self.assertFalse(result['task_ready'])
        self.assertFalse(result['product_qualified'])
        self.assertNotIn('SOURCE_SENTINEL', profiles.canonical(result))

    def test_metadata_rejects_wrong_types_scopes_labels_and_premature_qualification(self):
        original = self.fixture.candidate
        mutations = [('id', True), ('id', '../escape'), ('origin_repository', 'https://github.com/example/project.git'),
                     ('family', []), ('family', 'sql-injection'), ('family', 'bounds'), ('role', 'safe'),
                     ('analysis_selection', '../native'), ('selection', 'training')]
        for key, value in mutations:
            candidate = copy.deepcopy(original)
            candidate[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                profiles.retained_candidate_metadata(candidate)
        for section, key, value in [('expected', 'line', True), ('expected', 'cwes', [401, 401]),
                                    ('expected', 'multiplicity', 0), ('limits', 'repetitions', True),
                                    ('qualification', 'task_ready', 0), ('qualification', 'evaluation_frozen', True)]:
            candidate = copy.deepcopy(original)
            target = candidate['expected'][0] if section == 'expected' else candidate[section]
            target[key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                profiles.retained_candidate_metadata(candidate)
        for bad in ('../escape.json', '/tmp/escape.json', 'tests/product_corpus/candidates/CON.json'):
            candidate = copy.deepcopy(original)
            candidate['links']['source_review']['path'] = bad
            with self.subTest(path=bad), self.assertRaises(ValueError):
                profiles.retained_candidate_metadata(candidate)

    def test_full_reader_rejects_rehashed_inconsistent_review_rights_native_and_recipe(self):
        fixture = self.fixture
        variants = [('review', ('source_label', 'family'), 'bounds'),
                    ('review', ('independence', 'cluster'), 'other-cluster'),
                    ('review', ('prospective_mapping', 'line'), 16),
                    ('rights', ('source_sha256',), 'f' * 64),
                    ('rights', ('assessment', 'license_qualified'), True),
                    ('rights', ('references', 0, 'size_bytes'), True),
                    ('native', ('candidate_and_abi_syntax_verified',), 1),
                    ('native', ('quota_credit',), 0),
                    ('native', ('commands', 0, 'exit_code'), True),
                    ('native', ('commands', 4, 'argv'), ['/usr/bin/clang-20', '--version']),
                    ('wrapper', ('exit_code',), False),
                    ('native_review', ('verifier',), '/root'),
                    ('native_review', ('qualification', 'calling_abi_verified'), 0),
                    ('native_review', ('findings',), ['Unresolved synthetic finding']),
                    ('recipe', ('analyzer', 'executable_sha256'), 'f' * 64),
                    ('recipe', ('analyzer', 'selected_rule'), ['/product/bin/codeskeptic']),
                    ('recipe', ('environment', 'image_id'), 'f' * 64),
                    ('recipe', ('definition_reference', 'head'), 'f' * 40)]
        for name, keys, value in variants:
            record = getattr(fixture, name)
            target = record
            for key in keys[:-1]:
                target = target[key]
            original = copy.deepcopy(target[keys[-1]])
            target[keys[-1]] = value
            fixture.sync()
            with self.subTest(record=name, path=keys), self.assertRaises(ValueError):
                fixture.check()
            target[keys[-1]] = original
            fixture.sync()
        self.assertTrue(fixture.check()['source_bytes_verified'])

    def test_raw_stream_missing_drift_extra_file_and_wrong_negative_marker_fail_closed(self):
        fixture = self.fixture
        path = fixture.observation / 'cdb-wrong-width.stderr'
        original = path.read_bytes()
        for mutation in ('missing', 'drift', 'rehash-wrong-marker', 'extra'):
            rows = copy.deepcopy(fixture.native['files'])
            extra = fixture.observation / 'unexpected.txt'
            if mutation == 'missing':
                path.unlink()
            elif mutation == 'extra':
                extra.write_bytes(b'Unexpected extra output')
            else:
                path.write_bytes(b'Unrelated failure without required assertion marker\n')
                if mutation == 'rehash-wrong-marker':
                    next(row for row in fixture.native['files'] if row['file'] == path.name).update(fixture.content(path))
                    fixture.sync()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                fixture.check()
            path.write_bytes(original)
            if extra.exists():
                extra.unlink()
            fixture.native['files'] = rows
            fixture.sync()
        self.assertTrue(fixture.check()['source_bytes_verified'])

    def test_empty_compiler_stream_does_not_relax_empty_source_or_other_file_rejection(self):
        fixture = self.fixture
        stream = fixture.observation / 'compiler-version.stderr'
        self.assertEqual(stream.stat().st_size, 0)
        self.assertEqual(profiles.empty_native_stream(stream).st_size, 0)
        for path in (fixture.source / 'case.c', fixture.base / 'not-a-stream.json'):
            path.write_bytes(b'')
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                profiles.empty_native_stream(path)
        with self.assertRaises(ValueError):
            fixture.check()

    def test_ancestor_blobs_are_used_but_external_producer_and_definition_drift_reject(self):
        fixture = self.fixture
        path = fixture.repo / 'scripts/product_profiles.py'
        path.write_text('Later implementation may differ from preflight producer\n', encoding='utf-8')
        self.assertTrue(fixture.check()['source_bytes_verified'])
        producer = fixture.base / 'observe.py'
        producer.write_text('Altered retained producer\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            fixture.check()

    def test_git_timeout_is_redacted_by_actual_reader_and_cli(self):
        fixture = self.fixture
        error = subprocess.TimeoutExpired(['git', 'SOURCE_SENTINEL_PRIVATE_TIMEOUT'], 30)
        with mock.patch.object(profiles, 'verify_reviewed_files', side_effect=error):
            for reader in (profiles.verify_retained_source_candidate, profiles.verify_source_candidate):
                with self.subTest(reader=reader.__name__):
                    with self.assertRaisesRegex(ValueError, 'candidate.*rejected') as caught:
                        reader(fixture.repo, fixture.path)
                    self.assertNotIn('SOURCE_SENTINEL', str(caught.exception))
            argv = ['product_profiles.py', 'source-candidate-check', '--root', str(fixture.repo),
                    '--candidate', fixture.path]
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stdout', output), \
                    mock.patch.object(sys, 'stderr', errors):
                self.assertEqual(profiles.main(), 2)
            self.assertEqual(output.getvalue(), '')
            self.assertNotIn('SOURCE_SENTINEL', errors.getvalue())

    def test_source_change_after_initial_binding_is_rechecked_before_success(self):
        fixture = self.fixture
        original = profiles.verify_external_inputs
        calls = 0
        def mutate_after_binding(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 1:
                (fixture.source / 'case.c').write_bytes(b'Changed source after first binding\n')
            return result
        with mock.patch.object(profiles, 'verify_external_inputs', side_effect=mutate_after_binding):
            with self.assertRaises(ValueError):
                fixture.check()
        self.assertGreaterEqual(calls, 1)

    def test_environment_shape_kind_and_compiler_identity_are_not_free_form_claims(self):
        fixture = self.fixture
        original = copy.deepcopy(fixture.recipe['environment'])
        for key, value in (('kind', 'HOSTED_PRODUCT_QUALIFIED'), ('unexpected', True)):
            fixture.recipe['environment'][key] = value
            fixture.sync()
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.check()
            fixture.recipe['environment'] = copy.deepcopy(original)
        # Keep all superficial references internally consistent; the observed
        # /usr/bin/clang-20 identity must not describe a different selected tool.
        fixture.recipe['environment']['compiler']['path'] = '/usr/bin/other-compiler'
        fixture.native['initial_identities']['/usr/bin/clang-20']['path'] = '/usr/bin/other-compiler'
        fixture.sync()
        with self.assertRaises(ValueError):
            fixture.check()

    def test_v2_admission_and_legacy_v1_are_not_interchangeable(self):
        fixture = self.fixture
        review = fixture.admission(fixture.head)
        result = profiles.admission_review_metadata(review, fixture.candidate,
                                                    review['candidate_sha256'], fixture.path)
        self.assertTrue(result['quota'])
        for key, value in (('schema', 'codeskeptic-source-admission-review/v1'), ('admitted_source_count', True),
                           ('candidate_path', profiles.GCC_SOURCE_CANDIDATE), ('verifier', '/root'),
                           ('source_sha256', 'f' * 64), ('repository_head', 'HEAD')):
            changed = {**review, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                profiles.admission_review_metadata(changed, fixture.candidate, review['candidate_sha256'], fixture.path)
        legacy = SourceAdmissionTests('test_admitting_review_matches_exact_candidate_projection')
        legacy.setUp()
        legacy.review['schema'] = 'codeskeptic-source-admission-review/v2'
        with self.assertRaises(ValueError):
            profiles.admission_review_metadata(legacy.review, legacy.candidate, legacy.candidate_sha)

    def test_cli_explicit_generic_path_dispatch_and_redacted_failures(self):
        fixture = self.fixture
        script = Path(__file__).resolve().with_name('product_profiles.py')
        argv = [sys.executable, '-B', str(script), 'source-candidate-check', '--root', str(fixture.repo),
                '--candidate', fixture.path]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['independent_quota_examples'], 0)
        for candidate in ('../escape.json', '/tmp/not-selected.json', 'tests/product_corpus/candidates/missing.json'):
            result = subprocess.run([*argv[:-1], candidate], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('SOURCE_SENTINEL', result.stderr)
        result = subprocess.run([*argv[:3], 'limits', *argv[4:]], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        (fixture.repo / fixture.path).write_text('{"SOURCE_SENTINEL_PRIVATE":', encoding='utf-8')
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('SOURCE_SENTINEL', result.stderr)

    def test_two_real_reader_paths_count_distinct_synthetic_sources_once_per_origin(self):
        first = self.fixture
        second = RetainedCandidateFixture(self, 'synthetic-retained-two', repo=first.repo)
        first.git('add', '--', 'tests/product_corpus/candidates')
        first.git('commit', '--no-gpg-sign', '-qm', 'synthetic source proposal integration')
        head = first.git('rev-parse', 'HEAD')
        index = {'schema': 'codeskeptic-product-reviewed-source-selection/v1',
                 'state': 'PARTIAL_REVIEWED_SOURCE_SELECTION_NOT_FROZEN',
                 'origins': {'synthetic-origin': 'https://github.com/example/project'},
                 'admissions': [], 'boundary': 'Synthetic source-count test only; no real source admission.'}
        for fixture in (first, second):
            review = fixture.admission(head)
            path = fixture.base / 'admission.json'
            index['admissions'].append({'candidate': {'path': fixture.path, 'sha256': review['candidate_sha256']},
                                       'review': {'path': str(path), 'sha256': fixture.write(path, review)}})
        def check(value):
            path = first.repo / profiles.SOURCE_SELECTION
            return profiles.verify_source_selection(first.repo, {'path': profiles.SOURCE_SELECTION,
                                                                  'sha256': first.write(path, value)})
        result = check(index)
        self.assertEqual(result['quota_examples'], 2)
        self.assertEqual(result['source_admission_reviews_bound'], 2)
        self.assertEqual(result['buckets']['memory-leak'], {'buggy': 2, 'safe': 0, 'origins': ['synthetic-origin']})
        self.assertFalse(result['evaluation_frozen'])
        original_reader = profiles.verify_retained_source_candidate
        # A later candidate must not let an earlier candidate's source, rights,
        # stream or directory identity drift out of the aggregate transaction.
        for target in (first.source / 'case.c', first.base / 'project-statement.txt',
                       first.observation / 'cdb-wrong-width.stderr', first.source / 'unexpected.txt'):
            original_bytes = target.read_bytes() if target.exists() else None
            def mutate_earlier_input(repo, candidate_path, **kwargs):
                observed = original_reader(repo, candidate_path, **kwargs)
                if candidate_path == second.path:
                    target.write_bytes(b'Changed earlier transitive input during later reader\n')
                return observed
            with mock.patch.object(profiles, 'verify_retained_source_candidate', side_effect=mutate_earlier_input):
                with self.subTest(earlier_input=target.name), self.assertRaises(ValueError):
                    check(index)
            if original_bytes is None:
                target.unlink()
            else:
                target.write_bytes(original_bytes)
            self.assertEqual(check(index)['quota_examples'], 2)
        for mutation in ('duplicate', 'origin-alias', 'later-source-drift'):
            changed = copy.deepcopy(index)
            if mutation == 'duplicate':
                changed['admissions'].append(copy.deepcopy(changed['admissions'][0]))
            elif mutation == 'origin-alias':
                changed['origins']['another-origin'] = 'https://github.com/example/project'
            else:
                (second.source / 'case.c').write_bytes(b'Changed second source after synthetic review\n')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check(changed)


class GccStagingTests(unittest.TestCase):
    @staticmethod
    def stat_fixture(**changes):
        values = dict(st_dev=1, st_ino=2, st_mode=0o100600, st_nlink=1,
                      st_size=3, st_mtime_ns=5, st_ctime_ns=6, st_birthtime_ns=6)
        values.update(changes)
        return SimpleNamespace(**values)

    def read_stat_fixture(self, platform, before, opened, final=None, path_final=None):
        path = mock.Mock(spec=Path)
        path.is_absolute.return_value = True
        path.resolve.return_value = path
        path.lstat.side_effect = [before, path_final or before]
        with mock.patch.object(profiles.sys, 'platform', platform), \
                mock.patch.object(profiles.os, 'open', return_value=47), \
                mock.patch.object(profiles.os, 'fstat', side_effect=[opened, final or opened]), \
                mock.patch.object(profiles.os, 'read', side_effect=[b'abc', b'']), \
                mock.patch.object(profiles.os, 'close') as close:
            try:
                return profiles.external_read(path)
            finally:
                close.assert_called_once_with(47)

    def test_windows_creation_and_change_timestamps_are_distinct_queries(self):
        # CPython 3.12 Windows lstat exposes creation time as deprecated ctime;
        # fstat exposes ChangeTime. Both independently expose birthtime_ns.
        result = self.read_stat_fixture('win32', self.stat_fixture(),
                                       self.stat_fixture(st_ctime_ns=17))
        self.assertEqual(result[0], {'size_bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()})
        self.assertEqual(result[2], b'')

    def test_cross_query_normalization_keeps_all_other_identity_guards(self):
        for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_birthtime_ns'):
            opened = self.stat_fixture(st_ctime_ns=17, **{field: 99})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', self.stat_fixture(), opened)

    def test_raw_descriptor_and_path_ctime_drift_remain_rejected(self):
        for platform in ('win32', 'linux', 'darwin'):
            opened = self.stat_fixture(st_ctime_ns=17 if platform == 'win32' else 6)
            for query in ('descriptor', 'path'):
                changes = {'final': self.stat_fixture(st_ctime_ns=29)} if query == 'descriptor' else {
                    'path_final': self.stat_fixture(st_ctime_ns=29)}
                with self.subTest(platform=platform, query=query), self.assertRaises(ValueError):
                    self.read_stat_fixture(platform, self.stat_fixture(), opened, **changes)

    def test_final_descriptor_birthtime_drift_and_its_redacted_label(self):
        with self.assertRaises(profiles.ExternalIdentityError) as caught:
            self.read_stat_fixture('win32', self.stat_fixture(), self.stat_fixture(st_ctime_ns=17),
                                   final=self.stat_fixture(st_ctime_ns=17, st_birthtime_ns=876543210))
        message = profiles.gcc_stage_failure(caught.exception, 'verification')
        self.assertIn('identity=descriptor-final:birthtime_ns', message)
        self.assertNotIn('876543210', message)

    def test_birthtime_normalization_is_windows_only_and_requires_both_fields(self):
        for platform in ('linux', 'darwin'):
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                self.read_stat_fixture(platform, self.stat_fixture(), self.stat_fixture(st_ctime_ns=17))
        for field in ('before', 'opened', 'both'):
            before, opened = self.stat_fixture(), self.stat_fixture()
            if field in ('before', 'both'):
                del before.st_birthtime_ns
            if field in ('opened', 'both'):
                del opened.st_birthtime_ns
            if field == 'both':
                self.read_stat_fixture('win32', before, opened)
                opened.st_ctime_ns = 17
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', before, opened)
        for value in (None, True, '6'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.read_stat_fixture('win32', self.stat_fixture(), self.stat_fixture(st_birthtime_ns=value))

    def test_stat_rejection_diagnostics_contain_only_fixed_field_names(self):
        values = dict(st_dev=1, st_ino=2, st_mode=3, st_nlink=1, st_size=4, st_mtime_ns=5, st_ctime_ns=6)
        before = SimpleNamespace(**values)
        after = SimpleNamespace(**{**values, 'st_ino': 876543210})
        with self.assertRaises(profiles.ExternalIdentityError) as caught:
            profiles.check_external_identity(after, before, 'descriptor-open')
        message = profiles.gcc_stage_failure(caught.exception, 'verification')
        self.assertIn('identity=descriptor-open:inode', message)
        self.assertNotIn('876543210', message)
        forged = profiles.ExternalIdentityError('PRIVATE_SOURCE_SENTINEL', (1,), (2,))
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', profiles.gcc_stage_failure(forged, 'verification'))
        profiles.check_external_identity(before, before, 'descriptor-final')

    def test_staging_failure_location_never_contains_exception_payload(self):
        error = ValueError('PRIVATE_SOURCE_SENTINEL /private/location')
        message = profiles.gcc_stage_failure(error, 'destination')
        self.assertIn('destination', message)
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', message)
        self.assertNotIn('/private/location', message)
        message = profiles.gcc_stage_failure(error, 'PRIVATE_SOURCE_SENTINEL')
        self.assertNotIn('PRIVATE_SOURCE_SENTINEL', message)

    def test_adaptation_selects_only_frozen_lines_and_removes_instrumentation(self):
        lines = ["synthetic line " + str(i) for i in range(1, 67)]
        lines[7] = "static int __attribute__((noinline))"
        lines[64] = '  return synthetic; /* { dg-message "synthetic" } */'
        result = profiles.adapt_gcc_source(("\n".join(lines) + "\n").encode()).decode()
        self.assertEqual(len(result.splitlines()), 28)
        self.assertIn("static int\nsynthetic line 9", result)
        self.assertNotIn("noinline", result.split("*/", 1)[1])
        self.assertNotIn("synthetic line 59", result)
        self.assertNotIn("synthetic line 63", result)
        self.assertNotIn("synthetic line 33", result)
        self.assertTrue(result.endswith("  return synthetic;\nsynthetic line 66\n"))

    def test_adaptation_rejects_changed_structure_or_non_utf8(self):
        for payload in (b"short", b"\xff", b"unselected\n" * 66):
            with self.subTest(payload=payload[:10]), self.assertRaises(ValueError):
                profiles.adapt_gcc_source(payload)

    def test_download_is_bounded_hash_checked_and_never_follows_redirects(self):
        row = {"size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        def response(payload):
            stream = io.BytesIO(payload)
            stream.status = 200
            return stream
        with mock.patch.object(profiles.urllib.request, "build_opener") as builder:
            opener = builder.return_value
            opener.open.return_value = response(b"abc")
            self.assertEqual(profiles.fetch_gcc_input("notices/COPYING3", row), b"abc")
            handler = builder.call_args.args[0]
            self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid"))
            argv = opener.open.call_args
            self.assertEqual(argv.kwargs, {"timeout": 30})
            self.assertEqual(argv.args[0], "https://raw.githubusercontent.com/gcc-mirror/gcc/5115c7e447fc07457443df874bf57840e8316d5f/COPYING3")
            for payload in (b"ab", b"abcd", b"xyz"):
                opener.open.return_value = response(payload)
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    profiles.fetch_gcc_input("notices/COPYING3", row)
            with self.assertRaises(ValueError):
                profiles.fetch_gcc_input("unapproved-source", row)

    def test_stage_refuses_existing_or_checkout_destination_before_network(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="codeskeptic-gcc-stage-") as directory:
            existing = Path(directory).resolve()
            marker = existing / "preserve"
            marker.write_bytes(b"original")
            with mock.patch.object(profiles.urllib.request, "build_opener", side_effect=AssertionError("no download")):
                for destination in (existing, root / "uncreated-case-stage", Path("relative")):
                    with self.subTest(destination=destination), self.assertRaises(ValueError):
                        profiles.stage_gcc_inputs(root, destination)
            self.assertEqual(marker.read_bytes(), b"original")


class SourceCohortFixture:
    """Private synthetic source/API bytes, never real provenance or admission."""

    def __init__(self, owner):
        temporary = tempfile.TemporaryDirectory(prefix='codeskeptic-source-cohort-')
        owner.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        self.path = 'tests/product_corpus/cohorts/synthetic-shared-origin.json'
        self.cohort_path = self.repo / self.path
        self.cohort_path.parent.mkdir(parents=True)
        self.source_path = self.base / 'PRIVATE_SOURCE_SENTINEL.c'
        self.capture_path = self.base / 'PRIVATE_CAPTURE_SENTINEL.json'
        self.raw = ('/* PRIVATE_PAYLOAD_SENTINEL: café, synthetic only. */\n'
                    'void candidate(void) {\n'
                    '  void *p = malloc(1);\n'
                    '  p = 0;\n'
                    '}\n'
                    '\n'
                    '/* Same mechanism safe control; no independent quota. */\n'
                    'void safe_control(void) {\n'
                    '  void *p = malloc(1);\n'
                    '  free(p);\n'
                    '  p = 0;\n'
                    '}\n').encode('utf-8')
        self.source_path.write_bytes(self.raw)
        self.revision = 'a' * 40
        self.upstream_path = 'tests/source.c'
        self.endpoint = 'repos/example/synthetic/contents/' + self.upstream_path + '?ref=' + self.revision
        self.blob = hashlib.sha1(b'blob ' + str(len(self.raw)).encode() + b'\0' + self.raw).hexdigest()
        self.api = {'type': 'file', 'path': self.upstream_path, 'size': len(self.raw), 'sha': self.blob,
                    'url': 'https://api.github.com/' + self.endpoint, 'encoding': 'base64',
                    'content': base64.b64encode(self.raw).decode('ascii')}
        self.capture = {'command': ['gh', 'api', self.endpoint], 'cwd': str(self.repo), 'exit': 0,
                        'expected_exit': 0, 'head': 'b' * 40, 'working_diff_sha256': 'c' * 64,
                        'stdout': profiles.canonical(self.api), 'stderr': '', 'capture_script_sha256': 'd' * 64}
        self.capture_path.write_text(profiles.canonical(self.capture), encoding='utf-8')
        self.origin = {'id': 'synthetic-origin', 'repository': 'https://github.com/example/synthetic',
                       'revision': self.revision, 'path': self.upstream_path, 'git_blob': self.blob,
                       'source': self.link(self.source_path), 'api_capture': self.link(self.capture_path)}
        self.value = {'schema': 'codeskeptic-product-source-cohort/v1',
                      'state': 'PRE_RESULT_SOURCE_PREPARATION_NOT_ADMITTED', 'id': 'synthetic-shared-origin',
                      'origins': [self.origin],
                      'records': [self.record('synthetic-candidate', 'buggy', [[1, 5]]),
                                  self.record('synthetic-control', 'safe', [[7, 12]])],
                      'limits': copy.deepcopy(profiles.LIMITS),
                      'boundary': 'Synthetic preparation test only; no genuine upstream provenance or source admission.',
                      'qualification': {key: False for key in profiles.SOURCE_QUALIFICATION.split()}}
        self.save()

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def link(cls, path):
        data = path.read_bytes()
        return {'path': str(path), 'sha256': cls.digest(data), 'size_bytes': len(data)}

    @classmethod
    def address(cls, value):
        return {'sha256': cls.digest(profiles.canonical(value).encode('utf-8')), 'value': value}

    @classmethod
    def source(cls, text):
        data = text.encode('utf-8')
        return {'language': 'C17', 'text': text, 'sha256': cls.digest(data), 'size_bytes': len(data)}

    def record(self, name, role, ranges):
        lines = self.raw.splitlines(keepends=True)
        extracted = b''.join(b''.join(lines[start - 1:end]) for start, end in ranges)
        value = {'id': name, 'selection': ('independent-evaluation-candidate' if role == 'buggy'
                                         else 'supplemental-control'),
                 'family': 'memory-leak', 'subprofile': None, 'role': role, 'origin': 'synthetic-origin',
                 'cluster': 'synthetic-caller-slot', 'related_to': None if role == 'buggy' else 'synthetic-candidate',
                 'source': self.source('#include <stdlib.h>\n\n' + extracted.decode('utf-8')),
                 'extraction': {'ranges': ranges, 'raw_sha256': self.digest(extracted),
                                'adaptation': 'native-stdlib-prefix/v1'},
                 'assumptions': ['Synthetic labels still require independent semantic review.'],
                 'expected': ([{'rule': 'memory-leak', 'function': 'candidate', 'line': 6, 'column': 3,
                                'cwes': [401], 'multiplicity': 1}] if role == 'buggy' else []),
                 'boundary': 'Preparation only; no native execution, independent sample judgment or quota.'}
        return self.address(value)

    def save(self, refresh_records=True):
        if refresh_records:
            self.value['records'] = [self.address(row['value']) for row in self.value['records']]
        self.cohort_path.write_text(profiles.canonical(self.value), encoding='utf-8')

    def save_capture(self, refresh_api=True):
        if refresh_api:
            self.capture['stdout'] = profiles.canonical(self.api)
        self.capture_path.write_text(profiles.canonical(self.capture), encoding='utf-8')
        self.value['origins'][0]['api_capture'] = self.link(self.capture_path)
        self.save()

    def check(self):
        return profiles.verify_source_cohort(self.repo, self.path)


class SourceCohortTests(unittest.TestCase):
    """Bounded synthetic preparation checks cannot establish a real cohort."""

    def setUp(self):
        self.fixture = SourceCohortFixture(self)

    def assert_uncredited(self, result, verified, total=2, candidates=1, controls=1):
        self.assertIs(result['source_bytes_verified'], verified)
        self.assertEqual(result['total_sources'], total)
        self.assertEqual(result['preparation_candidates'], candidates)
        self.assertEqual(result['control_sources'], controls)
        self.assertIs(result['independently_reviewed'], False)
        self.assertEqual(result['admitted_sources'], 0)
        self.assertEqual(result['additional_quota_examples'], 0)
        for key in profiles.SOURCE_QUALIFICATION.split():
            self.assertIs(result[key], False)
        public = profiles.canonical(result)
        self.assertNotIn('PRIVATE_', public)
        self.assertNotIn('#include', public)
        self.assertNotIn(str(self.fixture.base), public)

    @staticmethod
    def replace(value, keys, replacement):
        target = value
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = replacement

    def assert_metadata_rejects(self, variants):
        validate = profiles.source_cohort_metadata
        for keys, replacement in variants:
            value = copy.deepcopy(self.fixture.value)
            self.replace(value, keys, replacement)
            value['records'] = [self.fixture.address(row['value']) for row in value['records']]
            with self.subTest(path=keys, replacement=repr(replacement)[:100]), self.assertRaises(ValueError):
                validate(value)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('product_profiles.py').resolve()),
                               *arguments], capture_output=True, text=True, check=False, timeout=10)

    def test_metadata_projects_content_addresses_without_reading_or_credit(self):
        validate = profiles.source_cohort_metadata
        original = copy.deepcopy(self.fixture.value)
        with mock.patch.object(profiles, 'external_read', side_effect=AssertionError('metadata must be pure')):
            result = validate(self.fixture.value)
        self.assertEqual(profiles.SOURCE_COHORT_SCHEMA, 'codeskeptic-product-source-cohort/v1')
        self.assertEqual(self.fixture.value, original)
        self.assert_uncredited(result, False)
        self.assertEqual(result['records'], [
            {'id': row['value']['id'], 'record_sha256': row['sha256'],
             'source_sha256': row['value']['source']['sha256'],
             **{key: row['value'][key] for key in ('origin', 'cluster', 'selection', 'role', 'family', 'related_to')}}
            for row in self.fixture.value['records']])

    def test_reader_binds_shared_origin_once_without_execution_network_or_writes(self):
        read = profiles.verify_source_cohort
        original_read = profiles.external_read
        seen = []
        def observe(path, capture=False):
            seen.append(Path(path))
            return original_read(path, capture)
        with mock.patch.object(profiles, 'external_read', side_effect=observe), \
                mock.patch.object(profiles.subprocess, 'run', side_effect=AssertionError('no native execution')), \
                mock.patch.object(profiles.urllib.request, 'urlopen', side_effect=AssertionError('no network')), \
                mock.patch.object(profiles.urllib.request, 'build_opener', side_effect=AssertionError('no network')), \
                mock.patch.object(Path, 'write_bytes', side_effect=AssertionError('reader must not write')), \
                mock.patch.object(Path, 'write_text', side_effect=AssertionError('reader must not write')):
            result = read(self.fixture.repo, self.fixture.path)
        self.assert_uncredited(result, True)
        self.assertEqual(seen.count(self.fixture.source_path), 1)
        self.assertEqual(seen.count(self.fixture.capture_path), 1)
        self.assertEqual(result['records'], profiles.source_cohort_metadata(self.fixture.value)['records'])

    def test_1020_synthetic_sources_fit_sixteen_bounded_shards_with_zero_credit(self):
        validate = profiles.source_cohort_metadata
        total, addresses, shard_sizes = 0, set(), []
        # This exercises bounded representation, not 17-bucket coverage or real independence.
        for start in range(0, 1020, 64):
            value = copy.deepcopy(self.fixture.value)
            value['id'] = 'synthetic-shard-' + str(start // 64)
            value['records'] = []
            for number in range(start, min(start + 64, 1020)):
                row = copy.deepcopy(self.fixture.value['records'][0]['value'])
                row.update(id='synthetic-case-' + str(number), cluster='synthetic-cluster-' + str(number),
                           role='safe', expected=[])
                row['source'] = self.fixture.source('#include <stdlib.h>\n\nvoid case_' + str(number) + '(void) {}\n')
                value['records'].append(self.fixture.address(row))
            result = validate(value)
            count = len(value['records'])
            self.assert_uncredited(result, False, count, count, 0)
            total += result['total_sources']
            shard_sizes.append(count)
            addresses.update(row['source_sha256'] for row in result['records'])
        self.assertEqual((total, len(addresses), len(shard_sizes)), (1020, 1020, 16))
        self.assertEqual(shard_sizes, [64] * 15 + [60])
        oversized = copy.deepcopy(value)
        oversized['records'] = []
        for number in range(65):
            row = copy.deepcopy(value['records'][0]['value'])
            row.update(id='overflow-' + str(number), cluster='overflow-' + str(number))
            row['source'] = self.fixture.source('#include <stdlib.h>\n\nvoid overflow_' + str(number) + '(void) {}\n')
            oversized['records'].append(self.fixture.address(row))
        with self.assertRaises(ValueError):
            validate(oversized)

    def test_envelope_and_qualification_are_exact_and_strictly_typed(self):
        variants = [(('schema',), 'other'), (('state',), 'ADMITTED'), (('id',), True),
                    (('id',), '../PRIVATE_SENTINEL'), (('id',), 'x' * 97), (('boundary',), ''),
                    (('boundary',), 'x' * 8193), (('unexpected',), True),
                    (('origins',), []), (('records',), []), (('limits', 'repetitions'), True)]
        for key in profiles.SOURCE_QUALIFICATION.split():
            variants.extend([(('qualification', key), True), (('qualification', key), 0)])
        variants.append((('qualification', 'admitted_sources'), 1))
        self.assert_metadata_rejects(variants)

    def test_declared_linked_bytes_and_origin_count_are_bounded_before_any_read(self):
        validate = profiles.source_cohort_metadata
        self.assertEqual(profiles.SOURCE_COHORT_RECORDS_MAX, 64)
        self.assertEqual(profiles.SOURCE_COHORT_LINKED_BYTES_MAX, 64 * 1024 * 1024)
        value = copy.deepcopy(self.fixture.value)
        value['origins'], value['records'] = [], []
        for number in range(4):
            origin = copy.deepcopy(self.fixture.origin)
            origin['id'] = 'synthetic-origin-' + str(number)
            origin['source'].update(path=str(self.fixture.base / ('origin-' + str(number) + '.c')),
                                    size_bytes=16 * 1024 * 1024)
            origin['api_capture']['path'] = str(self.fixture.base / ('capture-' + str(number) + '.json'))
            row = copy.deepcopy(self.fixture.value['records'][0]['value'])
            row.update(id='synthetic-case-' + str(number), cluster='synthetic-cluster-' + str(number),
                       origin=origin['id'], role='safe', expected=[])
            row['source'] = self.fixture.source('#include <stdlib.h>\n\nvoid case_' + str(number) + '(void) {}\n')
            value['origins'].append(origin)
            value['records'].append(self.fixture.address(row))
        with mock.patch.object(profiles, 'external_read', side_effect=AssertionError('metadata must be pure')):
            with self.assertRaises(ValueError):
                validate(value)
        value = copy.deepcopy(self.fixture.value)
        value['origins'] = [{**copy.deepcopy(self.fixture.origin), 'id': 'origin-' + str(number)}
                            for number in range(65)]
        with self.assertRaises(ValueError):
            validate(value)

    def test_origin_metadata_rejects_foreign_shapes_paths_and_byte_identities(self):
        prefix = ('origins', 0)
        variants = [(prefix + (key,), value) for key, value in (
            ('id', 'INVALID'), ('repository', 'https://github.com/example/synthetic.git'),
            ('repository', 'https://example.invalid/example/synthetic'), ('revision', 'HEAD'),
            ('revision', '0' * 40), ('git_blob', 'x' * 40), ('path', '../source.c'),
            ('path', 'a//source.c'), ('path', 'a\\source.c'), ('path', '/source.c'),
            ('path', 'x' * 513), ('unexpected', 'PRIVATE_SENTINEL'))]
        for link in ('source', 'api_capture'):
            for key, value in (('path', 'relative/PRIVATE_SENTINEL'), ('sha256', 'bad'),
                               ('size_bytes', True), ('size_bytes', 0), ('size_bytes', 16777217),
                               ('unexpected', 'PRIVATE_SENTINEL')):
                variants.append((prefix + (link, key), value))
        self.assert_metadata_rejects(variants)

    def test_record_shapes_sources_and_expected_occurrences_reject_rehashed_forgery(self):
        prefix = ('records', 0, 'value')
        variants = [(prefix + (key,), value) for key, value in (
            ('id', True), ('cluster', '../escape'), ('origin', 'missing-origin'),
            ('selection', 'independent-evaluation'), ('related_to', 'synthetic-control'),
            ('family', 'sql-injection'), ('family', 'unknown-family'), ('family', 'bounds'),
            ('subprofile', 'cwe-121'), ('role', 'unknown'), ('expected', []), ('assumptions', []),
            ('assumptions', ['']), ('assumptions', ['x' * 2049]), ('assumptions', ['x'] * 17),
            ('boundary', ''), ('boundary', 'x' * 8193), ('quota', True))]
        for key, value in (('language', 'C++20'), ('text', 'not terminated'), ('text', 'bad\0\n'),
                           ('sha256', '0' * 64), ('size_bytes', True), ('size_bytes', 1),
                           ('unexpected', 'PRIVATE_SENTINEL')):
            variants.append((prefix + ('source', key), value))
        variants.append((prefix + ('source',), self.fixture.source('x' * 65536 + '\n')))
        for key, value in (('rule', 'double-free'), ('function', ''), ('line', True), ('line', 999),
                           ('column', False), ('column', 0), ('cwes', [401, 401]), ('cwes', [415, 401]),
                           ('cwes', [True]), ('multiplicity', 0), ('multiplicity', True), ('extra', 1)):
            variants.append((prefix + ('expected', 0, key), value))
        variants.append((prefix + ('expected',), self.fixture.value['records'][0]['value']['expected'] * 2))
        variants.append((('records', 1, 'value', 'expected'), self.fixture.value['records'][0]['value']['expected']))
        self.assert_metadata_rejects(variants)

    def test_record_digests_duplicate_ids_sources_origins_and_candidate_clusters_are_rejected(self):
        validate = profiles.source_cohort_metadata
        for mutation in ('digest', 'duplicate-id', 'duplicate-source', 'duplicate-origin', 'unused-origin',
                         'candidate-cluster', 'record-wrapper-field'):
            value = copy.deepcopy(self.fixture.value)
            if mutation == 'duplicate-id': value['records'][1]['value']['id'] = value['records'][0]['value']['id']
            elif mutation == 'duplicate-source': value['records'][1]['value']['source'] = value['records'][0]['value']['source']
            elif mutation in ('duplicate-origin', 'unused-origin'):
                origin = copy.deepcopy(value['origins'][0])
                if mutation == 'unused-origin': origin['id'] = 'unused-origin'
                value['origins'].append(origin)
            elif mutation == 'candidate-cluster':
                value['records'][1]['value'].update(selection='independent-evaluation-candidate', related_to=None)
            value['records'] = [self.fixture.address(row['value']) for row in value['records']]
            if mutation == 'digest': value['records'][0]['sha256'] = '0' * 64
            elif mutation == 'record-wrapper-field': value['records'][0]['private'] = 'PRIVATE_SENTINEL'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(value)

    def test_controls_require_an_in_packet_candidate_with_matching_origin_family_and_cluster(self):
        prefix = ('records', 1, 'value')
        self.assert_metadata_rejects([(prefix + ('related_to',), None),
                                     (prefix + ('related_to',), 'synthetic-control'),
                                     (prefix + ('related_to',), 'external-candidate'),
                                     (prefix + ('cluster',), 'other-cluster'),
                                     (prefix + ('family',), 'double-free')])
        value = copy.deepcopy(self.fixture.value)
        value['origins'].append({**copy.deepcopy(value['origins'][0]), 'id': 'other-origin'})
        value['records'][1]['value']['origin'] = 'other-origin'
        value['records'] = [self.fixture.address(row['value']) for row in value['records']]
        with self.assertRaises(ValueError):
            profiles.source_cohort_metadata(value)

    def test_extraction_requires_sorted_nonoverlapping_bounded_integer_spans(self):
        prefix = ('records', 0, 'value', 'extraction')
        variants = [(prefix + ('ranges',), value) for value in (
            [], [[True, 5]], [[0, 5]], [[5, 1]], [[1, 5], [5, 6]], [[7, 8], [1, 5]],
            [[1, 2, 3]], [[1, 1]] * 65)]
        variants.extend([(prefix + ('adaptation',), 'arbitrary-rewrite'),
                         (prefix + ('raw_sha256',), 'bad'), (prefix + ('extra',), True)])
        self.assert_metadata_rejects(variants)

    def test_reader_rejects_rehashed_extraction_edits_and_out_of_origin_spans(self):
        read = profiles.verify_source_cohort
        for mutation in ('range', 'raw-hash', 'rewrite', 'prefix', 'line-endings'):
            fixture = SourceCohortFixture(self)
            row = fixture.value['records'][0]['value']
            if mutation == 'range': row['extraction']['ranges'] = [[1, 999]]
            elif mutation == 'raw-hash': row['extraction']['raw_sha256'] = 'f' * 64
            else:
                text = row['source']['text']
                if mutation == 'rewrite': text = text.replace('p = 0;', 'free(p);')
                elif mutation == 'prefix': text = text.replace('#include <stdlib.h>\n\n', '#include <stdlib.h>\n')
                else: text = text.replace('\n', '\r\n')
                row['source'] = fixture.source(text)
            fixture.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                read(fixture.repo, fixture.path)

    def test_adjacent_extraction_ranges_preserve_original_utf8_comments_and_whitespace(self):
        read = profiles.verify_source_cohort
        row = self.fixture.value['records'][0]['value']
        row['extraction']['ranges'] = [[1, 3], [4, 5]]
        self.fixture.save()
        self.assert_uncredited(read(self.fixture.repo, self.fixture.path), True)
        self.fixture.source_path.write_bytes(self.fixture.raw.replace(b'p = 0;', b'p = 1;'))
        self.fixture.value['origins'][0]['source'] = self.fixture.link(self.fixture.source_path)
        self.fixture.save()
        with self.assertRaises(ValueError):
            read(self.fixture.repo, self.fixture.path)

    def test_api_capture_rejects_foreign_repository_revision_path_blob_content_and_exit(self):
        read = profiles.verify_source_cohort
        variants = [('api', 'type', 'directory'), ('api', 'path', 'other.c'), ('api', 'sha', 'e' * 40),
                    ('api', 'size', True), ('api', 'size', 1), ('api', 'encoding', 'utf-8'),
                    ('api', 'content', base64.b64encode(b'PRIVATE_PAYLOAD_SENTINEL').decode()),
                    ('api', 'content', '%%%PRIVATE_SENTINEL'),
                    ('api', 'url', 'https://api.github.com/repos/foreign/project/contents/source.c?ref=' + 'a' * 40),
                    ('capture', 'command', ['gh', 'api', self.fixture.endpoint.replace('example/synthetic', 'foreign/project')]),
                    ('capture', 'command', ['gh', 'api', self.fixture.endpoint.replace('a' * 40, 'b' * 40)]),
                    ('capture', 'command', ['gh', 'api', self.fixture.endpoint, '--jq', '.content']),
                    ('capture', 'exit', 1), ('capture', 'expected_exit', 1), ('capture', 'exit', False),
                    ('capture', 'stderr', 'PRIVATE_PAYLOAD_SENTINEL'), ('capture', 'unexpected', True)]
        for section, key, replacement in variants:
            fixture = SourceCohortFixture(self)
            getattr(fixture, section)[key] = replacement
            fixture.save_capture()
            with self.subTest(section=section, key=key), self.assertRaises(ValueError) as caught:
                read(fixture.repo, fixture.path)
            self.assertNotIn('PRIVATE_', str(caught.exception))

    def test_external_source_and_capture_paths_are_exact_host_local_files(self):
        read = profiles.verify_source_cohort
        for kind in ('source', 'api_capture'):
            for mutation in ('missing', 'stale', 'host-relative', 'in-repo', 'parent-alias', 'foreign-host', 'symlink'):
                fixture = SourceCohortFixture(self)
                link = fixture.value['origins'][0][kind]
                target = Path(link['path'])
                if mutation == 'missing': target.unlink()
                elif mutation == 'stale': target.write_bytes(b'PRIVATE_PAYLOAD_SENTINEL\n')
                elif mutation == 'host-relative': link['path'] = target.name
                elif mutation == 'in-repo':
                    inner = fixture.repo / target.name
                    inner.write_bytes(target.read_bytes())
                    link['path'] = str(inner)
                elif mutation == 'parent-alias':
                    (fixture.base / 'alias').mkdir()
                    link['path'] = str(fixture.base / 'alias') + '/../' + target.name
                elif mutation == 'foreign-host':
                    link['path'] = ('/foreign-host/PRIVATE_SENTINEL.c' if os.name == 'nt'
                                    else r'C:\foreign-host\PRIVATE_SENTINEL.c')
                else:
                    saved = target.with_suffix('.saved')
                    target.rename(saved)
                    try: target.symlink_to(saved)
                    except OSError: continue  # Hosts that cannot create symlinks still exercise every other case.
                fixture.save()
                with self.subTest(kind=kind, mutation=mutation), self.assertRaises(ValueError) as caught:
                    read(fixture.repo, fixture.path)
                self.assertNotIn('PRIVATE_', str(caught.exception))
                self.assertNotIn(str(fixture.base), str(caught.exception))

    def test_cohort_selector_is_repo_relative_and_cannot_escape_its_directory(self):
        read = profiles.verify_source_cohort
        for path in (str(self.fixture.cohort_path), '../PRIVATE_SENTINEL.json',
                     'tests/product_corpus/candidates/PRIVATE_SENTINEL.json',
                     'tests/product_corpus/cohorts/../PRIVATE_SENTINEL.json',
                     'tests/product_corpus/cohorts//PRIVATE_SENTINEL.json'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                read(self.fixture.repo, path)

    def test_duplicate_json_keys_are_rejected_in_cohort_capture_and_api(self):
        read = profiles.verify_source_cohort
        for where in ('cohort', 'capture', 'api'):
            fixture = SourceCohortFixture(self)
            if where == 'cohort':
                text = profiles.canonical(fixture.value)
                fixture.cohort_path.write_text('{"id":"PRIVATE_SENTINEL",' + text[1:], encoding='utf-8')
            elif where == 'capture':
                text = profiles.canonical(fixture.capture)
                fixture.capture_path.write_text('{"exit":0,' + text[1:], encoding='utf-8')
                fixture.value['origins'][0]['api_capture'] = fixture.link(fixture.capture_path)
                fixture.save()
            else:
                fixture.capture['stdout'] = '{"type":"file",' + profiles.canonical(fixture.api)[1:]
                fixture.save_capture(refresh_api=False)
            with self.subTest(where=where), self.assertRaises(ValueError):
                read(fixture.repo, fixture.path)

    def test_final_identity_audit_rejects_late_source_capture_and_cohort_drift_without_partial_counts(self):
        read = profiles.verify_source_cohort
        original_read = profiles.external_read
        for target_name in ('source_path', 'capture_path', 'cohort_path'):
            fixture = SourceCohortFixture(self)
            seen, changed = set(), []
            expected = {fixture.source_path, fixture.capture_path, fixture.cohort_path}
            def mutate_after_last_read(path, capture=False):
                result = original_read(path, capture)
                seen.add(Path(path))
                if expected <= seen and not changed:
                    target = getattr(fixture, target_name)
                    target.write_bytes(target.read_bytes() + b'\nPRIVATE_LATE_DRIFT_SENTINEL\n')
                    changed.append(target)
                return result
            output = io.StringIO()
            with mock.patch.object(profiles, 'external_read', side_effect=mutate_after_last_read), \
                    mock.patch.object(sys, 'stdout', output), self.subTest(target=target_name), \
                    self.assertRaises(ValueError) as caught:
                read(fixture.repo, fixture.path)
            self.assertTrue(changed, 'mutation must occur after all three actual inputs were read')
            self.assertEqual(output.getvalue(), '')
            self.assertNotIn('PRIVATE_', str(caught.exception))

    def test_completed_invocations_do_not_cache_later_private_source_drift(self):
        read = profiles.verify_source_cohort
        self.assert_uncredited(read(self.fixture.repo, self.fixture.path), True)
        self.fixture.source_path.write_bytes(b'PRIVATE_NEW_INVOCATION_SENTINEL\n')
        with self.assertRaises(ValueError):
            read(self.fixture.repo, self.fixture.path)

    def test_real_cli_dispatch_reports_only_uncredited_projection(self):
        result = self.cli('source-cohort-check', '--root', str(self.fixture.repo), '--cohort', self.fixture.path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assert_uncredited(json.loads(result.stdout), True)

    def test_real_cli_missing_selector_unrelated_overrides_and_private_failures_have_no_partial_json(self):
        base = ['source-cohort-check', '--root', str(self.fixture.repo), '--cohort', self.fixture.path]
        commands = [['source-cohort-check', '--root', str(self.fixture.repo)],
                    ['limits', '--cohort', self.fixture.path]]
        for option in ('--binding', '--candidate', '--ground-truth', '--external-root', '--evidence-root'):
            commands.append([*base, option, 'PRIVATE_OPTION_SENTINEL'])
        for arguments in commands:
            result = self.cli(*arguments)
            with self.subTest(arguments=arguments):
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('PRIVATE_', result.stderr)
        self.fixture.source_path.write_bytes(b'PRIVATE_PAYLOAD_SENTINEL\n')
        result = self.cli(*base)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('PRIVATE_', result.stderr)
        self.assertNotIn(str(self.fixture.base), result.stderr)


class SourceCohortNativeFixture(SourceCohortFixture):
    """Invented compiler packet bytes: no compiler, container or source execution.

    Commands, streams and projections are constructed here from the documented
    protocol, without any production command-matrix generator or real packet.
    Only a small temporary Git repository supplies actual historical blobs.
    """

    names = ('llvm-caller-slot-overwrite', 'llvm-caller-slot-retained-control')
    forms = ('cdb', 'frontend-adjusted')
    controls = ('wrong-width', 'wrong-malloc', 'wrong-slot')
    compiler = '/usr/bin/clang-20'
    resource = '/usr/lib/llvm-20/lib/clang/20'
    branch = 'agent/cs3-ch08-s01-u003-frozen-product-profiles'
    definitions = ('src/source_manager/SourceManager.cpp', 'src/main.cpp', 'src/core/RuleCapabilities.def')
    helpers = ('scripts/product_profiles.py', 'scripts/product_identity.py', 'scripts/product_quality.py')

    def __init__(self, owner):
        super().__init__(owner)
        for row, name in zip(self.value['records'], self.names):
            row['value']['id'] = name
        self.value['records'][1]['value']['related_to'] = self.names[0]
        self.value['id'] = 'llvm-caller-slot-v1'
        self.save()
        for relative in (*self.definitions, *self.helpers):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('Synthetic historical producer bytes: ' + relative + '\n', encoding='utf-8')
        self.git('init', '--initial-branch=' + self.branch, '--quiet')
        self.git('add', '--', *self.definitions, *self.helpers, self.path)
        self.git('commit', '--no-gpg-sign', '-qm', 'Synthetic source cohort producer')
        self.head = self.git('rev-parse', 'HEAD')
        self.native_root = self.base / 'native'
        self.inputs = self.native_root / 'inputs'
        self.output = self.native_root / 'observation'
        self.inputs.mkdir(parents=True)
        self.output.mkdir()
        for row in self.value['records']:
            record = row['value']
            (self.inputs / (record['id'] + '.c')).write_bytes(record['source']['text'].encode('utf-8'))
        for name in ('run.py', 'observe.py', 'probe.c', *(item + '.c' for item in self.controls)):
            payload = ('/* Synthetic producer fixture ' + name + '; never executed. */\n').encode()
            if name == 'probe.c':
                payload += ''.join('#include "/input/' + item + '.c"\n' for item in self.names).encode()
            (self.native_root / name).write_bytes(payload)
        self.cases = {name: {'path': '/input/' + name + '.c',
                            'sha256': row['value']['source']['sha256']}
                      for name, row in zip(self.names, self.value['records'])}
        self.roles = {name: row['path'] for name, row in self.cases.items()} | {'abi': '/runner/probe.c'}
        self.environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': '/tmp'}
        selected = [self.compiler, '--no-default-config', '-fno-modules', '--target=x86_64-pc-linux-gnu',
                    '-resource-dir', self.resource, '-x', 'c', '-std=c17', '-fsyntax-only']
        adjusted = [self.compiler, '-resource-dir', self.resource, '-fparse-all-comments', *selected[1:]]
        self.cdb = [{'directory': '/input', 'file': row['path'], 'arguments': [*selected, row['path']]}
                    for row in self.cases.values()]
        self.version = 'Ubuntu clang version 20.1.2 (synthetic, never executed)\nTarget: x86_64-pc-linux-gnu\n'
        self.userspace = 'NAME="Synthetic Packet OS"\nID=synthetic\n'
        self.commands, self.stream_names = [], []
        self.dependencies = {name: [path, '/usr/include/stdlib.h'] for name, path in self.roles.items()}
        self.dependencies['abi'] = ['/runner/probe.c', *[row['path'] for row in self.cases.values()],
                                    '/usr/include/stdlib.h']

        def command(name, argv, stdout=b'', stderr=b'', negative=False, marker=None):
            self.commands.append({'name': name, 'argv': argv, 'cwd': '/input',
                                  'environment': copy.deepcopy(self.environment), 'exit_code': int(negative),
                                  'expected_exit': int(negative),
                                  'stderr_marker': marker})
            for suffix, payload in (('stdout', stdout), ('stderr', stderr)):
                filename = name + '.' + suffix
                (self.output / filename).write_bytes(payload)
                self.stream_names.append(filename)

        command('resource-directory', [self.compiler, '--no-default-config', '-print-resource-dir'],
                (self.resource + '\n').encode())
        command('compiler-version', [self.compiler, '--no-default-config', '--version'], self.version.encode())
        self.environment['CODESKEPTIC_RESOURCE_DIR'] = self.resource
        self.write(self.output / 'compile_commands.json', self.cdb)
        self.stream_names.append('compile_commands.json')
        for form, prefix in (('cdb', selected), ('frontend-adjusted', adjusted)):
            for role, path in self.roles.items():
                argv = [item for item in prefix if item != '-fsyntax-only'] + ['-M', '-MT', 'identity-probe', path]
                command(form + '-' + role + '-dependencies-before', argv,
                        ('identity-probe: ' + ' '.join(self.dependencies[role]) + '\n').encode())
            for role, path in self.roles.items():
                command(form + '-' + role + '-syntax', [*prefix, path])
            for control in self.controls:
                name = form + '-' + control
                marker = 'slot-' + control + '-control'
                command(name, [*prefix, '/runner/' + control + '.c'], negative=True, marker=marker,
                        stderr=('probe.c:1:1: error: static assertion failed: ' + marker + '\n').encode())
            for role, path in self.roles.items():
                argv = [item for item in prefix if item != '-fsyntax-only'] + ['-M', '-MT', 'identity-probe', path]
                command(form + '-' + role + '-dependencies-after', argv,
                        ('identity-probe: ' + ' '.join(self.dependencies[role]) + '\n').encode())

        initial = {
            self.compiler: self.identity(self.compiler, b'Synthetic compiler object\n', '/usr/lib/llvm-20/bin/clang'),
            '/etc/os-release': self.identity('/etc/os-release', self.userspace.encode(), '/usr/lib/os-release')}
        mapped = {'/runner/' + name: self.native_root / name for name in
                  ('observe.py', 'probe.c', *(item + '.c' for item in self.controls))}
        mapped['/helpers/product_identity.py'] = self.repo / 'scripts/product_identity.py'
        mapped.update({row['path']: self.inputs / (name + '.c') for name, row in self.cases.items()})
        initial.update({path: self.identity(path, host.read_bytes()) for path, host in mapped.items()})
        native_identities = {path: copy.deepcopy(initial[path]) for paths in self.dependencies.values()
                             for path in paths if path in initial}
        native_identities['/usr/include/stdlib.h'] = self.identity('/usr/include/stdlib.h', b'Synthetic stdlib header\n')
        self.observation = {
            'schema': 'codeskeptic-source-cohort-native-preflight/v1', 'profile': 'caller-slot-publication-c17-v1',
            'cases': copy.deepcopy(self.cases), 'initial_identities': initial, 'compiler_version': self.version,
            'resource_directory': self.resource, 'userspace': self.userspace, 'observed_kernel': 'synthetic-kernel',
            'compilation_database': self.cdb, 'compilation_database_sha256': profiles.file_sha(self.output / 'compile_commands.json'),
            'frontend_adjusted_arguments': {name: [*adjusted, row['path']] for name, row in self.cases.items()},
            'child_environment': copy.deepcopy(self.environment), 'commands': self.commands, 'files': [],
            'native_inputs': {form: {'dependency_paths': copy.deepcopy(self.dependencies),
                                      'input_identities': copy.deepcopy(native_identities)} for form in self.forms},
            'matrix': {'source_roles': list(self.roles), 'command_forms': list(self.forms),
                       'negative_controls': list(self.controls), 'expected_commands': 26},
            'candidate_and_abi_syntax_verified': True, 'same_header_closure_verified': True,
            'before_after_input_identity_verified': True, 'additional_quota_examples': 0,
            'boundary': 'Synthetic retained bytes only; no actual compiler, source admission or qualification.'}
        self.observation.update({key: False for key in (
            'analyzer_run candidate_executed native_product_qualified embedded_frontend_verified calling_abi_executed '
            'runtime_allocator_semantics_verified source_admitted task_ready product_qualified').split()})
        self.refresh_streams()
        self.image = '1' * 64
        self.image_digest = 'sha256:' + '2' * 64
        self.inspection = [{'Id': self.image, 'Digest': self.image_digest, 'Os': 'linux', 'Architecture': 'amd64'}]
        self.write(self.native_root / 'image-inspect.json', self.inspection)
        (self.native_root / 'container.stderr').write_bytes(b'')
        self.projections = [self.project(row) for row in self.value['records']]
        self.cohort_projection = {'records': self.projections, 'total_sources': 2, 'preparation_candidates': 1,
                                  'control_sources': 1, 'source_bytes_verified': True, 'independently_reviewed': False,
                                  'admitted_sources': 0, 'additional_quota_examples': 0,
                                  'cohort_sha256': profiles.file_sha(self.cohort_path),
                                  **copy.deepcopy(self.value['qualification'])}
        argv = ['podman', 'run', '--rm', '--pull=never', '--network=none', '--read-only', '--timeout=150',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--security-opt=label=disable',
                '--cpus=2', '--memory=6144m', '--memory-swap=12288m', '--pids-limit=256',
                '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=1024m']
        for source, destination, mode in ((self.repo / 'scripts', '/helpers', 'ro'),
                                           (self.inputs, '/input', 'ro'), (self.native_root, '/runner', 'ro'),
                                           (self.output, '/output', 'rw')):
            argv.extend(['--mount', 'type=bind,src=' + str(source) + ',dst=' + destination + ',' + mode + '=true'])
        argv.extend(['--entrypoint=/usr/bin/python3', self.image, '-B', '/runner/observe.py'])
        for name, case in self.cases.items():
            argv.extend(['--case', name + '=' + case['sha256']])
        producer_paths = [self.repo / relative for relative in self.helpers] + [self.cohort_path]
        producer_paths += [self.inputs / (name + '.c') for name in self.names]
        producer_paths += [self.native_root / name for name in
                           ('run.py', 'observe.py', 'probe.c', *(item + '.c' for item in self.controls))]
        producer_paths += [self.source_path, self.capture_path]
        self.wrapper = {'schema': 'codeskeptic-source-cohort-native-preflight-driver/v1', 'head': self.head,
                        'image': self.image, 'image_manifest_digest': self.image_digest, 'argv': argv, 'exit_code': 0,
                        'source_cohort': copy.deepcopy(self.cohort_projection),
                        'producer_inputs': {str(path): {'content': self.content(path),
                                            'identity': [17, 29, 33188, 1, path.stat().st_size, 101, 102]}
                                            for path in producer_paths},
                        'image_inspection_sha256': profiles.file_sha(self.native_root / 'image-inspect.json'),
                        'additional_quota_examples': 0,
                        **{key: False for key in 'analyzer_run candidate_executed source_admitted product_qualified task_ready'.split()}}
        self.review_path = self.base / 'PRIVATE_NATIVE_REVIEW.json'
        self.review = {'schema': 'codeskeptic-source-cohort-native-preflight-review/v1',
                       'implementer': '/root', 'verifier': '/root/synthetic_native_verifier', 'head': self.head,
                       'branch': self.branch, 'verdict': 'PASS_BOUNDED_COMPILER_ONLY_PREFLIGHT', 'findings': [],
                       'evidence': {'root': str(self.native_root), 'cohort_sha256': profiles.file_sha(self.cohort_path),
                                    'candidate_sha256': self.cases[self.names[0]]['sha256'],
                                    'control_sha256': self.cases[self.names[1]]['sha256']},
                       'checks': ['Synthetic command and raw-stream binding check, never real native evidence.'],
                       'source_assessment': 'Synthetic metadata; no independent semantic source assessment.',
                       'limitations': ['No real provenance, source admission, compiler execution or product qualification.'],
                       'boundary': 'This synthetic fixture grants no credit.'}
        self.evidence_path = 'tests/product_corpus/cohort_evidence/synthetic-caller-slot-native.json'
        self.packet_path = self.repo / self.evidence_path
        self.packet = {'schema': 'codeskeptic-product-cohort-native-evidence/v1',
                       'state': 'PRE_RESULT_REVIEWED_COMPILER_PACKET_NOT_ADMITTED', 'id': 'synthetic-caller-slot-native',
                       'profile': 'caller-slot-publication-c17-v1',
                       'cohort': {'path': self.path, 'sha256': profiles.file_sha(self.cohort_path)},
                       'records': [{key: row[key] for key in ('id', 'record_sha256', 'source_sha256')}
                                   for row in self.projections],
                       'native': {'head': self.head, 'root': str(self.native_root),
                                  'review': {'path': str(self.review_path), 'sha256': '0' * 64}},
                       'definition_reference': {'head': self.head, 'files': [
                           {'path': relative, 'sha256': profiles.file_sha(self.repo / relative)}
                           for relative in self.definitions]},
                       'limits': copy.deepcopy(profiles.LIMITS), 'additional_quota_examples': 0,
                       'qualification': copy.deepcopy(self.value['qualification']),
                       'boundary': 'Synthetic preparation packet; zero source admission, control credit or qualification.'}
        self.sync()

    @staticmethod
    def project(row):
        value = row['value']
        return {key: value[key] for key in ('id', 'origin', 'cluster', 'selection', 'role', 'family', 'related_to')} | {
            'record_sha256': row['sha256'], 'source_sha256': value['source']['sha256']}

    def entry_link(self, offset=0):
        return {'path': self.path, 'sha256': profiles.file_sha(self.cohort_path),
                **{key: self.projections[offset][key] for key in ('id', 'record_sha256', 'source_sha256')}}

    @classmethod
    def identity(cls, path, data, resolved=None):
        return {'path': path, 'resolved_path': resolved or path, 'sha256': cls.digest(data), 'bytes': len(data)}

    @classmethod
    def content(cls, path):
        return {key: value for key, value in cls.link(path).items() if key != 'path'}

    @staticmethod
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(profiles.canonical(value), encoding='utf-8')
        return profiles.file_sha(path)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Synthetic Test',
            '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=' + str(self.base / 'disabled-hooks'), *args],
            capture_output=True, text=True, check=True, timeout=10).stdout.strip()

    def refresh_streams(self):
        self.observation['files'] = [{'file': name, **self.content(self.output / name)} for name in self.stream_names]

    def sync(self, *, refresh_container=True):
        """Rehash enclosing records without repairing deliberately forged inner facts."""
        observation_sha = self.write(self.output / 'summary.json', self.observation)
        if refresh_container:
            self.write(self.native_root / 'container.stdout', {'commands': 26, 'negative_controls': 6, 'sources': 2,
                       'summary_sha256': observation_sha, 'analyzer_run': False})
        self.wrapper.update(observation_sha256=observation_sha,
                            stdout_sha256=profiles.file_sha(self.native_root / 'container.stdout'),
                            stderr_sha256=profiles.file_sha(self.native_root / 'container.stderr'))
        wrapper_sha = self.write(self.native_root / 'summary.json', self.wrapper)
        self.review['evidence'].update(driver_sha256=wrapper_sha, observation_sha256=observation_sha)
        review_sha = self.write(self.review_path, self.review)
        self.packet['native'].update(wrapper_sha256=wrapper_sha, observation_sha256=observation_sha)
        self.packet['native']['review']['sha256'] = review_sha
        self.write(self.packet_path, self.packet)


class SourceCohortNativeTests(unittest.TestCase):
    """Synthetic raw-packet binding only; never admission or native qualification."""

    def setUp(self):
        self.fixture = SourceCohortNativeFixture(self)

    def assert_uncredited(self, result):
        self.assertIs(result['source_bytes_verified'], True)
        self.assertEqual(result['admitted_sources'], 0)
        self.assertEqual(result['additional_quota_examples'], 0)
        for key in profiles.SOURCE_QUALIFICATION.split():
            self.assertIs(result[key], False)
        public = profiles.canonical(result)
        for private in ('PRIVATE_', '#include', str(self.fixture.base), 'assumptions', 'source_assessment'):
            self.assertNotIn(private, public)

    def assert_rejected(self, reader, fixture):
        output = io.StringIO()
        with mock.patch.object(sys, 'stdout', output), self.assertRaises(ValueError) as caught:
            reader(fixture.repo, fixture.evidence_path)
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn('PRIVATE_', str(caught.exception))
        self.assertNotIn(str(fixture.base), str(caught.exception))

    def cli(self, *arguments):
        script = Path(__file__).resolve().with_name('product_profiles.py')
        return subprocess.run([sys.executable, '-B', str(script), *arguments],
                              capture_output=True, text=True, check=False, timeout=10)

    def test_entry_resolver_reopens_each_exact_record_without_exporting_private_source(self):
        read = profiles.verify_source_cohort_entry
        guard = {}
        with mock.patch.object(profiles.subprocess, 'run', side_effect=AssertionError('no execution')), \
                mock.patch.object(profiles.urllib.request, 'urlopen', side_effect=AssertionError('no network')):
            for number in range(2):
                result = read(self.fixture.repo, self.fixture.entry_link(number), _input_guard=guard)
                self.assert_uncredited(result)
                self.assertIs(result['independently_reviewed'], False)
                self.assertEqual({key: result[key] for key in self.fixture.projections[number]},
                                 self.fixture.projections[number])
                self.assertEqual(result['cohort_sha256'], profiles.file_sha(self.fixture.cohort_path))
        self.assertTrue({self.fixture.cohort_path, self.fixture.source_path, self.fixture.capture_path} <= set(guard))
        self.fixture.capture_path.write_bytes(b'PRIVATE_LATER_CAPTURE_SENTINEL\n')
        with self.assertRaises(ValueError):
            profiles.verify_input_identities(guard)

    def test_existing_cohort_reader_accepts_shared_guard_and_registers_all_inputs(self):
        guard = {}
        result = profiles.verify_source_cohort(self.fixture.repo, self.fixture.path, _input_guard=guard)
        self.assert_uncredited(result)
        self.assertTrue({self.fixture.cohort_path, self.fixture.source_path, self.fixture.capture_path} <= set(guard))

    def test_entry_link_shape_hash_id_and_path_are_all_bound(self):
        read = profiles.verify_source_cohort_entry
        for key, replacement in (('path', '../PRIVATE_LINK_SENTINEL'), ('path', str(self.fixture.cohort_path)),
                                  ('sha256', 'e' * 64), ('id', 'missing-entry'), ('id', True),
                                  ('record_sha256', 'e' * 64), ('source_sha256', 'e' * 64),
                                  ('schema', 'borrowed-source-candidate/v1')):
            link = self.fixture.entry_link()
            link[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError) as caught:
                read(self.fixture.repo, link)
            self.assertNotIn('PRIVATE_', str(caught.exception))
        link = self.fixture.entry_link()
        del link['source_sha256']
        with self.assertRaises(ValueError):
            read(self.fixture.repo, link)

    def test_entry_resolver_rechecks_unselected_peer_and_redacts_input_exceptions(self):
        read = profiles.verify_source_cohort_entry
        peer = self.fixture.value['records'][1]['value']
        peer['source'] = self.fixture.source(peer['source']['text'].replace('free(p);', 'p = 0;'))
        self.fixture.save()
        link = self.fixture.entry_link()
        with self.assertRaises(ValueError):
            read(self.fixture.repo, link)
        with mock.patch.object(profiles, 'external_read', side_effect=ValueError('PRIVATE_INPUT_SENTINEL')):
            with self.assertRaises(ValueError) as caught:
                read(self.fixture.repo, link)
        self.assertNotIn('PRIVATE_', str(caught.exception))

    def test_synthetic_packet_has_real_git_bindings_but_no_native_execution_or_credit(self):
        read = profiles.verify_cohort_native
        execute = subprocess.run
        calls = []
        def git_reads_only(argv, *args, **kwargs):
            self.assertEqual(argv[0], 'git', 'reader cannot execute a compiler, container or source')
            for forbidden in ('commit', 'update-ref', 'checkout', 'fetch', 'push'):
                self.assertNotIn(forbidden, argv)
            calls.append(argv)
            return execute(argv, *args, **kwargs)
        with mock.patch.object(profiles.subprocess, 'run', side_effect=git_reads_only), \
                mock.patch.object(profiles.urllib.request, 'urlopen', side_effect=AssertionError('no network')), \
                mock.patch.object(profiles.urllib.request, 'build_opener', side_effect=AssertionError('no network')), \
                mock.patch.object(Path, 'write_bytes', side_effect=AssertionError('reader is read-only')), \
                mock.patch.object(Path, 'write_text', side_effect=AssertionError('reader is read-only')):
            result = read(self.fixture.repo, self.fixture.evidence_path)
        self.assertTrue(calls)
        self.assert_uncredited(result)
        self.assertIs(result['compiler_preflight_independently_reviewed'], True)
        self.assertEqual(result['recorded_commands'], 26)
        self.assertEqual(result['recorded_stream_files'], 53)
        self.assertEqual(result['producer_head'], self.fixture.head)
        self.assertEqual(result['packet_sha256'], profiles.file_sha(self.fixture.packet_path))
        self.assertEqual(result['cohort_sha256'], profiles.file_sha(self.fixture.cohort_path))
        self.assertEqual(len(result['records']), 2)
        for actual, expected in zip(result['records'], self.fixture.projections):
            self.assertEqual({key: actual[key] for key in expected}, expected)
        self.assertEqual(len(self.fixture.wrapper['producer_inputs']), 14)
        self.assertEqual([row['exit_code'] for row in self.fixture.commands].count(0), 20)
        self.assertEqual([row['exit_code'] for row in self.fixture.commands].count(1), 6)

    def test_packet_exact_shape_refs_candidate_control_order_and_old_protocol_are_rejected(self):
        read = profiles.verify_cohort_native
        variants = [(('schema',), 'codeskeptic-retained-linux-native-preflight/v1'),
                    (('state',), 'ADMITTED'), (('id',), True), (('profile',), 'gcc-parent-child'),
                    (('extra',), 'PRIVATE_PACKET_SENTINEL'), (('cohort', 'sha256'), 'e' * 64),
                    (('records', 0, 'record_sha256'), 'e' * 64), (('records', 1, 'source_sha256'), 'e' * 64),
                    (('records', 0, 'id'), 'missing-candidate'), (('records',), []),
                    (('records',), list(reversed(self.fixture.packet['records']))),
                    (('records',), self.fixture.packet['records'][:1]),
                    (('additional_quota_examples',), True), (('additional_quota_examples',), 1),
                    (('limits', 'repetitions'), 1)]
        variants += [(('qualification', key), True) for key in profiles.SOURCE_QUALIFICATION.split()]
        for keys, replacement in variants:
            fixture = SourceCohortNativeFixture(self)
            SourceCohortTests.replace(fixture.packet, keys, replacement)
            fixture.sync()
            with self.subTest(path=keys):
                self.assert_rejected(read, fixture)

    def test_driver_requires_exact_podman_request_image_identity_and_no_false_credit(self):
        read = profiles.verify_cohort_native
        for mutation in ('network', 'mount', 'image', 'timeout', 'env', 'exit', 'extra-producer', 'missing-producer',
                         'borrowed-schema', 'source-credit', 'control-credit', 'inspection'):
            fixture = SourceCohortNativeFixture(self)
            if mutation == 'network': fixture.wrapper['argv'].remove('--network=none')
            elif mutation == 'mount':
                offset = fixture.wrapper['argv'].index('--mount') + 1
                fixture.wrapper['argv'][offset] = 'type=bind,src=/PRIVATE_MOUNT_SENTINEL,dst=/helpers,ro=true'
            elif mutation == 'image': fixture.wrapper['image'] = '3' * 64
            elif mutation == 'timeout': fixture.wrapper['argv'][6] = '--timeout=999'
            elif mutation == 'env': fixture.wrapper['argv'].insert(2, '--env=LD_PRELOAD=PRIVATE_SENTINEL')
            elif mutation == 'exit': fixture.wrapper['exit_code'] = False
            elif mutation == 'extra-producer': fixture.wrapper['producer_inputs']['/PRIVATE_EXTRA_SENTINEL'] = {}
            elif mutation == 'missing-producer': fixture.wrapper['producer_inputs'].pop(str(fixture.native_root / 'run.py'))
            elif mutation == 'borrowed-schema': fixture.wrapper['schema'] = 'codeskeptic-retained-linux-native-preflight-driver/v1'
            elif mutation == 'source-credit': fixture.wrapper['source_cohort']['admitted_sources'] = 1
            elif mutation == 'control-credit': fixture.wrapper['additional_quota_examples'] = 1
            else:
                fixture.inspection[0]['Digest'] = 'sha256:' + '3' * 64
                fixture.wrapper['image_inspection_sha256'] = fixture.write(fixture.native_root / 'image-inspect.json', fixture.inspection)
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_command_argv_environment_order_count_exit_and_matrix_cannot_be_rehashed_away(self):
        read = profiles.verify_cohort_native
        for mutation in ('argv', 'environment', 'metadata-env', 'reorder', 'missing', 'duplicate', 'exit',
                         'expected-exit', 'marker', 'cdb', 'adjusted-resource', 'matrix', 'false-pass', 'qualification'):
            fixture = SourceCohortNativeFixture(self)
            commands = fixture.observation['commands']
            if mutation == 'argv': commands[2]['argv'].remove('-fno-modules')
            elif mutation == 'environment': commands[2]['environment']['LD_PRELOAD'] = 'PRIVATE_ENV_SENTINEL'
            elif mutation == 'metadata-env': commands[0]['environment']['CODESKEPTIC_RESOURCE_DIR'] = fixture.resource
            elif mutation == 'reorder': commands[2], commands[3] = commands[3], commands[2]
            elif mutation == 'missing': commands.pop()
            elif mutation == 'duplicate': commands.append(copy.deepcopy(commands[-1]))
            elif mutation == 'exit': commands[8]['exit_code'] = 0
            elif mutation == 'expected-exit': commands[8]['expected_exit'] = True
            elif mutation == 'marker': commands[8]['stderr_marker'] = 'borrowed-parent-child-control'
            elif mutation == 'cdb':
                fixture.cdb[0]['arguments'].remove('--no-default-config')
                fixture.observation['compilation_database_sha256'] = fixture.write(fixture.output / 'compile_commands.json', fixture.cdb)
                fixture.refresh_streams()
            elif mutation == 'adjusted-resource':
                argv = fixture.observation['frontend_adjusted_arguments'][fixture.names[0]]
                del argv[1:3]
            elif mutation == 'matrix': fixture.observation['matrix']['expected_commands'] = 25
            elif mutation == 'false-pass': fixture.observation['candidate_and_abi_syntax_verified'] = 1
            else: fixture.observation['native_product_qualified'] = True
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_rehashed_raw_streams_must_show_intended_failure_and_actual_dependency_closure(self):
        read = profiles.verify_cohort_native
        negative = 'cdb-wrong-slot.stderr'
        dep = 'cdb-' + self.fixture.names[0] + '-dependencies-before.stdout'
        variants = [(negative, b'PRIVATE_FAILURE_SENTINEL\n'),
                    (negative, b'slot-wrong-slot-control unrelated diagnostic\n'),
                    (negative, b'error: static assertion failed: unrelated-control\n'),
                    ('cdb-wrong-slot.stdout', b'PRIVATE_NEGATIVE_STDOUT_SENTINEL\n'),
                    ('cdb-' + self.fixture.names[0] + '-syntax.stderr', b'PRIVATE_SYNTAX_SENTINEL\n'),
                    ('resource-directory.stderr', b'PRIVATE_METADATA_SENTINEL\n'),
                    ('compiler-version.stdout', b'PRIVATE_FOREIGN_COMPILER_SENTINEL\n'),
                    (dep, ('identity-probe: /input/' + self.fixture.names[0] + '.c\n').encode()),
                    (dep, b'identity-probe: /usr/include/stdlib.h\n'),
                    (dep, b'PRIVATE_INVALID_MAKE_SENTINEL\n'),
                    ('cdb-abi-dependencies-before.stdout',
                     b'identity-probe: /runner/probe.c /usr/include/stdlib.h\n')]
        for filename, data in variants:
            fixture = SourceCohortNativeFixture(self)
            (fixture.output / filename).write_bytes(data)
            fixture.refresh_streams()
            fixture.sync()
            with self.subTest(filename=filename, data=data[:50]):
                self.assert_rejected(read, fixture)

    def test_dependency_forms_and_initial_identities_must_agree_on_complete_union(self):
        read = profiles.verify_cohort_native
        for mutation in ('missing-header', 'extra-header', 'foreign-form', 'initial-source', 'userspace',
                         'identity-path', 'identity-resolved', 'identity-size', 'initial-extra', 'initial-missing',
                         'overlap-source'):
            fixture = SourceCohortNativeFixture(self)
            native = fixture.observation['native_inputs']['cdb']
            initial = fixture.observation['initial_identities']
            source = fixture.cases[fixture.names[0]]['path']
            if mutation == 'missing-header': native['input_identities'].pop('/usr/include/stdlib.h')
            elif mutation == 'extra-header':
                native['input_identities']['/PRIVATE_HEADER_SENTINEL'] = fixture.identity('/PRIVATE_HEADER_SENTINEL', b'header')
            elif mutation == 'foreign-form':
                fixture.observation['native_inputs']['frontend-adjusted']['input_identities']['/usr/include/stdlib.h']['sha256'] = 'e' * 64
            elif mutation == 'initial-source': initial[source]['sha256'] = 'e' * 64
            elif mutation == 'userspace': fixture.observation['userspace'] += 'PRIVATE_OS_SENTINEL\n'
            elif mutation == 'identity-path': native['input_identities'][source]['path'] = '/PRIVATE_PATH_SENTINEL'
            elif mutation == 'identity-resolved': native['input_identities'][source]['resolved_path'] = 'relative/PRIVATE_SENTINEL'
            elif mutation == 'identity-size': native['input_identities'][source]['bytes'] = True
            elif mutation == 'initial-extra': initial['/PRIVATE_EXTRA_SENTINEL'] = fixture.identity('/PRIVATE_EXTRA_SENTINEL', b'x')
            elif mutation == 'overlap-source': native['input_identities'][source]['sha256'] = 'e' * 64
            else: initial.pop('/runner/observe.py')
            if mutation in ('missing-header', 'extra-header', 'identity-path', 'identity-resolved', 'identity-size', 'overlap-source'):
                fixture.observation['native_inputs']['frontend-adjusted'] = copy.deepcopy(native)
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_review_findings_mapped_paths_cannot_consistently_resolve_outside_fixed_mounts(self):
        read = profiles.verify_cohort_native
        initial = self.fixture.observation['initial_identities']
        for path in sorted(set(initial) - {self.fixture.compiler, '/etc/os-release'}):
            fixture = SourceCohortNativeFixture(self)
            fixture.observation['initial_identities'][path]['resolved_path'] = '/PRIVATE_FOREIGN_RESOLVED_SOURCE'
            for form in fixture.forms:
                identities = fixture.observation['native_inputs'][form]['input_identities']
                if path in identities:
                    identities[path]['resolved_path'] = '/PRIVATE_FOREIGN_RESOLVED_SOURCE'
            fixture.sync()
            with self.subTest(path=path):
                self.assert_rejected(read, fixture)
        # The profile's ordinary compiler and OS symlinks remain valid.
        self.assertNotEqual(initial[self.fixture.compiler]['resolved_path'], self.fixture.compiler)
        self.assertNotEqual(initial['/etc/os-release']['resolved_path'], '/etc/os-release')
        self.assert_uncredited(read(self.fixture.repo, self.fixture.evidence_path))

    def test_review_findings_recorded_sizes_obey_the_producers_512_mib_limit(self):
        import product_identity as identity
        self.assertEqual(identity.MAX_FILE, 512 * 1024 * 1024)
        read = profiles.verify_cohort_native
        for path in (self.fixture.compiler, '/usr/include/stdlib.h'):
            for size in (identity.MAX_FILE, identity.MAX_FILE + 1, 2 ** 32):
                fixture = SourceCohortNativeFixture(self)
                if path in fixture.observation['initial_identities']:
                    fixture.observation['initial_identities'][path]['bytes'] = size
                for form in fixture.forms:
                    identities = fixture.observation['native_inputs'][form]['input_identities']
                    if path in identities:
                        identities[path]['bytes'] = size
                fixture.sync()
                with self.subTest(path=path, size=size):
                    if size == identity.MAX_FILE:
                        # Metadata boundary only, not a claim of matching extracted bytes.
                        self.assert_uncredited(read(fixture.repo, fixture.evidence_path))
                    else:
                        self.assert_rejected(read, fixture)

    def test_review_findings_image_platform_must_match_the_explicit_linux_x86_64_profile(self):
        read = profiles.verify_cohort_native
        for key, replacement in (('Os', 'windows'), ('Architecture', 'arm64'), ('Os', None),
                                  ('Architecture', None), ('Os', True), ('Architecture', ['amd64'])):
            fixture = SourceCohortNativeFixture(self)
            if replacement is None:
                del fixture.inspection[0][key]
            else:
                fixture.inspection[0][key] = replacement
            fixture.wrapper['image_inspection_sha256'] = fixture.write(
                fixture.native_root / 'image-inspect.json', fixture.inspection)
            fixture.sync()
            with self.subTest(key=key, replacement=replacement):
                self.assert_rejected(read, fixture)

    def test_consistently_rehashed_dependencies_cannot_omit_native_stdlib_or_probe_peer(self):
        read = profiles.verify_cohort_native
        for mutation in ('native-header', 'probe-peer'):
            fixture = SourceCohortNativeFixture(self)
            paths = copy.deepcopy(fixture.dependencies)
            if mutation == 'native-header':
                paths = {role: [path for path in entries if path != '/usr/include/stdlib.h']
                         for role, entries in paths.items()}
            else:
                peer = fixture.cases[fixture.names[1]]['path']
                paths['abi'].remove(peer)
            union = {path for entries in paths.values() for path in entries}
            for form in fixture.forms:
                fixture.observation['native_inputs'][form]['dependency_paths'] = copy.deepcopy(paths)
                fixture.observation['native_inputs'][form]['input_identities'] = {
                    path: row for path, row in fixture.observation['native_inputs'][form]['input_identities'].items()
                    if path in union}
                for role, entries in paths.items():
                    for phase in ('before', 'after'):
                        name = form + '-' + role + '-dependencies-' + phase + '.stdout'
                        (fixture.output / name).write_bytes(('identity-probe: ' + ' '.join(entries) + '\n').encode())
            fixture.refresh_streams()
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_review_binds_distinct_agents_exact_producer_and_non_admission_verdict(self):
        read = profiles.verify_cohort_native
        variants = [(('schema',), 'codeskeptic-native-preflight-review/v1'), (('verdict',), 'PASS'),
                    (('verifier',), '/root'), (('verifier',), 'unbounded identity'),
                    (('findings',), ['PRIVATE_UNRESOLVED_SENTINEL']), (('head',), 'e' * 40),
                    (('branch',), 'main'), (('evidence', 'root'), '/PRIVATE_ROOT_SENTINEL'),
                    (('evidence', 'cohort_sha256'), 'e' * 64), (('evidence', 'candidate_sha256'), 'e' * 64),
                    (('evidence', 'control_sha256'), 'e' * 64), (('checks',), []), (('extra',), True)]
        for keys, replacement in variants:
            fixture = SourceCohortNativeFixture(self)
            SourceCohortTests.replace(fixture.review, keys, replacement)
            fixture.sync()
            with self.subTest(path=keys):
                self.assert_rejected(read, fixture)

    def test_producer_blob_hash_size_and_ancestor_are_actual_git_gates(self):
        read = profiles.verify_cohort_native
        for mutation in ('helper-sha', 'helper-size', 'definition-sha', 'cohort-sha', 'nonancestor'):
            fixture = SourceCohortNativeFixture(self)
            link = fixture.wrapper['producer_inputs'][str(fixture.repo / 'scripts/product_identity.py')]['content']
            if mutation == 'helper-sha': link['sha256'] = 'e' * 64
            elif mutation == 'helper-size':
                # Forge all repeated size claims, so only the actual historical
                # Git blob size (not an internal summary disagreement) rejects it.
                link['size_bytes'] += 1
                fixture.wrapper['producer_inputs'][str(fixture.repo / 'scripts/product_identity.py')]['identity'][4] += 1
                fixture.observation['initial_identities']['/helpers/product_identity.py']['bytes'] += 1
            elif mutation == 'definition-sha': fixture.packet['definition_reference']['files'][0]['sha256'] = 'e' * 64
            elif mutation == 'cohort-sha':
                fixture.wrapper['producer_inputs'][str(fixture.cohort_path)]['content']['sha256'] = 'e' * 64
            else:
                tree = fixture.git('rev-parse', 'HEAD^{tree}')
                orphan = fixture.git('commit-tree', tree, '-m', 'Synthetic nonancestor without a parent')
                self.assertNotEqual(orphan, fixture.head)
                fixture.wrapper['head'] = fixture.review['head'] = orphan
                fixture.packet['native']['head'] = fixture.packet['definition_reference']['head'] = orphan
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_later_unrelated_checkout_commit_preserves_historical_producer_hashes_and_sizes(self):
        read = profiles.verify_cohort_native
        self.assert_uncredited(read(self.fixture.repo, self.fixture.evidence_path))
        helper = self.fixture.repo / 'scripts/product_identity.py'
        helper.write_text('Later helper implementation differs from the recorded producer.\n', encoding='utf-8')
        note = self.fixture.repo / 'later-note.txt'
        note.write_text('Unrelated integration after native preparation.\n', encoding='utf-8')
        self.fixture.git('add', '--', 'scripts/product_identity.py', 'later-note.txt')
        self.fixture.git('commit', '--no-gpg-sign', '-qm', 'Synthetic later integration')
        self.assertNotEqual(self.fixture.git('rev-parse', 'HEAD'), self.fixture.head)
        result = read(self.fixture.repo, self.fixture.evidence_path)
        self.assert_uncredited(result)
        self.assertEqual(result['producer_head'], self.fixture.head)

    def test_early_source_and_api_drift_cannot_be_overwritten_by_later_packet_reads(self):
        read = profiles.verify_cohort_native
        original = profiles.external_read
        for target_name in ('source_path', 'capture_path'):
            fixture = SourceCohortNativeFixture(self)
            seen, changed = set(), []
            def mutate(path, capture=False):
                result = original(path, capture)
                seen.add(Path(path))
                if {fixture.source_path, fixture.capture_path} <= seen and fixture.native_root in Path(path).parents and not changed:
                    target = getattr(fixture, target_name)
                    target.write_bytes(target.read_bytes() + b'\nPRIVATE_EARLY_DRIFT_SENTINEL\n')
                    changed.append(target)
                return result
            with mock.patch.object(profiles, 'external_read', side_effect=mutate), self.subTest(target=target_name):
                self.assert_rejected(read, fixture)
            self.assertTrue(changed, 'must mutate a bound origin while later native inputs are read')

    def test_empty_streams_container_stderr_and_directories_join_the_final_guard(self):
        read = profiles.verify_cohort_native
        original = profiles.verify_input_identities
        for mutation in ('empty-stream', 'container-stderr', 'directory'):
            fixture = SourceCohortNativeFixture(self)
            target = (fixture.native_root / 'container.stderr' if mutation == 'container-stderr'
                      else fixture.output / ('cdb-' + fixture.names[0] + '-syntax.stderr'))
            changed = []
            def mutate(guard):
                if target in guard and fixture.output in guard and not changed:
                    if mutation == 'directory': (fixture.output / 'PRIVATE_LATE_DIRECTORY_SENTINEL').mkdir()
                    else: target.write_bytes(b'PRIVATE_LATE_EMPTY_STREAM_SENTINEL\n')
                    changed.append(target)
                return original(guard)
            with mock.patch.object(profiles, 'verify_input_identities', side_effect=mutate), self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)
            self.assertTrue(changed, 'empty stream and directory identities must be registered before final audit')

    def test_packet_tree_missing_duplicate_and_unexpected_members_are_rejected(self):
        read = profiles.verify_cohort_native
        for mutation in ('root-extra', 'input-extra', 'output-extra', 'output-directory', 'missing-stream',
                         'missing-source', 'duplicate-file', 'undeclared-file', 'container-output'):
            fixture = SourceCohortNativeFixture(self)
            if mutation == 'root-extra': (fixture.native_root / 'PRIVATE_EXTRA_SENTINEL').write_bytes(b'extra')
            elif mutation == 'input-extra': (fixture.inputs / 'PRIVATE_EXTRA_SENTINEL').write_bytes(b'extra')
            elif mutation == 'output-extra': (fixture.output / 'PRIVATE_EXTRA_SENTINEL').write_bytes(b'extra')
            elif mutation == 'output-directory': (fixture.output / 'PRIVATE_DIRECTORY_SENTINEL').mkdir()
            elif mutation == 'missing-stream': (fixture.output / fixture.stream_names[0]).unlink()
            elif mutation == 'missing-source': (fixture.inputs / (fixture.names[1] + '.c')).unlink()
            elif mutation == 'duplicate-file': fixture.observation['files'].append(copy.deepcopy(fixture.observation['files'][0]))
            elif mutation == 'undeclared-file': fixture.observation['files'].pop()
            else:
                (fixture.native_root / 'container.stdout').write_bytes(b'PRIVATE_CONTAINER_SENTINEL\n')
            fixture.sync(refresh_container=mutation != 'container-output')
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_symlink_hardlink_and_host_path_aliases_never_count_as_bound_native_inputs(self):
        read = profiles.verify_cohort_native
        def unavailable_windows_link(fixture, target, error):
            if os.name != 'nt':
                raise error
            # Without Windows link-creation privileges, exercise a real reader
            # rejection of an injected canonical-path alias. Do not silently
            # skip or claim that a physical NTFS symlink was tested.
            resolve, reached = Path.resolve, []
            def alias(path, *args, **kwargs):
                if path == target:
                    reached.append(path)
                    return fixture.base / 'PRIVATE_RESOLVED_ALIAS_SENTINEL'
                return resolve(path, *args, **kwargs)
            fixture.sync()
            with mock.patch.object(Path, 'resolve', autospec=True, side_effect=alias):
                self.assert_rejected(read, fixture)
            self.assertTrue(reached, 'reader must inspect and reject the observed alias')
        for mutation in ('hardlink', 'symlink', 'relative-root', 'in-repo-root', 'relative-review'):
            fixture = SourceCohortNativeFixture(self)
            target = fixture.output / 'cdb-wrong-slot.stderr'
            if mutation == 'hardlink':
                alias = fixture.base / 'PRIVATE_HARDLINK_SENTINEL'
                try: os.link(target, alias)
                except OSError as error:
                    unavailable_windows_link(fixture, target, error)
                    continue
            elif mutation == 'symlink':
                saved = fixture.base / 'PRIVATE_SYMLINK_SENTINEL'
                target.rename(saved)
                try: target.symlink_to(saved)
                except OSError as error:
                    saved.rename(target)
                    unavailable_windows_link(fixture, target, error)
                    continue
            elif mutation == 'relative-root': fixture.packet['native']['root'] = 'relative/PRIVATE_ROOT_SENTINEL'
            elif mutation == 'in-repo-root': fixture.packet['native']['root'] = str(fixture.repo)
            else: fixture.packet['native']['review']['path'] = 'relative/PRIVATE_REVIEW_SENTINEL'
            fixture.sync()
            with self.subTest(mutation=mutation):
                self.assert_rejected(read, fixture)

    def test_real_native_cli_dispatch_returns_unqualified_metadata_only(self):
        result = self.cli('cohort-native-check', '--root', str(self.fixture.repo),
                          '--cohort-evidence', self.fixture.evidence_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        value = json.loads(result.stdout)
        self.assert_uncredited(value)
        self.assertEqual(value['recorded_commands'], 26)
        self.assertEqual(value['recorded_stream_files'], 53)

    def test_real_native_cli_rejects_missing_cross_command_selectors_and_private_failures(self):
        base = ['cohort-native-check', '--root', str(self.fixture.repo), '--cohort-evidence', self.fixture.evidence_path]
        variants = [['cohort-native-check', '--root', str(self.fixture.repo)],
                    ['limits', '--cohort-evidence', self.fixture.evidence_path]]
        for option in ('--cohort', '--binding', '--candidate', '--ground-truth', '--external-root', '--evidence-root'):
            variants.append([*base, option, 'PRIVATE_OPTION_SENTINEL'])
        for arguments in variants:
            result = self.cli(*arguments)
            with self.subTest(arguments=arguments):
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('PRIVATE_', result.stderr)
        self.fixture.capture_path.write_bytes(b'PRIVATE_CLI_PAYLOAD_SENTINEL\n')
        result = self.cli(*base)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('PRIVATE_', result.stderr)
        self.assertNotIn(str(self.fixture.base), result.stderr)


if __name__ == "__main__":
    unittest.main()
