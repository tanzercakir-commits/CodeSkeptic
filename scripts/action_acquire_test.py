#!/usr/bin/env python3
"""Artifact acquisition regressions; only synthetic local archives, no network."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import action_acquire as acquire


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="action acquisition ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.archive = self.root / "codeskeptic-v0.4.9-test-linux-x86_64.tar.gz"
        self.package = "codeskeptic-v0.4.9-test-linux-x86_64"
        self.path_file = self.root / "github-path"
        self.make_archive()
        self.env = dict(os.environ, INPUT_ARTIFACT_PATH=str(self.archive),
                        INPUT_ARTIFACT_SHA256=self.digest(), INPUT_VERSION="",
                        RUNNER_TEMP=str(self.runner), GITHUB_PATH=str(self.path_file), GH_TOKEN="synthetic-test-only")
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, self.env, clear=True).start()

    def digest(self):
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def make_archive(self, extra=(), omit=(), identity="0.4.9-test"):
        contents = {"bin/codeskeptic": ("#!" + sys.executable + "\nprint('CodeSkeptic " + identity + "')\n").encode(),
                    "lib/clang/20/include/stddef.h": b"/* synthetic resource header */\n",
                    "LICENSE": b"synthetic license", "README.md": b"synthetic package"}
        with tarfile.open(self.archive, "w:gz") as output:
            for name, data in contents.items():
                if name in omit:
                    continue
                info = tarfile.TarInfo(self.package + "/" + name)
                info.size = len(data)
                info.mode = 0o755 if name.startswith("bin/") else 0o644
                output.addfile(info, io.BytesIO(data))
            for info, data in extra:
                output.addfile(info, io.BytesIO(data) if info.isfile() else None)

    def refresh(self):
        os.environ["INPUT_ARTIFACT_SHA256"] = self.digest()

    def rejected(self, mode="local"):
        with self.assertRaises((acquire.ActionError, OSError, tarfile.TarError)):
            acquire.acquire(mode)
        self.assertFalse(self.path_file.exists())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_local_install_is_unique_and_binary_environment_has_no_token(self):
        with patch.object(acquire, "execute", wraps=acquire.execute) as execute:
            first = acquire.acquire("local")
            second = acquire.acquire("local")
        self.assertNotEqual(first, second)
        self.assertEqual(self.path_file.read_text().splitlines(), [str(first / "bin"), str(second / "bin")])
        self.assertEqual(len(execute.call_args_list), 2)
        for call in execute.call_args_list:
            self.assertNotEqual(call.args[0][0], "gh")
            self.assertNotIn("GH_TOKEN", call.args[1])

    def test_checksum_mismatch_is_rejected_before_execution(self):
        os.environ["INPUT_ARTIFACT_SHA256"] = "0" * 64
        with patch.object(acquire, "execute") as execute:
            self.rejected()
            execute.assert_not_called()

    def test_missing_checksum_and_mixed_inputs_are_rejected(self):
        for changes in ({"INPUT_ARTIFACT_SHA256": ""}, {"INPUT_VERSION": "latest"}, {"INPUT_ARTIFACT_PATH": ""}):
            with self.subTest(changes=changes), patch.dict(os.environ, changes):
                self.rejected()

    def test_archive_link_or_special_member_is_rejected_before_execution(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo(self.package + "/extra")
                info.type, info.linkname = kind, "bin/codeskeptic"
                self.make_archive(extra=[(info, b"")])
                self.refresh()
                with patch.object(acquire, "execute") as execute:
                    self.rejected()
                    execute.assert_not_called()

    def test_unsafe_paths_duplicate_and_second_root_are_rejected(self):
        for name in ("/absolute", self.package + "/../outside", self.package + "/./alias",
                     self.package + "/a//b", self.package + "/back\\slash", self.package + "/line\nbreak",
                     self.package + "/LICENSE", "codeskeptic-v1.2.3-linux-x86_64/LICENSE"):
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                self.make_archive(extra=[(info, b"")])
                self.refresh()
                self.rejected()

    def test_file_may_not_be_used_as_parent(self):
        info = tarfile.TarInfo(self.package + "/LICENSE/child")
        self.make_archive(extra=[(info, b"")])
        self.refresh()
        self.rejected()

    def test_missing_binary_license_or_headers_is_rejected(self):
        for name in ("bin/codeskeptic", "lib/clang/20/include/stddef.h", "LICENSE", "README.md"):
            with self.subTest(name=name):
                self.make_archive(omit=[name])
                self.refresh()
                self.rejected()

    def test_binary_identity_must_match_package(self):
        self.make_archive(identity="9.9.9")
        self.refresh()
        self.rejected()

    def test_source_archive_symlink_is_not_followed(self):
        link = self.root / "linked.tar.gz"
        link.symlink_to(self.archive)
        os.environ["INPUT_ARTIFACT_PATH"] = str(link)
        self.rejected()

    def test_existing_command_file_symlink_is_preserved(self):
        sentinel = self.root / "sentinel"
        sentinel.write_text("preserve")
        self.path_file.symlink_to(sentinel)
        with self.assertRaises(OSError):
            acquire.acquire("local")
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertTrue(self.path_file.is_symlink())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_command_file_injection_is_rejected(self):
        os.environ["GITHUB_PATH"] += "\nsecond-line"
        self.rejected()

    def test_archive_and_expanded_size_budgets_are_enforced(self):
        for constant in ("MAX_ARCHIVE", "MAX_EXPANDED"):
            with self.subTest(constant=constant), patch.object(acquire, constant, 1):
                self.rejected()

    def test_branch_and_sha_refs_never_implicitly_float(self):
        for ref in ("", "main", "a" * 40, "./", "vgarbage", "v1.2.3/unsafe"):
            with self.subTest(ref=ref), self.assertRaises(acquire.ActionError):
                acquire.release_version("", ref)
        self.assertEqual(acquire.release_version("", "v1.2.3"), "v1.2.3")
        self.assertEqual(acquire.release_version("latest", "main"), "latest")
        self.assertEqual(acquire.release_version("v1.2.3", "main"), "v1.2.3")

    def mock_download(self, arguments, environment, timeout, **kwargs):
        if arguments[0] != "gh":
            return self.original_execute(arguments, environment, timeout, **kwargs)
        self.download_arguments = arguments
        self.assertEqual(arguments[arguments.index("-R") + 1], acquire.REPOSITORY)
        destination = Path(arguments[arguments.index("-D") + 1])
        shutil.copyfile(self.archive, destination / self.archive.name)
        (destination / "sha256sums.txt").write_text(self.checksum_text)
        return self.download_exit, None, None

    def release_setup(self, version="v0.4.9-test"):
        os.environ.update(INPUT_ARTIFACT_PATH="", INPUT_ARTIFACT_SHA256="", INPUT_VERSION=version, ACTION_REF="main")
        self.original_execute = acquire.execute
        self.checksum_text = self.digest() + "  " + self.archive.name + "\n"
        self.download_exit = 0
        return patch.object(acquire, "execute", side_effect=self.mock_download)

    def test_explicit_pinned_and_latest_release_mock_downloads(self):
        for version in ("v0.4.9-test", "latest"):
            with self.subTest(version=version), self.release_setup(version):
                root = acquire.acquire("release")
                self.assertTrue((root / "bin/codeskeptic").is_file())
                self.assertEqual(version in self.download_arguments, version != "latest")

    def test_release_download_failure_rejects_even_if_files_exist(self):
        with self.release_setup():
            self.download_exit = 7
            self.rejected("release")

    def test_release_requires_exact_single_matching_checksum(self):
        with self.release_setup():
            good = self.checksum_text
            for invalid in ("", good + good, good.replace(self.archive.name, "prefix-" + self.archive.name), "0" * 64 + good[64:]):
                with self.subTest(invalid=invalid):
                    self.checksum_text = invalid
                    self.rejected("release")

    def test_requested_release_must_match_archive_identity(self):
        with self.release_setup("v1.2.3"):
            self.rejected("release")


if __name__ == "__main__":
    unittest.main()
