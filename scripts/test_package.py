#!/usr/bin/env python3
"""Small synthetic packaging regressions; not actual artifact qualification."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="package fixtures ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.resources = self.root / "clang" / "20"
        (self.resources / "include").mkdir(parents=True)
        (self.resources / "include" / "stddef.h").write_text("/* fixture */\n")
        self.lib = self.root / "original libs" / "libLLVM.so.20.1"
        self.lib.parent.mkdir()
        self.lib.write_text("synthetic DSO, never executed\n")
        self.license = self.root / "share/doc/fixture/copyright"
        self.license.parent.mkdir(parents=True)
        self.license.write_text("Copyright fixture authors\nLicense: MIT\nfixture text\n")
        self.binary = self.root / "source binary"
        self.version = "0.4.9-dev+g0123456789ab"
        self.executable(self.binary, 'printf "CodeSkeptic %s\\n" "$FIXTURE_VERSION"\n')
        self.executable(self.commands / "clang-20",
                        'case "$1" in -print-resource-dir) printf "%s\\n" "$FIXTURE_RESOURCE";; '
                        '--version) echo "Ubuntu clang version 20.1.2";; *) exit 2;; esac\n')
        self.executable(self.commands / "ldd", '''
case "${FIXTURE_LDD_MODE:-ok}" in
error) echo 'fixture ldd error' >&2; exit 7;;
missing) echo 'libLLVM.so.20.1 => not found'; exit 0;;
unknown) echo 'unexpected loader record'; exit 0;;
esac
lib="$FIXTURE_LIB"
stage="$(dirname "$1")/../lib/libLLVM.so.20.1"
if [ -f "$stage" ] && [ "${FIXTURE_LDD_MODE:-ok}" != fallback ]; then lib="$stage"; fi
printf 'libLLVM.so.20.1 => %s (0x1234)\\n' "$lib"
echo 'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x5678)'
echo '/lib64/ld-linux-x86-64.so.2 (0x9876)'
''')
        self.executable(self.commands / "readelf",
                        "echo ' 0x000000000000000f (RPATH) Library rpath: [$ORIGIN/../lib]'\n")
        self.executable(self.commands / "dpkg-query", '''
case "$1" in
-S) printf 'fixture: %s\\n' "$2";;
-L) printf '%s\\n' "$FIXTURE_LICENSE";;
-W) printf 'fixture\\t1.2.3\\n';;
*) exit 2;;
esac
''')
        self.out = self.root / "output dir"
        self.env = dict(os.environ, PATH=str(self.commands) + os.pathsep + os.environ["PATH"],
                        FIXTURE_VERSION=self.version, FIXTURE_RESOURCE=str(self.resources),
                        FIXTURE_LIB=str(self.lib), FIXTURE_LICENSE=str(self.license),
                        PYTHONDONTWRITEBYTECODE="1")
        self.name = f"codeskeptic-v{self.version}-linux-{platform.machine()}"

    @staticmethod
    def executable(path, body):
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)

    def run_package(self, **env):
        return subprocess.run(["bash", str(REPO / "scripts/package_release.sh"),
                               str(self.binary), str(self.out), str(self.commands / "clang-20")],
                              env=dict(self.env, **env), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)

    def failed(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stdout)
        self.assertNotIn("PACKAGE_RESULT", result.stdout)
        self.assertFalse(list(self.out.glob("*.tar.gz")))

    def test_full_development_identity_and_spaces(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stdout)
        archive = self.out / (self.name + ".tar.gz")
        self.assertTrue(archive.is_file(), result.stdout)
        self.assertTrue((self.out / self.name / "bin/codeskeptic").is_file())
        with tarfile.open(archive) as packed:
            self.assertIn(self.name + "/lib/clang/20/include/stddef.h", packed.getnames())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertIn(digest + "  " + archive.name, (self.out / "sha256sums.txt").read_text())

    def test_unresolved_dependency_fails(self):
        self.failed(self.run_package(FIXTURE_LDD_MODE="missing"), "not found")

    def test_ldd_command_failure_fails(self):
        self.failed(self.run_package(FIXTURE_LDD_MODE="error"), "ldd")

    def test_missing_library_fails(self):
        self.lib.unlink()
        self.failed(self.run_package(), "libLLVM")

    def test_missing_license_fails(self):
        self.license.unlink()
        self.failed(self.run_package(), "copyright")

    def test_mismatched_resource_major_fails(self):
        other = self.root / "clang/19"
        (other / "include").mkdir(parents=True)
        (other / "include/stddef.h").write_text("/* fixture */\n")
        self.failed(self.run_package(FIXTURE_RESOURCE=str(other)), "major")

    def test_existing_destination_preserved(self):
        # Old script truncated the version at '+': preserve both candidate names.
        for name in (self.name, self.name.replace("+g0123456789ab", "")):
            target = self.out / name
            target.mkdir(parents=True)
            (target / "sentinel").write_text("keep\n")
        result = self.run_package()
        for sentinel in self.out.glob("*/sentinel"):
            self.assertEqual(sentinel.read_text(), "keep\n")
        self.assertEqual(len(list(self.out.glob("*/sentinel"))), 2)
        self.failed(result, "exists")

    def test_unrecognized_ldd_line_fails(self):
        self.failed(self.run_package(FIXTURE_LDD_MODE="unknown"), "unknown ldd")

    def test_staged_library_must_not_fall_back_to_build_host(self):
        self.failed(self.run_package(FIXTURE_LDD_MODE="fallback"), "escaped staged package")

    def test_rpath_required(self):
        self.executable(self.commands / "readelf", "echo 'no RPATH'\n")
        self.failed(self.run_package(), "RPATH")

    def test_runpath_is_not_transitive_rpath(self):
        self.executable(self.commands / "readelf",
                        "echo ' (RUNPATH) Library runpath: [$ORIGIN/../lib]'\n")
        self.failed(self.run_package(), "RPATH")

    def test_resource_header_required(self):
        (self.resources / "include/stddef.h").unlink()
        self.failed(self.run_package(), "stddef.h")

    def test_non_codeskeptic_identity_rejected(self):
        self.executable(self.binary, "echo 'unrelated tool 0.4.9'\n")
        self.failed(self.run_package(), "identity")

    def test_unsafe_version_rejected(self):
        self.failed(self.run_package(FIXTURE_VERSION="0.4.9-dev/elsewhere"), "identity")

    def test_existing_archive_preserved(self):
        self.out.mkdir()
        archive = self.out / (self.name + ".tar.gz")
        archive.write_bytes(b"existing artifact")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exists", result.stdout)
        self.assertEqual(archive.read_bytes(), b"existing artifact")
        self.assertFalse((self.out / self.name).exists())

    def test_license_index_accounts_for_resources_and_shared_libraries(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stdout)
        licenses = self.out / self.name / "licenses"
        index = (licenses / "INDEX.tsv").read_text()
        self.assertIn("lib/clang/20/include\tfixture\t1.2.3\tlicenses/fixture/copyright", index)
        self.assertIn("lib/libLLVM.so.20.1\tfixture\t1.2.3\tlicenses/fixture/copyright", index)
        self.assertEqual((licenses / "fixture/copyright").read_bytes(), self.license.read_bytes())
        self.assertEqual(len(list(licenses.glob("*/copyright"))), 1)

    def test_unknown_package_owner_rejected(self):
        self.executable(self.commands / "dpkg-query", "exit 1\n")
        self.failed(self.run_package(), "owner/copyright")

    def test_missing_referenced_license_rejected(self):
        self.license.write_text("See /usr/share/common-licenses/CodeSkeptic-Missing-Fixture-License\n")
        self.failed(self.run_package(), "missing referenced common license")

    def test_second_package_never_replaces_first(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stdout)
        archive = self.out / (self.name + ".tar.gz")
        before = archive.read_bytes()
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exists", result.stdout)
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(len((self.out / "sha256sums.txt").read_text().splitlines()), 1)

    def test_checksum_symlink_does_not_modify_target(self):
        self.out.mkdir()
        protected = self.root / "keep me"
        protected.write_text("keep\n")
        (self.out / "sha256sums.txt").symlink_to(protected)
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PACKAGE_RESULT", result.stdout)
        self.assertEqual(protected.read_text(), "keep\n")

    def test_release_identity_is_not_rewritten(self):
        result = self.run_package(FIXTURE_VERSION="0.4.8")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue((self.out / f"codeskeptic-v0.4.8-linux-{platform.machine()}.tar.gz").is_file())


if __name__ == "__main__":
    unittest.main()
