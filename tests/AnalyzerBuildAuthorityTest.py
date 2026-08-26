#!/usr/bin/env python3
"""Hermetic contracts for the Phase 10 analyzer build authority."""

from __future__ import annotations

import copy
import io
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path, PureWindowsPath
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyzer_build_authority as authority  # noqa: E402
import run_determinism_qualification as determinism  # noqa: E402


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _run_git(repo: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments], cwd=repo, text=True
    ).strip()


def _commit_all(repo: Path, message: str) -> str:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Build Authority Test", "-c",
            "user.email=authority@example.invalid", "commit", "-m", message,
        ],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return _run_git(repo, "rev-parse", "HEAD")


def _initialize_source(path: Path) -> str:
    path.mkdir()
    for relative in authority.determinism.SOURCE_FILE_RELATIVES:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"fixture {relative}\n", encoding="utf-8", newline="\n")
    for relative in authority.determinism.SOURCE_DIRECTORY_RELATIVES:
        target = path / relative / "fixture.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"fixture {relative}\n", encoding="utf-8", newline="\n")
    retained_authority = path / "scripts" / "analyzer_build_authority.py"
    retained_authority.write_bytes(Path(authority.__file__).read_bytes())
    retained_authority.chmod(0o755)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=path, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Build Authority Test", "-c",
            "user.email=authority@example.invalid", "commit", "-m",
            "fixture source",
        ],
        cwd=path,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    revision = _run_git(path, "rev-parse", "HEAD")
    subprocess.run(
        ["git", "checkout", "--detach", revision],
        cwd=path,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return revision


def _fake_cmake_program(failure: str | None) -> str:
    failure_literal = repr(failure)
    return f'''#!/usr/bin/python3
import json
import sys
from pathlib import Path

FAILURE = {failure_literal}
args = sys.argv[1:]
tools = Path(__file__).resolve().parent
if args == ["--version"]:
    print("cmake version 4.0.3-fixture")
    raise SystemExit(0)
if "-S" in args and "-B" in args:
    print("fixture configure")
    if FAILURE == "configure":
        raise SystemExit(7)
    source = Path(args[args.index("-S") + 1]).resolve()
    build = Path(args[args.index("-B") + 1]).resolve()
    build.mkdir(parents=True, exist_ok=True)
    prefix_option = next(item for item in args if item.startswith("-DCMAKE_PREFIX_PATH="))
    prefix = prefix_option.split("=", 1)[1]
    entries = [
        f"CMAKE_COMMAND:INTERNAL={{Path(__file__).resolve()}}",
        f"CMAKE_MAKE_PROGRAM:FILEPATH={{tools / 'ninja'}}",
        f"CMAKE_C_COMPILER:FILEPATH={{tools / 'clang-20'}}",
        f"CMAKE_CXX_COMPILER:FILEPATH={{tools / 'clang++-20'}}",
        "CMAKE_GENERATOR:INTERNAL=Ninja",
        f"CMAKE_HOME_DIRECTORY:INTERNAL={{source}}",
        f"CMAKE_CACHEFILE_DIR:INTERNAL={{build}}",
        "CMAKE_BUILD_TYPE:STRING=Release",
        f"CMAKE_PREFIX_PATH:UNINITIALIZED={{prefix}}",
        "CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON",
        "CODESKEPTIC_BUILD_TESTS:BOOL=OFF",
        "CODESKEPTIC_BUILD_FUZZERS:BOOL=OFF",
        "CODESKEPTIC_SANITIZER:STRING=none",
    ]
    (build / "CMakeCache.txt").write_text("\\n".join(entries) + "\\n", encoding="utf-8")
    commands = [{{
        "directory": str(build),
        "command": f"{{tools / 'clang++-20'}} -c {{source / 'src' / 'fixture.txt'}}",
        "file": str(source / "src" / "fixture.txt"),
    }}]
    (build / "compile_commands.json").write_text(
        json.dumps(commands, indent=2, sort_keys=True) + "\\n", encoding="utf-8"
    )
    raise SystemExit(0)
if len(args) >= 2 and args[0] == "--build":
    print("fixture build")
    if FAILURE == "build":
        raise SystemExit(9)
    build = Path(args[1]).resolve()
    analyzer = build / "src" / "codeskeptic"
    analyzer.parent.mkdir(parents=True, exist_ok=True)
    analyzer.write_text(
        "#!/usr/bin/python3\\nprint('CodeSkeptic 0.4.9-dev')\\n",
        encoding="utf-8",
    )
    analyzer.chmod(0o755)
    raise SystemExit(0)
print("unsupported fake cmake invocation", file=sys.stderr)
raise SystemExit(11)
'''


def _initialize_tools(path: Path, failure: str | None = None) -> authority._ToolPaths:
    path.mkdir()
    _write_executable(path / "cmake", _fake_cmake_program(failure))
    for name, version in (
        ("ninja", "1.12.1-fixture"),
        ("clang-20", "clang version 20.1.8-fixture"),
        ("clang++-20", "clang version 20.1.8-fixture"),
    ):
        _write_executable(
            path / name,
            f"#!/usr/bin/python3\nprint({version!r})\n",
        )
    prefix = path / "llvm-20"
    (prefix / "bin").mkdir(parents=True)
    return authority._ToolPaths(
        cmake=path / "cmake",
        ninja=path / "ninja",
        c_compiler=path / "clang-20",
        cxx_compiler=path / "clang++-20",
        llvm_prefix=prefix,
    )


def _initialize_podman(path: Path, *, drift: bool = False) -> Path:
    image_id = "f" * 64 if drift else authority.PINNED_IMAGE_ID.removeprefix("sha256:")
    program = f'''#!/usr/bin/python3
import json
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("podman version 5.6.1-fixture")
    raise SystemExit(0)
if args[:2] == ["image", "inspect"]:
    print(json.dumps({{
        "Digest": {authority.PINNED_IMAGE_DIGEST!r},
        "Id": {image_id!r},
        "RepoDigests": [{authority.PINNED_IMAGE!r}],
    }}, sort_keys=True))
    raise SystemExit(0)
raise SystemExit(17)
'''
    _write_executable(path, program)
    return path


def _wait_for_process_absence(process_id: int) -> bool:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.01)
    return False


def _rewrite_manifest(root: Path) -> None:
    names = sorted(
        path.name for path in root.iterdir()
        if path.name != "SHA256SUMS" and path.is_file()
    )
    (root / "SHA256SUMS").write_bytes(b"".join(
        f"{authority.sha256_file(root / name)}  {name}\n".encode("utf-8")
        for name in names
    ))


def _write_receipt(root: Path, payload: dict) -> None:
    raw = authority.canonical_json(payload)
    (root / "receipt.json").write_bytes(raw)
    (root / "receipt.json.sha256").write_bytes(
        f"{authority.sha256_bytes(raw)}  receipt.json\n".encode("utf-8")
    )
    _rewrite_manifest(root)


def _recompute_nested_identities(payload: dict) -> None:
    payload["configuration"]["identity_sha256"] = authority.digest_json({
        key: value
        for key, value in payload["configuration"].items()
        if key not in {"schema", "identity_sha256"}
    })
    payload["toolchain"]["identity_sha256"] = authority.digest_json(
        payload["toolchain"]["tools"]
    )
    payload["build_identity_sha256"] = authority.digest_json(
        authority._build_identity_material(payload)
    )


class Fixture:
    def __init__(self, failure: str | None = None) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.revision = _initialize_source(self.source)
        self.tools = _initialize_tools(self.root / "tools", failure)
        self.podman = _initialize_podman(self.root / "podman")
        self.build = self.root / "build"
        self.output = self.root / "authority"

    def produce(self) -> dict:
        return authority._produce_with_tools(
            self.source,
            self.revision,
            self.build,
            self.output,
            self.tools,
        )

    def verify(self) -> dict:
        return authority._verify_inner_authority_with_tools(
            self.output, self.source, self.build, self.tools
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def __enter__(self) -> "Fixture":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class AnalyzerBuildAuthorityPortableTest(unittest.TestCase):
    def test_regular_reader_accepts_cross_api_ctime_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            payload = b"stable\n"
            path.write_bytes(payload)
            observed = path.stat()
            opened = mock.Mock(
                st_mode=observed.st_mode,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_nlink=observed.st_nlink,
                st_size=observed.st_size,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns + 1,
            )
            with mock.patch.object(
                authority.os,
                "fstat",
                side_effect=(opened, copy.copy(opened)),
            ):
                self.assertEqual(
                    authority._read_regular(path, 1024), payload
                )

    def test_regular_reader_rejects_final_path_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            path.write_bytes(b"stable\n")
            before = path.lstat()
            after = mock.Mock(
                st_mode=before.st_mode,
                st_dev=before.st_dev,
                st_ino=before.st_ino + 1,
                st_nlink=before.st_nlink,
                st_size=before.st_size,
                st_mtime_ns=before.st_mtime_ns,
                st_ctime_ns=before.st_ctime_ns,
            )
            with mock.patch.object(
                authority.os, "lstat", side_effect=(before, after)
            ), self.assertRaisesRegex(
                authority.BuildAuthorityError, "changed while reading"
            ):
                authority._read_regular(path, 1024)

    def test_module_and_recipe_contract_import_on_every_platform(self) -> None:
        self.assertEqual(
            authority.RECEIPT_SCHEMA,
            "codeskeptic-analyzer-build-authority-v1",
        )
        self.assertEqual(
            authority._normalized_recipe()["environment"][
                "CODESKEPTIC_VERSION_OVERRIDE"
            ],
            "0.4.9-dev",
        )
        self.assertEqual(
            authority._parser().parse_args([
                "verify", "--source", "source", "--build-dir", "build",
                "--authority", "authority",
            ]).command,
            "verify",
        )
        self.assertEqual(
            authority._parser().parse_args([
                "produce", "--source", "source", "--revision", "a" * 40,
                "--build-dir", "build", "--output", "authority",
            ]).container_layout,
            "legacy",
        )
        self.assertEqual(
            authority._parser().parse_args([
                "produce", "--source", "source", "--revision", "a" * 40,
                "--build-dir", "build", "--output", "authority",
                "--container-layout", "p10-09",
            ]).container_layout,
            "p10-09",
        )

    def test_production_explicitly_rejects_non_posix(self) -> None:
        with mock.patch.object(authority.os, "name", "nt"):
            with self.assertRaisesRegex(authority.BuildAuthorityError, "POSIX"):
                authority.produce_authority(
                    Path("source"),
                    "a" * 40,
                    Path("build"),
                    Path("authority"),
                )

    def test_retained_linux_podman_path_is_platform_neutral(self) -> None:
        runtime = {
            "schema": authority.RUNTIME_SCHEMA,
            "image": {
                "reference": authority.PINNED_IMAGE,
                "digest": authority.PINNED_IMAGE_DIGEST,
                "id": authority.PINNED_IMAGE_ID,
            },
            "podman": {
                "path": authority.PINNED_PODMAN_PATH,
                "sha256": "a" * 64,
                "version": "podman version fixture",
            },
            "normalized_argv": authority._normalized_container_argv("produce"),
        }
        runtime["normalized_argv_sha256"] = authority.digest_json(
            runtime["normalized_argv"]
        )

        self.assertEqual(
            authority._validate_runtime(runtime, authority.DEFAULT_PODMAN),
            runtime,
        )

    def test_retained_linux_tool_paths_are_platform_neutral(self) -> None:
        retained = "/usr/bin/cmake"
        self.assertFalse(PureWindowsPath(retained).is_absolute())
        self.assertTrue(authority._is_canonical_posix_absolute_path(retained))
        for malformed in (
            "usr/bin/cmake",
            "//usr/bin/cmake",
            "/usr/../bin/cmake",
            "/usr//bin/cmake",
            "/usr/bin/cmake\x00forged",
        ):
            with self.subTest(path=malformed):
                self.assertFalse(
                    authority._is_canonical_posix_absolute_path(malformed)
                )


@unittest.skipUnless(os.name == "posix", "hermetic producer fixture requires POSIX")
class AnalyzerBuildAuthorityTest(unittest.TestCase):
    def test_regular_reader_rejects_symlink_and_external_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_bytes(b"{}\n")
            symlink = root / "symlink.json"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "regular file"
            ):
                authority._read_regular(symlink, 1024)

            hardlink = root / "hardlink.json"
            os.link(target, hardlink)
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "external hard links"
            ):
                authority._read_regular(target, 1024)

    def test_regular_reader_rejects_mid_read_metadata_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            path.write_bytes(b"stable\n")
            observed = os.stat(path)
            before = mock.Mock(
                st_mode=observed.st_mode,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
                st_nlink=1,
                st_size=observed.st_size,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns,
            )
            after = copy.copy(before)
            after.st_size += 1
            with mock.patch.object(
                authority.os, "fstat", side_effect=(before, after)
            ):
                with self.assertRaisesRegex(
                    authority.BuildAuthorityError, "changed while reading"
                ):
                    authority._read_regular(path, 1024)

    def test_podman_host_environment_is_closed_and_used(self) -> None:
        hostile = {
            "CONTAINERS_CONF": "/tmp/hostile-containers.conf",
            "CONTAINERS_CONF_OVERRIDE": "/tmp/hostile-override.conf",
            "CONTAINERS_STORAGE_CONF": "/tmp/hostile-storage.conf",
            "HOME": "/tmp/hostile-home",
            "HTTP_PROXY": "http://hostile.invalid",
            "LD_PRELOAD": "/tmp/hostile.so",
            "PODMAN_CONNECTIONS_CONF": "/tmp/hostile-connections.json",
            "XDG_CONFIG_HOME": "/tmp/hostile-config",
        }
        with mock.patch.dict(os.environ, hostile):
            environment = authority._podman_environment()
        self.assertEqual(environment["CONTAINERS_CONF"], os.devnull)
        self.assertEqual(environment["CONTAINERS_CONF_OVERRIDE"], os.devnull)
        self.assertEqual(
            environment["XDG_CONFIG_HOME"], str(authority.PODMAN_CONFIG_ROOT)
        )
        self.assertNotEqual(environment["HOME"], hostile["HOME"])
        for rejected in (
            "CONTAINERS_STORAGE_CONF",
            "HTTP_PROXY",
            "LD_PRELOAD",
            "PODMAN_CONNECTIONS_CONF",
        ):
            self.assertNotIn(rejected, environment)

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "operator.log"

            def completed(*_args: object, **kwargs: object) -> subprocess.CompletedProcess:
                kwargs["stdout"].write(b"closed environment used\n")
                self.assertEqual(kwargs["env"], authority._podman_environment())
                return subprocess.CompletedProcess([], 0)

            with mock.patch.object(authority.subprocess, "run", side_effect=completed):
                authority._execute_container(["/usr/bin/podman", "run"], log)

    @unittest.skipUnless(os.name == "posix", "process-group contract is POSIX-only")
    def test_runtime_identity_timeout_reaps_the_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process_id = root / "probe.pid"
            podman = root / "podman"
            _write_executable(
                podman,
                "#!/usr/bin/python3\n"
                "import os\n"
                "import time\n"
                "from pathlib import Path\n"
                f"Path({str(process_id)!r}).write_text(str(os.getpid()))\n"
                "time.sleep(60)\n",
            )
            with (
                mock.patch.object(
                    authority, "RUNTIME_IDENTITY_TIMEOUT_SECONDS", 0.05
                ),
                self.assertRaisesRegex(
                    authority.BuildAuthorityError, "Podman identity timed out"
                ),
            ):
                authority._runtime_authority(podman)
            self.assertTrue(process_id.is_file())
            self.assertTrue(
                _wait_for_process_absence(int(process_id.read_text()))
            )

    @unittest.skipUnless(os.name == "posix", "process-group contract is POSIX-only")
    def test_runtime_image_inspect_timeout_reaps_the_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process_id = root / "probe.pid"
            podman = root / "podman"
            _write_executable(
                podman,
                "#!/usr/bin/python3\n"
                "import os\n"
                "import sys\n"
                "import time\n"
                "from pathlib import Path\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    print('podman version timeout-fixture')\n"
                "    raise SystemExit(0)\n"
                f"Path({str(process_id)!r}).write_text(str(os.getpid()))\n"
                "time.sleep(60)\n",
            )
            with (
                mock.patch.object(
                    authority, "RUNTIME_IDENTITY_TIMEOUT_SECONDS", 0.05
                ),
                self.assertRaisesRegex(
                    authority.BuildAuthorityError,
                    "pinned image inspect timed out",
                ),
            ):
                authority._runtime_authority(podman)
            self.assertTrue(process_id.is_file())
            self.assertTrue(
                _wait_for_process_absence(int(process_id.read_text()))
            )

    @unittest.skipUnless(os.name == "posix", "process-group contract is POSIX-only")
    def test_runtime_identity_interruption_reaps_the_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process_id = root / "probe.pid"
            probe = root / "probe"
            _write_executable(
                probe,
                "#!/usr/bin/python3\n"
                "import os\n"
                "import time\n"
                "from pathlib import Path\n"
                f"Path({str(process_id)!r}).write_text(str(os.getpid()))\n"
                "time.sleep(60)\n",
            )

            def interrupt_after_start(
                _selector: selectors.BaseSelector, _timeout: float,
            ) -> list[tuple[selectors.SelectorKey, int]]:
                deadline = time.monotonic() + 1.0
                while not process_id.is_file() and time.monotonic() < deadline:
                    time.sleep(0.005)
                raise KeyboardInterrupt

            with (
                mock.patch.object(
                    authority.selectors.DefaultSelector,
                    "select",
                    autospec=True,
                    side_effect=interrupt_after_start,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                authority._run_bounded_runtime_identity(
                    [str(probe)],
                    {"PATH": "/usr/bin:/bin"},
                    "interrupt probe",
                    stdout_limit=1024,
                    stderr_limit=1024,
                    timeout_seconds=2.0,
                )
            self.assertTrue(process_id.is_file())
            self.assertTrue(
                _wait_for_process_absence(int(process_id.read_text()))
            )

    def test_runtime_identity_closes_stdin_and_does_not_inherit_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / "probe"
            _write_executable(
                probe,
                "#!/usr/bin/python3\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "print(json.dumps({\n"
                "    'expected': os.environ.get('EXPECTED'),\n"
                "    'hostile': os.environ.get('HOSTILE_RUNTIME_PROBE'),\n"
                "    'stdin': sys.stdin.read(),\n"
                "}, sort_keys=True))\n",
            )
            with mock.patch.dict(
                os.environ, {"HOSTILE_RUNTIME_PROBE": "inherited"}
            ):
                completed = authority._run_bounded_runtime_identity(
                    [str(probe)],
                    {"EXPECTED": "closed", "PATH": "/usr/bin:/bin"},
                    "closed probe",
                    stdout_limit=1024,
                    stderr_limit=1024,
                    timeout_seconds=2.0,
                )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(
                json.loads(completed.stdout),
                {"expected": "closed", "hostile": None, "stdin": ""},
            )
            self.assertEqual(completed.stderr, b"")

    def test_runtime_image_inspect_output_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            podman = Path(directory) / "podman"
            _write_executable(
                podman,
                "#!/usr/bin/python3\n"
                "import sys\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    print('podman version bounded-fixture')\n"
                "else:\n"
                "    print('x' * 2048)\n",
            )
            with (
                mock.patch.object(authority, "MAX_JSON_BYTES", 1024),
                self.assertRaisesRegex(
                    authority.BuildAuthorityError,
                    "pinned image inspect output exceeds size limit",
                ),
            ):
                authority._runtime_authority(podman)

    def test_runtime_version_output_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            podman = Path(directory) / "podman"
            _write_executable(
                podman,
                "#!/usr/bin/python3\n"
                "print('x' * 2048)\n",
            )
            with (
                mock.patch.object(authority, "RUNTIME_VERSION_MAX_BYTES", 1024),
                self.assertRaisesRegex(
                    authority.BuildAuthorityError,
                    "Podman identity output exceeds size limit",
                ),
            ):
                authority._runtime_authority(podman)

    def test_runtime_tripwire_pins_digest_id_podman_and_normalized_argv(self) -> None:
        with Fixture() as fixture:
            runtime = authority._runtime_authority(fixture.podman)
            self.assertEqual(runtime["image"]["reference"], authority.PINNED_IMAGE)
            self.assertEqual(runtime["image"]["digest"], authority.PINNED_IMAGE_DIGEST)
            self.assertEqual(runtime["image"]["id"], authority.PINNED_IMAGE_ID)
            self.assertEqual(
                runtime["normalized_argv"],
                authority._normalized_container_argv("produce"),
            )
            self.assertEqual(
                runtime["normalized_argv_sha256"],
                authority.digest_json(runtime["normalized_argv"]),
            )
            drifted = _initialize_podman(fixture.root / "podman-drift", drift=True)
            with self.assertRaisesRegex(authority.BuildAuthorityError, "digest|ID"):
                authority._runtime_authority(drifted)

    def test_p10_09_layout_is_exact_and_hybrids_fail_closed(self) -> None:
        with Fixture() as fixture:
            runtime = authority._runtime_authority(
                fixture.podman, container_layout="p10-09"
            )
            normalized = runtime["normalized_argv"]
            self.assertEqual(
                normalized,
                authority._normalized_container_argv("produce", "p10-09"),
            )
            self.assertIn("$SOURCE:/authority/source:ro", normalized)
            self.assertIn("$BUILD:/authority/build:rw", normalized)
            self.assertIn(
                "$STAGE:/authority/build-authority:rw", normalized
            )
            self.assertNotIn("$SOURCE:/source:ro", normalized)
            self.assertEqual(
                authority._container_layout_from_runtime(runtime), "p10-09"
            )

            hybrid = copy.deepcopy(runtime)
            index = hybrid["normalized_argv"].index(
                "$BUILD:/authority/build:rw"
            )
            hybrid["normalized_argv"][index] = "$BUILD:/build:rw"
            hybrid["normalized_argv_sha256"] = authority.digest_json(
                hybrid["normalized_argv"]
            )
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "layout|normalized Podman argv"
            ):
                authority._validate_runtime(hybrid, fixture.podman)

            verify_command = authority._container_command(
                "verify",
                fixture.podman,
                fixture.source,
                fixture.build,
                fixture.output,
                container_layout="p10-09",
            )
            self.assertIn(
                f"{fixture.source}:/authority/source:ro", verify_command
            )
            self.assertIn(
                f"{fixture.build}:/authority/build:ro", verify_command
            )
            self.assertIn(
                f"{fixture.output}:/authority/build-authority:ro",
                verify_command,
            )
            self.assertIn("--source", verify_command)
            self.assertIn("/authority/source", verify_command)
            self.assertIn("--build-dir", verify_command)
            self.assertIn("/authority/build", verify_command)
            self.assertIn("--authority", verify_command)
            self.assertIn("/authority/build-authority", verify_command)

    def test_public_p10_09_verifier_infers_layout_from_receipt(self) -> None:
        with Fixture() as fixture:
            commands: list[list[str]] = []

            def mounted(command: list[str], suffix: str) -> Path:
                for index, item in enumerate(command[:-1]):
                    if item == "-v" and command[index + 1].endswith(suffix):
                        return Path(command[index + 1].split(":", 1)[0])
                raise AssertionError(f"missing mount {suffix}")

            def execute(command: list[str], log: Path) -> None:
                commands.append(list(command))
                if "_inner-produce" in command:
                    stage = mounted(
                        command, ":/authority/build-authority:rw"
                    )
                    observation = authority._produce_with_tools(
                        fixture.source,
                        fixture.revision,
                        fixture.build,
                        stage / "inner",
                        fixture.tools,
                    )
                    log.write_bytes(authority._expected_operator_log(
                        observation["build_identity_sha256"], "p10-09"
                    ))
                elif "_inner-verify" in command:
                    retained = mounted(
                        command, ":/authority/build-authority:ro"
                    )
                    authority.verify_authority_with_tools(
                        retained,
                        fixture.source,
                        fixture.build,
                        fixture.tools,
                        podman=fixture.podman,
                    )
                    log.write_text(
                        "simulated inner verification\n", encoding="utf-8"
                    )
                else:
                    raise AssertionError("unexpected container command")

            with mock.patch.object(
                authority, "_execute_container", side_effect=execute
            ):
                receipt = authority.produce_authority(
                    fixture.source,
                    fixture.revision,
                    fixture.build,
                    fixture.output,
                    podman=fixture.podman,
                    container_layout="p10-09",
                )
            self.assertEqual(
                authority._container_layout_from_runtime(receipt["runtime"]),
                "p10-09",
            )
            self.assertEqual(len(commands), 2)

            commands.clear()
            with mock.patch.object(
                authority, "_execute_container", side_effect=execute
            ):
                verified = authority.verify_authority(
                    fixture.output,
                    fixture.source,
                    fixture.build,
                    podman=fixture.podman,
                )
            self.assertEqual(verified, receipt)
            self.assertEqual(len(commands), 1)
            self.assertIn(
                f"{fixture.output}:/authority/build-authority:ro",
                commands[0],
            )

    def test_launch_token_and_actual_podman_argv_are_exact_expansions(self) -> None:
        with Fixture() as fixture:
            runtime = authority._runtime_authority(fixture.podman)
            raw = authority._launch_authority(runtime)
            launch = fixture.root / "launch.json"
            launch.write_bytes(raw)
            token = authority.sha256_bytes(raw)
            with mock.patch.object(
                authority, "DEFAULT_PODMAN", fixture.podman
            ), mock.patch.dict(os.environ, {authority.INNER_TOKEN_ENV: token}):
                retained = authority._validate_launch_authority(launch)
            self.assertEqual(retained["runtime"], runtime)
            with mock.patch.dict(os.environ, {authority.INNER_TOKEN_ENV: "f" * 64}):
                with self.assertRaisesRegex(authority.BuildAuthorityError, "token"):
                    authority._validate_launch_authority(launch)

            stage = fixture.root / "stage"
            stage.mkdir()
            command = authority._container_command(
                "produce",
                fixture.podman,
                fixture.source,
                fixture.build,
                stage,
                revision=fixture.revision,
                launch_sha256=token,
                runtime=runtime,
            )
            self.assertNotIn("$", "".join(command))
            self.assertIn("--pull=never", command)
            self.assertIn("--network=none", command)
            self.assertIn("--read-only", command)
            self.assertIn("--cgroup-manager=cgroupfs", command)
            self.assertIn("--conmon=/usr/bin/conmon", command)
            self.assertIn("--events-backend=none", command)
            self.assertIn("--hooks-dir=/usr/share/empty", command)
            self.assertIn("--runtime=/usr/bin/crun", command)
            self.assertIn("--http-proxy=false", command)
            self.assertIn("--env-host=false", command)
            self.assertIn("--image-volume=ignore", command)
            self.assertNotIn("--userns=keep-id", command)
            self.assertIn("--cap-drop=all", command)
            self.assertIn("no-new-privileges", command)
            self.assertIn("PYTHONDONTWRITEBYTECODE=1", command)
            self.assertIn(f"{fixture.source}:/source:ro", command)
            self.assertIn(f"{fixture.build}:/build:rw", command)
            self.assertIn(f"{stage}:/authority-stage:rw", command)
            self.assertEqual(command[-11], "_inner-produce")
            self.assertEqual(
                command[-2:],
                ["--launch-authority", "/authority-stage/launch-authority.json"],
            )

            verify_command = authority._container_command(
                "verify",
                fixture.podman,
                fixture.source,
                fixture.build,
                fixture.output,
            )
            self.assertIn(f"{fixture.build}:/build:ro", verify_command)
            self.assertIn(f"{fixture.output}:/authority:ro", verify_command)
            self.assertEqual(verify_command[-7], "_inner-verify")

    def test_public_outer_producer_only_promotes_after_inner_verification(self) -> None:
        with Fixture() as fixture:
            commands: list[list[str]] = []

            def mounted(command: list[str], suffix: str) -> Path:
                for index, item in enumerate(command[:-1]):
                    if item == "-v" and command[index + 1].endswith(suffix):
                        return Path(command[index + 1].split(":", 1)[0])
                raise AssertionError(f"missing mount {suffix}")

            def execute(command: list[str], log: Path) -> None:
                commands.append(list(command))
                if "_inner-produce" in command:
                    stage = mounted(command, ":/authority-stage:rw")
                    observation = authority._produce_with_tools(
                        fixture.source,
                        fixture.revision,
                        fixture.build,
                        stage / "inner",
                        fixture.tools,
                    )
                    log.write_bytes(authority._expected_operator_log(
                        observation["build_identity_sha256"]
                    ))
                elif "_inner-verify" in command:
                    retained = mounted(command, ":/authority:ro")
                    authority.verify_authority_with_tools(
                        retained,
                        fixture.source,
                        fixture.build,
                        fixture.tools,
                        podman=fixture.podman,
                    )
                    log.write_text("simulated inner verification\n", encoding="utf-8")
                else:
                    raise AssertionError("unexpected container command")

            with mock.patch.object(authority, "_execute_container", side_effect=execute):
                receipt = authority.produce_authority(
                    fixture.source,
                    fixture.revision,
                    fixture.build,
                    fixture.output,
                    podman=fixture.podman,
                )
            self.assertEqual(receipt["schema"], authority.RECEIPT_SCHEMA)
            self.assertEqual(receipt["status"], "accepted")
            self.assertEqual(receipt["runtime"], authority._runtime_authority(fixture.podman))
            self.assertEqual(
                sorted(path.name for path in fixture.output.iterdir()),
                sorted(authority.AUTHORITY_FILES),
            )
            self.assertEqual(
                (fixture.output / "operator.log").read_text(encoding="utf-8"),
                authority._expected_operator_log(
                    authority._inner_build_identity_from_final(receipt)
                ).decode("utf-8"),
            )
            self.assertEqual(len(commands), 2)
            self.assertIn("_inner-produce", commands[0])
            self.assertIn("_inner-verify", commands[1])

            commands.clear()
            with mock.patch.object(authority, "_execute_container", side_effect=execute):
                verified = authority.verify_authority(
                    fixture.output,
                    fixture.source,
                    fixture.build,
                    podman=fixture.podman,
                )
            self.assertEqual(verified, receipt)
            self.assertEqual(len(commands), 1)
            self.assertIn("_inner-verify", commands[0])

    def test_public_container_failure_leaves_no_accepted_receipt(self) -> None:
        with Fixture() as fixture, mock.patch.object(
            authority,
            "_execute_container",
            side_effect=authority.BuildAuthorityError("container exit 7"),
        ):
            with self.assertRaisesRegex(authority.BuildAuthorityError, "exit 7"):
                authority.produce_authority(
                    fixture.source,
                    fixture.revision,
                    fixture.build,
                    fixture.output,
                    podman=fixture.podman,
                )
            self.assertEqual(list(fixture.output.iterdir()), [])
            self.assertFalse((fixture.output / "receipt.json").exists())

    def test_final_runtime_and_operator_log_are_sealed_and_rederived(self) -> None:
        with Fixture() as fixture:
            fixture.produce()
            runtime = authority._runtime_authority(fixture.podman)
            operator = fixture.root / "podman.log"
            observation = json.loads(
                (fixture.output / "receipt.json").read_text(encoding="utf-8")
            )
            operator.write_bytes(authority._expected_operator_log(
                observation["build_identity_sha256"]
            ))
            final = fixture.root / "final"
            receipt = authority._finalize_outer_bundle(
                fixture.output,
                final,
                operator,
                runtime,
                fixture.podman,
            )
            self.assertEqual(receipt["status"], "accepted")
            authority.verify_authority_with_tools(
                final,
                fixture.source,
                fixture.build,
                fixture.tools,
                podman=fixture.podman,
            )

            payload = json.loads(
                (final / "receipt.json").read_text(encoding="utf-8")
            )
            payload["runtime"]["image"]["id"] = "sha256:" + "f" * 64
            _recompute_nested_identities(payload)
            _write_receipt(final, payload)
            with self.assertRaisesRegex(authority.BuildAuthorityError, "runtime image"):
                authority.verify_authority_with_tools(
                    final,
                    fixture.source,
                    fixture.build,
                    fixture.tools,
                    podman=fixture.podman,
                )

        with Fixture() as fixture:
            fixture.produce()
            runtime = authority._runtime_authority(fixture.podman)
            observation = json.loads(
                (fixture.output / "receipt.json").read_text(encoding="utf-8")
            )
            operator = fixture.root / "podman.log"
            operator.write_bytes(authority._expected_operator_log(
                observation["build_identity_sha256"]
            ))
            final = fixture.root / "final"
            authority._finalize_outer_bundle(
                fixture.output, final, operator, runtime, fixture.podman
            )
            raw = (final / "operator.log").read_bytes() + b"resigned tamper\n"
            (final / "operator.log").write_bytes(raw)
            payload = json.loads(
                (final / "receipt.json").read_text(encoding="utf-8")
            )
            payload["logs"]["operator.log"].update({
                "sha256": authority.sha256_bytes(raw),
                "size": len(raw),
            })
            _recompute_nested_identities(payload)
            _write_receipt(final, payload)
            with self.assertRaisesRegex(authority.BuildAuthorityError, "operator.log"):
                authority.verify_authority_with_tools(
                    final,
                    fixture.source,
                    fixture.build,
                    fixture.tools,
                    podman=fixture.podman,
                )

    def test_tool_identity_accepts_symlinked_compiler_executables(self) -> None:
        with Fixture() as fixture:
            for compiler in (
                fixture.tools.c_compiler,
                fixture.tools.cxx_compiler,
            ):
                target = compiler.with_name(f"{compiler.name}-real")
                compiler.rename(target)
                compiler.symlink_to(target.name)
            identity = authority._toolchain_identity(fixture.tools)
            self.assertEqual(
                identity["tools"]["c_compiler"]["path"],
                str(fixture.tools.c_compiler),
            )
            self.assertEqual(
                identity["tools"]["c_compiler"]["sha256"],
                authority.sha256_file(fixture.tools.c_compiler),
            )

    def test_in_runtime_verifier_has_no_caller_selectable_tools(self) -> None:
        with mock.patch.object(
            authority, "verify_authority_with_tools", return_value={"status": "accepted"}
        ) as verifier:
            result = authority.verify_authority_in_current_runtime(
                Path("/authority"), Path("/source"), Path("/build")
            )
        self.assertEqual(result, {"status": "accepted"})
        verifier.assert_called_once_with(
            Path("/authority"),
            Path("/source"),
            Path("/build"),
            authority.DEFAULT_TOOLS,
            podman=authority.DEFAULT_PODMAN,
        )

    def test_public_authority_requires_self_contained_git_checkout(self) -> None:
        with Fixture() as fixture:
            linked = fixture.root / "linked-source"
            subprocess.run(
                [
                    "git", "worktree", "add", "--detach", str(linked),
                    fixture.revision,
                ],
                cwd=fixture.source,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertTrue((linked / ".git").is_file())
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "self-contained Git checkout"
            ):
                authority._outer_source_identity(
                    linked, fixture.revision, producer=True
                )

        with Fixture() as fixture:
            alternates = fixture.source / ".git" / "objects" / "info" / "alternates"
            alternates.parent.mkdir(parents=True, exist_ok=True)
            alternates.write_text("/external/objects\n", encoding="utf-8")
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "object alternates"
            ):
                authority._outer_source_identity(
                    fixture.source, fixture.revision, producer=True
                )

        with Fixture() as fixture:
            external = fixture.root / "external-source.txt"
            external.write_text("external\n", encoding="utf-8")
            (fixture.source / "src" / "external-link").symlink_to(external)
            revision = _commit_all(fixture.source, "tracked source symlink")
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "unsupported Git tree entry"
            ):
                authority._outer_source_identity(
                    fixture.source, revision, producer=True
                )

        with Fixture() as fixture:
            tracked = fixture.source / "scripts" / "analyzer_build_authority.py"
            os.link(tracked, fixture.root / "external-source-alias.py")
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "tracked source has external hard links"
            ):
                authority._outer_source_identity(
                    fixture.source, fixture.revision, producer=True
                )

        with Fixture() as fixture:
            grafts = fixture.source / ".git" / "info" / "grafts"
            grafts.parent.mkdir(parents=True, exist_ok=True)
            grafts.write_text(
                f"{fixture.revision} {fixture.revision}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "legacy graft authority"
            ):
                authority._outer_source_identity(
                    fixture.source, fixture.revision, producer=True
                )

        with Fixture() as fixture:
            subprocess.run(
                [
                    "git", "config", "--local", "filter.evil.clean",
                    "/tmp/evil-filter",
                ],
                cwd=fixture.source,
                check=True,
            )
            with self.assertRaisesRegex(
                authority.BuildAuthorityError, "Git config has external authority"
            ):
                authority._outer_source_identity(
                    fixture.source, fixture.revision, producer=True
                )

        for key, value in (
            ("core.hooksPath", "/tmp/external-hooks"),
            ("includeIf.gitdir:/tmp/.path", "/tmp/external-config"),
        ):
            with self.subTest(config=key), Fixture() as fixture:
                subprocess.run(
                    ["git", "config", "--local", key, value],
                    cwd=fixture.source,
                    check=True,
                )
                with self.assertRaisesRegex(
                    authority.BuildAuthorityError,
                    "Git config has external authority",
                ):
                    authority._outer_source_identity(
                        fixture.source, fixture.revision, producer=True
                    )

    def test_source_authority_ignores_git_replace_refs(self) -> None:
        with Fixture() as fixture:
            original = fixture.revision
            target = fixture.source / "src" / "fixture.txt"
            target.write_text("replacement bytes\n", encoding="utf-8")
            replacement = _commit_all(fixture.source, "replacement source")
            subprocess.run(
                ["git", "replace", original, replacement],
                cwd=fixture.source,
                check=True,
            )
            subprocess.run(
                ["git", "checkout", "--detach", original],
                cwd=fixture.source,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "reset", "--hard", original],
                cwd=fixture.source,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "replacement bytes\n")
            with self.assertRaises(authority.BuildAuthorityError):
                authority._source_identity(fixture.source, original)

    def test_source_authority_drops_inherited_git_config_parameters(self) -> None:
        with Fixture() as fixture:
            marker = fixture.root / "fsmonitor-ran"
            hook = fixture.root / "fsmonitor-hook"
            _write_executable(
                hook,
                "#!/bin/sh\n"
                f"touch {marker}\n"
                "printf '0\\n'\n",
            )
            injected = f"'core.fsmonitor={hook}'"
            with mock.patch.dict(
                os.environ, {"GIT_CONFIG_PARAMETERS": injected}, clear=False
            ):
                closed = determinism._git_authority_environment(fixture.source)
                self.assertNotIn("GIT_CONFIG_PARAMETERS", closed)
                authority._source_identity(fixture.source, fixture.revision)
            self.assertFalse(marker.exists())

    def test_pinned_recipe_is_exact_and_workspace_independent(self) -> None:
        self.assertEqual(
            authority.PINNED_IMAGE,
            "localhost/codeskeptic-p10-07-evidence@sha256:"
            "3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca",
        )
        recipe = authority._normalized_recipe()
        self.assertEqual(
            recipe["build"][-4:],
            ["--target", "codeskeptic", "--parallel", "2"],
        )
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", recipe["configure"])
        self.assertIn("-DCODESKEPTIC_BUILD_TESTS=OFF", recipe["configure"])
        self.assertIn("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", recipe["configure"])
        self.assertEqual(
            recipe["environment"]["CODESKEPTIC_VERSION_OVERRIDE"], "0.4.9-dev"
        )
        self.assertNotIn(str(ROOT), authority.canonical_json(recipe).decode())

    def test_produce_and_rederive_complete_authority(self) -> None:
        with Fixture() as fixture:
            produced = fixture.produce()
            verified = fixture.verify()
            self.assertEqual(produced, verified)
            self.assertEqual(produced["status"], "observed")
            self.assertEqual(produced["schema"], authority.INNER_RECEIPT_SCHEMA)
            self.assertEqual(produced["source"]["revision"], fixture.revision)
            self.assertEqual(produced["analyzer"]["version"], "CodeSkeptic 0.4.9-dev")
            self.assertRegex(produced["build_identity_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                sorted(path.name for path in fixture.output.iterdir()),
                sorted(authority.INNER_AUTHORITY_FILES),
            )
            receipt_raw = (fixture.output / "receipt.json").read_bytes()
            self.assertEqual(
                receipt_raw,
                authority.canonical_json(json.loads(receipt_raw.decode("utf-8"))),
            )
            self.assertEqual(
                (fixture.output / "SHA256SUMS").read_bytes(),
                b"".join(
                    f"{authority.sha256_file(fixture.output / name)}  {name}\n".encode()
                    for name in sorted(
                        set(authority.INNER_AUTHORITY_FILES) - {"SHA256SUMS"}
                    )
                ),
            )

    def test_source_must_be_clean_exact_head_and_repository_root(self) -> None:
        with Fixture() as fixture:
            dirty = fixture.source / "src" / "dirty.cpp"
            dirty.write_text("int dirty;\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "dirty"):
                fixture.produce()
            self.assertFalse((fixture.output / "receipt.json").exists())

        with Fixture() as fixture:
            other = fixture.source / "src" / "fixture.txt"
            other.write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=fixture.source, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Build Authority Test", "-c",
                    "user.email=authority@example.invalid", "commit", "-m",
                    "later",
                ], cwd=fixture.source, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            with self.assertRaisesRegex(authority.BuildAuthorityError, "exact revision"):
                fixture.produce()

        with Fixture() as fixture:
            with self.assertRaisesRegex(
                authority.BuildAuthorityError,
                "self-contained Git checkout|repository root",
            ):
                authority._produce_with_tools(
                    fixture.source / "src",
                    fixture.revision,
                    fixture.build,
                    fixture.output,
                    fixture.tools,
                )

    def test_dedicated_build_and_output_must_be_empty_and_external(self) -> None:
        with Fixture() as fixture:
            fixture.build.mkdir()
            (fixture.build / "reused.txt").write_text("state\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "must be empty"):
                fixture.produce()

        with Fixture() as fixture:
            fixture.output.mkdir()
            (fixture.output / "receipt.json").write_text("forged\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "must be empty"):
                fixture.produce()

        with Fixture() as fixture:
            with self.assertRaisesRegex(authority.BuildAuthorityError, "outside"):
                authority._produce_with_tools(
                    fixture.source,
                    fixture.revision,
                    fixture.source / "build",
                    fixture.output,
                    fixture.tools,
                )

    def test_failed_configure_or_build_never_writes_accepted_receipt(self) -> None:
        for stage, exit_code in (("configure", "7"), ("build", "9")):
            with self.subTest(stage=stage), Fixture(stage) as fixture:
                with self.assertRaisesRegex(
                    authority.BuildAuthorityError, f"exit {exit_code}"
                ):
                    fixture.produce()
                self.assertFalse((fixture.output / "receipt.json").exists())
                self.assertEqual(list(fixture.output.iterdir()), [])

    def test_verify_rejects_missing_authority_and_nonregular_or_extra_files(self) -> None:
        with Fixture() as fixture:
            with self.assertRaisesRegex(authority.BuildAuthorityError, "missing"):
                fixture.verify()
            fixture.produce()
            (fixture.output / "extra").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "file set"):
                fixture.verify()
            (fixture.output / "extra").unlink()
            (fixture.output / "nested").mkdir()
            with self.assertRaisesRegex(authority.BuildAuthorityError, "non-regular"):
                fixture.verify()

    def test_receipt_and_sidecar_and_manifest_tampering_is_rejected(self) -> None:
        with Fixture() as fixture:
            fixture.produce()
            sidecar = fixture.output / "receipt.json.sha256"
            original_sidecar = sidecar.read_bytes()
            sidecar.write_bytes(b"0" * len(original_sidecar))
            with self.assertRaisesRegex(authority.BuildAuthorityError, "sidecar"):
                fixture.verify()
            sidecar.write_bytes(original_sidecar)

            receipt = fixture.output / "receipt.json"
            original_receipt = receipt.read_bytes()
            receipt.write_bytes(original_receipt + b" ")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "sidecar"):
                fixture.verify()
            receipt.write_bytes(original_receipt)
            sidecar.write_bytes(original_sidecar)

            manifest = fixture.output / "SHA256SUMS"
            manifest.write_bytes(manifest.read_bytes() + b"0" * 64 + b"  extra\n")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "SHA256SUMS"):
                fixture.verify()

    def test_resigned_schema_status_image_recipe_and_digest_forgery_is_rejected(self) -> None:
        mutations = {
            "schema": lambda payload: payload.__setitem__("schema", "future"),
            "status": lambda payload: payload.__setitem__("status", "rejected"),
            "image": lambda payload: payload.__setitem__(
                "image", authority.PINNED_IMAGE[:-1] + "0"
            ),
            "recipe": lambda payload: payload["recipe"]["configure"].append("-DFORGED=ON"),
            "build identity": lambda payload: payload.__setitem__(
                "build_identity_sha256", "f" * 64
            ),
        }
        for expected, mutate in mutations.items():
            with self.subTest(expected=expected), Fixture() as fixture:
                fixture.produce()
                payload = json.loads(
                    (fixture.output / "receipt.json").read_text(encoding="utf-8")
                )
                mutate(payload)
                _write_receipt(fixture.output, payload)
                with self.assertRaisesRegex(authority.BuildAuthorityError, expected):
                    fixture.verify()

    def test_forged_nested_identities_cannot_replace_external_authority(self) -> None:
        cases = {
            "source": lambda payload: payload["source"].__setitem__(
                "manifest_sha256", "f" * 64
            ),
            "toolchain": lambda payload: payload["toolchain"]["tools"][
                "c_compiler"
            ].__setitem__("sha256", "f" * 64),
            "configuration": lambda payload: payload["configuration"].__setitem__(
                "cmake_cache_sha256", "f" * 64
            ),
            "analyzer": lambda payload: payload["analyzer"].__setitem__(
                "sha256", "f" * 64
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), Fixture() as fixture:
                fixture.produce()
                payload = json.loads(
                    (fixture.output / "receipt.json").read_text(encoding="utf-8")
                )
                mutate(payload)
                _recompute_nested_identities(payload)
                _write_receipt(fixture.output, payload)
                with self.assertRaises(authority.BuildAuthorityError):
                    fixture.verify()

    def test_log_cache_analyzer_and_tool_drift_are_rederived(self) -> None:
        with Fixture() as fixture:
            fixture.produce()
            log = fixture.output / "build.log"
            log.write_bytes(log.read_bytes() + b"tampered\n")
            _rewrite_manifest(fixture.output)
            with self.assertRaisesRegex(authority.BuildAuthorityError, "build.log"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            log = fixture.output / "build.log"
            raw = log.read_bytes() + b"resigned tamper\n"
            log.write_bytes(raw)
            payload = json.loads(
                (fixture.output / "receipt.json").read_text(encoding="utf-8")
            )
            payload["logs"]["build.log"].update({
                "sha256": authority.sha256_bytes(raw),
                "size": len(raw),
            })
            _recompute_nested_identities(payload)
            _write_receipt(fixture.output, payload)
            with self.assertRaisesRegex(authority.BuildAuthorityError, "producer"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            cache = fixture.build / "CMakeCache.txt"
            cache.write_text(
                cache.read_text(encoding="utf-8").replace(
                    "CMAKE_BUILD_TYPE:STRING=Release",
                    "CMAKE_BUILD_TYPE:STRING=Debug",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(authority.BuildAuthorityError, "CMAKE_BUILD_TYPE"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            analyzer = fixture.build / authority.ANALYZER_RELATIVE
            analyzer.write_bytes(analyzer.read_bytes() + b"# binary drift\n")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "analyzer differs"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            compiler = fixture.tools.c_compiler
            compiler.write_bytes(compiler.read_bytes() + b"# compiler drift\n")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "toolchain differs"):
                fixture.verify()

    def test_source_drift_after_build_is_rejected_during_verification(self) -> None:
        with Fixture() as fixture:
            fixture.produce()
            source = fixture.source / "src" / "fixture.txt"
            source.write_text("changed after authority\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "dirty"):
                fixture.verify()

    def test_verify_allows_only_clean_source_equivalent_descendants(self) -> None:
        with Fixture() as fixture:
            receipt = fixture.produce()
            evidence = (
                fixture.source / "docs" / "evidence" / "phase10" /
                "quality" / "retained.txt"
            )
            evidence.parent.mkdir(parents=True)
            evidence.write_text("retained evidence\n", encoding="utf-8")
            _commit_all(fixture.source, "retain excluded evidence")
            verified = fixture.verify()
            self.assertEqual(verified["source"], receipt["source"])
            with self.assertRaisesRegex(authority.BuildAuthorityError, "exact revision"):
                authority._produce_with_tools(
                    fixture.source,
                    fixture.revision,
                    fixture.root / "second-build",
                    fixture.root / "second-observation",
                    fixture.tools,
                )

        with Fixture() as fixture:
            fixture.produce()
            todo = fixture.source / "docs" / "TODO.md"
            todo.write_text("source-scope change\n", encoding="utf-8")
            _commit_all(fixture.source, "change source-scope document")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "source authority"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            tree = _run_git(fixture.source, "rev-parse", "HEAD^{tree}")
            unrelated = subprocess.check_output(
                [
                    "git", "-c", "user.name=Build Authority Test", "-c",
                    "user.email=authority@example.invalid", "commit-tree", tree,
                    "-m", "unrelated root",
                ],
                cwd=fixture.source,
                text=True,
            ).strip()
            subprocess.run(
                ["git", "switch", "--detach", unrelated],
                cwd=fixture.source,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            with self.assertRaisesRegex(authority.BuildAuthorityError, "ancestor"):
                fixture.verify()

    def test_compile_database_and_analyzer_version_are_mandatory(self) -> None:
        with Fixture() as fixture:
            fixture.produce()
            (fixture.build / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(authority.BuildAuthorityError, "empty"):
                fixture.verify()

        with Fixture() as fixture:
            fixture.produce()
            analyzer = fixture.build / authority.ANALYZER_RELATIVE
            _write_executable(
                analyzer,
                "#!/usr/bin/python3\nprint('CodeSkeptic 0.4.9-dev+forged')\n",
            )
            with self.assertRaisesRegex(authority.BuildAuthorityError, "version"):
                fixture.verify()

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self) -> None:
        for raw, expected in (
            (b'{"schema":"a","schema":"b"}\n', "duplicate"),
            (b'{"value":NaN}\n', "non-finite"),
        ):
            with self.subTest(expected=expected), Fixture() as fixture:
                fixture.produce()
                (fixture.output / "receipt.json").write_bytes(raw)
                (fixture.output / "receipt.json.sha256").write_bytes(
                    f"{authority.sha256_bytes(raw)}  receipt.json\n".encode()
                )
                _rewrite_manifest(fixture.output)
                with self.assertRaisesRegex(authority.BuildAuthorityError, expected):
                    fixture.verify()

    def test_cli_markers_and_fail_closed_exit_are_stable(self) -> None:
        marker_receipt = {"build_identity_sha256": "a" * 64}
        with mock.patch.object(
            authority, "produce_authority", return_value=marker_receipt
        ) as producer, mock.patch.object(
            authority, "verify_authority", return_value=marker_receipt
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = authority.main([
                    "produce",
                    "--source", "source",
                    "--revision", "a" * 40,
                    "--build-dir", "build",
                    "--output", "authority",
                    "--container-layout", "p10-09",
                ])
            self.assertEqual(result, 0)
            self.assertIn("CODESKEPTIC_BUILD_AUTHORITY_ACCEPTED", output.getvalue())
            producer.assert_called_once_with(
                Path("source"),
                "a" * 40,
                Path("build"),
                Path("authority"),
                container_layout="p10-09",
            )
            output = io.StringIO()
            with redirect_stdout(output):
                result = authority.main([
                    "verify",
                    "--source", "source",
                    "--build-dir", "build",
                    "--authority", "authority",
                ])
            self.assertEqual(result, 0)
            self.assertIn("CODESKEPTIC_BUILD_AUTHORITY_VERIFIED", output.getvalue())

        with mock.patch.object(
            authority,
            "produce_authority",
            side_effect=authority.BuildAuthorityError("dirty source"),
        ):
            error = io.StringIO()
            with redirect_stderr(error):
                result = authority.main([
                    "produce",
                    "--source", "source",
                    "--revision", "a" * 40,
                    "--build-dir", "build",
                    "--output", "authority",
                ])
            self.assertEqual(result, 2)
            self.assertIn("CODESKEPTIC_BUILD_AUTHORITY_FAIL", error.getvalue())

    def test_source_manifest_is_the_shared_determinism_authority(self) -> None:
        with Fixture() as fixture:
            expected = determinism.source_manifest_at_revision(
                fixture.source, fixture.revision
            )
            receipt = fixture.produce()
            self.assertEqual(receipt["source"], expected)


if __name__ == "__main__":
    unittest.main()
