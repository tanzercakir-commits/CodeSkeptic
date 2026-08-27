#!/usr/bin/env python3
"""Contracts for the P10-09 create-new authority provisioner."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import provision_stability_authorities as provision  # noqa: E402


REVISION = "1" * 40


class PodmanContainerDouble:
    """Small stateful Podman double for ownership-checked cleanup tests."""

    def __init__(
        self,
        *,
        container_id: str = "a" * 64,
        launch_returncode: int = 0,
        create_cidfile: bool = True,
        install_foreign_replacement: bool = False,
    ) -> None:
        self.container_id = container_id
        self.launch_returncode = launch_returncode
        self.create_cidfile = create_cidfile
        self.install_foreign_replacement = install_foreign_replacement
        self.calls: list[list[str]] = []
        self.containers: dict[str, dict[str, object]] = {}
        self.removed_ids: list[str] = []

    def _find(self, reference: str) -> dict[str, object] | None:
        for value in self.containers.values():
            if value["Id"] == reference or value["Name"] == reference:
                return value
        return None

    def register_launch(self, argv: list[str]) -> None:
        name = argv[argv.index("--name") + 1]
        label = argv[argv.index("--label") + 1]
        prefix = "codeskeptic.provision.token="
        if not label.startswith(prefix):
            raise AssertionError("container launch omitted the ownership label")
        token = label.removeprefix(prefix)
        self.containers[self.container_id] = {
            "Id": self.container_id,
            "Name": name,
            "Config": {"Labels": {"codeskeptic.provision.token": token}},
        }
        if self.create_cidfile:
            cidfile = Path(argv[argv.index("--cidfile") + 1])
            cidfile.write_text(self.container_id, encoding="ascii")

    def __call__(
        self, argv: list[str], **unused: object
    ) -> subprocess.CompletedProcess[bytes]:
        del unused
        self.calls.append(argv)
        if "run" in argv:
            self.register_launch(argv)
            return subprocess.CompletedProcess(
                argv,
                self.launch_returncode,
                b"container output\n",
                b"",
            )
        if "inspect" in argv:
            value = self._find(argv[-1])
            if value is None:
                return subprocess.CompletedProcess(argv, 125, b"", b"not found\n")
            return subprocess.CompletedProcess(
                argv,
                0,
                (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"),
                b"",
            )
        if "exists" in argv:
            return subprocess.CompletedProcess(
                argv,
                0 if self._find(argv[-1]) is not None else 1,
                b"",
                b"",
            )
        if "rm" in argv:
            reference = argv[-1]
            value = self.containers.pop(reference, None)
            if value is None:
                return subprocess.CompletedProcess(argv, 1, b"", b"not found\n")
            self.removed_ids.append(reference)
            if self.install_foreign_replacement:
                foreign_id = "f" * 64
                self.containers[foreign_id] = {
                    "Id": foreign_id,
                    "Name": value["Name"],
                    "Config": {
                        "Labels": {
                            "codeskeptic.provision.token": "e" * 64,
                        }
                    },
                }
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(f"unexpected Podman command: {argv!r}")


def release_receipt() -> dict:
    return {
        "schema": provision.RELEASE_RECEIPT_SCHEMA,
        "status": "prepared",
        "source": {
            "revision": REVISION,
            "manifest_sha256": "2" * 64,
            "file_count": 10,
        },
        "image": {
            "reference": provision.build_authority.PINNED_IMAGE,
            "digest": provision.build_authority.PINNED_IMAGE_DIGEST,
            "id": provision.build_authority.PINNED_IMAGE_ID,
        },
        "manifests": {
            "determinism_sha256": "3" * 64,
            "baseline_sha256": "4" * 64,
            "realworld_sha256": "5" * 64,
            "workload_sha256": "6" * 64,
        },
        "mirror": {
            "authority_sha256": "7" * 64,
            "project_sha256": "8" * 64,
        },
        "release": {
            "project": "llama-cpp",
            "repository": "https://github.com/ggml-org/llama.cpp.git",
            "revision": "9" * 40,
            "manifest_sha256": "a" * 64,
            "recipe_sha256": "b" * 64,
            "tree": "c" * 40,
        },
        "layout": {
            "source": "/authority/release/source",
            "build": "/authority/release/build",
            "jobs": 2,
        },
        "compile": {
            "database_sha256": "d" * 64,
            "input_identity_sha256": "e" * 64,
            "translation_units": 12,
            "translation_unit_sha256": "f" * 64,
            "translation_unit_plan_sha256": "0" * 64,
            "selected_compile_commands_sha256": "1" * 64,
        },
        "build_toolchain": {
            "cmake_cache_schema": "fixture",
            "cmake_cache_canonical_sha256": "2" * 64,
            "cmake": "/usr/bin/cmake",
            "ninja": "/usr/bin/ninja",
            "c_compiler": "/usr/bin/clang-20",
            "cxx_compiler": "/usr/bin/clang++-20",
            "generator": "Ninja",
        },
        "inventories": {
            "source": {"fixture": "source-tree"},
            "build": {"fixture": "build-tree"},
        },
    }


class StabilityAuthorityProvisioningTest(unittest.TestCase):
    def test_lifecycle_lock_rejects_concurrent_recovery_or_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "prepared"
            staging.mkdir()
            with provision._lifecycle_lock(staging):
                with self.assertRaisesRegex(
                    provision.ProvisionError, "already active"
                ):
                    with provision._lifecycle_lock(staging):
                        self.fail("concurrent lifecycle lock was admitted")
            with provision._lifecycle_lock(staging):
                pass

    def test_lifecycle_lock_rejects_root_or_parent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "parent"
            staging = parent / "prepared"
            staging.mkdir(parents=True)
            moved = parent / "original-prepared"
            real_directory = provision._real_directory

            def replace_root(path: Path, label: str) -> Path:
                result = real_directory(path, label)
                if label == "prepared staging parent":
                    staging.rename(moved)
                    staging.mkdir()
                return result

            with (
                mock.patch.object(
                    provision, "_real_directory", side_effect=replace_root
                ),
                self.assertRaisesRegex(
                    provision.ProvisionError, "root identity drift"
                ),
            ):
                with provision._lifecycle_lock(staging):
                    self.fail("replacement root reached the lock body")
            self.assertTrue(staging.is_dir())
            self.assertTrue(moved.is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            grandparent = Path(temporary) / "grandparent"
            parent = grandparent / "parent"
            staging = parent / "prepared"
            staging.mkdir(parents=True)
            moved_parent = grandparent / "original-parent"
            real_directory = provision._real_directory

            def replace_parent(path: Path, label: str) -> Path:
                result = real_directory(path, label)
                if label == "prepared staging parent":
                    parent.rename(moved_parent)
                    staging.mkdir(parents=True)
                return result

            with (
                mock.patch.object(
                    provision, "_real_directory", side_effect=replace_parent
                ),
                self.assertRaisesRegex(
                    provision.ProvisionError, "(parent|root) identity drift"
                ),
            ):
                with provision._lifecycle_lock(staging):
                    self.fail("replacement parent reached the lock body")
            self.assertTrue(staging.is_dir())
            self.assertTrue((moved_parent / "prepared").is_dir())

    def test_tree_identity_binds_unselected_files_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            (root / "nested").mkdir(parents=True)
            selected = root / "nested/selected.cc"
            selected.write_text("int selected;\n", encoding="utf-8")
            before = provision._tree_identity(root, "fixture tree")
            root.chmod(0o750)
            mode_changed = provision._tree_identity(root, "fixture tree")
            self.assertNotEqual(before, mode_changed)
            (root / "unselected.txt").write_text("bound\n", encoding="utf-8")
            after = provision._tree_identity(root, "fixture tree")
            self.assertNotEqual(before, after)

            link = root / "linked"
            link.symlink_to(selected)
            with self.assertRaisesRegex(provision.ProvisionError, "linked"):
                provision._tree_identity(root, "fixture tree")
            link.unlink()

            hardlink = root / "hardlink"
            hardlink.hardlink_to(selected)
            with self.assertRaisesRegex(provision.ProvisionError, "hard-linked"):
                provision._tree_identity(root, "fixture tree")

    def test_container_contract_is_offline_pinned_and_mount_bounded(self) -> None:
        for profile in provision.PROFILES:
            for mode in ("sanitizer-produce", "sanitizer-verify"):
                with self.subTest(mode=mode, profile=profile):
                    argv = provision._normalized_container_argv(mode, profile)
                    joined = " ".join(argv)
                    self.assertIn("--network=none", argv)
                    self.assertIn("--pull=never", argv)
                    self.assertIn("--env-host=false", argv)
                    self.assertIn("--read-only", argv)
                    self.assertIn("--pid=private", argv)
                    self.assertIn("--cap-drop=all", argv)
                    self.assertIn(
                        f"--memory={provision.SANITIZER_MEMORY_BYTES}", argv
                    )
                    self.assertIn(
                        f"--memory-swap={provision.SANITIZER_MEMORY_BYTES}", argv
                    )
                    self.assertIn(f"--cpus={provision.CONTAINER_CPUS}", argv)
                    self.assertIn(
                        f"--pids-limit={provision.CONTAINER_PIDS}", argv
                    )
                    self.assertIn(
                        "--ulimit=nofile=4096:4096", argv
                    )
                    self.assertIn(provision.build_authority.PINNED_IMAGE, argv)
                    self.assertNotIn("/authority:rw", joined)
                    self.assertIn("$SOURCE:/authority/source:ro", argv)
                    suffix = "rw" if mode.endswith("produce") else "ro"
                    self.assertIn(
                        f"$TEST_BUILD:/authority/source/build/"
                        f"p10-09-sanitizers/{profile}-tests:{suffix}",
                        argv,
                    )
                    self.assertIn(
                        f"$OUTPUT:/authority/sanitizers/{profile}:{suffix}",
                        argv,
                    )
                    self.assertEqual(
                        argv[argv.index("--revision") + 1], "$REVISION"
                    )

        for mode in ("release-produce", "release-verify"):
            with self.subTest(mode=mode):
                argv = provision._normalized_container_argv(mode)
                joined = " ".join(argv)
                self.assertIn("$SOURCE:/authority/source:ro", argv)
                self.assertIn("$MIRRORS:/authority/mirrors:ro", argv)
                self.assertIn(
                    f"--memory={provision.RELEASE_MEMORY_BYTES}", argv
                )
                self.assertIn(
                    f"--memory-swap={provision.RELEASE_MEMORY_BYTES}", argv
                )
                self.assertIn(f"--cpus={provision.CONTAINER_CPUS}", argv)
                self.assertIn(f"--pids-limit={provision.CONTAINER_PIDS}", argv)
                self.assertNotIn("/authority:rw", joined)
                if mode.endswith("produce"):
                    self.assertIn("$RELEASE:/authority/release:rw", argv)
                    self.assertIn("$SCRATCH:/work:rw", argv)
                else:
                    self.assertIn("$RELEASE:/authority/release:ro", argv)
                    self.assertNotIn("$SCRATCH:/work:rw", argv)

    def test_container_file_and_supported_tmpfs_limits_are_exact(self) -> None:
        self.assertGreaterEqual(
            provision.SANITIZER_CONTAINER_FILE_BYTES,
            provision.realworld.MAX_PROCESS_FILE_BYTES,
        )
        self.assertGreaterEqual(
            provision.SANITIZER_CONTAINER_FILE_BYTES,
            provision.staging.MAX_FILE_BYTES,
        )
        self.assertGreater(
            provision.SANITIZER_CONTAINER_TMPFS_BYTES,
            provision.staging.LARGE_TEMPORARY_RESERVE_BYTES,
        )
        for capacity, mount in (
            (
                provision.SANITIZER_CONTAINER_TMPFS_BYTES,
                provision.SANITIZER_CONTAINER_TMPFS,
            ),
            (
                provision.RELEASE_CONTAINER_TMPFS_BYTES,
                provision.RELEASE_CONTAINER_TMPFS,
            ),
        ):
            self.assertEqual(capacity % (1 << 30), 0)
            self.assertEqual(
                mount,
                f"/tmp:rw,size={capacity >> 30}g,mode=1777",
            )
        commands = (
            (
                provision._normalized_container_argv(
                    "sanitizer-produce", "address"
                ),
                provision.SANITIZER_CONTAINER_FILE_BYTES,
                provision.SANITIZER_CONTAINER_TMPFS,
            ),
            (
                provision._normalized_container_argv("release-produce"),
                provision.RELEASE_CONTAINER_FILE_BYTES,
                provision.RELEASE_CONTAINER_TMPFS,
            ),
        )
        for command, file_limit, tmpfs in commands:
            with self.subTest(command=command[-4]):
                fsize = f"--ulimit=fsize={file_limit}:{file_limit}"
                self.assertEqual(command.count(fsize), 1)
                self.assertEqual(command.count(tmpfs), 1)
                self.assertEqual(command[command.index("--tmpfs") + 1], tmpfs)

    def test_cleanup_accepts_exact_unframed_podman_cidfile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cidfile = Path(temporary) / "container.cid"
            container_id = "c" * 64
            cidfile.write_bytes(container_id.encode("ascii"))

            with mock.patch.object(
                provision, "_cleanup_named_container"
            ) as cleanup:
                provision._cleanup_container_cidfile(
                    cidfile,
                    "/usr/bin/podman",
                    "fixture-container",
                    "d" * 64,
                )

            cleanup.assert_called_once_with(
                "fixture-container",
                "/usr/bin/podman",
                "d" * 64,
                container_id,
            )
            self.assertFalse(cidfile.exists())

            cidfile.write_bytes((container_id + "\n").encode("ascii"))
            with (
                mock.patch.object(
                    provision, "_cleanup_named_container"
                ) as framed_cleanup,
                self.assertRaisesRegex(
                    provision.ProvisionError,
                    "container ID file is malformed",
                ),
            ):
                provision._cleanup_container_cidfile(
                    cidfile,
                    "/usr/bin/podman",
                    "fixture-container",
                    "d" * 64,
                )
            framed_cleanup.assert_not_called()
            self.assertTrue(cidfile.exists())

    def test_pinned_container_can_write_past_log_cap_through_rw_bind(self) -> None:
        podman = "/usr/bin/podman"
        environment = provision.build_authority._podman_environment()
        try:
            image_exists = provision.staging._bounded_command(
                [
                    podman,
                    "--events-backend=none",
                    "image",
                    "exists",
                    provision.build_authority.PINNED_IMAGE,
                ],
                environment=environment,
                cwd=None,
                maximum_output=4096,
                timeout_seconds=15,
            )
        except Exception as error:
            self.skipTest(f"local container runtime unavailable: {error}")
        if image_exists.returncode != 0:
            self.skipTest("pinned local container image is unavailable")

        probe_parent = ROOT.parent
        if not provision.os.access(probe_parent, provision.os.W_OK):
            self.skipTest("no writable host-backed directory for container probe")
        with tempfile.TemporaryDirectory(
            prefix="codeskeptic-fsize-probe-",
            dir=probe_parent,
        ) as temporary:
            root = Path(temporary)
            filesystem = provision.os.statvfs(root)
            available = filesystem.f_bavail * filesystem.f_frsize
            required = (
                provision.MINIMUM_HOST_FREE_BYTES
                + provision.MAX_CONTAINER_WRITABLE_BYTES
            )
            if available < required:
                self.skipTest("insufficient local space for bounded container probe")
            workspace = root / "workspace"
            workspace.mkdir()
            log = root / "probe.log"
            cidfile = root / "probe.cid"
            token = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
            name = f"codeskeptic-fsize-probe-{token}"
            payload_bytes = provision.MAX_CONTAINER_OUTPUT_BYTES + (1 << 20)
            writer = (
                "from pathlib import Path\n"
                "import os\n"
                "import resource\n"
                "path = Path('/probe/payload.bin')\n"
                "block = b'x' * (1 << 20)\n"
                "with path.open('wb') as stream:\n"
                f"    for _ in range({payload_bytes // (1 << 20)}):\n"
                "        stream.write(block)\n"
                "    stream.flush()\n"
                "    os.fsync(stream.fileno())\n"
                "soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)\n"
                "print(path.stat().st_size, soft, hard, sep='|')\n"
            )
            command = [
                podman,
                "--events-backend=none",
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--security-opt",
                "label=disable",
                "--tmpfs",
                "/tmp:rw,size=4g,mode=1777",
                *provision._resource_container_argv("release-produce"),
                "--cidfile",
                str(cidfile),
                "--name",
                name,
                "-v",
                f"{workspace}:/probe:rw",
                provision.build_authority.PINNED_IMAGE,
                "/usr/bin/python3",
                "-c",
                writer,
            ]
            cleanup: subprocess.CompletedProcess[bytes] | None = None
            try:
                with mock.patch.object(
                    provision.staging, "IMAGE_LOAD_TIMEOUT_SECONDS", 1
                ):
                    completed = provision._run_bounded_container(
                        command,
                        log,
                        cidfile,
                        60,
                    )
            finally:
                cleanup = provision.staging._bounded_command(
                    [
                        podman,
                        "--events-backend=none",
                        "rm",
                        "--force",
                        "--ignore",
                        name,
                    ],
                    environment=environment,
                    cwd=None,
                    maximum_output=4096,
                    timeout_seconds=30,
                )
                cidfile.unlink(missing_ok=True)

            self.assertEqual(cleanup.returncode, 0)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            expected = (
                f"{payload_bytes}|{provision.RELEASE_CONTAINER_FILE_BYTES}|"
                f"{provision.RELEASE_CONTAINER_FILE_BYTES}"
            ).encode("ascii")
            self.assertEqual(completed.stdout.strip(), expected)
            self.assertEqual((workspace / "payload.bin").stat().st_size, payload_bytes)

    def test_writable_bind_parser_deduplicates_rw_roots_and_ignores_ro(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            writable = root / "writable"
            readonly = root / "readonly"
            writable.mkdir()
            readonly.mkdir()
            command = [
                "/usr/bin/podman",
                "run",
                "-v",
                f"{readonly}:/readonly:ro",
                "-v",
                f"{writable}:/first:rw",
                "-v",
                f"{writable}:/duplicate:rw",
                "fixture-image",
            ]

            self.assertEqual(
                provision._writable_bind_roots(command),
                (writable,),
            )
            with self.assertRaisesRegex(
                provision.ProvisionError, "not absolute"
            ):
                provision._writable_bind_roots(
                    [
                        "/usr/bin/podman",
                        "run",
                        "-v",
                        "relative:/work:rw",
                        "fixture-image",
                    ]
                )

    def test_writable_workspace_monitor_accepts_small_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "small.bin").write_bytes(b"small\n")
            filesystem = mock.Mock(f_bavail=2 << 20, f_frsize=1)
            with (
                mock.patch.object(
                    provision, "MAX_CONTAINER_WRITABLE_BYTES", 1 << 20
                ),
                mock.patch.object(
                    provision, "MAX_CONTAINER_WRITABLE_INODES", 8
                ),
                mock.patch.object(provision, "MINIMUM_HOST_FREE_BYTES", 1024),
                mock.patch.object(provision, "WORKSPACE_SCAN_INTERVAL_SECONDS", 0),
                mock.patch.object(provision, "FREE_SPACE_SCAN_INTERVAL_SECONDS", 0),
                mock.patch.object(
                    provision.os, "statvfs", return_value=filesystem
                ),
            ):
                monitor = provision._workspace_failure_monitor((root,))
                self.assertIsNone(monitor())

    def test_workspace_scan_tolerates_entries_removed_by_active_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transient = root / "object.cpp-deadbeef.o.tmp"
            transient.write_bytes(b"temporary object\n")
            real_scandir = provision.os.scandir
            removed = False

            class RemovingStream:
                def __init__(self, path: Path) -> None:
                    self.stream = real_scandir(path)

                def __enter__(self):
                    nonlocal removed
                    entries = list(self.stream)
                    transient.unlink()
                    removed = True
                    return iter(entries)

                def __exit__(self, *arguments: object) -> None:
                    self.stream.close()

            def remove_before_stat(path: Path):
                if Path(path) == root and not removed:
                    return RemovingStream(Path(path))
                return real_scandir(path)

            with mock.patch.object(
                provision.os, "scandir", side_effect=remove_before_stat
            ):
                self.assertEqual(provision._workspace_allocation((root,)), (0, 0))

            nested = root / "nested"
            nested.mkdir()
            (nested / "payload").write_bytes(b"payload\n")
            removed_nested = False

            def remove_before_nested_scan(path: Path):
                nonlocal removed_nested
                if Path(path) == nested and not removed_nested:
                    (nested / "payload").unlink()
                    nested.rmdir()
                    removed_nested = True
                return real_scandir(path)

            with mock.patch.object(
                provision.os, "scandir", side_effect=remove_before_nested_scan
            ):
                allocated, inodes = provision._workspace_allocation((root,))
            self.assertGreaterEqual(allocated, 0)
            self.assertEqual(inodes, 1)

            with self.assertRaisesRegex(
                provision.ProvisionError,
                "cannot inspect writable container workspace",
            ):
                provision._workspace_allocation((root / "missing",))

            class UnreadableEntry:
                path = str(root / "blocked")

                def stat(self, *, follow_symlinks: bool):
                    if follow_symlinks:
                        raise AssertionError("workspace scan followed a symlink")
                    raise PermissionError(13, "permission denied", self.path)

            class UnreadableStream:
                def __enter__(self):
                    return iter((UnreadableEntry(),))

                def __exit__(self, *arguments: object) -> None:
                    pass

            with (
                mock.patch.object(
                    provision.os, "scandir", return_value=UnreadableStream()
                ),
                self.assertRaisesRegex(
                    provision.ProvisionError,
                    "cannot inventory writable container workspace",
                ),
            ):
                provision._workspace_allocation((root,))

    def test_workspace_scan_revalidates_root_identity_after_entry_races(self) -> None:
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "workspace"
                    root.mkdir()
                    transient = root / "object.cpp-deadbeef.o.tmp"
                    transient.write_bytes(b"temporary object\n")
                    real_scandir = provision.os.scandir

                    class ReplacingRootStream:
                        def __init__(self, path: Path) -> None:
                            self.stream = real_scandir(path)

                        def __enter__(self):
                            entries = list(self.stream)
                            transient.unlink()
                            root.rmdir()
                            if replacement:
                                root.mkdir()
                            return iter(entries)

                        def __exit__(self, *arguments: object) -> None:
                            self.stream.close()

                    def replace_after_capture(path: Path):
                        if Path(path) == root:
                            return ReplacingRootStream(Path(path))
                        return real_scandir(path)

                    with (
                        mock.patch.object(
                            provision.os,
                            "scandir",
                            side_effect=replace_after_capture,
                        ),
                        self.assertRaisesRegex(
                            provision.ProvisionError,
                            "writable container workspace identity drift|"
                            "cannot inspect writable container workspace",
                        ),
                    ):
                        provision._workspace_allocation((root,))

    def test_writable_workspace_monitor_rejects_byte_and_inode_breaches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "allocated.bin").write_bytes(b"allocated\n")
            cases = (
                ("allocated-byte limit", 0, 8, 1),
                ("inode limit", 1 << 20, 0, 2 << 20),
            )
            for message, byte_limit, inode_limit, available in cases:
                with self.subTest(message=message):
                    with (
                        mock.patch.object(
                            provision, "MAX_CONTAINER_WRITABLE_BYTES", byte_limit
                        ),
                        mock.patch.object(
                            provision, "MAX_CONTAINER_WRITABLE_INODES", inode_limit
                        ),
                        mock.patch.object(provision, "MINIMUM_HOST_FREE_BYTES", 0),
                        mock.patch.object(
                            provision, "WORKSPACE_SCAN_INTERVAL_SECONDS", 0
                        ),
                        mock.patch.object(
                            provision, "FREE_SPACE_SCAN_INTERVAL_SECONDS", 0
                        ),
                        mock.patch.object(
                            provision.os,
                            "statvfs",
                            return_value=mock.Mock(
                                f_bavail=available,
                                f_frsize=1,
                            ),
                        ),
                        self.assertRaisesRegex(provision.ProvisionError, message),
                    ):
                        provision._workspace_failure_monitor((root,))

    def test_writable_workspace_monitor_rejects_free_reserve_breach(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            high = mock.Mock(f_bavail=100, f_frsize=1)
            low = mock.Mock(f_bavail=99, f_frsize=1)
            with (
                mock.patch.object(provision, "MAX_CONTAINER_WRITABLE_BYTES", 0),
                mock.patch.object(provision, "MAX_CONTAINER_WRITABLE_INODES", 1),
                mock.patch.object(provision, "MINIMUM_HOST_FREE_BYTES", 100),
                mock.patch.object(provision, "WORKSPACE_SCAN_INTERVAL_SECONDS", 0),
                mock.patch.object(provision, "FREE_SPACE_SCAN_INTERVAL_SECONDS", 0),
                mock.patch.object(
                    provision.os,
                    "statvfs",
                    side_effect=(high, high, low),
                ),
            ):
                monitor = provision._workspace_failure_monitor((root,))
                self.assertEqual(
                    monitor(),
                    "writable workspace exhausted host free-space reserve",
                )

    def test_expanded_container_commands_have_no_ambient_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            mirrors = root / "mirrors"
            release = root / "release"
            scratch = root / "scratch"
            for path in (source, mirrors, release, scratch):
                path.mkdir()
            command = provision._release_container_command(
                "release-produce", source, mirrors, release, REVISION, scratch
            )
            self.assertFalse(any("$" in token for token in command))
            self.assertEqual(command[0], "/usr/bin/podman")
            self.assertIn(f"{source}:/authority/source:ro", command)
            self.assertIn(f"{release}:/authority/release:rw", command)

    def test_sanitizer_configure_recipe_is_exact_for_each_profile(self) -> None:
        for profile in provision.PROFILES:
            with self.subTest(profile=profile):
                tests, fuzz = provision._sanitizer_configure_commands(
                    profile,
                    Path("/authority/source/build/p10-09-sanitizers")
                    / f"{profile}-tests",
                    Path("/authority/source/build/p10-09-sanitizers")
                    / f"{profile}-fuzz",
                )
                for command in (tests, fuzz):
                    self.assertEqual(command[0], "/usr/bin/cmake")
                    self.assertEqual(command[1:3], ["-S", "/authority/source"])
                    self.assertIn("-G", command)
                    self.assertIn("Ninja", command)
                    self.assertIn("-DCMAKE_MAKE_PROGRAM=/usr/bin/ninja", command)
                    self.assertIn("-DCMAKE_C_COMPILER=/usr/bin/clang-20", command)
                    self.assertIn("-DCMAKE_CXX_COMPILER=/usr/bin/clang++-20", command)
                    self.assertIn(f"-DCODESKEPTIC_SANITIZER={profile}", command)
                self.assertIn("-DCODESKEPTIC_BUILD_TESTS=ON", tests)
                self.assertIn("-DCODESKEPTIC_BUILD_FUZZERS=OFF", tests)
                self.assertIn("-DCODESKEPTIC_BUILD_TESTS=OFF", fuzz)
                self.assertIn("-DCODESKEPTIC_BUILD_FUZZERS=ON", fuzz)

    def test_inner_sanitizer_producer_configures_then_executes_and_verifies(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            outputs = root / "outputs"
            profile = "address"
            for path in (
                work / f"{profile}-tests",
                work / f"{profile}-fuzz",
                outputs / profile,
            ):
                path.mkdir(parents=True)
            receipt = {
                "profile": profile,
                "source": {"base_commit": REVISION},
            }
            with (
                mock.patch.object(provision, "CONTAINER_SANITIZER_WORK", work),
                mock.patch.object(provision, "CONTAINER_SANITIZERS", outputs),
                mock.patch.object(provision, "_run_configure") as configure,
                mock.patch.object(
                    provision.sanitizer, "execute", return_value=receipt
                ) as execute,
                mock.patch.object(
                    provision.sanitizer, "verify_receipt", return_value=receipt
                ) as verify,
            ):
                self.assertEqual(
                    provision._inner_populate_sanitizer(profile, REVISION),
                    receipt,
                )
            self.assertEqual(configure.call_count, 2)
            execute.assert_called_once_with(
                profile,
                work / f"{profile}-tests",
                work / f"{profile}-fuzz",
                outputs / profile,
            )
            verify.assert_called_once()

    def test_inner_sanitizer_verifier_rejects_wrong_exact_revision(self) -> None:
        receipt = {
            "profile": "address",
            "source": {"base_commit": "2" * 40},
        }
        with (
            mock.patch.object(
                provision.sanitizer, "verify_receipt", return_value=receipt
            ),
            self.assertRaisesRegex(provision.ProvisionError, "source/profile"),
        ):
            provision._inner_verify_sanitizer("address", REVISION)

    def test_collision_is_rejected_before_container_or_runtime_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority = root / "authority"
            source = authority / "source"
            (source / "build/p10-09-sanitizers").mkdir(parents=True)
            with (
                mock.patch.object(
                    provision,
                    "_validate_staging_root",
                    return_value=(authority, source, {"revision": REVISION}),
                ),
                mock.patch.object(
                    provision.build_authority, "_runtime_authority"
                ) as runtime,
                mock.patch.object(provision, "_execute_container") as execute,
                self.assertRaisesRegex(provision.ProvisionError, "must be absent"),
            ):
                provision.populate_sanitizers(root, REVISION)
            runtime.assert_not_called()
            execute.assert_not_called()

    def test_interrupted_multi_tree_publication_is_recovered_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            build_parent = authority / "source/build"
            build_parent.mkdir(parents=True)
            build_temp = build_parent / ".p10-09-sanitizers.fixture"
            receipt_temp = authority / ".sanitizers.fixture"
            build_temp.mkdir()
            receipt_temp.mkdir()
            (build_temp / "build.txt").write_text("build\n", encoding="utf-8")
            (receipt_temp / "receipt.txt").write_text(
                "receipt\n", encoding="utf-8"
            )
            final_build = build_parent / "p10-09-sanitizers"
            final_receipts = authority / "sanitizers"
            transaction = provision._write_transaction(
                authority,
                "sanitizers",
                REVISION,
                [(build_temp, final_build), (receipt_temp, final_receipts)],
            )
            provision.staging._publish_tree_noreplace(build_temp, final_build)

            provision._recover_transaction(staging_root, REVISION)
            self.assertFalse(final_build.exists())
            self.assertFalse(final_receipts.exists())
            self.assertFalse(build_temp.exists())
            self.assertFalse(receipt_temp.exists())
            self.assertFalse(
                (authority / provision.TRANSACTION_NAME).exists()
            )
            self.assertEqual(transaction["kind"], "sanitizers")

    def test_prepublication_operation_is_recoverable_after_power_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            (authority / "source/build").mkdir(parents=True)
            operation = provision._write_operation(
                staging_root, authority, "sanitizers", REVISION
            )
            owned: list[dict[str, object]] = []
            for role in (
                "sanitizer-build",
                "sanitizer-receipts",
                "operator-logs",
            ):
                workspace = provision._create_operation_workspace(
                    staging_root, authority, operation, role, owned
                )
                (workspace / "partial.txt").write_text(
                    "partial\n", encoding="utf-8"
                )

            with mock.patch.object(provision, "_cleanup_named_container") as cleanup:
                provision._recover_transaction(staging_root, REVISION)
            self.assertEqual(cleanup.call_count, 4)
            for record in owned:
                self.assertFalse(Path(record["path"]).exists())
            self.assertFalse(
                (authority / provision.OPERATION_NAME).exists()
            )

    def test_unowned_or_malformed_workspace_is_preserved_fail_closed(self) -> None:
        for malformed_owner in (False, True):
            with self.subTest(malformed_owner=malformed_owner), tempfile.TemporaryDirectory() as temporary:
                staging_root = Path(temporary) / "staging"
                authority = staging_root / "authority"
                (authority / "source/build").mkdir(parents=True)
                operation = provision._write_operation(
                    staging_root, authority, "sanitizers", REVISION
                )
                record = next(
                    item for item in operation["workspaces"]
                    if item["role"] == "sanitizer-receipts"
                )
                workspace = provision._workspace_path(
                    staging_root, authority, record
                )
                workspace.mkdir(mode=0o700)
                staged_owner = provision._workspace_path(
                    staging_root, authority, record, "ownership_staging"
                )
                if malformed_owner:
                    staged_owner.write_text("not canonical json\n", encoding="utf-8")
                with (
                    mock.patch.object(provision, "_cleanup_named_container"),
                    self.assertRaisesRegex(
                        provision.ProvisionError,
                        "marker retained|ownership is missing|ownership is invalid",
                    ),
                ):
                    provision._abort_operation(
                        staging_root, authority, operation, REVISION
                    )
                self.assertTrue(workspace.is_dir())
                self.assertEqual(list(workspace.iterdir()), [staged_owner] if malformed_owner else [])
                self.assertTrue((authority / provision.OPERATION_NAME).is_file())

    def test_workspace_creation_failure_removes_only_the_pinned_mkdir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            (authority / "source/build").mkdir(parents=True)
            operation = provision._write_operation(
                staging_root, authority, "sanitizers", REVISION
            )
            record = next(
                item for item in operation["workspaces"]
                if item["role"] == "sanitizer-receipts"
            )
            workspace = provision._workspace_path(
                staging_root, authority, record
            )
            with (
                mock.patch.object(
                    provision,
                    "_write_workspace_ownership",
                    side_effect=provision.ProvisionError("injected owner failure"),
                ),
                self.assertRaisesRegex(
                    provision.ProvisionError, "injected owner failure"
                ),
            ):
                provision._create_operation_workspace(
                    staging_root, authority, operation,
                    "sanitizer-receipts", [],
                )
            self.assertFalse(workspace.exists())

    def test_transaction_commit_preserves_only_verified_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            authority.mkdir(parents=True)
            source = authority / ".release.fixture"
            destination = authority / "release"
            source.mkdir()
            (source / "receipt.json").write_text("{}\n", encoding="utf-8")
            transaction = provision._write_transaction(
                authority,
                "release",
                REVISION,
                [(source, destination)],
            )
            provision.staging._publish_tree_noreplace(source, destination)
            provision._commit_transaction(authority, transaction, REVISION)
            self.assertTrue(destination.is_dir())
            self.assertFalse(source.exists())
            self.assertFalse(
                (authority / provision.TRANSACTION_NAME).exists()
            )

    def test_transaction_recovery_preserves_foreign_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            authority.mkdir(parents=True)
            source = authority / ".release.fixture"
            destination = authority / "release"
            source.mkdir()
            transaction = provision._write_transaction(
                authority,
                "release",
                REVISION,
                [(source, destination)],
            )
            source.rename(authority / "owned-moved-aside")
            source.mkdir()
            (source / "foreign.txt").write_text("foreign\n", encoding="utf-8")
            with self.assertRaisesRegex(
                provision.ProvisionError, "transaction retained"
            ):
                provision._rollback_transaction(
                    authority, transaction, REVISION
                )
            self.assertEqual(
                (source / "foreign.txt").read_text(encoding="utf-8"),
                "foreign\n",
            )
            self.assertTrue((authority / provision.TRANSACTION_NAME).is_file())

    def test_transaction_recovery_preserves_inserted_foreign_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            authority.mkdir(parents=True)
            source = authority / ".release.fixture"
            destination = authority / "release"
            source.mkdir()
            (source / "owned.txt").write_text("owned\n", encoding="utf-8")
            transaction = provision._write_transaction(
                authority,
                "release",
                REVISION,
                [(source, destination)],
            )
            (source / "foreign.txt").write_text("foreign\n", encoding="utf-8")
            with self.assertRaisesRegex(
                provision.ProvisionError, "content changed|transaction retained"
            ):
                provision._rollback_transaction(
                    authority, transaction, REVISION
                )
            self.assertEqual(
                (source / "foreign.txt").read_text(encoding="utf-8"),
                "foreign\n",
            )
            self.assertTrue((authority / provision.TRANSACTION_NAME).is_file())

    def test_failed_operation_logs_are_sealed_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging_root = Path(temporary) / "staging"
            authority = staging_root / "authority"
            (authority / "source/build").mkdir(parents=True)
            operation = provision._write_operation(
                staging_root, authority, "sanitizers", REVISION
            )
            log_root = provision._create_operation_workspace(
                staging_root, authority, operation, "operator-logs", []
            )
            (log_root / "producer.log").write_text(
                "bounded diagnostic\n", encoding="utf-8"
            )
            rejection = provision._persist_rejection_evidence(
                staging_root,
                authority,
                operation,
                REVISION,
                provision.ProvisionError("injected producer failure"),
            )
            self.assertIsNotNone(rejection)
            assert rejection is not None
            receipt = provision._verify_rejection_evidence(
                rejection, operation, REVISION
            )
            self.assertEqual(receipt["status"], "rejected")
            self.assertEqual(receipt["failure"]["type"], "ProvisionError")
            self.assertFalse(log_root.exists())
            with mock.patch.object(provision, "_cleanup_named_container"):
                provision._abort_operation(
                    staging_root, authority, operation, REVISION
                )
            self.assertTrue(rejection.is_dir())
            self.assertFalse((authority / provision.OPERATION_NAME).exists())

            rejection.chmod(0o700)
            log = rejection / "producer.log"
            log.chmod(0o600)
            log.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(
                provision.ProvisionError, "inventory drift|checksum"
            ):
                provision._verify_rejection_evidence(
                    rejection, operation, REVISION
                )

    def test_long_container_executor_disables_host_fsize_and_monitors_rw_binds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            log = root / "operator.log"
            cidfile = root / "operator.log.cid"
            monitor = mock.Mock(return_value=None)

            def bounded_process(
                command: list[str],
                environment: dict[str, str],
                timeout_seconds: float,
                stdout_path: Path,
                stderr_path: Path,
                monitored_paths: list[Path],
                maximum_bytes: int,
                file_size_limit_bytes: int | None,
                failure_monitor: object,
            ) -> subprocess.CompletedProcess[bytes]:
                del environment
                self.assertEqual(
                    timeout_seconds,
                    provision.staging.IMAGE_LOAD_TIMEOUT_SECONDS + 1,
                )
                self.assertEqual(monitored_paths, [cidfile])
                self.assertEqual(maximum_bytes, provision.MAX_CONTAINER_OUTPUT_BYTES)
                self.assertIsNone(file_size_limit_bytes)
                self.assertIs(failure_monitor, monitor)
                stdout_path.write_bytes(b"bounded output\n")
                stderr_path.write_bytes(b"")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    b"bounded output\n",
                    b"",
                )

            command = [
                "/usr/bin/podman",
                "run",
                "-v",
                f"{workspace}:/work:rw",
                "fixture-image",
            ]
            with (
                mock.patch.object(
                    provision,
                    "_workspace_failure_monitor",
                    return_value=monitor,
                ) as monitor_factory,
                mock.patch.object(
                    provision.determinism,
                    "_run_bounded_process",
                    side_effect=bounded_process,
                ) as runner,
            ):
                completed = provision._run_bounded_container(
                    command,
                    log,
                    cidfile,
                    provision.staging.IMAGE_LOAD_TIMEOUT_SECONDS + 1,
                )

            self.assertEqual(completed.returncode, 0)
            monitor_factory.assert_called_once_with((workspace,))
            runner.assert_called_once()
            self.assertFalse(log.with_suffix(".log.stdout.partial").exists())
            self.assertFalse(log.with_suffix(".log.stderr.partial").exists())

    def test_bounded_container_executor_uses_cid_and_cleans_every_exit(self) -> None:
        for returncode in (0, 2):
            with self.subTest(returncode=returncode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                log = root / "operator.log"
                podman = PodmanContainerDouble(launch_returncode=returncode)

                with mock.patch.object(
                    provision.staging, "_bounded_command", side_effect=podman
                ):
                    if returncode == 0:
                        provision._execute_container(
                            ["/usr/bin/podman", "run", "fixture-image"],
                            log,
                            timeout_seconds=provision.staging.IMAGE_LOAD_TIMEOUT_SECONDS,
                        )
                    else:
                        with self.assertRaisesRegex(
                            provision.ProvisionError, "exit 2"
                        ):
                            provision._execute_container(
                                ["/usr/bin/podman", "run", "fixture-image"],
                                log,
                                timeout_seconds=provision.staging.IMAGE_LOAD_TIMEOUT_SECONDS,
                            )
                self.assertEqual(log.read_text(encoding="utf-8"), "container output\n")
                self.assertFalse((root / "operator.log.cid").exists())
                launch = podman.calls[0]
                self.assertIn("--cidfile", launch)
                self.assertIn("--name", launch)
                self.assertIn("--label", launch)
                self.assertEqual(podman.removed_ids, ["a" * 64])
                name = launch[launch.index("--name") + 1]
                inspected = [
                    call[-1] for call in podman.calls if "inspect" in call
                ]
                self.assertEqual(inspected, ["a" * 64, "a" * 64, name])
                removal = next(call for call in podman.calls if "rm" in call)
                self.assertEqual(removal[-1], "a" * 64)
                self.assertNotIn("--name", removal)

    def test_missing_cid_uses_unique_name_cleanup_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "operator.log"
            podman = PodmanContainerDouble(
                launch_returncode=2,
                create_cidfile=False,
            )

            with (
                mock.patch.object(
                    provision.staging, "_bounded_command", side_effect=podman
                ),
                self.assertRaisesRegex(provision.ProvisionError, "exit 2"),
            ):
                provision._execute_container(
                    ["/usr/bin/podman", "run", "fixture-image"],
                    log,
                    timeout_seconds=provision.staging.IMAGE_LOAD_TIMEOUT_SECONDS,
                    invocation_token="b" * 64,
                    container_role="release-produce",
                )
            name = provision._container_name("b" * 64, "release-produce")
            self.assertIn(name, podman.calls[0])
            self.assertEqual(
                next(call for call in podman.calls if "inspect" in call)[-1],
                name,
            )
            self.assertEqual(podman.removed_ids, ["a" * 64])
            self.assertFalse((root / "operator.log.cid").exists())

    def test_foreign_same_name_replacement_is_preserved_and_rejected(self) -> None:
        token = "b" * 64
        name = provision._container_name(token, "release-produce")
        podman = PodmanContainerDouble(
            create_cidfile=False,
            install_foreign_replacement=True,
        )
        podman.register_launch(
            [
                "/usr/bin/podman",
                "run",
                "--cidfile",
                "/tmp/unused-cidfile",
                "--name",
                name,
                "--label",
                f"codeskeptic.provision.token={token}",
                "fixture-image",
            ]
        )

        with (
            mock.patch.object(
                provision.staging, "_bounded_command", side_effect=podman
            ),
            self.assertRaisesRegex(provision.ProvisionError, "ownership drift"),
        ):
            provision._cleanup_named_container(
                name,
                "/usr/bin/podman",
                token,
                "a" * 64,
            )

        self.assertEqual(podman.removed_ids, ["a" * 64])
        self.assertIn("f" * 64, podman.containers)
        self.assertEqual(podman.containers["f" * 64]["Name"], name)
        removals = [call for call in podman.calls if "rm" in call]
        self.assertEqual([call[-1] for call in removals], ["a" * 64])

    def test_release_executor_covers_materialization_build_and_postprocess(self) -> None:
        self.assertEqual(
            provision.RELEASE_CONTAINER_TIMEOUT_SECONDS,
            450 * 60,
        )
        self.assertEqual(
            provision.RELEASE_CONTAINER_TIMEOUT_SECONDS,
            provision.RELEASE_MATERIALIZATION_TIMEOUT_SECONDS
            + provision.RELEASE_PREPARATION_TIMEOUT_SECONDS
            + provision.RELEASE_CHECKOUT_AND_STARTUP_MARGIN_SECONDS
            + provision.RELEASE_POSTPROCESS_TIMEOUT_SECONDS,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "operator.log"

            def long_run(
                command: list[str],
                environment: dict[str, str],
                timeout_seconds: float,
                stdout_path: Path,
                stderr_path: Path,
                monitored_paths: list[Path],
                maximum_bytes: int,
                file_size_limit_bytes: int | None,
                failure_monitor: object,
            ) -> subprocess.CompletedProcess[bytes]:
                del environment
                self.assertEqual(
                    timeout_seconds,
                    provision.RELEASE_CONTAINER_TIMEOUT_SECONDS,
                )
                self.assertEqual(maximum_bytes, provision.MAX_CONTAINER_OUTPUT_BYTES)
                self.assertIsNone(file_size_limit_bytes)
                self.assertIsNone(failure_monitor)
                self.assertEqual(monitored_paths, [log.with_suffix(".log.cid")])
                podman.register_launch(command)
                stdout_path.write_bytes(b"release output\n")
                stderr_path.write_bytes(b"")
                return subprocess.CompletedProcess(
                    command, 0, b"release output\n", b""
                )

            podman = PodmanContainerDouble(container_id="c" * 64)
            with (
                mock.patch.object(
                    provision.determinism,
                    "_run_bounded_process",
                    side_effect=long_run,
                ) as runner,
                mock.patch.object(
                    provision.staging,
                    "_bounded_command",
                    side_effect=podman,
                ),
            ):
                provision._execute_container(
                    ["/usr/bin/podman", "run", "fixture-image"],
                    log,
                    timeout_seconds=provision.RELEASE_CONTAINER_TIMEOUT_SECONDS,
                    invocation_token="d" * 64,
                    container_role="release-produce",
                )
            runner.assert_called_once()
            self.assertEqual(log.read_bytes(), b"release output\n")

    def test_inner_release_canonicalizes_tool_paths_before_preparation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            mirrors = root / "mirrors"
            release = root / "release"
            release_source = release / "source"
            release_build = release / "build"
            scratch = root / "scratch"
            offline = root / "offline.git"
            private = root / "private"
            for path in (
                repo,
                mirrors,
                release_source,
                release_build,
                scratch,
                offline,
                private,
            ):
                path.mkdir(parents=True)

            tools = root / "tools"
            tools.mkdir()
            aliases: dict[str, Path] = {}
            resolved: dict[str, Path] = {}
            for name in ("cmake", "ninja", "clang", "clang++"):
                target = tools / f"real-{name}"
                target.write_text("tool\n", encoding="utf-8")
                target.chmod(0o700)
                alias = tools / name
                alias.symlink_to(target.name)
                aliases[name] = alias
                resolved[name] = target.resolve()

            workload = {
                "input": {
                    "realworld_manifest": "scripts/realworld_manifest.json",
                },
            }
            project = {
                "id": "llama-cpp",
                "repository": "https://example.test/llama.cpp.git",
            }
            manifest = {
                "campaigns": {
                    "release-candidate": {"projects": ["llama-cpp"]},
                },
            }
            receipt = release_receipt()

            with contextlib.ExitStack() as stack:
                for name, value in (
                    ("CONTAINER_SOURCE", repo),
                    ("CONTAINER_MIRRORS", mirrors),
                    ("CONTAINER_RELEASE", release),
                    ("CONTAINER_RELEASE_SOURCE", release_source),
                    ("CONTAINER_RELEASE_BUILD", release_build),
                    ("CONTAINER_SCRATCH", scratch),
                    ("CM", aliases["cmake"]),
                    ("NINJA", aliases["ninja"]),
                    ("C_COMPILER", aliases["clang"]),
                    ("CXX_COMPILER", aliases["clang++"]),
                ):
                    stack.enter_context(mock.patch.object(provision, name, value))
                stack.enter_context(
                    mock.patch.object(
                        provision,
                        "_load_release_inputs",
                        return_value=({}, workload, project),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision.realworld,
                        "load_manifest",
                        return_value=manifest,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision.realworld,
                        "load_mirror_authority",
                        return_value=({}, mirrors),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision.realworld,
                        "_bounded_shard_workspace",
                        return_value=contextlib.nullcontext(private),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision.realworld,
                        "_materialize_offline_repositories",
                        return_value={project["repository"]: offline},
                    )
                )
                prepare = stack.enter_context(
                    mock.patch.object(
                        provision.determinism, "prepare_release_candidate"
                    )
                )
                for name in (
                    "_normalize_release_payload_modes",
                    "_write_release_receipt",
                ):
                    stack.enter_context(mock.patch.object(provision, name))
                stack.enter_context(
                    mock.patch.object(
                        provision, "_release_projection", return_value=receipt
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision,
                        "verify_release_authority_in_current_runtime",
                        return_value=receipt,
                    )
                )
                provision._inner_populate_release(REVISION)

            arguments = prepare.call_args.args
            self.assertEqual(arguments[4], resolved["cmake"])
            self.assertEqual(arguments[5], resolved["ninja"])
            self.assertEqual(arguments[6], resolved["clang"])
            self.assertEqual(arguments[7], resolved["clang++"])

    def test_release_modes_are_normalized_before_inventory_is_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release"
            source = root / "source"
            build = root / "build"
            source.mkdir(parents=True, mode=0o700)
            build.mkdir(mode=0o700)
            regular = source / "source.cpp"
            executable = build / "tool"
            regular.write_text("int value;\n", encoding="utf-8")
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o700)

            provision._normalize_release_payload_modes(root)

            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(build.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(regular.stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o555)

    def test_release_receipt_is_canonical_and_semantically_rederived(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "release"
            (root / "source").mkdir(parents=True)
            (root / "build").mkdir()
            expected = release_receipt()
            provision._write_release_receipt(root, expected)
            with (
                mock.patch.object(
                    provision, "_release_projection", return_value=expected
                ) as projection,
                mock.patch.object(
                    provision,
                    "_tree_identity",
                    side_effect=[
                        expected["inventories"]["source"],
                        expected["inventories"]["build"],
                    ],
                ),
            ):
                self.assertEqual(
                    provision.verify_release_authority_in_current_runtime(
                        root, Path("/authority/source"),
                        Path("/authority/mirrors"), REVISION
                    ),
                    expected,
                )
            projection.assert_called_once()
            raw = (root / "receipt.json").read_bytes()
            self.assertEqual(raw, provision.canonical_json(expected))
            self.assertEqual(
                (root / "receipt.json.sha256").read_text(encoding="ascii"),
                f"{hashlib.sha256(raw).hexdigest()}  receipt.json\n",
            )

            forged = copy.deepcopy(expected)
            forged["release"]["tree"] = "d" * 40
            (root / "receipt.json").write_bytes(provision.canonical_json(forged))
            forged_raw = (root / "receipt.json").read_bytes()
            (root / "receipt.json.sha256").write_text(
                f"{hashlib.sha256(forged_raw).hexdigest()}  receipt.json\n",
                encoding="ascii",
            )
            with (
                mock.patch.object(
                    provision, "_release_projection", return_value=expected
                ),
                mock.patch.object(
                    provision,
                    "_tree_identity",
                    side_effect=[
                        expected["inventories"]["source"],
                        expected["inventories"]["build"],
                    ],
                ),
                self.assertRaisesRegex(provision.ProvisionError, "re-derived"),
            ):
                provision.verify_release_authority_in_current_runtime(
                    root, Path("/authority/source"),
                    Path("/authority/mirrors"), REVISION
                )

    def test_cli_is_versioned_and_exposes_only_fixed_public_operations(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(provision.__file__), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout,
            "CodeSkeptic P10-09 authority provisioner 1\n",
        )
        parser = provision.build_parser()
        choices = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
        )
        self.assertEqual(
            {name for name in choices if not name.startswith("_")},
            {"populate-sanitizers", "populate-release"},
        )


if __name__ == "__main__":
    unittest.main()
