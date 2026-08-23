#!/usr/bin/env python3
"""Hermetic contracts for the release-candidate mirror authority producer."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_realworld_campaign.py"
PRODUCER = ROOT / "scripts" / "seal_realworld_mirror.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaign = load_module("mirror_test_campaign", RUNNER)
producer = load_module("mirror_authority_producer", PRODUCER)
LINUX_SUBREAPER_AVAILABLE = (
    sys.platform.startswith("linux")
    and Path("/proc").is_dir()
    and campaign._enable_subreaper()
)


def git(repository: Path, *arguments: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "CodeSkeptic fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "CodeSkeptic fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git failed ({result.returncode}): {' '.join(arguments)}\n{result.stderr}"
        )
    return result.stdout.strip()


def initialize_repository(root: Path, name: str, upstream: str) -> Path:
    repository = root / name
    repository.mkdir()
    git(repository, "init", "--quiet", "--initial-branch=main")
    git(repository, "remote", "add", "origin", upstream)
    (repository / "payload.txt").write_text(f"{name}\n", encoding="utf-8")
    git(repository, "add", "payload.txt")
    git(repository, "commit", "--quiet", "-m", "fixture")
    return repository


def add_submodule(
    parent: Path,
    child: Path,
    path: str,
    upstream: str,
) -> None:
    git(
        parent,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "--quiet",
        str(child),
        path,
    )
    modules = parent / ".gitmodules"
    git(
        parent,
        "config",
        "--file",
        str(modules),
        f"submodule.{path}.url",
        upstream,
    )
    git(parent, "add", ".gitmodules", path)
    git(parent, "commit", "--quiet", "-m", f"add {path}")


def project(project_id: str, repository: str, revision: str, checkout: dict) -> dict:
    return {
        "id": project_id,
        "label": "fixture",
        "repository": repository,
        "revision": revision,
        "checkout": checkout,
        "timeout_minutes": 20,
        "memory_mb": 4096,
        "commands": {
            "configure": [
                [
                    "cmake",
                    "-S",
                    "{source}",
                    "-B",
                    "{build}",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                ]
            ],
            "build": [["cmake", "--build", "{build}"]],
        },
        "copies": [],
        "compile_database": "{build}/compile_commands.json",
        "sources": {
            "roots": ["src"],
            "extensions": [".c"],
            "fallback_globs": [],
        },
        "analyzer_args": ["--report-paths", "{source}/src"],
        "expected": {
            "translation_units": 1,
            "translation_unit_sha256": "a" * 64,
            "attempted_tus": 1,
            "analyzed_tus": 1,
            "broken_tus": 0,
            "incomplete_functions": 0,
            "findings": 0,
            "exit_code": 0,
            "fingerprint_sha256": campaign.digest_json([]),
        },
    }


def empty_checkout() -> dict:
    return {
        "submodules": "none",
        "expected_count": 0,
        "expected_sha256": campaign.digest_json([]),
    }


def make_fixture(root: Path) -> tuple[Path, dict[str, Path], dict[str, str]]:
    urls = {
        "root": "https://github.com/codeskeptic-fixtures/root.git",
        "child": "https://github.com/codeskeptic-fixtures/child.git",
        "grand": "https://github.com/codeskeptic-fixtures/grand.git",
        "plain": "https://github.com/codeskeptic-fixtures/plain.git",
        "excluded": "https://github.com/codeskeptic-fixtures/excluded.git",
    }
    grand = initialize_repository(root, "grand", urls["grand"])
    child = initialize_repository(root, "child", urls["child"])
    add_submodule(child, grand, "nested/grand", "../grand.git")
    main = initialize_repository(root, "root", urls["root"])
    add_submodule(main, child, "deps/child", "../child.git")
    plain = initialize_repository(root, "plain", urls["plain"])
    excluded = initialize_repository(root, "excluded", urls["excluded"])

    revisions = {
        "root": git(main, "rev-parse", "HEAD"),
        "child": git(child, "rev-parse", "HEAD"),
        "grand": git(grand, "rev-parse", "HEAD"),
        "plain": git(plain, "rev-parse", "HEAD"),
        "excluded": git(excluded, "rev-parse", "HEAD"),
    }
    submodule_identity = [
        {"path": "deps/child", "revision": revisions["child"]},
        {
            "path": "deps/child/nested/grand",
            "revision": revisions["grand"],
        },
    ]
    recursive = {
        "submodules": "recursive",
        "expected_count": len(submodule_identity),
        "expected_sha256": campaign.digest_json(submodule_identity),
    }
    manifest = {
        "schema": 1,
        "campaigns": {
            "release-candidate": {
                "window_minutes": 4320,
                "repetitions": 3,
                "projects": ["root", "plain"],
            },
            "nightly": {
                "window_minutes": 720,
                "repetitions": 3,
                "projects": ["excluded"],
            },
        },
        "projects": [
            project("root", urls["root"], revisions["root"], recursive),
            project("plain", urls["plain"], revisions["plain"], empty_checkout()),
            project(
                "excluded",
                urls["excluded"],
                revisions["excluded"],
                empty_checkout(),
            ),
        ],
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(campaign.canonical_bytes(manifest) + b"\n")
    sources = {
        urls["root"]: main,
        urls["child"]: child,
        urls["grand"]: grand,
        urls["plain"]: plain,
    }
    return manifest_path, sources, revisions


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            try:
                path.chmod(0o755 if path.is_dir() else 0o644)
            except FileNotFoundError:
                pass


@unittest.skipUnless(
    LINUX_SUBREAPER_AVAILABLE,
    "mirror production requires Linux /proc subreaper containment",
)
class MirrorAuthorityProducerTest(unittest.TestCase):
    def setUp(self) -> None:
        reserve = mock.patch.object(producer, "EMERGENCY_RESERVE_BYTES", 1 << 20)
        reserve.start()
        self.addCleanup(reserve.stop)
        free_floor = mock.patch.object(
            producer, "MIN_SEAL_FILESYSTEM_FREE_BYTES", 1 << 20
        )
        free_floor.start()
        self.addCleanup(free_floor.stop)
        file_limit = mock.patch.object(
            producer, "MAX_GIT_CREATED_FILE_BYTES", 1 << 20
        )
        file_limit.start()
        self.addCleanup(file_limit.stop)
        shard_reserve = mock.patch.object(
            campaign, "SHARD_EMERGENCY_RESERVE_BYTES", 1 << 20
        )
        shard_reserve.start()
        self.addCleanup(shard_reserve.stop)
        shard_free_floor = mock.patch.object(
            campaign, "MIN_SHARD_FILESYSTEM_FREE_BYTES", 1 << 20
        )
        shard_free_floor.start()
        self.addCleanup(shard_free_floor.stop)
        shard_file_limit = mock.patch.object(
            campaign, "MAX_PROCESS_FILE_BYTES", 1 << 20
        )
        shard_file_limit.start()
        self.addCleanup(shard_file_limit.stop)

    def test_git_runner_uses_absolute_binary_closed_environment_and_bounded_output(self) -> None:
        environment = producer._git_environment("file")
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        with mock.patch.object(producer, "MAX_GIT_OUTPUT_BYTES", 1):
            with self.assertRaisesRegex(producer.SealError, "safety limit"):
                producer._git(["version"])

    def test_git_tree_inventory_has_a_dedicated_bounded_stdout_cap(self) -> None:
        empty_hash = producer._git(
            ["hash-object", "--stdin"], stdout_limit_bytes=41
        )
        self.assertEqual(len(empty_hash), 41)
        with self.assertRaisesRegex(producer.SealError, "stdout.*safety limit"):
            producer._git(["hash-object", "--stdin"], stdout_limit_bytes=40)

        revision = "1" * 40
        payload = f"160000 commit {revision}\tdeps/example\0".encode("ascii")
        with mock.patch.object(producer, "_git", return_value=payload) as invoke:
            self.assertEqual(
                producer._gitlinks(Path("repository"), revision, 5),
                {"deps/example": revision},
            )
        self.assertEqual(
            invoke.call_args.kwargs["stdout_limit_bytes"],
            producer.MAX_TREE_LIST_BYTES,
        )

    def test_git_output_flood_terminates_and_reaps_its_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            pid_path = workspace / "child.pid"
            flood = workspace / "flood.sh"
            flood.write_text(
                "#!/usr/bin/python3\nimport os,time\n"
                "pid=os.fork()\n"
                "if pid == 0:\n"
                f" os.setsid(); os.close(1); os.close(2); open('{pid_path}','w').write(str(os.getpid())); time.sleep(30)\n"
                "time.sleep(.05)\n"
                "while True: os.write(1,b'0123456789abcdef')\n",
                encoding="utf-8",
            )
            flood.chmod(0o755)
            with mock.patch.object(producer, "MAX_GIT_OUTPUT_BYTES", 4096):
                with self.assertRaisesRegex(producer.SealError, "safety limit"):
                    producer._git(["-c", f"alias.flood=!{flood}", "flood"])
            self.assertTrue(pid_path.is_file())
            pid = int(pid_path.read_text(encoding="ascii"))
            for _ in range(50):
                if not Path(f"/proc/{pid}").exists():
                    break
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_git_commands_share_one_absolute_deadline(self) -> None:
        token = producer._GIT_DEADLINE.set(time.monotonic() + 0.05)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(producer.SealError, "global deadline"):
                producer._git(["-c", "alias.pause=!sleep 30", "pause"])
        finally:
            producer._GIT_DEADLINE.reset(token)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_git_rejects_a_preexisting_direct_child_without_killing_it(self) -> None:
        unrelated = subprocess.Popen(["/usr/bin/sleep", "30"])
        try:
            with self.assertRaisesRegex(producer.SealError, "pre-existing child"):
                producer._git(["version"])
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)

    def test_selector_setup_failure_reaps_git_leader(self) -> None:
        captured: list[subprocess.Popen] = []
        real_popen = producer.subprocess.Popen

        def recording_popen(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        leaked = False
        try:
            with (
                mock.patch.object(
                    producer.subprocess, "Popen", side_effect=recording_popen
                ),
                mock.patch.object(
                    producer.selectors,
                    "DefaultSelector",
                    side_effect=RuntimeError("selector setup failed"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "selector setup"):
                    producer._git(["-c", "alias.pause=!exec sleep 30", "pause"])
            self.assertEqual(len(captured), 1)
            leaked = captured[0].poll() is None
        finally:
            if captured and captured[0].poll() is None:
                os.killpg(captured[0].pid, signal.SIGKILL)
                captured[0].wait(timeout=2)
            campaign._child_table_empty()
        self.assertFalse(leaked)
        self.assertTrue(campaign._child_table_empty())

    def test_selector_close_failure_preserves_primary_and_closes_pipes(self) -> None:
        real_selector = producer.selectors.DefaultSelector

        class CloseFailureSelector:
            def __init__(self) -> None:
                self.inner = real_selector()

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def close(self) -> None:
                self.inner.close()
                raise OSError("selector close failed")

        captured: list[subprocess.Popen] = []
        real_popen = producer.subprocess.Popen

        def recording_popen(*arguments, **keywords):
            process = real_popen(*arguments, **keywords)
            captured.append(process)
            return process

        with (
            mock.patch.object(
                producer.subprocess, "Popen", side_effect=recording_popen
            ),
            mock.patch.object(
                producer.selectors,
                "DefaultSelector",
                side_effect=CloseFailureSelector,
            ),
            mock.patch.object(producer, "MAX_GIT_OUTPUT_BYTES", 1),
        ):
            with self.assertRaisesRegex(
                producer.SealError,
                "safety limit; cleanup failed: Git selector",
            ):
                producer._git(
                    ["-c", "alias.flood=!printf 0123456789", "flood"]
                )
        self.assertEqual(len(captured), 1)
        self.assertIsNotNone(captured[0].poll())
        self.assertTrue(captured[0].stdout.closed)
        self.assertTrue(captured[0].stderr.closed)
        self.assertTrue(campaign._child_table_empty())

    def test_reserve_release_retries_delayed_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = mock.Mock(f_bavail=1 << 20, f_frsize=1)
            below_floor = mock.Mock(f_bavail=0, f_frsize=1)
            delayed = root / "delayed"
            delayed.mkdir()
            with (
                producer._bounded_git_workspace(delayed),
                mock.patch.object(
                    producer.os,
                    "fstatvfs",
                    side_effect=[below_floor, recovered],
                ) as probe,
                mock.patch.object(producer.time, "sleep") as pause,
            ):
                producer._release_git_emergency_reserve()
                self.assertEqual(probe.call_count, 2)
                pause.assert_called_once()

            never = root / "never"
            never.mkdir()
            with (
                mock.patch.object(producer, "RESERVE_RECOVERY_TIMEOUT_SECONDS", 0),
                producer._bounded_git_workspace(never),
                mock.patch.object(
                    producer.os, "fstatvfs", return_value=below_floor
                ),
            ):
                with self.assertRaisesRegex(producer.SealError, "recover"):
                    producer._release_git_emergency_reserve()

    def test_bundle_creation_is_hard_limited_while_git_is_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = "https://github.com/codeskeptic-fixtures/bounded.git"
            source = initialize_repository(root, "bounded-source", upstream)
            revision = git(source, "rev-parse", "HEAD")
            tree = git(source, "rev-parse", "HEAD^{tree}")
            bounded = root / "bounded-workspace"
            sealed = bounded / "sealed"
            scratch = bounded / "scratch"
            bounded.mkdir()
            sealed.mkdir()
            scratch.mkdir()
            with producer._bounded_git_workspace(bounded):
                with mock.patch.object(producer, "MAX_BUNDLE_BYTES", 128):
                    with self.assertRaises(producer.SealError):
                        producer._build_bundle(
                            upstream,
                            {"repository": source, "revisions": {revision: tree}},
                            sealed,
                            scratch,
                            5,
                        )
            destination = sealed / producer._bundle_name(upstream)
            if destination.exists():
                self.assertLessEqual(destination.stat().st_size, 128)

    def test_workspace_multi_file_growth_is_stopped_after_pipes_close(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bounded = root / "bounded-workspace"
            bounded.mkdir()
            payloads = bounded / "payloads"
            pid_path = bounded / "writer.pid"
            writer = root / "multi-file-writer.py"
            writer.write_text(
                "#!/usr/bin/python3\nimport os,pathlib,time\n"
                f"root=pathlib.Path('{payloads}'); root.mkdir(); "
                f"pathlib.Path('{pid_path}').write_text(str(os.getpid())); "
                "os.close(1); os.close(2)\n"
                "for index in range(10000):\n"
                " fd=os.open(root / str(index),os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600); "
                "os.posix_fallocate(fd,0,4096); os.close(fd); time.sleep(.002)\n",
                encoding="utf-8",
            )
            writer.chmod(0o755)
            before = producer._workspace_allocated_bytes(bounded)
            with mock.patch.object(
                producer, "MAX_SEAL_WORKSPACE_ALLOCATED_BYTES", 128 << 10
            ), mock.patch.object(
                producer, "MIN_SEAL_FILESYSTEM_FREE_BYTES", 1 << 20
            ):
                with producer._bounded_git_workspace(bounded):
                    with self.assertRaisesRegex(producer.SealError, "workspace allocation"):
                        producer._git(
                            ["-c", f"alias.spread=!{writer}", "spread"],
                            timeout_seconds=3,
                            file_size_limit_bytes=1 << 20,
                        )
                    reserve = producer._GIT_RESERVE_STATE.get()
                    self.assertIsNotNone(reserve)
                    pid = int(pid_path.read_text(encoding="ascii"))
                    self.assertFalse(Path(f"/proc/{pid}").exists())
                    self.assertIsNone(reserve["reserve"])
                    capacity = os.fstatvfs(reserve["probe"])
                    self.assertGreaterEqual(
                        capacity.f_bavail * capacity.f_frsize,
                        producer.MIN_SEAL_FILESYSTEM_FREE_BYTES,
                    )
                    stable_allocation = producer._workspace_allocated_bytes(bounded)
                    time.sleep(0.05)
                    self.assertEqual(
                        producer._workspace_allocated_bytes(bounded), stable_allocation
                    )
            self.assertTrue(pid_path.is_file())
            pid = int(pid_path.read_text(encoding="ascii"))
            self.assertFalse(Path(f"/proc/{pid}").exists())
            growth = producer._workspace_allocated_bytes(bounded) - before
            self.assertLess(growth, 4 << 20)

    def test_workspace_reserve_and_private_tmp_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                producer.shutil,
                "disk_usage",
                return_value=mock.Mock(
                    free=producer.MIN_SEAL_FILESYSTEM_FREE_BYTES - 1
                ),
            ):
                with self.assertRaisesRegex(producer.SealError, "free-space reserve"):
                    with producer._bounded_git_workspace(root):
                        pass
            private_root = root / "private"
            private_root.mkdir()
            with mock.patch.object(producer, "MIN_SEAL_FILESYSTEM_FREE_BYTES", 0):
                with producer._bounded_git_workspace(private_root):
                    self.assertEqual(
                        producer._git_environment("file")["TMPDIR"],
                        os.fspath(private_root / "tmp"),
                    )

    def test_successful_git_leader_cannot_leave_a_closed_pipe_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            pid_path = workspace / "detached.pid"
            pgid_path = workspace / "detached.pgid"
            launcher = workspace / "launcher.sh"
            launcher.write_text(
                "#!/usr/bin/python3\nimport os,time\n"
                "pid=os.fork()\n"
                "if pid == 0:\n"
                f" os.setsid(); os.close(1); os.close(2); open('{pid_path}','w').write(str(os.getpid())); open('{pgid_path}','w').write(str(os.getpgrp())); time.sleep(30)\n"
                "time.sleep(.05)\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            with self.assertRaisesRegex(producer.SealError, "descendant"):
                producer._git(["-c", f"alias.launch=!{launcher}", "launch"])
            pid = int(pid_path.read_text(encoding="ascii"))
            pgid = int(pgid_path.read_text(encoding="ascii"))
            for _ in range(50):
                if not Path(f"/proc/{pid}").exists():
                    break
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{pid}").exists())
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)

    def test_git_timeout_reaps_detached_inherited_pipe_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            pid_path = workspace / "timeout.pid"
            launcher = workspace / "timeout.py"
            launcher.write_text(
                "#!/usr/bin/python3\nimport os,time\n"
                "pid=os.fork()\n"
                "if pid == 0:\n"
                f" os.setsid(); open('{pid_path}','w').write(str(os.getpid())); time.sleep(30)\n"
                "time.sleep(.05)\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            token = producer._GIT_DEADLINE.set(time.monotonic() + 0.2)
            try:
                with self.assertRaisesRegex(producer.SealError, "deadline"):
                    producer._git(["-c", f"alias.escape=!{launcher}", "escape"])
            finally:
                producer._GIT_DEADLINE.reset(token)
            pid = int(pid_path.read_text(encoding="ascii"))
            for _ in range(100):
                if not Path(f"/proc/{pid}").exists():
                    break
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_repository_local_fsmonitor_and_ambient_template_cannot_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            repository = initialize_repository(
                workspace,
                "hostile-config",
                "https://github.com/codeskeptic-fixtures/hostile.git",
            )
            marker = workspace / "executed"
            hook = workspace / "fsmonitor-hook"
            hook.write_text(
                f"#!/bin/sh\nprintf owned > {marker}\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            git(repository, "config", "core.fsmonitor", str(hook))
            producer._git(["-C", str(repository), "status", "--porcelain"])
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        LINUX_SUBREAPER_AVAILABLE,
        "real runner adapter requires Linux /proc subreaper containment",
    )
    def test_sealer_to_real_run_adapter_uses_the_published_offline_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            upstream = "https://github.com/codeskeptic-fixtures/adapter.git"
            source = initialize_repository(workspace, "adapter", upstream)
            (source / "src").mkdir()
            (source / "src" / "main.c").write_text(
                "int main(void) { return 0; }\n", encoding="utf-8"
            )
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(adapter C)\nadd_executable(adapter src/main.c)\n",
                encoding="utf-8",
            )
            git(source, "add", "CMakeLists.txt", "src/main.c")
            git(source, "commit", "--quiet", "-m", "buildable fixture")
            revision = git(source, "rev-parse", "HEAD")
            record = project("adapter", upstream, revision, empty_checkout())
            record["expected"]["translation_unit_sha256"] = campaign.translation_unit_digest(
                ["src/main.c"]
            )
            manifest = {
                "schema": 1,
                "campaigns": {
                    "release-candidate": {
                        "window_minutes": 4320,
                        "repetitions": 3,
                        "projects": ["adapter"],
                    }
                },
                "projects": [record],
            }
            manifest_path = workspace / "adapter-manifest.json"
            manifest_path.write_bytes(campaign.canonical_bytes(manifest) + b"\n")
            output = workspace / "authority-layout" / "mirrors"
            output.parent.mkdir()
            self.addCleanup(make_writable, output)
            authority_path = producer.seal_mirror_authority(
                manifest_path, output, sources={upstream: source}
            )
            analyzer = workspace / "fixture-analyzer.py"
            analyzer.write_text(
                "#!/usr/bin/python3\n"
                "import json, pathlib, sys\n"
                "args=sys.argv; report=pathlib.Path(args[args.index('--json')+1]); "
                "files=pathlib.Path(args[args.index('--files')+1]).read_text().splitlines(); "
                "timeout=int(args[args.index('--tu-timeout-seconds')+1]); "
                "memory=int(args[args.index('--tu-memory-mib')+1]); "
                "rows=[{'path':p,'compile_command_sha256':'1'*64,'command_ordinal':0,"
                "'phase':'analysis','status':'completed','duration_ms':1,"
                "'peak_memory_kib':1,'timeout_seconds':timeout,'memory_mib':memory,"
                "'origin':'executed','checkpoint_key_sha256':'','payload_sha256':''} for p in files]; "
                "report.write_text(json.dumps({'complete':True,'exit_code':0,'total':0,"
                "'coverage':{'attempted_tus':1,'analyzed_tus':1,'broken_tus':0,"
                "'incomplete_functions':0},'diagnostics':[],'translation_units':rows}))\n",
                encoding="utf-8",
            )
            analyzer.chmod(0o755)
            normalized = campaign.validate_manifest(manifest)
            receipt = workspace / "run" / "receipt.json"
            status = campaign.run_shard(
                normalized,
                "adapter",
                1,
                analyzer,
                workspace / "shard-work",
                receipt,
                None,
                ROOT,
                authority_path,
            )
            self.assertEqual(status, 0, receipt.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(receipt.read_text())["status"], "accepted")

    @unittest.skipUnless(
        LINUX_SUBREAPER_AVAILABLE,
        "offline consumer requires Linux /proc subreaper containment",
    )
    def test_consumer_rejects_bundle_path_replacement_after_checksum_before_git_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            output = workspace / "sealed"
            self.addCleanup(make_writable, output)
            authority_path = producer.seal_mirror_authority(
                manifest_path, output, sources=sources
            )
            manifest = campaign.validate_manifest(campaign.load_manifest(manifest_path))
            selected, selected_root = campaign.load_mirror_authority(
                authority_path, manifest, "plain"
            )
            bundle = output / selected["bundle"]
            original = bundle.read_bytes()
            real_run = campaign._run_command
            replaced = False

            def replace_before_fetch(command, *arguments, **keywords):
                nonlocal replaced
                if not replaced and "fetch" in command:
                    replaced = True
                    replacement = workspace / "replacement.bundle"
                    replacement.write_bytes(original)
                    replacement.chmod(0o444)
                    output.chmod(0o755)
                    bundle.parent.chmod(0o755)
                    os.replace(replacement, bundle)
                    bundle.parent.chmod(0o555)
                    output.chmod(0o555)
                return real_run(command, *arguments, **keywords)

            with mock.patch.object(
                campaign, "_run_command", side_effect=replace_before_fetch
            ):
                with self.assertRaisesRegex(campaign.EvidenceError, "changed while in use"):
                    campaign._checkout_project(
                        campaign.project_by_id(manifest, "plain"),
                        workspace / "checkout",
                        time.monotonic() + 30.0,
                        workspace / "checkout.log",
                        selected,
                        selected_root,
                    )
            self.assertTrue(replaced)

    def test_seals_exact_tier_and_recursive_submodules_as_offline_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, revisions = make_fixture(workspace)
            output = workspace / "sealed"
            self.addCleanup(make_writable, output)

            authority_path = producer.seal_mirror_authority(
                manifest_path,
                output,
                tier="release-candidate",
                sources=sources,
                fetch_online=False,
            )

            encoded = authority_path.read_bytes()
            authority = json.loads(encoded)
            normalized = campaign.validate_manifest(
                campaign.load_manifest(manifest_path)
            )
            self.assertEqual(encoded, campaign.canonical_bytes(authority) + b"\n")
            self.assertEqual(
                authority_path.with_suffix(".json.sha256").read_text(encoding="ascii"),
                f"{campaign.digest_bytes(encoded)}  authority.json\n",
            )
            self.assertEqual(authority["manifest_sha256"], campaign.digest_json(normalized))
            self.assertEqual(
                [entry["id"] for entry in authority["projects"]],
                ["root", "plain"],
            )
            self.assertNotIn("excluded", {entry["id"] for entry in authority["projects"]})

            root_record = authority["projects"][0]
            self.assertEqual(root_record["revision"], revisions["root"])
            self.assertEqual(
                [
                    {"path": entry["path"], "revision": entry["revision"]}
                    for entry in root_record["submodules"]
                ],
                [
                    {"path": "deps/child", "revision": revisions["child"]},
                    {
                        "path": "deps/child/nested/grand",
                        "revision": revisions["grand"],
                    },
                ],
            )
            self.assertEqual(
                [entry["repository"] for entry in root_record["submodules"]],
                [
                    "https://github.com/codeskeptic-fixtures/child.git",
                    "https://github.com/codeskeptic-fixtures/grand.git",
                ],
            )
            records = [
                record
                for item in authority["projects"]
                for record in (item, *item["submodules"])
            ]
            self.assertEqual(len({record["repository"] for record in records}), 4)
            self.assertEqual(len({record["bundle"] for record in records}), 4)
            for record in records:
                bundle = output / record["bundle"]
                self.assertEqual(campaign.file_digest(bundle), record["bundle_sha256"])
                self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o444)
                bare = workspace / f"verify-{record['revision']}"
                git(workspace, "init", "--bare", "--quiet", str(bare))
                git(
                    workspace,
                    "--git-dir",
                    str(bare),
                    "-c",
                    "protocol.file.allow=always",
                    "fetch",
                    "--quiet",
                    str(bundle),
                    record["revision"],
                )
                self.assertEqual(
                    git(workspace, "--git-dir", str(bare), "rev-parse", "FETCH_HEAD^{tree}"),
                    record["tree"],
                )

            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((output / "bundles").stat().st_mode), 0o555)
            for project_id in ("root", "plain"):
                selected, selected_root = campaign.load_mirror_authority(
                    authority_path, normalized, project_id
                )
                self.assertEqual(selected["id"], project_id)
                self.assertEqual(selected_root, output.absolute())

            if not LINUX_SUBREAPER_AVAILABLE:
                return
            for source in sources.values():
                source.rename(workspace / f"retired-{source.name}")
            selected, selected_root = campaign.load_mirror_authority(
                authority_path, normalized, "root"
            )
            checked_out = campaign._checkout_project(
                campaign.project_by_id(normalized, "root"),
                workspace / "offline-checkout",
                time.monotonic() + 60.0,
                workspace / "offline-checkout.log",
                selected,
                selected_root,
            )
            self.assertEqual(
                checked_out,
                campaign._expected_submodules(
                    campaign.project_by_id(normalized, "root")
                ),
            )

    def test_missing_source_never_falls_back_to_network_and_leaves_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            sources.pop("https://github.com/codeskeptic-fixtures/grand.git")
            output = workspace / "sealed"
            with mock.patch.object(producer, "_clone_online") as online:
                with self.assertRaisesRegex(producer.SealError, "source mapping"):
                    producer.seal_mirror_authority(
                        manifest_path,
                        output,
                        sources=sources,
                        fetch_online=False,
                    )
            online.assert_not_called()
            self.assertFalse(output.exists())

    def test_rejects_manifest_submodule_drift_unused_sources_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)

            drifted = json.loads(manifest_path.read_text(encoding="utf-8"))
            drifted["projects"][0]["checkout"]["expected_sha256"] = "f" * 64
            drifted_path = workspace / "drifted.json"
            drifted_path.write_bytes(campaign.canonical_bytes(drifted) + b"\n")
            with self.assertRaisesRegex(producer.SealError, "submodule identity"):
                producer.seal_mirror_authority(
                    drifted_path,
                    workspace / "drifted-output",
                    sources=sources,
                )
            self.assertFalse((workspace / "drifted-output").exists())

            unused = dict(sources)
            unused["https://github.com/codeskeptic-fixtures/unused.git"] = sources[
                "https://github.com/codeskeptic-fixtures/plain.git"
            ]
            with self.assertRaisesRegex(producer.SealError, "unused source"):
                producer.seal_mirror_authority(
                    manifest_path,
                    workspace / "unused-output",
                    sources=unused,
                )
            self.assertFalse((workspace / "unused-output").exists())

            existing = workspace / "existing"
            existing.mkdir()
            marker = existing / "marker"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(producer.SealError, "already exists"):
                producer.seal_mirror_authority(
                    manifest_path,
                    existing,
                    sources=sources,
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_online_fetch_requires_an_explicit_mode_and_cannot_mix_local_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            with self.assertRaisesRegex(producer.SealError, "mutually exclusive"):
                producer.seal_mirror_authority(
                    manifest_path,
                    workspace / "mixed",
                    sources=sources,
                    fetch_online=True,
                )
            with self.assertRaisesRegex(producer.SealError, "release-candidate"):
                producer.seal_mirror_authority(
                    manifest_path,
                    workspace / "wrong-tier",
                    tier="nightly",
                    sources={
                        "https://github.com/codeskeptic-fixtures/excluded.git": workspace / "excluded"
                    },
                )

    def test_revision_drift_fails_before_any_authority_is_published(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            drifted = json.loads(manifest_path.read_text(encoding="utf-8"))
            drifted["projects"][1]["revision"] = "1" * 40
            drifted_path = workspace / "revision-drift.json"
            drifted_path.write_bytes(campaign.canonical_bytes(drifted) + b"\n")
            output = workspace / "sealed"
            with self.assertRaisesRegex(producer.SealError, "revision"):
                producer.seal_mirror_authority(
                    drifted_path,
                    output,
                    sources=sources,
                )
            self.assertFalse(output.exists())

    def test_one_upstream_bundle_carries_every_distinct_pinned_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root_url = "https://github.com/codeskeptic-fixtures/multi-root.git"
            child_url = "https://github.com/codeskeptic-fixtures/multi-child.git"
            child = initialize_repository(workspace, "multi-child", child_url)
            first = git(child, "rev-parse", "HEAD")
            root = initialize_repository(workspace, "multi-root", root_url)
            add_submodule(root, child, "deps/first", child_url)
            (child / "payload.txt").write_text("second\n", encoding="utf-8")
            git(child, "add", "payload.txt")
            git(child, "commit", "--quiet", "-m", "second")
            second = git(child, "rev-parse", "HEAD")
            add_submodule(root, child, "deps/second", child_url)
            root_revision = git(root, "rev-parse", "HEAD")
            identity = [
                {"path": "deps/first", "revision": first},
                {"path": "deps/second", "revision": second},
            ]
            manifest = {
                "schema": 1,
                "campaigns": {
                    "release-candidate": {
                        "window_minutes": 4320,
                        "repetitions": 3,
                        "projects": ["multi-root"],
                    }
                },
                "projects": [
                    project(
                        "multi-root",
                        root_url,
                        root_revision,
                        {
                            "submodules": "recursive",
                            "expected_count": 2,
                            "expected_sha256": campaign.digest_json(identity),
                        },
                    )
                ],
            }
            manifest_path = workspace / "multi-manifest.json"
            manifest_path.write_bytes(campaign.canonical_bytes(manifest) + b"\n")
            output = workspace / "multi-sealed"
            self.addCleanup(make_writable, output)
            authority_path = producer.seal_mirror_authority(
                manifest_path,
                output,
                sources={root_url: root, child_url: child},
            )
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            submodules = authority["projects"][0]["submodules"]
            self.assertEqual(submodules[0]["bundle"], submodules[1]["bundle"])
            self.assertEqual(
                submodules[0]["bundle_sha256"], submodules[1]["bundle_sha256"]
            )
            heads = git(
                workspace,
                "bundle",
                "list-heads",
                str(output / submodules[0]["bundle"]),
            ).splitlines()
            self.assertEqual(
                heads,
                [
                    f"{revision} refs/codeskeptic/revisions/{revision}"
                    for revision in sorted((first, second))
                ],
            )

    def test_atomic_publication_never_replaces_a_concurrent_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "destination"
            source.mkdir()
            destination.mkdir()
            marker = destination / "marker"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(producer.SealError, "already exists"):
                producer._rename_noreplace(source, destination)
            self.assertTrue(source.is_dir())
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_cli_requires_explicit_sources_and_publishes_the_same_authority(self) -> None:
        self.assertIn(
            "OUTPUT/authority.json", producer.build_parser().format_help()
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            output = workspace / "cli-sealed"
            self.addCleanup(make_writable, output)
            arguments = [
                "--manifest",
                str(manifest_path),
                "--output",
                str(output),
            ]
            for upstream, source in sorted(sources.items()):
                arguments.extend(["--source", f"{upstream}={source}"])
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = producer.main(arguments)
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertEqual(
                stdout.getvalue(),
                f"CODESKEPTIC_REALWORLD_MIRROR_SEALED {output / 'authority.json'}\n",
            )
            self.assertTrue((output / "authority.json.sha256").is_file())

    def test_failed_final_verification_removes_the_unpublished_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            output = workspace / "failed-final"
            real_loader = producer.campaign.load_mirror_authority
            calls = 0

            def reject_after_move(*arguments, **keywords):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise producer.campaign.EvidenceError("forced final rejection")
                return real_loader(*arguments, **keywords)

            with mock.patch.object(
                producer.campaign,
                "load_mirror_authority",
                side_effect=reject_after_move,
            ):
                with self.assertRaisesRegex(producer.SealError, "published authority"):
                    producer.seal_mirror_authority(
                        manifest_path,
                        output,
                        sources=sources,
                    )
            self.assertFalse(output.exists())
            self.assertEqual(list(workspace.glob(".failed-final.mirror-work-*")), [])

    def test_post_rename_fsync_failure_rolls_back_and_reports_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            output = workspace / "failed-fsync"
            real_fsync = producer._fsync_directory
            publication_failed = False

            def fail_publication_and_parent(path: Path) -> None:
                nonlocal publication_failed
                if path == output:
                    publication_failed = True
                    raise producer.SealError("forced publication sync failure")
                if path == workspace and publication_failed:
                    raise producer.SealError("forced rollback sync failure")
                real_fsync(path)

            with mock.patch.object(
                producer, "_fsync_directory", side_effect=fail_publication_and_parent
            ):
                with self.assertRaisesRegex(
                    producer.SealError,
                    "forced publication sync failure.*rollback failed.*rollback sync failure",
                ):
                    producer.seal_mirror_authority(
                        manifest_path, output, sources=sources
                    )
            self.assertFalse(output.exists())

    def test_rollback_never_deletes_a_replaced_publication_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            output = workspace / "replaced-output"
            stolen = workspace / "producer-output"
            real_fsync = producer._fsync_directory
            replaced = False

            def replace_after_rename(path: Path) -> None:
                nonlocal replaced
                if path == output and not replaced:
                    replaced = True
                    output.rename(stolen)
                    output.mkdir()
                    (output / "preserve").write_text("foreign\n", encoding="utf-8")
                    raise producer.SealError("forced post-rename failure")
                real_fsync(path)

            with mock.patch.object(
                producer, "_fsync_directory", side_effect=replace_after_rename
            ):
                with self.assertRaisesRegex(
                    producer.SealError, "rollback failed.*identity changed"
                ):
                    producer.seal_mirror_authority(
                        manifest_path, output, sources=sources
                    )
            self.assertTrue(replaced)
            self.assertEqual(
                (output / "preserve").read_text(encoding="utf-8"), "foreign\n"
            )
            make_writable(stolen)
            make_writable(output)

    def test_rejects_gitmodules_authority_supplied_only_by_external_include(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            root = sources["https://github.com/codeskeptic-fixtures/root.git"]
            external = workspace / "external-submodule.config"
            external.write_text(
                "[untrusted]\n\tvalue = outside-the-commit\n",
                encoding="utf-8",
            )
            (root / ".gitmodules").write_text(
                "[submodule \"deps/child\"]\n"
                "\tpath = deps/child\n"
                "\turl = ../child.git\n"
                f"[include]\n\tpath = {external}\n",
                encoding="utf-8",
            )
            git(root, "add", ".gitmodules")
            git(root, "commit", "--quiet", "-m", "external include")
            manifest["projects"][0]["revision"] = git(root, "rev-parse", "HEAD")
            manifest_path.write_bytes(campaign.canonical_bytes(manifest) + b"\n")
            output = workspace / "external-include-output"
            try:
                with self.assertRaisesRegex(
                    producer.SealError,
                    "gitmodules|submodule entries|exactly match",
                ):
                    producer.seal_mirror_authority(
                        manifest_path,
                        output,
                        sources=sources,
                    )
            finally:
                make_writable(output)

    def test_repository_local_tree_replacement_cannot_forge_submodule_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest_path, sources, _ = make_fixture(workspace)
            root_url = "https://github.com/codeskeptic-fixtures/root.git"
            child_url = "https://github.com/codeskeptic-fixtures/child.git"
            alternate_url = (
                "https://github.com/codeskeptic-fixtures/alternate-child.git"
            )
            root = sources[root_url]
            child = sources.pop(child_url)
            sources[alternate_url] = child
            original_tree = git(root, "rev-parse", "HEAD^{tree}")
            git(
                root,
                "config",
                "--file",
                str(root / ".gitmodules"),
                "submodule.deps/child.url",
                alternate_url,
            )
            git(root, "add", ".gitmodules")
            replacement_tree = git(root, "write-tree")
            git(root, "reset", "--hard", "--quiet", "HEAD")
            git(root, "replace", original_tree, replacement_tree)
            output = workspace / "tree-replace-output"
            try:
                with self.assertRaisesRegex(producer.SealError, "source mapping"):
                    producer.seal_mirror_authority(
                        manifest_path,
                        output,
                        sources=sources,
                    )
            finally:
                make_writable(output)


if __name__ == "__main__":
    unittest.main()
