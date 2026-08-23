#!/usr/bin/env python3
"""Contracts for the fixed P10-09 fault-injection evidence gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_stability_fault_injection.py"
SPEC = importlib.util.spec_from_file_location("stability_fault", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load fault-injection runner: {RUNNER}")
fault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fault)


REVISION = "a" * 40
LINUX_CONTAINMENT_AVAILABLE = (
    sys.platform.startswith("linux")
    and Path("/proc/self/stat").is_file()
)


def gtest_xml(*, reverse_suite_order: bool = False) -> str:
    suites: dict[str, list[str]] = {}
    for test in fault.REQUIRED_TESTS:
        suite, case = test.split(".", 1)
        suites.setdefault(suite, []).append(case)
    if reverse_suite_order:
        suites = dict(reversed(list(suites.items())))
    parts = ['<testsuites tests="6" failures="0" disabled="0" errors="0">']
    for suite, cases in suites.items():
        parts.append(f'<testsuite name="{suite}">')
        for case in cases:
            parts.append(
                f'<testcase name="{case}" status="run" result="completed"/>'
            )
        parts.append("</testsuite>")
    parts.append("</testsuites>")
    return "".join(parts)


def mocked_gtest(
    binary: Path, *, exit_code: int = 0, reverse_suite_order: bool = False,
) -> tuple[list[list[str]], object]:
    calls: list[list[str]] = []

    def run(
        command: list[str], root: Path, log_path: Path, timeout_seconds: int,
    ) -> int:
        del root, timeout_seconds
        if command[0] != binary.as_posix():
            raise AssertionError("fault gate executed a different binary")
        target = next(
            value.split("xml:", 1)[1]
            for value in command
            if value.startswith("--gtest_output=xml:")
        )
        Path(target).write_text(
            gtest_xml(reverse_suite_order=reverse_suite_order),
            encoding="utf-8",
        )
        log_path.write_text("[  PASSED  ] 6 tests.\n", encoding="ascii")
        calls.append(list(command))
        return exit_code

    return calls, run


def posix_gtest(
    path: Path, *, exit_code: int = 0, reverse_suite_order: bool = False,
) -> None:
    tests = json.dumps(fault.REQUIRED_TESTS)
    source = f"""#!/usr/bin/env python3
import html
import json
import pathlib
import sys

tests = json.loads({tests!r})
target = next(value.split('xml:', 1)[1] for value in sys.argv if value.startswith('--gtest_output=xml:'))
suites = {{}}
for test in tests:
    suite, case = test.split('.', 1)
    suites.setdefault(suite, []).append(case)
if {reverse_suite_order!r}:
    suites = dict(reversed(list(suites.items())))
parts = ['<testsuites tests="6" failures="0" disabled="0" errors="0">']
for suite, cases in suites.items():
    parts.append('<testsuite name="' + html.escape(suite) + '">')
    for case in cases:
        parts.append('<testcase name="' + html.escape(case) + '" status="run" result="completed"/>')
    parts.append('</testsuite>')
parts.append('</testsuites>')
pathlib.Path(target).write_text(''.join(parts), encoding='utf-8')
print('[  PASSED  ] 6 tests.')
raise SystemExit({exit_code})
"""
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


class StabilityFaultInjectionContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.binary = self.root / "codeskeptic_tests"
        self.binary.write_bytes(b"portable native-binary fixture\n")
        self.binary_sha = fault.sha256_binary(self.binary)
        self.output = self.root / "evidence"
        self.output.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_fault_identity_absent(self, identity_path: Path) -> None:
        pid_text, start_text = identity_path.read_text(
            encoding="ascii"
        ).split(":")
        pid = int(pid_text)
        start_time = int(start_text)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            identity = fault._proc_identity(pid)
            if identity is None or identity[1] != start_time:
                break
            time.sleep(0.02)
        identity = fault._proc_identity(pid)
        self.assertTrue(identity is None or identity[1] != start_time)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_cleanup_treats_zombie_leader_live_worker_as_owned(
        self,
    ) -> None:
        root_pid = 10_001
        root_start = 71
        child_pid = 10_002
        child_start = 72
        process = mock.Mock(pid=root_pid)
        process.wait.return_value = 0
        child_snapshots = iter([
            {child_pid: "Z", child_pid + 100: "R"},
            {child_pid: "Z", child_pid + 100: "T"},
        ])

        def identity(pid: int) -> tuple[int, int] | None:
            return (1, root_start) if pid == root_pid else None

        def record(pid: int) -> tuple[int, int, str] | None:
            if pid == root_pid:
                return (1, root_start, "T")
            if pid == child_pid:
                return (root_pid, child_start, "Z")
            return None

        def task_states(pid: int, start_time: int) -> dict[int, str] | None:
            del start_time
            if pid == root_pid:
                return {root_pid: "T"}
            return next(child_snapshots)

        with (
            mock.patch.object(fault, "_proc_identity", side_effect=identity),
            mock.patch.object(fault, "_proc_record", side_effect=record),
            mock.patch.object(
                fault,
                "_owned_descendants",
                side_effect=[
                    {child_pid: child_start},
                    {child_pid: child_start},
                    {},
                ],
            ),
            mock.patch.object(
                fault,
                "_proc_task_states",
                side_effect=task_states,
                create=True,
            ),
            mock.patch.object(fault, "_signal_owned") as signal_owned,
        ):
            fault._kill_owned_command(process)

        self.assertIn(
            mock.call(child_pid, child_start, fault.signal.SIGSTOP),
            signal_owned.call_args_list,
        )
        self.assertIn(
            mock.call(child_pid, child_start, fault.signal.SIGKILL),
            signal_owned.call_args_list,
        )

    @staticmethod
    def detached_fault_command(identity_path: Path) -> list[str]:
        child = "import time;time.sleep(60)"
        code = (
            "import os,pathlib,subprocess,sys;"
            "sink=open(os.devnull,'wb');"
            f"child=subprocess.Popen([sys.executable,'-c',{child!r}],"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=sink,stderr=sink,close_fds=True);"
            "fields=(pathlib.Path('/proc')/str(child.pid)/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[1],'w',encoding='ascii').write("
            "str(child.pid)+':'+fields[19])"
        )
        return [sys.executable, "-c", code, str(identity_path)]

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_selector_constructor_failure_reaps_fault_tree(self) -> None:
        identity_path = self.root / "fault-selector-ctor.identity"
        log_path = self.output / "selector-ctor.log"
        captured: list[object] = []
        real_popen = fault.subprocess.Popen

        def capture_popen(*args: object, **kwargs: object) -> object:
            process = real_popen(*args, **kwargs)
            captured.append(process)
            return process

        def fail_after_child_started() -> object:
            deadline = time.monotonic() + 2.0
            while not identity_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise OSError("fixture fault selector constructor failure")

        try:
            with (
                mock.patch.object(
                    fault.subprocess, "Popen", side_effect=capture_popen
                ),
                mock.patch.object(
                    fault.selectors,
                    "DefaultSelector",
                    side_effect=fail_after_child_started,
                ),
                self.assertRaisesRegex(
                    fault.FaultInjectionError,
                    "selector constructor failure",
                ),
            ):
                fault._run_bounded_gtest(
                    self.detached_fault_command(identity_path),
                    self.output,
                    log_path,
                    5,
                )
            self.assertTrue(identity_path.is_file())
            self.assert_fault_identity_absent(identity_path)
            self.assertTrue(captured)
            self.assertIsNotNone(captured[0].poll())
        finally:
            for process in captured:
                if process.poll() is None:
                    fault._kill_owned_command(process)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_selector_failure_before_target_spawn_cannot_release_wrapper(
        self,
    ) -> None:
        identity_path = self.root / "fault-pre-spawn.identity"
        log_path = self.output / "pre-spawn-selector.log"
        captured: list[object] = []
        real_popen = fault.subprocess.Popen
        delayed_supervisor = r"""
import os
import json
import subprocess
import sys
import time

time.sleep(0.25)
subprocess.Popen(
    json.loads(sys.argv[1]),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
    close_fds=True,
)
os._exit(0)
"""
        target = (
            "import os,pathlib,sys,time;"
            "fields=(pathlib.Path('/proc')/str(os.getpid())/'stat').read_text("
            "encoding='ascii').rsplit(')',1)[1].strip().split();"
            "open(sys.argv[1],'w',encoding='ascii').write("
            "str(os.getpid())+':'+fields[19]);time.sleep(60)"
        )

        def capture_popen(*args: object, **kwargs: object) -> object:
            process = real_popen(*args, **kwargs)
            captured.append(process)
            return process

        try:
            with (
                mock.patch.object(
                    fault, "_COMMAND_SUPERVISOR", delayed_supervisor
                ),
                mock.patch.object(
                    fault.subprocess, "Popen", side_effect=capture_popen
                ),
                mock.patch.object(
                    fault.selectors,
                    "DefaultSelector",
                    side_effect=OSError(
                        "fixture pre-spawn selector constructor failure"
                    ),
                ),
                self.assertRaisesRegex(
                    fault.FaultInjectionError,
                    "pre-spawn selector constructor failure",
                ),
            ):
                fault._run_bounded_gtest(
                    [sys.executable, "-c", target, str(identity_path)],
                    self.output,
                    log_path,
                    5,
                )
            time.sleep(0.50)
            self.assertFalse(
                identity_path.exists(),
                "stopped wrapper was resumed and launched an escaped target",
            )
            self.assertTrue(captured)
            self.assertIsNotNone(captured[0].poll())
            with self.assertRaises(ChildProcessError):
                os.waitpid(-1, os.WNOHANG)
        finally:
            if identity_path.exists():
                pid_text, start_text = identity_path.read_text(
                    encoding="ascii"
                ).split(":")
                fault._signal_owned(int(pid_text), int(start_text), fault.signal.SIGKILL)
            for process in captured:
                if process.poll() is None:
                    fault._kill_owned_command(process)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_selector_register_and_close_failures_compose_after_fault_cleanup(
        self,
    ) -> None:
        identity_path = self.root / "fault-selector-register.identity"
        log_path = self.output / "selector-register.log"
        captured: list[object] = []
        real_popen = fault.subprocess.Popen
        real_selector = fault.selectors.DefaultSelector

        def capture_popen(*args: object, **kwargs: object) -> object:
            process = real_popen(*args, **kwargs)
            captured.append(process)
            return process

        class FailingSelector:
            def __init__(self) -> None:
                self.inner = real_selector()

            def register(self, *args: object, **kwargs: object) -> None:
                del args, kwargs
                deadline = time.monotonic() + 2.0
                while (
                    not identity_path.exists()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                raise OSError("fixture fault selector register failure")

            def close(self) -> None:
                self.inner.close()
                raise OSError("fixture fault selector close failure")

        try:
            with (
                mock.patch.object(
                    fault.subprocess, "Popen", side_effect=capture_popen
                ),
                mock.patch.object(
                    fault.selectors,
                    "DefaultSelector",
                    new=FailingSelector,
                ),
                self.assertRaisesRegex(
                    fault.FaultInjectionError,
                    "register failure.*cleanup failed.*close failure",
                ),
            ):
                fault._run_bounded_gtest(
                    self.detached_fault_command(identity_path),
                    self.output,
                    log_path,
                    5,
                )
            self.assertTrue(identity_path.is_file())
            self.assert_fault_identity_absent(identity_path)
            self.assertTrue(captured)
            self.assertIsNotNone(captured[0].poll())
        finally:
            for process in captured:
                if process.poll() is None:
                    fault._kill_owned_command(process)

    def test_exact_six_faults_run_and_verify_without_mutation(self) -> None:
        calls, run = mocked_gtest(self.binary)
        with mock.patch.object(fault, "_run_bounded_gtest", side_effect=run):
            receipt = fault.run_gate(
                self.output,
                source_revision=REVISION,
                binary=self.binary,
                binary_sha256=self.binary_sha,
            )
        self.assertEqual(receipt["results"]["tests"], fault.CANONICAL_TESTS)
        self.assertEqual(calls, [[
            self.binary.as_posix(),
            f"--gtest_filter={':'.join(fault.REQUIRED_TESTS)}",
            "--gtest_color=no",
            f"--gtest_output=xml:{self.output / 'gtest.xml'}",
        ]])
        before = {
            path.name: (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.output.iterdir()
        }
        verified = fault.verify_evidence(
            self.output,
            source_revision=REVISION,
            binary=self.binary,
            binary_sha256=self.binary_sha,
        )
        after = {
            path.name: (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.output.iterdir()
        }
        self.assertEqual(verified, receipt)
        self.assertEqual(after, before)

    def test_xml_binary_and_nonzero_fail_closed(self) -> None:
        _, run = mocked_gtest(self.binary)
        with mock.patch.object(fault, "_run_bounded_gtest", side_effect=run):
            fault.run_gate(
                self.output,
                source_revision=REVISION,
                binary=self.binary,
                binary_sha256=self.binary_sha,
            )
        xml = self.output / "gtest.xml"
        xml.write_text(
            xml.read_text(encoding="utf-8").replace(
                'tests="6"', 'tests="5"', 1
            ),
            encoding="utf-8",
        )
        with self.assertRaises(fault.FaultInjectionError):
            fault.verify_evidence(
                self.output,
                source_revision=REVISION,
                binary=self.binary,
                binary_sha256=self.binary_sha,
            )

        other = self.root / "other"
        other.mkdir()
        with self.assertRaisesRegex(fault.FaultInjectionError, "checksum"):
            fault.run_gate(
                other,
                source_revision=REVISION,
                binary=self.binary,
                binary_sha256="0" * 64,
            )

        failed_binary = self.root / "failed-tests"
        failed_binary.write_bytes(b"failing native-binary fixture\n")
        failed_output = self.root / "failed-output"
        failed_output.mkdir()
        _, failed_run = mocked_gtest(failed_binary, exit_code=1)
        with (
            mock.patch.object(
                fault, "_run_bounded_gtest", side_effect=failed_run
            ),
            self.assertRaisesRegex(fault.FaultInjectionError, "returned 1"),
        ):
            fault.run_gate(
                failed_output,
                source_revision=REVISION,
                binary=failed_binary,
                binary_sha256=fault.sha256_binary(failed_binary),
            )
        self.assertFalse((failed_output / "receipt.json").exists())

    def test_large_binary_hash_is_streamed_and_bounded(self) -> None:
        large = self.root / "large-codeskeptic-tests"
        with large.open("wb") as stream:
            stream.truncate(fault.MAX_FILE_BYTES + 1)
        digest = __import__("hashlib").sha256()
        with large.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        expected = digest.hexdigest()
        with mock.patch.object(
            fault, "_read_regular", side_effect=AssertionError("must stream")
        ):
            self.assertEqual(fault.sha256_binary(large), expected)

        oversized = self.root / "oversized-codeskeptic-tests"
        with oversized.open("wb") as stream:
            stream.truncate(fault.MAX_BINARY_BYTES + 1)
        with self.assertRaisesRegex(fault.FaultInjectionError, "limit"):
            fault.sha256_binary(oversized)

    def test_low_level_regular_io_requests_binary_descriptors(self) -> None:
        sentinel = 1 << 29
        actual_open = os.open
        observed_flags: list[int] = []

        def open_without_sentinel(path, flags, mode=0o777):
            observed_flags.append(flags)
            return actual_open(path, flags & ~sentinel, mode)

        target = self.root / "binary-io.txt"
        with mock.patch.object(
            fault.os, "O_BINARY", sentinel, create=True
        ), mock.patch.object(
            fault.os, "open", side_effect=open_without_sentinel
        ):
            fault._atomic_create(target, b"line one\nline two\n")
            self.assertEqual(
                fault._read_regular(target), b"line one\nline two\n"
            )
            self.assertEqual(
                fault._sha256_regular(target, fault.MAX_FILE_BYTES),
                hashlib.sha256(b"line one\nline two\n").hexdigest(),
            )
        self.assertEqual(len(observed_flags), 3)
        self.assertTrue(all(flags & sentinel for flags in observed_flags))

    def test_xml_execution_order_may_differ_but_inventory_is_exact(self) -> None:
        reordered_binary = self.root / "reordered-codeskeptic-tests"
        reordered_binary.write_bytes(b"reordered native-binary fixture\n")
        reordered_output = self.root / "reordered-evidence"
        reordered_output.mkdir()
        _, run = mocked_gtest(reordered_binary, reverse_suite_order=True)
        with mock.patch.object(fault, "_run_bounded_gtest", side_effect=run):
            receipt = fault.run_gate(
                reordered_output,
                source_revision=REVISION,
                binary=reordered_binary,
                binary_sha256=fault.sha256_binary(reordered_binary),
            )
        self.assertEqual(receipt["results"]["tests"], fault.CANONICAL_TESTS)
        self.assertEqual(
            receipt["command"]["filter"], ":".join(fault.REQUIRED_TESTS)
        )

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_posix_direct_binary_execution_is_retained(self) -> None:
        binary = self.root / "posix-codeskeptic-tests"
        posix_gtest(binary)
        output = self.root / "posix-evidence"
        output.mkdir()
        receipt = fault.run_gate(
            output,
            source_revision=REVISION,
            binary=binary,
            binary_sha256=fault.sha256_binary(binary),
        )
        self.assertEqual(receipt["results"]["test_count"], 6)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_live_log_flood_is_killed_at_the_hard_limit(self) -> None:
        binary = self.root / "flood-tests"
        source = """#!/usr/bin/env python3
import os
while True:
    os.write(1, b'x' * 65536)
"""
        binary.write_text(source, encoding="utf-8")
        binary.chmod(0o755)
        output = self.root / "flood-evidence"
        output.mkdir()
        with (
            mock.patch.object(fault, "MAX_LOG_BYTES", 4096),
            self.assertRaisesRegex(fault.FaultInjectionError, "size limit"),
        ):
            fault.run_gate(
                output,
                source_revision=REVISION,
                binary=binary,
                binary_sha256=fault.sha256_binary(binary),
            )
        self.assertLessEqual((output / "gtest.log").stat().st_size, 4096)
        self.assertFalse((output / "receipt.json").exists())

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_live_oversize_xml_is_killed_before_hashing(self) -> None:
        binary = self.root / "oversize-xml-tests"
        source = """#!/usr/bin/env python3
import pathlib
import sys
import time
target = next(value.split('xml:', 1)[1] for value in sys.argv if value.startswith('--gtest_output=xml:'))
with pathlib.Path(target).open('wb') as stream:
    stream.truncate(8192)
time.sleep(60)
"""
        binary.write_text(source, encoding="utf-8")
        binary.chmod(0o755)
        output = self.root / "oversize-xml-evidence"
        output.mkdir()
        with (
            mock.patch.object(fault, "MAX_XML_BYTES", 4096),
            self.assertRaises(fault.FaultInjectionError),
        ):
            fault.run_gate(
                output,
                source_revision=REVISION,
                binary=binary,
                binary_sha256=fault.sha256_binary(binary),
            )
        self.assertLessEqual((output / "gtest.xml").stat().st_size, 4096)
        self.assertFalse((output / "receipt.json").exists())

    def test_evidence_file_count_is_bounded_before_verification_hashes(self) -> None:
        output = self.root / "many-files-evidence"
        output.mkdir()
        for index in range(3):
            (output / f"{index}.txt").write_text("x", encoding="ascii")
        with (
            mock.patch.object(fault, "MAX_EVIDENCE_FILES", 2),
            self.assertRaisesRegex(fault.FaultInjectionError, "file count"),
        ):
            fault._inventory(output)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_new_session_descendant_is_killed_by_standalone_timeout(self) -> None:
        binary = self.root / "detached-tests"
        pid_path = self.root / "detached.pid"
        xml = gtest_xml()
        source = f"""#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys

target = next(value.split('xml:', 1)[1] for value in sys.argv if value.startswith('--gtest_output=xml:'))
sink = open(os.devnull, 'wb')
child = subprocess.Popen(
    [sys.executable, '-c', 'import time;time.sleep(60)'],
    start_new_session=True,
    stdout=sink,
    stderr=sink,
)
fields = (pathlib.Path('/proc') / str(child.pid) / 'stat').read_text(
    encoding='ascii'
).rsplit(')', 1)[1].strip().split()
pathlib.Path({str(pid_path)!r}).write_text(
    str(child.pid) + ':' + fields[19], encoding='ascii'
)
pathlib.Path(target).write_text({xml!r}, encoding='utf-8')
"""
        binary.write_text(source, encoding="utf-8")
        binary.chmod(0o755)
        output = self.root / "detached-evidence"
        output.mkdir()
        with (
            mock.patch.object(fault, "TIMEOUT_SECONDS", 1),
            self.assertRaisesRegex(fault.FaultInjectionError, "timed out"),
        ):
            fault.run_gate(
                output,
                source_revision=REVISION,
                binary=binary,
                binary_sha256=fault.sha256_binary(binary),
            )
        pid_text, start_text = pid_path.read_text(encoding="ascii").split(":")
        pid = int(pid_text)
        start_time = int(start_text)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            identity = fault._proc_identity(pid)
            if identity is None or identity[1] != start_time:
                break
            time.sleep(0.02)
        identity = fault._proc_identity(pid)
        self.assertTrue(identity is None or identity[1] != start_time)

    @unittest.skipUnless(
        LINUX_CONTAINMENT_AVAILABLE,
        "Linux process containment unavailable",
    )
    def test_cleanup_converges_while_descendant_rapidly_forks_new_sessions(self) -> None:
        binary = self.root / "cleanup-fork-race-tests"
        pid_path = self.root / "cleanup-fork-race.pids"
        forker_pid_path = self.root / "cleanup-fork-race-parent.pid"
        forker = f"""import os,time
sink = os.open(os.devnull, os.O_WRONLY)
while True:
    pid = os.fork()
    if pid == 0:
        os.setsid()
        fields = open('/proc/self/stat', encoding='ascii').read().rsplit(")", 1)[1].strip().split()
        descriptor = os.open({str(pid_path)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(descriptor, (str(os.getpid()) + ':' + fields[19] + '\\n').encode('ascii'))
        os.fsync(descriptor)
        os.close(descriptor)
        time.sleep(60)
        os._exit(0)
    time.sleep(0.01)
"""
        source = f"""#!/usr/bin/env python3
import os
import subprocess
import sys
import time

forker = subprocess.Popen(
    [sys.executable, '-c', {forker!r}],
    start_new_session=True,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)
with open({str(forker_pid_path)!r}, 'w', encoding='ascii') as stream:
    stream.write(str(forker.pid))
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(60)
"""
        binary.write_text(source, encoding="utf-8")
        binary.chmod(0o755)
        output = self.root / "cleanup-fork-race-evidence"
        output.mkdir()
        observed: list[tuple[int, int]] = []
        real_signal = fault._signal_owned
        stop_calls: dict[int, int] = {}

        def delayed_second_stop(
            pid: int, start_time: int, signal_number: int,
        ) -> None:
            if signal_number == fault.signal.SIGSTOP and forker_pid_path.exists():
                forker_pid = int(forker_pid_path.read_text(encoding="ascii"))
                if pid == forker_pid:
                    stop_calls[pid] = stop_calls.get(pid, 0) + 1
                    if stop_calls[pid] == 1:
                        return
                    if stop_calls[pid] == 2:
                        # Force children to appear after the cleanup snapshot
                        # but before this descendant becomes uninterruptibly
                        # stopped. A fixed two-snapshot cleanup misses them.
                        time.sleep(0.10)
            real_signal(pid, start_time, signal_number)

        try:
            with (
                mock.patch.object(fault, "TIMEOUT_SECONDS", 1),
                mock.patch.object(
                    fault, "_signal_owned", side_effect=delayed_second_stop
                ),
                self.assertRaisesRegex(fault.FaultInjectionError, "timed out"),
            ):
                fault.run_gate(
                    output,
                    source_revision=REVISION,
                    binary=binary,
                    binary_sha256=fault.sha256_binary(binary),
                )
            observed = [
                tuple(map(int, value.split(":")))
                for value in pid_path.read_text(encoding="ascii").splitlines()
            ]
            self.assertGreaterEqual(len(observed), 10)
            deadline = time.monotonic() + 2.0
            while (
                any(
                    (identity := fault._proc_identity(pid)) is not None
                    and identity[1] == start_time
                    for pid, start_time in observed
                )
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            survivors = [
                (pid, start_time)
                for pid, start_time in observed
                if (
                    (identity := fault._proc_identity(pid)) is not None
                    and identity[1] == start_time
                )
            ]
            self.assertEqual(survivors, [])
        finally:
            for pid, start_time in observed:
                fault._signal_owned(pid, start_time, fault.signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
