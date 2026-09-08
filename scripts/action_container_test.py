#!/usr/bin/env python3
"""Bounded runtime-guard regressions; synthetic inspect objects, no containers."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from action_container import created_container, identifier, validate_runtime
from action_run import ActionError


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.image = "a" * 64
        self.fixture = Path("/owned/fixtures")
        self.output = Path("/owned/output")
        self.container = {
            "Image": "sha256:" + self.image,
            "Config": {"User": "1000:1000", "Env": ["PATH=/opt/codeskeptic/bin:/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "LANG=C.UTF-8"]},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapAdd": [],
                           "Memory": 6 * 1024**3, "MemorySwap": 12 * 1024**3, "PidsLimit": 256,
                           "CpuPeriod": 100000, "CpuQuota": 200000,
                           "CapDrop": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
                                       "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT"],
                           "SecurityOpt": ["no-new-privileges", "label=disable"],
                           "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=1g,mode=1777"}},
            "Mounts": [{"Type": "bind", "Source": str(self.fixture), "Destination": str(self.fixture), "RW": False},
                       {"Type": "bind", "Source": str(self.output), "Destination": "/out", "RW": True}],
        }
        self.addCleanup(patch.stopall)
        patch.object(os, "getuid", return_value=1000).start()
        patch.object(os, "getgid", return_value=1000).start()

    def check(self, data=None):
        validate_runtime(self.container if data is None else data, self.image, self.fixture, self.output)

    def reject_host(self, key, value):
        self.container["HostConfig"][key] = value
        with self.assertRaises(ActionError):
            self.check()

    def test_intended_runtime_passes(self):
        self.check()

    def test_tag_is_not_an_immutable_image_identifier(self):
        for value in ("ubuntu:24.04", "", "a" * 63, "sha256:" + "z" * 64):
            with self.subTest(value=value), self.assertRaises(ActionError):
                identifier(value)
        self.assertEqual(identifier("sha256:" + self.image), self.image)

    def test_wrong_image_is_rejected(self):
        self.container["Image"] = "b" * 64
        with self.assertRaises(ActionError):
            self.check()

    def test_network_access_is_rejected(self):
        self.reject_host("NetworkMode", "bridge")

    def test_writable_root_is_rejected(self):
        self.reject_host("ReadonlyRootfs", False)

    def test_privilege_or_capabilities_are_rejected(self):
        original = copy.deepcopy(self.container)
        for key, value in (("Privileged", True), ("CapAdd", ["SYS_ADMIN"]), ("CapDrop", []), ("SecurityOpt", [])):
            with self.subTest(key=key):
                self.container = copy.deepcopy(original)
                self.reject_host(key, value)

    def test_each_resource_limit_is_required(self):
        original = copy.deepcopy(self.container)
        for key in ("Memory", "MemorySwap", "PidsLimit", "CpuQuota", "CpuPeriod"):
            with self.subTest(key=key):
                self.container = copy.deepcopy(original)
                self.reject_host(key, 0)

    def test_root_user_is_rejected(self):
        self.container["Config"]["User"] = "0:0"
        with self.assertRaises(ActionError):
            self.check()

    def test_unbounded_executable_tmp_is_rejected(self):
        self.reject_host("Tmpfs", {"/tmp": "rw,size=8g"})

    def test_source_must_remain_read_only(self):
        self.container["Mounts"][0]["RW"] = True
        with self.assertRaises(ActionError):
            self.check()

    def test_no_extra_bind_or_named_volume(self):
        for kind in ("bind", "volume"):
            with self.subTest(kind=kind):
                data = copy.deepcopy(self.container)
                data["Mounts"].append({"Type": kind, "Destination": "/secret", "Source": "/another/path", "RW": True})
                with self.assertRaises(ActionError):
                    self.check(data)


    def test_host_secrets_and_header_overrides_are_rejected(self):
        for variable in ("GH_TOKEN=synthetic", "CPATH=/host", "LD_LIBRARY_PATH=/host"):
            with self.subTest(variable=variable):
                data = copy.deepcopy(self.container)
                data["Config"]["Env"].append(variable)
                with self.assertRaises(ActionError):
                    self.check(data)

    def test_extra_tmpfs_is_rejected_even_without_mounts_entry(self):
        self.container["HostConfig"]["Tmpfs"]["/extra-writable"] = "rw,size=8g"
        with self.assertRaises(ActionError):
            self.check()


class DockerContextTests(unittest.TestCase):
    def test_default_build_context_includes_required_cmake_script_sources(self):
        import re
        root = Path(__file__).resolve().parents[1]
        dependencies = re.findall(r'\.\./(scripts/[^\s)]+)', (root / "src/CMakeLists.txt").read_text())
        self.assertIn("scripts/corpus_compile_commands.cpp", dependencies)
        patterns = (root / ".dockerignore").read_text().splitlines()
        for dependency in dependencies:
            self.assertIn("!" + dependency, patterns)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="container lifecycle ")
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name)
        self.cid = "c" * 64

    def test_create_failure_after_cid_is_cleaned_up(self):
        for error in (1, RuntimeError("timeout"), OSError("process receipt write failed")):
            with self.subTest(error=error):
                calls = []
                def fake_run(arguments, *unused):
                    calls.append(arguments)
                    if arguments[:2] == ["podman", "create"]:
                        (self.case / "container-id").write_text(self.cid)
                        if isinstance(error, Exception):
                            raise error
                        return error
                    return 0
                with patch("action_container.run", side_effect=fake_run):
                    with self.assertRaises((ActionError, RuntimeError, OSError)):
                        with created_container(["podman", "create"], self.case, {}, self.case):
                            self.fail("failed create entered scan body")
                self.assertIn(["podman", "rm", "--force", self.cid], calls)

    def test_start_timeout_cleans_exact_owned_id(self):
        (self.case / "container-id").write_text(self.cid)
        with patch("action_container.run", return_value=0) as run:
            with self.assertRaisesRegex(RuntimeError, "start timeout"):
                with created_container(["podman", "create"], self.case, {}, self.case) as cid:
                    self.assertEqual(cid, self.cid)
                    raise RuntimeError("start timeout")
        self.assertEqual(run.call_args_list[-1].args[0], ["podman", "rm", "--force", self.cid])

    def test_cleanup_failure_remains_failure(self):
        (self.case / "container-id").write_text(self.cid)
        with patch("action_container.run", side_effect=[0, 1]):
            with self.assertRaisesRegex(ActionError, "cleanup failed"):
                with created_container(["podman", "create"], self.case, {}, self.case):
                    pass

    def test_ambiguous_id_never_triggers_broad_cleanup(self):
        (self.case / "container-id").write_text("not-an-exact-id")
        with patch("action_container.run", return_value=1) as run:
            with self.assertRaises(ActionError):
                with created_container(["podman", "create"], self.case, {}, self.case):
                    pass
        self.assertEqual(len(run.call_args_list), 1)


if __name__ == "__main__":
    unittest.main()
