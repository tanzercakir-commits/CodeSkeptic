#!/usr/bin/env python3
"""Bounded runtime-guard regressions; synthetic inspect objects, no containers."""
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from action_container import identifier, validate_runtime
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


if __name__ == "__main__":
    unittest.main()
