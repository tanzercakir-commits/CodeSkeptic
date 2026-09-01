#!/usr/bin/env python3
"""Fail-closed contracts for the separate passwordless P10-09 launcher."""

from __future__ import annotations

import grp
import hashlib
import importlib.util
import io
import json
import os
import pwd
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LAUNCH = ROOT / "scripts" / "stability-launch"
BROKER = LAUNCH / "launch-broker.py"
CLIENT = LAUNCH / "launch-client.py"
INSTALLER = LAUNCH / "install-launch-broker.py"
README = LAUNCH / "README.md"

CAMPAIGN_SOCKET = LAUNCH / "codeskeptic-p10-09-campaign.socket.in"
CAMPAIGN_SERVICE = LAUNCH / "codeskeptic-p10-09-campaign@.service"
PROBE_SOCKET = LAUNCH / "codeskeptic-p10-09-probe.socket.in"
PROBE_SERVICE = LAUNCH / "codeskeptic-p10-09-probe@.service"
TIMEOUT_DROPIN = LAUNCH / "timeout-stop-terminate.conf"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


class StabilityLaunchPresenceTest(unittest.TestCase):
    def test_separate_launch_subsystem_sources_exist(self) -> None:
        for path in (
            BROKER,
            CLIENT,
            INSTALLER,
            README,
            CAMPAIGN_SOCKET,
            CAMPAIGN_SERVICE,
            PROBE_SOCKET,
            PROBE_SERVICE,
            TIMEOUT_DROPIN,
        ):
            self.assertTrue(path.is_file(), f"missing launch source: {path}")


@unittest.skipUnless(BROKER.is_file(), "launch broker is the RED gap")
class StabilityLaunchBrokerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.broker = load_module("codeskeptic_launch_broker", BROKER)

    def test_kernel_peer_credentials_and_empty_half_close_are_mandatory(self) -> None:
        client, server = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        try:
            client.shutdown(socket.SHUT_WR)
            peer = self.broker.authorize_connection(
                server,
                expected_path=None,
                authorized_uid=os.getuid(),
                payload_timeout=0.2,
            )
            self.assertEqual(peer.uid, os.getuid())
            self.assertGreater(peer.pid, 0)
        finally:
            client.close()
            server.close()

        client, server = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        try:
            client.send(b"")
            with self.assertRaisesRegex(
                self.broker.BrokerError,
                "did not half-close",
            ):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid(),
                    payload_timeout=0.05,
                )
        finally:
            client.close()
            server.close()

    def test_wrong_uid_stream_socket_and_any_payload_are_rejected(self) -> None:
        client, server = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        try:
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(self.broker.BrokerError):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid() + 1,
                    payload_timeout=0.2,
                )
        finally:
            client.close()
            server.close()

        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(self.broker.BrokerError):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid(),
                    payload_timeout=0.2,
                )
        finally:
            client.close()
            server.close()

        for payload in (b"\x00", b"campaign\n", b"{}"):
            client, server = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            try:
                client.send(payload)
                client.shutdown(socket.SHUT_WR)
                with self.assertRaises(self.broker.BrokerError):
                    self.broker.authorize_connection(
                        server,
                        expected_path=None,
                        authorized_uid=os.getuid(),
                        payload_timeout=0.2,
                    )
            finally:
                client.close()
                server.close()

        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertEqual(client.send(b""), 0)
            client.sendall(b"forbidden")
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(self.broker.BrokerError):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid(),
                    payload_timeout=0.2,
                )
        finally:
            client.close()
            server.close()

        client, server = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        try:
            with self.assertRaises(self.broker.BrokerError):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid(),
                    payload_timeout=0.05,
                )
        finally:
            client.close()
            server.close()

        client, server = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        read_fd, write_fd = os.pipe()
        try:
            client.sendmsg(
                [b"x"],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", read_fd))],
            )
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(self.broker.BrokerError):
                self.broker.authorize_connection(
                    server,
                    expected_path=None,
                    authorized_uid=os.getuid(),
                    payload_timeout=0.2,
                )
        finally:
            os.close(read_fd)
            os.close(write_fd)
            client.close()
            server.close()

    def test_fixed_mode_builds_one_argv_and_scrubbed_environment(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.broker.OperatorIdentity(
            uid=account.pw_uid,
            user=account.pw_name,
            gid=account.pw_gid,
            group=grp.getgrgid(account.pw_gid).gr_name,
        )
        campaign = self.broker.guided_invocation("campaign", identity)
        probe = self.broker.guided_invocation("probe", identity)
        guided = "/opt/codeskeptic-p10-09/operator/guided-stability.sh"
        self.assertEqual(campaign.argv, (guided, "--root"))
        self.assertEqual(probe.argv, (guided, "--root", "--probe-only"))
        self.assertEqual(campaign.environment["SUDO_UID"], str(identity.uid))
        self.assertEqual(campaign.environment["SUDO_USER"], identity.user)
        self.assertEqual(
            set(campaign.environment),
            {
                "HOME",
                "LANG",
                "LC_ALL",
                "LOGNAME",
                "PATH",
                "SUDO_GID",
                "SUDO_UID",
                "SUDO_USER",
                "USER",
            },
        )
        with self.assertRaises(self.broker.BrokerError):
            self.broker.guided_invocation("cleanup", identity)

    def test_effective_systemd_authority_binds_actual_instance_and_socket(
        self,
    ) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.broker.OperatorIdentity(
            uid=account.pw_uid,
            user=account.pw_name,
            gid=account.pw_gid,
            group=grp.getgrgid(account.pw_gid).gr_name,
        )
        unit_root = Path("/authority/systemd")
        instance = "codeskeptic-p10-09-campaign@1-42.service"

        def runner(argv: list[str], *, foreign_dropin: bool = False):
            if argv[1:2] == ["whoami"]:
                return subprocess.CompletedProcess(
                    argv, 0, f"{instance}\n".encode("ascii"), b""
                )
            fields = [
                value.split("=", 1)[1]
                for value in argv
                if value.startswith("--property=")
            ]
            name = argv[-1]
            if name == instance:
                service_name = "codeskeptic-p10-09-campaign@.service"
                dropin = str(
                    unit_root / f"{service_name}.d" / "10-timeout-abort.conf"
                )
                if foreign_dropin:
                    dropin += " /run/systemd/system/foreign.conf"
                properties = {
                    "Id": instance,
                    "LoadState": "loaded",
                    "FragmentPath": str(unit_root / service_name),
                    "DropInPaths": dropin,
                    "ExecStart": (
                        "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 "
                        "-I -B /opt/codeskeptic-p10-09-launch/"
                        "launch-broker.py campaign ; ignore_errors=no ; "
                        "start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; "
                        "code=(null) ; status=0/0 }"
                    ),
                    "ExecStartPre": "",
                    "ExecCondition": "",
                    "ExecStartPost": "",
                    "ExecReload": "",
                    "ExecStop": "",
                    "ExecStopPost": "",
                    "User": "root",
                    "Group": "root",
                    "StandardInput": "socket",
                    "StandardOutput": "journal",
                    "StandardError": "journal",
                    "RefuseManualStart": "yes",
                    "IgnoreOnIsolate": "yes",
                    "RuntimeDirectory": "codeskeptic-p10-09",
                    "RuntimeDirectoryMode": "0700",
                    "RuntimeDirectoryPreserve": "yes",
                    "RuntimeMaxUSec": "16min",
                    "TimeoutStopFailureMode": "terminate",
                }
            else:
                properties = {
                    "Id": "codeskeptic-p10-09-campaign.socket",
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "listening",
                    "FragmentPath": str(
                        unit_root / "codeskeptic-p10-09-campaign.socket"
                    ),
                    "DropInPaths": "",
                    "Listen": (
                        "/run/codeskeptic-p10-09-launch/campaign.sock "
                        "(Stream)"
                    ),
                    "SocketUser": "root",
                    "SocketGroup": identity.group,
                    "SocketMode": "0660",
                    "Accept": "yes",
                    "AcceptFileDescriptors": "no",
                    "IgnoreOnIsolate": "yes",
                }
            output = "".join(
                f"{field}={properties[field]}\n" for field in fields
            ).encode("utf-8")
            return subprocess.CompletedProcess(argv, 0, output, b"")

        self.broker.verify_effective_systemd_authority(
            "campaign",
            identity,
            pid=42,
            runner=runner,
            unit_root=unit_root,
        )
        with self.assertRaises(self.broker.BrokerError):
            self.broker.verify_effective_systemd_authority(
                "campaign",
                identity,
                pid=42,
                runner=lambda argv: runner(argv, foreign_dropin=True),
                unit_root=unit_root,
            )


@unittest.skipUnless(CLIENT.is_file(), "launch client is the RED gap")
class StabilityLaunchClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = load_module("codeskeptic_launch_client", CLIENT)

    def test_client_sends_nothing_and_accepts_one_bounded_bound_result(self) -> None:
        account = pwd.getpwuid(os.getuid())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            path = root / "campaign.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(path))
            os.chmod(path, 0o660)
            listener.listen(1)
            observed: list[bytes] = []

            def serve() -> None:
                connection, _address = listener.accept()
                try:
                    observed.append(connection.recv(1))
                    connection.sendall(b"CODESKEPTIC_LAUNCH_")
                    connection.sendall(b"RESULT_V1 campaign 0")
                finally:
                    connection.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            output = io.BytesIO()
            try:
                result = self.client.run_client(
                    "campaign",
                    socket_path=path,
                    expected_parent_uid=os.getuid(),
                    expected_parent_gid=os.getgid(),
                    expected_socket_uid=os.getuid(),
                    expected_socket_gid=account.pw_gid,
                    expected_mode=0o660,
                    expected_server_uid=os.getuid(),
                    output=output,
                    timeout=2.0,
                )
            finally:
                listener.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(observed, [b""])
            self.assertEqual(result, 0)
            self.assertIn(b"campaign accepted", output.getvalue())

    def test_runtime_parent_and_socket_have_separate_owner_contracts(self) -> None:
        account = pwd.getpwuid(os.getuid())
        path = Path("/run/codeskeptic-p10-09-launch/campaign.sock")
        parent_metadata = mock.Mock(
            st_mode=stat.S_IFDIR | 0o755,
            st_uid=0,
            st_gid=0,
        )
        socket_metadata = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o660,
            st_nlink=1,
            st_uid=0,
            st_gid=account.pw_gid,
        )

        def lstat(candidate: Path):
            return parent_metadata if candidate == path.parent else socket_metadata

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat):
            self.client._verify_socket_path(
                path,
                expected_parent_uid=0,
                expected_parent_gid=0,
                expected_socket_uid=0,
                expected_socket_gid=account.pw_gid,
                expected_mode=0o660,
            )
            with self.assertRaises(self.client.ClientError):
                self.client._verify_socket_path(
                    path,
                    expected_parent_uid=0,
                    expected_parent_gid=account.pw_gid,
                    expected_socket_uid=0,
                    expected_socket_gid=account.pw_gid,
                    expected_mode=0o660,
                )

    def test_client_rejects_empty_record_without_server_half_close(self) -> None:
        account = pwd.getpwuid(os.getuid())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            path = root / "campaign.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(path))
            os.chmod(path, 0o660)
            listener.listen(1)
            release = threading.Event()

            def serve() -> None:
                connection, _address = listener.accept()
                try:
                    connection.recv(1)
                    connection.send(
                        b"CODESKEPTIC_LAUNCH_RESULT_V1 campaign 0"
                    )
                    connection.send(b"")
                    release.wait(1.0)
                finally:
                    connection.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(
                    self.client.ClientError,
                    "did not close its result",
                ):
                    self.client.run_client(
                        "campaign",
                        socket_path=path,
                        expected_parent_uid=os.getuid(),
                        expected_parent_gid=os.getgid(),
                        expected_socket_uid=os.getuid(),
                        expected_socket_gid=account.pw_gid,
                        expected_mode=0o660,
                        expected_server_uid=os.getuid(),
                        output=io.BytesIO(),
                        timeout=0.05,
                    )
            finally:
                release.set()
                listener.close()
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())

    def test_client_rejects_wrong_mode_trailing_and_ancillary_results(self) -> None:
        account = pwd.getpwuid(os.getuid())

        def exercise(sender) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o755)
                path = root / "campaign.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(os.fspath(path))
                os.chmod(path, 0o660)
                listener.listen(1)

                def serve() -> None:
                    connection, _address = listener.accept()
                    try:
                        connection.recv(1)
                        sender(connection)
                    finally:
                        connection.close()

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    with self.assertRaises(self.client.ClientError):
                        self.client.run_client(
                            "campaign",
                            socket_path=path,
                            expected_parent_uid=os.getuid(),
                            expected_parent_gid=os.getgid(),
                            expected_socket_uid=os.getuid(),
                            expected_socket_gid=account.pw_gid,
                            expected_mode=0o660,
                            expected_server_uid=os.getuid(),
                            output=io.BytesIO(),
                            timeout=2.0,
                        )
                finally:
                    listener.close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

        exercise(
            lambda connection: connection.send(
                b"CODESKEPTIC_LAUNCH_RESULT_V1 probe 0"
            )
        )

        def trailing(connection) -> None:
            connection.send(b"CODESKEPTIC_LAUNCH_RESULT_V1 campaign 0")
            self.assertEqual(connection.send(b""), 0)
            connection.send(b"extra")

        exercise(trailing)

        def ancillary(connection) -> None:
            read_fd, write_fd = os.pipe()
            try:
                connection.sendmsg(
                    [b"CODESKEPTIC_LAUNCH_RESULT_V1 campaign 0"],
                    [(
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        struct.pack("i", read_fd),
                    )],
                )
            finally:
                os.close(read_fd)
                os.close(write_fd)

        exercise(ancillary)


@unittest.skipUnless(
    all(
        path.is_file()
        for path in (
            CAMPAIGN_SOCKET,
            CAMPAIGN_SERVICE,
            PROBE_SOCKET,
            PROBE_SERVICE,
        )
    ),
    "fixed launch units are the RED gap",
)
class StabilityLaunchUnitTest(unittest.TestCase):
    def test_socket_templates_are_distinct_group_bound_seqpacket_endpoints(self) -> None:
        expected = (
            (CAMPAIGN_SOCKET, CAMPAIGN_SERVICE, "campaign"),
            (PROBE_SOCKET, PROBE_SERVICE, "probe"),
        )
        for socket_unit, service_unit, mode in expected:
            socket_text = socket_unit.read_text(encoding="utf-8")
            service_text = service_unit.read_text(encoding="utf-8")
            self.assertEqual(socket_text.count("ListenStream="), 1)
            self.assertNotIn("ListenSequentialPacket=", socket_text)
            self.assertIn("SocketUser=root", socket_text)
            self.assertIn("SocketGroup=@OPERATOR_GROUP@", socket_text)
            self.assertIn("SocketMode=0660", socket_text)
            self.assertIn("Accept=yes", socket_text)
            self.assertIn("AcceptFileDescriptors=no", socket_text)
            self.assertNotIn("Service=", socket_text)
            self.assertIn("Backlog=1", socket_text)
            self.assertIn("MaxConnections=1", socket_text)
            self.assertIn("MaxConnectionsPerSource=1", socket_text)
            self.assertIn("RemoveOnStop=yes", socket_text)
            self.assertIn("TriggerLimitIntervalSec=0", socket_text)
            self.assertIn("PollLimitIntervalSec=2s", socket_text)
            self.assertIn("PollLimitBurst=4", socket_text)
            self.assertIn("WantedBy=sockets.target", socket_text)

            self.assertIn("User=root", service_text)
            self.assertIn("CollectMode=inactive-or-failed", service_text)
            self.assertIn("RefuseManualStart=yes", service_text)
            self.assertIn("IgnoreOnIsolate=yes", service_text)
            self.assertIn("StandardInput=socket", service_text)
            self.assertIn("StandardOutput=journal", service_text)
            self.assertIn("StandardError=journal", service_text)
            self.assertIn("RuntimeDirectory=codeskeptic-p10-09", service_text)
            self.assertIn("RuntimeDirectoryMode=0700", service_text)
            self.assertIn("RuntimeDirectoryPreserve=yes", service_text)
            self.assertIn(
                "/usr/bin/python3 -I -B "
                "/opt/codeskeptic-p10-09-launch/launch-broker.py "
                f"{mode}",
                service_text,
            )
            self.assertNotIn("/bin/sh", service_text)
            self.assertNotIn("%i", service_text)
            self.assertNotIn("%I", service_text)

    def test_core_guided_contract_is_not_modified(self) -> None:
        guided = (
            ROOT
            / "scripts"
            / "stability-systemd"
            / "guided-stability.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'exec /usr/bin/sudo -- "$GUIDED_PATH" --root', guided
        )
        self.assertNotIn("codeskeptic-p10-09-launch", guided)

    @unittest.skipUnless(
        Path("/usr/bin/systemd-analyze").is_file(),
        "systemd-analyze is unavailable",
    )
    def test_rendered_units_pass_systemd_analyze_verify(self) -> None:
        installer = load_module(
            "codeskeptic_launch_installer_for_units", INSTALLER
        )
        account = pwd.getpwuid(os.getuid())
        identity = installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths: list[str] = []
            for source in (
                CAMPAIGN_SOCKET,
                CAMPAIGN_SERVICE,
                PROBE_SOCKET,
                PROBE_SERVICE,
            ):
                name = source.name.removesuffix(".in")
                destination = root / name
                data = source.read_bytes()
                if source.suffix == ".in":
                    data = installer.render_socket_unit(data, identity.group)
                destination.write_bytes(data)
                paths.append(str(destination))
            completed = subprocess.run(
                ["/usr/bin/systemd-analyze", "verify", *paths],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


@unittest.skipUnless(INSTALLER.is_file(), "launch installer is the RED gap")
class StabilityLaunchInstallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_module("codeskeptic_launch_installer", INSTALLER)
        cls.broker = load_module(
            "codeskeptic_launch_broker_for_installer", BROKER
        )

    def test_operator_identity_is_bound_to_uid_gid_user_and_group(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        self.assertEqual(identity.uid, account.pw_uid)
        self.assertEqual(identity.user, account.pw_name)
        self.assertEqual(identity.gid, account.pw_gid)
        self.assertTrue(identity.group)
        with self.assertRaises(self.installer.InstallError):
            self.installer.resolve_operator_identity(
                account.pw_uid + 1, account.pw_name
            )

    def test_socket_template_rendering_changes_only_exact_group_token(self) -> None:
        rendered = self.installer.render_socket_unit(
            CAMPAIGN_SOCKET.read_bytes(), "tanzer"
        )
        self.assertNotIn(b"@OPERATOR_GROUP@", rendered)
        self.assertIn(b"SocketGroup=tanzer\n", rendered)
        with self.assertRaises(self.installer.InstallError):
            self.installer.render_socket_unit(
                CAMPAIGN_SOCKET.read_bytes() + b"@OPERATOR_GROUP@", "tanzer"
            )

    def test_unit_validators_reject_any_extra_root_command_or_service(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        rendered = self.installer.render_socket_unit(
            CAMPAIGN_SOCKET.read_bytes(), identity.group
        )
        with self.assertRaises(self.installer.InstallError):
            self.installer._validate_socket_unit(
                rendered + b"Service=foreign-root@.service\n",
                self.installer.CAMPAIGN_SOCKET_NAME,
                identity,
            )
        with self.assertRaises(self.installer.InstallError):
            self.installer._validate_service_unit(
                CAMPAIGN_SERVICE.read_bytes() + b"ExecStartPre=/usr/bin/id\n",
                self.installer.CAMPAIGN_SERVICE_NAME,
            )

    def test_parser_rejects_unimplemented_update_and_revoke(self) -> None:
        for command in ("update", "revoke"):
            with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
                self.installer.build_parser().parse_args([command])

    def _layout(self, root: Path):
        root.chmod(0o755)
        install_parent = root / "opt"
        unit_root = root / "etc/systemd/system"
        install_parent.mkdir(parents=True)
        unit_root.mkdir(parents=True)
        (root / "etc").chmod(0o755)
        (root / "etc/systemd").chmod(0o755)
        core_install_root = install_parent / "codeskeptic-p10-09"
        operator_root = core_install_root / "operator"
        installation_root = core_install_root / "installation"
        operator_root.mkdir(parents=True)
        installation_root.mkdir()
        guided = operator_root / "guided-stability.sh"
        guided.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        guided.chmod(0o555)
        var_root = root / "var"
        var_lib_root = var_root / "lib"
        core_root = var_lib_root / "codeskeptic-p10-09"
        core_root.mkdir(parents=True)
        var_root.chmod(0o755)
        var_lib_root.chmod(0o755)
        core_root.chmod(0o700)
        core_authority = core_root / "installation-authority.json"
        core_authority.write_bytes(
            self.installer._canonical_document(
                {
                    "bundle_receipt_sha256": "b" * 64,
                    "bundle_revision": "a" * 40,
                    "schema": "codeskeptic-stability-installation-authority-v1",
                }
            )
        )
        core_authority.chmod(0o400)
        core_producer = operator_root / "stage_stability_campaign.py"
        core_producer.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        core_producer.chmod(0o555)
        core_receipt = installation_root / "receipt.json"
        core_receipt.write_text("{}\n", encoding="utf-8")
        core_receipt.chmod(0o400)
        core_install_root.chmod(0o555)
        operator_root.chmod(0o555)
        installation_root.chmod(0o500)
        return self.installer.Layout(
            install_root=install_parent / "codeskeptic-p10-09-launch",
            unit_root=unit_root,
            activation_root=unit_root / "sockets.target.wants",
            guided_path=guided,
            core_authority_path=core_authority,
            core_producer_path=core_producer,
            core_receipt_path=core_receipt,
            install_lock_path=root / "launch-install.lock",
            runtime_root=root / "run/codeskeptic-p10-09-launch",
        )

    def _runner(
        self,
        layout,
        identity,
        *,
        commands: list[list[str]] | None = None,
        fail_start: bool = False,
        preexisting_active: bool = False,
    ):
        active = preexisting_active

        def create_runtime_nodes() -> None:
            layout.runtime_root.mkdir(parents=True, exist_ok=True, mode=0o755)
            layout.runtime_root.chmod(0o755)
            for mode in ("campaign", "probe"):
                path = layout.runtime_root / f"{mode}.sock"
                endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    endpoint.bind(os.fspath(path))
                finally:
                    endpoint.close()
                path.chmod(0o660)

        if preexisting_active:
            create_runtime_nodes()

        def runner(argv: list[str]):
            nonlocal active
            if commands is not None:
                commands.append(argv)
            if argv[0:2] == ["/usr/bin/systemctl", "start"]:
                if fail_start:
                    raise self.installer.InstallError("injected start failure")
                create_runtime_nodes()
                active = True
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0:2] == ["/usr/bin/systemctl", "stop"]:
                active = False
                for mode in ("campaign", "probe"):
                    path = layout.runtime_root / f"{mode}.sock"
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0:2] == ["/usr/bin/systemctl", "list-units"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[0:2] != ["/usr/bin/systemctl", "show"]:
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            fields = [
                value.split("=", 1)[1]
                for value in argv
                if value.startswith("--property=")
            ]
            name = argv[-1]
            if name in self.installer.SOCKET_NAMES:
                loaded = active or (layout.unit_root / name).is_file()
                mode = (
                    "campaign"
                    if name == self.installer.CAMPAIGN_SOCKET_NAME
                    else "probe"
                )
                properties = {
                    "LoadState": "loaded" if loaded else "not-found",
                    "ActiveState": "active" if active else "inactive",
                    "SubState": "listening" if active else "dead",
                    "FragmentPath": str(layout.unit_root / name) if loaded else "",
                    "DropInPaths": "",
                    "UnitFileState": (
                        "enabled"
                        if (layout.activation_root / name).is_symlink()
                        else "disabled"
                    ),
                    "Listen": (
                        f"/run/codeskeptic-p10-09-launch/{mode}.sock "
                        "(Stream)"
                    ),
                    "SocketUser": "root",
                    "SocketGroup": identity.group,
                    "SocketMode": "0660",
                    "DirectoryMode": "0755",
                    "Accept": "yes",
                    "AcceptFileDescriptors": "no",
                    "Backlog": "1",
                    "MaxConnections": "1",
                    "MaxConnectionsPerSource": "1",
                    "RemoveOnStop": "yes",
                    "IgnoreOnIsolate": "yes",
                }
            else:
                mode = "campaign" if "campaign" in name else "probe"
                template = (
                    self.installer.CAMPAIGN_SERVICE_NAME
                    if mode == "campaign"
                    else self.installer.PROBE_SERVICE_NAME
                )
                properties = {
                    "LoadState": "loaded",
                    "FragmentPath": str(layout.unit_root / template),
                    "DropInPaths": str(
                        layout.unit_root
                        / f"{template}.d"
                        / self.installer.TIMEOUT_DROPIN_NAME
                    ),
                    "UnitFileState": "static",
                    "ExecStart": (
                        "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 "
                        "-I -B /opt/codeskeptic-p10-09-launch/"
                        f"launch-broker.py {mode} ; ignore_errors=no ; "
                        "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
                        "code=(null) ; status=0/0 }"
                    ),
                    "ExecStartPre": "",
                    "ExecCondition": "",
                    "ExecStartPost": "",
                    "ExecReload": "",
                    "ExecStop": "",
                    "ExecStopPost": "",
                    "User": "root",
                    "Group": "root",
                    "StandardInput": "socket",
                    "StandardOutput": "journal",
                    "StandardError": "journal",
                    "RefuseManualStart": "yes",
                    "IgnoreOnIsolate": "yes",
                    "RuntimeDirectory": "codeskeptic-p10-09",
                    "RuntimeDirectoryMode": "0700",
                    "RuntimeDirectoryPreserve": "yes",
                    "RuntimeMaxUSec": "16min",
                    "TimeoutStopFailureMode": "terminate",
                }
            output = "".join(
                f"{field}={properties[field]}\n" for field in fields
            ).encode("utf-8")
            return subprocess.CompletedProcess(argv, 0, output, b"")

        return runner

    def test_install_lock_rejects_a_concurrent_writer_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            with self.installer._exclusive_install_lock(
                layout, os.getuid(), os.getgid()
            ):
                with self.assertRaises(self.installer.InstallError):
                    with self.installer._exclusive_install_lock(
                        layout, os.getuid(), os.getgid()
                    ):
                        self.fail("a second installer acquired the fixed lock")
            self.assertFalse(layout.install_root.exists())

    def test_install_lock_setup_failure_removes_and_fsyncs_new_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            with (
                mock.patch.object(
                    self.installer.os,
                    "fchown",
                    side_effect=OSError("injected lock fchown failure"),
                ),
                mock.patch.object(
                    self.installer,
                    "_fsync_directory",
                    wraps=self.installer._fsync_directory,
                ) as fsync,
                self.assertRaises(self.installer.InstallError),
            ):
                with self.installer._exclusive_install_lock(
                    layout, os.getuid(), os.getgid()
                ):
                    self.fail("failed lock setup yielded authority")

            self.assertFalse(layout.install_lock_path.exists())
            self.assertEqual(
                [call.args[0] for call in fsync.call_args_list],
                [layout.install_lock_path.parent],
            )

    def test_install_lock_is_held_during_first_inode_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            setup_entered = threading.Event()
            setup_release = threading.Event()
            creator_outcome: list[str] = []
            real_fchown = os.fchown

            def blocking_fchown(descriptor, uid, gid):
                # Production installers are root and can open the mode-000
                # bootstrap inode.  Let the same-UID test peer model that
                # capability while the creator is already holding flock.
                os.fchmod(descriptor, 0o600)
                setup_entered.set()
                if not setup_release.wait(2.0):
                    raise OSError("test did not release lock setup")
                return real_fchown(descriptor, uid, gid)

            def creator() -> None:
                try:
                    with self.installer._exclusive_install_lock(
                        layout, os.getuid(), os.getgid()
                    ):
                        creator_outcome.append("yielded")
                except BaseException as error:
                    creator_outcome.append(f"failed:{error}")

            with mock.patch.object(
                self.installer.os,
                "fchown",
                side_effect=blocking_fchown,
            ):
                thread = threading.Thread(target=creator)
                thread.start()
                try:
                    self.assertTrue(setup_entered.wait(2.0))
                    with self.assertRaisesRegex(
                        self.installer.InstallError,
                        "another launch installation is active",
                    ):
                        with self.installer._exclusive_install_lock(
                            layout, os.getuid(), os.getgid()
                        ):
                            self.fail("second installer entered during setup")
                finally:
                    setup_release.set()
                    thread.join(timeout=3.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(creator_outcome, ["yielded"])

    def test_duplicate_systemd_property_output_is_rejected(self) -> None:
        def runner(argv: list[str]):
            return subprocess.CompletedProcess(
                argv, 0, b"LoadState=loaded\nLoadState=loaded\n", b""
            )

        with self.assertRaises(self.installer.InstallError):
            self.installer._systemctl_properties(
                runner, "fixed.socket", ("LoadState",)
            )

    def test_rollback_preserves_a_foreign_child_and_refuses_tree_removal(
        self,
    ) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            base = self._runner(layout, identity, fail_start=True)
            injected = False

            def runner(argv: list[str]):
                nonlocal injected
                if (
                    argv[0:2] == ["/usr/bin/systemctl", "daemon-reload"]
                    and layout.install_root.is_dir()
                    and not injected
                ):
                    layout.install_root.chmod(0o755)
                    (layout.install_root / "foreign").write_bytes(b"foreign\n")
                    layout.install_root.chmod(0o555)
                    injected = True
                return base(argv)

            with self.assertRaisesRegex(
                self.installer.InstallError, "rollback incomplete"
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertEqual(
                (layout.install_root / "foreign").read_bytes(), b"foreign\n"
            )
            self.assertTrue((layout.install_root / "receipt.json").is_file())

    def test_rollback_fsyncs_each_mutated_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "parent"
            directory = parent / "created"
            parent.mkdir()
            directory.mkdir()
            payload = directory / "payload"
            payload.write_bytes(b"payload\n")
            link = directory / "link"
            os.symlink("payload", link)
            directory_metadata = directory.lstat()
            payload_metadata = payload.lstat()
            link_metadata = link.lstat()
            nodes = [
                self.installer.CreatedNode(
                    directory,
                    directory_metadata.st_dev,
                    directory_metadata.st_ino,
                    "directory",
                ),
                self.installer.CreatedNode(
                    payload,
                    payload_metadata.st_dev,
                    payload_metadata.st_ino,
                    "file",
                ),
                self.installer.CreatedNode(
                    link,
                    link_metadata.st_dev,
                    link_metadata.st_ino,
                    "symlink",
                    "payload",
                ),
            ]

            with mock.patch.object(
                self.installer,
                "_fsync_directory",
                wraps=self.installer._fsync_directory,
            ) as fsync:
                failures = self.installer._rollback(nodes)

            self.assertEqual(failures, [])
            self.assertFalse(directory.exists())
            self.assertEqual(
                [call.args[0] for call in fsync.call_args_list],
                [directory, directory, parent],
            )

    def test_fresh_install_fsyncs_new_activation_parent_entry(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity)
            with mock.patch.object(
                self.installer,
                "_fsync_directory",
                wraps=self.installer._fsync_directory,
            ) as fsync:
                result = self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertEqual(result, "created")
            self.assertEqual(
                [call.args[0] for call in fsync.call_args_list][-2:],
                [layout.activation_root, layout.unit_root],
            )

    def test_quiescence_failure_preserves_published_authority(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            base = self._runner(layout, identity, fail_start=True)
            start_attempted = False

            def runner(argv: list[str]):
                nonlocal start_attempted
                if argv[0:2] == ["/usr/bin/systemctl", "start"]:
                    start_attempted = True
                completed = base(argv)
                if (
                    start_attempted
                    and argv[0:2] == ["/usr/bin/systemctl", "list-units"]
                ):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        (
                            b"codeskeptic-p10-09-campaign@live.service "
                            b"loaded active running broker\n"
                        ),
                        b"",
                    )
                return completed

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "on-disk rollback refused",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertTrue(layout.install_root.is_dir())
            self.assertTrue((layout.install_root / "receipt.json").is_file())

    def test_concurrent_prestart_activation_is_stopped_before_rollback(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            base = self._runner(layout, identity, commands=commands)

            def runner(argv: list[str]):
                completed = base(argv)
                fields = {
                    value.split("=", 1)[1]
                    for value in argv
                    if value.startswith("--property=")
                }
                if (
                    argv[0:2] == ["/usr/bin/systemctl", "show"]
                    and argv[-1] in self.installer.SOCKET_NAMES
                    and "LoadState" in fields
                    and (layout.unit_root / argv[-1]).is_file()
                ):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        completed.stdout.replace(
                            b"ActiveState=inactive\n",
                            b"ActiveState=active\n",
                        ).replace(
                            b"SubState=dead\n",
                            b"SubState=listening\n",
                        ),
                        b"",
                    )
                return completed

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "loaded socket authority drift",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertIn(
                [
                    "/usr/bin/systemctl",
                    "stop",
                    *self.installer.SOCKET_NAMES,
                ],
                commands,
            )
            self.assertFalse(layout.install_root.exists())

    def test_quiescence_rejects_a_stale_runtime_socket_path(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            layout.runtime_root.mkdir(parents=True)
            base = self._runner(layout, identity)
            stale = layout.runtime_root / "campaign.sock"

            def runner(argv: list[str]):
                completed = base(argv)
                if argv[0:2] == ["/usr/bin/systemctl", "stop"]:
                    stale.write_bytes(b"stale\n")
                return completed

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "stopped launch socket path remains",
            ):
                self.installer._stop_and_verify_quiescent(runner, layout)

            self.assertEqual(stale.read_bytes(), b"stale\n")

    def test_install_is_exception_transactional_verifiable_and_idempotent(
        self,
    ) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity, commands=commands)
            result = self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=runner,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            self.assertEqual(result, "created")
            payload = self.installer.prepare_payload(LAUNCH, identity)
            guided_hash = hashlib.sha256(
                layout.guided_path.read_bytes()
            ).hexdigest()
            core_authority_hash = hashlib.sha256(
                layout.core_authority_path.read_bytes()
            ).hexdigest()
            self.installer.verify_installation(
                layout,
                identity,
                payload,
                guided_hash,
                core_authority_hash,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            broker_identity = self.broker_identity(layout)
            self.assertEqual(broker_identity.uid, identity.uid)

            reused = self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=runner,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            self.assertEqual(reused, "reused")
            self.assertGreaterEqual(
                commands.count(["/usr/bin/systemctl", "daemon-reload"]), 2
            )
            self.assertEqual(
                commands.count(
                    [
                        "/usr/bin/systemctl",
                        "start",
                        *self.installer.SOCKET_NAMES,
                    ]
                ),
                1,
            )
            self.assertNotIn(
                [
                    "/usr/bin/systemctl",
                    "stop",
                    *self.installer.SOCKET_NAMES,
                ],
                commands,
            )

    def test_failed_read_only_reuse_does_not_stop_healthy_sockets(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            base = self._runner(layout, identity, commands=commands)
            created = self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=base,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            self.assertEqual(created, "created")
            reuse_phase = True

            def runner(argv: list[str]):
                completed = base(argv)
                fields = {
                    value.split("=", 1)[1]
                    for value in argv
                    if value.startswith("--property=")
                }
                if (
                    reuse_phase
                    and argv[0:2] == ["/usr/bin/systemctl", "show"]
                    and argv[-1] == self.installer.CAMPAIGN_SOCKET_NAME
                    and fields
                    == {
                        "LoadState",
                        "ActiveState",
                        "SubState",
                        "FragmentPath",
                        "DropInPaths",
                        "UnitFileState",
                    }
                ):
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        completed.stdout.replace(
                            b"ActiveState=active\n", b"ActiveState=inactive\n"
                        ),
                        b"",
                    )
                return completed

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "did not activate the exact socket",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertEqual(
                commands.count(
                    [
                        "/usr/bin/systemctl",
                        "start",
                        *self.installer.SOCKET_NAMES,
                    ]
                ),
                1,
            )
            self.assertNotIn(
                [
                    "/usr/bin/systemctl",
                    "stop",
                    *self.installer.SOCKET_NAMES,
                ],
                commands,
            )
            self.assertTrue(layout.install_root.is_dir())

    def test_inactive_reuse_rejects_a_surviving_broker_before_start(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            base = self._runner(layout, identity, commands=commands)
            created = self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=base,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            self.assertEqual(created, "created")
            base(["/usr/bin/systemctl", "stop", *self.installer.SOCKET_NAMES])

            def runner(argv: list[str]):
                completed = base(argv)
                if argv[0:2] == ["/usr/bin/systemctl", "list-units"]:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        (
                            b"codeskeptic-p10-09-campaign@old.service "
                            b"loaded active running broker\n"
                        ),
                        b"",
                    )
                return completed

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "broker instances are not quiescent",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertEqual(
                commands.count(
                    [
                        "/usr/bin/systemctl",
                        "start",
                        *self.installer.SOCKET_NAMES,
                    ]
                ),
                1,
            )

    def test_active_reuse_rejects_socket_node_mode_drift_without_stop(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity, commands=commands)
            created = self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=runner,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            self.assertEqual(created, "created")
            (layout.runtime_root / "campaign.sock").chmod(0o666)

            with self.assertRaisesRegex(
                self.installer.InstallError,
                "socket node authority drift",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertNotIn(
                [
                    "/usr/bin/systemctl",
                    "stop",
                    *self.installer.SOCKET_NAMES,
                ],
                commands,
            )

    def broker_identity(self, layout):
        return self.broker.read_launch_authority(
            install_root=layout.install_root,
            unit_root=layout.unit_root,
            activation_root=layout.activation_root,
            guided_path=layout.guided_path,
            core_authority_path=layout.core_authority_path,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )

    def test_failed_start_rolls_back_only_created_launch_nodes(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )

        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity, fail_start=True)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertFalse(layout.install_root.exists())
            for name in self.installer.UNIT_NAMES:
                self.assertFalse((layout.unit_root / name).exists())
            self.assertFalse(layout.activation_root.exists())

    def test_foreign_unit_collision_is_preserved_without_partial_install(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            foreign = layout.unit_root / self.installer.CAMPAIGN_SOCKET_NAME
            foreign.write_bytes(b"foreign\n")
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=lambda argv: subprocess.CompletedProcess(
                        argv, 0, b"", b""
                    ),
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertEqual(foreign.read_bytes(), b"foreign\n")
            self.assertFalse(layout.install_root.exists())

    def test_fresh_install_rejects_preexisting_live_sockets_before_mutation(
        self,
    ) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        commands: list[list[str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(
                layout,
                identity,
                commands=commands,
                preexisting_active=True,
            )
            with self.assertRaisesRegex(
                self.installer.InstallError,
                "pre-existing launch socket authority",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertFalse(layout.install_root.exists())
            self.assertTrue((layout.runtime_root / "campaign.sock").exists())
            self.assertNotIn(
                [
                    "/usr/bin/systemctl",
                    "stop",
                    *self.installer.SOCKET_NAMES,
                ],
                commands,
            )

    def test_partial_installation_requires_separate_administrator_recovery(
        self,
    ) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            layout.install_root.mkdir(mode=0o555)
            layout.install_root.chmod(0o555)
            runner = self._runner(layout, identity)
            with self.assertRaisesRegex(
                self.installer.InstallError,
                "separately reviewed administrator recovery",
            ):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

            self.assertTrue(layout.install_root.is_dir())

    def test_post_creation_ownership_failures_roll_back_exact_nodes(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        for failure in ("dropin-chown", "activation-chown", "symlink-lchown"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                layout = self._layout(Path(temporary))
                dropin = (
                    layout.unit_root
                    / f"{self.installer.CAMPAIGN_SERVICE_NAME}.d"
                )
                activation = layout.activation_root
                link = activation / self.installer.CAMPAIGN_SOCKET_NAME
                real_chown = os.chown
                real_lchown = os.lchown

                def injected_chown(path, uid, gid):
                    target = Path(path)
                    if (
                        failure == "dropin-chown"
                        and target.parent == dropin.parent
                        and target.name.startswith(f".{dropin.name}.install-")
                    ) or (
                        failure == "activation-chown"
                        and target.parent == activation.parent
                        and target.name.startswith(
                            f".{activation.name}.install-"
                        )
                    ):
                        raise OSError("injected post-creation chown failure")
                    return real_chown(path, uid, gid)

                def injected_lchown(path, uid, gid):
                    target = Path(path)
                    if (
                        failure == "symlink-lchown"
                        and target.parent == link.parent
                        and target.name.startswith(f".{link.name}.install-")
                    ):
                        raise OSError("injected post-creation lchown failure")
                    return real_lchown(path, uid, gid)

                runner = self._runner(layout, identity)
                with (
                    mock.patch.object(
                        self.installer.os,
                        "chown",
                        side_effect=injected_chown,
                    ),
                    mock.patch.object(
                        self.installer.os,
                        "lchown",
                        side_effect=injected_lchown,
                    ),
                    self.assertRaises(self.installer.InstallError),
                ):
                    self.installer.install_launch_boundary(
                        identity,
                        layout=layout,
                        runner=runner,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )

                self.assertFalse(layout.install_root.exists())
                self.assertFalse(activation.exists())
                for name in self.installer.UNIT_NAMES:
                    self.assertFalse((layout.unit_root / name).exists())
                for name in self.installer.SERVICE_NAMES:
                    self.assertFalse(
                        (layout.unit_root / f"{name}.d").exists()
                    )
                self.assertFalse(
                    any(
                        ".install-" in path.name
                        for path in layout.unit_root.rglob("*")
                    )
                )

    def test_fixed_file_failure_is_removed_and_parent_fsynced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            path = parent / "fixed"
            with (
                mock.patch.object(
                    self.installer.os,
                    "fchown",
                    side_effect=OSError("injected fchown failure"),
                ),
                mock.patch.object(
                    self.installer,
                    "_fsync_directory",
                    wraps=self.installer._fsync_directory,
                ) as fsync,
                self.assertRaises(OSError),
            ):
                self.installer._write_new(
                    path,
                    b"payload\n",
                    0o400,
                    os.getuid(),
                    os.getgid(),
                )

            self.assertFalse(path.exists())
            self.assertEqual(
                [call.args[0] for call in fsync.call_args_list],
                [parent],
            )

    def test_fixed_file_reports_an_incomplete_failure_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixed"
            with (
                mock.patch.object(
                    self.installer.os,
                    "fchown",
                    side_effect=OSError("injected fchown failure"),
                ),
                mock.patch.object(
                    Path,
                    "unlink",
                    side_effect=OSError("injected unlink failure"),
                ),
                self.assertRaisesRegex(
                    self.installer.InstallError,
                    "cleanup failed",
                ),
            ):
                self.installer._write_new(
                    path,
                    b"payload\n",
                    0o400,
                    os.getuid(),
                    os.getgid(),
                )

            self.assertTrue(path.is_file())

    def test_hostile_umask_cannot_weaken_or_overrestrict_installation(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        for hostile_umask in (0o077, 0o000):
            with (
                self.subTest(umask=oct(hostile_umask)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                layout = self._layout(Path(temporary))
                runner = self._runner(layout, identity)
                previous_umask = os.umask(hostile_umask)
                try:
                    result = self.installer.install_launch_boundary(
                        identity,
                        layout=layout,
                        runner=runner,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                finally:
                    os.umask(previous_umask)

                self.assertEqual(result, "created")
                self.assertEqual(
                    stat.S_IMODE(layout.install_root.stat().st_mode),
                    0o555,
                )
                self.assertEqual(
                    stat.S_IMODE(layout.activation_root.stat().st_mode),
                    0o755,
                )
                self.assertEqual(
                    stat.S_IMODE(layout.install_lock_path.stat().st_mode),
                    0o600,
                )
                for name, mode in self.installer.PACKAGE_MODES.items():
                    self.assertEqual(
                        stat.S_IMODE(
                            (layout.install_root / name).stat().st_mode
                        ),
                        mode,
                    )
                for name in self.installer.UNIT_NAMES:
                    self.assertEqual(
                        stat.S_IMODE((layout.unit_root / name).stat().st_mode),
                        0o444,
                    )
                for name in self.installer.SERVICE_NAMES:
                    self.assertEqual(
                        stat.S_IMODE(
                            (layout.unit_root / f"{name}.d").stat().st_mode
                        ),
                        0o755,
                    )

    def test_verifiers_reject_writable_authority_parents(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity)
            self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=runner,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            payload = self.installer.prepare_payload(LAUNCH, identity)
            guided_hash = hashlib.sha256(
                layout.guided_path.read_bytes()
            ).hexdigest()
            core_authority_hash = hashlib.sha256(
                layout.core_authority_path.read_bytes()
            ).hexdigest()

            authority_directories = {
                layout.install_root.parent: 0o755,
                layout.guided_path.parent.parent: 0o555,
                layout.guided_path.parent: 0o555,
                layout.core_authority_path.parent.parent.parent: 0o755,
                layout.core_authority_path.parent.parent: 0o755,
                layout.core_authority_path.parent: 0o700,
                layout.unit_root.parent.parent: 0o755,
                layout.unit_root.parent: 0o755,
                layout.unit_root: 0o755,
            }
            for directory, expected_mode in authority_directories.items():
                with self.subTest(directory=directory):
                    directory.chmod(0o777)
                    try:
                        with self.assertRaisesRegex(
                            self.installer.InstallError,
                            "fixed parent authority drift",
                        ):
                            self.installer.verify_installation(
                                layout,
                                identity,
                                payload,
                                guided_hash,
                                core_authority_hash,
                                owner_uid=os.getuid(),
                                owner_gid=os.getgid(),
                            )
                        with self.assertRaisesRegex(
                            self.broker.BrokerError,
                            "fixed parent authority drift",
                        ):
                            self.broker_identity(layout)
                    finally:
                        directory.chmod(expected_mode)

    def test_receipt_bound_package_rejects_extra_or_mutated_files(self) -> None:
        account = pwd.getpwuid(os.getuid())
        identity = self.installer.resolve_operator_identity(
            account.pw_uid, account.pw_name
        )
        with tempfile.TemporaryDirectory() as temporary:
            layout = self._layout(Path(temporary))
            runner = self._runner(layout, identity)
            self.installer.install_launch_boundary(
                identity,
                layout=layout,
                runner=runner,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )
            layout.install_root.chmod(0o755)
            (layout.install_root / "foreign").write_bytes(b"foreign\n")
            layout.install_root.chmod(0o555)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_launch_boundary(
                    identity,
                    layout=layout,
                    runner=runner,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            broker = load_module(
                f"codeskeptic_launch_broker_foreign_{id(layout)}", BROKER
            )
            with self.assertRaises(broker.BrokerError):
                broker.read_launch_authority(
                    install_root=layout.install_root,
                    unit_root=layout.unit_root,
                    activation_root=layout.activation_root,
                    guided_path=layout.guided_path,
                    core_authority_path=layout.core_authority_path,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )


if __name__ == "__main__":
    unittest.main()
