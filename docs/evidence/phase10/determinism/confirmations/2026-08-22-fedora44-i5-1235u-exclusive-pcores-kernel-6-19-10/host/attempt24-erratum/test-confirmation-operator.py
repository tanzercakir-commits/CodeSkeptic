#!/usr/bin/python3
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import signal
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent
LAUNCHER = ROOT / "cgroup-launcher.sh"
CONTROLLER = ROOT / "headless-controller-root.sh"
AUTHORIZER = ROOT / "authorize-headless-confirmation.sh"
WRAPPER = ROOT / "guided-headless-confirmation.sh"
SNAPSHOT_BUILDER = ROOT / "snapshot-builder.sh"
STATIC_PREFLIGHT = ROOT / "static-preflight.py"
RUNNER = ROOT / "run-confirmation.sh"
VSCODE_HELPER = ROOT / "vscode-helper-drain.py"
SHORT_LAUNCHER = ROOT.parent / f"{ROOT.name}.launcher.sh"
TIMER_STRESS = ROOT / "stress-timer-mask-transition.sh"
GC_STRESS = ROOT / "stress-gc-normalization.sh"
STRESS_SERVICE = ROOT / "codeskeptic-attempt24-mask-stress.service"
STRESS_MANAGER = ROOT / "codeskeptic-attempt24-mask-stress-manager.service"
STRESS_CONSUMER = ROOT / "codeskeptic-attempt24-mask-stress-consumer.service"
STRESS_HELPER = ROOT / "stress-dependency-service.sh"
STRESS_TIMER = ROOT / "codeskeptic-attempt24-mask-stress.timer"
STRESS_SOCKET = ROOT / "codeskeptic-attempt24-mask-stress.socket"
STRESS_SOCKET_TEMPLATE = ROOT / "codeskeptic-attempt24-mask-stress@.service"
STRESS_PATH = ROOT / "codeskeptic-attempt24-mask-stress.path"
STRESS_TARGET = ROOT / "codeskeptic-attempt24-mask-stress.target"

sys.dont_write_bytecode = True
VSCODE_HELPER_SPEC = importlib.util.spec_from_file_location(
    "codeskeptic_v7_vscode_helper", VSCODE_HELPER
)
assert VSCODE_HELPER_SPEC is not None and VSCODE_HELPER_SPEC.loader is not None
vscode_helper = importlib.util.module_from_spec(VSCODE_HELPER_SPEC)
sys.modules[VSCODE_HELPER_SPEC.name] = vscode_helper
VSCODE_HELPER_SPEC.loader.exec_module(vscode_helper)

VSCODE_1133_CRASHPAD_PREFIX = (
    b"/usr/share/code/chrome_crashpad_handler\0"
    b"--monitor-self-annotation=ptype=crashpad-handler\0"
    b"--no-rate-limit\0"
    b"--database=/home/tanzer/.config/Code/Crashpad\0"
    b"--url=appcenter://code?aid=fba07a4d-84bd-4fc8-a125-9640fc8ce171&"
    b"uid=df97b794-7d19-43d6-89aa-8d15a4d2f5dc&"
    b"iid=df97b794-7d19-43d6-89aa-8d15a4d2f5dc&"
    b"sid=df97b794-7d19-43d6-89aa-8d15a4d2f5dc\0"
    b"--annotation=_companyName=Microsoft\0"
    b"--annotation=_productName=VSCode\0"
    b"--annotation=_version=1.133.0\0"
    b"--annotation=lsb-release=Fedora Linux 44 (KDE Plasma Desktop Edition)\0"
    b"--annotation=plat=Linux\0"
    b"--annotation=prod=Electron\0"
    b"--annotation=ver=42.8.0\0"
)
VSCODE_1133_KONSOLE_CRASHPAD_CMDLINE = (
    VSCODE_1133_CRASHPAD_PREFIX
    + b"--initial-client-fd=48\0"
    + b"--shared-client-connection\0"
)
VSCODE_1133_DESKTOP_CRASHPAD_CMDLINE = (
    VSCODE_1133_CRASHPAD_PREFIX
    + b"--initial-client-fd=46\0"
    + b"--shared-client-connection\0"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V7ConfirmationOperatorTest(unittest.TestCase):
    def test_attempt24_user_unit_stress_is_bounded_disposable_and_non_root(self):
        text = TIMER_STRESS.read_text(encoding="utf-8")
        self.assertIn("for ((cycle = 1; cycle <= 100; cycle++))", text)
        self.assertIn("/usr/bin/sleep 0.05", text)
        self.assertIn("remove_exact_template_copy", text)
        self.assertIn("/usr/bin/rm -- \"$destination\"", text)
        self.assertIn("CODESKEPTIC_ATTEMPT24_STOP_BEFORE_MASK_STRESS_PASS", text)
        self.assertIn('userctl stop -- "${all_units[@]}"', text)
        self.assertIn('userctl mask --runtime -- "${all_units[@]}"', text)
        self.assertLess(
            text.index('userctl stop -- "${all_units[@]}"', text.index("for ((cycle")),
            text.index('userctl mask --runtime -- "${all_units[@]}"', text.index("for ((cycle")),
        )
        self.assertIn("dependency_order=consumer-manager-backend", text)
        self.assertIn("activation_guard_rejected=$activation_guard_rejected", text)
        self.assertIn("accept_gap_guard_rejected=$accept_gap_guard_rejected", text)
        self.assertIn("coredump_inventory_delta=0", text)
        self.assertIn("if require_no_stress_activation; then", text)
        self.assertIn("drkonqi_accept_delta=0", text)
        self.assertIn("accept_socket_pre_stop=$stress_socket_accepted_pre_stop", text)
        self.assertIn("accept_socket_post_stop=$stress_socket_accepted_baseline", text)
        self.assertIn("accept_socket_delta=0", text)
        self.assertIn('[[ $stress_socket_accepted_pre_stop == 1 ]]', text)
        self.assertIn('[[ $stress_socket_accepted_baseline == 0 ]]', text)
        self.assertIn("wait_for_stress_socket_accept 1", text)
        self.assertIn("wait_for_stress_socket_accept 2", text)
        self.assertIn("[[ $(unit_value NAccepted \"$socket_name\") == 2 ]]", text)
        self.assertIn("if require_no_stress_activation; then", text)
        self.assertIn(
            "^codeskeptic-attempt24-mask-stress@[A-Za-z0-9_.@:-]+\\.service$",
            text,
        )
        self.assertIn("client.connect(sys.argv[1])", text)
        self.assertIn("require_stress_socket_clean", text)
        self.assertNotIn("sudo", text)
        self.assertNotIn("systemctl isolate", text)

        for variable, path in (
            ("helper", STRESS_HELPER),
            ("backend", STRESS_SERVICE),
            ("manager", STRESS_MANAGER),
            ("consumer", STRESS_CONSUMER),
            ("timer", STRESS_TIMER),
            ("socket", STRESS_SOCKET),
            ("path", STRESS_PATH),
            ("target", STRESS_TARGET),
            ("socket_template", STRESS_SOCKET_TEMPLATE),
        ):
            self.assertIn(f"readonly {variable}_sha={sha256(path)}", text)

        backend = STRESS_SERVICE.read_text(encoding="utf-8")
        manager = STRESS_MANAGER.read_text(encoding="utf-8")
        consumer = STRESS_CONSUMER.read_text(encoding="utf-8")
        self.assertIn("Type=simple", backend)
        self.assertIn("Before=codeskeptic-attempt24-mask-stress-manager.service", backend)
        self.assertIn("BindsTo=codeskeptic-attempt24-mask-stress.service", manager)
        self.assertIn("After=codeskeptic-attempt24-mask-stress.service", manager)
        self.assertIn("Before=codeskeptic-attempt24-mask-stress-consumer.service", manager)
        self.assertIn("BindsTo=", consumer)
        self.assertIn("After=", consumer)
        self.assertIn("backend-stop", STRESS_HELPER.read_text(encoding="utf-8"))
        self.assertIn("OnActiveSec=1h", STRESS_TIMER.read_text(encoding="utf-8"))
        socket = STRESS_SOCKET.read_text(encoding="utf-8")
        self.assertIn("ListenStream=%t/codeskeptic-attempt24-mask-stress.sock", socket)
        self.assertIn("Accept=yes", socket)
        self.assertIn("RemoveOnStop=yes", socket)
        socket_template = STRESS_SOCKET_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("StandardInput=socket", socket_template)
        self.assertIn("ExecStart=/usr/bin/true", socket_template)
        path = STRESS_PATH.read_text(encoding="utf-8")
        self.assertIn("PathExists=%t/codeskeptic-attempt24-mask-stress.trigger", path)
        target = STRESS_TARGET.read_text(encoding="utf-8")
        self.assertIn("disposable stop-before-mask target", target)

    def test_attempt24_gc_probe_is_disposable_and_requires_canonical_reset(self):
        text = GC_STRESS.read_text(encoding="utf-8")
        self.assertIn("baseline_active", text)
        self.assertIn("baseline_inactive", text)
        self.assertIn("InactiveExitTimestampMonotonic=0", text)
        self.assertIn("ActiveEnterTimestampMonotonic=0", text)
        self.assertIn("LoadState=masked", text)
        self.assertIn("UnitFileState=masked-runtime", text)
        self.assertIn("CODESKEPTIC_ATTEMPT24_GC_NORMALIZATION_PASS", text)
        self.assertIn('userctl unmask --runtime "$unit"', text)
        self.assertIn('userctl disable "$unit"', text)
        self.assertIn('/usr/bin/rm -f -- "$unit_file"', text)
        self.assertIn("unit_file_installed=0", text)
        self.assertIn("unit_enabled=0", text)
        self.assertIn("mask_created=0", text)
        self.assertIn("if ((unit_file_installed == 1)); then", text)
        self.assertIn("if ((unit_enabled == 1)); then", text)
        self.assertIn("if ((mask_created == 1)); then", text)
        self.assertIn('[[ $actual_sha == "$unit_file_sha" ]]', text)
        preflight = text.index('[[ ! -e $unit_file && ! -L $unit_file')
        install = text.index('/usr/bin/install -d -m 0700')
        self.assertLess(preflight, install)
        self.assertNotIn("trap cleanup EXIT INT TERM HUP", text)
        self.assertIn("trap 'exit 130' INT", text)
        self.assertIn("coredump_inventory_sha", text)
        self.assertIn("drkonqi-coredump-launcher.socket", text)
        self.assertNotIn("sudo", text)
        self.assertNotIn("systemctl isolate", text)

    def test_attempt24_main_accepts_only_signal_free_absence_mode(self):
        with mock.patch.object(
            vscode_helper, "require_helper_session_cgroup"
        ) as require_session, mock.patch.object(
            vscode_helper, "require_vscode_absent", create=True
        ) as require_absent, mock.patch.object(
            vscode_helper, "drain_vscode"
        ) as drain:
            self.assertEqual(vscode_helper.main(["--require-absent"]), 0)
            self.assertEqual(vscode_helper.main([]), 2)
        require_session.assert_called_once_with()
        require_absent.assert_called_once_with()
        drain.assert_not_called()

    def test_attempt24_absence_mode_requires_two_stable_empty_snapshots(self):
        manager = mock.Mock(pid=42)
        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ) as find_manager, mock.patch.object(
            vscode_helper, "collect_code_unit_members", return_value={}
        ) as collect_units, mock.patch.object(
            vscode_helper, "_list_code_units", return_value={}
        ) as list_units, mock.patch.object(
            vscode_helper, "collect_named", return_value=[]
        ) as collect_names, mock.patch.object(
            vscode_helper.time, "sleep"
        ) as sleep:
            vscode_helper.require_vscode_absent()
        self.assertEqual(find_manager.call_count, 2)
        self.assertEqual(collect_units.call_count, 2)
        self.assertEqual(list_units.call_count, 2)
        self.assertEqual(collect_names.call_count, 2)
        sleep.assert_called_once_with(0.25)

    def test_attempt24_absence_mode_rejects_units_processes_and_code_crashpad(self):
        manager = mock.Mock(pid=42)
        process = mock.Mock(pid=101, comm="codex", exe="/tmp/version-independent")
        crashpad = mock.Mock(
            pid=102,
            comm="chrome_crashpad",
            exe=vscode_helper.CRASHPAD_EXE,
        )
        cases = (
            ({"app-code-101.scope": [process]}, {}, [], "processes remain"),
            ({}, {"app-code-101.scope": ("loaded", "active", "running")}, [], "units remain"),
            ({}, {}, [process], "processes remain"),
            ({}, {}, [crashpad], "processes remain"),
        )
        for members, units, named, message in cases:
            with self.subTest(message=message), mock.patch.object(
                vscode_helper, "find_user_manager", return_value=manager
            ), mock.patch.object(
                vscode_helper, "collect_code_unit_members", return_value=members
            ), mock.patch.object(
                vscode_helper, "_list_code_units", return_value=units
            ), mock.patch.object(
                vscode_helper, "collect_named", return_value=named
            ), self.assertRaisesRegex(vscode_helper.DrainError, message):
                vscode_helper.require_vscode_absent()

    def test_attempt24_production_invokes_only_exact_absence_mode(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        wrapper_call = (
            '/usr/bin/python3 -I -B "$helper_local" --require-absent'
        )
        authorizer_call = (
            '/usr/bin/python3 -I -B "$helper_staged" --require-absent'
        )
        self.assertEqual(wrapper.count(wrapper_call), 1)
        self.assertEqual(authorizer.count(authorizer_call), 1)
        self.assertLess(wrapper.index(wrapper_call), wrapper.index("/usr/bin/sudo -v"))
        self.assertLess(
            wrapper.index(wrapper_call),
            wrapper.index("/usr/bin/sudo -n /usr/bin/systemctl isolate multi-user.target"),
        )
        self.assertLess(
            authorizer.index(authorizer_call),
            authorizer.index('userctl stop -- "${user_graphical_targets[@]}"'),
        )
        self.assertNotRegex(
            wrapper + authorizer,
            r'/usr/bin/python3 -I -B "\$(?:helper_local|helper_staged)"(?:\s|$)(?!--require-absent)',
        )

    def test_vscode_units_are_derived_from_exact_cgroups(self):
        base = vscode_helper.Snapshot(
            pid=101,
            comm="code",
            state="S",
            ppid=42,
            starttime=900,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/share/code/code",
            cmdline=b"/usr/share/code/code\0--type=utility\0",
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-code-101.scope\n"
            ),
        )
        self.assertEqual(vscode_helper.code_unit_name(base), "app-code-101.scope")
        service = vscode_helper.Snapshot(
            **{
                **base.__dict__,
                "pid": 102,
                "cgroup": (
                    b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                    b"app-code@0123456789abcdef0123456789abcdef.service\n"
                ),
            }
        )
        self.assertEqual(
            vscode_helper.code_unit_name(service),
            "app-code@0123456789abcdef0123456789abcdef.service",
        )
        for cgroup in (
            base.cgroup.rstrip(b"\n") + b"/child\n",
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
            b"app-code-0.scope\n",
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
            b"app-code@0123456789ABCDEF0123456789ABCDEF.service\n",
        ):
            with self.subTest(cgroup=cgroup), self.assertRaises(
                vscode_helper.DrainError
            ):
                vscode_helper.code_unit_name(
                    vscode_helper.Snapshot(**{**base.__dict__, "cgroup": cgroup})
                )

    def test_vscode_unit_properties_are_strict_and_fail_closed(self):
        scope = "app-code-101.scope"
        scope_properties = {
            "Id": scope,
            "Description": scope,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "FreezerState": "running",
            "FragmentPath": f"/run/user/1000/systemd/transient/{scope}",
            "SourcePath": "",
            "UnitFileState": "transient",
            "RefuseManualStart": "no",
            "RefuseManualStop": "no",
            "Transient": "yes",
            "Result": "success",
            "ControlGroup": (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/"
                + scope
            ),
            "KillMode": "control-group",
            "SendSIGKILL": "yes",
        }
        vscode_helper.validate_code_unit_properties(scope, scope_properties)
        frozen_scope_properties = {**scope_properties, "FreezerState": "frozen"}
        vscode_helper.validate_code_unit_properties(
            scope, frozen_scope_properties, freezer_state="frozen"
        )
        service = "app-code@0123456789abcdef0123456789abcdef.service"
        service_properties = {
            **scope_properties,
            "Id": service,
            "Description": "Visual Studio Code - Text Editor",
            "FragmentPath": f"/run/user/1000/systemd/transient/{service}",
            "SourcePath": "/usr/share/applications/code.desktop",
            "ControlGroup": (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/"
                + service
            ),
            "Type": "simple",
            "MainPID": "0",
            "ControlPID": "0",
            "Restart": "no",
        }
        vscode_helper.validate_code_unit_properties(service, service_properties)
        exited_launcher = {**service_properties, "Result": "exit-code"}
        vscode_helper.validate_code_unit_properties(service, exited_launcher)
        with self.assertRaises(vscode_helper.DrainError):
            vscode_helper.validate_code_unit_properties(
                service, {**exited_launcher, "MainPID": "123"}
            )
        with self.assertRaises(vscode_helper.DrainError):
            vscode_helper.validate_code_unit_properties(
                scope, {**scope_properties, "Result": "exit-code"}
            )
        for result in ("signal", "timeout", "core-dump"):
            with self.subTest(result=result), self.assertRaises(
                vscode_helper.DrainError
            ):
                vscode_helper.validate_code_unit_properties(
                    service, {**service_properties, "Result": result}
                )
        for key, value in (
            ("RefuseManualStop", "yes"),
            ("KillMode", "process"),
            ("Transient", "no"),
            ("SourcePath", "/tmp/code.desktop"),
            ("FreezerState", "frozen"),
            ("Restart", "always"),
        ):
            forged = dict(service_properties)
            forged[key] = value
            with self.subTest(key=key), self.assertRaises(vscode_helper.DrainError):
                vscode_helper.validate_code_unit_properties(service, forged)

    def test_vscode_stopped_unit_properties_are_strict_and_fail_closed(self):
        scope = "app-code-101.scope"
        not_found = {
            "Id": scope,
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "FreezerState": "running",
            "FragmentPath": "",
            "SourcePath": "",
            "UnitFileState": "",
            "RefuseManualStart": "no",
            "RefuseManualStop": "no",
            "Transient": "no",
            "Result": "success",
            "ControlGroup": "",
            "KillMode": "control-group",
            "SendSIGKILL": "yes",
        }
        vscode_helper.validate_stopped_code_unit_properties(scope, not_found)
        loaded = {
            **not_found,
            "LoadState": "loaded",
            "FragmentPath": f"/run/user/1000/systemd/transient/{scope}",
            "UnitFileState": "transient",
            "Transient": "yes",
            "ControlGroup": (
                "/user.slice/user-1000.slice/user@1000.service/app.slice/"
                + scope
            ),
        }
        vscode_helper.validate_stopped_code_unit_properties(scope, loaded)
        vscode_helper.validate_stopped_code_unit_properties(
            scope, {**loaded, "Result": "signal"}
        )
        service = "app-code@0123456789abcdef0123456789abcdef.service"
        service_not_found = {
            **not_found,
            "Id": service,
            "Type": "",
            "MainPID": "0",
            "ControlPID": "0",
            "Restart": "no",
        }
        vscode_helper.validate_stopped_code_unit_properties(
            service, service_not_found
        )
        for restart in ("", "always"):
            with self.subTest(restart=restart), self.assertRaises(
                vscode_helper.DrainError
            ):
                vscode_helper.validate_stopped_code_unit_properties(
                    service, {**service_not_found, "Restart": restart}
                )
        for key, value in (
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Result", "exit-code"),
            ("LoadState", "masked"),
            ("FreezerState", "frozen"),
        ):
            forged = dict(not_found)
            forged[key] = value
            with self.subTest(key=key), self.assertRaises(vscode_helper.DrainError):
                vscode_helper.validate_stopped_code_unit_properties(scope, forged)

    def test_vscode_systemd_inventory_is_exact_and_fail_closed(self):
        output = (
            "app-code-101.scope loaded inactive dead VS Code scope\n"
            "app-code@0123456789abcdef0123456789abcdef.service "
            "loaded inactive dead VS Code service\n"
            "dbus.service loaded active running D-Bus\n"
        )
        with mock.patch.object(
            vscode_helper, "_systemctl", return_value=output
        ) as systemctl:
            self.assertEqual(
                vscode_helper._list_code_units(),
                {
                    "app-code-101.scope": ("loaded", "inactive", "dead"),
                    "app-code@0123456789abcdef0123456789abcdef.service": (
                        "loaded",
                        "inactive",
                        "dead",
                    ),
                },
            )
        systemctl.assert_called_once_with(
            [
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--type=service",
                "--type=scope",
            ]
        )
        with mock.patch.object(
            vscode_helper,
            "_systemctl",
            return_value="app-code-101.scope loaded active\n",
        ), self.assertRaisesRegex(vscode_helper.DrainError, "malformed"):
            vscode_helper._list_code_units()

    def test_vscode_unit_dconf_child_is_exact_but_need_not_be_orphaned(self):
        snapshot = vscode_helper.Snapshot(
            pid=201,
            comm="dconf",
            state="S",
            ppid=101,
            starttime=901,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/bin/dconf",
            cmdline=b"dconf\0watch\0/system/proxy/\0",
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-code-101.scope\n"
            ),
        )
        self.assertEqual(
            hashlib.sha256(snapshot.cmdline).hexdigest(),
            vscode_helper.DCONF_CMDLINE_SHA256,
        )
        vscode_helper._validate_code_unit_member(snapshot, user_manager_pid=42)
        forged = vscode_helper.Snapshot(
            **{**snapshot.__dict__, "cmdline": snapshot.cmdline + b"extra\0"}
        )
        with self.assertRaises(vscode_helper.DrainError):
            vscode_helper._validate_code_unit_member(forged, user_manager_pid=42)

    def test_vscode_units_are_stopped_before_orphan_helper_drain(self):
        order = []
        with mock.patch.object(
            vscode_helper, "stop_vscode_units", side_effect=lambda _root: order.append("stop")
        ) as stop_units, mock.patch.object(
            vscode_helper, "wait_for_code_exit", side_effect=lambda _root: order.append("code-absent")
        ) as wait_code, mock.patch.object(
            vscode_helper,
            "require_extension_helpers_absent",
            side_effect=lambda _root: order.append("extension-absent"),
        ) as wait_extension, mock.patch.object(
            vscode_helper, "drain_helpers", side_effect=lambda _root: order.append("orphans")
        ) as drain_helpers:
            vscode_helper.drain_vscode()
        stop_units.assert_called_once_with(Path("/proc"))
        wait_code.assert_called_once_with(Path("/proc"))
        wait_extension.assert_called_once_with(Path("/proc"))
        drain_helpers.assert_called_once_with(Path("/proc"))
        self.assertEqual(order, ["stop", "code-absent", "extension-absent", "orphans"])

    def test_vscode_helper_requires_physical_session_cgroup_before_freeze(self):
        with mock.patch.object(
            vscode_helper,
            "_read_bounded",
            return_value=b"0::/user.slice/user-1000.slice/session-3.scope\n",
        ):
            vscode_helper.require_helper_session_cgroup(Path("/proc"))
        for cgroup in (
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
            b"app-code-101.scope\n",
            b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
            b"run-p1-i2.scope\n",
        ):
            with self.subTest(cgroup=cgroup), mock.patch.object(
                vscode_helper, "_read_bounded", return_value=cgroup
            ), self.assertRaisesRegex(vscode_helper.DrainError, "physical TTY session"):
                vscode_helper.require_helper_session_cgroup(Path("/proc"))

    def test_vscode_frozen_members_use_exact_pidfds_and_close_all(self):
        member = vscode_helper.Snapshot(
            pid=101,
            comm="code",
            state="S",
            ppid=42,
            starttime=900,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/share/code/code",
            cmdline=b"/usr/share/code/code\0--type=utility\0",
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-code-101.scope\n"
            ),
        )
        with mock.patch.object(
            vscode_helper.os, "pidfd_open", return_value=11
        ) as pidfd_open, mock.patch.object(
            vscode_helper, "read_snapshot", return_value=member
        ), mock.patch.object(
            vscode_helper.signal, "pidfd_send_signal"
        ) as pidfd_signal, mock.patch.object(
            vscode_helper, "_wait_pidfds", return_value=[]
        ) as wait_pidfds, mock.patch.object(
            vscode_helper.os, "close"
        ) as close:
            handles = vscode_helper._open_code_unit_handles(
                {"app-code-101.scope": [member]}, 42, Path("/proc")
            )
            vscode_helper._terminate_frozen_code_handles(
                handles, 42, Path("/proc")
            )
            vscode_helper._close_handles(handles)
        pidfd_open.assert_called_once_with(101, 0)
        pidfd_signal.assert_called_once_with(11, signal.SIGKILL)
        wait_pidfds.assert_called_once_with(handles, 10.0)
        close.assert_called_once_with(11)

        changed = vscode_helper.Snapshot(
            **{**member.__dict__, "starttime": member.starttime + 1}
        )
        with mock.patch.object(
            vscode_helper.os, "pidfd_open", return_value=12
        ), mock.patch.object(
            vscode_helper, "read_snapshot", return_value=changed
        ), mock.patch.object(
            vscode_helper.os, "close"
        ) as changed_close, self.assertRaisesRegex(
            vscode_helper.DrainError, "identity changed while opening pidfd"
        ):
            vscode_helper._open_code_unit_handles(
                {"app-code-101.scope": [member]}, 42, Path("/proc")
            )
        changed_close.assert_called_once_with(12)

    def test_vscode_thaw_is_exact_and_tolerates_only_verified_absence(self):
        unit = "app-code-101.scope"
        absent = {
            "Id": unit,
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "FreezerState": "running",
        }
        frozen = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "FreezerState": "frozen",
        }
        running = {**frozen, "FreezerState": "running"}
        with mock.patch.object(
            vscode_helper, "_query_code_unit_lifecycle", return_value=absent
        ), mock.patch.object(vscode_helper, "_systemctl") as absent_systemctl:
            vscode_helper._thaw_code_unit(unit)
        absent_systemctl.assert_not_called()

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, running],
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ) as thaw_systemctl, mock.patch.object(
            vscode_helper, "_query_code_unit", return_value={}
        ) as running_query:
            vscode_helper._thaw_code_unit(unit)
        thaw_systemctl.assert_called_once_with(["thaw", unit])
        running_query.assert_called_once_with(unit)

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, absent],
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            side_effect=vscode_helper.DrainError("unit disappeared"),
        ):
            vscode_helper._thaw_code_unit(unit)

        malformed_absent = {**absent, "FreezerState": "frozen"}
        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, malformed_absent],
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            side_effect=vscode_helper.DrainError("unit disappeared"),
        ), self.assertRaisesRegex(
            vscode_helper.DrainError, "after thaw error"
        ):
            vscode_helper._thaw_code_unit(unit)

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            return_value={**frozen, "FreezerState": "freezing"},
        ), self.assertRaisesRegex(vscode_helper.DrainError, "before thaw"):
            vscode_helper._thaw_code_unit(unit)

    def test_vscode_thaw_accepts_only_full_validated_stopped_lifecycle(self):
        unit = "app-code@0123456789abcdef0123456789abcdef.service"
        frozen = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "FreezerState": "frozen",
        }
        stopped = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "FreezerState": "running",
        }

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[stopped, stopped],
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit", return_value={}
        ) as stopped_query, mock.patch.object(
            vscode_helper, "_systemctl"
        ) as systemctl:
            vscode_helper._thaw_code_unit(unit)
        systemctl.assert_not_called()
        stopped_query.assert_called_once_with(unit)

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, stopped],
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            side_effect=vscode_helper.DrainError("Unit is not active"),
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit", return_value={}
        ) as stopped_after_error:
            vscode_helper._thaw_code_unit(unit)
        stopped_after_error.assert_called_once_with(unit)

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, stopped],
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit", return_value={}
        ) as stopped_after_success:
            vscode_helper._thaw_code_unit(unit)
        stopped_after_success.assert_called_once_with(unit)

        malformed = {**stopped, "SubState": "failed"}
        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[frozen, malformed],
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            side_effect=vscode_helper.DrainError("Unit is not active"),
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit"
        ) as malformed_stopped, self.assertRaisesRegex(
            vscode_helper.DrainError, "lifecycle recovery failed after thaw error"
        ):
            vscode_helper._thaw_code_unit(unit)
        malformed_stopped.assert_not_called()

    def test_vscode_thaw_resets_exact_failed_unit_after_intentional_kill(self):
        unit = "app-code@0123456789abcdef0123456789abcdef.service"
        failed_frozen = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "failed",
            "SubState": "failed",
            "FreezerState": "frozen",
        }
        failed_running = {**failed_frozen, "FreezerState": "running"}
        stopped = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "FreezerState": "running",
        }

        with mock.patch.object(
            vscode_helper,
            "_query_code_unit_lifecycle",
            side_effect=[failed_frozen, failed_running, stopped],
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ) as systemctl, mock.patch.object(
            vscode_helper, "_query_stopped_code_unit", return_value={}
        ) as stopped_query:
            vscode_helper._thaw_code_unit(unit)

        self.assertEqual(
            systemctl.call_args_list,
            [
                mock.call(["thaw", unit]),
                mock.call(["reset-failed", "--", unit]),
            ],
        )
        stopped_query.assert_called_once_with(unit)

    def test_vscode_partial_freeze_failure_thaws_all_exact_units(self):
        manager = vscode_helper.Snapshot(
            pid=42,
            comm="systemd",
            state="S",
            ppid=1,
            starttime=1,
            uids=(1000, 1000, 1000, 1000),
            exe=None,
            cmdline=vscode_helper.USER_MANAGER_CMDLINE,
            cgroup=vscode_helper.USER_MANAGER_CGROUP,
        )
        member = vscode_helper.Snapshot(
            pid=101,
            comm="code",
            state="S",
            ppid=42,
            starttime=900,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/share/code/code",
            cmdline=b"/usr/share/code/code\0--type=utility\0",
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-code-101.scope\n"
            ),
        )
        units = {
            "app-code@0123456789abcdef0123456789abcdef.service": [],
            "app-code-101.scope": [member],
        }
        unit_states = {
            unit: ("loaded", "active", "running") for unit in units
        }
        handles = [vscode_helper.Handle(member, 11)]
        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper, "collect_code_unit_members", return_value=units
        ), mock.patch.object(
            vscode_helper, "_list_code_units", return_value=unit_states
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            side_effect=vscode_helper.DrainError("partial freeze failed"),
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ) as terminate_handles, mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ) as thaw_unit, mock.patch.object(
            vscode_helper, "_close_handles"
        ) as close_handles, self.assertRaisesRegex(
            vscode_helper.DrainError, "partial freeze failed"
        ):
            vscode_helper.stop_vscode_units(Path("/proc"))
        terminate_handles.assert_not_called()
        self.assertEqual(
            thaw_unit.call_args_list,
            [
                mock.call("app-code-101.scope"),
                mock.call("app-code@0123456789abcdef0123456789abcdef.service"),
            ],
        )
        close_handles.assert_called_once_with(handles)

    def test_vscode_unit_stop_is_sorted_bounded_and_rejects_replacement(self):
        manager = vscode_helper.Snapshot(
            pid=42,
            comm="systemd",
            state="S",
            ppid=1,
            starttime=1,
            uids=(1000, 1000, 1000, 1000),
            exe=None,
            cmdline=vscode_helper.USER_MANAGER_CMDLINE,
            cgroup=vscode_helper.USER_MANAGER_CGROUP,
        )
        member = vscode_helper.Snapshot(
            pid=101,
            comm="code",
            state="S",
            ppid=42,
            starttime=900,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/share/code/code",
            cmdline=b"/usr/share/code/code\0--type=utility\0",
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-code-101.scope\n"
            ),
        )
        units = {
            "app-code@0123456789abcdef0123456789abcdef.service": [],
            "app-code-101.scope": [member],
        }
        unit_states = {
            unit: ("loaded", "active", "running") for unit in units
        }
        handles = [vscode_helper.Handle(member, 11)]
        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, units, {}],
        ) as collect, mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ) as open_handles, mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ) as terminate_handles, mock.patch.object(
            vscode_helper, "_close_handles"
        ) as close_handles, mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ) as thaw_unit, mock.patch.object(
            vscode_helper, "_query_code_unit"
        ) as query, mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ) as query_frozen, mock.patch.object(
            vscode_helper, "_query_stopped_code_unit"
        ) as query_stopped, mock.patch.object(
            vscode_helper,
            "_list_code_units",
            side_effect=[unit_states, unit_states, {}],
        ) as list_units, mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ) as systemctl:
            vscode_helper.stop_vscode_units(Path("/proc"))
        self.assertEqual(query.call_count, 2)
        self.assertEqual(query_frozen.call_count, 2)
        self.assertEqual(list_units.call_count, 3)
        open_handles.assert_called_once_with(units, manager.pid, Path("/proc"))
        terminate_handles.assert_called_once_with(handles, manager.pid, Path("/proc"))
        close_handles.assert_called_once_with(handles)
        self.assertEqual(
            thaw_unit.call_args_list,
            [
                mock.call("app-code-101.scope"),
                mock.call("app-code@0123456789abcdef0123456789abcdef.service"),
            ],
        )
        self.assertEqual(
            query_stopped.call_args_list,
            [
                mock.call("app-code-101.scope"),
                mock.call("app-code@0123456789abcdef0123456789abcdef.service"),
            ],
        )
        self.assertEqual(
            collect.call_args_list[2].kwargs["allowed_dead"], {(101, 900)}
        )
        self.assertEqual(
            systemctl.call_args_list,
            [
                mock.call(
                    [
                        "freeze",
                        "--",
                        "app-code-101.scope",
                        "app-code@0123456789abcdef0123456789abcdef.service",
                    ]
                ),
            ],
        )

        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper, "collect_code_unit_members", return_value=units
        ), mock.patch.object(
            vscode_helper,
            "_list_code_units",
            return_value={
                **unit_states,
                "app-code-202.scope": ("loaded", "active", "running"),
            },
        ):
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "systemd/process inventory differs"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))

        replacement = {"app-code-202.scope": []}
        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, units, replacement],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper, "_list_code_units", return_value=unit_states
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ) as failed_systemctl:
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "new VS Code units appeared"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))
        self.assertEqual(
            failed_systemctl.call_args_list,
            [
                mock.call(
                    [
                        "freeze",
                        "--",
                        "app-code-101.scope",
                        "app-code@0123456789abcdef0123456789abcdef.service",
                    ]
                ),
            ],
        )

        same_name_replacement = {
            "app-code@0123456789abcdef0123456789abcdef.service": [],
            "app-code-101.scope": [
                vscode_helper.Snapshot(
                    **{**member.__dict__, "pid": 202, "starttime": 901}
                )
            ],
        }
        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, units, same_name_replacement],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit"
        ), mock.patch.object(
            vscode_helper, "_list_code_units", return_value=unit_states
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ):
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "new VS Code process appeared"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))

        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, units, {}],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper,
            "_query_stopped_code_unit",
            side_effect=vscode_helper.DrainError("unit remained active"),
        ), mock.patch.object(
            vscode_helper,
            "_list_code_units",
            side_effect=[
                unit_states,
                unit_states,
                {"app-code-101.scope": ("loaded", "active", "running")},
            ],
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ), mock.patch.object(
            vscode_helper.time, "monotonic", side_effect=[0.0, 31.0]
        ):
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "unit remained active"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))

        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, units, {}],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_stopped_code_unit"
        ), mock.patch.object(
            vscode_helper,
            "_list_code_units",
            side_effect=[
                unit_states,
                unit_states,
                {"app-code-202.scope": ("loaded", "active", "running")},
            ],
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ):
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "new VS Code units remained"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))

        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, replacement],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper, "_thaw_code_unit"
        ) as thaw_unit, mock.patch.object(
            vscode_helper, "_query_code_unit"
        ) as thaw_query, mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper, "_list_code_units", return_value=unit_states
        ), mock.patch.object(
            vscode_helper, "_systemctl", return_value=""
        ) as thaw_systemctl:
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "inventory changed before stop"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))
        self.assertEqual(
            thaw_systemctl.call_args_list,
            [
                mock.call(
                    [
                        "freeze",
                        "--",
                        "app-code-101.scope",
                        "app-code@0123456789abcdef0123456789abcdef.service",
                    ]
                ),
            ],
        )
        self.assertEqual(thaw_query.call_count, 2)
        self.assertEqual(thaw_unit.call_count, 2)

        with mock.patch.object(
            vscode_helper, "find_user_manager", return_value=manager
        ), mock.patch.object(
            vscode_helper,
            "collect_code_unit_members",
            side_effect=[units, replacement],
        ), mock.patch.object(
            vscode_helper, "_open_code_unit_handles", return_value=handles
        ), mock.patch.object(
            vscode_helper, "_terminate_frozen_code_handles"
        ), mock.patch.object(
            vscode_helper, "_close_handles"
        ), mock.patch.object(
            vscode_helper,
            "_thaw_code_unit",
            side_effect=vscode_helper.DrainError("thaw failed"),
        ), mock.patch.object(
            vscode_helper, "_query_code_unit"
        ), mock.patch.object(
            vscode_helper, "_query_frozen_code_unit"
        ), mock.patch.object(
            vscode_helper, "_list_code_units", return_value=unit_states
        ), mock.patch.object(
            vscode_helper,
            "_systemctl",
            return_value="",
        ):
            with self.assertRaisesRegex(
                vscode_helper.DrainError, "validation failed and cleanup failed"
            ):
                vscode_helper.stop_vscode_units(Path("/proc"))

    def test_vscode_1133_crashpad_identities_are_exact_and_narrow(self):
        self.assertEqual(
            hashlib.sha256(VSCODE_1133_KONSOLE_CRASHPAD_CMDLINE).hexdigest(),
            vscode_helper.KONSOLE_CRASHPAD_CMDLINE_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(VSCODE_1133_DESKTOP_CRASHPAD_CMDLINE).hexdigest(),
            vscode_helper.DESKTOP_CRASHPAD_CMDLINE_SHA256,
        )
        konsole = vscode_helper.Snapshot(
            pid=101,
            comm="chrome_crashpad",
            state="S",
            ppid=42,
            starttime=900,
            uids=(1000, 1000, 1000, 1000),
            exe="/usr/share/code/chrome_crashpad_handler",
            cmdline=VSCODE_1133_KONSOLE_CRASHPAD_CMDLINE,
            cgroup=(
                b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                b"app-org.kde.konsole-10.scope/tab(11).scope\n"
            ),
        )
        desktop = vscode_helper.Snapshot(
            **{
                **konsole.__dict__,
                "pid": 102,
                "cmdline": VSCODE_1133_DESKTOP_CRASHPAD_CMDLINE,
                "cgroup": (
                    b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                    b"app-code@0123456789abcdef0123456789abcdef.service\n"
                ),
            }
        )
        self.assertEqual(vscode_helper.validate_helper(konsole, 42), "crashpad")
        self.assertEqual(vscode_helper.validate_helper(desktop, 42), "crashpad")
        with self.assertRaises(vscode_helper.DrainError):
            vscode_helper.validate_helper(
                vscode_helper.Snapshot(
                    **{
                        **konsole.__dict__,
                        "cmdline": VSCODE_1133_KONSOLE_CRASHPAD_CMDLINE + b"--extra\0",
                    }
                ),
                42,
            )
        with self.assertRaises(vscode_helper.DrainError):
            vscode_helper.validate_helper(
                vscode_helper.Snapshot(
                    **{
                        **desktop.__dict__,
                        "cmdline": VSCODE_1133_KONSOLE_CRASHPAD_CMDLINE,
                    }
                ),
                42,
            )

    def test_explicit_cgroup_modes_survive_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = "umask 077; mkdir -m 0755 authority; mkdir -m 0755 authority/controller authority/measurement"
            subprocess.run(["/usr/bin/bash", "-ceu", script], cwd=root, check=True)
            self.assertEqual((root / "authority").stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "authority/controller").stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "authority/measurement").stat().st_mode & 0o777, 0o755)

    def test_launcher_pins_and_verifies_all_traversal_modes(self):
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('mkdir -m 0755 "$authority"', text)
        self.assertIn('mkdir -m 0755 "$controller" "$measurement"', text)
        self.assertNotIn('mkdir "$authority"', text)
        self.assertNotIn('mkdir "$controller" "$measurement"', text)
        self.assertEqual(text.count("delegated cgroup traversal mode differs"), 1)
        self.assertLess(text.index('mkdir -m 0755 "$authority"'), text.index('created_authority=1'))
        self.assertLess(text.index('mkdir -m 0755 "$controller"'), text.index('chown "$(id -u'))

    def test_launcher_pins_exact_current_child_hash_inventory(self):
        text = LAUNCHER.read_text(encoding="utf-8")
        start = text.index("printf '%s  %s\\n' \\")
        end = text.index("  | /usr/bin/sha256sum -c -", start)
        pairs = re.findall(
            r'  ([0-9a-f]{64}) \\\n  "\$run_root/([^"]+)" \\',
            text[start:end],
        )
        names = (
            "static-preflight.py",
            "run-static-preflight.sh",
            "container-entry.py",
            "cgroup-smoke.py",
            "git-authority-entry.sh",
            "run-confirmation.sh",
        )
        self.assertEqual(
            pairs,
            [(sha256(ROOT / name), name) for name in names],
        )

    def test_controller_requires_preexisting_pause_before_journal(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        requirement = "((count == 1)) || {\n    echo 'exactly one pre-existing Podman pause process is required before authority mutation'"
        self.assertIn(requirement, text)
        self.assertLess(text.index("capture_pause_identity\n"), text.index("write_transaction_journal\n"))
        self.assertLess(text.index("write_transaction_journal\n"), text.index("quiesce_system_units\n"))

    def test_guided_wrapper_materializes_and_validates_pause_before_isolation(self):
        text = WRAPPER.read_text(encoding="utf-8")
        call = "ensure_podman_pause\n"
        self.assertIn("ensure_podman_pause() {", text)
        self.assertEqual(text.count("/usr/bin/podman unshare /usr/bin/true"), 1)
        self.assertEqual(text.count(call), 1)
        self.assertLess(text.index(call), text.index("/usr/bin/sudo -v"))
        self.assertLess(
            text.index(call),
            text.index("/usr/bin/sudo -n /usr/bin/systemctl isolate multi-user.target"),
        )
        self.assertIn("podman-pause-[0-9a-f]+", text)

    def test_live_pause_matches_frozen_controller_contract(self):
        completed = subprocess.run(
            ["/usr/bin/pgrep", "-u", "1000", "-x", "catatonit"],
            text=True, capture_output=True, check=True,
        )
        pids = [int(value) for value in completed.stdout.split()]
        self.assertEqual(len(pids), 1)
        pid = pids[0]
        self.assertEqual((Path("/proc") / str(pid) / "cmdline").read_bytes(), b"catatonit\0-P\0")
        self.assertRegex(
            (Path("/proc") / str(pid) / "cgroup").read_text(encoding="ascii"),
            r"\A0::/user\.slice/user-1000\.slice/user@1000\.service/user\.slice/"
            r"podman-pause-[0-9a-f]+\.scope\n\Z",
        )
        status = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii")
        self.assertIn("Uid:\t1000\t1000\t1000\t1000\n", status)

    def test_hash_wiring_and_attempt_paths(self):
        launcher_hash = sha256(LAUNCHER)
        controller_hash = sha256(CONTROLLER)
        authorizer_hash = sha256(AUTHORIZER)
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn(f"readonly launcher_sha={launcher_hash}", authorizer)
        self.assertIn(f"readonly controller_sha={controller_hash}", authorizer)
        self.assertIn(f"readonly authorizer_sha={authorizer_hash}", wrapper)
        combined = authorizer + wrapper + CONTROLLER.read_text()
        self.assertNotIn("4bd5e0b-headless-v7-04", combined)
        self.assertIn("88e369b-confirmation-v7-24", combined)
        self.assertIn("p10-07-v7-confirmation-operator-88e369b-attempt24", authorizer)
        self.assertIn("CODESKEPTIC_GUIDED_CONFIRMATION_SUCCESS payload_exit=0", wrapper)
        self.assertIn("CODESKEPTIC_GUIDED_CONFIRMATION_FAILED payload_exit=$payload_rc", wrapper)
        self.assertIn("CODESKEPTIC_GUIDED_FINAL_EXIT=$payload_rc", wrapper)
        self.assertLess(
            wrapper.index("CODESKEPTIC_GUIDED_FINAL_EXIT=$payload_rc"),
            wrapper.rindex('exit "$payload_rc"'),
        )

    def test_short_launcher_pins_current_wrapper_and_helper(self):
        launcher = SHORT_LAUNCHER.read_text(encoding="utf-8")
        self.assertIn(f"readonly wrapper={WRAPPER}", launcher)
        self.assertIn(f"readonly wrapper_sha={sha256(WRAPPER)}", launcher)
        self.assertIn(f"readonly helper={VSCODE_HELPER}", launcher)
        self.assertIn(f"readonly helper_sha={sha256(VSCODE_HELPER)}", launcher)
        self.assertIn("CODESKEPTIC_A24_VSCODE_ABSENCE_STABLE", launcher)

    def test_attempt24_binds_the_qualified_wireplumber_candidate(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        controller = CONTROLLER.read_text(encoding="utf-8")
        expected_main = "wireplumber-0.5.14-1.1.codeskeptic.fc44.x86_64"
        expected_libs = "wireplumber-libs-0.5.14-1.1.codeskeptic.fc44.x86_64"
        expected_binary = "7f13a431f6f583ffed76a4e41992a5b1de034bd684010f977b638c359b27ed8f"
        for label, text in (("wrapper", wrapper), ("controller", controller)):
            with self.subTest(path=label):
                self.assertIn(expected_main, text)
                self.assertIn(expected_libs, text)
                self.assertIn(expected_binary, text)
                self.assertIn("rpm -V wireplumber wireplumber-libs", text)
                self.assertIn("require_wireplumber_candidate", text)
        self.assertLess(
            wrapper.index("require_wireplumber_candidate \\\n  || fail"),
            wrapper.index("capture_graphical_transition_baseline || fail"),
        )
        self.assertLess(
            controller.index("CODESKEPTIC_HEADLESS_GATE_BEGIN=require_wireplumber_candidate"),
            controller.index("CODESKEPTIC_HEADLESS_GATE_BEGIN=require_local_tty_session"),
        )

    def test_precontroller_status_is_unique_and_sealed_before_handoff(self):
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        wrapper = WRAPPER.read_text(encoding="utf-8")
        status = "p10-07-v7-confirmation-precontroller-88e369b-attempt24.status"
        helper_log = "p10-07-v7-confirmation-vscode-helper-88e369b-attempt24.log"
        self.assertIn(status, authorizer)
        self.assertIn(status, wrapper)
        self.assertIn(helper_log, authorizer)
        self.assertIn(helper_log, wrapper)
        self.assertIn("trap finish_precontroller_failure EXIT", authorizer)
        self.assertIn("CODESKEPTIC_PRECONTROLLER_LAST_STEP", authorizer)
        self.assertIn("record_precontroller_step vscode-absence-check-started", authorizer)
        self.assertIn("record_precontroller_step vscode-absence-check-passed", authorizer)
        self.assertIn('2>&1 | \\\n  /usr/bin/tee "$helper_log"', authorizer)
        self.assertIn("seal_helper_log", authorizer)
        self.assertIn("record_precontroller_step snapshot-ready", authorizer)
        self.assertIn("seal_precontroller_status\nexec /usr/bin/sudo -n", authorizer)
        self.assertLess(
            authorizer.index("seal_precontroller_status\nexec /usr/bin/sudo -n"),
            authorizer.index("$controller_staged", authorizer.index("seal_precontroller_status\nexec /usr/bin/sudo -n")),
        )

    def test_vscode_absence_check_precedes_user_graphical_target_shutdown(self):
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        self.assertLess(
            authorizer.index("record_precontroller_step vscode-absence-check-passed"),
            authorizer.index('userctl stop -- "${user_graphical_targets[@]}"'),
        )

    def test_all_authorizer_sudo_after_gui_shutdown_is_noninteractive(self):
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        self.assertNotIn("/usr/bin/sudo -v", authorizer)
        self.assertEqual(authorizer.count("/usr/bin/sudo -n -v"), 1)
        self.assertLess(
            authorizer.index("/usr/bin/sudo -n -v"),
            authorizer.index("/usr/bin/sudo -n /usr/bin/install -d"),
        )

    def test_quiesce_stops_before_one_batched_mask_and_never_stops_masked_graph(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        system = text[
            text.index("quiesce_system_units() {") : text.index("quiesce_user_units() {")
        ]
        user = text[
            text.index("quiesce_user_units() {") : text.index("verify_unit_restoration() {")
        ]
        system_mask = '/usr/bin/systemctl mask --runtime -- "${system_mask_attempted_units[@]}"'
        user_mask = 'userctl mask --runtime -- "${user_mask_attempted_units[@]}"'
        self.assertEqual(system.count("/usr/bin/systemctl mask --runtime --"), 1)
        self.assertEqual(user.count("userctl mask --runtime --"), 1)
        self.assertIn(system_mask, system)
        self.assertIn(user_mask, user)
        self.assertNotIn('/usr/bin/systemctl mask --runtime -- "$unit"', system)
        self.assertNotIn('userctl mask --runtime -- "$unit"', user)
        system_stop = '/usr/bin/systemctl stop -- "${system_planned_units[@]}"'
        user_stop = 'userctl stop -- "${user_planned_units[@]}"'
        self.assertEqual(system.count(system_stop), 1)
        self.assertEqual(user.count(user_stop), 1)
        self.assertLess(system.index(system_stop), system.index(system_mask))
        self.assertLess(user.index(user_stop), user.index(user_mask))
        self.assertLess(
            system.index("verify_system_quiescent_units stopped"),
            system.index(system_mask),
        )
        self.assertLess(
            user.index("verify_user_quiescent_units stopped"),
            user.index(user_mask),
        )
        self.assertNotIn(" stop -- ", system[system.index(system_mask) :])
        self.assertNotIn(" stop -- ", user[user.index(user_mask) :])

    def test_quiesce_captures_activation_guard_and_restores_gap_activations(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        system = text[
            text.index("quiesce_system_units() {") : text.index("quiesce_user_units() {")
        ]
        user = text[
            text.index("quiesce_user_units() {") : text.index("verify_unit_restoration() {")
        ]
        self.assertIn("capture_system_activation_guard", system)
        self.assertIn("capture_user_activation_guard", user)
        self.assertEqual(system.count("require_no_planned_activation_after_cursor system"), 3)
        self.assertEqual(user.count("require_no_planned_activation_after_cursor user"), 3)
        guard = text[
            text.index("capture_system_activation_guard() {") :
            text.index("require_no_planned_activation_after_cursor() {")
        ]
        self.assertIn("--show-cursor -n 0", guard)
        journal_guard = text[
            text.index("require_no_planned_activation_after_cursor() {") :
            text.index("system_quiescent_show() {")
        ]
        self.assertIn("--after-cursor=", journal_guard)
        self.assertIn('MESSAGE_ID="$systemd_unit_starting_message_id"', journal_guard)
        self.assertIn('MESSAGE_ID="$systemd_unit_started_message_id"', journal_guard)
        self.assertIn('MESSAGE_ID="$systemd_unit_failed_message_id"', journal_guard)
        self.assertIn("7d4958e842da4a758f6c1cdc7b36dcc5", text)
        self.assertIn("39f53479d3a045ac8e11786248231fbf", text)
        self.assertIn("be02cf6855d2428ba40df7e9d022f03d", text)
        self.assertIn("journalctl --sync", journal_guard)
        self.assertIn("/usr/bin/jq -r", journal_guard)
        user_journal = text[
            text.index("userjournal() {") : text.index("usergit() {")
        ]
        self.assertIn('/usr/bin/runuser -u "$target_user" --', user_journal)
        self.assertIn("/usr/bin/journalctl --user --quiet --no-pager", user_journal)
        self.assertNotIn(
            "/usr/bin/journalctl --user",
            text[text.index("capture_user_activation_guard() {") :
                 text.index("require_no_planned_activation_after_cursor() {")],
        )
        verifier = text[
            text.index("system_quiescent_show() {") :
            text.index("quiesce_system_units() {")
        ]
        self.assertIn("ActiveEnterTimestampMonotonic", verifier)
        self.assertIn("InactiveExitTimestampMonotonic", verifier)
        self.assertEqual(verifier.count('/usr/bin/systemctl show "$1"'), 1)
        self.assertEqual(verifier.count('userctl show "$1"'), 1)
        self.assertIn("quiescent_job=${snapshot[Job]}", verifier)
        self.assertIn("epoch_mode=", verifier)
        self.assertIn("gc-reset", verifier)
        self.assertIn("invalid-epoch-normalization", verifier)
        self.assertIn("verify_runtime_mask_link", verifier)
        self.assertNotIn("resources/masked-runtime", verifier)
        self.assertNotIn("core-dump", verifier)
        for marker in (
            "stopped-snapshot", "stopped-journal", "masked-initial",
            "masked-initial-journal", "masked-stable", "masked-stable-journal",
        ):
            self.assertIn(marker, system)
            self.assertIn(marker, user)
        restore = text[
            text.index("restore_transaction() {") : text.index("validate_terminal_receipt() {")
        ]
        self.assertIn("stop_unexpected_transaction_activations system", restore)
        self.assertIn("stop_unexpected_transaction_activations user", restore)
        self.assertNotIn("reset-failed", restore)
        self.assertNotIn("reset_inactive_transaction_failures", restore)
        self.assertIn("verify_original_unit_files system", restore)
        self.assertIn("verify_original_unit_files user", restore)
        self.assertIn("if [[ $graph_ready != 1 ]]", restore)
        self.assertIn("refusing corrective stop/start on a masked graph", restore)
        self.assertLess(
            restore.index("stop_unexpected_transaction_activations system"),
            restore.index('/usr/bin/systemctl start -- "${system_restore_units[@]}"'),
        )
        self.assertLess(
            restore.index("stop_unexpected_transaction_activations user"),
            restore.index('userctl start -- "${user_restore_units[@]}"'),
        )

    def test_quiet_authority_rechecks_masked_snapshots_and_journals(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        quiet = text[
            text.index("require_quiet_authority() {") :
            text.index("prepare_system_units() {")
        ]
        system_snapshot = "verify_system_quiescent_units masked stable"
        system_journal = "require_no_planned_activation_after_cursor system"
        user_snapshot = "verify_user_quiescent_units masked stable"
        user_journal = "require_no_planned_activation_after_cursor user"
        for guard in (system_snapshot, system_journal, user_snapshot, user_journal):
            self.assertEqual(quiet.count(guard), 1)
        self.assertLess(quiet.index(system_snapshot), quiet.index(system_journal))
        self.assertLess(quiet.index(system_journal), quiet.index(user_snapshot))
        self.assertLess(quiet.index(user_snapshot), quiet.index(user_journal))

    def test_strict_quiescent_matrix_rejects_all_failed_results(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("verify_quiescent_units() {")
        matrix = text[start:text.index("quiesce_system_units() {", start)]
        self.assertIn("*.target)", matrix)
        self.assertIn("[[ -z $quiescent_result ]]", matrix)
        self.assertIn("*.service|*.timer|*.socket|*.path)", matrix)
        self.assertIn("[[ $quiescent_result == success ]]", matrix)
        self.assertIn('$quiescent_state == inactive', matrix)
        self.assertIn('$quiescent_substate == dead', matrix)
        self.assertIn("typed-result", matrix)
        self.assertIn("target-result", matrix)
        self.assertNotIn("reset-failed", matrix)
        self.assertNotIn("resources", matrix)
        self.assertNotIn("core-dump", matrix)

    def test_activation_guard_behavior_rejects_planned_and_dynamic_helpers(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("require_no_planned_activation_after_cursor() {")
        function = text[start:text.index("\n}\n\nsystem_quiescent_show()", start) + 2]
        for message_id, emitted_unit, expected_rc in (
            ("7d4958e842da4a758f6c1cdc7b36dcc5", "planned-trigger.service", 2),
            ("39f53479d3a045ac8e11786248231fbf", "planned-trigger.service", 2),
            ("be02cf6855d2428ba40df7e9d022f03d", "planned-trigger.service", 2),
            ("7d4958e842da4a758f6c1cdc7b36dcc5", "drkonqi-coredump-launcher@7-8-9.service", 2),
            ("39f53479d3a045ac8e11786248231fbf", "unrelated.service", 0),
        ):
            emitted_json = (
                '{"MESSAGE_ID":"' + message_id + '","USER_UNIT":"'
                + emitted_unit + '"}'
            )
            script = f"""
set -u -o pipefail
systemd_unit_starting_message_id=7d4958e842da4a758f6c1cdc7b36dcc5
systemd_unit_started_message_id=39f53479d3a045ac8e11786248231fbf
systemd_unit_failed_message_id=be02cf6855d2428ba40df7e9d022f03d
system_activation_cursor=system-cursor
user_activation_cursor=user-cursor
system_planned_units=()
user_planned_units=(planned-trigger.service)
array_contains() {{
  local needle=$1 item
  shift
  for item in "$@"; do [[ $item == "$needle" ]] && return 0; done
  return 1
}}
userjournal() {{
  [[ $* != *--sync* ]] || return 0
  printf '%s\n' {shlex.quote(emitted_json)}
}}
{function}
set +e
require_no_planned_activation_after_cursor user >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(message_id=message_id, unit=emitted_unit):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_user_plan_includes_timer_socket_and_path_trigger_closure(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        prepare = text[
            text.index("prepare_user_units() {") :
            text.index("write_transaction_journal() {")
        ]
        self.assertIn('triggers=$(user_value Triggers "$unit")', prepare)
        self.assertIn('trigger_units+=$\'\\n\'"$trigger"', prepare)
        self.assertIn('"$trigger_units"', prepare)
        self.assertIn("user activation trigger is not an exact service", prepare)

    def test_live_frozen_user_socket_endpoint_contract(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("socket_endpoint_listen_count() {")
        functions = text[start:text.index("\nvalidate_inert_user_service() {", start)]
        script = f"""
set -u -o pipefail
user_value() {{
  /usr/bin/env XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    /usr/bin/systemctl --user --no-pager show "$2" -p "$1" --value
}}
{functions}
for unit in \
  drkonqi-coredump-launcher.socket \
  pipewire-pulse.socket \
  pipewire.socket \
  ssh-agent.socket \
  systemd-ask-password.socket; do
  verify_frozen_user_socket_endpoints "$unit" active
done
set +e
verify_frozen_user_socket_endpoints unknown.socket active >/dev/null 2>&1
rc=$?
set -e
[[ $rc == 2 ]]
"""
        subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
            ],
            check=True,
            cwd=ROOT,
        )

    def test_masked_gc_socket_contract_uses_frozen_endpoint_inventory(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("socket_endpoint_listen_count() {")
        functions = text[start:text.index("\nvalidate_inert_user_service() {", start)]
        script = f"""
set -u -o pipefail
user_value() {{
  echo 'masked GC must not query discarded socket properties' >&2
  return 99
}}
{functions}
socket_endpoint_listen_count() {{ printf '0\\n'; }}
verify_frozen_user_socket_endpoints drkonqi-coredump-launcher.socket stopped masked

set +e
verify_frozen_user_socket_endpoints drkonqi-coredump-launcher.socket active masked >/dev/null 2>&1
active_rc=$?
verify_frozen_user_socket_endpoints drkonqi-coredump-launcher.socket stopped invalid >/dev/null 2>&1
invalid_rc=$?
socket_endpoint_listen_count() {{ printf '1\\n'; }}
verify_frozen_user_socket_endpoints drkonqi-coredump-launcher.socket stopped masked >/dev/null 2>&1
listening_rc=$?
set -e
[[ $active_rc == 2 && $invalid_rc == 2 && $listening_rc == 2 ]]
"""
        subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
            ],
            check=True,
            cwd=ROOT,
        )
        self.assertIn(
            '"$unit" stopped "$quiescent_load"',
            CONTROLLER.read_text(encoding="utf-8"),
        )

    def test_transient_gate_accepts_only_exact_planned_masked_services(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("validate_planned_masked_user_service_snapshot() {")
        function = text[start:text.index("\n}\n\ncollect_active_user_transients() {", start) + 2]
        script = f"""
set -u -o pipefail
array_contains() {{
  local needle=$1 item
  shift
  for item in "$@"; do [[ $item != "$needle" ]] || return 0; done
  return 1
}}
transient_snapshot_is_inert() {{ return 0; }}
{function}
user_masked_units=(planned.service)
snapshot_id=planned.service
snapshot_load=masked
snapshot_active=inactive
snapshot_sub=dead
snapshot_unit_file=masked-runtime
snapshot_transient=no
snapshot_main_pid=0
snapshot_control_pid=0

validate_planned_masked_user_service_snapshot planned.service
set +e
validate_planned_masked_user_service_snapshot unplanned.service >/dev/null 2>&1
unplanned_rc=$?
snapshot_active=active
validate_planned_masked_user_service_snapshot planned.service >/dev/null 2>&1
active_rc=$?
snapshot_active=inactive
snapshot_unit_file=masked
validate_planned_masked_user_service_snapshot planned.service >/dev/null 2>&1
unit_file_rc=$?
snapshot_unit_file=masked-runtime
snapshot_transient=yes
validate_planned_masked_user_service_snapshot planned.service >/dev/null 2>&1
transient_rc=$?
snapshot_transient=no
transient_snapshot_is_inert() {{ return 1; }}
validate_planned_masked_user_service_snapshot planned.service >/dev/null 2>&1
cgroup_rc=$?
set -e
[[ $unplanned_rc == 2 && $active_rc == 2 && $unit_file_rc == 2 && \
      $transient_rc == 2 && $cgroup_rc == 2 ]]
"""
        subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
            ],
            check=True,
            cwd=ROOT,
        )
        collector = text[
            text.index("collect_active_user_transients() {") :
            text.index("require_no_active_user_transients() {")
        ]
        self.assertIn("masked)", collector)
        self.assertEqual(
            collector.count('validate_planned_masked_user_service_snapshot "$unit"'),
            2,
        )
        self.assertIn(
            "CODESKEPTIC_HEADLESS_PLANNED_MASKED_SERVICE_INERT=$unit",
            collector,
        )
        quiet = text[
            text.index("require_quiet_authority() {") :
            text.index("prepare_system_units() {")
        ]
        for marker in (
            "local_tty_session", "system_headless", "no_failed_system_units",
            "no_failed_user_units", "coredump_unchanged",
            "no_active_user_transients", "minimal_user_units",
            "minimal_user_processes", "network_disabled",
            "system_timers_empty", "system_services_inactive",
            "system_plan_quiescent", "hardware_identity",
            "authority_paths_clear", "feature_repo_clean", "primary_repo_clean",
            "rejection_ledger", "rejection_bundle", "root_staging",
            "system_quiescence_recheck", "user_quiescence_recheck",
        ):
            self.assertIn(
                f"CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS={marker}",
                quiet,
            )

    def test_restoration_matrix_executes_type_pid_and_result_contract(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("verify_unit_restoration() {")
        function = text[start:text.index("\n}\n\nverify_pause_restoration()", start) + 2]
        cases = (
            ("exact.service", "active", "running", "success", "77", 0),
            ("exact.service", "active", "running", "success", "0", 2),
            ("exact.timer", "active", "waiting", "success", "0", 0),
            ("exact.socket", "active", "listening", "success", "0", 0),
            ("exact.path", "active", "running", "success", "0", 0),
            ("exact.target", "active", "active", "", "0", 0),
            ("exact.target", "active", "active", "success", "0", 2),
            ("exact.service", "inactive", "dead", "success", "0", 0),
            ("exact.service", "inactive", "failed", "exit-code", "0", 2),
        )
        for unit, state, substate, result, main_pid, expected_rc in cases:
            script = f"""
set -u -o pipefail
unit={shlex.quote(unit)}
mock_state={shlex.quote(state)}
mock_substate={shlex.quote(substate)}
mock_result={shlex.quote(result)}
mock_main_pid={shlex.quote(main_pid)}
system_restore_units=()
user_restore_units=()
[[ $mock_state != active ]] || user_restore_units=("$unit")
declare -A system_original_unit_files=()
declare -A user_original_unit_files=(["$unit"]=enabled)
array_contains() {{
  local needle=$1 item
  shift
  for item in "$@"; do [[ $item == "$needle" ]] && return 0; done
  return 1
}}
user_value() {{
  case $1 in
    ActiveState) printf '%s' "$mock_state" ;;
    SubState) printf '%s' "$mock_substate" ;;
    Result) printf '%s' "$mock_result" ;;
    UnitFileState) printf enabled ;;
    Job) : ;;
    MainPID) printf '%s' "$mock_main_pid" ;;
    *) return 2 ;;
  esac
}}
system_value() {{ return 2; }}
verify_frozen_user_socket_endpoints() {{ return 0; }}
{function}
set +e
verify_unit_restoration user "$unit" >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(unit=unit, state=state, substate=substate, result=result):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_quiescent_user_matrix_executes_gc_normalization_contract(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("read_quiescent_snapshot() {")
        functions = text[start:text.index("\nquiesce_system_units() {", start)]
        cases = (
            # phase, sample, unit, load, state, result, file, job, enter, exit, rc
            ("stopped", "single", "exact.service", "loaded", "inactive", "success", "enabled", "", "10", "20", 0),
            ("masked", "initial", "exact.service", "loaded", "inactive", "success", "masked-runtime", "", "10", "20", 0),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "masked-runtime", "", "10", "20", 0),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "masked-runtime", "", "0", "0", 0),
            ("masked", "initial", "exact.service", "loaded", "inactive", "success", "masked-runtime", "", "0", "0", 2),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "masked-runtime", "", "0", "20", 2),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "masked-runtime", "", "11", "20", 2),
            ("masked", "initial", "exact.service", "masked", "active", "success", "masked-runtime", "", "10", "20", 2),
            ("masked", "initial", "exact.service", "masked", "inactive", "core-dump", "masked-runtime", "", "10", "20", 2),
            ("masked", "initial", "exact.timer", "masked", "inactive", "resources", "masked-runtime", "", "10", "20", 2),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "masked-runtime", "99/start", "10", "20", 2),
            ("masked", "initial", "exact.service", "masked", "inactive", "success", "disabled", "", "10", "20", 2),
            ("masked", "initial", "exact.target", "masked", "inactive", "", "masked-runtime", "", "0", "0", 0),
            ("masked", "initial", "exact.target", "masked", "inactive", "success", "masked-runtime", "", "0", "0", 2),
        )
        for phase, sample, unit, load, state, result, unit_file, job, enter, leave, expected_rc in cases:
            substate = "running" if state == "active" else "dead"
            script = f"""
set -u -o pipefail
user_runtime=/run/user/1000
user_activation_cursor=test-cursor
user_planned_units=({shlex.quote(unit)})
declare -A user_original_unit_files=([{shlex.quote(unit)}]=enabled)
declare -A user_active_enter_epoch=([{shlex.quote(unit)}]=10)
declare -A user_inactive_exit_epoch=([{shlex.quote(unit)}]=20)
declare -A user_masked_epoch_mode=()
declare -A user_masked_load_state=()
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter=
quiescent_inactive_exit= quiescent_epoch_mode=
mock_load={shlex.quote(load)}
mock_state={shlex.quote(state)}
mock_substate={shlex.quote(substate)}
mock_result={shlex.quote(result)}
mock_file={shlex.quote(unit_file)}
mock_job={shlex.quote(job)}
mock_enter={shlex.quote(enter)}
mock_exit={shlex.quote(leave)}
user_quiescent_show() {{
  printf 'LoadState=%s\nActiveState=%s\nSubState=%s\nResult=%s\nUnitFileState=%s\nJob=%s\nActiveEnterTimestampMonotonic=%s\nInactiveExitTimestampMonotonic=%s\n' \
    "$mock_load" "$mock_state" "$mock_substate" "$mock_result" "$mock_file" \
    "$mock_job" "$mock_enter" "$mock_exit"
}}
{functions}
verify_runtime_mask_link() {{ return 0; }}
verify_frozen_user_socket_endpoints() {{ return 0; }}
set +e
verify_user_quiescent_units {shlex.quote(phase)} {shlex.quote(sample)} >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(phase=phase, unit=unit, load=load, enter=enter, leave=leave):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_quiescent_snapshot_parser_rejects_split_or_malformed_inventory(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("read_quiescent_snapshot() {")
        function = text[start:text.index("\n}\n\nreject_quiescent_snapshot()", start) + 2]
        valid = (
            "LoadState=masked\nActiveState=inactive\nSubState=dead\nResult=success\n"
            "UnitFileState=masked-runtime\nJob=\nActiveEnterTimestampMonotonic=0\n"
            "InactiveExitTimestampMonotonic=0"
        )
        for unit, payload, expected_rc in (
            ("exact.service", valid, 0),
            ("exact.service", valid + "\nLoadState=masked", 2),
            ("exact.service", valid.replace("Result=success\n", ""), 2),
            ("exact.target", valid.replace("Result=success\n", ""), 0),
            ("exact.target", valid.replace("Result=success", "Result="), 0),
            ("exact.service", valid + "\nUnknown=value", 2),
            ("exact.service", valid.replace("Job=", "malformed"), 2),
        ):
            script = f"""
set -u -o pipefail
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter= quiescent_inactive_exit=
system_quiescent_show() {{ printf '%s\n' {shlex.quote(payload)}; }}
{function}
set +e
read_quiescent_snapshot system {shlex.quote(unit)} >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(unit=unit, expected_rc=expected_rc, payload=payload[-32:]):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_live_system_target_snapshot_synthesizes_only_unsupported_result(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("system_quiescent_show() {")
        functions = text[start:text.index("\n}\n\nreject_quiescent_snapshot()", start) + 2]
        script = f"""
set -u -o pipefail
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter= quiescent_inactive_exit=
userctl() {{ return 2; }}
{functions}
read_quiescent_snapshot system graphical.target
[[ $quiescent_load == loaded ]]
[[ -n $quiescent_state && -n $quiescent_substate && -n $quiescent_unit_file ]]
[[ -z $quiescent_result && -z $quiescent_job ]]
[[ $quiescent_active_enter =~ ^[0-9]+$ ]]
[[ $quiescent_inactive_exit =~ ^[0-9]+$ ]]
"""
        subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
            ],
            check=True,
            cwd=ROOT,
        )

    def test_live_user_target_snapshot_synthesizes_only_unsupported_result(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("system_quiescent_show() {")
        functions = text[start:text.index("\n}\n\nreject_quiescent_snapshot()", start) + 2]
        script = f"""
set -u -o pipefail
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter= quiescent_inactive_exit=
userctl() {{ /usr/bin/systemctl --user --no-pager "$@"; }}
{functions}
read_quiescent_snapshot user plasma-workspace-wayland.target
[[ $quiescent_load == loaded ]]
[[ -n $quiescent_state && -n $quiescent_substate && -n $quiescent_unit_file ]]
[[ -z $quiescent_result && -z $quiescent_job ]]
[[ $quiescent_active_enter =~ ^[0-9]+$ ]]
[[ $quiescent_inactive_exit =~ ^[0-9]+$ ]]
"""
        subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                "XDG_RUNTIME_DIR=/run/user/1000",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
            ],
            check=True,
            cwd=ROOT,
        )

    def test_quiescent_stable_sample_rejects_gc_rehydration(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("read_quiescent_snapshot() {")
        functions = text[start:text.index("\nquiesce_system_units() {", start)]
        for initial_load, initial_enter, stable_load, stable_enter, expected_rc in (
            ("loaded", "10", "loaded", "10", 0),
            ("loaded", "10", "masked", "0", 0),
            ("masked", "10", "masked", "10", 0),
            ("masked", "0", "masked", "0", 0),
            ("masked", "0", "masked", "10", 2),
            ("masked", "10", "loaded", "10", 2),
        ):
            script = f"""
set -u -o pipefail
user_runtime=/run/user/1000
user_activation_cursor=test-cursor
user_planned_units=(exact.service)
declare -A user_original_unit_files=([exact.service]=enabled)
declare -A user_active_enter_epoch=([exact.service]=10)
declare -A user_inactive_exit_epoch=([exact.service]=20)
declare -A user_masked_epoch_mode=()
declare -A user_masked_load_state=()
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter=
quiescent_inactive_exit= quiescent_epoch_mode=
mock_load={shlex.quote(initial_load)}
mock_enter={shlex.quote(initial_enter)}
user_quiescent_show() {{
  local leave=20
  [[ $mock_enter != 0 ]] || leave=0
  printf 'LoadState=%s\nActiveState=inactive\nSubState=dead\nResult=success\nUnitFileState=masked-runtime\nJob=\nActiveEnterTimestampMonotonic=%s\nInactiveExitTimestampMonotonic=%s\n' \
    "$mock_load" "$mock_enter" "$leave"
}}
{functions}
verify_runtime_mask_link() {{ return 0; }}
verify_frozen_user_socket_endpoints() {{ return 0; }}
verify_user_quiescent_units masked initial >/dev/null
mock_load={shlex.quote(stable_load)}
mock_enter={shlex.quote(stable_enter)}
set +e
verify_user_quiescent_units masked stable >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(initial=(initial_load, initial_enter), stable=(stable_load, stable_enter)):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_quiescent_stable_samples_advance_monotonic_gc_state(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("read_quiescent_snapshot() {")
        functions = text[start:text.index("\nquiesce_system_units() {", start)]
        for samples, expected_rc in (
            (("loaded", "10", "masked", "0", "loaded", "10"), 2),
            (("masked", "10", "masked", "0", "masked", "10"), 2),
            (("loaded", "10", "loaded", "10", "masked", "0"), 0),
            (("loaded", "10", "masked", "0", "masked", "0"), 0),
            (("masked", "10", "masked", "10", "masked", "0"), 0),
        ):
            initial_load, initial_enter, second_load, second_enter, third_load, third_enter = samples
            script = f"""
set -u -o pipefail
user_runtime=/run/user/1000
user_activation_cursor=test-cursor
user_planned_units=(exact.service)
declare -A user_original_unit_files=([exact.service]=enabled)
declare -A user_active_enter_epoch=([exact.service]=10)
declare -A user_inactive_exit_epoch=([exact.service]=20)
declare -A user_masked_epoch_mode=()
declare -A user_masked_load_state=()
quiescent_load= quiescent_state= quiescent_substate= quiescent_result=
quiescent_unit_file= quiescent_job= quiescent_active_enter=
quiescent_inactive_exit= quiescent_epoch_mode=
mock_load={shlex.quote(initial_load)}
mock_enter={shlex.quote(initial_enter)}
user_quiescent_show() {{
  local leave=20
  [[ $mock_enter != 0 ]] || leave=0
  printf 'LoadState=%s\nActiveState=inactive\nSubState=dead\nResult=success\nUnitFileState=masked-runtime\nJob=\nActiveEnterTimestampMonotonic=%s\nInactiveExitTimestampMonotonic=%s\n' \
    "$mock_load" "$mock_enter" "$leave"
}}
{functions}
verify_runtime_mask_link() {{ return 0; }}
verify_frozen_user_socket_endpoints() {{ return 0; }}
verify_user_quiescent_units masked initial >/dev/null
mock_load={shlex.quote(second_load)}
mock_enter={shlex.quote(second_enter)}
verify_user_quiescent_units masked stable >/dev/null
mock_load={shlex.quote(third_load)}
mock_enter={shlex.quote(third_enter)}
set +e
verify_user_quiescent_units masked stable >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
"""
            with self.subTest(samples=samples):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_stop_failure_is_fail_closed_before_any_mask(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        system = text[
            text.index("quiesce_system_units() {") : text.index("quiesce_user_units() {")
        ]
        user = text[
            text.index("quiesce_user_units() {") : text.index("verify_unit_restoration() {")
        ]
        self.assertIn(
            '/usr/bin/systemctl stop -- "${system_planned_units[@]}" || return 2',
            system,
        )
        self.assertIn('userctl stop -- "${user_planned_units[@]}" || return 2', user)
        self.assertLess(
            system.index('/usr/bin/systemctl stop -- "${system_planned_units[@]}"'),
            system.index('/usr/bin/systemctl mask --runtime --'),
        )
        self.assertLess(
            user.index('userctl stop -- "${user_planned_units[@]}"'),
            user.index('userctl mask --runtime --'),
        )

    def test_drkonqi_counter_transition_accepts_only_preservation_or_zero_reset(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        start = text.index("transition_drkonqi_counter_after_quiesce() {")
        function = text[start:text.index("\n}\n\nrequire_recovery_coredump_unchanged()", start) + 2]
        for previous, accepted, state, substate, result, job, expected_rc, expected_baseline in (
            (240, 240, "inactive", "dead", "success", "", 0, 240),
            (240, 0, "inactive", "dead", "success", "", 0, 0),
            (0, 0, "inactive", "dead", "success", "", 0, 0),
            (240, 241, "inactive", "dead", "success", "", 2, 240),
            (240, 20, "inactive", "dead", "success", "", 2, 240),
            (240, 240, "active", "listening", "success", "", 2, 240),
            (240, 240, "inactive", "dead", "resources", "", 2, 240),
            (240, 240, "inactive", "dead", "success", "7/start", 2, 240),
        ):
            script = f"""
set -u -o pipefail
user_planned_units=(drkonqi-coredump-launcher.socket)
user_restore_units=(drkonqi-coredump-launcher.socket)
drkonqi_socket_accepted_baseline={previous}
mock_state={shlex.quote(state)}
mock_substate={shlex.quote(substate)}
mock_result={shlex.quote(result)}
mock_job={shlex.quote(job)}
mock_accepted={accepted}
array_contains() {{ local needle=$1 item; shift; for item in "$@"; do [[ $item != "$needle" ]] || return 0; done; return 1; }}
user_value() {{
  case "$1" in
    ActiveState) printf '%s\n' "$mock_state" ;;
    SubState) printf '%s\n' "$mock_substate" ;;
    Result) printf '%s\n' "$mock_result" ;;
    Job) printf '%s\n' "$mock_job" ;;
    NAccepted) printf '%s\n' "$mock_accepted" ;;
    *) return 2 ;;
  esac
}}
{function}
set +e
transition_drkonqi_counter_after_quiesce >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
[[ $drkonqi_socket_accepted_baseline == {expected_baseline} ]]
"""
            with self.subTest(previous=previous, accepted=accepted, state=state, result=result, job=job):
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_drkonqi_counter_transition_runs_only_after_masked_snapshot_and_journal(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        user = text[
            text.index("quiesce_user_units() {") : text.index("verify_unit_restoration() {")
        ]
        transition = "transition_drkonqi_counter_after_quiesce"
        self.assertEqual(user.count(transition), 1)
        self.assertLess(user.index("masked-initial-journal"), user.index(transition))
        self.assertLess(user.index(transition), user.index("masked-stable"))
        self.assertLess(user.index('userctl mask --runtime --'), user.index(transition))

    def test_coredump_guards_cover_every_authority_boundary_and_journal_v3(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("capture_graphical_transition_baseline", wrapper)
        self.assertGreaterEqual(wrapper.count("require_graphical_transition_clean"), 3)
        self.assertIn("require_graphical_transition_non_counter_clean", wrapper)
        self.assertIn("transition_graphical_counter_after_receipt", wrapper)
        transition = wrapper[
            wrapper.index("transition_graphical_counter_after_receipt() {") :
            wrapper.index("restoration_surface_clean() {")
        ]
        self.assertIn("$terminal_journal_sha != none", transition)
        self.assertIn("JOURNAL_DRKONQI_SOCKET_NACCEPTED=*", transition)
        self.assertIn(
            "JOURNAL_USER_UNIT=drkonqi-coredump-launcher.socket\\|*", transition
        )
        self.assertIn(
            '$journal_accepted == "$drkonqi_accepted_before_isolate"', transition
        )
        self.assertIn(
            '( $accepted == "$journal_accepted" || $accepted == 0 )',
            transition,
        )
        self.assertIn('$unit_file == "$journal_unit_file"', transition)
        self.assertIn("drkonqi_accepted_before_isolate=$accepted", transition)
        self.assertIn("CODESKEPTIC_GUIDED_DRKONQI_COUNTER_TRANSITION", transition)
        handoff = wrapper[
            wrapper.index("qualification_contaminated=0") :
            wrapper.index("ring\nsay 'Confirmation işlemi döndü")
        ]
        self.assertEqual(handoff.count("capture_graphical_transition_baseline"), 1)
        self.assertLess(
            handoff.index("require_graphical_transition_non_counter_clean"),
            handoff.index("validate_terminal_receipt"),
        )
        self.assertLess(
            handoff.index("validate_terminal_receipt"),
            handoff.index("transition_graphical_counter_after_receipt"),
        )
        self.assertLess(
            handoff.index("transition_graphical_counter_after_receipt"),
            handoff.index("require_graphical_transition_clean"),
        )
        self.assertIn(
            "if [[ $transaction_safe == 1 && $qualification_contaminated == 0 ]]; then\n"
            "  if ! require_graphical_transition_clean; then",
            handoff,
        )
        self.assertIn(
            "if [[ $transaction_safe == 1 && $qualification_contaminated == 1 ]]; then\n"
            "  if ! capture_graphical_transition_baseline || ! restoration_surface_clean; then",
            handoff,
        )
        self.assertIn(
            '"$authorizer" "$coredump_before_isolate_sha"', wrapper
        )
        self.assertIn("require_handoff_unchanged", authorizer)
        self.assertIn("[[ $# == 2", authorizer)
        self.assertIn("record_precontroller_step coredump-handoff-verified", authorizer)
        self.assertIn("record_precontroller_step final-coredump-handoff-verified", authorizer)
        self.assertIn(
            '"$coredump_handoff_sha" "$drkonqi_handoff_accepted"', authorizer
        )
        self.assertIn("capture_coredump_baseline", controller)
        self.assertIn("establish_inherited_coredump_baseline", controller)
        self.assertIn("require_coredump_unchanged", controller)
        self.assertIn("JOURNAL_VERSION=3", controller)
        self.assertIn("JOURNAL_COREDUMP_INVENTORY_SHA256=", controller)
        self.assertIn("JOURNAL_DRKONQI_SOCKET_NACCEPTED=", controller)
        self.assertIn("drkonqi_socket_accepted_journal_baseline", controller)
        self.assertIn("transition_drkonqi_counter_after_quiesce", controller)
        counter_transition = controller[
            controller.index("transition_drkonqi_counter_after_quiesce() {") :
            controller.index("require_recovery_coredump_unchanged() {")
        ]
        self.assertIn('$accepted == "$previous" || $accepted == 0', counter_transition)
        self.assertIn("drkonqi_socket_accepted_baseline=$accepted", counter_transition)
        self.assertIn("CODESKEPTIC_HEADLESS_DRKONQI_COUNTER_TRANSITION", counter_transition)
        user_quiesce = controller[
            controller.index("quiesce_user_units() {") :
            controller.index("verify_unit_restoration() {")
        ]
        self.assertLess(
            user_quiesce.index("capture_user_activation_guard"),
            user_quiesce.index("require_coredump_unchanged"),
        )
        self.assertLess(
            user_quiesce.index("require_coredump_unchanged"),
            user_quiesce.index('userctl stop -- "${user_planned_units[@]}"'),
        )
        for source in (wrapper, authorizer, controller):
            self.assertIn("drkonqi-coredump-launcher@*.service", source)
            self.assertIn("systemd-coredump@*.service", source)
            self.assertIn("drkonqi-coredump-processor@*.service", source)
            self.assertIn("NAccepted", source)
            self.assertIn("coredump_inventory_sha", source)
            self.assertIn("--json=short list", source)

    def test_guided_counter_transition_accepts_preserved_or_reset_counter(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        function = wrapper[
            wrapper.index("transition_graphical_counter_after_receipt() {") :
            wrapper.index("restoration_surface_clean() {")
        ]
        cases = (
            (160, 0, 160),
            (0, 0, 0),
            (161, 2, 160),
        )
        for accepted, expected_rc, expected_baseline in cases:
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as temporary:
                journal = Path(temporary) / "journal"
                journal.write_text(
                    "JOURNAL_VERSION=3\n"
                    "JOURNAL_DRKONQI_SOCKET_NACCEPTED=160\n"
                    "JOURNAL_USER_UNIT=drkonqi-coredump-launcher.socket|active|disabled\n",
                    encoding="ascii",
                )
                script = f"""
set -euo pipefail
terminal_journal_sha=present
transaction_journal={shlex.quote(str(journal))}
drkonqi_accepted_before_isolate=160
mock_accepted={accepted}
say() {{ :; }}
user_value() {{
  case "$1" in
    LoadState) printf '%s\n' loaded ;;
    ActiveState) printf '%s\n' active ;;
    SubState) printf '%s\n' listening ;;
    Result) printf '%s\n' success ;;
    UnitFileState) printf '%s\n' disabled ;;
    Job) printf '\n' ;;
    NAccepted) printf '%s\n' "$mock_accepted" ;;
    *) return 2 ;;
  esac
}}
{function}
set +e
transition_graphical_counter_after_receipt >/dev/null 2>&1
rc=$?
set -e
[[ $rc == {expected_rc} ]]
[[ $drkonqi_accepted_before_isolate == {expected_baseline} ]]
"""
                subprocess.run(
                    [
                        "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin",
                        "/usr/bin/bash", "--noprofile", "--norc", "-ceu", script,
                    ],
                    check=True,
                    cwd=ROOT,
                )

    def test_restoration_receipt_requires_clean_failed_inventories_and_coredump(self):
        text = CONTROLLER.read_text(encoding="utf-8")
        restore = text[text.index("restore_transaction() {") :]
        self.assertIn("require_no_failed_system_units || failed=1", restore)
        self.assertIn("require_no_failed_user_units || failed=1", restore)
        final_surface = text[
            text.index("require_final_restoration_surface() {") :
            text.index("validate_terminal_receipt() {")
        ]
        self.assertIn("require_no_coredump_helper_instances", final_surface)
        receipt = text[
            text.index("publish_terminal_receipt() {") :
            text.index("cleanup() {")
        ]
        self.assertIn("require_final_restoration_surface", receipt)
        self.assertIn("require_coredump_unchanged", receipt)
        self.assertIn("require_recovery_coredump_unchanged", receipt)
        self.assertGreater(
            receipt.index("require_final_restoration_surface"),
            receipt.index('actual=$(<"$terminal_receipt_tmp")'),
        )
        self.assertLess(
            receipt.index("require_final_restoration_surface"),
            receipt.index('/usr/bin/mv -T -- "$terminal_receipt_tmp"'),
        )
        self.assertLess(
            restore.index("require_no_failed_system_units || failed=1"),
            restore.index('return "$failed"'),
        )
        self.assertIn("CODESKEPTIC_HEADLESS_RESTORATION_FAILED=$restoration_failed", text)
    def test_guided_wrapper_has_no_one_off_failed_unit_exception(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertNotIn("foomatic", wrapper.lower())
        self.assertNotIn("reset-failed", wrapper)
        self.assertIn("require_no_failed_system_units\n", wrapper)

    def test_graphical_restore_waits_for_user_and_rings_without_open_sudo_prompt(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("await_graphical_restore_authorization() {", wrapper)
        self.assertIn("read -r -t 15", wrapper)
        wait_body = wrapper[wrapper.index("await_graphical_restore_authorization() {") :]
        self.assertIn("ring\n", wait_body)
        self.assertIn("CODESKEPTIC_GUIDED_GRAPHICAL_AUTHORIZATION_REQUIRED", wrapper)
        self.assertNotIn("/usr/bin/sudo /usr/bin/systemctl isolate graphical.target", wrapper)
        wait_call = wrapper.index("await_graphical_restore_authorization\n")
        refresh = wrapper.index("/usr/bin/sudo -v", wait_call)
        restore_function = wrapper.index(
            "/usr/bin/sudo -n /usr/bin/systemctl isolate graphical.target"
        )
        restore = wrapper.index("restore_graphical_noninteractive", refresh)
        self.assertLess(wait_call, refresh)
        self.assertLess(refresh, restore)
        self.assertLess(restore_function, restore)
        self.assertIn("CODESKEPTIC_GUIDED_GRAPHICAL_AUTHORIZATION_ACKNOWLEDGED", wrapper)

    def test_graphical_authorization_accepts_only_empty_enter_and_propagates_signal(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        start = wrapper.index("await_graphical_restore_authorization() {")
        end = wrapper.index("\n}\n\nrestore_graphical_noninteractive()", start) + 2
        function = wrapper[start:end]
        common = (
            "set -u\n"
            "caller_tty=\n"
            "signal_received=\n"
            "ring() { :; }\n"
            "say() { printf '%s\\n' \"$*\"; }\n"
            "signal_exit_code() { case $signal_received in TERM) printf '143\\n';; *) printf '2\\n';; esac; }\n"
            f"{function}\n"
        )
        acknowledged = subprocess.run(
            ["/usr/bin/bash", "-c", common + "await_graphical_restore_authorization\n"],
            input="\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(acknowledged.returncode, 0)
        self.assertIn(
            "CODESKEPTIC_GUIDED_GRAPHICAL_AUTHORIZATION_ACKNOWLEDGED",
            acknowledged.stdout,
        )
        signaled = subprocess.run(
            [
                "/usr/bin/bash",
                "-c",
                common
                + "read() { signal_received=TERM; return 142; }\n"
                + "await_graphical_restore_authorization\n",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(signaled.returncode, 143)

    def test_guided_unique_precheck_includes_root_controller_log(self):
        wrapper = WRAPPER.read_text(encoding="utf-8")
        self.assertIn(
            "readonly headless_log=$headless_root/88e369b-confirmation-v7-24.log",
            wrapper,
        )
        absence = wrapper[wrapper.index('for path in "$headless_log"') :]
        self.assertLess(
            absence.index('for path in "$headless_log"'),
            absence.index("/usr/bin/sudo -v"),
        )

    def test_controller_pins_every_manifested_root_staging_file(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        for line in (ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, filename = line.split("  ", 1)
            with self.subTest(filename=filename):
                self.assertIn(f'{digest} "$run_root/{filename}"', controller)

    def test_manifest_and_authorizer_pin_current_root_staging_bytes(self):
        names = (
            "snapshot-builder.sh",
            "tree-hash.py",
            "cgroup-launcher.sh",
            "run-static-preflight.sh",
            "container-entry.py",
            "cgroup-smoke.py",
            "static-preflight.py",
            "git-authority-entry.sh",
            "run-confirmation.sh",
        )
        manifest = ROOT / "SHA256SUMS"
        entries = [
            tuple(line.split("  ", 1))
            for line in manifest.read_text(encoding="ascii").splitlines()
        ]
        self.assertEqual(entries, [(sha256(ROOT / name), name) for name in names])

        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        self.assertIn(
            f"readonly operator_manifest_sha={sha256(manifest)}",
            authorizer,
        )
        start = authorizer.index('readonly expected_hashes="')
        end = authorizer.index('"\nactual_hashes=', start)
        staged_hashes = authorizer[start:end]
        for name in names:
            expected = "$launcher_sha" if name == "cgroup-launcher.sh" else sha256(ROOT / name)
            with self.subTest(filename=name):
                self.assertIn(f"{expected}  $run_root/{name}", staged_hashes)
        self.assertIn("$helper_sha  $helper_staged", staged_hashes)
        self.assertIn("$controller_sha  $controller_staged", staged_hashes)

    def test_snapshot_builder_runs_before_controller(self):
        revision = "88e369b21675e64e0a92842b0ce22f0c8148745e"
        snapshot = SNAPSHOT_BUILDER.read_text(encoding="utf-8")
        authorizer = AUTHORIZER.read_text(encoding="utf-8")
        self.assertIn(f"readonly revision={revision}", snapshot)
        self.assertIn(f'"revision": "{revision}"', STATIC_PREFLIGHT.read_text(encoding="utf-8"))
        invocation = '/usr/bin/sudo -n "$run_root/snapshot-builder.sh"'
        self.assertEqual(authorizer.count(invocation), 1)
        self.assertLess(
            authorizer.index(invocation),
            authorizer.index('exec /usr/bin/sudo -n /usr/bin/flock'),
        )
        self.assertIn("if [[ -e $snapshot || -L $snapshot ]]; then", snapshot)
        self.assertEqual(snapshot.count("verify_snapshot\n"), 2)
        self.assertIn("sealed snapshot contains writable entries", snapshot)
        self.assertIn("export GIT_OPTIONAL_LOCKS=0", snapshot)
        self.assertIn("sealed snapshot changed during verification", snapshot)
        self.assertIn("sealed snapshot final ownership or write-protection drift", snapshot)
        self.assertEqual(snapshot.count('$(python3 "$tree_hash" "$snapshot")'), 2)
        self.assertIn('[[ $snapshot_after == "$snapshot_before" ]]', snapshot)
        self.assertLess(
            snapshot.index('snapshot_before=$(python3 "$tree_hash" "$snapshot")'),
            snapshot.index('git -C "$snapshot/source" rev-parse HEAD'),
        )
        self.assertLess(
            snapshot.index('git -C "$snapshot/llama-mirror.git" fsck --full --no-dangling'),
            snapshot.index('snapshot_after=$(python3 "$tree_hash" "$snapshot")'),
        )
        self.assertLess(
            snapshot.index('snapshot_after=$(python3 "$tree_hash" "$snapshot")'),
            snapshot.index("sealed snapshot final ownership or write-protection drift"),
        )

    def test_both_confirmation_containers_mount_the_pinned_build(self):
        runner = RUNNER.read_text(encoding="utf-8")
        mount = '-v "$build_host:/work/build-p10-07-v6-release:ro"'
        self.assertEqual(runner.count(mount), 2)
        first_run = runner.index("podman run --rm")
        second_run = runner.index("podman run --rm", first_run + 1)
        verify = runner.index("--verify-receipt /evidence/confirmation")
        first_mount = runner.index(mount)
        second_mount = runner.index(mount, first_mount + 1)
        self.assertLess(first_run, first_mount)
        self.assertLess(first_mount, second_run)
        self.assertLess(second_run, second_mount)
        self.assertLess(second_mount, verify)

    def test_kernel_identity_is_pinned_at_every_authority_boundary(self):
        expected = "Linux 6.19.10-300.fc44.x86_64"
        for path in (WRAPPER, CONTROLLER, LAUNCHER, ROOT / "run-static-preflight.sh", RUNNER):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(f"readonly expected_os='{expected}'", text)
                self.assertIn('$(/usr/bin/uname -sr) == "$expected_os"', text)
        preflight = STATIC_PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn(f'expected_os = "{expected}"', preflight)
        self.assertIn('observed_os = f"{platform.system()} {platform.release()}"', preflight)
        self.assertIn("if observed_os != expected_os:", preflight)

    def test_v7_confirmation_paths_and_fail_closed_outer_manifest(self):
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertEqual(runner.count("--baseline /work/scripts/determinism_baseline.json"), 2)
        self.assertEqual(runner.count("--baseline-authority-root /work"), 2)
        self.assertIn("--output /evidence/confirmation", runner)
        self.assertIn("--verify-receipt /evidence/confirmation", runner)
        self.assertNotIn("--establish-baseline", runner)
        self.assertNotIn("--calibration-output", runner)
        self.assertNotIn("baseline-v6.json", runner)
        self.assertIn("trap - EXIT\n  exit \"$status\"", runner)
        self.assertNotIn('return "$status"\n}\ntrap finalize EXIT', runner)
        self.assertIn("p10-07-v7-confirmation-88e369b-attempt24", runner)
        self.assertIn("-confirmation-v7-24", SNAPSHOT_BUILDER.read_text(encoding="utf-8"))

    def test_outer_manifest_failure_overrides_successful_payload_exit(self):
        text = RUNNER.read_text(encoding="utf-8")
        start = text.index("finalize() {")
        end = text.index("\n}\ntrap finalize EXIT", start) + 2
        finalize = text[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            fake_bin = root / "bin"
            stage.mkdir()
            fake_bin.mkdir()
            (stage / "evidence.txt").write_text("evidence\n", encoding="utf-8")
            fake_sha = fake_bin / "sha256sum"
            fake_sha.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            fake_sha.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                f"stage_host={shlex.quote(str(stage))}\n"
                f"PATH={shlex.quote(str(fake_bin))}:/usr/bin\n"
                f"{finalize}\n"
                "trap finalize EXIT\n"
                "exit 0\n"
            )
            completed = subprocess.run(
                ["/usr/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(
                "outer confirmation manifest verification failed",
                completed.stderr,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
