#!/usr/bin/env python3
"""Focused contract tests for the final P10-09 cgroup authority lifecycle."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts" / "stability-systemd"
AUTHORITY_PATH = OPERATOR / "cgroup-authority.py"
RUNNER_PATH = OPERATOR / "run-authoritative-stability.sh"
SESSION = (
    "20260824T010203Z-"
    "11111111-1111-1111-1111-111111111111-"
    "22222222-2222-2222-2222-222222222222"
)


def load_authority():
    spec = importlib.util.spec_from_file_location(
        "stability_cgroup_authority", AUTHORITY_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load cgroup authority helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


class StabilityCgroupAuthorityTest(unittest.TestCase):
    def test_helper_and_runner_share_the_exact_lifecycle(self) -> None:
        self.assertTrue(AUTHORITY_PATH.is_file())
        authority = AUTHORITY_PATH.read_text(encoding="utf-8")
        runner = RUNNER_PATH.read_text(encoding="utf-8")

        self.assertIn('STATE_ROOT = Path("/var/lib/codeskeptic-p10-09")', authority)
        self.assertIn('SERVICE = SYSTEM_SLICE / "codeskeptic-stability.service"', authority)
        self.assertIn('PAYLOAD = SERVICE / "codeskeptic-p10-09"', authority)
        self.assertIn('MEASUREMENT = PAYLOAD / "measurement"', authority)
        self.assertIn(
            'choices=("arm", "verify-active", "cleanup", "recover", "check-clean")',
            authority,
        )
        self.assertLess(
            authority.index("publish_marker(session)"),
            authority.index('write_control(SYSTEM_SLICE / "cpuset.cpus.exclusive"'),
        )
        self.assertIn('write_control(path / "cgroup.kill", "1")', authority)
        self.assertIn("remove_owned_tree(child", authority)
        self.assertIn("refusing to clear foreign", authority)
        self.assertLess(
            authority.index("validate_payload_tree(owned_container_ids)"),
            authority.index('kill_and_wait(PAYLOAD, "payload")'),
        )

        self.assertIn('readonly CGROUP_AUTHORITY="${OPERATOR_ROOT}/cgroup-authority.py"', runner)
        self.assertIn('readonly HOST_RECOVERY="${OPERATOR_ROOT}/host-recovery.py"', runner)
        self.assertIn('"$HOST_RECOVERY" recover', runner)
        self.assertIn('"$CGROUP_AUTHORITY" arm --session "$session_name"', runner)
        self.assertIn('"$CGROUP_AUTHORITY" verify-active --session "$session_name"', runner)
        self.assertIn('"$CGROUP_AUTHORITY" cleanup --session "$session_name"', runner)
        self.assertNotIn("cleanup_measurement_cgroup()", runner)
        self.assertNotIn("cgroup_prepared=", runner)
        self.assertLess(
            runner.index("enable_service_controllers"),
            runner.index('"$CGROUP_AUTHORITY" arm --session "$session_name"'),
        )

    def test_handoff_is_canonical_and_precedes_automatic_isolation(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'readonly GUIDED_HANDOFF_PATH="${RUNTIME_ROOT}/guided-handoff.json"',
            runner,
        )
        self.assertIn(
            'readonly GUIDED_HANDOFF_SCHEMA="codeskeptic-guided-handoff-v1"',
            runner,
        )
        self.assertIn('readonly CGROUP_SESSION_PATH="${RUNTIME_ROOT}/session-name"', runner)
        self.assertIn("os.O_CREAT | os.O_EXCL", runner)
        self.assertIn("os.fsync(descriptor)", runner)
        self.assertIn("os.fsync(directory)", runner)
        self.assertIn("publish_guided_handoff", runner)
        self.assertIn("isolate_graphical_session", runner)
        self.assertLess(
            runner.index("publish_guided_handoff"),
            runner.index("isolate_graphical_session"),
        )
        self.assertIn("systemctl isolate --no-block multi-user.target", runner)
        self.assertNotIn("/usr/bin/systemd-inhibit", runner)

    def test_cleanup_v4_records_durable_authority_restoration(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        for literal in (
            '"schema": "codeskeptic-stability-host-cleanup-v4"',
            '"cgroup_authority"',
            '"cgroup_restoration"',
            '"cgroup_authority_intent_bound": "pass"',
            '"cgroup_authority_marker_absent": "pass"',
            '"cgroup_authority_temporary_absent": "pass"',
            '"root_isolated_cpus_empty": "pass"',
            '"system_slice_exclusive_cpus_empty": "pass"',
            '"service_exclusive_cpus_empty": "pass"',
        ):
            self.assertIn(literal, runner)

    def test_arm_publishes_marker_before_any_ancestor_mutation(self) -> None:
        authority = load_authority()
        events: list[str] = []

        def write(path: Path, value: str) -> None:
            events.append(f"write:{path.name}:{value}")

        with (
            mock.patch.object(
                authority,
                "require_initial_state",
                side_effect=lambda: events.append("initial"),
            ),
            mock.patch.object(
                authority,
                "publish_marker",
                side_effect=lambda session: events.append("marker"),
            ),
            mock.patch.object(authority, "write_control", side_effect=write),
            mock.patch.object(
                authority,
                "require_owned_exclusive",
                side_effect=lambda path, label: events.append(f"owned:{label}"),
            ),
            mock.patch.object(
                authority,
                "read_marker",
                side_effect=lambda session: events.append("read"),
            ),
        ):
            authority.arm(SESSION)

        self.assertEqual(events[:2], ["initial", "marker"])
        self.assertEqual(
            events[2:],
            [
                "write:cpuset.cpus.exclusive:0-3",
                "owned:system.slice",
                "write:cpuset.cpus.exclusive:0-3",
                "owned:service",
                "read",
            ],
        )

    def test_installed_revision_uses_the_stager_pretty_canonical_format(self) -> None:
        authority = load_authority()
        revision = "a" * 40
        value = {"bundle_revision": revision, "schema": "installation-test"}
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_bytes(authority.installation_canonical(value))
            receipt.chmod(0o400)
            with mock.patch.multiple(
                authority,
                INSTALLATION_RECEIPT=receipt,
                ROOT_UID=os.getuid(),
                ROOT_GID=os.getgid(),
            ):
                self.assertEqual(authority.installed_source_revision(), revision)
                receipt.chmod(0o600)
                receipt.write_bytes(canonical(value))
                receipt.chmod(0o400)
                with self.assertRaises(authority.AuthorityError):
                    authority.installed_source_revision()

    def test_marker_publication_cutpoints_are_recoverable(self) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            state_root.chmod(0o700)
            marker = state_root / "cgroup-authority-intent.json"
            temporary = state_root / ".cgroup-authority-intent.tmp"
            with mock.patch.object(
                authority, "installed_source_revision", return_value="a" * 40
            ), mock.patch.multiple(
                authority,
                STATE_ROOT=state_root,
                MARKER=marker,
                MARKER_TEMP=temporary,
                ROOT_UID=os.getuid(),
                ROOT_GID=os.getgid(),
            ):
                raw = canonical(authority.expected_marker(SESSION))
                temporary.write_bytes(raw)
                temporary.chmod(0o400)
                os.link(temporary, marker)
                self.assertEqual(marker.stat().st_nlink, 2)
                self.assertEqual(authority.discover_marker_session(), SESSION)
                self.assertEqual(authority.read_marker(SESSION, repair_link=True), raw)
                self.assertFalse(temporary.exists())

                marker.unlink()
                temporary.write_bytes(raw)
                temporary.chmod(0o400)
                self.assertEqual(authority.discover_marker_session(), SESSION)
                with mock.patch.object(authority, "already_clean") as clean:
                    self.assertEqual(
                        authority.cleanup(SESSION), "discarded-unarmed-intent"
                    )
                    clean.assert_called_once_with()
                self.assertFalse(temporary.exists())

                marker.write_bytes(
                    canonical({**authority.expected_marker(SESSION), "extra": True})
                )
                marker.chmod(0o400)
                with self.assertRaises(authority.AuthorityError):
                    authority.discover_marker_session()

    def test_incomplete_prepublication_marker_is_discarded_only_after_clean_gate(
        self,
    ) -> None:
        authority = load_authority()
        with mock.patch.object(
            authority, "installed_source_revision", return_value="a" * 40
        ):
            raw = canonical(authority.expected_marker(SESSION))
        prefixes = (
            b"",
            raw[:1],
            raw[: raw.index(SESSION.encode("ascii")) + 19],
            raw[:-1],
        )

        for prefix in prefixes:
            with self.subTest(prefix_length=len(prefix)), tempfile.TemporaryDirectory() as directory:
                state_root = Path(directory)
                state_root.chmod(0o700)
                marker = state_root / "cgroup-authority-intent.json"
                temporary = state_root / ".cgroup-authority-intent.tmp"
                temporary.write_bytes(prefix)
                temporary.chmod(0o400)
                events: list[str] = []
                with mock.patch.object(
                    authority, "installed_source_revision", return_value="a" * 40
                ), mock.patch.multiple(
                    authority,
                    STATE_ROOT=state_root,
                    MARKER=marker,
                    MARKER_TEMP=temporary,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ), mock.patch.object(
                    authority,
                    "already_clean",
                    side_effect=lambda: events.append("clean"),
                ):
                    self.assertEqual(
                        authority.recover(),
                        "discarded-partial-unarmed-intent",
                    )
                self.assertEqual(events, ["clean"])
                self.assertFalse(temporary.exists())

    def test_incomplete_prepublication_marker_rejects_forgery(self) -> None:
        authority = load_authority()
        with mock.patch.object(
            authority, "installed_source_revision", return_value="a" * 40
        ):
            raw = canonical(authority.expected_marker(SESSION))
            malformed_full = canonical(
                {**authority.expected_marker(SESSION), "forged": True}
            )

        cases = (
            ("wrong-mode", raw[:32], 0o600),
            ("wrong-first-byte", b"X", 0o400),
            ("corrupt-strict-prefix", raw[:31] + b"X", 0o400),
            ("malformed-full-marker", malformed_full, 0o400),
        )
        for name, contents, mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                state_root = Path(directory)
                state_root.chmod(0o700)
                marker = state_root / "cgroup-authority-intent.json"
                temporary = state_root / ".cgroup-authority-intent.tmp"
                temporary.write_bytes(contents)
                temporary.chmod(mode)
                with mock.patch.object(
                    authority, "installed_source_revision", return_value="a" * 40
                ), mock.patch.multiple(
                    authority,
                    STATE_ROOT=state_root,
                    MARKER=marker,
                    MARKER_TEMP=temporary,
                    ROOT_UID=os.getuid(),
                    ROOT_GID=os.getgid(),
                ), mock.patch.object(
                    authority, "already_clean"
                ) as already_clean, mock.patch.object(
                    authority, "cleanup"
                ) as cleanup:
                    with self.assertRaises(authority.AuthorityError):
                        authority.recover()
                already_clean.assert_not_called()
                cleanup.assert_not_called()
                self.assertTrue(temporary.exists())

    def test_incomplete_prepublication_marker_preserves_foreign_mutated_state(
        self,
    ) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            state_root.chmod(0o700)
            marker = state_root / "cgroup-authority-intent.json"
            temporary = state_root / ".cgroup-authority-intent.tmp"
            temporary.write_bytes(b'{"exclusive_cpus"')
            temporary.chmod(0o400)
            with mock.patch.object(
                authority, "installed_source_revision", return_value="a" * 40
            ), mock.patch.multiple(
                authority,
                STATE_ROOT=state_root,
                MARKER=marker,
                MARKER_TEMP=temporary,
                ROOT_UID=os.getuid(),
                ROOT_GID=os.getgid(),
            ), mock.patch.object(
                authority,
                "already_clean",
                side_effect=authority.AuthorityError(
                    "cgroup authority marker is absent but payload remains"
                ),
            ) as already_clean, mock.patch.object(
                authority, "cleanup_payload"
            ) as cleanup_payload, mock.patch.object(
                authority, "restore_ancestor"
            ) as restore_ancestor, mock.patch.object(
                authority, "write_control"
            ) as write_control:
                with self.assertRaisesRegex(
                    authority.AuthorityError, "payload remains"
                ):
                    authority.recover()
            already_clean.assert_called_once_with()
            cleanup_payload.assert_not_called()
            restore_ancestor.assert_not_called()
            write_control.assert_not_called()
            self.assertTrue(temporary.exists())

    def test_recursive_kill_and_foreign_ancestor_value_fail_closed(self) -> None:
        authority = load_authority()
        cgroup = Path("/test/payload")
        with (
            mock.patch.object(
                authority,
                "cgroup_events",
                side_effect=[
                    {"populated": "1"},
                    {"populated": "0"},
                    {"populated": "0"},
                ],
            ),
            mock.patch.object(authority, "write_control") as write,
        ):
            authority.kill_and_wait(cgroup, "payload")
            write.assert_called_once_with(cgroup / "cgroup.kill", "1")

        with (
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(authority, "require_exact_directory"),
            mock.patch.object(authority, "cgroup_value", side_effect=["member", "4-5"]),
            mock.patch.object(authority, "write_control") as write,
        ):
            with self.assertRaises(authority.AuthorityError):
                authority.restore_ancestor(cgroup, "system.slice")
            write.assert_not_called()

        payload = mock.Mock()
        payload.exists.return_value = True
        payload.is_symlink.return_value = False
        with (
            mock.patch.object(authority, "PAYLOAD", payload),
            mock.patch.object(
                authority,
                "validate_payload_tree",
                side_effect=authority.AuthorityError("foreign payload"),
            ),
            mock.patch.object(authority, "kill_and_wait") as kill,
        ):
            with self.assertRaises(authority.AuthorityError):
                authority.cleanup_payload()
            kill.assert_not_called()

    def test_check_clean_is_an_explicit_fail_closed_action(self) -> None:
        authority = load_authority()
        with mock.patch.object(authority, "already_clean") as already_clean:
            authority.check_clean()
        already_clean.assert_called_once_with()

    def test_active_payload_container_cgroups_are_bound_to_exact_ids(self) -> None:
        authority = load_authority()
        container_id = "a" * 64
        children = [
            authority.MEASUREMENT,
            authority.PAYLOAD / f"libpod-{container_id}.scope",
        ]
        values = [
            authority.CONTROLLER_CPUS,
            authority.EXCLUSIVE_CPUS,
            authority.CAMPAIGN_CPUS,
            authority.CAMPAIGN_CPUS,
        ]
        with (
            mock.patch.object(authority, "read_marker"),
            mock.patch.object(authority, "expected_active_ancestry", return_value=()),
            mock.patch.object(authority, "require_exact_directory"),
            mock.patch.object(authority, "cgroup_value", side_effect=values),
            mock.patch.object(
                authority, "validate_payload_tree", return_value=children
            ) as validate,
        ):
            authority.verify_active(SESSION, (container_id,))
        validate.assert_called_once_with((container_id,))

        with (
            mock.patch.object(authority, "read_marker"),
            mock.patch.object(authority, "expected_active_ancestry", return_value=()),
            mock.patch.object(authority, "require_exact_directory"),
            mock.patch.object(authority, "cgroup_value", side_effect=values.copy()),
            mock.patch.object(
                authority, "validate_payload_tree", return_value=children
            ),
            self.assertRaisesRegex(
                authority.AuthorityError, "unbound container cgroup"
            ),
        ):
            authority.verify_active(SESSION)

    def test_recover_discovers_the_durable_session_after_runtime_loss(self) -> None:
        authority = load_authority()
        with (
            mock.patch.object(
                authority,
                "discover_marker_session",
                return_value=SESSION,
            ) as discover,
            mock.patch.object(
                authority,
                "cleanup",
                return_value="restored",
            ) as cleanup,
        ):
            self.assertEqual(authority.recover(), "restored")
        discover.assert_called_once_with()
        cleanup.assert_called_once_with(SESSION, ())

        container_id = "b" * 64
        with (
            mock.patch.object(
                authority,
                "discover_marker_session",
                return_value=SESSION,
            ),
            mock.patch.object(
                authority,
                "cleanup",
                return_value="restored",
            ) as cleanup,
        ):
            self.assertEqual(authority.recover((container_id,)), "restored")
        cleanup.assert_called_once_with(SESSION, (container_id,))

        with (
            mock.patch.object(authority, "discover_marker_session", return_value=None),
            mock.patch.object(authority, "check_clean") as check_clean,
        ):
            self.assertEqual(authority.recover((container_id,)), "already-clean")
        check_clean.assert_called_once_with()

    def test_partial_cgroup_restoration_retry_retains_then_removes_marker(
        self,
    ) -> None:
        authority = load_authority()
        container_id = "d" * 64
        marker_present = True
        interrupted = True
        events: list[str] = []

        marker = mock.Mock()
        marker.exists.side_effect = lambda: marker_present
        marker.is_symlink.return_value = False
        service = mock.MagicMock()
        service.exists.return_value = True
        service.is_symlink.return_value = False

        def cgroup_value(path: Path, _label: str) -> str:
            if path == authority.CPU_POSSIBLE or path == authority.CPU_ONLINE:
                return authority.CAMPAIGN_CPUS
            return ""

        def restore(_path: Path, label: str, *, allow_absent: bool = False) -> bool:
            nonlocal interrupted
            events.append(f"restore:{label}")
            if label == "system.slice" and interrupted:
                interrupted = False
                raise authority.AuthorityError("simulated partial restoration")
            return True

        def remove(_session: str) -> None:
            nonlocal marker_present
            events.append("remove-marker")
            marker_present = False

        with (
            mock.patch.object(authority, "MARKER", marker),
            mock.patch.object(authority, "read_marker"),
            mock.patch.object(authority, "SERVICE", service),
            mock.patch.object(authority, "cgroup_value", side_effect=cgroup_value),
            mock.patch.object(authority, "cleanup_payload") as cleanup_payload,
            mock.patch.object(authority, "restore_ancestor", side_effect=restore),
            mock.patch.object(authority, "remove_marker", side_effect=remove),
        ):
            with self.assertRaisesRegex(
                authority.AuthorityError, "partial restoration"
            ):
                authority.cleanup(SESSION, (container_id,))
            self.assertTrue(marker_present)
            self.assertEqual(
                authority.cleanup(SESSION, (container_id,)), "restored"
            )
        self.assertFalse(marker_present)
        self.assertEqual(cleanup_payload.call_count, 2)
        cleanup_payload.assert_called_with((container_id,))
        self.assertEqual(events[-1], "remove-marker")

        with (
            mock.patch.object(
                authority,
                "discover_marker_session",
                return_value=None,
            ),
            mock.patch.object(authority, "check_clean") as check_clean,
        ):
            self.assertEqual(authority.recover(), "already-clean")
        check_clean.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
