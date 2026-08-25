#!/usr/bin/env python3
"""Focused contract tests for the final P10-09 cgroup authority lifecycle."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
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


def write_value(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{value}\n", encoding="ascii")


def create_group(
    path: Path,
    *,
    controllers: frozenset[str],
    subtree: frozenset[str],
    cpus: str,
    effective_cpus: str,
    exclusive: str,
    exclusive_effective: str,
    partition: str,
    mems: str,
    effective_mems: str = "0",
    uclamp: tuple[str, str] | None = None,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    values = {
        "cgroup.controllers": " ".join(sorted(controllers)),
        "cgroup.subtree_control": " ".join(sorted(subtree)),
        "cgroup.type": "domain",
        "cpuset.cpus": cpus,
        "cpuset.cpus.effective": effective_cpus,
        "cpuset.cpus.exclusive": exclusive,
        "cpuset.cpus.exclusive.effective": exclusive_effective,
        "cpuset.cpus.partition": partition,
        "cpuset.mems": mems,
        "cpuset.mems.effective": effective_mems,
    }
    if uclamp is not None:
        values["cpu.uclamp.min"], values["cpu.uclamp.max"] = uclamp
    for name, value in values.items():
        write_value(path / name, value)


def active_cgroup_fixture(authority, directory: str) -> dict[str, Path]:
    root = Path(directory) / "cgroup"
    system = root / "system.slice"
    service = system / "codeskeptic-stability.service"
    controller = service / "controller"
    payload = service / "codeskeptic-p10-09"
    measurement = payload / "measurement"
    possible = Path(directory) / "possible"
    online = Path(directory) / "online"
    create_group(
        root,
        controllers=authority.ROOT_CONTROLLERS,
        subtree=authority.HOST_CONTROLLERS,
        cpus="",
        effective_cpus=authority.CAMPAIGN_CPUS,
        exclusive="",
        exclusive_effective="",
        partition="member",
        mems="",
    )
    for name in (
        "cgroup.type",
        "cpuset.cpus",
        "cpuset.cpus.exclusive",
        "cpuset.cpus.exclusive.effective",
        "cpuset.cpus.partition",
        "cpuset.mems",
    ):
        (root / name).unlink()
    write_value(root / "cpuset.cpus.isolated", authority.EXCLUSIVE_CPUS)
    create_group(
        system,
        controllers=authority.HOST_CONTROLLERS,
        subtree=authority.HOST_CONTROLLERS,
        cpus="",
        effective_cpus=authority.CONTROLLER_CPUS,
        exclusive=authority.EXCLUSIVE_CPUS,
        exclusive_effective=authority.EXCLUSIVE_CPUS,
        partition="member",
        mems="",
        uclamp=authority.DEFAULT_UCLAMP,
    )
    create_group(
        service,
        controllers=authority.HOST_CONTROLLERS,
        subtree=authority.REQUIRED_CONTROLLERS,
        cpus=authority.CAMPAIGN_CPUS,
        effective_cpus=authority.CONTROLLER_CPUS,
        exclusive=authority.EXCLUSIVE_CPUS,
        exclusive_effective=authority.EXCLUSIVE_CPUS,
        partition="member",
        mems="",
        uclamp=authority.DEFAULT_UCLAMP,
    )
    create_group(
        controller,
        controllers=authority.REQUIRED_CONTROLLERS,
        subtree=frozenset(),
        cpus="",
        effective_cpus=authority.CONTROLLER_CPUS,
        exclusive="",
        exclusive_effective="",
        partition="member",
        mems="",
        uclamp=authority.DEFAULT_UCLAMP,
    )
    create_group(
        payload,
        controllers=authority.REQUIRED_CONTROLLERS,
        subtree=authority.REQUIRED_CONTROLLERS,
        cpus=authority.CAMPAIGN_CPUS,
        effective_cpus=authority.CONTROLLER_CPUS,
        exclusive=authority.EXCLUSIVE_CPUS,
        exclusive_effective=authority.EXCLUSIVE_CPUS,
        partition="member",
        mems=authority.MEMORY_NODES,
        uclamp=authority.DEFAULT_UCLAMP,
    )
    create_group(
        measurement,
        controllers=authority.REQUIRED_CONTROLLERS,
        subtree=frozenset(),
        cpus=authority.EXCLUSIVE_CPUS,
        effective_cpus=authority.EXCLUSIVE_CPUS,
        exclusive=authority.EXCLUSIVE_CPUS,
        exclusive_effective=authority.EXCLUSIVE_CPUS,
        partition="isolated",
        mems=authority.MEMORY_NODES,
        uclamp=("max", "max"),
    )
    write_value(possible, authority.CAMPAIGN_CPUS)
    write_value(online, authority.CAMPAIGN_CPUS)
    return {
        "root": root,
        "system": system,
        "service": service,
        "controller": controller,
        "payload": payload,
        "measurement": measurement,
        "possible": possible,
        "online": online,
    }


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
            '"arm", "verify-active", "verify-recovery", "cleanup",',
            authority,
        )
        self.assertLess(
            authority.index("publish_marker(session)"),
            authority.index('write_control(SYSTEM_SLICE / "cpuset.cpus.exclusive"'),
        )
        self.assertNotIn('write_control(path / "cgroup.kill", "1")', authority)
        self.assertIn("require_empty_cgroup(path, label)", authority)
        self.assertIn("remove_owned_tree(child", authority)
        self.assertIn("refusing to clear foreign", authority)
        self.assertIn("payload contains an unexpected runtime cgroup", authority)
        self.assertLess(
            authority.index("validate_payload_tree(owned_container_ids)"),
            authority.index('require_empty_cgroup(PAYLOAD, "payload")'),
        )

        self.assertIn('readonly CGROUP_AUTHORITY="${OPERATOR_ROOT}/cgroup-authority.py"', runner)
        self.assertIn('readonly HOST_RECOVERY="${OPERATOR_ROOT}/host-recovery.py"', runner)
        self.assertIn("require_active_controller_inventory", runner)
        self.assertIn('"payload subtree"', runner)
        self.assertIn('"$HOST_RECOVERY" recover', runner)
        self.assertIn('"$CGROUP_AUTHORITY" arm --session "$session_name"', runner)
        self.assertIn('"$CGROUP_AUTHORITY" verify-active --session "$session_name"', runner)
        self.assertIn('"$CGROUP_AUTHORITY" cleanup --session "$session_name"', runner)
        self.assertNotIn("cleanup_measurement_cgroup()", runner)
        self.assertNotIn("cgroup_prepared=", runner)
        self.assertLess(
            runner.index('\n"$HOST_RECOVERY" recover\n'),
            runner.rindex("\nenable_service_controllers\n"),
        )
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

    def test_cleanup_v5_records_durable_authority_restoration(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        for literal in (
            '"schema": "codeskeptic-stability-host-cleanup-v5"',
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

    def test_populated_payload_and_foreign_ancestor_value_fail_closed(self) -> None:
        authority = load_authority()
        cgroup = Path("/test/payload")
        with (
            mock.patch.object(
                authority,
                "cgroup_events",
                return_value={"frozen": "0", "populated": "1"},
            ),
            mock.patch.object(authority, "write_control") as write,
            self.assertRaisesRegex(
                authority.AuthorityError, "remains populated"
            ),
        ):
            authority.require_empty_cgroup(cgroup, "payload")
        write.assert_not_called()

        with mock.patch.object(
            authority,
            "cgroup_events",
            return_value={"frozen": "0", "populated": "0"},
        ), mock.patch.object(authority, "cgroup_value", return_value=""):
            authority.require_empty_cgroup(cgroup, "payload")

        with (
            mock.patch.object(
                authority,
                "cgroup_events",
                return_value={"frozen": "0", "populated": "0"},
            ),
            mock.patch.object(authority, "cgroup_value", return_value="123"),
            self.assertRaisesRegex(
                authority.AuthorityError, "membership is not empty"
            ),
        ):
            authority.require_empty_cgroup(cgroup, "payload")

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
            mock.patch.object(authority, "require_empty_cgroup") as empty,
        ):
            with self.assertRaises(authority.AuthorityError):
                authority.cleanup_payload()
            empty.assert_not_called()

    def test_check_clean_is_an_explicit_fail_closed_action(self) -> None:
        authority = load_authority()
        with mock.patch.object(authority, "already_clean") as already_clean:
            authority.check_clean()
        already_clean.assert_called_once_with()

    def test_active_gate_invokes_the_complete_correlated_contract(self) -> None:
        authority = load_authority()
        container_id = "a" * 64
        with (
            mock.patch.object(authority, "read_marker") as read_marker,
            mock.patch.object(authority, "require_topology") as topology,
            mock.patch.object(authority, "require_ancestor_state") as ancestor,
            mock.patch.object(authority, "require_controller_state") as controller,
            mock.patch.object(
                authority,
                "cgroup_value",
                return_value=authority.EXCLUSIVE_CPUS,
            ),
            mock.patch.object(
                authority, "require_active_payload_state"
            ) as payload,
        ):
            authority.verify_active(SESSION, (container_id,))
        read_marker.assert_called_once_with(SESSION)
        topology.assert_called_once_with()
        self.assertEqual(ancestor.call_count, 2)
        controller.assert_called_once_with(
            authority.CONTROLLER_CPUS, payload_present=True
        )
        payload.assert_called_once_with()

        with (
            mock.patch.object(authority, "read_marker"),
            mock.patch.object(authority, "require_topology"),
            mock.patch.object(
                authority,
                "require_ancestor_state",
                side_effect=authority.AuthorityError(
                    "correlated cpuset state drift"
                ),
            ),
            self.assertRaisesRegex(
                authority.AuthorityError, "correlated cpuset"
            ),
        ):
            authority.verify_active(SESSION, (container_id,))

    def test_exact_active_fixture_and_impossible_states_fail_before_mutation(
        self,
    ) -> None:
        authority = load_authority()
        mutations = (
            (
                "controller-child",
                lambda paths: (paths["controller"] / "foreign").mkdir(),
            ),
            (
                "service-sibling",
                lambda paths: (paths["service"] / "foreign").mkdir(),
            ),
            (
                "measurement-exclusive-effective",
                lambda paths: write_value(
                    paths["measurement"] / "cpuset.cpus.exclusive.effective",
                    "",
                ),
            ),
            (
                "root-isolation",
                lambda paths: write_value(
                    paths["root"] / "cpuset.cpus.isolated", ""
                ),
            ),
            (
                "system-configured-cpus",
                lambda paths: write_value(
                    paths["system"] / "cpuset.cpus",
                    authority.CAMPAIGN_CPUS,
                ),
            ),
            (
                "root-effective-memory-nodes",
                lambda paths: write_value(
                    paths["root"] / "cpuset.mems.effective", "1"
                ),
            ),
            (
                "root-configured-memory-interface",
                lambda paths: write_value(
                    paths["root"] / "cpuset.mems", authority.MEMORY_NODES
                ),
            ),
            (
                "service-configured-cpus",
                lambda paths: write_value(paths["service"] / "cpuset.cpus", ""),
            ),
            (
                "service-configured-memory-nodes",
                lambda paths: write_value(
                    paths["service"] / "cpuset.mems", authority.MEMORY_NODES
                ),
            ),
            (
                "system-uclamp",
                lambda paths: write_value(
                    paths["system"] / "cpu.uclamp.min", "1.00"
                ),
            ),
            (
                "payload-uclamp",
                lambda paths: write_value(
                    paths["payload"] / "cpu.uclamp.max", "50.00"
                ),
            ),
            (
                "measurement-type",
                lambda paths: write_value(
                    paths["measurement"] / "cgroup.type", "threaded"
                ),
            ),
            (
                "uclamp-cartesian-mix",
                lambda paths: (
                    write_value(
                        paths["measurement"] / "cpu.uclamp.min", "max"
                    ),
                    write_value(
                        paths["measurement"] / "cpu.uclamp.max", "100.00"
                    ),
                ),
            ),
            (
                "noncanonical-full-uclamp",
                lambda paths: (
                    write_value(
                        paths["measurement"] / "cpu.uclamp.min", "100.00"
                    ),
                    write_value(
                        paths["measurement"] / "cpu.uclamp.max", "100.00"
                    ),
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                paths = active_cgroup_fixture(authority, directory)
                patch_values = {
                    "CGROUP_ROOT": paths["root"],
                    "SYSTEM_SLICE": paths["system"],
                    "SERVICE": paths["service"],
                    "CONTROLLER": paths["controller"],
                    "PAYLOAD": paths["payload"],
                    "MEASUREMENT": paths["measurement"],
                    "CPU_POSSIBLE": paths["possible"],
                    "CPU_ONLINE": paths["online"],
                }
                with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                    authority, "read_marker"
                ), mock.patch.object(
                    authority, "self_cgroup_path", return_value=paths["controller"]
                ):
                    authority.verify_active(SESSION)
                    mutate(paths)
                    marker = mock.Mock()
                    marker.exists.return_value = True
                    marker.is_symlink.return_value = False
                    with mock.patch.object(
                        authority, "MARKER", marker
                    ), mock.patch.object(
                        authority, "write_control"
                    ) as write, mock.patch.object(
                        authority, "require_empty_cgroup"
                    ) as empty, self.assertRaises(authority.AuthorityError):
                        authority.cleanup(SESSION)
                write.assert_not_called()
                empty.assert_not_called()

    def test_marker_link_repair_follows_the_complete_read_only_gate(self) -> None:
        authority = load_authority()
        marker = mock.Mock()
        marker.exists.return_value = True
        marker.is_symlink.return_value = False
        with (
            mock.patch.object(authority, "MARKER", marker),
            mock.patch.object(authority, "read_marker") as read_marker,
            mock.patch.object(
                authority,
                "validate_cleanup_state",
                side_effect=authority.AuthorityError("read-only gate failed"),
            ) as validate,
            mock.patch.object(authority, "cleanup_payload") as cleanup_payload,
            self.assertRaisesRegex(
                authority.AuthorityError, "read-only gate failed"
            ),
        ):
            authority.cleanup(SESSION)
        read_marker.assert_called_once_with(SESSION)
        validate.assert_called_once_with(())
        cleanup_payload.assert_not_called()

    def test_active_controller_is_bound_to_the_current_helper(self) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["controller"]
            ):
                authority.require_controller_state(
                    authority.CONTROLLER_CPUS, payload_present=True
                )
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["service"]
            ), self.assertRaisesRegex(
                authority.AuthorityError, "active controller caller identity"
            ):
                authority.require_controller_state(
                    authority.CONTROLLER_CPUS, payload_present=True
                )

    def test_service_control_subgroup_is_bound_to_the_current_helper(self) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            control = paths["service"] / ".control"
            create_group(
                control,
                controllers=authority.REQUIRED_CONTROLLERS,
                subtree=frozenset(),
                cpus="",
                effective_cpus=authority.CONTROLLER_CPUS,
                exclusive="",
                exclusive_effective="",
                partition="member",
                mems="",
                uclamp=authority.DEFAULT_UCLAMP,
            )
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=control
            ):
                authority.require_controller_state(
                    authority.CONTROLLER_CPUS,
                    payload_present=True,
                    caller_role="recovery",
                )
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["controller"]
            ), self.assertRaisesRegex(
                authority.AuthorityError, "foreign service control subgroup"
            ):
                authority.require_controller_state(
                    authority.CONTROLLER_CPUS,
                    payload_present=True,
                    caller_role="recovery",
                )

    def test_recovery_control_subgroup_can_replace_absent_delegate(self) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            shutil.rmtree(paths["controller"])
            control = paths["service"] / ".control"
            create_group(
                control,
                controllers=authority.REQUIRED_CONTROLLERS,
                subtree=frozenset(),
                cpus="",
                effective_cpus=authority.CAMPAIGN_CPUS,
                exclusive="",
                exclusive_effective="",
                partition="member",
                mems="",
                uclamp=authority.DEFAULT_UCLAMP,
            )
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=control
            ):
                authority.require_recovery_control_plane(
                    authority.CAMPAIGN_CPUS, payload_present=True
                )
            shutil.rmtree(control)
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["service"]
            ):
                authority.require_recovery_control_plane(
                    authority.CAMPAIGN_CPUS, payload_present=True
                )
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["payload"]
            ), self.assertRaisesRegex(
                authority.AuthorityError, "startup recovery caller identity"
            ):
                authority.require_recovery_control_plane(
                    authority.CAMPAIGN_CPUS, payload_present=True
                )

    def test_clean_exec_start_pre_accepts_only_undelegated_service_root(
        self,
    ) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            shutil.rmtree(paths["payload"])
            shutil.rmtree(paths["controller"])
            write_value(paths["root"] / "cpuset.cpus.isolated", "")
            for path in (paths["system"], paths["service"]):
                write_value(path / "cpuset.cpus.effective", authority.CAMPAIGN_CPUS)
                write_value(path / "cpuset.cpus.exclusive", "")
                write_value(path / "cpuset.cpus.exclusive.effective", "")
            write_value(paths["service"] / "cgroup.subtree_control", "")
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["service"]
            ):
                authority.already_clean()
                authority.validate_cleanup_state()
                write_value(
                    paths["service"] / "cgroup.subtree_control",
                    " ".join(sorted(authority.REQUIRED_CONTROLLERS)),
                )
                with self.assertRaisesRegex(
                    authority.AuthorityError,
                    "service subtree controller inventory drift",
                ):
                    authority.already_clean()
                with self.assertRaisesRegex(
                    authority.AuthorityError,
                    "service subtree controller inventory drift",
                ):
                    authority.validate_cleanup_state()

    def test_cleanup_accepts_only_correlated_creation_and_restoration_cuts(
        self,
    ) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority, "self_cgroup_path", return_value=paths["controller"]
            ):
                authority.validate_cleanup_state()

                write_value(paths["root"] / "cpuset.cpus.isolated", "")
                write_value(
                    paths["measurement"] / "cpuset.cpus.partition", "member"
                )
                for path in (
                    paths["system"], paths["service"], paths["controller"],
                    paths["payload"],
                ):
                    write_value(
                        path / "cpuset.cpus.effective", authority.CAMPAIGN_CPUS
                    )
                authority.validate_cleanup_state()

                shutil.rmtree(paths["measurement"])
                authority.validate_cleanup_state()
                write_value(paths["payload"] / "cgroup.subtree_control", "")
                authority.validate_cleanup_state()
                write_value(paths["payload"] / "cpuset.cpus.exclusive", "")
                write_value(
                    paths["payload"] / "cpuset.cpus.exclusive.effective", ""
                )
                authority.validate_cleanup_state()
                write_value(paths["payload"] / "cpuset.cpus", "")
                write_value(paths["payload"] / "cpuset.mems", "")
                authority.validate_cleanup_state()

                shutil.rmtree(paths["payload"])
                authority.validate_cleanup_state()
                write_value(paths["service"] / "cpuset.cpus.exclusive", "")
                write_value(
                    paths["service"] / "cpuset.cpus.exclusive.effective", ""
                )
                authority.validate_cleanup_state()
                write_value(paths["system"] / "cpuset.cpus.exclusive", "")
                write_value(
                    paths["system"] / "cpuset.cpus.exclusive.effective", ""
                )
                authority.validate_cleanup_state()

                shutil.rmtree(paths["service"])
                authority.validate_cleanup_state()
                write_value(
                    paths["system"] / "cpuset.cpus.exclusive",
                    authority.EXCLUSIVE_CPUS,
                )
                write_value(
                    paths["system"] / "cpuset.cpus.exclusive.effective",
                    authority.EXCLUSIVE_CPUS,
                )
                authority.validate_cleanup_state()

    def test_clean_main_start_accepts_only_core_controller_subgroup(
        self,
    ) -> None:
        authority = load_authority()
        with tempfile.TemporaryDirectory() as directory:
            paths = active_cgroup_fixture(authority, directory)
            shutil.rmtree(paths["payload"])
            shutil.rmtree(paths["controller"])
            write_value(paths["root"] / "cpuset.cpus.isolated", "")
            for path in (paths["system"], paths["service"]):
                write_value(
                    path / "cpuset.cpus.effective", authority.CAMPAIGN_CPUS
                )
                write_value(path / "cpuset.cpus.exclusive", "")
                write_value(path / "cpuset.cpus.exclusive.effective", "")
            write_value(paths["service"] / "cgroup.subtree_control", "")
            paths["controller"].mkdir()
            write_value(paths["controller"] / "cgroup.controllers", "")
            write_value(paths["controller"] / "cgroup.subtree_control", "")
            write_value(paths["controller"] / "cgroup.type", "domain")
            patch_values = {
                "CGROUP_ROOT": paths["root"],
                "SYSTEM_SLICE": paths["system"],
                "SERVICE": paths["service"],
                "CONTROLLER": paths["controller"],
                "PAYLOAD": paths["payload"],
                "MEASUREMENT": paths["measurement"],
                "CPU_POSSIBLE": paths["possible"],
                "CPU_ONLINE": paths["online"],
            }
            with mock.patch.multiple(authority, **patch_values), mock.patch.object(
                authority,
                "self_cgroup_path",
                return_value=paths["controller"],
            ):
                authority.already_clean()
                authority.validate_cleanup_state()
                write_value(paths["controller"] / "cpuset.cpus", "")
                with self.assertRaisesRegex(
                    authority.AuthorityError,
                    "startup controller exposes unexpected cpuset.cpus",
                ):
                    authority.already_clean()

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
            mock.patch.object(authority, "validate_cleanup_state"),
            mock.patch.object(authority, "cleanup_payload") as cleanup_payload,
            mock.patch.object(authority, "restore_ancestor", side_effect=restore),
            mock.patch.object(authority, "already_clean"),
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
