#!/usr/bin/env python3
"""Static operator contract for the authoritative P10-09 stability run."""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATOR_ROOT = ROOT / "scripts" / "stability-systemd"
UNIT = OPERATOR_ROOT / "codeskeptic-stability.service"
OPERATOR = OPERATOR_ROOT / "run-authoritative-stability.sh"
GUIDED = OPERATOR_ROOT / "guided-stability.sh"
POST_STOP = OPERATOR_ROOT / "post-stop.sh"
HOST_RECOVERY = OPERATOR_ROOT / "host-recovery.py"
CONTAINER_ENTRY = OPERATOR_ROOT / "container-entry.py"
CONTAINERS_CONF = OPERATOR_ROOT / "containers.conf"
README = OPERATOR_ROOT / "README.md"
CONTROLLER = ROOT / "scripts" / "run_stability_campaign.py"


def unit_value(text: str, key: str) -> str:
    matches = re.findall(rf"^{re.escape(key)}=(.*)$", text, re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {key}= assignment")
    return matches[0]


def shell_array(text: str, name: str) -> list[str]:
    match = re.search(
        rf"^readonly -a {re.escape(name)}=\(\n(?P<body>.*?)^\)$",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing readonly shell array {name}")
    return shlex.split(match.group("body"), posix=True)


def literal_constant(path: Path, name: str):
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            return ast.literal_eval(statement.value)
    raise AssertionError(f"missing literal controller constant {name}")


def guided_handoff_parser() -> str:
    text = GUIDED.read_text(encoding="utf-8")
    marker = (
        '"$HANDOFF_SCHEMA" "$expected_mode" "$expected_nonce" '
        '"$MAX_HANDOFF_BYTES" <<\'PY\'\n'
    )
    start = text.index(marker) + len(marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


def post_stop_session_parser() -> str:
    text = POST_STOP.read_text(encoding="utf-8")
    marker = '"$PYTHON" -B - "$SESSION_PATH" <<\'PY\'\n'
    start = text.index(marker) + len(marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


def post_stop_restoration_parser() -> str:
    text = POST_STOP.read_text(encoding="utf-8")
    marker = (
        '"$RESTORE_GRAPHICAL_SCHEMA" "$expected_session" <<\'PY\'\n'
    )
    start = text.index(marker) + len(marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


def shell_function(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index("\n}\n", start) + 3
    return text[start:end]


def restoration_harness(
    state_path: Path, systemctl_path: Path, attempts: int
) -> str:
    post_stop = POST_STOP.read_text(encoding="utf-8")
    functions = "\n".join(
        shell_function(post_stop, name)
        for name in (
            "read_bound_restoration_intent",
            "clear_graphical_restoration_state",
            "system_transition_clear",
            "read_graphical_identity",
            "read_display_manager_identity",
            "restore_graphical_state",
        )
    )
    functions = functions.replace(
        "metadata.st_uid != 0", "metadata.st_uid != os.getuid()"
    ).replace("metadata.st_gid != 0", "metadata.st_gid != os.getgid()")
    return f"""#!/usr/bin/env bash
set -u
PYTHON={shlex.quote(sys.executable)}
SYSTEMCTL={shlex.quote(os.fspath(systemctl_path))}
RESTORE_GRAPHICAL_PATH={shlex.quote(os.fspath(state_path))}
RESTORE_GRAPHICAL_SCHEMA=codeskeptic-graphical-restoration-v1
RESTORE_WAIT_ATTEMPTS={attempts}
RESTORE_WAIT_INTERVAL=0.05
TRANSITION_TARGETS=(shutdown.target rescue.target emergency.target)
session_name=unverified
graphical_outcome=not-attempted
{functions}
result=0
restore_graphical_state "" || result=$?
printf '%s\n' "$graphical_outcome"
exit "$result"
"""


class StabilityWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = UNIT.read_text(encoding="utf-8")
        self.operator = OPERATOR.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")

    def test_service_is_gui_safe_and_survives_the_runner_isolate(self) -> None:
        self.assertNotIn("ConditionKernelCommandLine=", self.unit)
        self.assertNotIn("[Install]", self.unit)
        self.assertNotIn("WantedBy=", self.unit)
        transition_targets = {
            "shutdown.target",
            "rescue.target",
            "emergency.target",
        }
        self.assertEqual(set(unit_value(self.unit, "Before").split()), transition_targets)
        self.assertEqual(set(unit_value(self.unit, "Conflicts").split()), transition_targets)
        self.assertEqual(unit_value(self.unit, "IgnoreOnIsolate"), "yes")
        self.assertNotIn("graphical.target", unit_value(self.unit, "Conflicts"))
        self.assertNotIn("sleep.target", unit_value(self.unit, "Conflicts"))
        self.assertEqual(unit_value(self.unit, "Type"), "exec")
        self.assertEqual(unit_value(self.unit, "User"), "root")
        self.assertEqual(unit_value(self.unit, "Group"), "root")
        self.assertEqual(unit_value(self.unit, "StandardInput"), "null")

        executable_contract = self.unit + "\n" + self.operator
        for forbidden in (
            "/dev/tty",
            "read -p",
            "sudo ",
            "DISPLAY=",
            "WAYLAND_DISPLAY=",
            "reboot",
            "poweroff",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, executable_contract)

    def test_service_stops_fail_closed_without_restart_or_orphans(self) -> None:
        self.assertEqual(unit_value(self.unit, "Restart"), "no")
        self.assertEqual(unit_value(self.unit, "KillMode"), "control-group")
        self.assertEqual(
            unit_value(self.unit, "Delegate"),
            "cpu cpuset memory pids",
        )
        self.assertEqual(unit_value(self.unit, "DelegateSubgroup"), "controller")
        self.assertEqual(unit_value(self.unit, "AllowedCPUs"), "0-11")
        self.assertEqual(unit_value(self.unit, "CPUAffinity"), "4-11")
        self.assertEqual(unit_value(self.unit, "LimitNOFILE"), "4096")
        self.assertEqual(unit_value(self.unit, "RuntimeMaxSec"), "7d")
        self.assertEqual(unit_value(self.unit, "SendSIGKILL"), "yes")
        self.assertEqual(unit_value(self.unit, "OOMPolicy"), "stop")
        self.assertEqual(unit_value(self.unit, "StateDirectory"), "codeskeptic-p10-09")
        self.assertEqual(unit_value(self.unit, "RuntimeDirectory"), "codeskeptic-p10-09")
        self.assertEqual(unit_value(self.unit, "ProtectSystem"), "strict")
        self.assertEqual(unit_value(self.unit, "ProtectHome"), "yes")
        self.assertEqual(unit_value(self.unit, "PrivateNetwork"), "yes")
        self.assertIn("/var/lib/codeskeptic-p10-09", unit_value(self.unit, "ReadWritePaths"))
        self.assertIn("/run/codeskeptic-p10-09", unit_value(self.unit, "ReadWritePaths"))
        self.assertIn("/sys/fs/cgroup", unit_value(self.unit, "ReadWritePaths"))
        read_only = unit_value(self.unit, "ReadOnlyPaths").split()
        self.assertIn("/opt/codeskeptic-p10-09", read_only)
        self.assertIn("/etc/codeskeptic-p10-09/runtime.json", read_only)
        self.assertIn("/etc/codeskeptic-p10-09/runtime.json.sha256", read_only)
        self.assertNotIn("/etc/codeskeptic-p10-09/stability_manifest.json", read_only)
        self.assertEqual(
            shlex.split(unit_value(self.unit, "ExecStart")),
            [
                "/usr/bin/systemd-inhibit",
                "--what=sleep",
                "--who=CodeSkeptic-P10-09",
                "--why=authoritative-scope-bound-stability-evidence-session",
                "--mode=block",
                "--no-ask-password",
                "/usr/bin/prlimit",
                "--nofile=4096:4096",
                "--",
                "/opt/codeskeptic-p10-09/operator/run-authoritative-stability.sh",
            ],
        )
        self.assertEqual(
            unit_value(self.unit, "ExecStopPost"),
            "/opt/codeskeptic-p10-09/operator/post-stop.sh",
        )

    def test_operator_seals_launch_before_one_inhibited_fresh_run(self) -> None:
        self.assertIn('readonly AUTHORITY_ROOT="/opt/codeskeptic-p10-09/authority"', self.operator)
        self.assertIn('readonly CONFIG_PATH="/etc/codeskeptic-p10-09/runtime.json"', self.operator)
        self.assertIn('readonly CONFIG_SHA_PATH="${CONFIG_PATH}.sha256"', self.operator)
        self.assertIn('readonly STATE_ROOT="/var/lib/codeskeptic-p10-09"', self.operator)
        self.assertIn(
            'readonly CONTAINER_RUNTIME_ROOT="${STATE_ROOT}/runtime"',
            self.operator,
        )
        self.assertIn(
            'readonly RUNTIME_IDENTITY_ROOT="${STATE_ROOT}/runtime-identities"',
            self.operator,
        )
        self.assertIn("create_campaign_runtime_identity", self.operator)
        self.assertIn("verify_campaign_runtime_identity", self.operator)
        self.assertIn("cleanup_campaign_runtime", self.operator)
        self.assertIn("--recursive --one-file-system --preserve-root=all", self.operator)
        self.assertIn("campaign runtime contains mountpoint", self.operator)
        self.assertIn("campaign runtime is a separate filesystem", self.operator)
        cleanup = self.operator[
            self.operator.index("cleanup_campaign_runtime() {"):
            self.operator.index("require_closed_hooks_directory() {")
        ]
        runtime_remove = cleanup.index(
            '/usr/bin/rm --recursive --one-file-system --preserve-root=all --'
        )
        runtime_sync = cleanup.index(
            '/usr/bin/sync --file-system "$CONTAINER_RUNTIME_ROOT"'
        )
        identity_remove = cleanup.index(
            '/usr/bin/rm -- "$container_runtime_identity"'
        )
        identity_sync = cleanup.index(
            '/usr/bin/sync --file-system "$RUNTIME_IDENTITY_ROOT"'
        )
        self.assertLess(runtime_remove, runtime_sync)
        self.assertLess(runtime_sync, identity_remove)
        self.assertLess(identity_remove, identity_sync)
        self.assertIn("dedicated Podman store contains stale container state", self.operator)
        self.assertIn('readonly RUNTIME_ROOT="/run/codeskeptic-p10-09"', self.operator)
        self.assertIn('readonly PODMAN_ROOT="${STATE_ROOT}/podman-root"', self.operator)
        self.assertIn('readonly PODMAN_RUNROOT="${RUNTIME_ROOT}/podman-runroot"', self.operator)
        self.assertIn('require_root_immutable_directory "$AUTHORITY_ROOT"', self.operator)
        self.assertIn('require_root_immutable_file "$CONFIG_PATH"', self.operator)
        self.assertIn('require_root_immutable_file "$CONFIG_SHA_PATH"', self.operator)
        self.assertIn('require_root_immutable_file "$RUNNER_PATH"', self.operator)

        self.assertEqual(self.operator.count("/usr/bin/flock"), 1)
        self.assertIn('/usr/bin/flock --nonblock "$LOCK_FD"', self.operator)
        self.assertNotIn("/usr/bin/systemd-inhibit", self.operator)

        self.assertIn('[[ ! -e "$session_output" && ! -L "$session_output" ]]', self.operator)
        self.assertIn('/usr/bin/mkdir --mode=0700 -- "$session_output"', self.operator)
        self.assertIn('evidence_output="${session_output}/campaign"', self.operator)
        self.assertIn('host_output="${session_output}/host"', self.operator)
        seal = '"$PYTHON" -B "$RUNNER_PATH" seal-launch'
        verify = '"$PYTHON" -B "$RUNNER_PATH" verify-launch'
        self.assertIn(seal, self.operator)
        self.assertIn(verify, self.operator)
        self.assertIn(
            '--config "$CONFIG_PATH" --output "$launch_root" --boot-id "$boot_id"',
            self.operator,
        )
        self.assertIn(
            '--config "$CONFIG_PATH" --receipt "$launch_receipt" --boot-id "$boot_id"',
            self.operator,
        )
        self.assertLess(
            self.operator.index('capture_host_snapshot "pre"'),
            self.operator.index(seal),
        )
        self.assertLess(self.operator.index(seal), self.operator.index('"${podman_run_args[@]}"'))
        self.assertIn(
            'podman_run_args+=("$PINNED_EVIDENCE_IMAGE" "${RUNTIME_CONTROLLER_COMMAND[@]}")',
            self.operator,
        )
        self.assertNotIn('"$RUNNER_PATH" run', self.operator)
        self.assertNotIn("--resume", self.operator)

    def test_operator_uses_the_exact_pinned_offline_container_topology(self) -> None:
        self.assertIn(
            'readonly PINNED_EVIDENCE_IMAGE="localhost/codeskeptic-p10-07-evidence@sha256:'
            '3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"',
            self.operator,
        )
        self.assertIn(
            'readonly PINNED_EVIDENCE_IMAGE_DIGEST="sha256:'
            '3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"',
            self.operator,
        )
        self.assertIn(
            'readonly PINNED_EVIDENCE_IMAGE_ID="sha256:'
            '25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"',
            self.operator,
        )
        command = shell_array(self.operator, "RUNTIME_CONTROLLER_COMMAND")
        self.assertEqual(
            command,
            [
                "/usr/bin/taskset",
                "--cpu-list",
                "4-11",
                "/usr/bin/python3",
                "-B",
                "/operator/container-entry.py",
                "run",
            ],
        )
        self.assertEqual(
            command,
            literal_constant(CONTROLLER, "RUNTIME_CONTROLLER_COMMAND"),
        )
        bind_mounts = shell_array(self.operator, "CONTAINER_BIND_MOUNTS")
        self.assertEqual(
            bind_mounts,
            [
                "${AUTHORITY_ROOT}:/authority:ro",
                "${OPERATOR_ROOT}:/operator:ro",
                "${CONFIG_PATH}:/config/runtime.json:ro",
                "${CONFIG_SHA_PATH}:/config/runtime.json.sha256:ro",
                "${launch_root}:/launch:ro",
                "${evidence_output}:/evidence:rw",
                "${container_runtime}:/runtime:rw",
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            ],
        )
        actual_mount_contract = []
        for binding in bind_mounts:
            _, destination, mode = binding.rsplit(":", 2)
            actual_mount_contract.append({"destination": destination, "mode": mode})
        self.assertEqual(
            actual_mount_contract,
            literal_constant(CONTROLLER, "RUNTIME_LAUNCH_MOUNTS"),
        )
        self.assertEqual(
            shell_array(self.operator, "PODMAN_GLOBAL_OPTIONS"),
            [
                "--root",
                "$PODMAN_ROOT",
                "--runroot",
                "$PODMAN_RUNROOT",
                "--storage-driver=overlay",
                "--cgroup-manager=cgroupfs",
                "--conmon=/usr/bin/conmon",
                "--events-backend=none",
                "--hooks-dir=$OPERATOR_ROOT",
                "--runtime=/usr/bin/crun",
            ],
        )
        self.assertEqual(
            shell_array(self.operator, "PODMAN_CONTAINER_OPTIONS"),
            [
                "run",
                "--pull=never",
                "--network=none",
                "--cgroups=disabled",
                "--ipc=private",
                "--pid=private",
                "--uts=private",
                "--ulimit",
                "nofile=4096:4096",
                "--read-only",
                "--read-only-tmpfs=false",
                "--user=0:0",
                "--http-proxy=false",
                "--env-host=false",
                "--image-volume=ignore",
                "--security-opt=label=disable",
                "--security-opt=no-new-privileges",
                "--workdir=/authority/source",
                "--env=HOME=/runtime/home",
                "--env=TMPDIR=/runtime/tmp",
                "--env=XDG_CACHE_HOME=/runtime/xdg-cache",
                "--env=LANG=C",
                "--env=LC_ALL=C",
                "--env=TZ=UTC",
            ],
        )
        self.assertIn(
            '"cgroups": "disabled"', CONTROLLER.read_text(encoding="utf-8")
        )
        controller = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(
            literal_constant(CONTROLLER, "RUNTIME_CGROUP_PARENT"),
            "/system.slice/codeskeptic-stability.service/codeskeptic-p10-09",
        )
        self.assertEqual(
            literal_constant(CONTROLLER, "RUNTIME_MEASUREMENT_CGROUP"),
            "/sys/fs/cgroup/system.slice/codeskeptic-stability.service/"
            "codeskeptic-p10-09/measurement",
        )
        self.assertNotIn('"cgroup_parent": RUNTIME_CGROUP_PARENT', controller)
        self.assertIn('"pid_namespace": "private"', controller)
        self.assertIn('"maximum_open_fds": MAXIMUM_OPEN_FDS', controller)
        self.assertIn("--cgroups=disabled", self.operator)
        self.assertNotIn("--cgroupns", self.operator)
        self.assertNotIn("--cgroup-parent", self.operator)
        self.assertNotIn("--cpuset-cpus=", self.operator)
        self.assertIn("cgroup creation disabled", self.readme)
        self.assertEqual(
            CONTAINERS_CONF.read_text(encoding="utf-8"),
            '[containers]\ncgroupns = "host"\n',
        )
        self.assertIn(
            '"CONTAINERS_CONF=${CONTAINERS_CONF}"', self.operator
        )
        self.assertIn('"$ENV" --ignore-environment --', self.operator)
        self.assertNotIn("CONTAINERS_CONF_OVERRIDE", self.operator)
        self.assertIn('readonly PINNED_PODMAN_VERSION="5.8.4"', self.operator)
        self.assertIn("run_podman version --format", self.operator)
        self.assertIn('--root "$PODMAN_ROOT"', self.operator)
        self.assertIn('--runroot "$PODMAN_RUNROOT"', self.operator)
        self.assertIn('image inspect \\\n            --format', self.operator)
        self.assertIn('[[ "$image_id" == "$PINNED_EVIDENCE_IMAGE_ID" ]]', self.operator)
        self.assertIn('[[ "$image_digest" == "$PINNED_EVIDENCE_IMAGE_DIGEST" ]]', self.operator)
        self.assertNotIn("rootless", self.operator.lower())
        self.assertNotIn("--userns=keep-id", self.operator)

    def test_rootful_preflight_proves_unit_cgroup_affinity_image_and_hooks(self) -> None:
        self.assertIn(
            'readonly SERVICE_CGROUP_RELATIVE="/system.slice/'
            'codeskeptic-stability.service"',
            self.operator,
        )
        self.assertIn(
            'readonly CONTROLLER_CGROUP_RELATIVE="${SERVICE_CGROUP_RELATIVE}/controller"',
            self.operator,
        )
        self.assertIn(
            'readonly PAYLOAD_CGROUP_RELATIVE="${SERVICE_CGROUP_RELATIVE}/'
            'codeskeptic-p10-09"',
            self.operator,
        )
        self.assertIn(
            'readonly MEASUREMENT_CGROUP="${CGROUP_ROOT}${PAYLOAD_CGROUP_RELATIVE}/'
            'measurement"',
            self.operator,
        )
        self.assertIn('readonly CONTROLLER_CPUS="4-11"', self.operator)
        self.assertIn('readonly MEASUREMENT_CPUS="0-3"', self.operator)
        self.assertIn('prepare_measurement_cgroup() {', self.operator)
        self.assertIn('run_rootful_preflight_probe() {', self.operator)
        self.assertIn('cleanup_cgroup_authority() {', self.operator)
        self.assertIn(
            '"$CGROUP_AUTHORITY" arm --session "$session_name"',
            self.operator,
        )
        self.assertIn(
            '"$CGROUP_AUTHORITY" cleanup --session "$session_name"',
            self.operator,
        )
        self.assertIn(
            'local -a probe_args=("${PODMAN_CONTAINER_OPTIONS[@]}")',
            self.operator,
        )
        self.assertIn(
            'for bind_mount in "${CONTAINER_BIND_MOUNTS[@]}"',
            self.operator,
        )
        self.assertIn('probe_args+=(\n        "$PINNED_EVIDENCE_IMAGE"', self.operator)
        self.assertIn('/proc/self/cgroup', self.operator)
        self.assertIn('cpuset.cpus.effective', self.operator)
        self.assertIn('cpuset.cpus.exclusive.effective', self.operator)
        self.assertIn('cpuset.cpus.partition', self.operator)
        self.assertIn('cgroup.procs', self.operator)
        self.assertIn('cgroup.events', self.operator)
        self.assertIn('os.sched_getaffinity(0)', self.operator)
        self.assertIn('os.sched_setaffinity(0, range(4, 12))', self.operator)
        self.assertIn('record != f"0::{expected_controller}"', self.operator)
        self.assertIn('resource.getrlimit(resource.RLIMIT_NOFILE)', self.operator)
        self.assertIn('import yaml', self.operator)
        self.assertIn('run_in_measurement_cgroup.py', self.operator)
        self.assertIn('os.getpid() != 1', self.operator)
        self.assertIn('CODESKEPTIC_ROOTFUL_PREFLIGHT_OK', self.operator)
        self.assertIn('find "$OPERATOR_ROOT"', self.operator)
        self.assertIn("-name '*.json'", self.operator)
        self.assertIn(
            'cgroup_has_word "${PAYLOAD_CGROUP}/cgroup.subtree_control"',
            self.operator,
        )
        self.assertIn(
            '[[ "$config_measurement_cgroup" == "$MEASUREMENT_CGROUP" ]]',
            self.operator,
        )
        self.assertIn('\nprepare_measurement_cgroup\n', self.operator)
        self.assertIn('\nrun_rootful_preflight_probe\n', self.operator)
        self.assertLess(
            self.operator.rindex('\nrun_rootful_preflight_probe\n'),
            self.operator.rindex('\nrunner_exit=0\n'),
        )
        self.assertIn("private PID namespace", self.readme)
        self.assertIn("4096", self.readme)
        self.assertIn("PyYAML", self.readme)
        self.assertIn("undefined-sanitizer", self.readme)
        self.assertIn("tests/codeskeptic_tests", self.readme)
        self.assertIn("0-3", self.readme)
        self.assertIn("4-11", self.readme)

    def test_real_container_entry_rechecks_exact_process_contract(self) -> None:
        entry = CONTAINER_ENTRY.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_CGROUP = "/system.slice/', entry)
        self.assertIn('codeskeptic-stability.service/controller"', entry)
        self.assertIn("os.getpid() != 1", entry)
        self.assertIn("os.geteuid() != 0", entry)
        self.assertIn("os.sched_getaffinity(0)", entry)
        self.assertIn("resource.getrlimit(resource.RLIMIT_NOFILE)", entry)
        self.assertIn('record != f"0::{EXPECTED_CGROUP}"', entry)
        self.assertIn('"run": (', entry)
        self.assertIn('"verify": (', entry)
        completed = subprocess.run(
            [sys.executable, "-B", os.fspath(CONTAINER_ENTRY), "run"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"CODESKEPTIC_STABILITY_CONTAINER_ENTRY_FAIL", completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)

    def test_controller_inventory_gate_propagates_each_ancestor_failure(self) -> None:
        functions = "\n".join(
            shell_function(self.operator, name)
            for name in (
                "require_ancestor_controller_inventory",
                "require_active_controller_inventory",
            )
        )
        for failure_label in (
            "root available",
            "root subtree",
            "system.slice available",
            "system.slice subtree",
            "service available",
            "service subtree",
            "payload available",
            "payload subtree",
        ):
            with self.subTest(failure_label=failure_label):
                harness = f"""#!/usr/bin/env bash
set -uo pipefail
CGROUP_ROOT=/root
SYSTEM_SLICE_CGROUP=/system.slice
SERVICE_CGROUP=/service
PAYLOAD_CGROUP=/payload
ROOT_AVAILABLE_CONTROLLER_INVENTORY=root-available
HOST_SUBTREE_CONTROLLER_INVENTORY=host-subtree
DELEGATED_CONTROLLER_INVENTORY=delegated-baseline
FAILURE_LABEL={shlex.quote(failure_label)}
require_exact_controller_inventory() {{
    [[ "$4" != "$FAILURE_LABEL" ]]
}}
{functions}
if require_active_controller_inventory; then
    exit 9
fi
exit 0
"""
                completed = subprocess.run(
                    ["/usr/bin/bash", "-c", harness],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_empty_cgroup_gate_propagates_pseudofile_read_failures(self) -> None:
        function = shell_function(self.operator, "require_empty_cgroup")
        for failed_file in ("cgroup.procs", "cgroup.events"):
            with self.subTest(failed_file=failed_file):
                harness = f"""#!/usr/bin/env bash
set -uo pipefail
FAILED_FILE={shlex.quote(failed_file)}
fail() {{ return 1; }}
cgroup_value() {{
    if [[ "$1" == */"$FAILED_FILE" ]]; then
        return 1
    fi
    if [[ "$1" == */cgroup.procs ]]; then
        printf ''
    else
        printf 'populated 0\\nfrozen 0'
    fi
}}
{function}
if require_empty_cgroup /payload; then
    exit 9
fi
exit 0
"""
                completed = subprocess.run(
                    ["/usr/bin/bash", "-c", harness],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_empty_cgroup_gate_rejects_symlinked_pseudofile(self) -> None:
        functions = "\n".join(
            shell_function(self.operator, name)
            for name in ("cgroup_value", "require_empty_cgroup")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("", encoding="ascii")
            (root / "cgroup.procs").symlink_to(target)
            (root / "cgroup.events").write_text(
                "populated 0\nfrozen 0\n", encoding="ascii"
            )
            harness = f"""#!/usr/bin/env bash
set -uo pipefail
fail() {{ return 1; }}
{functions}
if require_empty_cgroup {shlex.quote(os.fspath(root))}; then
    exit 9
fi
exit 0
"""
            completed = subprocess.run(
                ["/usr/bin/bash", "-c", harness],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_operator_seals_host_envelope_after_independent_inner_verification(self) -> None:
        verifier = shell_array(self.operator, "RUNTIME_VERIFIER_COMMAND")
        self.assertEqual(
            verifier,
            [
                "/usr/bin/taskset",
                "--cpu-list",
                "4-11",
                "/usr/bin/python3",
                "-B",
                "/operator/container-entry.py",
                "verify",
            ],
        )
        for function in (
            "capture_host_snapshot() {",
            "cleanup_container() {",
            "run_inner_verifier() {",
            "write_cleanup_record() {",
            "seal_operator_evidence() {",
        ):
            self.assertIn(function, self.operator)
        pre = self.operator.rindex('capture_host_snapshot "pre"')
        image_check = self.operator.rindex(
            "verify_pinned_image_and_empty_container_store"
        )
        prepare = self.operator.rindex("\nprepare_measurement_cgroup\n")
        main = self.operator.rindex("\nrunner_exit=0\n")
        main_cleanup = self.operator.rindex("\ncleanup_container 1\n")
        main_identity = self.operator.rindex(
            '\nmain_container_id="$last_removed_container_id"\n'
        )
        verifier_run = self.operator.rindex("\nrun_inner_verifier\n")
        cgroup_cleanup = self.operator.rindex("\ncleanup_cgroup_authority\n")
        runtime_cleanup = self.operator.rindex("\ncleanup_campaign_runtime\n")
        cleanup_record = self.operator.rindex("\nwrite_cleanup_record\n")
        post = self.operator.rindex('\ncapture_host_snapshot "post"\n')
        seal = self.operator.rindex("\nseal_operator_evidence\n")
        final_exit = self.operator.rindex('\nexit 0\n')
        sequence = [
            pre,
            image_check,
            prepare,
            main,
            main_cleanup,
            main_identity,
            verifier_run,
            cgroup_cleanup,
            runtime_cleanup,
            cleanup_record,
            post,
            seal,
            final_exit,
        ]
        for left, right in zip(sequence, sequence[1:]):
            self.assertLess(left, right)
        self.assertIn('${evidence_output}:/evidence:ro', self.operator)
        self.assertIn('${container_runtime}:/runtime:ro', self.operator)
        self.assertIn('"$RUNNER_PATH" seal-operator', self.operator)
        self.assertIn('"$RUNNER_PATH" verify-operator', self.operator)

    def test_durable_host_recovery_wraps_every_host_mutation_and_acceptance(self) -> None:
        post_stop = POST_STOP.read_text(encoding="utf-8")
        guided = GUIDED.read_text(encoding="utf-8")
        runner = self.operator
        self.assertIn(
            'readonly HOST_RECOVERY="${OPERATOR_ROOT}/host-recovery.py"',
            runner,
        )
        self.assertIn(
            'readonly HOST_RECOVERY_PATH="${OPERATOR_ROOT}/host-recovery.py"',
            guided,
        )
        self.assertIn('require_root_immutable_file "$HOST_RECOVERY"', runner)
        self.assertIn('require_root_immutable_executable "$HOST_RECOVERY_PATH"', guided)
        self.assertIn('readonly PRLIMIT="/usr/bin/prlimit"', guided)
        self.assertIn('require_root_immutable_executable "$PRLIMIT"', guided)
        self.assertIn(
            'readonly HOST_RECOVERY="/opt/codeskeptic-p10-09/operator/'
            'host-recovery.py"',
            post_stop,
        )

        startup_recovery = runner.index('\n"$HOST_RECOVERY" recover\n')
        inspect_request = runner.index("\ninspect_launch_request\n")
        arm = runner.index(
            '\n"$HOST_RECOVERY" arm --mode "$operator_mode" '
            '--session "$session_name"\n'
        )
        campaign_mkdir = runner.index(
            '/usr/bin/mkdir --mode=0700 -- "$session_output"', arm
        )
        consume_request = runner.index("\nconsume_launch_request\n", arm)
        probe_mkdir = runner.index(
            '/usr/bin/mkdir --mode=0700 -- "$probe_root"', arm
        )
        snapshot = runner.index(
            '"$HOST_RECOVERY" snapshot --session "$session_name"', arm
        )
        handoff = runner.rindex("\npublish_guided_handoff\n")
        cgroup_arm = runner.rindex(
            '\n"$CGROUP_AUTHORITY" arm --session "$session_name"\n'
        )
        self.assertLess(startup_recovery, inspect_request)
        self.assertLess(inspect_request, arm)
        self.assertLess(arm, consume_request)
        self.assertLess(consume_request, campaign_mkdir)
        self.assertLess(arm, campaign_mkdir)
        self.assertLess(arm, probe_mkdir)
        self.assertLess(snapshot, handoff)
        self.assertLess(handoff, cgroup_arm)

        self.assertIn("append_host_recovery_labels() {", runner)
        for kind in ("preflight", "campaign", "verifier"):
            self.assertIn(
                f'append_host_recovery_labels {kind} ',
                runner,
            )
        self.assertIn(
            '"$HOST_RECOVERY" cleanup --session "$session_name"', runner
        )
        accepted = runner.index("CODESKEPTIC_ROOTFUL_PROBE_ACCEPTED")
        probe_branch = runner.rindex(
            'if [[ "$operator_mode" == "probe-only" ]]; then', 0, accepted
        )
        probe_cleanup = runner.index(
            "complete_host_recovery_cleanup", probe_branch
        )
        self.assertLess(probe_cleanup, accepted)

        startup_body = post_stop[post_stop.index(
            'if (( $# == 1 )) && [[ "$1" == "--startup-recovery" ]]'
        ):]
        self.assertLess(
            startup_body.index('"$HOST_RECOVERY" recover'),
            startup_body.index('restore_graphical_state ""'),
        )
        normal_recovery = post_stop.rindex('"$HOST_RECOVERY" recover')
        graphical_recovery = post_stop.rindex('restore_graphical_state "$runtime_session"')
        self.assertLess(normal_recovery, graphical_recovery)

        cleanup = shell_function(runner, "write_cleanup_record")
        self.assertIn("codeskeptic-stability-host-cleanup-v5", cleanup)
        self.assertIn("host-recovery-intent.json", cleanup)
        self.assertIn("host_recovery_intent_bound", cleanup)
        self.assertIn("host_recovery_marker_absent", cleanup)
        self.assertIn("host_recovery_temporary_absent", cleanup)

    def test_probe_only_request_is_atomic_bound_and_creates_no_campaign(self) -> None:
        guided = GUIDED.read_text(encoding="utf-8")
        marker = "/run/codeskeptic-p10-09/probe-only.request"
        self.assertIn(f'readonly PROBE_REQUEST_PATH="{marker}"', guided)
        self.assertIn(f'readonly PROBE_REQUEST_PATH="{marker}"', self.operator)
        self.assertIn('guided_mode="probe-only"', guided)
        self.assertIn('exec /usr/bin/sudo -- "$GUIDED_PATH" --root --probe-only', guided)
        self.assertIn("os.O_CREAT | os.O_EXCL", guided)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", guided)
        self.assertIn('cleanup_owned_probe_request() {', guided)
        self.assertIn('value["mode"] != expected_mode', guided)
        self.assertIn('operator_mode="probe-only"', self.operator)
        self.assertIn('/usr/bin/mv --no-target-directory --', self.operator)
        self.assertIn('consume_probe_request() {', self.operator)
        self.assertIn('cleanup_consumed_probe_request() {', self.operator)
        self.assertIn('readonly PROBE_REQUEST_SCHEMA="codeskeptic-probe-only-v1"', guided)
        self.assertIn('readonly PROBE_REQUEST_SCHEMA="codeskeptic-probe-only-v1"', self.operator)
        self.assertIn('"mode": "probe-only"', guided)
        self.assertIn('"schema": schema', guided)
        self.assertIn('"nonce": nonce', guided)
        self.assertIn('probe_root="${RUNTIME_ROOT}/probe-${session_nonce}"', self.operator)
        self.assertIn('evidence_output="${probe_root}/evidence"', self.operator)
        self.assertIn('session_output=""', self.operator)
        self.assertIn('if [[ "$operator_mode" == "campaign" ]]; then', self.operator)
        self.assertIn('if [[ "$operator_mode" == "probe-only" ]]; then', self.operator)
        branch_start = self.operator.index(
            'if [[ "$operator_mode" == "campaign" ]]; then\n    session_name='
        )
        branch_else = self.operator.index(
            '\nelse\n    session_name="probe-', branch_start
        )
        branch_end = self.operator.index(
            '\nfi\n\npublish_guided_handoff\nwait_for_guided_decision\n\n'
            'if [[ "$operator_mode" == "campaign" ]]; then\n'
            '    capture_host_snapshot "pre"',
            branch_else,
        )
        self.assertNotIn("seal-launch", self.operator[branch_start:branch_end])
        campaign_seal_branch = self.operator.index(
            'if [[ "$operator_mode" == "campaign" ]]; then\n'
            '    capture_host_snapshot "pre"\n'
        )
        campaign_seal_end = self.operator.index(
            '\nfi\n\nreadonly -a CONTAINER_BIND_MOUNTS', campaign_seal_branch
        )
        self.assertLess(campaign_seal_branch, campaign_seal_end)
        self.assertIn(
            "seal-launch",
            self.operator[campaign_seal_branch:campaign_seal_end],
        )
        handoff = self.operator.rindex("\npublish_guided_handoff\n")
        arm = self.operator.rindex(
            '\n"$CGROUP_AUTHORITY" arm --session "$session_name"\n'
        )
        self.assertLess(handoff, arm)
        probe_terminal = self.operator.index('CODESKEPTIC_ROOTFUL_PROBE_ACCEPTED')
        self.assertLess(probe_terminal, self.operator.rindex('\nrunner_exit=0\n'))
        self.assertIn("--probe-only", self.readme)
        self.assertIn("UnitFileState=static", self.readme)
        self.assertIn("--property=UnitFileState", guided)
        self.assertIn('== "static"', guided)
        self.assertIn("--property=DropInPaths --value", guided)
        self.assertIn('[[ -z "$drop_in_paths" ]]', guided)
        self.assertIn("rejects every systemd drop-in", self.readme)
        self.assertIn("graphical.target must be active", guided)
        self.assertIn("display-manager.service must be active/running", guided)
        self.assertNotIn("list-sessions --no-legend --no-pager", guided)
        self.assertIn("codeskeptic-campaign-request-v1", guided)
        self.assertIn("create_campaign_request", guided)
        self.assertIn("cleanup_owned_campaign_request", guided)
        self.assertIn("campaign must be launched by the installed non-root", guided)
        self.assertIn("codeskeptic-campaign-request-v1", self.operator)
        self.assertIn("consume_campaign_request", self.operator)
        self.assertIn("cleanup_consumed_campaign_request", self.operator)
        self.assertIn("probe and campaign requests cannot coexist", self.operator)
        self.assertRegex(self.readme.lower(), r"no\s+campaign evidence")

    def test_guided_handoff_is_canonical_root_owned_and_nonce_bound(self) -> None:
        nonce = "11111111-2222-3333-4444-555555555555"
        boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        parser = guided_handoff_parser().replace(
            "metadata.st_uid != 0",
            "metadata.st_uid != os.getuid()",
            1,
        ).replace(
            "metadata.st_gid != 0",
            "metadata.st_gid != os.getgid()",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            handoff = Path(directory) / "guided-handoff.json"

            def run(session_nonce: str) -> subprocess.CompletedProcess[bytes]:
                handoff.unlink(missing_ok=True)
                handoff.write_text(
                    '{"mode":"campaign","nonce":"'
                    f'{session_nonce}","schema":"codeskeptic-guided-handoff-v1",'
                    f'"session":"20260823T120000Z-{boot_id}-{session_nonce}"}}\n',
                    encoding="ascii",
                )
                handoff.chmod(0o400)
                return subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-",
                        str(handoff),
                        "codeskeptic-guided-handoff-v1",
                        "campaign",
                        nonce,
                        "512",
                    ],
                    input=parser.encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            accepted = run(nonce)
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            rejected = run("99999999-8888-7777-6666-555555555555")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"differs from this invocation", rejected.stderr)

    def test_cidfile_cleanup_is_fail_closed(self) -> None:
        self.assertIn('[[ ! -e "$cidfile" && ! -L "$cidfile" ]]', self.operator)
        self.assertIn('podman_run_args+=(--cidfile "$cidfile")', self.operator)
        self.assertIn('cleanup_container', self.operator)
        self.assertNotIn("container inspect", self.operator)
        self.assertNotIn('"$HOST_RECOVERY" owned-container-id', self.operator)
        self.assertNotIn(
            'rm --force --ignore -- "$container_name"', self.operator
        )
        self.assertNotIn("run_podman rm --force --ignore", self.operator)
        self.assertIn(
            '"$HOST_RECOVERY" remove-owned-container', self.operator
        )
        self.assertIn('cleanup_container 1', self.operator)
        self.assertIn(
            'fail "required container was absent from central cleanup"',
            self.operator,
        )
        self.assertIn(
            'main_container_id="$last_removed_container_id"', self.operator
        )
        self.assertIn('trap publish_terminal_status EXIT', self.operator)
        self.assertIn("trap 'terminate_with_signal_status 1' HUP", self.operator)
        self.assertIn("trap 'terminate_with_signal_status 2' INT", self.operator)
        self.assertIn("trap 'terminate_with_signal_status 15' TERM", self.operator)
        self.assertIn('exit "$((128 + signal_number))"', self.operator)
        self.assertRegex(self.operator, r"if ! cleanup_container; then\n\s+exit_code=1")
        terminal = self.operator[
            self.operator.index("publish_terminal_status() {"):
            self.operator.index("(( EUID == 0 ))")
        ]
        self.assertIn("bounded_cleanup_safe=0", terminal)
        self.assertIn("if (( bounded_cleanup_safe == 1 )); then", terminal)
        self.assertLess(
            terminal.index("cleanup_container"),
            terminal.index("cleanup_campaign_runtime"),
        )
        bounded = self.operator[
            self.operator.index("cleanup_container() {"):
            self.operator.index("run_rootful_preflight_probe() {")
        ]
        self.assertLess(
            bounded.index("remove-owned-container"),
            bounded.index("container ID file survived central cleanup"),
        )

    def test_controller_exposes_the_exact_operator_entrypoint(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", str(CONTROLLER), "run", "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--config CONFIG", completed.stdout)
        self.assertIn("--output OUTPUT", completed.stdout)

    def test_notifications_and_status_exist_only_for_terminal_state(self) -> None:
        self.assertIn("trap publish_terminal_status EXIT", self.operator)
        function_start = self.operator.index("publish_terminal_status() {")
        function_end = self.operator.index("\n}\n", function_start) + 3
        function = self.operator[function_start:function_end]
        self.assertIn('result="success"', function)
        self.assertIn('result="failure"', function)
        self.assertIn("terminal-status", function)
        self.assertIn("mode=%s", function)
        self.assertIn("probe_request=%s", function)
        self.assertIn('"$operator_mode"', function)
        self.assertIn('CODESKEPTIC_TERMINAL_NOTIFY:-0', function)
        self.assertIn("\\a\\a\\a", function)
        self.assertIn("/usr/bin/wall", function)

        outside_function = (
            self.operator[:function_start] + self.operator[function_end:]
        )
        self.assertNotIn("/usr/bin/wall", outside_function)
        self.assertNotIn("\\a", outside_function)

    def test_guided_entrypoint_is_one_command_bounded_and_non_destructive(self) -> None:
        guided = GUIDED.read_text(encoding="utf-8")
        self.assertIn(
            'readonly GUIDED_PATH="/opt/codeskeptic-p10-09/operator/'
            'guided-stability.sh"',
            guided,
        )
        self.assertIn(
            'readonly SERVICE_UNIT="codeskeptic-stability.service"', guided
        )
        self.assertIn(
            'readonly HANDOFF_PATH="/run/codeskeptic-p10-09/'
            'guided-handoff.json"',
            guided,
        )
        self.assertIn(
            'readonly RESTORE_GRAPHICAL_PATH="/var/lib/codeskeptic-p10-09/'
            'graphical-restoration-state.json"',
            guided,
        )
        self.assertIn('readonly HANDOFF_SCHEMA="codeskeptic-guided-handoff-v1"', guided)
        self.assertIn('readonly MAX_HANDOFF_BYTES=512', guided)
        self.assertIn('readonly HANDOFF_WAIT_ATTEMPTS=600', guided)
        self.assertIn('readonly HANDOFF_WAIT_INTERVAL=0.1', guided)
        self.assertIn("CODESKEPTIC_GUIDED_INPUT_REQUIRED", guided)
        self.assertIn("CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE", guided)
        self.assertIn('/usr/bin/printf \'\\a\\a\\a\'', guided)
        self.assertIn(
            'exec /usr/bin/sudo -- "$GUIDED_PATH" --root', guided
        )
        self.assertIn(
            '"$SYSTEMCTL" start --no-block "$SERVICE_UNIT"', guided
        )
        self.assertIn('read_bound_handoff() {', guided)
        self.assertIn('wait_for_bound_handoff() {', guided)
        self.assertIn("metadata.st_uid != 0", guided)
        self.assertIn("metadata.st_gid != 0", guided)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o400", guided)
        self.assertIn('CODESKEPTIC_P10_09_HANDOFF_ACCEPTED', guided)
        self.assertIn('"$SYSTEMCTL" reset-failed "$SERVICE_UNIT"', guided)
        self.assertNotIn("systemctl isolate", guided)
        self.assertNotIn("systemctl reboot", guided)
        self.assertNotIn("systemctl poweroff", guided)
        self.assertNotIn("start --wait", guided)
        self.assertIn("unconfirmed graphical restoration state exists", guided)
        graphical_check = guided.rindex("graphical.target must be active")
        request = guided.rindex("create_campaign_request ||")
        start = guided.rindex('"$SYSTEMCTL" start --no-block "$SERVICE_UNIT"')
        handoff = guided.rindex(
            'handoff_session="$(wait_for_bound_handoff "$guided_mode" "$expected_nonce")"'
        )
        release = guided.rindex('owned_campaign_nonce=""')
        self.assertLess(graphical_check, request)
        self.assertLess(request, start)
        self.assertLess(start, handoff)
        self.assertLess(handoff, release)
        self.assertIn(
            "/opt/codeskeptic-p10-09/operator/guided-stability.sh",
            self.readme,
        )
        self.assertIn("one command", self.readme.lower())
        self.assertIn("never reboots", self.readme.lower())
        self.assertIn("no manual isolate", self.readme.lower())
        self.assertIn("no exit-code capture", self.readme.lower())

    def test_post_stop_cleans_first_and_restores_graphics_fail_closed(self) -> None:
        post_stop = POST_STOP.read_text(encoding="utf-8")
        self.assertNotEqual(POST_STOP.stat().st_mode & 0o111, 0)
        self.assertIn(
            'readonly HOST_RECOVERY="/opt/codeskeptic-p10-09/operator/'
            'host-recovery.py"',
            post_stop,
        )
        self.assertIn(
            'readonly SESSION_PATH="/run/codeskeptic-p10-09/session-name"',
            post_stop,
        )
        self.assertIn(
            'readonly RESTORE_GRAPHICAL_PATH="/var/lib/codeskeptic-p10-09/'
            'graphical-restoration-state.json"',
            post_stop,
        )
        self.assertIn('restore_graphical_state "$runtime_session"', post_stop)
        cleanup = '"$HOST_RECOVERY" recover'
        self.assertIn(cleanup, post_stop)
        cleanup_position = post_stop.rindex(cleanup)
        transition_position = post_stop.rindex(
            'restore_graphical_state "$runtime_session"'
        )
        graphical_position = transition_position
        self.assertLess(cleanup_position, transition_position)
        self.assertLessEqual(transition_position, graphical_position)
        self.assertIn("LoadState=loaded\\nActiveState=active", post_stop)
        self.assertEqual(
            set(shell_array(post_stop, "TRANSITION_TARGETS")),
            {"shutdown.target", "rescue.target", "emergency.target"},
        )
        self.assertIn(
            'readonly STATUS_PATH="/var/lib/codeskeptic-p10-09/status/'
            'post-stop-status.txt"',
            post_stop,
        )
        self.assertIn("skipped-system-transition", post_stop)
        self.assertIn("skipped-unverified-transition", post_stop)
        self.assertIn("not-requested", post_stop)
        self.assertIn("host_cleanup=%s", post_stop)
        self.assertIn("graphical=%s", post_stop)
        self.assertIn("service_result=%s", post_stop)
        self.assertIn("chmod 0400", post_stop)
        self.assertNotIn("/etc/systemd/system/codeskeptic-stability.service", post_stop)
        self.assertNotIn("rm -rf", post_stop)
        self.assertIn("permanent unit and operator remain installed", self.readme.lower())

        runner = self.operator
        self.assertIn(
            'readonly RESTORE_GRAPHICAL_PATH="/var/lib/codeskeptic-p10-09/'
            'graphical-restoration-state.json"',
            runner,
        )
        self.assertIn("publish_graphical_restoration_intent() {", runner)
        intent = runner.rindex("\npublish_graphical_restoration_intent\n")
        isolate = runner.rindex("\nisolate_graphical_session\n")
        self.assertLess(intent, isolate)

    def test_post_stop_session_marker_is_exact_and_root_bound(self) -> None:
        parser = post_stop_session_parser().replace(
            "metadata.st_uid != 0",
            "metadata.st_uid != os.getuid()",
            1,
        ).replace(
            "metadata.st_gid != 0",
            "metadata.st_gid != os.getgid()",
            1,
        )
        nonce = "11111111-2222-3333-4444-555555555555"
        boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "session-name"

            def run(value: str) -> subprocess.CompletedProcess[bytes]:
                marker.unlink(missing_ok=True)
                marker.write_text(value, encoding="ascii")
                marker.chmod(0o400)
                return subprocess.run(
                    [sys.executable, "-B", "-", str(marker)],
                    input=parser.encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            session = f"20260823T120000Z-{boot_id}-{nonce}"
            accepted = run(session + "\n")
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            self.assertEqual(accepted.stdout, (session + "\n").encode("ascii"))
            rejected = run(session + "\n\n")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"malformed", rejected.stderr)

    def test_post_stop_restoration_intent_is_exact_and_session_bound(self) -> None:
        parser = post_stop_restoration_parser().replace(
            "metadata.st_uid != 0",
            "metadata.st_uid != os.getuid()",
            1,
        ).replace(
            "metadata.st_gid != 0",
            "metadata.st_gid != os.getgid()",
            1,
        )
        nonce = "11111111-2222-3333-4444-555555555555"
        boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        session = f"20260823T120000Z-{boot_id}-{nonce}"
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "graphical-restoration-state.json"

            def run(expected: str) -> subprocess.CompletedProcess[bytes]:
                marker.unlink(missing_ok=True)
                marker.write_text(
                    '{"nonce":"'
                    f'{nonce}","phase":"restore-required","schema":"'
                    'codeskeptic-graphical-restoration-v1","session":"'
                    f'{session}"}}\n',
                    encoding="ascii",
                )
                marker.chmod(0o400)
                return subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-",
                        str(marker),
                        "codeskeptic-graphical-restoration-v1",
                        expected,
                    ],
                    input=parser.encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            accepted = run(session)
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            rejected = run(session + "-drift")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"graphical restoration intent", rejected.stderr)

    def test_guided_requires_a_second_exact_ack_before_isolation(self) -> None:
        guided = GUIDED.read_text(encoding="utf-8")
        runner = self.operator
        self.assertIn(
            'readonly GUIDED_DECISION_PATH="/run/codeskeptic-p10-09/'
            'guided-decision.json"',
            guided,
        )
        self.assertIn(
            'readonly GUIDED_DECISION_SCHEMA="codeskeptic-guided-decision-v1"',
            guided,
        )
        self.assertIn("publish_guided_decision() {", guided)
        self.assertIn('publish_guided_decision "accept"', guided)
        self.assertIn('publish_guided_decision "cancel"', guided)
        self.assertIn(
            'readonly GUIDED_DECISION_PATH="${RUNTIME_ROOT}/guided-decision.json"',
            runner,
        )
        self.assertIn("wait_for_guided_decision() {", runner)
        self.assertIn('"$guided_decision" == "accept"', runner)
        self.assertIn('"$guided_decision" == "cancel"', runner)
        self.assertIn('guided_ack_consumed=1', runner)
        handoff = runner.rindex("\npublish_guided_handoff\n")
        ack = runner.rindex("\nwait_for_guided_decision\n")
        restore = runner.rindex("\npublish_graphical_restoration_intent\n")
        isolate = runner.rindex("\nisolate_graphical_session\n")
        self.assertLess(handoff, ack)
        self.assertLess(ack, restore)
        self.assertLess(restore, isolate)
        isolate_body = shell_function(runner, "isolate_graphical_session")
        self.assertIn("guided_ack_consumed == 1", isolate_body)

    def test_visible_control_files_are_published_atomically(self) -> None:
        guided = GUIDED.read_text(encoding="utf-8")
        runner = self.operator
        for temporary in (
            ".campaign.request.tmp",
            ".probe-only.request.tmp",
            ".guided-decision.json.tmp",
        ):
            self.assertIn(temporary, guided)
        for temporary in (
            ".session-name.tmp",
            ".guided-handoff.json.tmp",
            ".graphical-restoration-state.json.tmp",
        ):
            self.assertIn(temporary, runner)
        for source in (guided, runner):
            self.assertIn("os.link(temporary, path", source)
            self.assertIn("os.fsync(descriptor)", source)
            self.assertIn("os.fsync(directory)", source)

    def test_graphical_restoration_is_durable_and_exactly_confirmed(self) -> None:
        post_stop = POST_STOP.read_text(encoding="utf-8")
        runner = self.operator
        durable = (
            "/var/lib/codeskeptic-p10-09/graphical-restoration-state.json"
        )
        self.assertIn(f'readonly RESTORE_GRAPHICAL_PATH="{durable}"', post_stop)
        self.assertIn(f'readonly RESTORE_GRAPHICAL_PATH="{durable}"', runner)
        self.assertIn("codeskeptic-graphical-restoration-v1", post_stop)
        self.assertIn("codeskeptic-graphical-restoration-v1", runner)
        self.assertIn('"phase": "restore-required"', runner)
        self.assertIn("restore_graphical_state() {", post_stop)
        self.assertIn("clear_graphical_restoration_state() {", post_stop)
        restore = shell_function(post_stop, "restore_graphical_state")
        exact_graphical = (
            "LoadState=loaded\\nActiveState=active\\nSubState=active\\nJob="
        )
        exact_display = (
            "LoadState=loaded\\nActiveState=active\\nSubState=running\\nJob="
        )
        self.assertIn(exact_graphical, restore)
        self.assertIn(exact_display, restore)
        self.assertIn('"$SYSTEMCTL" start --no-block graphical.target', restore)
        self.assertIn("RESTORE_WAIT_ATTEMPTS", restore)
        self.assertIn("clear_graphical_restoration_state", restore)
        self.assertNotIn('graphical_outcome="restore-requested"', post_stop)
        self.assertIn("--startup-recovery", post_stop)
        self.assertIn(
            "ExecStartPre=/opt/codeskeptic-p10-09/operator/post-stop.sh "
            "--startup-recovery",
            self.unit,
        )

    def test_async_graphical_start_never_counts_as_restored(self) -> None:
        post_stop = POST_STOP.read_text(encoding="utf-8")
        restore = shell_function(post_stop, "restore_graphical_state")
        start = restore.index('"$SYSTEMCTL" start --no-block graphical.target')
        clear = restore.index("clear_graphical_restoration_state")
        proof = restore.index(
            "LoadState=loaded\\nActiveState=active\\nSubState=active\\nJob=",
            start,
        )
        self.assertLess(start, proof)
        self.assertLess(proof, clear)
        self.assertIn('graphical_outcome="restore-timeout"', restore)
        self.assertRegex(
            restore,
            r'restore-timeout"\n\s+return 1',
        )

    def test_post_stop_interruption_leaves_durable_retry_authority(self) -> None:
        post_stop = POST_STOP.read_text(encoding="utf-8")
        clear = shell_function(post_stop, "clear_graphical_restoration_state")
        restore = shell_function(post_stop, "restore_graphical_state")
        self.assertNotIn("trap", restore)
        self.assertIn("path.unlink()", clear)
        self.assertIn("os.fsync(directory)", clear)
        exact_proof = restore.index(
            "LoadState=loaded\\nActiveState=active\\nSubState=active\\nJob="
        )
        clear_call = restore.index("clear_graphical_restoration_state")
        self.assertLess(exact_proof, clear_call)
        publish = shell_function(runner := self.operator, "publish_graphical_restoration_intent")
        self.assertIn("os.fsync(descriptor)", publish)
        self.assertIn("os.fsync(directory)", publish)
        self.assertLess(
            runner.rindex("\npublish_graphical_restoration_intent\n"),
            runner.rindex("\nisolate_graphical_session\n"),
        )

    def test_async_failure_and_interrupted_post_stop_retry_behavior(self) -> None:
        nonce = "11111111-2222-3333-4444-555555555555"
        boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        session = f"20260823T120000Z-{boot_id}-{nonce}"
        payload = {
            "nonce": nonce,
            "phase": "restore-required",
            "schema": "codeskeptic-graphical-restoration-v1",
            "session": session,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "graphical-restoration-state.json"
            mode = root / "mode"
            started = root / "start-called"
            fake_systemctl = root / "systemctl"
            harness = root / "restore-harness.sh"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f"mode_file={shlex.quote(os.fspath(mode))}\n"
                f"started={shlex.quote(os.fspath(started))}\n"
                "if [[ \"$1\" == start ]]; then\n"
                "  : >\"$started\"\n"
                "  exit 0\n"
                "fi\n"
                "target=\"${!#}\"\n"
                "case \"$target\" in\n"
                "  shutdown.target|rescue.target|emergency.target)\n"
                "    printf 'ActiveState=inactive\\nJob=\\n' ;;\n"
                "  graphical.target)\n"
                "    if [[ \"$(<\"$mode_file\")\" == active ]]; then\n"
                "      printf 'LoadState=loaded\\nActiveState=active\\nSubState=active\\nJob=\\n'\n"
                "    else\n"
                "      printf 'LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nJob=\\n'\n"
                "    fi ;;\n"
                "  display-manager.service)\n"
                "    if [[ \"$(<\"$mode_file\")\" == active ]]; then\n"
                "      printf 'LoadState=loaded\\nActiveState=active\\nSubState=running\\nJob=\\n'\n"
                "    else\n"
                "      printf 'LoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nJob=\\n'\n"
                "    fi ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_systemctl.chmod(0o700)

            def create_state() -> None:
                state.write_text(
                    json.dumps(payload, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="ascii",
                )
                state.chmod(0o400)

            mode.write_text("inactive\n", encoding="ascii")
            create_state()
            harness.write_text(
                restoration_harness(state, fake_systemctl, 2),
                encoding="utf-8",
            )
            harness.chmod(0o700)
            timed_out = subprocess.run(
                [os.fspath(harness)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            self.assertNotEqual(timed_out.returncode, 0)
            self.assertEqual(timed_out.stdout, "restore-timeout\n")
            self.assertTrue(state.exists(), "enqueue must retain durable state")

            mode.write_text("active\n", encoding="ascii")
            retried = subprocess.run(
                [os.fspath(harness)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            self.assertEqual(retried.returncode, 0, retried.stderr)
            self.assertEqual(retried.stdout, "restored-and-confirmed\n")
            self.assertFalse(state.exists())

            started.unlink(missing_ok=True)
            mode.write_text("inactive\n", encoding="ascii")
            create_state()
            harness.write_text(
                restoration_harness(state, fake_systemctl, 600),
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [os.fspath(harness)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            for _ in range(100):
                if started.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(started.exists())
            os.killpg(process.pid, 15)
            process.communicate(timeout=5)
            self.assertTrue(state.exists(), "interruption must retain retry state")

            mode.write_text("active\n", encoding="ascii")
            retried_after_interrupt = subprocess.run(
                [os.fspath(harness)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            self.assertEqual(
                retried_after_interrupt.returncode,
                0,
                retried_after_interrupt.stderr,
            )
            self.assertFalse(state.exists())

    def test_transport_describes_scope_not_elapsed_time_as_the_gate(self) -> None:
        contract = self.unit + "\n" + self.operator + "\n" + self.readme
        self.assertNotIn("259200", contract)
        self.assertNotRegex(contract.lower(), r"\b72\s*(?:h|hours?)\b")
        self.assertIn("does not prove", self.readme.lower())
        self.assertIn("one cold", self.readme.lower())
        self.assertIn("one warm", self.readme.lower())
        self.assertIn("18", self.readme)
        self.assertRegex(self.readme.lower(), r"elapsed time is\s+metadata")
        self.assertIn("launch receipt", self.readme.lower())
        self.assertIn("network=none", self.readme.lower())
        self.assertIn("pre-run receipt", self.readme.lower())
        self.assertIn("terminal receipt", self.readme.lower())
        self.assertIn("no resume", self.readme.lower())


if __name__ == "__main__":
    unittest.main()
