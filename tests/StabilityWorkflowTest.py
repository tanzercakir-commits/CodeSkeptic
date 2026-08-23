#!/usr/bin/env python3
"""Static operator contract for the authoritative P10-09 stability run."""

from __future__ import annotations

import ast
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATOR_ROOT = ROOT / "scripts" / "stability-systemd"
UNIT = OPERATOR_ROOT / "codeskeptic-stability.service"
OPERATOR = OPERATOR_ROOT / "run-authoritative-stability.sh"
GUIDED = OPERATOR_ROOT / "guided-stability.sh"
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


def guided_terminal_status_parser() -> str:
    text = GUIDED.read_text(encoding="utf-8")
    marker = '"$expected_probe_request" "$expected_campaign_request" <<\'PY\'\n'
    start = text.index(marker) + len(marker)
    end = text.index("\nPY\n}", start)
    return text[start:end]


class StabilityWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = UNIT.read_text(encoding="utf-8")
        self.operator = OPERATOR.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")

    def test_service_is_a_noninteractive_multi_user_control_plane(self) -> None:
        self.assertEqual(
            unit_value(self.unit, "ConditionKernelCommandLine"),
            "systemd.unit=multi-user.target",
        )
        self.assertNotIn("[Install]", self.unit)
        self.assertNotIn("WantedBy=", self.unit)
        conflicts = unit_value(self.unit, "Conflicts").split()
        self.assertIn("graphical.target", conflicts)
        self.assertIn("sleep.target", conflicts)
        self.assertIn("suspend.target", conflicts)
        self.assertEqual(unit_value(self.unit, "Type"), "exec")
        self.assertEqual(unit_value(self.unit, "User"), "root")
        self.assertEqual(unit_value(self.unit, "Group"), "root")
        self.assertEqual(unit_value(self.unit, "StandardInput"), "null")

        self.assertNotIn("graphical.target", self.operator)
        executable_contract = self.unit + "\n" + self.operator
        for forbidden in (
            "systemctl isolate",
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
        self.assertEqual(unit_value(self.unit, "Delegate"), "yes")
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
            unit_value(self.unit, "ExecStart"),
            "/opt/codeskeptic-p10-09/operator/run-authoritative-stability.sh",
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
        self.assertEqual(self.operator.count("/usr/bin/systemd-inhibit"), 1)
        self.assertIn("--what=shutdown:sleep", self.operator)
        self.assertIn("--mode=block", self.operator)

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
                "/usr/bin/python3",
                "-B",
                "/authority/source/scripts/run_stability_campaign.py",
                "run",
                "--config",
                "/config/runtime.json",
                "--output",
                "/evidence",
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
                "--cgroups=no-conmon",
                "--cgroupns=host",
                "--cgroup-parent",
                "$PAYLOAD_CGROUP_RELATIVE",
                "--pid=private",
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
            '"cgroups": "no-conmon"', CONTROLLER.read_text(encoding="utf-8")
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
        self.assertIn('"cgroup_parent": RUNTIME_CGROUP_PARENT', controller)
        self.assertIn('"pid_namespace": "private"', controller)
        self.assertIn('"maximum_open_fds": MAXIMUM_OPEN_FDS', controller)
        self.assertNotIn("--cgroups=disabled", self.operator)
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
        self.assertIn('cleanup_measurement_cgroup() {', self.operator)
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
            self.operator.rindex('/usr/bin/systemd-inhibit'),
        )
        self.assertIn("private PID namespace", self.readme)
        self.assertIn("4096", self.readme)
        self.assertIn("PyYAML", self.readme)
        self.assertIn("undefined-sanitizer", self.readme)
        self.assertIn("tests/codeskeptic_tests", self.readme)
        self.assertIn("0-3", self.readme)
        self.assertIn("4-11", self.readme)

    def test_operator_seals_host_envelope_after_independent_inner_verification(self) -> None:
        verifier = shell_array(self.operator, "RUNTIME_VERIFIER_COMMAND")
        self.assertEqual(
            verifier,
            [
                "/usr/bin/python3",
                "-B",
                "/authority/source/scripts/run_stability_campaign.py",
                "verify",
                "--config",
                "/config/runtime.json",
                "--evidence",
                "/evidence",
            ],
        )
        for function in (
            "capture_host_snapshot() {",
            "read_bound_container_id() {",
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
        main_identity = self.operator.rindex(
            '\nmain_container_id="$(read_bound_container_id)"\n'
        )
        main_cleanup = self.operator.rindex("\ncleanup_container\n", main_identity)
        verifier_run = self.operator.rindex("\nrun_inner_verifier\n")
        cgroup_cleanup = self.operator.rindex("\ncleanup_measurement_cgroup\n")
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
            main_identity,
            main_cleanup,
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
        self.assertIn('values["mode"] != expected_mode', guided)
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
            '\nfi\n\nif [[ "$operator_mode" == "campaign" ]]; then\n'
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
        probe_terminal = self.operator.index('CODESKEPTIC_ROOTFUL_PROBE_ACCEPTED')
        self.assertLess(probe_terminal, self.operator.rindex('/usr/bin/systemd-inhibit'))
        self.assertIn("--probe-only", self.readme)
        self.assertIn("UnitFileState=static", self.readme)
        self.assertIn("--property=UnitFileState", guided)
        self.assertIn('== "static"', guided)
        self.assertIn("--property=DropInPaths --value", guided)
        self.assertIn('[[ -z "$drop_in_paths" ]]', guided)
        self.assertIn("rejects every systemd drop-in", self.readme)
        self.assertIn("--property=ActiveState --value graphical.target", guided)
        self.assertIn("display-manager.service must already be inactive/dead", guided)
        self.assertIn("list-sessions --no-legend --no-pager", guided)
        self.assertIn("x11|wayland|mir", guided)
        self.assertIn("codeskeptic-campaign-request-v1", guided)
        self.assertIn("create_campaign_request", guided)
        self.assertIn("cleanup_owned_campaign_request", guided)
        self.assertIn("campaign must be launched by the installed non-root", guided)
        self.assertIn("codeskeptic-campaign-request-v1", self.operator)
        self.assertIn("consume_campaign_request", self.operator)
        self.assertIn("cleanup_consumed_campaign_request", self.operator)
        self.assertIn("probe and campaign requests cannot coexist", self.operator)
        self.assertRegex(self.readme.lower(), r"no\s+campaign evidence")

    def test_campaign_terminal_status_is_bound_to_guided_nonce(self) -> None:
        nonce = "11111111-2222-3333-4444-555555555555"
        boot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        parser = guided_terminal_status_parser().replace(
            "metadata.st_uid != 0",
            "metadata.st_uid != os.getuid()",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / "terminal-status"

            def run(session_nonce: str) -> subprocess.CompletedProcess[bytes]:
                status.write_text(
                    "mode=campaign\n"
                    "probe_request=none\n"
                    "result=success\n"
                    "exit_code=0\n"
                    "session=/var/lib/codeskeptic-p10-09/sessions/"
                    f"20260823T120000Z-{boot_id}-{session_nonce}\n"
                    "completed_utc=2026-08-23T12:00:00Z\n",
                    encoding="ascii",
                )
                status.chmod(0o600)
                return subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-",
                        str(status),
                        "1024",
                        "campaign",
                        "",
                        nonce,
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
            self.assertIn(b"differs from this campaign request", rejected.stderr)

    def test_cidfile_cleanup_is_fail_closed(self) -> None:
        self.assertIn('[[ ! -e "$cidfile" && ! -L "$cidfile" ]]', self.operator)
        self.assertIn('podman_run_args+=(--cidfile "$cidfile")', self.operator)
        self.assertIn('cleanup_container', self.operator)
        self.assertIn("container inspect", self.operator)
        self.assertIn('[[ "$bound_container_name" == "$container_name" ]]', self.operator)
        self.assertIn('rm --force --ignore -- "$container_id"', self.operator)
        self.assertIn('trap publish_terminal_status EXIT', self.operator)
        self.assertIn("trap 'terminate_with_signal_status 1' HUP", self.operator)
        self.assertIn("trap 'terminate_with_signal_status 2' INT", self.operator)
        self.assertIn("trap 'terminate_with_signal_status 15' TERM", self.operator)
        self.assertIn('exit "$((128 + signal_number))"', self.operator)
        self.assertRegex(self.operator, r"if ! cleanup_container; then\n\s+exit_code=1")

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
            'readonly STATUS_PATH="/var/lib/codeskeptic-p10-09/status/'
            'terminal-status"',
            guided,
        )
        self.assertIn('readonly MAX_STATUS_BYTES=1024', guided)
        self.assertIn("CODESKEPTIC_GUIDED_INPUT_REQUIRED", guided)
        self.assertIn("CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE", guided)
        self.assertIn('/usr/bin/printf \'\\a\\a\\a\'', guided)
        self.assertIn(
            'exec /usr/bin/sudo -- "$GUIDED_PATH" --root', guided
        )
        self.assertIn(
            '"$SYSTEMCTL" start --wait "$SERVICE_UNIT"', guided
        )
        self.assertIn('read_bounded_terminal_status() {', guided)
        self.assertIn("MAX_STATUS_BYTES", guided)
        self.assertIn("CODESKEPTIC_GUIDED_TERMINAL_STATUS", guided)
        self.assertIn('"$SYSTEMCTL" reset-failed "$SERVICE_UNIT"', guided)
        self.assertNotIn("systemctl isolate", guided)
        self.assertNotIn("systemctl reboot", guided)
        self.assertNotIn("systemctl poweroff", guided)
        self.assertNotIn("--no-block", guided)
        self.assertIn(
            "/opt/codeskeptic-p10-09/operator/guided-stability.sh",
            self.readme,
        )
        self.assertIn("one command", self.readme.lower())
        self.assertIn("never reboots", self.readme.lower())
        self.assertIn("never isolates", self.readme.lower())

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
