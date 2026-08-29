#!/usr/bin/env python3
"""Fail-closed contracts for the P10-09 staging producer and installer."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "scripts" / "stage_stability_campaign.py"
GUIDED = ROOT / "scripts" / "stability-systemd" / "guided-stability.sh"
AUTHORITATIVE = (
    ROOT
    / "scripts"
    / "stability-systemd"
    / "run-authoritative-stability.sh"
)
CGROUP_AUTHORITY = (
    ROOT
    / "scripts"
    / "stability-systemd"
    / "cgroup-authority.py"
)
HOST_RECOVERY = (
    ROOT
    / "scripts"
    / "stability-systemd"
    / "host-recovery.py"
)
POST_STOP = (
    ROOT
    / "scripts"
    / "stability-systemd"
    / "post-stop.sh"
)
UNIT = (
    ROOT
    / "scripts"
    / "stability-systemd"
    / "codeskeptic-stability.service"
)
TIMEOUT_OVERRIDE = UNIT.parent / "10-timeout-abort.conf"

BUNDLE_FIELDS = frozenset(
    {
        "schema",
        "revision",
        "source_tree_sha1",
        "source_manifest_sha256",
        "inventory_sha256",
        "runtime_config_sha256",
        "image_archive_sha256",
        "image_reference",
        "image_digest",
        "image_id",
    }
)
INSTALLATION_FIELDS = frozenset(
    {
        "schema",
        "bundle_revision",
        "bundle_receipt_sha256",
        "bundle_inventory_sha256",
        "installed_inventory_sha256",
        "authority_root",
        "operator_root",
        "config_path",
        "unit_path",
        "image",
    }
)
DIRECTORY_INVENTORY_FIELDS = frozenset({"path", "type", "mode"})
FILE_INVENTORY_FIELDS = frozenset(
    {"path", "type", "mode", "size", "sha256"}
)
PINNED_IMAGE_DIGEST = (
    "sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
)
PINNED_IMAGE_REFERENCE = (
    "localhost/codeskeptic-p10-07-evidence@" + PINNED_IMAGE_DIGEST
)
PINNED_IMAGE_ID = (
    "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"
)


def load_producer():
    specification = importlib.util.spec_from_file_location(
        "stability_staging_producer", PRODUCER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import staging producer: {PRODUCER}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


stage = load_producer() if PRODUCER.is_file() else None


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c", "maintenance.auto=false",
            "-c", "maintenance.autoDetach=false",
            "-c", "gc.auto=0",
            "-c", "gc.autoDetach=false",
            "-C", str(repository),
            *arguments,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "CodeSkeptic staging fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "CodeSkeptic staging fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"git failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"{completed.stderr}"
        )
    return completed.stdout.strip()


def initialize_source(repository: Path) -> str:
    return initialize_lifecycle_source(repository)


def make_inventory_tree(root: Path) -> None:
    root.mkdir()
    (root / "nested").mkdir()
    (root / "alpha.txt").write_bytes(b"alpha\n")
    (root / "nested" / "bravo.bin").write_bytes(b"\x00\x01\x02")
    root.chmod(0o755)
    (root / "nested").chmod(0o750)
    (root / "alpha.txt").chmod(0o644)
    (root / "nested" / "bravo.bin").chmod(0o600)


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        try:
            path.chmod(0o700 if path.is_dir() else 0o600)
        except FileNotFoundError:
            pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_payload(path: Path, payload: bytes, mode: int = 0o600) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)
    return hashlib.sha256(payload).hexdigest()


def fixture_baseline_authority_verifier(
    source: Path,
    manifest_path: Path,
    baseline_path: Path,
    hardware_class: str,
) -> dict:
    if manifest_path != source / "scripts/determinism_workloads.json":
        raise AssertionError("fixture determinism manifest path drift")
    if baseline_path != source / "scripts/determinism_baseline.json":
        raise AssertionError("fixture determinism baseline path drift")
    projection = {
        "schema": "codeskeptic-determinism-baseline-authority-v1",
        "hardware_class": hardware_class,
        "manifest_sha256": sha256_file(manifest_path),
        "baseline_sha256": sha256_file(baseline_path),
        "fixture": "trusted-current-producer-verifier",
    }
    return {
        "projection": projection,
        "projection_sha256": hashlib.sha256(
            stage.canonical_json(projection)
        ).hexdigest(),
    }


def configure_fixture(
    staging: Path, revision: str, *, repository: str,
) -> dict:
    assert stage is not None
    return stage.configure_staging(
        staging,
        revision,
        repository=repository,
        baseline_authority_verifier=fixture_baseline_authority_verifier,
    )


def initialize_lifecycle_source(
    repository: Path, *, execution_marker: Path | None = None,
) -> str:
    """Create the smallest standalone source accepted by prepare/seal."""

    repository.mkdir()
    git(repository, "init", "--quiet", "--initial-branch=main")
    scripts = repository / "scripts"
    systemd = scripts / "stability-systemd"
    systemd.mkdir(parents=True)
    for relative in (
        "CMakeLists.txt", ".gitattributes", "Dockerfile", "action.yml",
    ):
        (repository / relative).write_text(
            f"fixture {relative}\n", encoding="utf-8"
        )
    for relative in (
        ".github/workflows", "src", "fuzz", "tests", "docs", "profiles",
        "third_party",
    ):
        directory = repository / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "fixture.txt").write_text(
            f"fixture {relative}\n", encoding="utf-8"
        )
    (repository / ".gitignore").write_text("/build/\n", encoding="utf-8")
    shutil.copyfile(PRODUCER, scripts / PRODUCER.name)
    (scripts / PRODUCER.name).chmod(0o755)
    staged_runner = scripts / "run_stability_campaign.py"
    if execution_marker is None:
        staged_runner.write_text(
            "raise RuntimeError('staged Python must not execute on the host')\n",
            encoding="utf-8",
        )
    else:
        staged_runner.write_text(
            "from pathlib import Path\n"
            f"Path({os.fspath(execution_marker)!r}).write_text('executed\\n')\n"
            "raise RuntimeError('staged Python executed on the host')\n",
            encoding="utf-8",
        )
    (scripts / "stability_manifest.json").write_text(
        '{"schema":"codeskeptic-staging-fixture-policy-v1"}\n',
        encoding="ascii",
    )
    (scripts / "determinism_workloads.json").write_text(
        '{"fixture":"determinism-manifest"}\n', encoding="ascii"
    )
    (scripts / "determinism_baseline.json").write_text(
        '{"fixture":"determinism-baseline"}\n', encoding="ascii"
    )
    (systemd / "README.md").write_text("fixture operator\n", encoding="utf-8")
    (systemd / "guided-stability.sh").write_text(
        "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
    )
    (systemd / "run-authoritative-stability.sh").write_text(
        "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
    )
    (systemd / "cgroup-authority.py").write_text(
        "#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8"
    )
    (systemd / "container-entry.py").write_text(
        "#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8"
    )
    (systemd / "containers.conf").write_text(
        '[containers]\ncgroupns = "host"\n', encoding="utf-8"
    )
    (systemd / "host-recovery.py").write_text(
        "#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8"
    )
    (systemd / "post-stop.sh").write_text(
        "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
    )
    (systemd / UNIT.name).write_text(
        "[Unit]\n"
        "Description=fixture\n"
        "Before=shutdown.target rescue.target emergency.target\n"
        "Conflicts=shutdown.target rescue.target emergency.target\n"
        "IgnoreOnIsolate=yes\n\n"
        "[Service]\n"
        "Type=exec\n"
        "ExecStartPre=/opt/codeskeptic-p10-09/operator/"
        "post-stop.sh --startup-recovery\n"
        "ExecStart=/usr/bin/systemd-inhibit --what=sleep "
        "--who=CodeSkeptic-P10-09 "
        "--why=authoritative-scope-bound-stability-evidence-session "
        "--mode=block --no-ask-password "
        "/usr/bin/prlimit --nofile=4096:4096 -- "
        "/opt/codeskeptic-p10-09/operator/run-authoritative-stability.sh\n"
        "ExecStopPost=/opt/codeskeptic-p10-09/operator/post-stop.sh\n"
        "KillMode=control-group\n"
        "TimeoutStopSec=2min\n"
        "Delegate=cpu cpuset memory pids\n"
        "DelegateSubgroup=controller\n"
        "StateDirectory=codeskeptic-p10-09\n"
        "ProtectControlGroups=no\n",
        encoding="utf-8",
    )
    shutil.copyfile(TIMEOUT_OVERRIDE, systemd / TIMEOUT_OVERRIDE.name)
    for executable in (
        "guided-stability.sh", "run-authoritative-stability.sh",
        "cgroup-authority.py", "container-entry.py", "host-recovery.py",
        "post-stop.sh",
    ):
        (systemd / executable).chmod(0o755)
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "staging fixture")
    revision = git(repository, "rev-parse", "HEAD")
    git(repository, "checkout", "--quiet", "--detach", revision)
    return revision


def populate_prepared_authorities(
    prepared: Path,
    revision: str,
    *,
    mirror_authority_sealer=None,
) -> None:
    authority = prepared / "authority"
    blobs: dict[str, bytes] = {
        "build/src/codeskeptic": b"fixture analyzer\n",
        "build-authority/receipt.json": b'{"accepted":true}\n',
        "prerequisites/hosted/receipt.json": b'{"gate":"hosted"}\n',
        "prerequisites/quality/receipt.json": b'{"gate":"quality"}\n',
        "release/receipt.json": b'{"project":"llama-cpp"}\n',
        "sanitizers/address/receipt.json": b'{"profile":"address"}\n',
        "sanitizers/undefined/receipt.json": b'{"profile":"undefined"}\n',
        (
            "source/build/p10-09-sanitizers/undefined-tests/"
            "tests/codeskeptic_tests"
        ): b"fixture tests\n",
    }
    for relative, payload in blobs.items():
        write_payload(authority / relative, payload)
    mirror_root = authority / "mirrors"
    if mirror_root.exists() or mirror_root.is_symlink():
        raise AssertionError("mirror sealer target must be create-new")
    if mirror_authority_sealer is None:
        mirror_root.mkdir()
        write_payload(
            mirror_root / "authority.json", b'{"projects":[]}\n'
        )
    else:
        mirror_authority_sealer(mirror_root)
    mirror_authority = mirror_root / "authority.json"
    if not mirror_authority.is_file() or mirror_authority.is_symlink():
        raise AssertionError("mirror sealer did not publish authority.json")
    for relative in (
        "release/source",
        "release/build",
        "source/build/p10-09-sanitizers/address-tests",
        "source/build/p10-09-sanitizers/address-fuzz",
        "source/build/p10-09-sanitizers/undefined-fuzz",
    ):
        (authority / relative).mkdir(parents=True, exist_ok=True)

    assert stage is not None
    configure_fixture(
        prepared,
        revision,
        repository="codeskeptic/staging-fixture",
    )


def make_manual_prepared_tree(
    workspace: Path,
    *,
    execution_marker: Path | None = None,
    mirror_authority_sealer=None,
) -> tuple[Path, str]:
    assert stage is not None
    source = workspace / "fixture-source"
    revision = initialize_lifecycle_source(
        source, execution_marker=execution_marker
    )
    stage.validate_staged_source(source, revision)
    prepared = workspace / "prepared"
    for relative in ("authority", "image", "operator", "unit"):
        (prepared / relative).mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, prepared / "authority" / "source")
    for relative in ("build", "build-authority", "prerequisites"):
        (prepared / "authority" / relative).mkdir(parents=True, exist_ok=True)

    systemd = source / "scripts" / "stability-systemd"
    operator_files = {
        "README.md": systemd / "README.md",
        "cgroup-authority.py": systemd / "cgroup-authority.py",
        "container-entry.py": systemd / "container-entry.py",
        "containers.conf": systemd / "containers.conf",
        "host-recovery.py": systemd / "host-recovery.py",
        "guided-stability.sh": systemd / "guided-stability.sh",
        "post-stop.sh": systemd / "post-stop.sh",
        "run-authoritative-stability.sh": (
            systemd / "run-authoritative-stability.sh"
        ),
        UNIT.name: systemd / UNIT.name,
        TIMEOUT_OVERRIDE.name: systemd / TIMEOUT_OVERRIDE.name,
        PRODUCER.name: source / "scripts" / PRODUCER.name,
    }
    for name, source_path in operator_files.items():
        shutil.copyfile(source_path, prepared / "operator" / name)
        (prepared / "operator" / name).chmod(
            0o500 if name.endswith((".sh", ".py")) else 0o400
        )
    shutil.copyfile(systemd / UNIT.name, prepared / "unit" / UNIT.name)
    (prepared / "unit" / UNIT.name).chmod(0o400)
    retained_dropin_directory = prepared / "unit" / f"{UNIT.name}.d"
    retained_dropin_directory.mkdir(mode=0o700)
    shutil.copyfile(
        systemd / TIMEOUT_OVERRIDE.name,
        retained_dropin_directory / TIMEOUT_OVERRIDE.name,
    )
    (retained_dropin_directory / TIMEOUT_OVERRIDE.name).chmod(0o400)
    write_payload(
        prepared / "image" / stage.PINNED_ARCHIVE_NAME,
        b"fixture OCI archive\n",
        0o400,
    )
    populate_prepared_authorities(
        prepared,
        revision,
        mirror_authority_sealer=mirror_authority_sealer,
    )
    return prepared, revision


@contextlib.contextmanager
def sealed_bundle_fixture():
    assert stage is not None
    temporary = tempfile.TemporaryDirectory()
    workspace = Path(temporary.name)
    try:
        prepared, revision = make_manual_prepared_tree(workspace)
        sealed = workspace / "sealed"
        receipt = stage.seal_staging(
            prepared, revision, sealed,
            command_runner=FakeCommandRunner(),
        )
        yield workspace, prepared, revision, sealed, receipt
    finally:
        make_writable(workspace)
        temporary.cleanup()


@contextlib.contextmanager
def patched_install_layout(workspace: Path):
    assert stage is not None
    for parent in (
        workspace / "opt",
        workspace / "etc",
        workspace / "etc/systemd/system",
        workspace / "var/lib",
        workspace / "run",
    ):
        parent.mkdir(parents=True, exist_ok=True)
    values = {
        "AUTHORITY_ROOT": workspace / "opt/codeskeptic-p10-09/authority",
        "OPERATOR_ROOT": workspace / "opt/codeskeptic-p10-09/operator",
        "CONFIG_PATH": workspace / "etc/codeskeptic-p10-09/runtime.json",
        "UNIT_PATH": (
            workspace / "etc/systemd/system/codeskeptic-stability.service"
        ),
        "UNIT_DROPIN_DIRECTORY": (
            workspace
            / "etc/systemd/system/codeskeptic-stability.service.d"
        ),
        "UNIT_DROPIN_PATH": (
            workspace
            / "etc/systemd/system/codeskeptic-stability.service.d"
            / TIMEOUT_OVERRIDE.name
        ),
        "INSTALLATION_ROOT": workspace / "opt/codeskeptic-p10-09/installation",
        "INSTALLATION_RECEIPT_PATH": (
            workspace
            / "opt/codeskeptic-p10-09/installation/receipt.json"
        ),
        "STATE_ROOT": workspace / "var/lib/codeskeptic-p10-09",
        "INSTALLATION_AUTHORITY_PATH": (
            workspace
            / "var/lib/codeskeptic-p10-09/installation-authority.json"
        ),
        "PODMAN_ROOT": workspace / "var/lib/codeskeptic-p10-09/podman-root",
        "PODMAN_RUNROOT": workspace / "run/codeskeptic-p10-09/podman-runroot",
    }
    with contextlib.ExitStack() as stack:
        for name, value in values.items():
            stack.enter_context(mock.patch.object(stage, name, value))
        if hasattr(stage, "CONFIG_SHA_PATH"):
            stack.enter_context(
                mock.patch.object(
                    stage,
                    "CONFIG_SHA_PATH",
                    Path(f"{values['CONFIG_PATH']}.sha256"),
                )
            )
        yield values


class FakeCommandRunner:
    def __init__(self, *, image_id: str = PINNED_IMAGE_ID) -> None:
        self.commands: list[list[str]] = []
        self.loaded = False
        self.image_id = image_id

    def __call__(self, argv: list[str], **_kwargs) -> bytes:
        assert stage is not None
        command = [os.fspath(item) for item in argv]
        self.commands.append(command)
        if "load" in command:
            self.loaded = True
            return b""
        if "inspect" in command and "image" in command:
            if not self.loaded:
                raise stage.StagingError("fixture image is not loaded")
            if "--format" in command:
                return f"{self.image_id}|{PINNED_IMAGE_DIGEST}\n".encode(
                    "ascii"
                )
            return stage.canonical_document(
                [
                    {
                        "Digest": PINNED_IMAGE_DIGEST,
                        "Id": self.image_id,
                        "RepoDigests": [PINNED_IMAGE_REFERENCE],
                    }
                ]
            )
        if "list" in command and "image" in command:
            if not self.loaded:
                raise stage.StagingError("fixture image is not loaded")
            return f"{self.image_id}\n".encode("ascii")
        if "--pull=never" in command:
            if not self.loaded:
                raise stage.StagingError("fixture image is not loaded")
            joined = " ".join(command)
            if "CODESKEPTIC_STAGING_IMAGE_PROBE_OK" in joined:
                return stage.IMAGE_PROBE_MARKER
            if "CODESKEPTIC_STAGING_STATIC_AUTHORITIES_OK" in joined:
                return stage.STATIC_AUTHORITY_MARKER
            return b""
        if "show" in command:
            return b"static\n"
        return b""


def option_value(command: list[str], option: str) -> str | None:
    for index, token in enumerate(command):
        if token == option and index + 1 < len(command):
            return command[index + 1]
        if token.startswith(option + "="):
            return token.split("=", 1)[1]
    return None


def bundle_authority(bundle: Path) -> dict[str, str]:
    receipt_path = bundle / "bundle" / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    return {
        "expected_revision": receipt["revision"],
        "expected_bundle_receipt_sha256": sha256_file(receipt_path),
    }


def bundle_receipt() -> dict[str, object]:
    return {
        "schema": "codeskeptic-stability-staging-bundle-v1",
        "revision": "1" * 40,
        "source_tree_sha1": "2" * 40,
        "source_manifest_sha256": "3" * 64,
        "inventory_sha256": "4" * 64,
        "runtime_config_sha256": "5" * 64,
        "image_archive_sha256": "6" * 64,
        "image_reference": PINNED_IMAGE_REFERENCE,
        "image_digest": PINNED_IMAGE_DIGEST,
        "image_id": PINNED_IMAGE_ID,
    }


def installation_receipt() -> dict[str, object]:
    return {
        "schema": "codeskeptic-stability-installation-v1",
        "bundle_revision": "0" * 40,
        "bundle_receipt_sha256": "1" * 64,
        "bundle_inventory_sha256": "2" * 64,
        "installed_inventory_sha256": "2" * 64,
        "authority_root": "/opt/codeskeptic-p10-09/authority",
        "operator_root": "/opt/codeskeptic-p10-09/operator",
        "config_path": "/etc/codeskeptic-p10-09/runtime.json",
        "unit_path": "/etc/systemd/system/codeskeptic-stability.service",
        "image": {
            "reference": PINNED_IMAGE_REFERENCE,
            "digest": PINNED_IMAGE_DIGEST,
            "id": PINNED_IMAGE_ID,
            "archive_sha256": "5" * 64,
        },
    }


class StabilityStagingProducerPresenceTest(unittest.TestCase):
    def test_canonical_staging_producer_exists(self) -> None:
        self.assertTrue(
            PRODUCER.is_file(),
            "missing canonical P10-09 producer scripts/stage_stability_campaign.py",
        )


@unittest.skipUnless(PRODUCER.is_file(), "staging producer is the RED gap")
class StabilityStagingProducerTest(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "Linux child-subreaper contract unavailable",
    )
    def test_fixture_git_never_leaves_detached_maintenance_children(self) -> None:
        code = r"""
import ctypes
import importlib.util
import os
import pathlib
import sys
import tempfile
import time

if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise SystemExit(125)
specification = importlib.util.spec_from_file_location("staging_fixture", sys.argv[1])
if specification is None or specification.loader is None:
    raise SystemExit(126)
fixture = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = fixture
specification.loader.exec_module(fixture)
with tempfile.TemporaryDirectory() as directory:
    fixture.initialize_lifecycle_source(pathlib.Path(directory) / "source")
deadline = time.monotonic() + 2.0
while True:
    try:
        pid, _status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        print("CODESKEPTIC_FIXTURE_GIT_CHILDREN_CLEAN")
        raise SystemExit(0)
    if pid != 0:
        print(f"unexpected adopted Git child: {pid}", file=sys.stderr)
        raise SystemExit(1)
    if time.monotonic() >= deadline:
        print("adopted Git child did not exit", file=sys.stderr)
        raise SystemExit(1)
    time.sleep(0.02)
"""
        completed = subprocess.run(
            [sys.executable, "-c", code, os.fspath(Path(__file__).resolve())],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            completed.stdout,
            "CODESKEPTIC_FIXTURE_GIT_CHILDREN_CLEAN\n",
        )

    def test_trusted_sibling_loader_pins_one_inode_and_rejects_aliases(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_stage = root / "stage_stability_campaign.py"
            fake_stage.write_text("# loader anchor\n", encoding="ascii")
            victim = root / "victim.py"
            victim.write_text("VALUE = 'original'\n", encoding="ascii")
            victim.chmod(0o600)
            with mock.patch.object(stage, "__file__", os.fspath(fake_stage)):
                loaded = stage._load_trusted_sibling_module(
                    "private_victim", "victim.py"
                )
            self.assertEqual(loaded.VALUE, "original")

            if hasattr(os, "link"):
                hardlink = root / "hardlink.py"
                os.link(victim, hardlink)
                with (
                    mock.patch.object(stage, "__file__", os.fspath(fake_stage)),
                    self.assertRaisesRegex(
                        stage.StagingError, "bounded standalone"
                    ),
                ):
                    stage._load_trusted_sibling_module(
                        "private_hardlink", "hardlink.py"
                    )
                hardlink.unlink()

            symlink = root / "symlink.py"
            try:
                symlink.symlink_to(victim.name)
            except (OSError, NotImplementedError):
                pass
            else:
                with (
                    mock.patch.object(stage, "__file__", os.fspath(fake_stage)),
                    self.assertRaisesRegex(stage.StagingError, "unavailable"),
                ):
                    stage._load_trusted_sibling_module(
                        "private_symlink", "symlink.py"
                    )

            replacement = root / "replacement.py"
            replacement.write_text("VALUE = 'swapped'\n", encoding="ascii")
            real_read = os.read
            swapped = False

            def swap_after_read(descriptor: int, count: int) -> bytes:
                nonlocal swapped
                data = real_read(descriptor, count)
                if not swapped:
                    swapped = True
                    os.replace(replacement, victim)
                return data

            with (
                mock.patch.object(stage, "__file__", os.fspath(fake_stage)),
                mock.patch.object(stage.os, "read", side_effect=swap_after_read),
                self.assertRaisesRegex(stage.StagingError, "changed while loading"),
            ):
                stage._load_trusted_sibling_module(
                    "private_swapped", "victim.py"
                )
            self.assertTrue(swapped)

    def test_trusted_baseline_loader_ignores_preloaded_dependency_poison(
        self,
    ) -> None:
        assert stage is not None
        poisoned_realworld = types.ModuleType("run_realworld_campaign")
        poisoned_fault = types.ModuleType("run_stability_fault_injection")
        poisoned_realworld.__file__ = os.fspath(
            ROOT / "scripts/run_realworld_campaign.py"
        )
        poisoned_fault.__file__ = os.fspath(
            ROOT / "scripts/run_stability_fault_injection.py"
        )
        with mock.patch.dict(
            sys.modules,
            {
                "run_realworld_campaign": poisoned_realworld,
                "run_stability_fault_injection": poisoned_fault,
            },
        ):
            wrapped = stage._trusted_baseline_authority_verifier()
            closure = dict(zip(
                wrapped.__code__.co_freevars,
                (cell.cell_contents for cell in wrapped.__closure__ or ()),
            ))
            raw = closure["verifier"]
            self.assertIsNot(raw.__globals__["realworld"], poisoned_realworld)
            self.assertIsNot(
                raw.__globals__["fault_injection"], poisoned_fault
            )
            self.assertEqual(
                Path(raw.__globals__["realworld"].__file__).resolve(),
                (ROOT / "scripts/run_realworld_campaign.py").resolve(),
            )
            self.assertEqual(
                Path(raw.__globals__["fault_injection"].__file__).resolve(),
                (ROOT / "scripts/run_stability_fault_injection.py").resolve(),
            )

    def test_trusted_baseline_verifier_keeps_exact_sibling_imports_available(
        self,
    ) -> None:
        assert stage is not None
        scripts = os.fspath(ROOT / "scripts")
        original_path = list(sys.path)
        previous = sys.modules.pop("run_determinism_qualification", None)
        sys.path[:] = [entry for entry in sys.path if entry != scripts]
        try:
            verifier = stage._trusted_baseline_authority_verifier()
            with self.assertRaisesRegex(
                Exception, "determinism baseline hardware class is absent"
            ):
                verifier(
                    ROOT,
                    ROOT / "scripts/determinism_workloads.json",
                    ROOT / "scripts/determinism_baseline.json",
                    "deliberately-absent-staging-test-profile",
                )
            self.assertNotIn(scripts, sys.path)
        finally:
            sys.modules.pop("run_determinism_qualification", None)
            if previous is not None:
                sys.modules["run_determinism_qualification"] = previous
            sys.path[:] = original_path

    def test_cli_is_versioned_and_exposes_the_complete_lifecycle(self) -> None:
        assert stage is not None
        self.assertEqual(stage.TOOL_VERSION, "6")
        parser = stage.build_parser()
        subparser_actions = [
            action
            for action in parser._actions
            if hasattr(action, "choices") and isinstance(action.choices, dict)
        ]
        self.assertEqual(len(subparser_actions), 1)
        self.assertEqual(
            set(subparser_actions[0].choices),
            {
                "prepare", "configure", "seal", "verify", "install",
                "migrate-install", "recover-install-migration",
                "verify-install",
                "verify-install-filesystem",
            },
        )
        for command in ("seal", "verify", "install", "migrate-install"):
            command_parser = subparser_actions[0].choices[command]
            temporary_actions = [
                action
                for action in command_parser._actions
                if "--temporary-root" in action.option_strings
            ]
            self.assertEqual(len(temporary_actions), 1)
            self.assertTrue(temporary_actions[0].required)

        version = subprocess.run(
            [sys.executable, str(PRODUCER), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stderr, "")
        self.assertEqual(version.stdout, "CodeSkeptic P10-09 staging producer 6\n")

    def test_cli_dispatches_every_lifecycle_command(self) -> None:
        assert stage is not None
        cases = (
            (
                [
                    "prepare",
                    "--source", "/fixture/source",
                    "--revision", "1" * 40,
                    "--image-archive", "/fixture/image.oci.tar",
                    "--output", "/fixture/prepared",
                ],
                "prepare_staging",
            ),
            (
                [
                    "configure",
                    "--staging", "/fixture/prepared",
                    "--revision", "1" * 40,
                    "--repository", "codeskeptic/staging-fixture",
                ],
                "configure_staging",
            ),
            (
                [
                    "seal",
                    "--staging", "/fixture/prepared",
                    "--revision", "1" * 40,
                    "--output", "/fixture/sealed",
                    "--temporary-root", "/fixture/disk-temporary",
                ],
                "seal_staging",
            ),
            (
                [
                    "verify", "--bundle", "/fixture/sealed",
                    "--expected-revision", "1" * 40,
                    "--expected-bundle-receipt-sha256", "2" * 64,
                    "--temporary-root", "/fixture/disk-temporary",
                ],
                "verify_bundle",
            ),
            (
                [
                    "install", "--bundle", "/fixture/sealed",
                    "--expected-revision", "1" * 40,
                    "--expected-bundle-receipt-sha256", "2" * 64,
                    "--temporary-root", "/fixture/disk-temporary",
                ],
                "install_bundle",
            ),
            (
                [
                    "verify-install",
                    "--receipt", "/fixture/installation/receipt.json",
                    "--expected-revision", "1" * 40,
                    "--expected-bundle-receipt-sha256", "2" * 64,
                ],
                "verify_installation",
            ),
            (
                [
                    "verify-install-filesystem",
                    "--receipt", "/fixture/installation/receipt.json",
                    "--expected-revision", "1" * 40,
                    "--expected-bundle-receipt-sha256", "2" * 64,
                ],
                "verify_installation_filesystem",
            ),
        )
        lifecycle = (
            "prepare_staging", "configure_staging",
            "seal_staging",
            "verify_bundle",
            "install_bundle",
            "verify_installation",
            "verify_installation_filesystem",
        )
        for arguments, expected in cases:
            with self.subTest(command=arguments[0]), contextlib.ExitStack() as stack:
                calls = {
                    name: stack.enter_context(
                        mock.patch.object(stage, name, create=True)
                    )
                    for name in lifecycle
                }
                self.assertEqual(stage.main(arguments), 0)
                calls[expected].assert_called_once()
                for name, function in calls.items():
                    if name != expected:
                        function.assert_not_called()

    def test_configure_and_seal_reject_unresolved_authority_lifecycle(
        self,
    ) -> None:
        assert stage is not None
        token = "a" * 32
        reserved_paths = [
            (Path(name), "file")
            for name in sorted(stage.AUTHORITY_OPERATION_MARKERS)
        ]
        journal_token = "b" * 64
        for journal in ("operation", "transaction"):
            staging_name = (
                f".p10-09-authority-{journal}.json."
                f"{journal_token}.staging"
            )
            reserved_paths.extend((
                (Path(staging_name), "file"),
                (Path(staging_name + ".cleanup"), "file"),
                (
                    Path(
                        f".p10-09-authority-{journal}.json."
                        "malformed.staging"
                    ),
                    "file",
                ),
            ))
        for base in (
            Path(f".sanitizers.{token}"),
            Path(f".release.{token}"),
            Path("source/build") / f".p10-09-sanitizers.{token}",
        ):
            reserved_paths.extend(
                (base.with_name(base.name + suffix), kind)
                for suffix, kind in (
                    ("", "directory"),
                    (".cleanup", "directory"),
                    (".owner.json", "file"),
                    (".owner.json.cleanup", "file"),
                    (".rollback", "directory"),
                )
            )

        for lifecycle, worker_name in (
            ("configure", "_configure_staging_unlocked"),
            ("seal", "_seal_staging_unlocked"),
        ):
            for relative, kind in reserved_paths:
                with (
                    self.subTest(lifecycle=lifecycle, reserved=relative),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    workspace = Path(temporary)
                    staging = workspace / "prepared"
                    authority = staging / "authority"
                    authority.mkdir(parents=True)
                    reserved = authority / relative
                    reserved.parent.mkdir(parents=True, exist_ok=True)
                    if kind == "directory":
                        reserved.mkdir()
                    else:
                        reserved.write_bytes(b"unresolved fixture state\n")
                    output = workspace / "sealed"

                    with (
                        mock.patch.object(
                            stage, worker_name, create=True
                        ) as worker,
                        self.assertRaisesRegex(
                            stage.StagingError,
                            "unresolved authority provisioning lifecycle",
                        ),
                    ):
                        if lifecycle == "configure":
                            stage.configure_staging(
                                staging,
                                "1" * 40,
                                repository="codeskeptic/staging-fixture",
                            )
                        else:
                            stage.seal_staging(
                                staging,
                                "1" * 40,
                                output,
                            )

                    worker.assert_not_called()
                    self.assertTrue(
                        reserved.is_dir()
                        if kind == "directory"
                        else reserved.is_file()
                    )
                    self.assertFalse(output.exists())

    def test_configure_and_seal_fail_closed_on_lifecycle_lock_contention(
        self,
    ) -> None:
        assert stage is not None
        for lifecycle, worker_name in (
            ("configure", "_configure_staging_unlocked"),
            ("seal", "_seal_staging_unlocked"),
        ):
            with (
                self.subTest(lifecycle=lifecycle),
                tempfile.TemporaryDirectory() as temporary,
            ):
                workspace = Path(temporary)
                staging = workspace / "prepared"
                (staging / "authority").mkdir(parents=True)
                output = workspace / "sealed"

                with stage._authority_lifecycle_lock(staging):
                    with (
                        mock.patch.object(
                            stage, worker_name, create=True
                        ) as worker,
                        self.assertRaisesRegex(
                            stage.StagingError,
                            "authority provisioning is still active",
                        ),
                    ):
                        if lifecycle == "configure":
                            stage.configure_staging(
                                staging,
                                "1" * 40,
                                repository="codeskeptic/staging-fixture",
                            )
                        else:
                            stage.seal_staging(
                                staging,
                                "1" * 40,
                                output,
                            )

                worker.assert_not_called()
                self.assertFalse(output.exists())

    def test_lifecycle_lock_pins_root_and_parent_before_lock_creation(
        self,
    ) -> None:
        assert stage is not None
        real_open = os.open
        for target in ("root", "parent"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                workspace = Path(temporary)
                parent = workspace / "authority-workspace"
                staging = parent / "prepared"
                staging.mkdir(parents=True)
                original: Path | None = None
                replaced = False

                def replace_before_parent_open(
                    path,
                    flags,
                    mode=0o777,
                    *,
                    dir_fd=None,
                ):
                    nonlocal original, replaced
                    if (
                        not replaced
                        and dir_fd is None
                        and Path(path) == parent
                    ):
                        replaced = True
                        if target == "root":
                            original = parent / "prepared-original"
                            staging.rename(original)
                            staging.mkdir()
                        else:
                            original = workspace / "authority-workspace-original"
                            parent.rename(original)
                            parent.mkdir()
                            staging.mkdir()
                    if dir_fd is None:
                        return real_open(path, flags, mode)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with (
                    mock.patch.object(
                        stage.os,
                        "open",
                        side_effect=replace_before_parent_open,
                    ),
                    self.assertRaisesRegex(
                        stage.StagingError,
                        f"authority lifecycle {target} identity drift",
                    ),
                ):
                    with stage._authority_lifecycle_lock(staging):
                        self.fail("replacement reached the protected lifecycle")

                self.assertTrue(replaced)
                assert original is not None
                self.assertTrue(original.is_dir())
                self.assertTrue(staging.is_dir())

    def test_lifecycle_lock_revalidates_root_and_parent_after_flock(
        self,
    ) -> None:
        assert stage is not None
        real_flock = stage.fcntl.flock
        exclusive = stage.fcntl.LOCK_EX | stage.fcntl.LOCK_NB
        for target in ("root", "parent"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                workspace = Path(temporary)
                parent = workspace / "authority-workspace"
                staging = parent / "prepared"
                staging.mkdir(parents=True)
                original: Path | None = None
                replaced = False

                def replace_after_flock(descriptor: int, operation: int):
                    nonlocal original, replaced
                    result = real_flock(descriptor, operation)
                    if not replaced and operation == exclusive:
                        replaced = True
                        if target == "root":
                            original = parent / "prepared-original"
                            staging.rename(original)
                            staging.mkdir()
                        else:
                            original = workspace / "authority-workspace-original"
                            parent.rename(original)
                            parent.mkdir()
                            staging.mkdir()
                    return result

                with (
                    mock.patch.object(
                        stage.fcntl,
                        "flock",
                        side_effect=replace_after_flock,
                    ),
                    self.assertRaisesRegex(
                        stage.StagingError,
                        f"authority lifecycle {target} identity drift",
                    ),
                ):
                    with stage._authority_lifecycle_lock(staging):
                        self.fail("replacement reached the protected lifecycle")

                self.assertTrue(replaced)
                assert original is not None
                self.assertTrue(original.is_dir())
                self.assertTrue(staging.is_dir())

    def test_lifecycle_lock_rejects_lock_file_replacement_after_flock(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            parent = workspace / "authority-workspace"
            staging = parent / "prepared"
            staging.mkdir(parents=True)
            suffix = hashlib.sha256(
                staging.absolute().as_posix().encode("utf-8")
            ).hexdigest()[:32]
            lock_path = parent / f".codeskeptic-p10-09-{suffix}.lock"
            original_lock = parent / "original-lifecycle.lock"
            real_flock = stage.fcntl.flock
            exclusive = stage.fcntl.LOCK_EX | stage.fcntl.LOCK_NB
            replaced = False

            def replace_after_flock(descriptor: int, operation: int):
                nonlocal replaced
                result = real_flock(descriptor, operation)
                if not replaced and operation == exclusive:
                    replaced = True
                    lock_path.rename(original_lock)
                    lock_path.write_bytes(b"")
                    lock_path.chmod(0o600)
                return result

            with (
                mock.patch.object(
                    stage.fcntl,
                    "flock",
                    side_effect=replace_after_flock,
                ),
                self.assertRaisesRegex(
                    stage.StagingError,
                    "authority lifecycle lock identity drift",
                ),
            ):
                with stage._authority_lifecycle_lock(staging):
                    self.fail("replacement reached the protected lifecycle")

            self.assertTrue(replaced)
            self.assertTrue(original_lock.is_file())
            self.assertTrue(lock_path.is_file())

    def test_prepare_creates_a_fresh_exact_head_layout_and_never_overwrites(self) -> None:
        assert stage is not None
        temporary = tempfile.TemporaryDirectory()
        workspace = Path(temporary.name)
        try:
            source = workspace / "source"
            revision = initialize_lifecycle_source(source)
            archive = workspace / "fixture.oci.tar"
            archive.write_bytes(b"fixture OCI archive\n")
            prepared = workspace / "prepared"
            identity = stage.prepare_staging(
                source, revision, archive, prepared
            )
            self.assertEqual(identity["revision"], revision)
            self.assertEqual(
                sorted(path.name for path in prepared.iterdir()),
                ["authority", "image", "operator", "unit"],
            )
            self.assertFalse(
                (prepared / "authority" / "mirrors").exists(),
                "real-world mirror sealer output must remain create-new",
            )
            self.assertTrue(
                (prepared / "authority" / "prerequisites").is_dir()
            )
            for relative in (
                "prerequisites/hosted",
                "prerequisites/quality",
                "release",
                "sanitizers",
                "source/build/p10-09-sanitizers",
            ):
                self.assertFalse(
                    (prepared / "authority" / relative).exists(),
                    f"producer output must remain create-new: {relative}",
                )
            staged_identity = stage.validate_staged_source(
                prepared / "authority" / "source", revision
            )
            self.assertEqual(staged_identity, {
                "revision": identity["revision"],
                "tree_sha1": identity["tree_sha1"],
                "manifest_sha256": identity["manifest_sha256"],
            })
            self.assertEqual(
                sha256_file(
                    prepared / "image" / stage.PINNED_ARCHIVE_NAME
                ),
                identity["image_archive_sha256"],
            )

            collision = workspace / "collision"
            collision.mkdir()
            marker = collision / "owner-data"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaises(stage.StagingError):
                stage.prepare_staging(
                    source, revision, archive, collision
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        finally:
            make_writable(workspace)
            temporary.cleanup()

    def test_prepare_publication_interrupt_removes_published_output(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            revision = initialize_lifecycle_source(source)
            archive = workspace / "fixture.oci.tar"
            archive.write_bytes(b"fixture OCI archive\n")
            prepared = workspace / "prepared"
            real_publish = stage._publish_tree_noreplace

            def publish_then_interrupt(source_path, destination):
                real_publish(source_path, destination)
                raise KeyboardInterrupt()

            with mock.patch.object(
                stage,
                "_publish_tree_noreplace",
                side_effect=publish_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage.prepare_staging(source, revision, archive, prepared)
            self.assertFalse(prepared.exists())
            self.assertEqual(
                list(workspace.glob(".prepared.prepare-*")),
                [],
            )

    def test_tree_publications_roll_back_on_temporary_cleanup_failure(self) -> None:
        assert stage is not None

        def cleanup_failure_context(prefix: str):
            published = False
            real_publish = stage._publish_tree_noreplace
            real_lstat = Path.lstat

            def publish(source, destination):
                nonlocal published
                result = real_publish(source, destination)
                published = True
                return result

            def fail_old_temporary_lstat(path):
                if published and path.name.startswith(prefix):
                    raise PermissionError("fixture temporary cleanup failure")
                return real_lstat(path)

            return (
                mock.patch.object(
                    stage, "_publish_tree_noreplace", side_effect=publish
                ),
                mock.patch.object(Path, "lstat", new=fail_old_temporary_lstat),
            )

        with self.subTest(lifecycle="prepare"), tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            revision = initialize_lifecycle_source(source)
            archive = workspace / "fixture.oci.tar"
            archive.write_bytes(b"fixture OCI archive\n")
            prepared = workspace / "prepared"
            publish_patch, lstat_patch = cleanup_failure_context(
                ".prepared.prepare-"
            )
            with publish_patch, lstat_patch, self.assertRaisesRegex(
                stage.StagingError, "temporary cleanup failure"
            ):
                stage.prepare_staging(source, revision, archive, prepared)
            self.assertFalse(prepared.exists())

        with self.subTest(lifecycle="configure"), tempfile.TemporaryDirectory() as temporary:
            prepared, revision = make_manual_prepared_tree(Path(temporary))
            config_root = prepared / "config"
            shutil.rmtree(config_root)
            publish_patch, lstat_patch = cleanup_failure_context(
                ".config.runtime-"
            )
            with publish_patch, lstat_patch, self.assertRaisesRegex(
                stage.StagingError, "temporary cleanup failure"
            ):
                configure_fixture(
                    prepared,
                    revision,
                    repository="codeskeptic/staging-fixture",
                )
            self.assertFalse(config_root.exists())

        with self.subTest(lifecycle="seal"), tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prepared, revision = make_manual_prepared_tree(workspace)
            sealed = workspace / "sealed"
            publish_patch, lstat_patch = cleanup_failure_context(
                ".sealed.seal-"
            )
            with publish_patch, lstat_patch, self.assertRaisesRegex(
                stage.StagingError, "temporary cleanup failure"
            ):
                stage.seal_staging(
                    prepared,
                    revision,
                    sealed,
                    command_runner=FakeCommandRunner(),
                )
            self.assertFalse(sealed.exists())

    def test_configure_materializes_canonical_receipt_bound_runtime_config(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            prepared, revision = make_manual_prepared_tree(Path(temporary))
            config_path = prepared / "config" / "runtime.json"
            sidecar_path = Path(f"{config_path}.sha256")
            data = config_path.read_bytes()
            config = json.loads(data.decode("utf-8"))

            self.assertEqual(data, stage.canonical_document(config))
            self.assertEqual(
                config["schema"], "codeskeptic-stability-runtime-v3"
            )
            self.assertEqual(config["source"]["revision"], revision)
            self.assertEqual(
                set(config["prerequisites"]),
                {"hosted_exact_head", "quality_floor"},
            )
            baseline_authority = config["qualification"][
                "baseline_authority"
            ]
            self.assertEqual(
                baseline_authority["root"], "/authority/source"
            )
            self.assertEqual(
                baseline_authority["manifest_sha256"],
                sha256_file(
                    prepared
                    / "authority/source/scripts/determinism_workloads.json"
                ),
            )
            self.assertEqual(
                baseline_authority["baseline_sha256"],
                sha256_file(
                    prepared
                    / "authority/source/scripts/determinism_baseline.json"
                ),
            )
            self.assertRegex(
                baseline_authority["projection_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                config["prerequisites"]["hosted_exact_head"]["repository"],
                "codeskeptic/staging-fixture",
            )
            self.assertEqual(
                config["build_authority"]["receipt_sha256"],
                sha256_file(
                    prepared / "authority/build-authority/receipt.json"
                ),
            )
            self.assertEqual(
                sidecar_path.read_bytes(),
                f"{hashlib.sha256(data).hexdigest()}  runtime.json\n".encode(
                    "ascii"
                ),
            )

            before = (data, sidecar_path.read_bytes())
            with self.assertRaisesRegex(stage.StagingError, "previously absent"):
                configure_fixture(
                    prepared,
                    revision,
                    repository="codeskeptic/staging-fixture",
                )
            self.assertEqual(
                (config_path.read_bytes(), sidecar_path.read_bytes()), before
            )

    def test_legacy_runtime_and_external_determinism_prerequisite_fail_closed(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            prepared, _revision = make_manual_prepared_tree(Path(temporary))
            config_path = prepared / "config/runtime.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))

            for schema in (
                "codeskeptic-stability-runtime-v1",
                "codeskeptic-stability-runtime-v2",
            ):
                with self.subTest(schema=schema):
                    old_schema = copy.deepcopy(config)
                    old_schema["schema"] = schema
                    with self.assertRaisesRegex(stage.StagingError, "schema"):
                        stage._validate_runtime_config_contract(old_schema)

            external = copy.deepcopy(config)
            external["prerequisites"]["determinism"] = {
                "root": "/authority/prerequisites/determinism",
                "receipt_sha256": "0" * 64,
            }
            with self.assertRaisesRegex(stage.StagingError, "fields"):
                stage._validate_runtime_config_contract(external)

    def test_configure_rejects_baseline_projection_digest_drift(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            prepared, revision = make_manual_prepared_tree(Path(temporary))
            shutil.rmtree(prepared / "config")

            def drifted(*args, **kwargs):
                result = fixture_baseline_authority_verifier(*args, **kwargs)
                result["projection_sha256"] = "0" * 64
                return result

            with self.assertRaisesRegex(
                stage.StagingError, "baseline authority projection"
            ):
                stage.configure_staging(
                    prepared,
                    revision,
                    repository="codeskeptic/staging-fixture",
                    baseline_authority_verifier=drifted,
                )
            self.assertFalse((prepared / "config").exists())

    def test_configure_is_atomic_and_rejects_missing_authority_inputs(self) -> None:
        assert stage is not None
        for case in (
            "missing-receipt",
            "missing-release-receipt",
            "malformed-repository-suffix",
            "malformed-repository-component",
            "sidecar-write",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                prepared, revision = make_manual_prepared_tree(Path(temporary))
                config_path = prepared / "config" / "runtime.json"
                sidecar_path = Path(f"{config_path}.sha256")
                shutil.rmtree(config_path.parent)

                if case == "missing-receipt":
                    (
                        prepared
                        / "authority/prerequisites/hosted/receipt.json"
                    ).unlink()
                    context = contextlib.nullcontext()
                    repository = "codeskeptic/staging-fixture"
                elif case == "missing-release-receipt":
                    (
                        prepared / "authority/release/receipt.json"
                    ).unlink()
                    context = contextlib.nullcontext()
                    repository = "codeskeptic/staging-fixture"
                elif case == "malformed-repository-suffix":
                    context = contextlib.nullcontext()
                    repository = "codeskeptic/invalid.git"
                elif case == "malformed-repository-component":
                    context = contextlib.nullcontext()
                    repository = "../staging-fixture"
                else:
                    original_write = stage._write_new

                    def fail_sidecar(path, data, *args, **kwargs):
                        if Path(path).name == "runtime.json.sha256":
                            raise stage.StagingError("fixture sidecar failure")
                        return original_write(path, data, *args, **kwargs)

                    context = mock.patch.object(
                        stage, "_write_new", side_effect=fail_sidecar
                    )
                    repository = "codeskeptic/staging-fixture"

                with context, self.assertRaises(stage.StagingError):
                    configure_fixture(
                        prepared,
                        revision,
                        repository=repository,
                    )
                self.assertFalse(config_path.parent.exists())

    def test_configure_interrupt_before_identity_pin_retains_child(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            prepared, revision = make_manual_prepared_tree(Path(temporary))
            config_root = prepared / "config"
            shutil.rmtree(config_root)
            original_mkdir = os.mkdir

            def interrupt_after_create(path, mode=0o777, *args, **kwargs):
                result = original_mkdir(path, mode, *args, **kwargs)
                if Path(path).name.startswith(".config.runtime-"):
                    raise KeyboardInterrupt()
                return result

            with mock.patch.object(
                stage.os, "mkdir", side_effect=interrupt_after_create
            ), self.assertRaisesRegex(
                stage.StagingError, "cleanup withheld"
            ):
                configure_fixture(
                    prepared,
                    revision,
                    repository="codeskeptic/staging-fixture",
                )
            self.assertFalse(config_root.exists())
            retained = [
                path
                for path in prepared.iterdir()
                if path.name.startswith(".config.runtime-")
            ]
            self.assertEqual(len(retained), 1)
            retained[0].rmdir()

    def test_configure_preserves_replacement_when_temporary_identity_drifts(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            prepared, revision = make_manual_prepared_tree(Path(temporary))
            config_root = prepared / "config"
            shutil.rmtree(config_root)
            moved = prepared / "producer-temporary-moved"
            marker: Path | None = None
            original_write = stage._write_new

            def swap_before_sidecar(path, data, *args, **kwargs):
                nonlocal marker
                target = Path(path)
                if target.name == "runtime.json.sha256":
                    producer_root = target.parent
                    producer_root.rename(moved)
                    producer_root.mkdir(mode=0o700)
                    marker = producer_root / "owner-data"
                    marker.write_text("preserve\n", encoding="utf-8")
                    raise stage.StagingError("fixture sidecar failure")
                return original_write(path, data, *args, **kwargs)

            with mock.patch.object(
                stage, "_write_new", side_effect=swap_before_sidecar
            ), self.assertRaisesRegex(
                stage.StagingError, "cleanup failure|identity changed"
            ):
                configure_fixture(
                    prepared,
                    revision,
                    repository="codeskeptic/staging-fixture",
                )
            assert marker is not None
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
            self.assertTrue(moved.is_dir())
            self.assertTrue((moved / "runtime.json").is_file())
            self.assertFalse(config_root.exists())

    def test_configure_rolls_back_after_publication_and_preserves_collision(self) -> None:
        assert stage is not None
        for case in (
            "post-publication", "publish-interrupt", "concurrent-collision",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                prepared, revision = make_manual_prepared_tree(Path(temporary))
                config_root = prepared / "config"
                shutil.rmtree(config_root)
                if case == "post-publication":
                    context = mock.patch.object(
                        stage,
                        "_runtime_config",
                        side_effect=stage.StagingError(
                            "fixture post-publication failure"
                        ),
                    )
                    marker = None
                    expected_exception = stage.StagingError
                elif case == "publish-interrupt":
                    real_publish = stage._publish_tree_noreplace

                    def publish_then_interrupt(source, destination):
                        real_publish(source, destination)
                        raise KeyboardInterrupt()

                    context = mock.patch.object(
                        stage,
                        "_publish_tree_noreplace",
                        side_effect=publish_then_interrupt,
                    )
                    marker = None
                    expected_exception = KeyboardInterrupt
                else:
                    def collide(source, destination):
                        destination.mkdir()
                        collision_marker = destination / "owner-data"
                        collision_marker.write_text(
                            "preserve\n", encoding="utf-8"
                        )
                        raise FileExistsError(destination)

                    context = mock.patch.object(
                        stage, "_publish_tree_noreplace", side_effect=collide
                    )
                    marker = config_root / "owner-data"
                    expected_exception = stage.StagingError

                with context, self.assertRaises(expected_exception):
                    configure_fixture(
                        prepared,
                        revision,
                        repository="codeskeptic/staging-fixture",
                    )
                if marker is None:
                    self.assertFalse(config_root.exists())
                else:
                    self.assertEqual(
                        marker.read_text(encoding="utf-8"), "preserve\n"
                    )
                self.assertEqual(
                    [
                        path.name
                        for path in prepared.iterdir()
                        if path.name.startswith(".config.runtime-")
                    ],
                    [],
                )

    def test_seal_rejects_authority_changed_after_configuration(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prepared, revision = make_manual_prepared_tree(workspace)
            receipt = prepared / "authority/build-authority/receipt.json"
            receipt.write_bytes(b'{"accepted":false}\n')
            runner = FakeCommandRunner()
            with self.assertRaisesRegex(stage.StagingError, "checksum drift"):
                stage.seal_staging(
                    prepared,
                    revision,
                    workspace / "sealed",
                    command_runner=runner,
                )
            self.assertEqual(runner.commands, [])

    def test_seal_publication_interrupt_removes_published_output(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prepared, revision = make_manual_prepared_tree(workspace)
            sealed = workspace / "sealed"
            real_publish = stage._publish_tree_noreplace

            def publish_then_interrupt(source, destination):
                real_publish(source, destination)
                raise KeyboardInterrupt()

            with mock.patch.object(
                stage,
                "_publish_tree_noreplace",
                side_effect=publish_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage.seal_staging(
                    prepared,
                    revision,
                    sealed,
                    command_runner=FakeCommandRunner(),
                )
            self.assertFalse(sealed.exists())
            self.assertEqual(
                list(workspace.glob(".sealed.seal-*")),
                [],
            )

    def test_fixture_allows_a_create_new_realworld_mirror_sealer(self) -> None:
        assert stage is not None
        observed_absent: list[bool] = []

        def seal_mirror(output: Path) -> None:
            observed_absent.append(
                not output.exists() and not output.is_symlink()
            )
            output.mkdir()
            write_payload(
                output / "authority.json",
                stage.canonical_document({
                    "projects": [{"id": "fixture-valid-sealer-output"}],
                    "schema": "fixture-realworld-mirror-authority-v1",
                }),
            )

        with tempfile.TemporaryDirectory() as temporary:
            prepared, _revision = make_manual_prepared_tree(
                Path(temporary), mirror_authority_sealer=seal_mirror
            )
            self.assertEqual(observed_absent, [True])
            authority = prepared / "authority" / "mirrors" / "authority.json"
            self.assertTrue(authority.is_file())
            config = json.loads(
                (prepared / "config" / "runtime.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                config["realworld"]["mirror_authority_sha256"],
                sha256_file(authority),
            )

    def test_seal_verify_lifecycle_rejects_payload_and_manifest_tampering(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, prepared, revision, sealed, receipt = fixture
            self.assertEqual(
                stage.verify_bundle(
                    sealed, command_runner=FakeCommandRunner(),
                    **bundle_authority(sealed),
                ),
                receipt,
            )
            receipt_bytes = (sealed / "bundle" / "receipt.json").read_bytes()

            with self.assertRaises(stage.StagingError):
                stage.seal_staging(prepared, revision, sealed)
            self.assertEqual(
                (sealed / "bundle" / "receipt.json").read_bytes(),
                receipt_bytes,
            )

            receipt_tampered = workspace / "receipt-tampered"
            shutil.copytree(sealed, receipt_tampered)
            receipt_path = receipt_tampered / "bundle" / "receipt.json"
            receipt_path.chmod(0o600)
            changed_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            changed_receipt["revision"] = "f" * 40
            receipt_path.write_bytes(stage.canonical_document(changed_receipt))
            with self.assertRaises(stage.StagingError):
                stage.verify_bundle(
                    receipt_tampered,
                    **bundle_authority(sealed),
                )

            payload_tampered = workspace / "payload-tampered"
            shutil.copytree(sealed, payload_tampered)
            payload = payload_tampered / "operator" / "README.md"
            payload.chmod(0o600)
            payload.write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(stage.StagingError):
                stage.verify_bundle(
                    payload_tampered,
                    **bundle_authority(sealed),
                )

            metadata_tampered = workspace / "metadata-tampered"
            shutil.copytree(sealed, metadata_tampered)
            metadata = metadata_tampered / "bundle"
            metadata.chmod(0o700)
            (metadata / "unexpected.txt").write_text(
                "unexpected\n", encoding="utf-8"
            )
            with self.assertRaises(stage.StagingError):
                stage.verify_bundle(
                    metadata_tampered,
                    **bundle_authority(sealed),
                )

            metadata_mode_tampered = workspace / "metadata-mode-tampered"
            shutil.copytree(sealed, metadata_mode_tampered)
            (metadata_mode_tampered / "bundle" / "inventory.json").chmod(
                0o600
            )
            with self.assertRaisesRegex(stage.StagingError, "mode|type"):
                stage.verify_bundle(
                    metadata_mode_tampered,
                    **bundle_authority(sealed),
                )

    def test_large_private_trees_use_the_selected_disk_backed_root(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, prepared, revision, sealed, _receipt = fixture
            temporary_root = workspace / "disk-backed-temporary"
            temporary_root.mkdir(mode=0o700)
            observed: list[Path] = []
            original_mkdir = os.mkdir

            def observe_mkdir(path, mode=0o777, *args, **kwargs):
                candidate = Path(path)
                if candidate.name.startswith("codeskeptic-stability-work-"):
                    observed.append(candidate.parent)
                return original_mkdir(path, mode, *args, **kwargs)

            with mock.patch.object(
                stage.os, "mkdir", side_effect=observe_mkdir
            ):
                second_sealed = workspace / "second-sealed"
                stage.seal_staging(
                    prepared,
                    revision,
                    second_sealed,
                    command_runner=FakeCommandRunner(),
                    temporary_root=temporary_root,
                )
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=FakeCommandRunner(),
                    temporary_root=temporary_root,
                )
                install_workspace = workspace / "temporary-root-install"
                install_workspace.mkdir()
                with patched_install_layout(install_workspace):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=FakeCommandRunner(),
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        temporary_root=temporary_root,
                    )

            self.assertEqual(len(observed), 3)
            self.assertTrue(all(path == temporary_root for path in observed))
            self.assertEqual(list(temporary_root.iterdir()), [])

    def test_disk_backed_temporary_root_rejects_symlink_before_execution(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            target = workspace / "real-temporary-root"
            target.mkdir()
            linked = workspace / "linked-temporary-root"
            linked.symlink_to(target, target_is_directory=True)
            runner = FakeCommandRunner()
            with self.assertRaisesRegex(stage.StagingError, "temporary root"):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=linked,
                )
            self.assertEqual(runner.commands, [])
            self.assertEqual(list(target.iterdir()), [])

    def test_disk_backed_temporary_root_rejects_low_capacity_before_copy(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "small-temporary-root"
            temporary_root.mkdir(mode=0o700)
            runner = FakeCommandRunner()
            filesystem = mock.Mock(f_bavail=1, f_frsize=1)
            with mock.patch.object(
                stage.os, "statvfs", return_value=filesystem
            ), self.assertRaisesRegex(stage.StagingError, "insufficient"):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertEqual(runner.commands, [])
            self.assertEqual(list(temporary_root.iterdir()), [])

    def test_disk_backed_root_swap_is_rejected_and_cleaned_before_execution(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "swapped-temporary-root"
            temporary_root.mkdir(mode=0o700)
            original_root = workspace / "original-temporary-root"
            original_mkdir = os.mkdir

            def swap_root(path, mode=0o777, *args, **kwargs):
                candidate = Path(path)
                if candidate.name.startswith("codeskeptic-stability-work-"):
                    temporary_root.rename(original_root)
                    original_mkdir(temporary_root, 0o700)
                return original_mkdir(path, mode, *args, **kwargs)

            runner = FakeCommandRunner()
            with mock.patch.object(
                stage.os, "mkdir", side_effect=swap_root
            ), self.assertRaisesRegex(stage.StagingError, "identity changed"):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertEqual(runner.commands, [])
            self.assertEqual(list(temporary_root.iterdir()), [])
            self.assertEqual(list(original_root.iterdir()), [])

    def test_interrupt_before_workspace_pin_retains_created_child(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "creation-interrupt-root"
            temporary_root.mkdir(mode=0o700)
            original_mkdir = os.mkdir

            def interrupt_after_create(path, mode=0o777, *args, **kwargs):
                result = original_mkdir(path, mode, *args, **kwargs)
                if Path(path).name.startswith(
                    "codeskeptic-stability-work-"
                ):
                    raise KeyboardInterrupt()
                return result

            runner = FakeCommandRunner()
            with mock.patch.object(
                stage.os, "mkdir", side_effect=interrupt_after_create
            ), self.assertRaisesRegex(
                stage.StagingError, "cleanup withheld"
            ):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertEqual(runner.commands, [])
            retained = list(temporary_root.iterdir())
            self.assertEqual(len(retained), 1)
            retained[0].rmdir()

    def test_interrupt_during_workspace_identity_capture_retains_child(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "identity-interrupt-root"
            temporary_root.mkdir(mode=0o700)
            original_lstat = Path.lstat
            interrupted = False

            def interrupt_identity(path, *args, **kwargs):
                nonlocal interrupted
                if (
                    not interrupted
                    and path.name.startswith("codeskeptic-stability-work-")
                ):
                    interrupted = True
                    raise KeyboardInterrupt()
                return original_lstat(path, *args, **kwargs)

            runner = FakeCommandRunner()
            with mock.patch.object(
                stage.Path, "lstat", autospec=True, side_effect=interrupt_identity
            ), self.assertRaisesRegex(
                stage.StagingError, "cleanup withheld"
            ):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertEqual(runner.commands, [])
            retained = list(temporary_root.iterdir())
            self.assertEqual(len(retained), 1)
            retained[0].rmdir()

    def test_interrupt_during_workspace_parent_revalidation_removes_child(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "parent-interrupt-root"
            temporary_root.mkdir(mode=0o700)
            original_lstat = Path.lstat
            root_lstats = 0

            def interrupt_second_root_lstat(path, *args, **kwargs):
                nonlocal root_lstats
                if path == temporary_root:
                    root_lstats += 1
                    if root_lstats == 2:
                        raise KeyboardInterrupt()
                return original_lstat(path, *args, **kwargs)

            runner = FakeCommandRunner()
            with mock.patch.object(
                stage.Path,
                "lstat",
                autospec=True,
                side_effect=interrupt_second_root_lstat,
            ), self.assertRaises(KeyboardInterrupt):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertGreaterEqual(root_lstats, 2)
            self.assertEqual(runner.commands, [])
            self.assertEqual(list(temporary_root.iterdir()), [])

    def test_snapshot_directory_creation_preserves_space_and_inode_reserve(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "destination"
            source.mkdir()
            (source / "empty").mkdir()
            destination.mkdir()
            source_fd = os.open(
                source,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            reserve = 4096
            budget = {
                "entries": 0,
                "remaining_bytes": 4096,
                "reserve_bytes": reserve,
                "temporary_workspace": workspace,
            }
            roomy = mock.Mock(
                f_bavail=2,
                f_frsize=4096,
                f_files=2,
                f_favail=2,
            )
            exhausted = mock.Mock(
                f_bavail=0,
                f_frsize=4096,
                f_files=2,
                f_favail=0,
            )
            try:
                with mock.patch.object(
                    stage.os,
                    "statvfs",
                    side_effect=[roomy, exhausted],
                ), self.assertRaisesRegex(
                    stage.StagingError, "temporary root.*(space|inode)"
                ):
                    stage._copy_snapshot_directory(
                        source_fd, destination, budget
                    )
            finally:
                os.close(source_fd)

    def test_temporary_inventory_capacity_accepts_dynamic_inode_reporting(
        self,
    ) -> None:
        assert stage is not None
        filesystem = mock.Mock(
            f_bavail=2,
            f_frsize=4096,
            f_files=0,
            f_favail=0,
        )
        with mock.patch.object(stage.os, "statvfs", return_value=filesystem):
            stage._temporary_inventory_capacity(Path("/fixture"), 4096, 2)

    def test_temporary_inventory_capacity_enforces_bytes_when_inodes_unreported(
        self,
    ) -> None:
        assert stage is not None
        filesystem = mock.Mock(
            f_bavail=0,
            f_frsize=4096,
            f_files=0,
            f_favail=0,
        )
        with (
            mock.patch.object(stage.os, "statvfs", return_value=filesystem),
            self.assertRaisesRegex(stage.StagingError, "space or inodes"),
        ):
            stage._temporary_inventory_capacity(Path("/fixture"), 4096, 2)

    def test_temporary_inventory_capacity_rejects_fixed_inode_exhaustion(
        self,
    ) -> None:
        assert stage is not None
        filesystem = mock.Mock(
            f_bavail=2,
            f_frsize=4096,
            f_files=1024,
            f_favail=0,
        )
        with (
            mock.patch.object(stage.os, "statvfs", return_value=filesystem),
            self.assertRaisesRegex(stage.StagingError, "space or inodes"),
        ):
            stage._temporary_inventory_capacity(Path("/fixture"), 4096, 2)

    def test_snapshot_copy_separates_path_and_descriptor_ctime(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "destination"
            source.mkdir()
            destination.mkdir()
            payload = b"stable\n"
            nested = source / "nested"
            nested.mkdir()
            (nested / "payload.bin").write_bytes(payload)
            source_fd = os.open(
                source,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            actual_stat = os.stat

            def path_stat_with_distinct_ctime(path, *args, **kwargs):
                observed = actual_stat(path, *args, **kwargs)
                if kwargs.get("dir_fd") is None:
                    return observed
                return mock.Mock(
                    st_mode=observed.st_mode,
                    st_dev=observed.st_dev,
                    st_ino=observed.st_ino,
                    st_nlink=observed.st_nlink,
                    st_size=observed.st_size,
                    st_mtime_ns=observed.st_mtime_ns,
                    st_ctime_ns=observed.st_ctime_ns + 1,
                )

            budget = {
                "entries": 0,
                "remaining_bytes": 4096,
                "reserve_bytes": 0,
                "temporary_workspace": workspace,
            }
            try:
                with mock.patch.object(
                    stage.os,
                    "stat",
                    side_effect=path_stat_with_distinct_ctime,
                ):
                    stage._copy_snapshot_directory(
                        source_fd, destination, budget
                    )
            finally:
                os.close(source_fd)
            self.assertEqual(
                (destination / "nested" / "payload.bin").read_bytes(),
                payload,
            )

    def test_snapshot_copy_rejects_descriptor_metadata_drift(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "payload.bin").write_bytes(b"stable\n")
            source_fd = os.open(
                source,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            actual_fstat = os.fstat
            calls = 0

            def descriptor_stat_with_final_drift(descriptor):
                nonlocal calls
                observed = actual_fstat(descriptor)
                calls += 1
                if calls != 2:
                    return observed
                return mock.Mock(
                    st_mode=observed.st_mode,
                    st_dev=observed.st_dev,
                    st_ino=observed.st_ino,
                    st_nlink=observed.st_nlink,
                    st_size=observed.st_size + 1,
                    st_mtime_ns=observed.st_mtime_ns,
                    st_ctime_ns=observed.st_ctime_ns,
                )

            budget = {
                "entries": 0,
                "remaining_bytes": 4096,
                "reserve_bytes": 0,
                "temporary_workspace": workspace,
            }
            try:
                with mock.patch.object(
                    stage.os,
                    "fstat",
                    side_effect=descriptor_stat_with_final_drift,
                ), self.assertRaisesRegex(
                    stage.StagingError, "changed while copying"
                ):
                    stage._copy_snapshot_directory(
                        source_fd, destination, budget
                    )
            finally:
                os.close(source_fd)

    def test_pinned_snapshot_byte_budget_fails_before_disk_exhaustion(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "budgeted-temporary-root"
            temporary_root.mkdir(mode=0o700)
            archive_size = (
                sealed / "image" / stage.PINNED_ARCHIVE_NAME
            ).stat().st_size
            reserve = (
                archive_size * stage.VFS_ARCHIVE_EXPANSION_FACTOR
                + stage.LARGE_TEMPORARY_RESERVE_BYTES
            )
            runner = FakeCommandRunner()
            with mock.patch.object(
                stage,
                "_temporary_available_bytes",
                side_effect=[10**12, 10**12, reserve + 1],
            ), self.assertRaisesRegex(stage.StagingError, "pinned byte budget"):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    temporary_root=temporary_root,
                )
            self.assertEqual(runner.commands, [])
            self.assertEqual(list(temporary_root.iterdir()), [])

    def test_interrupt_cleans_snapshot_and_private_image_store(self) -> None:
        assert stage is not None

        class InterruptingRunner(FakeCommandRunner):
            def __call__(self, argv: list[str], **kwargs) -> bytes:
                command = [os.fspath(item) for item in argv]
                if "load" in command:
                    raise KeyboardInterrupt()
                return super().__call__(argv, **kwargs)

        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            temporary_root = workspace / "interrupted-temporary-root"
            temporary_root.mkdir(mode=0o700)
            with self.assertRaises(KeyboardInterrupt):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=InterruptingRunner(),
                    temporary_root=temporary_root,
                )
            self.assertEqual(list(temporary_root.iterdir()), [])

    def test_host_never_executes_staged_python_while_sealing(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            marker = workspace / "staged-python-executed"
            prepared, revision = make_manual_prepared_tree(
                workspace, execution_marker=marker
            )
            sealed = workspace / "sealed"
            stage.seal_staging(
                prepared, revision, sealed,
                command_runner=FakeCommandRunner(),
            )
            self.assertFalse(marker.exists())
            stage.verify_bundle(
                sealed, command_runner=FakeCommandRunner(),
                **bundle_authority(sealed),
            )
            self.assertFalse(marker.exists())

    def test_operator_payload_is_byte_bound_to_exact_head_source(self) -> None:
        assert stage is not None
        mutations = (
            ("README.md", False),
            ("cgroup-authority.py", False),
            ("container-entry.py", False),
            ("containers.conf", False),
            ("host-recovery.py", False),
            ("guided-stability.sh", False),
            ("post-stop.sh", False),
            ("run-authoritative-stability.sh", False),
            (PRODUCER.name, False),
            (UNIT.name, True),
        )
        for index, (name, duplicate_unit) in enumerate(mutations):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                prepared, revision = make_manual_prepared_tree(workspace)
                operator_path = prepared / "operator" / name
                original_mode = operator_path.stat().st_mode & 0o777
                operator_path.chmod(0o700)
                operator_path.write_bytes(
                    operator_path.read_bytes() + b"\n# consistent payload drift\n"
                )
                operator_path.chmod(original_mode)
                if duplicate_unit:
                    unit_path = prepared / "unit" / name
                    unit_mode = unit_path.stat().st_mode & 0o777
                    unit_path.chmod(0o600)
                    unit_path.write_bytes(operator_path.read_bytes())
                    unit_path.chmod(unit_mode)
                with self.assertRaisesRegex(
                    stage.StagingError, "operator|exact-head|source"
                ):
                    stage.seal_staging(
                        prepared,
                        revision,
                        workspace / f"sealed-{index}",
                        command_runner=FakeCommandRunner(),
                    )

    def test_source_validation_disables_repository_fsmonitor_execution(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            revision = initialize_lifecycle_source(source)
            marker = workspace / "fsmonitor-executed"
            monitor = workspace / "malicious-fsmonitor.sh"
            monitor.write_text(
                "#!/usr/bin/env bash\n"
                f"/usr/bin/touch {os.fspath(marker)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            monitor.chmod(0o700)
            git(source, "config", "core.fsmonitor", os.fspath(monitor))
            stage.validate_staged_source(source, revision)
            self.assertFalse(marker.exists())

    def test_ignored_unchecked_hash_bytecode_is_rejected_before_semantic_execution(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prepared, revision = make_manual_prepared_tree(workspace)
            source = prepared / "authority" / "source"
            marker = workspace / "malicious-bytecode-executed"
            malicious = source / "scripts" / "__pycache__" / "run_stability_campaign.cpython-311.pyc"
            malicious.parent.mkdir()
            # PEP 552 unchecked-hash pyc header followed by a real code object.
            import marshal
            code = compile(
                f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')",
                "ignored-malicious.py",
                "exec",
            )
            malicious.write_bytes(
                b"\xa7\r\r\n" + (1).to_bytes(4, "little") + b"0" * 8
                + marshal.dumps(code)
            )
            (source / ".git" / "info" / "exclude").write_text(
                "scripts/__pycache__/\n", encoding="utf-8"
            )
            runner = FakeCommandRunner()
            with self.assertRaisesRegex(stage.StagingError, "bytecode|__pycache__"):
                stage.seal_staging(
                    prepared,
                    revision,
                    workspace / "sealed-bytecode",
                    command_runner=runner,
                )
            self.assertFalse(marker.exists())
            self.assertEqual(runner.commands, [])

    def test_runtime_source_manifest_ignores_python_cache_outputs(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            initialize_lifecycle_source(source)
            expected = stage._runtime_source_manifest(source)
            cache = source / "scripts" / "__pycache__"
            cache.mkdir()
            (cache / "generated.cpython-314.pyc").write_bytes(b"cache output")
            (source / "tests" / "generated.pyo").write_bytes(b"cache output")
            self.assertEqual(stage._runtime_source_manifest(source), expected)

    def test_verify_and_install_require_out_of_band_bundle_identity(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            _workspace, _prepared, _revision, sealed, _receipt = fixture
            with self.assertRaises(TypeError):
                stage.verify_bundle(sealed, command_runner=FakeCommandRunner())
            with self.assertRaises(TypeError):
                stage.install_bundle(
                    sealed,
                    command_runner=FakeCommandRunner(),
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )

    def test_out_of_band_bundle_identity_is_checked_before_semantic_execution(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, revision, sealed, _receipt = fixture
            cases = (
                {
                    "expected_revision": "f" * 40,
                    "expected_bundle_receipt_sha256": bundle_authority(sealed)[
                        "expected_bundle_receipt_sha256"
                    ],
                },
                {
                    "expected_revision": revision,
                    "expected_bundle_receipt_sha256": "f" * 64,
                },
            )
            for index, authority in enumerate(cases):
                runner = FakeCommandRunner()
                with self.subTest(authority=index), self.assertRaisesRegex(
                    stage.StagingError, "out-of-band"
                ):
                    stage.verify_bundle(
                        sealed, command_runner=runner, **authority
                    )
                self.assertEqual(runner.commands, [])

                install_workspace = workspace / f"identity-{index}"
                install_workspace.mkdir()
                with patched_install_layout(install_workspace) as layout:
                    with self.assertRaisesRegex(
                        stage.StagingError, "out-of-band"
                    ):
                        stage.install_bundle(
                            sealed,
                            command_runner=runner,
                            require_root=False,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                            **authority,
                        )
                    self.assertFalse(layout["INSTALLATION_ROOT"].exists())
                    self.assertEqual(runner.commands, [])

    def test_no_replace_publish_fails_closed_without_renameat2(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "destination"
            source.write_text("source\n", encoding="utf-8")
            with mock.patch.object(stage.ctypes, "CDLL", return_value=object()):
                with self.assertRaises(OSError):
                    stage._rename_noreplace(source, destination)
            self.assertTrue(source.is_file())
            self.assertFalse(destination.exists())

    def test_schemas_fields_and_lexical_layout_are_fixed(self) -> None:
        assert stage is not None
        self.assertEqual(
            stage.BUNDLE_RECEIPT_SCHEMA,
            "codeskeptic-stability-staging-bundle-v1",
        )
        self.assertEqual(
            stage.INVENTORY_SCHEMA,
            "codeskeptic-stability-staging-inventory-v1",
        )
        self.assertEqual(
            stage.INSTALLATION_RECEIPT_SCHEMA,
            "codeskeptic-stability-installation-v1",
        )
        self.assertEqual(stage.BUNDLE_RECEIPT_FIELDS, BUNDLE_FIELDS)
        self.assertEqual(stage.INSTALLATION_RECEIPT_FIELDS, INSTALLATION_FIELDS)
        self.assertEqual(
            stage.DIRECTORY_INVENTORY_FIELDS,
            DIRECTORY_INVENTORY_FIELDS,
        )
        self.assertEqual(stage.FILE_INVENTORY_FIELDS, FILE_INVENTORY_FIELDS)

        self.assertEqual(stage.CONTAINER_AUTHORITY_ROOT, PurePosixPath("/authority"))
        self.assertEqual(
            stage.CONTAINER_SOURCE_ROOT,
            PurePosixPath("/authority/source"),
        )
        self.assertEqual(
            stage.CONTAINER_BUILD_ROOT,
            PurePosixPath("/authority/build"),
        )
        self.assertEqual(
            stage.SANITIZER_WORK_ROOT,
            Path("build/p10-09-sanitizers"),
        )
        self.assertEqual(stage.SANITIZER_PROFILES, ("address", "undefined"))

    def test_receipts_reject_missing_extra_and_wrong_schema_fields(self) -> None:
        assert stage is not None
        bundle = bundle_receipt()
        installation = installation_receipt()
        self.assertEqual(stage.validate_bundle_receipt(bundle), bundle)
        self.assertEqual(
            stage.validate_installation_receipt(installation), installation
        )

        for validator, valid in (
            (stage.validate_bundle_receipt, bundle),
            (stage.validate_installation_receipt, installation),
        ):
            with self.subTest(validator=validator.__name__, mutation="missing"):
                missing = copy.deepcopy(valid)
                missing.pop(next(iter(missing)))
                with self.assertRaises(stage.StagingError):
                    validator(missing)
            with self.subTest(validator=validator.__name__, mutation="extra"):
                extra = copy.deepcopy(valid)
                extra["unexpected"] = True
                with self.assertRaises(stage.StagingError):
                    validator(extra)
            with self.subTest(validator=validator.__name__, mutation="schema"):
                wrong_schema = copy.deepcopy(valid)
                wrong_schema["schema"] = "codeskeptic-stability-staging-v2"
                with self.assertRaises(stage.StagingError):
                    validator(wrong_schema)

    def test_source_authority_is_exact_head_detached_standalone_and_clean(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            revision = initialize_source(source)
            identity = stage.validate_staged_source(source, revision)
            self.assertEqual(identity["revision"], revision)
            self.assertEqual(identity["tree_sha1"], git(source, "rev-parse", "HEAD^{tree}"))

            (source / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(stage.StagingError, "clean"):
                stage.validate_staged_source(source, revision)
            (source / "untracked.txt").unlink()

            with self.assertRaisesRegex(stage.StagingError, "exact HEAD"):
                stage.validate_staged_source(source, "f" * 40)

            git(source, "switch", "--quiet", "main")
            with self.assertRaisesRegex(stage.StagingError, "detached"):
                stage.validate_staged_source(source, revision)

            linked = workspace / "linked"
            git(source, "worktree", "add", "--quiet", "--detach", str(linked), revision)
            self.assertTrue((linked / ".git").is_file())
            with self.assertRaisesRegex(stage.StagingError, "standalone"):
                stage.validate_staged_source(linked, revision)

    def test_inventory_is_lexical_exact_and_detects_content_tampering(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            make_inventory_tree(tree)
            inventory = stage.collect_inventory(tree)
            self.assertEqual(
                [entry["path"] for entry in inventory],
                ["alpha.txt", "nested", "nested/bravo.bin"],
            )
            for entry in inventory:
                expected = (
                    DIRECTORY_INVENTORY_FIELDS
                    if entry["type"] == "directory"
                    else FILE_INVENTORY_FIELDS
                )
                self.assertEqual(set(entry), expected)
            stage.verify_inventory(tree, inventory)

            (tree / "alpha.txt").write_bytes(b"tampered\n")
            with self.assertRaises(stage.StagingError):
                stage.verify_inventory(tree, inventory)

    def test_inventory_rejects_symlink_special_hardlink_and_unexpected_nodes(self) -> None:
        assert stage is not None
        mutations = ("symlink", "fifo", "hardlink", "unexpected")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                tree = Path(temporary) / "tree"
                make_inventory_tree(tree)
                inventory = stage.collect_inventory(tree)
                if mutation == "symlink":
                    (tree / "escape").symlink_to("alpha.txt")
                    operation = lambda: stage.collect_inventory(tree)
                elif mutation == "fifo":
                    os.mkfifo(tree / "pipe", 0o600)
                    operation = lambda: stage.collect_inventory(tree)
                elif mutation == "hardlink":
                    os.link(tree / "alpha.txt", tree / "alpha.link")
                    operation = lambda: stage.collect_inventory(tree)
                else:
                    (tree / "unexpected.txt").write_text("extra\n", encoding="utf-8")
                    operation = lambda: stage.verify_inventory(tree, inventory)
                with self.assertRaises(stage.StagingError):
                    operation()

    def test_install_is_create_new_then_exact_idempotent_reuse_without_overwrite(self) -> None:
        assert stage is not None
        producer_source = PRODUCER.read_text(encoding="utf-8")
        self.assertIn("os.geteuid()", producer_source)
        self.assertIn("root", producer_source)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "installed"
            make_inventory_tree(source)
            inventory = stage.collect_inventory(source)
            arguments = {
                "owner_uid": os.getuid(),
                "owner_gid": os.getgid(),
            }

            self.assertEqual(
                stage.install_tree_create_new(
                    source, destination, inventory, **arguments
                ),
                "created",
            )
            self.assertEqual(
                stage.install_tree_create_new(
                    source, destination, inventory, **arguments
                ),
                "reused",
            )

            installed = destination / "alpha.txt"
            installed.chmod(0o600)
            installed.write_bytes(b"pre-existing drift\n")
            with self.assertRaises(stage.StagingError):
                stage.install_tree_create_new(
                    source, destination, inventory, **arguments
                )
            self.assertEqual(installed.read_bytes(), b"pre-existing drift\n")

            collision = workspace / "collision"
            collision.mkdir()
            marker = collision / "owner-data"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaises(stage.StagingError):
                stage.install_tree_create_new(
                    source, collision, inventory, **arguments
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_publication_boundaries_self_clean_or_are_immediately_registered(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "published"
            make_inventory_tree(source)
            inventory = stage.collect_inventory(source)
            real_fsync_directory = stage._fsync_directory

            def fail_post_rename(path: Path) -> None:
                if Path(path) == destination.parent and destination.exists():
                    raise stage.StagingError("post-rename fsync failure")
                real_fsync_directory(path)

            with mock.patch.object(
                stage, "_fsync_directory", side_effect=fail_post_rename
            ):
                with self.assertRaisesRegex(
                    stage.StagingError, "post-rename"
                ):
                    stage.install_tree_create_new(
                        source,
                        destination,
                        inventory,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
            self.assertFalse(destination.exists())

            class RejectingRegistrationList(list):
                def append(self, item) -> None:
                    del item
                    raise RuntimeError("creation registration failure")

            with self.assertRaisesRegex(
                RuntimeError, "creation registration failure"
            ):
                stage.install_tree_create_new(
                    source,
                    destination,
                    inventory,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    created_nodes=RejectingRegistrationList(),
                )
            self.assertFalse(
                destination.exists(),
                "a published tree must self-clean if registration fails",
            )

            private = workspace / "private-state"
            with self.assertRaisesRegex(
                RuntimeError, "creation registration failure"
            ):
                stage._ensure_private_directory(
                    private,
                    os.getuid(),
                    os.getgid(),
                    created_nodes=RejectingRegistrationList(),
                )
            self.assertFalse(
                private.exists(),
                "a private fixed directory must self-clean if registration fails",
            )

    def test_tree_and_file_publication_interrupts_self_clean(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            destination = workspace / "published"
            make_inventory_tree(source)
            inventory = stage.collect_inventory(source)
            real_rename = stage._rename_noreplace

            def rename_then_interrupt(source_path, destination_path):
                real_rename(source_path, destination_path)
                raise KeyboardInterrupt()

            created = []
            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=rename_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage.install_tree_create_new(
                    source,
                    destination,
                    inventory,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    created_nodes=created,
                )
            self.assertFalse(destination.exists())
            self.assertEqual(created, [])

            foreign_destination = workspace / "foreign-published"
            foreign_marker = foreign_destination / "owner-data"
            staged_metadata = None
            real_lstat = Path.lstat
            real_remove = stage._remove_created_identity
            removed_paths: list[Path] = []

            def same_identity_collision(source_path, destination_path):
                nonlocal staged_metadata
                if Path(destination_path) != foreign_destination:
                    return real_rename(source_path, destination_path)
                staged_metadata = real_lstat(Path(source_path))
                Path(destination_path).mkdir()
                foreign_marker.write_text("preserve\n", encoding="utf-8")
                raise FileExistsError(destination_path)

            def report_same_identity(path):
                if Path(path) == foreign_destination and staged_metadata is not None:
                    return staged_metadata
                return real_lstat(path)

            def record_remove(path, device, inode, is_directory):
                removed_paths.append(Path(path))
                return real_remove(path, device, inode, is_directory)

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=same_identity_collision,
            ), mock.patch.object(
                Path, "lstat", new=report_same_identity
            ), mock.patch.object(
                stage,
                "_remove_created_identity",
                side_effect=record_remove,
            ), self.assertRaises(stage.StagingError):
                stage.install_tree_create_new(
                    source,
                    foreign_destination,
                    inventory,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertNotIn(foreign_destination, removed_paths)
            self.assertTrue(
                foreign_marker.exists(),
                f"removed={removed_paths!r}; workspace={list(workspace.iterdir())!r}",
            )
            self.assertEqual(
                foreign_marker.read_text(encoding="utf-8"), "preserve\n"
            )

            target = workspace / "created-file"
            real_write = stage.os.write
            interrupted = False

            def write_then_interrupt(descriptor, data):
                nonlocal interrupted
                written = real_write(descriptor, data)
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt()
                return written

            with mock.patch.object(
                stage.os, "write", side_effect=write_then_interrupt
            ), self.assertRaises(KeyboardInterrupt):
                stage._write_new(target, b"fixture\n")
            self.assertFalse(target.exists())

    def test_identity_cleanup_quarantines_before_removing_exact_nodes(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            for is_directory in (True, False):
                with self.subTest(is_directory=is_directory):
                    target = workspace / (
                        "owned-tree" if is_directory else "owned-file"
                    )
                    if is_directory:
                        target.mkdir()
                        (target / "owned-data").write_text(
                            "owned\n", encoding="utf-8"
                        )
                    else:
                        target.write_text("owned\n", encoding="utf-8")
                    metadata = target.lstat()
                    real_rename_at = stage._rename_noreplace_at
                    injected = False

                    def quarantine_then_replace(
                        source_directory,
                        source,
                        destination_directory,
                        destination,
                    ):
                        nonlocal injected
                        result = real_rename_at(
                            source_directory,
                            source,
                            destination_directory,
                            destination,
                        )
                        if not injected and destination.startswith(
                            ".codeskeptic-cleanup-"
                        ):
                            injected = True
                            if is_directory:
                                target.mkdir()
                                (target / "foreign-data").write_text(
                                    "preserve\n", encoding="utf-8"
                                )
                            else:
                                target.write_text(
                                    "preserve\n", encoding="utf-8"
                                )
                        return result

                    with mock.patch.object(
                        stage,
                        "_rename_noreplace_at",
                        side_effect=quarantine_then_replace,
                    ):
                        stage._remove_created_identity(
                            target,
                            metadata.st_dev,
                            metadata.st_ino,
                            is_directory,
                        )
                    marker = (
                        target / "foreign-data"
                        if is_directory
                        else target
                    )
                    self.assertEqual(
                        marker.read_text(encoding="utf-8"), "preserve\n"
                    )
                    self.assertEqual(
                        list(workspace.glob(".codeskeptic-cleanup-*")), []
                    )

            linked = workspace / "linked-file"
            linked.write_text("owned\n", encoding="utf-8")
            peer = workspace / "linked-peer"
            os.link(linked, peer)
            metadata = linked.lstat()
            with self.assertRaisesRegex(
                stage.StagingError, "identity changed"
            ):
                stage._remove_created_identity(
                    linked, metadata.st_dev, metadata.st_ino, False
                )
            self.assertEqual(linked.read_text(encoding="utf-8"), "owned\n")
            self.assertEqual(peer.read_text(encoding="utf-8"), "owned\n")

            interrupted_target = workspace / "interrupt-owned"
            interrupted_target.mkdir()
            (interrupted_target / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            metadata = interrupted_target.lstat()
            real_rename_at = stage._rename_noreplace_at
            interrupted = False

            def quarantine_then_interrupt(
                source_directory,
                source,
                destination_directory,
                destination,
            ):
                nonlocal interrupted
                result = real_rename_at(
                    source_directory,
                    source,
                    destination_directory,
                    destination,
                )
                if not interrupted and destination.startswith(
                    ".codeskeptic-cleanup-"
                ):
                    interrupted = True
                    raise KeyboardInterrupt()
                return result

            with mock.patch.object(
                stage,
                "_rename_noreplace_at",
                side_effect=quarantine_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage._remove_created_identity(
                    interrupted_target,
                    metadata.st_dev,
                    metadata.st_ino,
                    True,
                )
            self.assertTrue(
                (interrupted_target / "owned-data").is_file()
            )
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

            predelete_target = workspace / "predelete-owned"
            predelete_target.mkdir()
            (predelete_target / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            metadata = predelete_target.lstat()
            real_make_removable = stage._make_tree_removable_at
            interrupted = False

            def make_removable_then_interrupt(parent_descriptor, name):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt()
                return real_make_removable(parent_descriptor, name)

            with mock.patch.object(
                stage,
                "_make_tree_removable_at",
                side_effect=make_removable_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage._remove_created_identity(
                    predelete_target,
                    metadata.st_dev,
                    metadata.st_ino,
                    True,
                )
            self.assertFalse(predelete_target.exists())
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

            chmod_target = workspace / "chmod-owned"
            chmod_target.mkdir()
            (chmod_target / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            chmod_target.chmod(0o500)
            metadata = chmod_target.lstat()
            real_fchmod = stage.os.fchmod
            interrupted = False

            def fchmod_then_interrupt(descriptor, mode):
                nonlocal interrupted
                result = real_fchmod(descriptor, mode)
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt()
                return result

            with mock.patch.object(
                stage.os,
                "fchmod",
                side_effect=fchmod_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage._remove_created_identity(
                    chmod_target,
                    metadata.st_dev,
                    metadata.st_ino,
                    True,
                )
            self.assertFalse(chmod_target.exists())
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

            delete_target = workspace / "delete-owned"
            delete_target.mkdir()
            (delete_target / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            metadata = delete_target.lstat()
            real_rmtree = stage.shutil.rmtree
            interrupted = False

            def rmtree_then_interrupt(path, *args, **kwargs):
                nonlocal interrupted
                if not interrupted and str(path).startswith(
                    ".codeskeptic-cleanup-"
                ):
                    interrupted = True
                    raise KeyboardInterrupt()
                return real_rmtree(path, *args, **kwargs)

            with mock.patch.object(
                stage.shutil,
                "rmtree",
                side_effect=rmtree_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage._remove_created_identity(
                    delete_target,
                    metadata.st_dev,
                    metadata.st_ino,
                    True,
                )
            self.assertFalse(delete_target.exists())
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

            delete_file = workspace / "delete-file"
            delete_file.write_text("owned\n", encoding="utf-8")
            metadata = delete_file.lstat()
            real_unlink = stage.os.unlink
            interrupted = False

            def unlink_then_interrupt(path, *args, **kwargs):
                nonlocal interrupted
                if not interrupted and str(path).startswith(
                    ".codeskeptic-cleanup-"
                ):
                    interrupted = True
                    raise KeyboardInterrupt()
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(
                stage.os,
                "unlink",
                side_effect=unlink_then_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                stage._remove_created_identity(
                    delete_file,
                    metadata.st_dev,
                    metadata.st_ino,
                    False,
                )
            self.assertFalse(delete_file.exists())
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

    def test_publication_success_path_rechecks_and_preserves_replacements(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            real_rename = stage._rename_noreplace

            directory = workspace / "published-directory"
            directory_marker = directory / "foreign-data"

            def replace_directory_then_return(source, destination):
                real_rename(source, destination)
                shutil.rmtree(destination)
                Path(destination).mkdir()
                directory_marker.write_text(
                    "preserve\n", encoding="utf-8"
                )

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=replace_directory_then_return,
            ), self.assertRaisesRegex(stage.StagingError, "identity changed"):
                stage._ensure_private_directory(
                    directory, os.getuid(), os.getgid()
                )
            self.assertEqual(
                directory_marker.read_text(encoding="utf-8"), "preserve\n"
            )

            file_path = workspace / "published-file"

            def replace_file_then_return(source, destination):
                real_rename(source, destination)
                Path(destination).unlink()
                Path(destination).write_bytes(b"FOREIGN\n")

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=replace_file_then_return,
            ), self.assertRaisesRegex(stage.StagingError, "identity changed"):
                stage._write_new(file_path, b"owned\n")
            self.assertEqual(file_path.read_bytes(), b"FOREIGN\n")

            source = workspace / "source-tree"
            make_inventory_tree(source)
            inventory = stage.collect_inventory(source)
            installed = workspace / "published-installation"
            installation_marker = installed / "foreign-data"

            def replace_installation_then_return(source_path, destination):
                if Path(destination) != installed:
                    return real_rename(source_path, destination)
                real_rename(source_path, destination)
                shutil.rmtree(destination)
                Path(destination).mkdir()
                installation_marker.write_text(
                    "preserve\n", encoding="utf-8"
                )

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=replace_installation_then_return,
            ), self.assertRaisesRegex(stage.StagingError, "identity changed"):
                stage.install_tree_create_new(
                    source,
                    installed,
                    inventory,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            self.assertEqual(
                installation_marker.read_text(encoding="utf-8"),
                "preserve\n",
            )

            published_tree_source = workspace / "generic-source"
            published_tree_source.mkdir()
            (published_tree_source / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            published_tree = workspace / "generic-published"
            published_tree_marker = published_tree / "foreign-data"

            def replace_generic_tree_then_return(source_path, destination):
                real_rename(source_path, destination)
                shutil.rmtree(destination)
                Path(destination).mkdir()
                published_tree_marker.write_text(
                    "preserve\n", encoding="utf-8"
                )

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=replace_generic_tree_then_return,
            ), self.assertRaisesRegex(stage.StagingError, "identity changed"):
                stage._publish_tree_noreplace(
                    published_tree_source, published_tree
                )
            self.assertEqual(
                published_tree_marker.read_text(encoding="utf-8"),
                "preserve\n",
            )

            moved_source = workspace / "moved-source"
            moved_source.mkdir()
            (moved_source / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            moved_destination = workspace / "moved-destination"
            source_marker = moved_source / "foreign-data"

            def replace_source_after_publish(source_path, destination):
                real_rename(source_path, destination)
                Path(source_path).mkdir()
                source_marker.write_text("preserve\n", encoding="utf-8")
                raise KeyboardInterrupt()

            with mock.patch.object(
                stage,
                "_rename_noreplace",
                side_effect=replace_source_after_publish,
            ), self.assertRaisesRegex(
                stage.StagingError, "source identity changed"
            ):
                stage._publish_tree_noreplace(
                    moved_source, moved_destination
                )
            self.assertEqual(
                source_marker.read_text(encoding="utf-8"), "preserve\n"
            )
            self.assertFalse(moved_destination.exists())

    def test_install_rollback_uses_anchored_identity_cleanup(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "rollback-owned"
            target.mkdir()
            (target / "owned-data").write_text(
                "owned\n", encoding="utf-8"
            )
            metadata = target.lstat()
            marker = target / "foreign-data"
            real_rename_at = stage._rename_noreplace_at
            injected = False

            def quarantine_then_replace(
                source_directory,
                source,
                destination_directory,
                destination,
            ):
                nonlocal injected
                result = real_rename_at(
                    source_directory,
                    source,
                    destination_directory,
                    destination,
                )
                if not injected and destination.startswith(
                    ".codeskeptic-cleanup-"
                ):
                    injected = True
                    target.mkdir()
                    marker.write_text("preserve\n", encoding="utf-8")
                return result

            record = stage._CreatedNode(
                target,
                metadata.st_dev,
                metadata.st_ino,
                True,
                stage._open_identity_pin(
                    target,
                    metadata.st_dev,
                    metadata.st_ino,
                    True,
                    "rollback fixture",
                ),
            )
            with mock.patch.object(
                stage,
                "_rename_noreplace_at",
                side_effect=quarantine_then_replace,
            ):
                stage._rollback_created([record])
            self.assertEqual(
                marker.read_text(encoding="utf-8"), "preserve\n"
            )
            self.assertEqual(
                list(workspace.glob(".codeskeptic-cleanup-*")), []
            )

            absent = workspace / "already-absent"
            absent.mkdir()
            absent_metadata = absent.lstat()
            absent_record = stage._CreatedNode(
                absent,
                absent_metadata.st_dev,
                absent_metadata.st_ino,
                True,
                stage._open_identity_pin(
                    absent,
                    absent_metadata.st_dev,
                    absent_metadata.st_ino,
                    True,
                    "absent rollback fixture",
                ),
            )
            absent.rmdir()
            stage._rollback_created([absent_record])

    def test_private_directory_pin_failure_preserves_replacement(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            replacement: Path | None = None

            def replace_then_fail(path, *_arguments, **_keywords):
                nonlocal replacement
                replacement = Path(path)
                replacement.rmdir()
                replacement.mkdir(mode=0o700)
                (replacement / "foreign-data").write_text(
                    "preserve\n", encoding="utf-8"
                )
                raise stage.StagingError("identity changed while pinning")

            with mock.patch.object(
                stage,
                "_open_identity_pin",
                side_effect=replace_then_fail,
            ), self.assertRaisesRegex(
                stage.StagingError, "cleanup withheld"
            ):
                stage._create_private_temporary_directory(
                    workspace, ".creator-race-", "creator fixture"
                )
            assert replacement is not None
            self.assertEqual(
                (replacement / "foreign-data").read_text(encoding="utf-8"),
                "preserve\n",
            )

    def test_private_file_descriptor_remains_pinned_through_cleanup(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            captured_descriptor: int | None = None
            real_remove = stage._remove_created_identity

            def fail_payload(descriptor: int) -> None:
                nonlocal captured_descriptor
                captured_descriptor = descriptor
                os.write(descriptor, b"partial\n")
                raise RuntimeError("payload failure")

            def assert_pinned_then_remove(
                path: Path, device: int, inode: int, is_directory: bool,
            ) -> None:
                if Path(path).name == "payload":
                    assert captured_descriptor is not None
                    opened = os.fstat(captured_descriptor)
                    self.assertEqual((opened.st_dev, opened.st_ino), (device, inode))
                real_remove(path, device, inode, is_directory)

            target = workspace / "target"
            with mock.patch.object(
                stage,
                "_remove_created_identity",
                side_effect=assert_pinned_then_remove,
            ), self.assertRaisesRegex(RuntimeError, "payload failure"):
                stage._regular_file_create_new(
                    target,
                    0o600,
                    None,
                    None,
                    fail_payload,
                    label="payload fixture",
                )
            assert captured_descriptor is not None
            with self.assertRaises(OSError):
                os.fstat(captured_descriptor)
            self.assertFalse(target.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "transaction identity pins require Linux renameat2",
    )
    def test_transaction_identity_pin_survives_until_release_or_rollback(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            committed = workspace / "committed"
            committed_records = []
            stage._create_directory_create_new(
                committed,
                0o700,
                os.getuid(),
                os.getgid(),
                created_nodes=committed_records,
            )
            committed_descriptor = committed_records[0].descriptor
            self.assertTrue(stat.S_ISDIR(os.fstat(committed_descriptor).st_mode))
            stage._release_created(committed_records)
            self.assertEqual(committed_records, [])
            with self.assertRaises(OSError):
                os.fstat(committed_descriptor)

            rolled_back = workspace / "rolled-back"
            rollback_records = []
            stage._create_directory_create_new(
                rolled_back,
                0o700,
                os.getuid(),
                os.getgid(),
                created_nodes=rollback_records,
            )
            rollback_descriptor = rollback_records[0].descriptor
            rolled_back.rmdir()
            rolled_back.mkdir(mode=0o700)
            marker = rolled_back / "foreign-data"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(
                stage.StagingError, "rollback was incomplete"
            ):
                stage._rollback_created(rollback_records)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
            self.assertEqual(rollback_records, [])
            with self.assertRaises(OSError):
                os.fstat(rollback_descriptor)

            parent = workspace / "nested-parent"
            nested_records = []
            stage._create_directory_create_new(
                parent,
                0o700,
                os.getuid(),
                os.getgid(),
                created_nodes=nested_records,
            )
            child = parent / "nested-child"
            stage._create_directory_create_new(
                child,
                0o700,
                os.getuid(),
                os.getgid(),
                created_nodes=nested_records,
            )
            child.rmdir()
            child.mkdir(mode=0o700)
            nested_marker = child / "foreign-data"
            nested_marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(
                stage.StagingError, "descendant cleanup failed"
            ):
                stage._rollback_created(nested_records)
            self.assertEqual(
                nested_marker.read_text(encoding="utf-8"), "preserve\n"
            )

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "fixed runroot transaction requires Linux renameat2",
    )
    def test_fixed_runroot_rollback_preserves_replacement(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "runtime"
            parent.mkdir(mode=0o700)
            runroot = parent / "podman-runroot"
            marker = runroot / "foreign-data"
            with mock.patch.object(
                stage, "PODMAN_RUNROOT", runroot
            ), self.assertRaisesRegex(
                stage.StagingError, "rollback was incomplete"
            ):
                with stage._fixed_podman_runroot(
                    os.getuid(), os.getgid()
                ):
                    runroot.rmdir()
                    runroot.mkdir(mode=0o700)
                    marker.write_text("preserve\n", encoding="utf-8")
            self.assertEqual(
                marker.read_text(encoding="utf-8"), "preserve\n"
            )

    def test_file_publication_interrupt_preserves_foreign_collision(self) -> None:
        assert stage is not None
        marker = b"FOREIGN\n"
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            source.write_bytes(b"source\n")

            def foreign_then_interrupt(_source_path, destination_path):
                Path(destination_path).write_bytes(marker)
                raise KeyboardInterrupt()

            cases = (
                (
                    "write",
                    lambda target: stage._write_new(target, b"fixture\n"),
                ),
                (
                    "copy",
                    lambda target: stage._copy_regular_create_new(
                        source,
                        target,
                        0o600,
                        os.getuid(),
                        os.getgid(),
                    ),
                ),
            )
            for name, producer in cases:
                with self.subTest(name=name):
                    target = workspace / f"{name}-target"
                    with mock.patch.object(
                        stage,
                        "_rename_noreplace",
                        side_effect=foreign_then_interrupt,
                    ), self.assertRaisesRegex(
                        stage.StagingError, "published file identity changed"
                    ):
                        producer(target)
                    self.assertEqual(target.read_bytes(), marker)
                    self.assertFalse(any(
                        child.name.startswith(".codeskeptic-file-")
                        for child in workspace.iterdir()
                    ))

            def hardlink_then_collision(source_path, destination_path):
                os.link(source_path, destination_path)
                raise FileExistsError(destination_path)

            hardlink_cases = (
                (
                    "write-hardlink",
                    b"fixture\n",
                    0o400,
                    lambda target: stage._write_new(
                        target, b"fixture\n", mode=0o400
                    ),
                ),
                (
                    "copy-hardlink",
                    b"source\n",
                    0o440,
                    lambda target: stage._copy_regular_create_new(
                        source,
                        target,
                        0o440,
                        os.getuid(),
                        os.getgid(),
                    ),
                ),
            )
            for name, expected, expected_mode, producer in hardlink_cases:
                with self.subTest(name=name):
                    target = workspace / f"{name}-target"
                    with mock.patch.object(
                        stage,
                        "_rename_noreplace",
                        side_effect=hardlink_then_collision,
                    ), self.assertRaises(stage.StagingError):
                        producer(target)
                    self.assertEqual(target.read_bytes(), expected)
                    self.assertEqual(
                        stat.S_IMODE(target.stat().st_mode), expected_mode
                    )
                    self.assertFalse(any(
                        child.name.startswith(".codeskeptic-file-")
                        for child in workspace.iterdir()
                    ))

            target = workspace / "cleanup-failure-target"
            real_remove = stage._remove_created_identity

            def fail_private_directory_cleanup(
                path, device, inode, is_directory
            ):
                if (
                    is_directory
                    and Path(path).name.startswith(".codeskeptic-file-")
                ):
                    raise OSError("private file directory cleanup failure")
                return real_remove(path, device, inode, is_directory)

            with mock.patch.object(
                stage,
                "_remove_created_identity",
                side_effect=fail_private_directory_cleanup,
            ), self.assertRaisesRegex(
                stage.StagingError, "private file directory cleanup failure"
            ):
                stage._write_new(target, b"fixture\n")
            self.assertFalse(
                target.exists(),
                "a reported helper failure must not leave a fixed output",
            )

    def test_install_publication_boundaries_roll_back_fixed_targets(self) -> None:
        assert stage is not None

        def assert_fixed_targets_absent(layout: dict[str, Path]) -> None:
            for name in (
                "AUTHORITY_ROOT", "OPERATOR_ROOT", "CONFIG_PATH",
                "UNIT_PATH", "UNIT_DROPIN_DIRECTORY", "INSTALLATION_ROOT",
                "STATE_ROOT",
                "INSTALLATION_AUTHORITY_PATH",
                "PODMAN_ROOT", "PODMAN_RUNROOT",
            ):
                self.assertFalse(layout[name].exists(), name)

        boundary_names = ("installation-root-chown", "live-unit-fsync", "metadata-write")
        for boundary in boundary_names:
            with self.subTest(boundary=boundary), sealed_bundle_fixture() as fixture:
                workspace, _prepared, _revision, sealed, _receipt = fixture
                install_workspace = workspace / f"boundary-{boundary}"
                install_workspace.mkdir()
                runner = FakeCommandRunner()
                with patched_install_layout(install_workspace) as layout:
                    stack = contextlib.ExitStack()
                    with stack:
                        if boundary == "installation-root-chown":
                            real_chown = stage.os.chown

                            def fail_installation_root_chown(path, uid, gid):
                                candidate = Path(path)
                                installation_root = layout["INSTALLATION_ROOT"]
                                if (
                                    candidate.parent == installation_root.parent
                                    and candidate.name.startswith(
                                        f".{installation_root.name}.directory-"
                                    )
                                ):
                                    raise OSError("installation-root chown failure")
                                return real_chown(path, uid, gid)

                            stack.enter_context(mock.patch.object(
                                stage.os,
                                "chown",
                                side_effect=fail_installation_root_chown,
                            ))
                        elif boundary == "live-unit-fsync":
                            real_fsync = stage._fsync_directory

                            def fail_live_unit_fsync(path: Path) -> None:
                                if (
                                    Path(path) == layout["UNIT_PATH"].parent
                                    and layout["UNIT_PATH"].exists()
                                ):
                                    raise stage.StagingError(
                                        "live-unit fsync failure"
                                    )
                                real_fsync(path)

                            stack.enter_context(mock.patch.object(
                                stage,
                                "_fsync_directory",
                                side_effect=fail_live_unit_fsync,
                            ))
                        else:
                            real_write = stage._write_new

                            def fail_metadata_write(path, *args, **kwargs):
                                result = real_write(path, *args, **kwargs)
                                if Path(path) == Path(
                                    f"{layout['INSTALLATION_RECEIPT_PATH']}.sha256"
                                ):
                                    raise stage.StagingError(
                                        "metadata post-write failure"
                                    )
                                return result

                            stack.enter_context(mock.patch.object(
                                stage, "_write_new", side_effect=fail_metadata_write
                            ))
                        with self.assertRaises(stage.StagingError):
                            stage.install_bundle(
                                sealed,
                                **bundle_authority(sealed),
                                command_runner=runner,
                                require_root=False,
                                owner_uid=os.getuid(),
                                owner_gid=os.getgid(),
                            )
                    assert_fixed_targets_absent(layout)

    def test_install_and_verify_install_are_exact_idempotent_and_receipt_bound(self) -> None:
        assert stage is not None
        self.assertTrue(
            hasattr(stage, "install_bundle"),
            "install lifecycle implementation is missing",
        )
        self.assertTrue(
            hasattr(stage, "verify_installation"),
            "verify-install lifecycle implementation is missing",
        )
        self.assertTrue(
            hasattr(stage, "verify_installation_filesystem"),
            "pure installation verification lifecycle is missing",
        )
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "installation-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner()
            with patched_install_layout(install_workspace) as layout:
                arguments = {
                    "command_runner": runner,
                    "require_root": False,
                    "owner_uid": os.getuid(),
                    "owner_gid": os.getgid(),
                    **bundle_authority(sealed),
                }
                stage.install_bundle(sealed, **arguments)
                receipt_path = layout["INSTALLATION_RECEIPT_PATH"]
                live_dropin = layout["UNIT_DROPIN_PATH"]
                retained_dropin = (
                    layout["INSTALLATION_ROOT"]
                    / "unit"
                    / f"{UNIT.name}.d"
                    / TIMEOUT_OVERRIDE.name
                )
                self.assertEqual(
                    live_dropin.read_bytes(), TIMEOUT_OVERRIDE.read_bytes()
                )
                self.assertEqual(
                    live_dropin.read_bytes(), retained_dropin.read_bytes()
                )
                self.assertEqual(
                    layout["UNIT_DROPIN_DIRECTORY"].stat().st_mode & 0o777,
                    0o555,
                )
                self.assertEqual(live_dropin.stat().st_mode & 0o777, 0o444)
                sidecar_path = Path(f"{receipt_path}.sha256")
                self.assertTrue(receipt_path.is_file())
                self.assertTrue(sidecar_path.is_file())
                receipt_bytes = receipt_path.read_bytes()
                installed_receipt = json.loads(receipt_bytes.decode("utf-8"))
                self.assertEqual(
                    installed_receipt["bundle_revision"],
                    bundle_authority(sealed)["expected_revision"],
                )
                self.assertEqual(
                    installed_receipt["bundle_receipt_sha256"],
                    bundle_authority(sealed)[
                        "expected_bundle_receipt_sha256"
                    ],
                )
                sidecar_bytes = sidecar_path.read_bytes()
                receipt_inode = receipt_path.stat().st_ino
                expected_sidecar = (
                    f"{hashlib.sha256(receipt_bytes).hexdigest()}  receipt.json\n"
                ).encode("ascii")
                self.assertEqual(sidecar_bytes, expected_sidecar)
                authority_path = layout["INSTALLATION_AUTHORITY_PATH"]
                authority_bytes = authority_path.read_bytes()
                self.assertEqual(
                    json.loads(authority_bytes.decode("utf-8")),
                    {
                        "bundle_receipt_sha256": bundle_authority(sealed)[
                            "expected_bundle_receipt_sha256"
                        ],
                        "bundle_revision": bundle_authority(sealed)[
                            "expected_revision"
                        ],
                        "schema": stage.INSTALLATION_AUTHORITY_SCHEMA,
                    },
                )

                layout["PODMAN_RUNROOT"].parent.mkdir(
                    parents=True, exist_ok=True, mode=0o700
                )
                layout["PODMAN_RUNROOT"].parent.chmod(0o700)
                layout["PODMAN_RUNROOT"].mkdir(mode=0o700)
                runroot_sentinel = layout["PODMAN_RUNROOT"] / "sentinel"
                runroot_sentinel.write_bytes(b"must-not-change\n")
                sentinel_before = runroot_sentinel.stat()
                commands_before = list(runner.commands)
                pure_verified = stage.verify_installation_filesystem(
                    receipt_path,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    **bundle_authority(sealed),
                )
                sentinel_after = runroot_sentinel.stat()
                self.assertEqual(
                    pure_verified,
                    json.loads(receipt_bytes.decode("utf-8")),
                )
                self.assertEqual(runner.commands, commands_before)
                self.assertEqual(runroot_sentinel.read_bytes(), b"must-not-change\n")
                self.assertEqual(
                    (sentinel_after.st_dev, sentinel_after.st_ino),
                    (sentinel_before.st_dev, sentinel_before.st_ino),
                )
                runroot_sentinel.unlink()
                layout["PODMAN_RUNROOT"].rmdir()

                verified = stage.verify_installation(
                    receipt_path, **arguments
                )
                self.assertEqual(
                    verified,
                    json.loads(receipt_bytes.decode("utf-8")),
                )
                loads_after_first_install = sum(
                    "load" in command for command in runner.commands
                )
                self.assertEqual(
                    loads_after_first_install,
                    2,
                    "fresh install must preverify privately, then load the fixed store",
                )
                for command in runner.commands:
                    if "load" in command:
                        self.assertNotEqual(
                            option_value(command, "--input"),
                            os.fspath(
                                sealed / "image" / stage.PINNED_ARCHIVE_NAME
                            ),
                        )
                persistent_commands = [
                    command
                    for command in runner.commands
                    if option_value(command, "--root")
                    == os.fspath(layout["PODMAN_ROOT"])
                ]
                self.assertTrue(persistent_commands)
                self.assertTrue(all(
                    option_value(command, "--runroot")
                    == os.fspath(layout["PODMAN_RUNROOT"])
                    for command in persistent_commands
                ))
                self.assertFalse(layout["PODMAN_RUNROOT"].exists())

                original_mode = receipt_path.stat().st_mode & 0o777
                receipt_path.chmod(0o600)
                tampered_receipt = json.loads(receipt_bytes.decode("utf-8"))
                tampered_receipt["bundle_receipt_sha256"] = "f" * 64
                receipt_path.write_bytes(
                    stage.canonical_document(tampered_receipt)
                )
                with self.assertRaises(stage.StagingError):
                    stage.verify_installation(receipt_path, **arguments)
                receipt_path.write_bytes(receipt_bytes)
                receipt_path.chmod(original_mode)

                authority_path.chmod(0o600)
                forged_authority = json.loads(authority_bytes.decode("utf-8"))
                forged_authority["bundle_revision"] = "f" * 40
                authority_path.write_bytes(
                    stage.canonical_document(forged_authority)
                )
                authority_path.chmod(0o400)
                with self.assertRaisesRegex(
                    stage.StagingError, "out-of-band authority"
                ):
                    stage.verify_installation_filesystem(
                        receipt_path,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        **bundle_authority(sealed),
                    )
                authority_path.chmod(0o600)
                authority_path.write_bytes(authority_bytes)
                authority_path.chmod(0o400)

                live_dropin.chmod(0o600)
                live_dropin.write_text(
                    "[Service]\nTimeoutStopFailureMode=abort\n",
                    encoding="utf-8",
                )
                live_dropin.chmod(0o444)
                with self.assertRaises(stage.StagingError):
                    stage.verify_installation_filesystem(
                        receipt_path,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        **bundle_authority(sealed),
                    )
                live_dropin.chmod(0o600)
                live_dropin.write_bytes(TIMEOUT_OVERRIDE.read_bytes())
                live_dropin.chmod(0o444)

                dropin_directory = layout["UNIT_DROPIN_DIRECTORY"]
                dropin_directory.chmod(0o755)
                foreign_dropin = dropin_directory / "99-foreign.conf"
                foreign_dropin.write_text(
                    "[Service]\nEnvironment=DRIFT=1\n",
                    encoding="utf-8",
                )
                foreign_dropin.chmod(0o444)
                dropin_directory.chmod(0o555)
                with self.assertRaises(stage.StagingError):
                    stage.verify_installation_filesystem(
                        receipt_path,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        **bundle_authority(sealed),
                    )
                dropin_directory.chmod(0o755)
                foreign_dropin.unlink()
                dropin_directory.chmod(0o555)

                stage.install_bundle(sealed, **arguments)
                self.assertEqual(receipt_path.stat().st_ino, receipt_inode)
                self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
                self.assertEqual(sidecar_path.read_bytes(), sidecar_bytes)
                self.assertEqual(
                    sum("load" in command for command in runner.commands),
                    loads_after_first_install,
                )

                installed_operator = (
                    layout["OPERATOR_ROOT"] / "run-authoritative-stability.sh"
                )
                installed_operator.chmod(0o700)
                installed_operator.write_text("tampered\n", encoding="utf-8")
                with self.assertRaises(stage.StagingError):
                    stage.verify_installation(receipt_path, **arguments)
                with self.assertRaises(stage.StagingError):
                    stage.install_bundle(sealed, **arguments)
                self.assertEqual(
                    installed_operator.read_text(encoding="utf-8"),
                    "tampered\n",
                )

    def test_live_timeout_override_rejects_mode_and_hardlink_drift(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            expected = workspace / "expected.conf"
            expected.write_bytes(stage.UNIT_DROPIN_DATA)
            directory = workspace / "codeskeptic-stability.service.d"
            directory.mkdir(mode=0o755)
            live = directory / stage.UNIT_DROPIN_NAME
            live.write_bytes(stage.UNIT_DROPIN_DATA)
            live.chmod(0o444)
            directory.chmod(0o555)
            with (
                mock.patch.object(stage, "UNIT_DROPIN_DIRECTORY", directory),
                mock.patch.object(stage, "UNIT_DROPIN_PATH", live),
            ):
                stage.verify_live_dropin_authority(
                    expected, os.getuid(), os.getgid()
                )
                live.chmod(0o644)
                with self.assertRaisesRegex(
                    stage.StagingError, "drop-in file authority drift"
                ):
                    stage.verify_live_dropin_authority(
                        expected, os.getuid(), os.getgid()
                    )
                live.chmod(0o444)
                os.link(live, workspace / "outside-hardlink")
                with self.assertRaisesRegex(
                    stage.StagingError, "drop-in file authority drift"
                ):
                    stage.verify_live_dropin_authority(
                        expected, os.getuid(), os.getgid()
                    )

    def test_post_commit_pin_release_failure_never_enters_rollback(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "post-commit-release-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner()
            real_release = stage._release_created

            def release_then_fail(records) -> None:
                real_release(records)
                raise stage.StagingError("post-commit pin release failed")

            with (
                patched_install_layout(install_workspace) as layout,
                mock.patch.object(
                    stage,
                    "_release_created",
                    side_effect=release_then_fail,
                ),
                mock.patch.object(
                    stage, "_reset_persistent_podman_store"
                ) as reset_store,
                self.assertRaisesRegex(
                    stage.StagingError, "post-commit pin release failed"
                ),
            ):
                stage.install_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=runner,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            reset_store.assert_not_called()
            self.assertTrue(layout["INSTALLATION_RECEIPT_PATH"].is_file())

    def test_verify_install_survives_cold_boot_without_persistent_runroot(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "read-only-verify-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner()
            with patched_install_layout(install_workspace) as layout:
                arguments = {
                    "command_runner": runner,
                    "require_root": False,
                    "owner_uid": os.getuid(),
                    "owner_gid": os.getgid(),
                    **bundle_authority(sealed),
                }
                stage.install_bundle(sealed, **arguments)
                runroot = layout["PODMAN_RUNROOT"]
                self.assertFalse(runroot.exists())
                stage.verify_installation(
                    layout["INSTALLATION_RECEIPT_PATH"], **arguments
                )
                self.assertFalse(runroot.exists())

    def test_install_preflights_collisions_without_partial_overwrite(self) -> None:
        assert stage is not None
        self.assertTrue(
            hasattr(stage, "install_bundle"),
            "install lifecycle implementation is missing",
        )
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "collision-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner()
            with patched_install_layout(install_workspace) as layout:
                authority = layout["AUTHORITY_ROOT"]
                authority.mkdir(parents=True)
                marker = authority / "owner-data"
                marker.write_text("preserve\n", encoding="utf-8")
                with self.assertRaises(stage.StagingError):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(
                    marker.read_text(encoding="utf-8"), "preserve\n"
                )
                self.assertFalse(layout["OPERATOR_ROOT"].exists())
                self.assertFalse(layout["CONFIG_PATH"].exists())
                self.assertFalse(layout["UNIT_PATH"].exists())
                self.assertFalse(layout["UNIT_DROPIN_DIRECTORY"].exists())
                self.assertFalse(layout["INSTALLATION_RECEIPT_PATH"].exists())
                self.assertEqual(runner.commands, [])

    def test_install_rolls_back_identity_bound_paths_after_late_failure(self) -> None:
        assert stage is not None

        class FailPersistentLoad(FakeCommandRunner):
            def __init__(self) -> None:
                super().__init__()
                self.load_count = 0

            def __call__(self, argv: list[str], **kwargs) -> bytes:
                command = [os.fspath(item) for item in argv]
                if "load" in command:
                    self.load_count += 1
                    if self.load_count == 2:
                        raise stage.StagingError("late persistent load failure")
                return super().__call__(argv, **kwargs)

        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "rollback-root"
            install_workspace.mkdir()
            runner = FailPersistentLoad()
            with patched_install_layout(install_workspace) as layout:
                with self.assertRaisesRegex(
                    stage.StagingError, "late persistent load failure"
                ):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                for name in (
                    "AUTHORITY_ROOT", "OPERATOR_ROOT", "CONFIG_PATH",
                    "UNIT_PATH", "UNIT_DROPIN_DIRECTORY", "INSTALLATION_ROOT",
                    "STATE_ROOT",
                    "PODMAN_ROOT", "PODMAN_RUNROOT",
                ):
                    self.assertFalse(layout[name].exists(), name)

    def test_install_rolls_back_after_persistent_load_interrupt(self) -> None:
        assert stage is not None

        class InterruptPersistentLoad(FakeCommandRunner):
            def __init__(self) -> None:
                super().__init__()
                self.load_count = 0

            def __call__(self, argv: list[str], **kwargs) -> bytes:
                command = [os.fspath(item) for item in argv]
                if "load" in command:
                    self.load_count += 1
                    if self.load_count == 2:
                        raise KeyboardInterrupt()
                return super().__call__(argv, **kwargs)

        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "interrupt-rollback-root"
            install_workspace.mkdir()
            runner = InterruptPersistentLoad()
            with patched_install_layout(install_workspace) as layout:
                with self.assertRaises(KeyboardInterrupt):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                for name in (
                    "AUTHORITY_ROOT", "OPERATOR_ROOT", "CONFIG_PATH",
                    "UNIT_PATH", "UNIT_DROPIN_DIRECTORY", "INSTALLATION_ROOT",
                    "STATE_ROOT",
                    "PODMAN_ROOT", "PODMAN_RUNROOT",
                ):
                    self.assertFalse(layout[name].exists(), name)

    def test_persistent_store_reset_failure_is_combined_before_tree_rollback(self) -> None:
        assert stage is not None

        class FailLoadAndReset(FakeCommandRunner):
            def __init__(self, persistent_root: Path) -> None:
                super().__init__()
                self.persistent_root = os.fspath(persistent_root)

            def __call__(self, argv: list[str], **kwargs) -> bytes:
                command = [os.fspath(item) for item in argv]
                if (
                    "load" in command
                    and option_value(command, "--root")
                    == self.persistent_root
                ):
                    self.commands.append(command)
                    raise stage.StagingError("persistent load primary")
                if (
                    "reset" in command
                    and option_value(command, "--root")
                    == self.persistent_root
                ):
                    self.commands.append(command)
                    raise stage.StagingError("persistent reset cleanup")
                return super().__call__(argv, **kwargs)

        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "combined-cleanup-root"
            install_workspace.mkdir()
            with patched_install_layout(install_workspace) as layout:
                runner = FailLoadAndReset(layout["PODMAN_ROOT"])
                with self.assertRaisesRegex(
                    stage.StagingError,
                    "persistent load primary.*persistent reset cleanup",
                ):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                reset_commands = [
                    command for command in runner.commands
                    if "reset" in command
                    and option_value(command, "--root")
                    == os.fspath(layout["PODMAN_ROOT"])
                ]
                self.assertEqual(len(reset_commands), 1)
                self.assertEqual(
                    option_value(reset_commands[0], "--runroot"),
                    os.fspath(layout["PODMAN_RUNROOT"]),
                )
                for name in (
                    "AUTHORITY_ROOT", "OPERATOR_ROOT", "CONFIG_PATH",
                    "UNIT_PATH", "UNIT_DROPIN_DIRECTORY", "INSTALLATION_ROOT",
                    "STATE_ROOT",
                    "PODMAN_ROOT", "PODMAN_RUNROOT",
                ):
                    self.assertFalse(layout[name].exists(), name)

    def test_private_verify_reports_primary_and_reset_cleanup_failures(self) -> None:
        assert stage is not None

        class FailSemanticAndReset(FakeCommandRunner):
            def __call__(self, argv: list[str], **kwargs) -> bytes:
                command = [os.fspath(item) for item in argv]
                joined = " ".join(command)
                self.commands.append(command)
                if "CODESKEPTIC_STAGING_STATIC_AUTHORITIES_OK" in joined:
                    raise stage.StagingError("semantic primary")
                if "reset" in command:
                    raise stage.StagingError("private reset cleanup")
                # Avoid appending the successful commands twice.
                self.commands.pop()
                return super().__call__(argv, **kwargs)

        with sealed_bundle_fixture() as fixture:
            _workspace, _prepared, _revision, sealed, _receipt = fixture
            with self.assertRaisesRegex(
                stage.StagingError,
                "semantic primary.*private reset cleanup",
            ):
                stage.verify_bundle(
                    sealed,
                    **bundle_authority(sealed),
                    command_runner=FailSemanticAndReset(),
                )

    def test_install_rejects_wrong_base_authority_without_mutating_it(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "base-collision-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner()
            with patched_install_layout(install_workspace) as layout:
                base = layout["AUTHORITY_ROOT"].parent
                base.mkdir(parents=True)
                base.chmod(0o700)
                with self.assertRaisesRegex(
                    stage.StagingError, "base authority"
                ):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(base.stat().st_mode & 0o777, 0o700)
                self.assertEqual(runner.commands, [])

    def test_install_loads_only_the_sealed_archive_and_rejects_image_id_drift(self) -> None:
        assert stage is not None
        self.assertTrue(
            hasattr(stage, "install_bundle"),
            "install lifecycle implementation is missing",
        )
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "image-drift-root"
            install_workspace.mkdir()
            runner = FakeCommandRunner(image_id="sha256:" + "f" * 64)
            with patched_install_layout(install_workspace) as layout:
                with self.assertRaises(stage.StagingError):
                    stage.install_bundle(
                        sealed,
                        **bundle_authority(sealed),
                        command_runner=runner,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertFalse(layout["INSTALLATION_RECEIPT_PATH"].exists())
                self.assertFalse(layout["AUTHORITY_ROOT"].exists())
                self.assertFalse(layout["OPERATOR_ROOT"].exists())
                self.assertFalse(layout["CONFIG_PATH"].exists())
                self.assertFalse(layout["UNIT_PATH"].exists())
                self.assertFalse(layout["UNIT_DROPIN_DIRECTORY"].exists())
                self.assertFalse(layout["INSTALLATION_ROOT"].exists())
                self.assertFalse(layout["STATE_ROOT"].exists())
                self.assertFalse(layout["PODMAN_ROOT"].exists())
                self.assertFalse(layout["PODMAN_RUNROOT"].exists())

                load_commands = [
                    command for command in runner.commands if "load" in command
                ]
                self.assertEqual(len(load_commands), 1)
                load = load_commands[0]
                archive_input = option_value(load, "--input")
                self.assertIsNotNone(archive_input)
                self.assertNotEqual(
                    archive_input,
                    os.fspath(sealed / "image" / stage.PINNED_ARCHIVE_NAME),
                )
                self.assertTrue(
                    archive_input.endswith("/image/" + stage.PINNED_ARCHIVE_NAME)
                )
                podman_commands = [
                    command
                    for command in runner.commands
                    if command and Path(command[0]).name == "podman"
                ]
                self.assertTrue(podman_commands)
                for command in podman_commands:
                    self.assertNotEqual(
                        option_value(command, "--root"),
                        os.fspath(layout["PODMAN_ROOT"]),
                    )
                    self.assertNotEqual(
                        option_value(command, "--runroot"),
                        os.fspath(layout["PODMAN_RUNROOT"]),
                    )
                    self.assertNotIn("pull", command)

    def test_service_unit_is_static_and_only_canonical_dropin_is_accepted(self) -> None:
        assert stage is not None
        source = UNIT.read_text(encoding="utf-8")
        self.assertEqual(
            TIMEOUT_OVERRIDE.read_bytes(),
            b"[Service]\nTimeoutStopFailureMode=terminate\n",
        )
        self.assertIn("Delegate=cpu cpuset memory pids", source.splitlines())
        self.assertNotIn("Delegate=yes", source.splitlines())
        self.assertIn(
            "Delegate=cpu cpuset memory pids",
            stage.STABILITY_UNIT_REQUIRED_LINES,
        )
        stage.verify_static_unit(UNIT)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            drifted = workspace / UNIT.name
            drifted.write_text(
                UNIT.read_text(encoding="utf-8")
                + "\n[Install]\nWantedBy=multi-user.target\n",
                encoding="utf-8",
            )
            with self.assertRaises(stage.StagingError):
                stage.verify_static_unit(drifted)

            lifecycle_mutations = (
                (
                    "Before=shutdown.target rescue.target emergency.target",
                    "Before=shutdown.target",
                ),
                (
                    "Conflicts=shutdown.target rescue.target emergency.target",
                    "Conflicts=shutdown.target",
                ),
                ("IgnoreOnIsolate=yes", "IgnoreOnIsolate=no"),
                ("Type=exec", "Type=oneshot"),
                (
                    "ExecStartPre=/opt/codeskeptic-p10-09/operator/"
                    "post-stop.sh --startup-recovery",
                    "ExecStartPre=/bin/true",
                ),
                (
                    "ExecStopPost=/opt/codeskeptic-p10-09/operator/post-stop.sh",
                    "ExecStopPost=/bin/true",
                ),
                ("--what=sleep", "--what=shutdown:sleep"),
                ("KillMode=control-group", "KillMode=process"),
                ("TimeoutStopSec=2min", "TimeoutStopSec=infinity"),
                ("Delegate=cpu cpuset memory pids", "Delegate=yes"),
                ("DelegateSubgroup=controller", "DelegateSubgroup=payload"),
                (
                    "StateDirectory=codeskeptic-p10-09",
                    "StateDirectory=elsewhere",
                ),
                ("ProtectControlGroups=no", "ProtectControlGroups=yes"),
            )
            for expected, replacement in lifecycle_mutations:
                with self.subTest(expected=expected):
                    self.assertIn(expected, source)
                    drifted.write_text(
                        source.replace(expected, replacement, 1),
                        encoding="utf-8",
                    )
                    with self.assertRaises(stage.StagingError):
                        stage.verify_static_unit(drifted)

            for forbidden in (
                "ConditionKernelCommandLine=systemd.unit=multi-user.target",
                "Conflicts=graphical.target",
                "[Install]\nWantedBy=multi-user.target",
            ):
                with self.subTest(forbidden=forbidden):
                    drifted.write_text(
                        source + f"\n{forbidden}\n", encoding="utf-8"
                    )
                    with self.assertRaises(stage.StagingError):
                        stage.verify_static_unit(drifted)

            with self.assertRaises(stage.StagingError):
                stage.verify_static_unit(TIMEOUT_OVERRIDE)

    def test_image_provisioning_is_archive_only_pinned_and_never_pulls(self) -> None:
        assert stage is not None
        source = PRODUCER.read_text(encoding="utf-8")
        self.assertIn("--pull=never", source)
        self.assertIn("image", source)
        self.assertIn("load", source)
        self.assertIn("archive_sha256", source)
        self.assertNotIn('"pull",', source)
        self.assertNotIn("'pull',", source)
        self.assertIn("PINNED_EVIDENCE_IMAGE", source)
        self.assertIn("PINNED_EVIDENCE_IMAGE_DIGEST", source)
        self.assertIn("PINNED_EVIDENCE_IMAGE_ID", source)
        self.assertLessEqual(stage.MAX_FILE_BYTES, 8 * 1024 * 1024 * 1024)

    def test_static_authority_verifier_has_ephemeral_ctest_write_mounts(
        self,
    ) -> None:
        assert stage is not None
        runner = FakeCommandRunner()
        runner.loaded = True
        stage._verify_static_authorities_in_image(
            [os.fspath(stage.PODMAN)],
            Path("/host/authority"),
            Path("/host/config/runtime.json"),
            runner,
        )
        command = runner.commands[-1]
        expected_mounts = {
            (
                "/authority/source/build/p10-09-sanitizers/"
                f"{profile}-tests/Testing/Temporary:rw,nosuid,nodev,"
                "size=16m,mode=1777"
            )
            for profile in stage.SANITIZER_PROFILES
        }
        self.assertEqual(command.count("--tmpfs"), len(expected_mounts))
        authority_mount = "/host/authority:/authority:ro"
        authority_index = command.index(authority_mount)
        for mount in expected_mounts:
            with self.subTest(mount=mount):
                self.assertEqual(command.count(mount), 1)
                self.assertEqual(command[command.index(mount) - 1], "--tmpfs")
                self.assertLess(authority_index, command.index(mount))

    def test_external_commands_and_rootful_probes_have_hard_bounds(self) -> None:
        assert stage is not None
        self.assertEqual(
            stage._external_output(
                [sys.executable, "-c", "print('bounded')"], 128,
                timeout_seconds=5,
            ),
            b"bounded\n",
        )
        with self.assertRaisesRegex(stage.StagingError, "oversized"):
            stage._external_output(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 65536)",
                ],
                32,
                timeout_seconds=5,
            )
        started = time.monotonic()
        with self.assertRaisesRegex(stage.StagingError, "timed out"):
            stage._external_output(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                32,
                timeout_seconds=1,
            )
        self.assertLess(time.monotonic() - started, 5)

        with self.assertRaisesRegex(stage.StagingError, "oversized"):
            stage._run_checked(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('y' * 65536)",
                ],
                maximum_output=32,
                timeout_seconds=5,
            )
        descendant_started = time.monotonic()
        with self.assertRaisesRegex(stage.StagingError, "timed out"):
            stage._run_checked(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,time; pid=os.fork(); "
                        "time.sleep(30) if pid == 0 else os._exit(0)"
                    ),
                ],
                maximum_output=32,
                timeout_seconds=1,
            )
        self.assertLess(time.monotonic() - descendant_started, 5)

        with tempfile.TemporaryDirectory() as temporary:
            child_pid_path = Path(temporary) / "closed-pipe-child.pid"
            closed_started = time.monotonic()
            with self.assertRaisesRegex(stage.StagingError, "timed out"):
                stage._run_checked(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,pathlib,time; pid=os.fork(); "
                            f"p=pathlib.Path({str(child_pid_path)!r}); "
                            "(p.write_text(str(os.getpid())), os.close(1), "
                            "os.close(2), time.sleep(30)) if pid == 0 "
                            "else os._exit(0)"
                        ),
                    ],
                    maximum_output=32,
                    timeout_seconds=1,
                )
            self.assertLess(time.monotonic() - closed_started, 5)
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            try:
                child_state = (
                    Path(f"/proc/{child_pid}/stat")
                    .read_text(encoding="ascii")
                    .split(")", 1)[1]
                    .split()[0]
                )
            except FileNotFoundError:
                child_state = "gone"
            self.assertIn(child_state, {"gone", "Z"})

        symbolic_result = subprocess.CompletedProcess(
            ["/usr/bin/git"], 1, b"", b""
        )
        with mock.patch.object(
            stage, "_bounded_command", return_value=symbolic_result
        ) as bounded:
            self.assertEqual(
                stage._git(ROOT, "symbolic-ref", "-q", "HEAD").returncode,
                1,
            )
        self.assertEqual(bounded.call_args.kwargs["timeout_seconds"], 300)
        self.assertEqual(
            bounded.call_args.kwargs["maximum_output"],
            stage.MAX_DOCUMENT_BYTES,
        )

        with sealed_bundle_fixture() as fixture:
            _workspace, _prepared, _revision, sealed, _receipt = fixture
            runner = FakeCommandRunner()
            stage.verify_bundle(
                sealed,
                command_runner=runner,
                **bundle_authority(sealed),
            )
            runs = [
                command for command in runner.commands
                if "--pull=never" in command
            ]
            self.assertTrue(runs)
            for command in runs:
                for token in (
                    "--cgroups=enabled", "--cpus=2",
                    "--memory=2147483648", "--memory-swap=2147483648",
                    "--pids-limit=128", "--ulimit=nofile=4096:4096",
                    "--cap-drop=all",
                ):
                    self.assertIn(token, command)

    @unittest.skipUnless(
        os.environ.get("CODESKEPTIC_STAGING_IMAGE_ARCHIVE"),
        "set CODESKEPTIC_STAGING_IMAGE_ARCHIVE for the retained-image gate",
    )
    def test_retained_image_archive_passes_real_offline_podman_gate(self) -> None:
        assert stage is not None
        archive = Path(
            os.environ["CODESKEPTIC_STAGING_IMAGE_ARCHIVE"]
        ).resolve()
        workspace = Path(tempfile.mkdtemp(
            prefix="codeskeptic-real-image-gate-", dir=archive.parent
        ))
        podman_root = workspace / "root"
        podman_runroot = workspace / "runtime" / "podman-runroot"
        ambient_cwd = workspace / "ambient-cwd"
        ambient_cwd.mkdir()

        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    stage.Path, "cwd", return_value=ambient_cwd
                ))
                stack.enter_context(
                    mock.patch.object(stage, "PODMAN_ROOT", podman_root)
                )
                stack.enter_context(
                    mock.patch.object(stage, "PODMAN_RUNROOT", podman_runroot)
                )
                stack.enter_context(
                    mock.patch.object(
                        stage,
                        "OPERATOR_ROOT",
                        ROOT / "scripts" / "stability-systemd",
                    )
                )
                with stage._fixed_podman_runroot(
                    os.getuid(), os.getgid()
                ) as first_runroot:
                    self.assertEqual(first_runroot, podman_runroot)
                    stage._load_and_verify_image_archive(
                        archive,
                        podman_root=podman_root,
                        podman_runroot=first_runroot,
                        hooks=stage.OPERATOR_ROOT,
                        storage_driver="overlay",
                        command_runner=None,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                )
                self.assertFalse(podman_runroot.exists())
                self.assertFalse(
                    (ambient_cwd / ".local").exists(),
                    "Podman must not write an ambient cwd HOME cache",
                )

                # Recreate the exact same lexical runroot after a cold-/warm-
                # style boundary and reopen the already populated root.
                with stage._fixed_podman_runroot(
                    os.getuid(), os.getgid()
                ) as reopened_runroot:
                    self.assertEqual(reopened_runroot, podman_runroot)
                    reopened = stage._podman_global_options(
                        podman_root,
                        reopened_runroot,
                        stage.OPERATOR_ROOT,
                        storage_driver="overlay",
                    )
                    stage._verify_pinned_image_store(
                        reopened, None, run_probe=True
                    )
                    stage._external_output(
                        [*reopened, "system", "reset", "--force"],
                        64 * 1024,
                        timeout_seconds=300,
                    )
                self.assertFalse(podman_runroot.exists())
        finally:
            if workspace.exists():
                stage._remove_private_tree(workspace)
        self.assertFalse(workspace.exists())

    def test_guided_entrypoint_binds_execution_to_out_of_band_install_authority(
        self,
    ) -> None:
        guided = GUIDED.read_text(encoding="utf-8")
        self.assertIn(
            'readonly STAGING_TOOL_PATH="${OPERATOR_ROOT}/stage_stability_campaign.py"',
            guided,
        )
        self.assertIn("INSTALLATION_RECEIPT_PATH=", guided)
        self.assertIn(
            'readonly INSTALLATION_AUTHORITY_PATH="/var/lib/'
            'codeskeptic-p10-09/installation-authority.json"',
            guided,
        )
        for token in (
            '"$PYTHON" -B - "$INSTALLATION_AUTHORITY_PATH"',
            '"codeskeptic-stability-installation-authority-v1"',
            '"$PYTHON" -B "$STAGING_TOOL_PATH" verify-install-filesystem',
            '--receipt "$INSTALLATION_RECEIPT_PATH"',
            '--expected-revision "$expected_revision"',
            '--expected-bundle-receipt-sha256 '
            '"$expected_bundle_receipt_sha"',
        ):
            self.assertIn(token, " ".join(guided.split()))
        authority_parse = guided.index('installation_authority="$({')
        pure_verify = guided.index(
            '"$PYTHON" -B "$STAGING_TOOL_PATH" verify-install-filesystem'
        )
        startup_recovery = guided.index(
            '"$POST_STOP_PATH" --startup-recovery'
        )
        guided_lock = guided.index(
            '"$HOST_RECOVERY_PATH" lock-guided --mode "$guided_mode"'
        )
        inherited_lock = guided.index(
            '"$HOST_RECOVERY_PATH" validate-guided-lock '
            '--fd "$guided_lock_fd"'
        )
        service_start = guided.index(
            '"$SYSTEMCTL" start --no-block "$SERVICE_UNIT"'
        )
        self.assertLess(authority_parse, pure_verify)
        self.assertLess(pure_verify, guided_lock)
        self.assertLess(guided_lock, inherited_lock)
        self.assertLess(guided_lock, startup_recovery)
        self.assertLess(startup_recovery, service_start)
        self.assertNotIn(
            '"$PYTHON" -B "$STAGING_TOOL_PATH" verify-install \\\n',
            guided,
        )
        self.assertIn(
            'readonly MIGRATION_ACTIVE_PATH="/var/lib/'
            'codeskeptic-p10-09-migration/active"',
            guided,
        )
        self.assertIn(
            '[[ ! -e "$MIGRATION_ACTIVE_PATH" '
            '&& ! -L "$MIGRATION_ACTIVE_PATH" ]]',
            guided,
        )
        recovery = HOST_RECOVERY.read_text(encoding="utf-8")
        self.assertIn('GUIDED_LIFECYCLE_LOCK = STATE_ROOT / "guided.lock"', recovery)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', recovery)
        self.assertIn('fcntl.LOCK_EX | fcntl.LOCK_NB', recovery)
        self.assertNotIn('flock --unlock', guided)
        self.assertNotIn('rm -- "$GUIDED_LOCK_PATH"', guided)

        operator = AUTHORITATIVE.read_text(encoding="utf-8")
        for token in (
            "verify_runtime_source_and_policy(config)",
            "verify_runtime_static_authorities(config, policy)",
            "verify_runtime_static_authority_identities(config, authorities)",
        ):
            self.assertIn(token, operator)

    def test_install_migration_contract_is_explicitly_receipt_bound(self) -> None:
        assert stage is not None
        self.assertTrue(
            hasattr(stage, "migrate_installation"),
            "the fixed installation has no audited migration lifecycle",
        )
        parser = stage.build_parser()
        arguments = parser.parse_args([
            "migrate-install",
            "--bundle", "/sealed",
            "--current-revision", "1" * 40,
            "--current-bundle-receipt-sha256", "2" * 64,
            "--current-producer-sha256", "3" * 64,
            "--expected-revision", "4" * 40,
            "--expected-bundle-receipt-sha256", "5" * 64,
            "--temporary-root", "/temporary",
        ])
        self.assertEqual(arguments.command, "migrate-install")
        self.assertEqual(arguments.current_revision, "1" * 40)
        self.assertEqual(
            arguments.current_bundle_receipt_sha256, "2" * 64
        )
        self.assertEqual(arguments.current_producer_sha256, "3" * 64)
        self.assertEqual(arguments.expected_revision, "4" * 40)
        self.assertEqual(
            arguments.expected_bundle_receipt_sha256, "5" * 64
        )

    def test_migration_capacity_uses_one_aggregate_fixed_filesystem_gate(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as _layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                control_root = (
                    install_workspace / "etc/systemd/system.control"
                )
                requirements = mock.patch.object(
                    stage,
                    "_bundle_temporary_requirement",
                    side_effect=(
                        lambda *_args, include_snapshot: (
                            20 if include_snapshot else 30
                        )
                    ),
                )
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root
                    ),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=10
                    ),
                    requirements,
                    mock.patch.object(
                        stage, "_temporary_available_bytes", return_value=59
                    ),
                    self.assertRaisesRegex(
                        stage.StagingError, "insufficient free space"
                    ),
                ):
                    stage._verify_migration_capacity(bundle, temporary_root)
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root
                    ),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=10
                    ),
                    mock.patch.object(
                        stage,
                        "_bundle_temporary_requirement",
                        side_effect=(
                            lambda *_args, include_snapshot: (
                                20 if include_snapshot else 30
                            )
                        ),
                    ),
                    mock.patch.object(
                        stage, "_temporary_available_bytes", return_value=60
                    ) as available,
                ):
                    stage._verify_migration_capacity(bundle, temporary_root)
                available.assert_called_once_with(temporary_root)

    def test_migration_capacity_rejects_split_device_topology(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                control_root = (
                    install_workspace / "etc/systemd/system.control"
                )
                split_root = layout["AUTHORITY_ROOT"].parent.parent
                real_lstat = Path.lstat

                def split_device(path: Path, *args, **kwargs):
                    metadata = real_lstat(path, *args, **kwargs)
                    if path == split_root:
                        values = list(metadata)
                        values[2] = metadata.st_dev + 1
                        return os.stat_result(values)
                    return metadata

                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root
                    ),
                    mock.patch.object(Path, "lstat", new=split_device),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=10
                    ),
                    mock.patch.object(
                        stage,
                        "_bundle_temporary_requirement",
                        return_value=20,
                    ),
                    mock.patch.object(
                        stage, "_temporary_available_bytes", return_value=1000
                    ),
                    self.assertRaisesRegex(
                        stage.StagingError, "share one filesystem"
                    ),
                ):
                    stage._verify_migration_capacity(bundle, temporary_root)

    def test_migration_rejects_absent_control_parent_device_drift_before_lock(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as _layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                control_root = (
                    install_workspace / "etc/systemd/system.control"
                )
                self.assertFalse(control_root.exists())
                split_root = control_root.parent
                real_lstat = Path.lstat

                def split_device(path: Path, *args, **kwargs):
                    metadata = real_lstat(path, *args, **kwargs)
                    if path == split_root:
                        values = list(metadata)
                        values[2] = metadata.st_dev + 1
                        return os.stat_result(values)
                    return metadata

                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root
                    ),
                    mock.patch.object(Path, "lstat", new=split_device),
                    mock.patch.object(stage, "verify_bundle", return_value={}),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=10
                    ),
                    mock.patch.object(
                        stage,
                        "_bundle_temporary_requirement",
                        return_value=20,
                    ),
                    mock.patch.object(
                        stage, "_temporary_available_bytes", return_value=1000
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_lock",
                        side_effect=stage.StagingError("migration lock reached"),
                    ) as migration_lock,
                    self.assertRaisesRegex(
                        stage.StagingError, "share one filesystem"
                    ),
                ):
                    stage.migrate_installation(
                        bundle,
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        expected_revision="4" * 40,
                        expected_bundle_receipt_sha256="5" * 64,
                        temporary_root=temporary_root,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                migration_lock.assert_not_called()
                self.assertFalse(migration_root.exists())

    def test_migration_rejects_existing_control_root_device_drift_before_lock(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as _layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                control_root = (
                    install_workspace / "etc/systemd/system.control"
                )
                control_root.mkdir(mode=0o755)
                split_root = control_root
                real_lstat = Path.lstat

                def split_device(path: Path, *args, **kwargs):
                    metadata = real_lstat(path, *args, **kwargs)
                    if path == split_root:
                        values = list(metadata)
                        values[2] = metadata.st_dev + 1
                        return os.stat_result(values)
                    return metadata

                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root
                    ),
                    mock.patch.object(Path, "lstat", new=split_device),
                    mock.patch.object(stage, "verify_bundle", return_value={}),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=10
                    ),
                    mock.patch.object(
                        stage,
                        "_bundle_temporary_requirement",
                        return_value=20,
                    ),
                    mock.patch.object(
                        stage, "_temporary_available_bytes", return_value=1000
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_lock",
                        side_effect=stage.StagingError("migration lock reached"),
                    ) as migration_lock,
                    self.assertRaisesRegex(
                        stage.StagingError, "share one filesystem"
                    ),
                ):
                    stage.migrate_installation(
                        bundle,
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        expected_revision="4" * 40,
                        expected_bundle_receipt_sha256="5" * 64,
                        temporary_root=temporary_root,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                migration_lock.assert_not_called()
                self.assertFalse(migration_root.exists())

    def test_migration_rejects_noncanonical_temporary_root_before_verify(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            bundle = workspace / "sealed"
            bundle.mkdir()
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            temporary_root = workspace / "home/migration-temporary"
            temporary_root.mkdir(parents=True, mode=0o700)
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "verify_bundle") as verify_bundle,
                mock.patch.object(stage, "_verify_migration_capacity"),
                mock.patch.object(
                    stage,
                    "_migration_lock",
                    side_effect=stage.StagingError("migration lock reached"),
                ) as migration_lock,
                self.assertRaisesRegex(
                    stage.StagingError, "exact canonical sibling"
                ),
            ):
                stage.migrate_installation(
                    bundle,
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    current_producer_sha256="3" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    temporary_root=temporary_root,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            verify_bundle.assert_not_called()
            migration_lock.assert_not_called()

    def test_migration_pins_temporary_root_across_bundle_verification(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            bundle = workspace / "sealed"
            bundle.mkdir()
            migration_root = workspace / "migration"
            temporary_root = workspace / "migration-temporary"
            temporary_root.mkdir(mode=0o700)
            displaced_root = workspace / "displaced-migration-temporary"

            def replace_temporary_root(*_args, **_kwargs):
                temporary_root.rename(displaced_root)
                temporary_root.mkdir(mode=0o700)
                return {}

            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(
                    stage,
                    "verify_bundle",
                    side_effect=replace_temporary_root,
                ) as verify_bundle,
                mock.patch.object(stage, "_verify_migration_capacity"),
                mock.patch.object(
                    stage,
                    "_migration_lock",
                    side_effect=stage.StagingError("migration lock reached"),
                ) as migration_lock,
                self.assertRaisesRegex(
                    stage.StagingError, "temporary root identity changed"
                ),
            ):
                stage.migrate_installation(
                    bundle,
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    current_producer_sha256="3" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    temporary_root=temporary_root,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            verify_bundle.assert_called_once()
            migration_lock.assert_not_called()

    def test_migration_rejects_writable_temporary_parent_before_verify(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            bundle = workspace / "sealed"
            bundle.mkdir()
            migration_parent = workspace / "var-lib"
            migration_parent.mkdir(mode=0o700)
            migration_parent.chmod(0o777)
            migration_root = migration_parent / "migration"
            temporary_root = (
                migration_parent / f"{migration_root.name}-temporary"
            )
            temporary_root.mkdir(mode=0o700)
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "verify_bundle") as verify_bundle,
                self.assertRaisesRegex(
                    stage.StagingError, "parent is not root-controlled"
                ),
            ):
                stage.migrate_installation(
                    bundle,
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    current_producer_sha256="3" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    temporary_root=temporary_root,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            verify_bundle.assert_not_called()

    def test_install_migration_rehomes_exact_roots_and_retains_backup(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                migration_lock = (
                    install_workspace
                    / "run/codeskeptic-p10-09-migration.lock"
                )
                control_root = install_workspace / "etc/systemd/system.control"
                control_root.mkdir(parents=True)
                control_mask = control_root / UNIT.name
                fixed = {
                    "opt": layout["AUTHORITY_ROOT"].parent,
                    "config": layout["CONFIG_PATH"].parent,
                    "state": layout["STATE_ROOT"],
                    "unit": layout["UNIT_PATH"],
                    "dropin": layout["UNIT_DROPIN_DIRECTORY"],
                }
                for name, path in fixed.items():
                    if name == "unit":
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("old unit\n", encoding="utf-8")
                    elif name == "opt":
                        path.mkdir(parents=True, exist_ok=True)
                        for child in ("authority", "operator", "installation"):
                            (path / child).mkdir()
                        (path / "authority" / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )
                    else:
                        path.mkdir(parents=True, exist_ok=True)
                        (path / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )

                def install_target(_bundle, **_kwargs):
                    for name, path in fixed.items():
                        self.assertFalse(path.exists(), name)
                        if name == "unit":
                            path.write_text("new unit\n", encoding="utf-8")
                        elif name == "opt":
                            path.mkdir()
                            for child in (
                                "authority", "operator", "installation"
                            ):
                                (path / child).mkdir()
                            (path / "authority" / "new-marker").write_text(
                                name + "\n", encoding="utf-8"
                            )
                            layout["INSTALLATION_RECEIPT_PATH"].write_text(
                                '{"fixture":"target"}\n', encoding="utf-8"
                            )
                        else:
                            path.mkdir()
                            (path / "new-marker").write_text(
                                name + "\n", encoding="utf-8"
                            )
                    return {
                        "bundle_revision": "4" * 40,
                        "bundle_receipt_sha256": "5" * 64,
                    }

                patches = (
                    mock.patch.object(
                        stage, "MIGRATION_ROOT", migration_root, create=True
                    ),
                    mock.patch.object(
                        stage, "MIGRATION_LOCK_PATH", migration_lock, create=True
                    ),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root, create=True
                    ),
                    mock.patch.object(
                        stage, "MIGRATION_MASK_PATH", control_mask, create=True
                    ),
                    mock.patch.object(stage, "verify_bundle", return_value={}),
                    mock.patch.object(
                        stage, "_regular_tree_size", return_value=1
                    ),
                    mock.patch.object(
                        stage,
                        "_bundle_temporary_requirement",
                        return_value=1,
                    ),
                    mock.patch.object(
                        stage,
                        "_verify_current_installation_with_producer",
                        return_value={},
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_verify_migration_systemd_version",
                        return_value=stage.MIGRATION_SYSTEMD_VERSION,
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_service_guard",
                        return_value=contextlib.nullcontext(),
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_guided_lock",
                        return_value=contextlib.nullcontext(),
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_run_current_recovery_gates",
                        create=True,
                    ),
                    mock.patch.object(
                        stage, "install_bundle", side_effect=install_target
                    ),
                )
                with contextlib.ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    result = stage.migrate_installation(
                        bundle,
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        expected_revision="4" * 40,
                        expected_bundle_receipt_sha256="5" * 64,
                        temporary_root=temporary_root,
                        require_root=False,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(result, {
                    "bundle_revision": "4" * 40,
                    "bundle_receipt_sha256": "5" * 64,
                })
                for name, path in fixed.items():
                    self.assertTrue(path.exists(), name)
                    backup = migration_root / "backup" / name
                    self.assertTrue(backup.exists(), name)
                    marker = (
                        backup.read_text(encoding="utf-8")
                        if name == "unit"
                        else (
                            backup
                            / ("authority/old-marker" if name == "opt" else "old-marker")
                        ).read_text(encoding="utf-8")
                    )
                    self.assertEqual(marker, "old unit\n" if name == "unit" else name + "\n")
                self.assertTrue((migration_root / "plan.json").is_file())
                self.assertTrue((migration_root / "success.json").is_file())
                self.assertFalse((migration_root / "active").exists())
                self.assertTrue((migration_root / "retired").is_file())

    def test_migration_capacity_failure_precedes_lock_and_journal(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            bundle = workspace / "bundle"
            bundle.mkdir()
            migration_root = workspace / "migration"
            temporary_root = workspace / f"{migration_root.name}-temporary"
            temporary_root.mkdir(mode=0o700)
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "verify_bundle", return_value={}),
                mock.patch.object(
                    stage,
                    "_verify_migration_capacity",
                    side_effect=stage.StagingError("insufficient migration capacity"),
                ),
                mock.patch.object(stage, "_migration_lock") as migration_lock,
                self.assertRaisesRegex(
                    stage.StagingError, "insufficient migration capacity"
                ),
            ):
                stage.migrate_installation(
                    bundle,
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    current_producer_sha256="3" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    temporary_root=temporary_root,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            migration_lock.assert_not_called()
            self.assertFalse(migration_root.exists())

    def test_locked_capacity_recheck_closes_pinned_old_nodes(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            bundle = workspace / "bundle"
            bundle.mkdir()
            migration_root = workspace / "migration"
            temporary_root = workspace / f"{migration_root.name}-temporary"
            temporary_root.mkdir(mode=0o700)
            nodes = [{"fixture": "identity-pinned old roots"}]
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "verify_bundle", return_value={}),
                mock.patch.object(
                    stage,
                    "_verify_migration_capacity",
                    side_effect=(
                        None,
                        stage.StagingError("locked capacity recheck failed"),
                    ),
                ),
                mock.patch.object(
                    stage,
                    "_migration_lock",
                    return_value=contextlib.nullcontext(),
                ),
                mock.patch.object(
                    stage,
                    "_migration_guided_lock",
                    return_value=contextlib.nullcontext(),
                ),
                mock.patch.object(
                    stage, "_verify_current_installation_with_producer"
                ),
                mock.patch.object(stage, "_run_current_recovery_gates"),
                mock.patch.object(
                    stage,
                    "_verify_migration_systemd_version",
                    return_value=stage.MIGRATION_SYSTEMD_VERSION,
                ),
                mock.patch.object(
                    stage, "_migration_source_nodes", return_value=nodes
                ),
                mock.patch.object(stage, "_migration_plan", return_value={}),
                mock.patch.object(
                    stage, "_prepare_migration_transaction"
                ) as prepare_transaction,
                mock.patch.object(
                    stage, "_close_migration_nodes"
                ) as close_nodes,
                self.assertRaisesRegex(
                    stage.StagingError, "locked capacity recheck failed"
                ),
            ):
                stage.migrate_installation(
                    bundle,
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    current_producer_sha256="3" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    temporary_root=temporary_root,
                    require_root=False,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            prepare_transaction.assert_not_called()
            close_nodes.assert_called_once_with(nodes)

    def test_migration_rejects_unpinned_or_misreporting_old_producer(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            operator = workspace / "operator"
            operator.mkdir()
            producer = operator / "stage_stability_campaign.py"
            producer.write_bytes(b"# exact installed producer fixture\n")
            producer.chmod(0o555)
            receipt = workspace / "installation/receipt.json"
            current_sha = hashlib.sha256(producer.read_bytes()).hexdigest()
            with (
                mock.patch.object(stage, "OPERATOR_ROOT", operator),
                mock.patch.object(
                    stage, "INSTALLATION_RECEIPT_PATH", receipt
                ),
            ):
                with self.assertRaisesRegex(
                    stage.StagingError, "producer authority drift"
                ):
                    stage._verify_current_installation_with_producer(
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        command_runner=lambda *_args, **_kwargs: b"unused\n",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                with self.assertRaisesRegex(
                    stage.StagingError, "verification output drift"
                ):
                    stage._verify_current_installation_with_producer(
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256=current_sha,
                        command_runner=lambda *_args, **_kwargs: b"wrong\n",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )

    def test_migration_install_failure_quarantines_all_created_targets(self) -> None:
        assert stage is not None
        with sealed_bundle_fixture() as fixture:
            workspace, _prepared, _revision, sealed, _receipt = fixture
            install_workspace = workspace / "migration-install-root"
            install_workspace.mkdir()
            temporary_root = workspace / "migration-temporary"
            temporary_root.mkdir(mode=0o700)
            migration_root = workspace / "migration-journal"
            runner = FakeCommandRunner()
            with patched_install_layout(install_workspace) as layout:
                real_load = stage._load_and_verify_image_archive

                def fail_only_persistent_store(*args, **kwargs):
                    if kwargs.get("podman_root") == layout["PODMAN_ROOT"]:
                        raise stage.StagingError(
                            "simulated persistent image-store failure"
                        )
                    return real_load(*args, **kwargs)

                with mock.patch.object(stage, "MIGRATION_ROOT", migration_root):
                    transaction = stage._prepare_migration_transaction(
                        {"fixture": "installer-target-ledger"},
                        os.getuid(),
                        os.getgid(),
                    )
                    with (
                        mock.patch.object(
                            stage,
                            "_load_and_verify_image_archive",
                            side_effect=fail_only_persistent_store,
                        ),
                        self.assertRaisesRegex(
                            stage.StagingError,
                            "simulated persistent image-store failure",
                        ) as caught,
                    ):
                        stage.install_bundle(
                            sealed,
                            **bundle_authority(sealed),
                            command_runner=runner,
                            require_root=False,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                            temporary_root=temporary_root,
                            migration_transaction_nodes=transaction,
                        )
                    records = stage._load_migration_target_records(
                        owner_uid=os.getuid(), owner_gid=os.getgid()
                    )
                    quarantined = sorted(
                        path.name
                        for path in (migration_root / "failed-targets").iterdir()
                    )
                    failed_metadata = (
                        migration_root / "failed-targets"
                    ).lstat()
                    diagnostic = (
                        f"error={caught.exception}; "
                        f"records={[record['path'] for record in records]}; "
                        f"quarantined={quarantined}; "
                        f"failed-targets-mode="
                        f"{stat.S_IMODE(failed_metadata.st_mode):04o}; "
                        f"failed-targets-owner="
                        f"{failed_metadata.st_uid}:{failed_metadata.st_gid}"
                    )
                    for path in (
                        layout["AUTHORITY_ROOT"].parent,
                        layout["CONFIG_PATH"].parent,
                        layout["STATE_ROOT"],
                        layout["UNIT_PATH"],
                        layout["UNIT_DROPIN_DIRECTORY"],
                    ):
                        self.assertFalse(
                            path.exists() or path.is_symlink(),
                            f"{path}: {diagnostic}",
                        )
                    self.assertGreater(len(records), 5)
                    self.assertEqual(
                        quarantined,
                        [f"{record['index']:04d}" for record in records],
                    )
                    stage._rollback_created(transaction)
                self.assertFalse(migration_root.exists())

    def test_migration_journal_publishes_only_as_one_complete_tree(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/codeskeptic-p10-09-migration"
            migration_root.parent.mkdir(parents=True)
            observed = False
            original_rename = stage._rename_noreplace

            def interrupt_at_publication(source, destination):
                nonlocal observed
                if destination == migration_root:
                    observed = True
                    self.assertNotEqual(source, migration_root)
                    self.assertFalse(migration_root.exists())
                    self.assertEqual(
                        {path.name for path in source.iterdir()},
                        {
                            "active", "backup", "failed-targets", "fence",
                            "moves", "plan.json", "publication-staging",
                            "targets",
                        },
                    )
                    self.assertEqual(
                        os.readlink(source / "fence" / "mask-anchor"),
                        "/dev/null",
                    )
                    self.assertEqual(
                        (source / "active").read_bytes(),
                        b"codeskeptic-installation-migration-active-v1\n",
                    )
                    raise KeyboardInterrupt("simulated power loss before publish")
                return original_rename(source, destination)

            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(
                    stage, "_rename_noreplace", side_effect=interrupt_at_publication
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                stage._prepare_migration_transaction(
                    {"fixture": "complete-before-publication"},
                    os.getuid(),
                    os.getgid(),
                )
            self.assertTrue(observed)
            self.assertFalse(migration_root.exists())
            self.assertEqual(list(migration_root.parent.iterdir()), [])

    def test_rollback_journal_quarantine_crash_does_not_block_a_new_migration(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/codeskeptic-p10-09-migration"
            migration_root.parent.mkdir(parents=True)
            quarantine = (
                migration_root.parent / ".codeskeptic-cleanup-simulated"
            )
            with mock.patch.object(stage, "MIGRATION_ROOT", migration_root):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "atomic-rollback-removal"},
                    os.getuid(),
                    os.getgid(),
                )
                root_records = [
                    record for record in transaction
                    if record.path == migration_root and record.is_directory
                ]
                self.assertEqual(len(root_records), 1)
                root_record = root_records[0]
                with self.assertRaisesRegex(
                    stage.StagingError,
                    "rolled-back migration journal identity drift",
                ):
                    stage._remove_rolled_back_migration_root(
                        os.getuid(),
                        os.getgid(),
                        expected_identity=(
                            root_record.device,
                            root_record.inode + 1,
                        ),
                    )
                self.assertTrue(migration_root.is_dir())

                def interrupt_after_quarantine(
                    path, device, inode, is_directory,
                ):
                    self.assertEqual(path, migration_root)
                    self.assertEqual(
                        (device, inode, is_directory),
                        (root_record.device, root_record.inode, True),
                    )
                    os.rename(migration_root, quarantine)
                    stage._fsync_directory(migration_root.parent)
                    raise KeyboardInterrupt(
                        "simulated power loss after journal quarantine"
                    )

                with (
                    mock.patch.object(
                        stage,
                        "_remove_created_identity",
                        side_effect=interrupt_after_quarantine,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    stage._remove_rolled_back_migration_root(
                        os.getuid(),
                        os.getgid(),
                        expected_identity=(
                            root_record.device,
                            root_record.inode,
                        ),
                    )

                self.assertFalse(migration_root.exists())
                self.assertTrue(quarantine.is_dir())
                stage._release_created(transaction)

                next_transaction = stage._prepare_migration_transaction(
                    {"fixture": "after-atomic-rollback-removal"},
                    os.getuid(),
                    os.getgid(),
                )
                next_root = next(
                    record for record in next_transaction
                    if record.path == migration_root and record.is_directory
                )
                stage._remove_rolled_back_migration_root(
                    os.getuid(),
                    os.getgid(),
                    expected_identity=(next_root.device, next_root.inode),
                )
                stage._release_created(next_transaction)

                quarantine_metadata = quarantine.lstat()
                stage._remove_created_identity(
                    quarantine,
                    quarantine_metadata.st_dev,
                    quarantine_metadata.st_ino,
                    True,
                )
            self.assertEqual(list(migration_root.parent.iterdir()), [])

    def test_migration_publication_staging_is_journal_owned_across_crashes(
        self,
    ) -> None:
        assert stage is not None
        for crash_point in ("before-intent", "after-intent", "after-rename"):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                migration_root = workspace / "var/lib/migration"
                migration_root.parent.mkdir(parents=True)
                destination = workspace / "etc/systemd/system" / UNIT.name
                destination.parent.mkdir(parents=True)
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(stage, "UNIT_PATH", destination),
                ):
                    transaction = stage._prepare_migration_transaction(
                        {"fixture": crash_point},
                        os.getuid(),
                        os.getgid(),
                    )
                    root_record = next(
                        record for record in transaction
                        if record.path == migration_root and record.is_directory
                    )
                    ledger = stage._MigrationTargetLedger(
                        transaction, os.getuid(), os.getgid()
                    )
                    staged, staged_metadata, payload_descriptor = (
                        ledger.create_file_publication_staging(
                            destination,
                            ".codeskeptic-file-",
                            "crash-window fixture",
                        )
                    )
                    os.write(payload_descriptor, b"partial target\n")
                    os.fsync(payload_descriptor)
                    target_record = stage._CreatedNode(
                        destination,
                        staged_metadata.st_dev,
                        staged_metadata.st_ino,
                        False,
                        payload_descriptor,
                    )
                    if crash_point != "before-intent":
                        ledger.prepare_publication(target_record, staged)
                    if crash_point == "after-rename":
                        stage._rename_noreplace(staged, destination)
                        stage._fsync_directory(destination.parent)

                    target_record.close()
                    records = stage._load_migration_target_records(
                        owner_uid=os.getuid(), owner_gid=os.getgid()
                    )
                    stage._remove_recorded_partial_targets(records, [], {})
                    self.assertFalse(destination.exists())
                    if staged.exists():
                        self.assertEqual(
                            staged.parent,
                            migration_root / "publication-staging",
                        )

                    stage._remove_rolled_back_migration_root(
                        os.getuid(),
                        os.getgid(),
                        expected_identity=(
                            root_record.device,
                            root_record.inode,
                        ),
                    )
                    stage._release_created(transaction)
                self.assertFalse(migration_root.exists())
                self.assertFalse(any(
                    child.name.startswith(".codeskeptic-file-")
                    for child in destination.parent.iterdir()
                ))

    def test_directory_and_tree_preintent_staging_is_journal_owned(
        self,
    ) -> None:
        assert stage is not None
        cases = (
            ("directory", ".dropin.directory-"),
            ("tree", ".dropin.install-"),
        )
        for label, prefix in cases:
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temporary,
            ):
                workspace = Path(temporary)
                migration_root = workspace / "var/lib/migration"
                migration_root.parent.mkdir(parents=True)
                destination = workspace / "etc/systemd/system/dropin"
                destination.parent.mkdir(parents=True)
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "UNIT_DROPIN_DIRECTORY", destination
                    ),
                ):
                    transaction = stage._prepare_migration_transaction(
                        {"fixture": f"{label}-preintent"},
                        os.getuid(),
                        os.getgid(),
                    )
                    root_record = next(
                        record for record in transaction
                        if record.path == migration_root and record.is_directory
                    )
                    ledger = stage._MigrationTargetLedger(
                        transaction, os.getuid(), os.getgid()
                    )
                    staged, metadata, descriptor = (
                        ledger.create_publication_staging(
                            destination,
                            prefix,
                            f"{label} preintent fixture",
                        )
                    )
                    (staged / "partial").write_bytes(b"partial tree\n")
                    stage._fsync_tree(staged)
                    os.close(descriptor)
                    self.assertEqual(
                        (staged.lstat().st_dev, staged.lstat().st_ino),
                        (metadata.st_dev, metadata.st_ino),
                    )
                    self.assertEqual(
                        staged.parent,
                        migration_root / "publication-staging",
                    )
                    self.assertFalse(destination.exists())

                    stage._remove_rolled_back_migration_root(
                        os.getuid(),
                        os.getgid(),
                        expected_identity=(
                            root_record.device,
                            root_record.inode,
                        ),
                    )
                    stage._release_created(transaction)
                self.assertFalse(migration_root.exists())
                self.assertFalse(destination.exists())

    def test_cross_filesystem_publication_is_rejected_before_staging(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            destination = workspace / "etc/systemd/system" / UNIT.name
            destination.parent.mkdir(parents=True)
            destination.write_bytes(b"fixed target\n")
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "UNIT_PATH", destination),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "cross-filesystem-publication"},
                    os.getuid(),
                    os.getgid(),
                )
                ledger = stage._MigrationTargetLedger(
                    transaction, os.getuid(), os.getgid()
                )
                staging_root = migration_root / "publication-staging"
                with self.assertRaisesRegex(
                    stage.StagingError, "outside its target plan"
                ):
                    ledger.create_publication_staging(
                        destination,
                        ".codeskeptic-file-",
                        "forbidden wrapper fixture",
                    )
                real_verify = stage._verify_migration_owned_path

                def report_other_filesystem(path, **kwargs):
                    metadata = real_verify(path, **kwargs)
                    if path == staging_root:
                        values = list(metadata)
                        values[2] = metadata.st_dev + 1
                        return os.stat_result(values)
                    return metadata

                with (
                    mock.patch.object(
                        stage,
                        "_verify_migration_owned_path",
                        side_effect=report_other_filesystem,
                    ),
                    self.assertRaisesRegex(
                        stage.StagingError, "crosses a filesystem"
                    ),
                ):
                    ledger.create_file_publication_staging(
                        destination,
                        ".codeskeptic-file-",
                        "cross-filesystem fixture",
                    )
                self.assertEqual(destination.read_bytes(), b"fixed target\n")
                self.assertEqual(list(staging_root.iterdir()), [])
                stage._rollback_created(transaction)
            self.assertFalse(migration_root.exists())

    def test_cross_parent_publication_syncs_both_parents_before_commit(
        self,
    ) -> None:
        assert stage is not None
        for kind in ("file", "directory", "tree"):
            with (
                self.subTest(kind=kind),
                tempfile.TemporaryDirectory() as temporary,
            ):
                workspace = Path(temporary)
                migration_root = workspace / "var/lib/migration"
                migration_root.parent.mkdir(parents=True)
                destination = workspace / "etc/codeskeptic/dropin"
                destination.parent.mkdir(parents=True)
                source = workspace / "source"
                inventory = None
                if kind == "tree":
                    make_inventory_tree(source)
                    inventory = stage.collect_inventory(source)
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "UNIT_DROPIN_DIRECTORY", destination
                    ),
                ):
                    transaction = stage._prepare_migration_transaction(
                        {"fixture": f"{kind}-sync-order"},
                        os.getuid(),
                        os.getgid(),
                    )
                    ledger = stage._MigrationTargetLedger(
                        transaction, os.getuid(), os.getgid()
                    )
                    staging_root = migration_root / "publication-staging"
                    events: list[str] = []
                    original_rename = stage._rename_noreplace
                    original_fsync = stage._fsync_directory
                    original_append = stage._MigrationTargetLedger.append

                    def observe_rename(source_path, destination_path):
                        result = original_rename(
                            source_path, destination_path
                        )
                        if destination_path == destination:
                            events.append("rename")
                        return result

                    def observe_fsync(path):
                        result = original_fsync(path)
                        if "rename" in events:
                            if path == staging_root:
                                events.append("source-fsync")
                            elif path == destination.parent:
                                events.append("target-fsync")
                        return result

                    def observe_append(self, record):
                        if self is ledger:
                            events.append("commit")
                        return original_append(self, record)

                    with (
                        mock.patch.object(
                            stage,
                            "_rename_noreplace",
                            side_effect=observe_rename,
                        ),
                        mock.patch.object(
                            stage,
                            "_fsync_directory",
                            side_effect=observe_fsync,
                        ),
                        mock.patch.object(
                            stage._MigrationTargetLedger,
                            "append",
                            new=observe_append,
                        ),
                    ):
                        if kind == "file":
                            stage._write_new(
                                destination,
                                b"published file\n",
                                0o600,
                                owner_uid=os.getuid(),
                                owner_gid=os.getgid(),
                                created_nodes=ledger,
                            )
                        elif kind == "directory":
                            stage._create_directory_create_new(
                                destination,
                                0o500,
                                os.getuid(),
                                os.getgid(),
                                created_nodes=ledger,
                            )
                        else:
                            self.assertEqual(
                                stage.install_tree_create_new(
                                    source,
                                    destination,
                                    inventory,
                                    owner_uid=os.getuid(),
                                    owner_gid=os.getgid(),
                                    created_nodes=ledger,
                                ),
                                "created",
                            )
                    self.assertEqual(
                        events,
                        ["rename", "source-fsync", "target-fsync", "commit"],
                    )
                    ledger.rollback_publications()
                    stage._rollback_created(transaction)
                self.assertFalse(migration_root.exists())
                self.assertFalse(destination.exists())

    def test_normal_migration_success_requires_empty_publication_staging(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            receipt = workspace / "installation-receipt.json"
            receipt.write_bytes(b'{"fixture":"target"}\n')
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(
                    stage, "INSTALLATION_RECEIPT_PATH", receipt
                ),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "normal-success"},
                    os.getuid(),
                    os.getgid(),
                )
                stage._publish_migration_success(
                    {
                        "bundle_revision": "4" * 40,
                        "bundle_receipt_sha256": "5" * 64,
                    },
                    outcome="installed",
                    current_revision="1" * 40,
                    current_bundle_receipt_sha256="2" * 64,
                    expected_revision="4" * 40,
                    expected_bundle_receipt_sha256="5" * 64,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                    transaction_nodes=transaction,
                )
                self.assertTrue((migration_root / "success.json").is_file())
                self.assertEqual(
                    list((migration_root / "publication-staging").iterdir()),
                    [],
                )
                stage._rollback_created(transaction)
            self.assertFalse(migration_root.exists())

    def test_verified_target_check_preserves_unexpected_staging_inode(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            with mock.patch.object(stage, "MIGRATION_ROOT", migration_root):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "nonempty-publication-staging"},
                    os.getuid(),
                    os.getgid(),
                )
                staged = (
                    migration_root
                    / "publication-staging"
                    / (".codeskeptic-file-" + "b" * 32)
                )
                staged.write_bytes(b"unresolved payload\n")
                with self.assertRaisesRegex(
                    stage.StagingError,
                    "publication staging is not empty",
                ):
                    stage._verify_target_publication_staging_empty(
                        os.getuid(), os.getgid()
                    )
                self.assertEqual(staged.read_bytes(), b"unresolved payload\n")
                stage._rollback_created(transaction)
            self.assertFalse(migration_root.exists())

    def test_migration_target_journal_rejects_intent_commit_tamper(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = workspace / "migration"
                target = layout["UNIT_PATH"]
                staging = (
                    migration_root
                    / "publication-staging"
                    / (".codeskeptic-file-" + "a" * 32)
                )
                metadata = workspace.stat()
                intent = {
                    "schema": stage.INSTALLATION_MIGRATION_TARGET_SCHEMA,
                    "index": 0,
                    "path": target.as_posix(),
                    "staging": staging.as_posix(),
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "type": "file",
                    "phase": "intent",
                }
                commit = copy.deepcopy(intent)
                commit["phase"] = "commit"
                commit["inode"] += 1
                with mock.patch.object(stage, "MIGRATION_ROOT", migration_root):
                    transaction = stage._prepare_migration_transaction(
                        {"fixture": "target-journal-tamper"},
                        os.getuid(),
                        os.getgid(),
                    )
                    stage._write_migration_record(
                        migration_root / "targets/0000.intent.json",
                        stage.canonical_document(intent),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        created_nodes=transaction,
                    )
                    stage._write_migration_record(
                        migration_root / "targets/0000.commit.json",
                        stage.canonical_document(commit),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        created_nodes=transaction,
                    )
                    with self.assertRaisesRegex(
                        stage.StagingError, "commit differs from intent"
                    ):
                        stage._load_migration_target_records(
                            owner_uid=os.getuid(), owner_gid=os.getgid()
                        )
                    stage._rollback_created(transaction)
                self.assertFalse(migration_root.exists())

    def test_install_migration_restores_old_roots_after_install_failure(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                temporary_root = (
                    migration_root.parent / f"{migration_root.name}-temporary"
                )
                temporary_root.mkdir(mode=0o700)
                migration_lock = (
                    install_workspace
                    / "run/codeskeptic-p10-09-migration.lock"
                )
                control_root = install_workspace / "etc/systemd/system.control"
                control_root.mkdir(parents=True)
                control_mask = control_root / UNIT.name
                fixed = {
                    "opt": layout["AUTHORITY_ROOT"].parent,
                    "config": layout["CONFIG_PATH"].parent,
                    "state": layout["STATE_ROOT"],
                    "unit": layout["UNIT_PATH"],
                }
                for name, path in fixed.items():
                    if name == "unit":
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("old unit\n", encoding="utf-8")
                    elif name == "opt":
                        path.mkdir(parents=True, exist_ok=True)
                        for child in ("authority", "operator", "installation"):
                            (path / child).mkdir()
                        (path / "authority" / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )
                    else:
                        path.mkdir(parents=True, exist_ok=True)
                        (path / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )
                cleanup_observed: list[tuple[int, int]] = []

                @contextlib.contextmanager
                def created_control_guard(*_args, **_kwargs):
                    release = {
                        "ready": False,
                        "control_created": True,
                        "control_identity": (3, 4),
                    }
                    yield release
                    self.assertTrue(release["ready"])

                def cleanup_after_journal(identity):
                    self.assertFalse(migration_root.exists())
                    cleanup_observed.append(identity)

                patches = (
                    mock.patch.object(
                        stage, "MIGRATION_ROOT", migration_root, create=True
                    ),
                    mock.patch.object(
                        stage, "MIGRATION_LOCK_PATH", migration_lock, create=True
                    ),
                    mock.patch.object(
                        stage, "SYSTEMD_CONTROL_ROOT", control_root, create=True
                    ),
                    mock.patch.object(
                        stage, "MIGRATION_MASK_PATH", control_mask, create=True
                    ),
                    mock.patch.object(stage, "verify_bundle", return_value={}),
                    mock.patch.object(
                        stage, "_verify_migration_capacity", create=True
                    ),
                    mock.patch.object(
                        stage,
                        "_verify_current_installation_with_producer",
                        return_value={},
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_verify_migration_systemd_version",
                        return_value=stage.MIGRATION_SYSTEMD_VERSION,
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_service_guard",
                        side_effect=created_control_guard,
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_migration_guided_lock",
                        return_value=contextlib.nullcontext(),
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "_run_current_recovery_gates",
                        create=True,
                    ),
                    mock.patch.object(
                        stage,
                        "install_bundle",
                        side_effect=stage.StagingError("target install failed"),
                    ),
                    mock.patch.object(
                        stage,
                        "_remove_created_migration_control_root",
                        side_effect=cleanup_after_journal,
                    ),
                )
                with contextlib.ExitStack() as stack:
                    for patch in patches:
                        stack.enter_context(patch)
                    with self.assertRaisesRegex(
                        stage.StagingError, "target install failed"
                    ):
                        stage.migrate_installation(
                            bundle,
                            current_revision="1" * 40,
                            current_bundle_receipt_sha256="2" * 64,
                            current_producer_sha256="3" * 64,
                            expected_revision="4" * 40,
                            expected_bundle_receipt_sha256="5" * 64,
                            temporary_root=temporary_root,
                            require_root=False,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                        )
                for name, path in fixed.items():
                    self.assertTrue(path.exists(), name)
                    marker = (
                        path.read_text(encoding="utf-8")
                        if name == "unit"
                        else (
                            path
                            / ("authority/old-marker" if name == "opt" else "old-marker")
                        ).read_text(encoding="utf-8")
                    )
                    self.assertEqual(marker, "old unit\n" if name == "unit" else name + "\n")
                self.assertFalse(migration_root.exists())
                self.assertEqual(cleanup_observed, [(3, 4)])

    def test_migration_fence_is_identity_bound_and_behavior_probed(self) -> None:
        assert stage is not None

        class SystemdFenceRunner:
            def __init__(self, mask: Path, unit: Path) -> None:
                self.mask = mask
                self.unit = unit
                self.negative_probes = 0

            def __call__(self, argv, **_kwargs):
                command = [os.fspath(item) for item in argv]
                if command[1:] == ["--version"]:
                    return (
                        stage.MIGRATION_SYSTEMD_VERSION
                        + "\nfixture features\n"
                    ).encode("ascii")
                if "daemon-reload" in command:
                    return b""
                if "show" in command:
                    property_token = next(
                        token for token in command
                        if token.startswith("--property=")
                    )
                    property_name = property_token.split("=", 1)[1]
                    masked = self.mask.is_symlink()
                    values = {
                        "LoadState": "masked" if masked else "loaded",
                        "FragmentPath": os.fspath(
                            self.mask if masked else self.unit
                        ),
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "Job": "",
                        "MainPID": "0",
                        "ControlPID": "0",
                    }
                    return (values[property_name] + "\n").encode("ascii")
                raise AssertionError(command)

            def expected_failure(self, argv, **_kwargs):
                self.negative_probes += 1
                self.assert_masked(argv)
                return 1

            def assert_masked(self, argv):
                if not self.mask.is_symlink():
                    raise AssertionError("negative start ran without the mask")
                if argv[-1] != UNIT.name:
                    raise AssertionError("negative start targeted another unit")

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            control = workspace / "etc/systemd/system.control"
            control.mkdir(parents=True)
            control.chmod(0o755)
            unit = workspace / "etc/systemd/system" / UNIT.name
            unit.parent.mkdir(parents=True)
            unit.write_text("fixture unit\n", encoding="utf-8")
            mask = control / UNIT.name
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            absent_cgroup = workspace / "sys/fs/cgroup/absent"
            runner = SystemdFenceRunner(mask, unit)
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "SYSTEMD_CONTROL_ROOT", control),
                mock.patch.object(stage, "MIGRATION_MASK_PATH", mask),
                mock.patch.object(stage, "UNIT_PATH", unit),
                mock.patch.object(stage, "SERVICE_CGROUP_PATH", absent_cgroup),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "fence-identity"},
                    os.getuid(),
                    os.getgid(),
                )
                with stage._migration_service_guard(
                    runner, os.getuid(), os.getgid()
                ) as release:
                    self.assertEqual(os.readlink(mask), "/dev/null")
                    self.assertEqual(
                        mask.lstat().st_ino,
                        (migration_root / "fence/mask-anchor").lstat().st_ino,
                    )
                    release["ready"] = True
                stage._rollback_created(transaction)
            self.assertFalse(mask.exists() or mask.is_symlink())
            self.assertFalse(migration_root.exists())
            self.assertTrue(control.is_dir())
            self.assertEqual(runner.negative_probes, 1)

    def test_migration_recovery_never_adopts_a_foreign_admin_mask(self) -> None:
        assert stage is not None

        class VersionOnlyRunner:
            def __call__(self, argv, **_kwargs):
                command = [os.fspath(item) for item in argv]
                if command[1:] == ["--version"]:
                    return (
                        stage.MIGRATION_SYSTEMD_VERSION
                        + "\nfixture features\n"
                    ).encode("ascii")
                raise AssertionError(command)

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            control = workspace / "etc/systemd/system.control"
            control.mkdir(parents=True)
            control.chmod(0o755)
            mask = control / UNIT.name
            mask.symlink_to("/dev/null")
            foreign_identity = mask.lstat().st_dev, mask.lstat().st_ino
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "SYSTEMD_CONTROL_ROOT", control),
                mock.patch.object(stage, "MIGRATION_MASK_PATH", mask),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "foreign-admin-mask"},
                    os.getuid(),
                    os.getgid(),
                )
                with self.assertRaisesRegex(
                    stage.StagingError, "recovery fence authority drift"
                ):
                    stage._ensure_migration_recovery_fence(
                        VersionOnlyRunner(), os.getuid(), os.getgid()
                    )
                self.assertEqual(
                    (mask.lstat().st_dev, mask.lstat().st_ino),
                    foreign_identity,
                )
                self.assertNotEqual(
                    mask.lstat().st_ino,
                    (migration_root / "fence/mask-anchor").lstat().st_ino,
                )
                stage._rollback_created(transaction)
            self.assertEqual(os.readlink(mask), "/dev/null")

    def test_created_systemd_control_root_has_durable_provenance(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            control = workspace / "etc/systemd/system.control"
            control.parent.mkdir(parents=True)
            mask = control / UNIT.name
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "SYSTEMD_CONTROL_ROOT", control),
                mock.patch.object(stage, "MIGRATION_MASK_PATH", mask),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "created-control-root"},
                    os.getuid(),
                    os.getgid(),
                )
                created, identity = stage._create_migration_control_root(
                    os.getuid(), os.getgid()
                )
                self.assertTrue(created)
                self.assertEqual(
                    (control.lstat().st_dev, control.lstat().st_ino),
                    identity,
                )
                self.assertTrue(
                    (migration_root / "fence/control.intent.json").is_file()
                )
                self.assertTrue(
                    (migration_root / "fence/control.commit.json").is_file()
                )
                rediscovered, rediscovered_identity = (
                    stage._create_migration_control_root(
                        os.getuid(), os.getgid()
                    )
                )
                self.assertTrue(rediscovered)
                self.assertEqual(rediscovered_identity, identity)
                intent = json.loads(
                    (
                        migration_root / "fence/control.intent.json"
                    ).read_text(encoding="utf-8")
                )
                staging = Path(intent["staging"])
                os.rename(control, staging)
                with self.assertRaisesRegex(
                    stage.StagingError,
                    "committed systemd control root is not at its fixed path",
                ):
                    stage._create_migration_control_root(
                        os.getuid(), os.getgid()
                    )
                os.rename(staging, control)
                mask_identity = stage._create_migration_mask(
                    os.getuid(), os.getgid()
                )
                stage._remove_migration_mask(*mask_identity)
                stage._rollback_created(transaction)
                self.assertFalse(migration_root.exists())
                self.assertTrue(control.is_dir())
                stage._remove_created_migration_control_root(identity)
            self.assertFalse(control.exists())
            self.assertFalse(migration_root.exists())

    def test_journal_removal_crash_leaves_a_reusable_control_root(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            control = workspace / "etc/systemd/system.control"
            control.parent.mkdir(parents=True)
            mask = control / UNIT.name
            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "SYSTEMD_CONTROL_ROOT", control),
                mock.patch.object(stage, "MIGRATION_MASK_PATH", mask),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "control-cleanup-crash"},
                    os.getuid(),
                    os.getgid(),
                )
                created, identity = stage._create_migration_control_root(
                    os.getuid(), os.getgid()
                )
                self.assertTrue(created)
                mask_identity = stage._create_migration_mask(
                    os.getuid(), os.getgid()
                )
                stage._remove_migration_mask(*mask_identity)
                stage._rollback_created(transaction)

                self.assertFalse(migration_root.exists())
                self.assertEqual(
                    (control.lstat().st_dev, control.lstat().st_ino),
                    identity,
                )

                next_transaction = stage._prepare_migration_transaction(
                    {"fixture": "after-control-cleanup-crash"},
                    os.getuid(),
                    os.getgid(),
                )
                reused, reused_identity = stage._create_migration_control_root(
                    os.getuid(), os.getgid()
                )
                self.assertFalse(reused)
                self.assertEqual(reused_identity, identity)
                self.assertTrue(
                    (migration_root / "fence/control.reuse.json").is_file()
                )
                stage._rollback_created(next_transaction)
            self.assertTrue(control.is_dir())
            self.assertFalse(migration_root.exists())

    def test_control_root_intent_interrupt_preserves_recoverable_staging(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            migration_root = workspace / "var/lib/migration"
            migration_root.parent.mkdir(parents=True)
            control = workspace / "etc/systemd/system.control"
            control.parent.mkdir(parents=True)
            mask = control / UNIT.name
            original_write = stage._write_migration_control_record
            interrupted = False

            def interrupt_after_durable_intent(
                value, phase, owner_uid, owner_gid,
            ):
                nonlocal interrupted
                original_write(value, phase, owner_uid, owner_gid)
                if phase == "intent" and not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt(
                        "simulated interruption after durable intent"
                    )

            with (
                mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                mock.patch.object(stage, "SYSTEMD_CONTROL_ROOT", control),
                mock.patch.object(stage, "MIGRATION_MASK_PATH", mask),
            ):
                transaction = stage._prepare_migration_transaction(
                    {"fixture": "control-intent-interruption"},
                    os.getuid(),
                    os.getgid(),
                )
                with (
                    mock.patch.object(
                        stage,
                        "_write_migration_control_record",
                        side_effect=interrupt_after_durable_intent,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    stage._create_migration_control_root(
                        os.getuid(), os.getgid()
                    )
                intent = json.loads(
                    (
                        migration_root / "fence/control.intent.json"
                    ).read_text(encoding="utf-8")
                )
                staging = Path(intent["staging"])
                self.assertTrue(staging.is_dir())
                self.assertFalse(control.exists())

                created, identity = stage._create_migration_control_root(
                    os.getuid(), os.getgid()
                )
                self.assertTrue(created)
                self.assertEqual(
                    (control.lstat().st_dev, control.lstat().st_ino),
                    identity,
                )
                self.assertTrue(
                    (migration_root / "fence/control.commit.json").is_file()
                )
                stage._rollback_created(transaction)
                self.assertFalse(migration_root.exists())
                stage._remove_created_migration_control_root(identity)
            self.assertFalse(control.exists())

    def test_interrupted_migration_recovery_removes_recorded_partial_target(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                migration_lock = (
                    install_workspace
                    / "run/codeskeptic-p10-09-migration.lock"
                )
                fixed = {
                    "opt": layout["AUTHORITY_ROOT"].parent,
                    "config": layout["CONFIG_PATH"].parent,
                    "state": layout["STATE_ROOT"],
                    "unit": layout["UNIT_PATH"],
                }
                for name, path in fixed.items():
                    if name == "unit":
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("old unit\n", encoding="utf-8")
                    elif name == "opt":
                        path.mkdir(parents=True, exist_ok=True)
                        for child in ("authority", "operator", "installation"):
                            (path / child).mkdir()
                        (path / "authority" / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )
                    else:
                        path.mkdir(parents=True, exist_ok=True)
                        (path / "old-marker").write_text(
                            name + "\n", encoding="utf-8"
                        )
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "MIGRATION_LOCK_PATH", migration_lock
                    ),
                ):
                    nodes = stage._migration_source_nodes()
                    plan = stage._migration_plan(
                        nodes,
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        expected_revision="4" * 40,
                        expected_bundle_receipt_sha256="5" * 64,
                        systemd_version=stage.MIGRATION_SYSTEMD_VERSION,
                    )
                    transaction = stage._prepare_migration_transaction(
                        plan, os.getuid(), os.getgid()
                    )
                    first = nodes[0]
                    prefix = f"00-{first['name']}"
                    stage._write_migration_record(
                        migration_root
                        / "moves"
                        / f"{prefix}.intent.json",
                        stage.canonical_document(
                            stage._migration_move_value(first, 0, "intent")
                        ),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        created_nodes=transaction,
                    )
                    stage._rename_noreplace(first["source"], first["backup"])
                    stage._fsync_directory(first["source"].parent)
                    stage._fsync_directory(first["backup"].parent)
                    stage._write_migration_record(
                        migration_root
                        / "moves"
                        / f"{prefix}.commit.json",
                        stage.canonical_document(
                            stage._migration_move_value(first, 0, "commit")
                        ),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        created_nodes=transaction,
                    )
                    targets = stage._MigrationTargetLedger(
                        transaction, os.getuid(), os.getgid()
                    )
                    original_rename = stage._rename_noreplace

                    def require_intent_before_target(source, destination):
                        if destination == first["source"]:
                            self.assertTrue(
                                (
                                    migration_root
                                    / "targets/0000.intent.json"
                                ).is_file()
                            )
                            self.assertFalse(
                                (
                                    migration_root
                                    / "targets/0000.commit.json"
                                ).exists()
                            )
                        return original_rename(source, destination)

                    with mock.patch.object(
                        stage,
                        "_rename_noreplace",
                        side_effect=require_intent_before_target,
                    ):
                        stage._write_new(
                            first["source"],
                            b"partial target unit\n",
                            0o600,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                            created_nodes=targets,
                        )
                    self.assertTrue(
                        (migration_root / "targets/0000.intent.json").is_file()
                    )
                    self.assertTrue(
                        (migration_root / "targets/0000.commit.json").is_file()
                    )
                    stage._release_created(targets)
                    stage._release_created(transaction)
                    stage._close_migration_nodes(nodes)
                    target = {"revision": "4" * 40}
                    lock_state = {"held": False}
                    original_restore = stage._restore_migration_nodes

                    @contextlib.contextmanager
                    def hold_old_guided_lock(*_args, **_kwargs):
                        lock_state["held"] = True
                        try:
                            yield
                        finally:
                            lock_state["held"] = False

                    def restore_while_locked(values):
                        self.assertTrue(lock_state["held"])
                        return original_restore(values)

                    def retain_control_after_journal(_identity):
                        self.assertFalse(migration_root.exists())
                        raise stage.StagingError(
                            "simulated optional control-root cleanup failure"
                        )

                    patches = (
                        mock.patch.object(
                            stage,
                            "_assert_expected_bundle_identity",
                            return_value=target,
                        ),
                        mock.patch.object(
                            stage,
                            "_verify_bundle_structure",
                            return_value=target,
                        ),
                        mock.patch.object(
                            stage,
                            "_try_verify_target_installation",
                            return_value=None,
                        ),
                        mock.patch.object(
                            stage,
                            "_ensure_migration_recovery_fence",
                            return_value=((1, 2), True, (3, 4)),
                        ),
                        mock.patch.object(
                            stage, "_release_migration_recovery_fence"
                        ),
                        mock.patch.object(
                            stage,
                            "_verify_current_installation_with_producer",
                        ),
                        mock.patch.object(
                            stage, "_run_current_recovery_gates"
                        ),
                        mock.patch.object(
                            stage,
                            "_migration_guided_lock_at",
                            side_effect=hold_old_guided_lock,
                        ),
                        mock.patch.object(
                            stage,
                            "_restore_migration_nodes",
                            side_effect=restore_while_locked,
                        ),
                        mock.patch.object(
                            stage,
                            "_remove_created_migration_control_root",
                            side_effect=retain_control_after_journal,
                        ),
                    )
                    with contextlib.ExitStack() as stack:
                        for patch in patches:
                            stack.enter_context(patch)
                        recovered = stage.recover_installation_migration(
                            bundle,
                            current_revision="1" * 40,
                            current_bundle_receipt_sha256="2" * 64,
                            current_producer_sha256="3" * 64,
                            expected_revision="4" * 40,
                            expected_bundle_receipt_sha256="5" * 64,
                            require_root=False,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                        )
                self.assertEqual(
                    recovered["migration_outcome"],
                    "rolled-back-after-restart",
                )
                self.assertEqual(
                    recovered["migration_control_root_cleanup"],
                    "retained",
                )
                for path in fixed.values():
                    self.assertTrue(path.exists())
                self.assertEqual(
                    fixed["unit"].read_text(encoding="utf-8"),
                    "old unit\n",
                )
                self.assertFalse(migration_root.exists())

    def test_migration_recovery_preserves_foreign_partial_target(self) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            with patched_install_layout(install_workspace) as layout:
                target = layout["UNIT_PATH"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"foreign target\n")
                staged = (
                    target.parent / (".codeskeptic-file-" + "a" * 32)
                )
                staged.write_bytes(b"recorded but no longer present\n")
                metadata = staged.stat()
                staged.unlink()
                record = {
                    "schema": stage.INSTALLATION_MIGRATION_TARGET_SCHEMA,
                    "index": 0,
                    "path": target.as_posix(),
                    "staging": staged.as_posix(),
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "type": "file",
                    "phase": "intent",
                }
                with self.assertRaisesRegex(
                    stage.StagingError, "foreign object occupies"
                ):
                    stage._remove_recorded_partial_targets(
                        [record], [], {}
                    )
                self.assertEqual(target.read_bytes(), b"foreign target\n")
                self.assertFalse(staged.exists())

    def test_interrupted_migration_recovery_commits_rediscovered_target(
        self,
    ) -> None:
        assert stage is not None
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            install_workspace = workspace / "layout"
            install_workspace.mkdir()
            bundle = workspace / "sealed"
            bundle.mkdir()
            with patched_install_layout(install_workspace) as layout:
                migration_root = (
                    install_workspace
                    / "var/lib/codeskeptic-p10-09-migration"
                )
                migration_lock = (
                    install_workspace
                    / "run/codeskeptic-p10-09-migration.lock"
                )
                fixed = {
                    "opt": layout["AUTHORITY_ROOT"].parent,
                    "config": layout["CONFIG_PATH"].parent,
                    "state": layout["STATE_ROOT"],
                    "unit": layout["UNIT_PATH"],
                }
                for name, path in fixed.items():
                    if name == "unit":
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("old unit\n", encoding="utf-8")
                    elif name == "opt":
                        path.mkdir(parents=True, exist_ok=True)
                        for child in ("authority", "operator", "installation"):
                            (path / child).mkdir()
                    else:
                        path.mkdir(parents=True, exist_ok=True)
                with (
                    mock.patch.object(stage, "MIGRATION_ROOT", migration_root),
                    mock.patch.object(
                        stage, "MIGRATION_LOCK_PATH", migration_lock
                    ),
                ):
                    nodes = stage._migration_source_nodes()
                    plan = stage._migration_plan(
                        nodes,
                        current_revision="1" * 40,
                        current_bundle_receipt_sha256="2" * 64,
                        current_producer_sha256="3" * 64,
                        expected_revision="4" * 40,
                        expected_bundle_receipt_sha256="5" * 64,
                        systemd_version=stage.MIGRATION_SYSTEMD_VERSION,
                    )
                    transaction = stage._prepare_migration_transaction(
                        plan, os.getuid(), os.getgid()
                    )
                    moved = []
                    stage._move_migration_nodes(
                        nodes,
                        moved,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        transaction_nodes=transaction,
                    )
                    stage._release_created(transaction)
                    stage._close_migration_nodes(nodes)
                    for name, path in fixed.items():
                        if name == "unit":
                            path.write_text("new unit\n", encoding="utf-8")
                        elif name == "opt":
                            path.mkdir()
                            for child in (
                                "authority", "operator", "installation"
                            ):
                                (path / child).mkdir()
                            layout["INSTALLATION_RECEIPT_PATH"].write_text(
                                '{"fixture":"rediscovered"}\n',
                                encoding="utf-8",
                            )
                        else:
                            path.mkdir()
                    target = {
                        "bundle_revision": "4" * 40,
                        "bundle_receipt_sha256": "5" * 64,
                    }
                    bundle_receipt = {"revision": "4" * 40}
                    patches = (
                        mock.patch.object(
                            stage,
                            "_assert_expected_bundle_identity",
                            return_value=bundle_receipt,
                        ),
                        mock.patch.object(
                            stage,
                            "_verify_bundle_structure",
                            return_value=bundle_receipt,
                        ),
                        mock.patch.object(
                            stage,
                            "_try_verify_target_installation",
                            return_value=target,
                        ),
                        mock.patch.object(
                            stage,
                            "_ensure_migration_recovery_fence",
                            return_value=((1, 2), False, (3, 4)),
                        ),
                        mock.patch.object(
                            stage, "_release_migration_recovery_fence"
                        ),
                        mock.patch.object(
                            stage,
                            "_migration_guided_lock_at",
                            return_value=contextlib.nullcontext(),
                        ),
                    )
                    with contextlib.ExitStack() as stack:
                        for patch in patches:
                            stack.enter_context(patch)
                        recovered = stage.recover_installation_migration(
                            bundle,
                            current_revision="1" * 40,
                            current_bundle_receipt_sha256="2" * 64,
                            current_producer_sha256="3" * 64,
                            expected_revision="4" * 40,
                            expected_bundle_receipt_sha256="5" * 64,
                            require_root=False,
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                        )
                self.assertEqual(recovered, target)
                self.assertTrue((migration_root / "success.json").is_file())
                self.assertFalse((migration_root / "active").exists())
                self.assertTrue((migration_root / "retired").is_file())
                self.assertEqual(
                    list((migration_root / "publication-staging").iterdir()),
                    [],
                )
                for name in fixed:
                    self.assertTrue((migration_root / "backup" / name).exists())

    def test_authoritative_operator_uses_only_the_persistent_private_podman_environment(self) -> None:
        operator = AUTHORITATIVE.read_text(encoding="utf-8")
        for token in (
            'PODMAN_ENVIRONMENT_ROOT="${STATE_ROOT}/podman-environment"',
            '"HOME=${PODMAN_ENVIRONMENT_ROOT}/home"',
            '"XDG_DATA_HOME=${PODMAN_ENVIRONMENT_ROOT}/data"',
            '"XDG_CACHE_HOME=${PODMAN_ENVIRONMENT_ROOT}/cache"',
            '"XDG_CONFIG_HOME=${PODMAN_ENVIRONMENT_ROOT}/config"',
            '"XDG_RUNTIME_DIR=${PODMAN_ENVIRONMENT_ROOT}/runtime"',
            '"TMPDIR=${PODMAN_ENVIRONMENT_ROOT}/tmp"',
            "run_podman()",
        ):
            self.assertIn(token, operator)
        self.assertEqual(
            operator.count('"$PODMAN" "${PODMAN_GLOBAL_OPTIONS[@]}"'),
            1,
        )


if __name__ == "__main__":
    unittest.main()
