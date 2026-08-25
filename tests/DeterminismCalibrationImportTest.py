#!/usr/bin/env python3
"""Fail-closed contracts for sealed determinism calibration projection."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
IMPORTER = ROOT / "scripts" / "import_determinism_calibration.py"
sys.path.insert(0, os.fspath(ROOT / "scripts"))
import import_determinism_calibration as importer  # noqa: E402

SESSION_NAME = "20260825T000000Z-aa36770"
EVIDENCE_PATH = (
    "docs/evidence/phase10/determinism/calibrations/"
    "2026-08-24-fedora44-i5-1235u-p10-09-topology"
)
HEX = "a" * 64


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def qualification_canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def seal_tree(root: Path, *, qualification_receipt: bool = False) -> None:
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() != "SHA256SUMS"
    )
    if qualification_receipt:
        paths = ["receipt.json", "receipt.json.sha256"] + [
            path for path in paths
            if path not in {"receipt.json", "receipt.json.sha256"}
        ]
    (root / "SHA256SUMS").write_bytes(b"".join(
        f"{digest(root / relative)}  {relative}\n".encode()
        for relative in paths
    ))


def sidecar(root: Path) -> None:
    raw = (root / "receipt.json").read_bytes()
    (root / "receipt.json.sha256").write_text(
        f"{hashlib.sha256(raw).hexdigest()}  receipt.json\n", encoding="ascii"
    )


def freeze(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444, follow_symlinks=False)
    os.chmod(root, 0o555)


def thaw(root: Path) -> None:
    os.chmod(root, 0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)
        elif not path.is_symlink():
            os.chmod(path, 0o644)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "source"
        self.bundle = root / "operator"
        self.session = root / SESSION_NAME
        self.output = root / "projection"
        self.old_profile = {
            "os": {"id": "fedora", "version_id": "44"},
            "provenance": {"source_revision": "old"},
            "hardware": {"architecture": "x86_64"},
            "workloads": {"unit": {"statistics": {"median": 1}}},
        }
        self.previous = {
            "schema": "codeskeptic-determinism-baseline-v7",
            "profiles": {"class-a": self.old_profile},
        }
        self._repo()
        self._bundle()
        self.candidate = self._candidate()
        self.calibration = self._calibration()
        self.rejection = self._rejection()
        self._session()

    def _repo(self) -> None:
        (self.repo / "scripts").mkdir(parents=True)
        write(
            self.repo / "scripts/determinism_baseline.json",
            qualification_canonical(self.previous),
        )
        write(self.repo / "scripts/dependency.txt", b"trusted-base\n")
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "add", "scripts"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.repo, check=True)
        self.revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()

    def _bundle(self) -> None:
        self.bundle.mkdir()
        scripts = {
            "session-seal.py": (
                "#!/usr/bin/env python3\nimport pathlib,sys\n"
                "assert sys.argv[1:3] == ['verify', '--root']\n"
                "assert pathlib.Path(sys.argv[3]).name == 'producer'\n"
                "print('CODESKEPTIC_P10_09_CANDIDATE_SESSION_OK action=verify')\n"
            ),
            "controller-seal.py": (
                "#!/usr/bin/env python3\nimport pathlib,sys\n"
                "assert sys.argv[1:3] == ['verify', '--root']\n"
                "assert pathlib.Path(sys.argv[3]).name == '20260825T000000Z-aa36770'\n"
                "print('CODESKEPTIC_P10_09_CONTROLLER_SESSION_OK action=verify')\n"
            ),
            "verify-candidate.py": (
                "#!/usr/bin/env python3\nimport os,pathlib,subprocess,sys\n"
                "required = {'--source', '--previous', '--candidate', '--calibration', "
                "'--rejection', '--evidence-path', '--scratch-parent'}\n"
                "assert required <= set(sys.argv[1:])\n"
                "for flag in required - {'--evidence-path'}:\n"
                "    assert pathlib.Path(sys.argv[sys.argv.index(flag) + 1]).exists()\n"
                "source = pathlib.Path(sys.argv[sys.argv.index('--source') + 1])\n"
                "assert (source / 'scripts/dependency.txt').read_bytes() == b'trusted-base\\n'\n"
                "assert not (source / 'scripts/injected.py').exists()\n"
                "status = subprocess.check_output(['git', '-C', source, 'status', "
                "'--porcelain=v1', '--ignored=matching', '--untracked-files=all'])\n"
                "assert status == b''\n"
                "remotes = subprocess.check_output(['git', '-C', source, 'remote'])\n"
                "assert remotes == b''\n"
                "assert os.environ['GIT_ALLOW_PROTOCOL'] == 'file'\n"
                "assert os.environ['GIT_NO_LAZY_FETCH'] == '1'\n"
                "print('CODESKEPTIC_P10_09_CANDIDATE_VERIFIED revision=fixture ancestor_depth=3')\n"
            ),
        }
        for name, source in scripts.items():
            write(self.bundle / name, source.encode())
            os.chmod(self.bundle / name, 0o555)
        seal_tree(self.bundle)
        os.chmod(self.bundle / "SHA256SUMS", 0o444)
        os.chmod(self.bundle, 0o555)
        self.bundle_sha = digest(self.bundle / "SHA256SUMS")

    def _candidate(self) -> dict:
        old_raw = qualification_canonical(self.previous)
        profile = copy.deepcopy(self.old_profile)
        profile["provenance"] = {
            "source_revision": self.revision,
            "calibration": {
                "evidence_path": EVIDENCE_PATH,
                "receipt_sha256": "0" * 64,
            },
            "promotion": {
                "reason": "Reviewed calibration projection",
                "previous_baseline_sha256": hashlib.sha256(old_raw).hexdigest(),
                "previous_profile_sha256": hashlib.sha256(
                    qualification_canonical(self.old_profile)
                ).hexdigest(),
            },
        }
        return {
            "schema": "codeskeptic-determinism-baseline-v7",
            "profiles": {"class-a": profile},
        }

    def _calibration(self) -> dict:
        return {
            "schema": "codeskeptic-determinism-calibration-v7",
            "status": "calibration",
            "source": {"revision": self.revision},
            "host": {"class_id": "class-a"},
        }

    @staticmethod
    def _rejection() -> dict:
        return {
            "schema": "codeskeptic-determinism-rejected-v7",
            "status": "rejected",
            "decision": {"classification": "complete-gate-rejection"},
            "observations": {"complete": True},
            "failures": [{"type": "profile-unavailable"}],
        }

    def _session(self) -> None:
        producer = self.session / "producer"
        calibration = producer / "calibration"
        rejection = producer / "qualification-rejection"
        calibration.mkdir(parents=True)
        rejection.mkdir()
        write(calibration / "receipt.json", qualification_canonical(self.calibration))
        sidecar(calibration)
        write(calibration / "raw/measurement.json", canonical({"sample": 1}))
        seal_tree(calibration, qualification_receipt=True)
        self.candidate["profiles"]["class-a"]["provenance"]["calibration"][
            "receipt_sha256"
        ] = digest(calibration / "receipt.json")
        write(rejection / "receipt.json", qualification_canonical(self.rejection))
        sidecar(rejection)
        seal_tree(rejection, qualification_receipt=True)
        write(
            producer / "determinism-baseline.candidate.json",
            qualification_canonical(self.candidate),
        )
        fixed = {
            "qualification-exit-code.txt": b"2\n",
            "qualification.log": b"qualification\n",
            "calibration-verify.log": b"pass\n",
            "rejection-verify.log": b"pass\n",
            "candidate-verify.log": b"pass\n",
            "build-authority-verify.log": b"pass\n",
            "build-authority-preflight.log": b"pass\n",
            "cgroup-authority-intent.json": canonical({"intent": "fixture"}),
            "cgroup-authority-intent.json.sha256": b"fixture\n",
            "cgroup-smoke.json": canonical({"smoke": "fixture"}),
            "cgroup-smoke.json.sha256": b"fixture\n",
            "systemd-probe-run.json": canonical({"probe": "run"}),
            "systemd-probe-run.json.sha256": b"fixture\n",
            "systemd-probe-post-stop.json": canonical({"probe": "post"}),
            "systemd-probe-post-stop.json.sha256": b"fixture\n",
        }
        for name, value in fixed.items():
            write(producer / name, value)
        producer_receipt = {
            "schema": "codeskeptic-p10-09-candidate-session-v3",
            "status": "accepted-candidate",
            "source_revision": self.revision,
            "calibration_evidence_path": EVIDENCE_PATH,
            "inner_qualification_exit_code": 2,
            "candidate_baseline_sha256": digest(
                producer / "determinism-baseline.candidate.json"
            ),
            "calibration_receipt_sha256": digest(calibration / "receipt.json"),
            "rejection_receipt_sha256": digest(rejection / "receipt.json"),
            "cgroup_authority_intent_sha256": HEX,
            "cgroup_smoke_sha256": HEX,
            "systemd_probe_run_sha256": HEX,
            "systemd_probe_post_stop_sha256": HEX,
            "verification": {
                "calibration": "pass",
                "candidate_authority": "pass",
                "policy_diff": "pass",
                "rejection": "pass",
                "remote_exclusive_authority": "pass",
                "systemd_preflight": "pass",
            },
        }
        write(producer / "receipt.json", canonical(producer_receipt))
        sidecar(producer)
        seal_tree(producer)
        controller_inputs = {
            "independent-verifier.log": b"pass\n",
            "independent-verifier-exit-code.txt": b"0\n",
            "independent-verifier-container.json": canonical({"container": "fixture"}),
            "controller-cleanup.json": canonical({"cleanup": "fixture"}),
        }
        for name, value in controller_inputs.items():
            write(self.session / name, value)
        controller_receipt = {
            "schema": "codeskeptic-p10-09-candidate-controller-session-v3",
            "status": "accepted",
            "source_revision": self.revision,
            "producer_receipt_sha256": digest(producer / "receipt.json"),
            "producer_manifest_sha256": digest(producer / "SHA256SUMS"),
            "independent_verifier_log_sha256": HEX,
            "independent_verifier_container_sha256": HEX,
            "controller_cleanup_sha256": HEX,
            "cgroup_authority_intent_sha256": HEX,
            "cgroup_smoke_sha256": HEX,
            "systemd_probe_run_sha256": HEX,
            "systemd_probe_post_stop_sha256": HEX,
            "verification": {
                "producer_seal": "pass",
                "independent_verifier_exit_code": "pass",
                "independent_verifier_marker": "pass",
                "independent_verifier_container_authority": "pass",
                "recursive_inventory": "pass",
                "controller_cleanup": "pass",
                "systemd_preflight_replay": "pass",
            },
        }
        write(self.session / "receipt.json", canonical(controller_receipt))
        sidecar(self.session)
        seal_tree(self.session)
        freeze(self.session)

    def reseal(self) -> None:
        thaw(self.session)
        producer = self.session / "producer"
        calibration = producer / "calibration"
        rejection = producer / "qualification-rejection"
        write(calibration / "receipt.json", qualification_canonical(self.calibration))
        sidecar(calibration)
        seal_tree(calibration, qualification_receipt=True)
        self.candidate["profiles"]["class-a"]["provenance"]["calibration"][
            "receipt_sha256"
        ] = digest(calibration / "receipt.json")
        write(rejection / "receipt.json", qualification_canonical(self.rejection))
        sidecar(rejection)
        seal_tree(rejection, qualification_receipt=True)
        write(
            producer / "determinism-baseline.candidate.json",
            qualification_canonical(self.candidate),
        )
        producer_receipt = json.loads((producer / "receipt.json").read_bytes())
        producer_receipt.update({
            "candidate_baseline_sha256": digest(
                producer / "determinism-baseline.candidate.json"
            ),
            "calibration_receipt_sha256": digest(calibration / "receipt.json"),
            "rejection_receipt_sha256": digest(rejection / "receipt.json"),
        })
        write(producer / "receipt.json", canonical(producer_receipt))
        sidecar(producer)
        seal_tree(producer)
        controller = json.loads((self.session / "receipt.json").read_bytes())
        controller.update({
            "producer_receipt_sha256": digest(producer / "receipt.json"),
            "producer_manifest_sha256": digest(producer / "SHA256SUMS"),
        })
        write(self.session / "receipt.json", canonical(controller))
        sidecar(self.session)
        seal_tree(self.session)
        freeze(self.session)

    def command(self, action: str = "import") -> list[str]:
        return [
            sys.executable, "-B", str(IMPORTER), action,
            "--session", str(self.session),
            "--operator-bundle", str(self.bundle),
            "--operator-manifest-sha256", self.bundle_sha,
            "--source-repo", str(self.repo),
            "--base-revision", self.revision,
            "--projection", str(self.output),
        ]

    def run(self, action: str = "import") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(action), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )


class DeterminismCalibrationImportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="calibration-import-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, result: subprocess.CompletedProcess[str], text: str) -> None:
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn(text, result.stdout)
        self.assertFalse(self.fixture.output.exists())

    def test_import_and_offline_verify_are_exact_and_repo_is_unchanged(self) -> None:
        before = subprocess.check_output(
            ["git", "status", "--porcelain=v1"], cwd=self.fixture.repo
        )
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("CODESKEPTIC_DETERMINISM_CALIBRATION_IMPORT_OK", result.stdout)
        expected = {
            "SHA256SUMS", "receipt.json", "receipt.json.sha256",
            "scripts/determinism_baseline.json",
            f"{EVIDENCE_PATH}/SHA256SUMS",
            f"{EVIDENCE_PATH}/receipt.json",
            f"{EVIDENCE_PATH}/receipt.json.sha256",
            f"{EVIDENCE_PATH}/raw/measurement.json",
        }
        observed = {
            path.relative_to(self.fixture.output).as_posix()
            for path in self.fixture.output.rglob("*") if path.is_file()
        }
        self.assertEqual(observed, expected)
        receipt_raw = (self.fixture.output / "receipt.json").read_bytes()
        self.assertEqual(receipt_raw, canonical(json.loads(receipt_raw)))
        receipt = json.loads(receipt_raw)
        self.assertEqual(receipt["base_revision"], self.fixture.revision)
        self.assertEqual(receipt["source_session"]["name"], SESSION_NAME)
        self.assertEqual(
            receipt["trusted_operator"]["manifest_sha256"], self.fixture.bundle_sha
        )
        self.assertEqual(
            subprocess.check_output(
                ["git", "status", "--porcelain=v1"], cwd=self.fixture.repo
            ), before,
        )
        replay = self.fixture.run("verify")
        self.assertEqual(replay.returncode, 0, replay.stdout)
        self.assertIn("action=verify", replay.stdout)

    def test_dirty_and_ignored_source_cannot_influence_replay(self) -> None:
        dependency = self.fixture.repo / "scripts/dependency.txt"
        injected = self.fixture.repo / "scripts/injected.py"
        dependency.write_text("malicious-worktree\n", encoding="utf-8")
        injected.write_text("raise RuntimeError('must never load')\n", encoding="utf-8")
        (self.fixture.repo / ".git/info/exclude").write_text(
            "scripts/injected.py\n", encoding="utf-8"
        )
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            dependency.read_text(encoding="utf-8"), "malicious-worktree\n"
        )
        self.assertTrue(injected.exists())
        receipt = json.loads((self.fixture.output / "receipt.json").read_bytes())
        self.assertEqual(receipt["base_revision"], self.fixture.revision)
        self.assertRegex(receipt["base_tree_oid"], r"^[0-9a-f]{40}$")

    def test_existing_projection_is_never_replaced(self) -> None:
        self.fixture.output.mkdir()
        marker = self.fixture.output / "owned"
        marker.write_text("preserve", encoding="utf-8")
        result = self.fixture.run()
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_publish_race_preserves_competing_output_and_cleans_staging(self) -> None:
        def competing_publish(_source: Path, destination: Path) -> None:
            destination.mkdir()
            (destination / "owned").write_text("preserve", encoding="utf-8")
            raise importer.CalibrationImportError("projection output already exists")

        arguments = SimpleNamespace(
            action="import",
            session=self.fixture.session,
            operator_bundle=self.fixture.bundle,
            operator_manifest_sha256=self.fixture.bundle_sha,
            source_repo=self.fixture.repo,
            base_revision=self.fixture.revision,
            projection=self.fixture.output,
        )
        with mock.patch.object(
            importer, "rename_noreplace", side_effect=competing_publish
        ):
            with self.assertRaisesRegex(
                importer.CalibrationImportError, "already exists"
            ):
                importer.execute(arguments)
        self.assertEqual(
            (self.fixture.output / "owned").read_text(encoding="utf-8"),
            "preserve",
        )
        self.assertFalse(any(
            path.name.startswith(".projection.staging-")
            for path in self.fixture.root.iterdir()
        ))

    def test_wrong_operator_pin_is_rejected(self) -> None:
        command = self.fixture.command()
        command[command.index("--operator-manifest-sha256") + 1] = "0" * 64
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.assert_rejected(result, "operator manifest identity drift")

    def test_operator_inventory_drift_is_rejected(self) -> None:
        os.chmod(self.fixture.bundle, 0o755)
        write(self.fixture.bundle / "unexpected", b"drift\n")
        os.chmod(self.fixture.bundle / "unexpected", 0o444)
        os.chmod(self.fixture.bundle, 0o555)
        self.assert_rejected(self.fixture.run(), "operator bundle manifest inventory drift")

    def test_pinned_verifier_failure_leaves_no_projection(self) -> None:
        bundle = self.fixture.bundle
        verifier = bundle / "controller-seal.py"
        os.chmod(bundle, 0o755)
        os.chmod(bundle / "SHA256SUMS", 0o644)
        os.chmod(verifier, 0o755)
        verifier.write_text(
            "#!/usr/bin/env python3\nraise SystemExit(2)\n", encoding="utf-8"
        )
        os.chmod(verifier, 0o555)
        seal_tree(bundle)
        os.chmod(bundle / "SHA256SUMS", 0o444)
        os.chmod(bundle, 0o555)
        self.fixture.bundle_sha = digest(bundle / "SHA256SUMS")
        self.assert_rejected(self.fixture.run(), "controller session verifier failed")

    def test_session_symlink_and_mode_drift_are_rejected(self) -> None:
        target = self.fixture.session / "independent-verifier.log"
        os.chmod(self.fixture.session, 0o755)
        target.unlink()
        target.symlink_to("qualification.log")
        os.chmod(self.fixture.session, 0o555)
        self.assert_rejected(self.fixture.run(), "non-regular")

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory(prefix="calibration-import-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        target = self.fixture.session / "receipt.json"
        os.chmod(target, 0o644)
        self.assert_rejected(self.fixture.run(), "mode drift")

    def test_session_owner_drift_is_rejected(self) -> None:
        alternate_groups = [group for group in os.getgroups() if group != os.getgid()]
        if not alternate_groups:
            self.skipTest("no alternate owned group is available")
        target = self.fixture.session / "receipt.json"
        os.chown(target, -1, alternate_groups[0])
        self.assert_rejected(self.fixture.run(), "owner drift")

    def test_unexpected_session_inventory_is_rejected_even_when_resealed(self) -> None:
        thaw(self.fixture.session)
        write(self.fixture.session / "producer/unexpected.txt", b"sealed extra\n")
        self.fixture.reseal()
        self.assert_rejected(self.fixture.run(), "producer inventory drift")

    def test_resealed_noncanonical_candidate_is_rejected(self) -> None:
        session = self.fixture.session
        producer = session / "producer"
        candidate = producer / "determinism-baseline.candidate.json"
        thaw(session)
        candidate.write_bytes(candidate.read_bytes() + b" ")
        producer_receipt = json.loads((producer / "receipt.json").read_bytes())
        producer_receipt["candidate_baseline_sha256"] = digest(candidate)
        write(producer / "receipt.json", canonical(producer_receipt))
        sidecar(producer)
        seal_tree(producer)
        controller = json.loads((session / "receipt.json").read_bytes())
        controller["producer_receipt_sha256"] = digest(producer / "receipt.json")
        controller["producer_manifest_sha256"] = digest(producer / "SHA256SUMS")
        write(session / "receipt.json", canonical(controller))
        sidecar(session)
        seal_tree(session)
        freeze(session)
        self.assert_rejected(self.fixture.run(), "candidate baseline is not canonical")

    def test_wrong_base_and_session_source_revision_are_rejected(self) -> None:
        command = self.fixture.command()
        command[command.index("--base-revision") + 1] = "0" * 40
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.assert_rejected(result, "base revision")

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory(prefix="calibration-import-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        thaw(self.fixture.session)
        receipt = json.loads((self.fixture.session / "receipt.json").read_bytes())
        receipt["source_revision"] = "0" * 40
        write(self.fixture.session / "receipt.json", canonical(receipt))
        sidecar(self.fixture.session)
        seal_tree(self.fixture.session)
        freeze(self.fixture.session)
        self.assert_rejected(self.fixture.run(), "controller source revision drift")

    def test_candidate_predecessor_and_calibration_links_are_rejected(self) -> None:
        promotion = self.fixture.candidate["profiles"]["class-a"]["provenance"]["promotion"]
        promotion["previous_baseline_sha256"] = "0" * 64
        self.fixture.reseal()
        self.assert_rejected(self.fixture.run(), "predecessor baseline identity drift")

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory(prefix="calibration-import-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        calibration_link = self.fixture.candidate["profiles"]["class-a"]["provenance"]["calibration"]
        calibration_link["evidence_path"] = EVIDENCE_PATH + "-drift"
        self.fixture.reseal()
        self.assert_rejected(self.fixture.run(), "calibration evidence path drift")

    def test_calibration_and_rejection_relationship_drift_are_rejected(self) -> None:
        self.fixture.calibration["source"]["revision"] = "0" * 40
        self.fixture.reseal()
        self.assert_rejected(self.fixture.run(), "calibration source revision drift")

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory(prefix="calibration-import-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        self.fixture.rejection["failures"][0]["type"] = "performance-regression"
        self.fixture.reseal()
        self.assert_rejected(self.fixture.run(), "qualification rejection relationship drift")

    def test_projection_checksum_tamper_is_rejected(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout)
        baseline = self.fixture.output / "scripts/determinism_baseline.json"
        os.chmod(baseline, 0o644)
        baseline.write_bytes(baseline.read_bytes() + b" ")
        os.chmod(baseline, 0o444)
        replay = self.fixture.run("verify")
        self.assertEqual(replay.returncode, 2, replay.stdout)
        self.assertIn("projection", replay.stdout)

    def test_resealed_noncanonical_projection_receipt_is_rejected(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout)
        projection = self.fixture.output
        thaw(projection)
        receipt_path = projection / "receipt.json"
        receipt_path.write_bytes(
            qualification_canonical(json.loads(receipt_path.read_bytes()))
        )
        sidecar(projection)
        seal_tree(projection)
        freeze(projection)
        replay = self.fixture.run("verify")
        self.assertEqual(replay.returncode, 2, replay.stdout)
        self.assertIn("projection receipt is not canonical", replay.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
