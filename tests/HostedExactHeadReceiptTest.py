#!/usr/bin/env python3
"""Hermetic contract tests for the hosted exact-head evidence authority."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "seal_hosted_exact_head.py"
SPEC = importlib.util.spec_from_file_location("hosted_exact_head", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load hosted exact-head authority")
hosted = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hosted)

STABILITY_SPEC = importlib.util.spec_from_file_location(
    "run_stability_campaign", ROOT / "scripts" / "run_stability_campaign.py"
)
if STABILITY_SPEC is None or STABILITY_SPEC.loader is None:
    raise RuntimeError("cannot load stability campaign")
stability = importlib.util.module_from_spec(STABILITY_SPEC)
STABILITY_SPEC.loader.exec_module(stability)


REPOSITORY = "example/CodeSkeptic"
REVISION = "a" * 40
TREE = "b" * 40

GATE_WORKFLOWS = {
    "build-and-test": ".github/workflows/ci.yml",
    "resource-budget-macos": ".github/workflows/ci.yml",
    "fuzz-smoke": ".github/workflows/ci.yml",
    "sanitizer-address": ".github/workflows/ci.yml",
    "sanitizer-undefined": ".github/workflows/ci.yml",
    "windows-native": ".github/workflows/windows.yml",
    "docs-structure": ".github/workflows/docs.yml",
    "docs-quickstart": ".github/workflows/docs.yml",
    "docker": ".github/workflows/docker.yml",
    "juliet": ".github/workflows/juliet.yml",
}

GATE_JOB_KEYS = {
    "build-and-test": "build-and-test",
    "resource-budget-macos": "resource-budget-macos",
    "fuzz-smoke": "fuzz-smoke",
    "sanitizer-address": "sanitizer-runtime",
    "sanitizer-undefined": "sanitizer-runtime",
    "windows-native": "windows-native",
    "docs-structure": "structure",
    "docs-quickstart": "quickstart",
    "docker": "build",
    "juliet": "juliet",
}

CHECK_NAMES = {
    "build-and-test": "build-and-test",
    "resource-budget-macos": "resource-budget-macos",
    "fuzz-smoke": "fuzz-smoke",
    "sanitizer-address": "sanitizer-runtime (address)",
    "sanitizer-undefined": "sanitizer-runtime (undefined)",
    "windows-native": "windows-native",
    "docs-structure": "structure",
    "docs-quickstart": "quickstart",
    "docker": "build",
    "juliet": "juliet",
}


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def zip_bytes(name: str, value: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, value)
    return output.getvalue()


def status_template(gate: str) -> str:
    if gate.startswith("sanitizer-"):
        leaf = "sanitizer-${{ matrix.sanitizer }}"
    else:
        leaf = gate
    return (
        "${{ github.sha }}:refs/status/${{ github.sha }}/"
        f"{leaf}/${{{{ job.status }}}}"
    )


def workflow_blobs() -> dict[str, bytes]:
    by_path: dict[str, list[tuple[str, str]]] = {}
    for gate in stability.REQUIRED_HOSTED_GATES:
        template = status_template(gate)
        record = (GATE_JOB_KEYS[gate], template)
        if record not in by_path.setdefault(GATE_WORKFLOWS[gate], []):
            by_path[GATE_WORKFLOWS[gate]].append(record)
    def block(job_key: str, template: str) -> str:
        condition = ""
        if job_key == "juliet":
            condition = (
                "    if: github.event_name != 'pull_request' ||\n"
                "        github.event.pull_request.draft == false\n"
            )
        shell = "        shell: bash\n" if job_key == "windows-native" else ""
        return (
            f"  {job_key}:\n{condition}    runs-on: fixture\n    steps:\n"
            f"      - name: Mirror status\n        if: always()\n"
            f"{shell}        run: |\n"
            f"          git push --force origin \"{template}\""
        )

    return {
        path: (
            "name: fixture\njobs:\n"
            + "\n".join(block(job_key, template) for job_key, template in templates)
            + "\n"
        ).encode("utf-8")
        for path, templates in by_path.items()
    }


class FakeSource:
    def __init__(self) -> None:
        self.repository = REPOSITORY
        self.revision = REVISION
        self.tree = TREE
        self.blobs = workflow_blobs()

    def repository_identity(self) -> str:
        return self.repository

    def resolve_revision(self, revision: str) -> str:
        if revision != self.revision:
            raise hosted.HostedEvidenceError("unknown revision")
        return self.revision

    def tree_sha1(self, revision: str) -> str:
        self.resolve_revision(revision)
        return self.tree

    def read_file(self, revision: str, path: str) -> bytes:
        self.resolve_revision(revision)
        return self.blobs[path]


class Fixture:
    def __init__(self, root: Path, *, run_attempt: int = 1) -> None:
        self.root = root
        self.input = root / "input"
        self.output = root / "evidence"
        self.source = FakeSource()
        self.run_for_path = {
            path: 1000 + index
            for index, path in enumerate(dict.fromkeys(GATE_WORKFLOWS.values()), 1)
        }
        self.selection = {
            "schema": hosted.SELECTION_SCHEMA,
            "repository": REPOSITORY,
            "revision": REVISION,
            "gates": [
                {
                    "gate_id": gate,
                    "workflow_run_id": self.run_for_path[GATE_WORKFLOWS[gate]],
                    "check_run_id": 2000 + index,
                }
                for index, gate in enumerate(stability.REQUIRED_HOSTED_GATES, 1)
            ],
        }
        self.runs = []
        for path, run_id in self.run_for_path.items():
            suite_id = 5000 + run_id
            self.runs.append({
                "id": run_id,
                "run_attempt": run_attempt,
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "head_sha": REVISION,
                "head_branch": "main",
                "path": f"{path}@main",
                "url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}",
                "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
                "jobs_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}/jobs",
                "logs_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}/logs",
                "check_suite_id": suite_id,
                "check_suite_url": f"https://api.github.com/repos/{REPOSITORY}/check-suites/{suite_id}",
                "repository": {"full_name": REPOSITORY},
            })
        self.check_suites = [
            {
                "id": int(run["check_suite_id"]),
                "head_sha": REVISION,
                "status": "completed",
                "conclusion": "success",
                "url": run["check_suite_url"],
                "check_runs_url": (
                    f"{run['check_suite_url']}/check-runs"
                ),
                "app": {"slug": "github-actions"},
                "repository": {"full_name": REPOSITORY},
            }
            for run in self.runs
        ]
        self.checks = []
        self.jobs_by_run: dict[int, list[dict[str, object]]] = {
            run_id: [] for run_id in self.run_for_path.values()
        }
        for index, gate in enumerate(stability.REQUIRED_HOSTED_GATES, 1):
            run_id = self.run_for_path[GATE_WORKFLOWS[gate]]
            check_id = 2000 + index
            job_id = 4000 + index
            job_html = (
                f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{job_id}"
            )
            self.checks.append({
                "id": check_id,
                "name": CHECK_NAMES[gate],
                "status": "completed",
                "conclusion": "success",
                "head_sha": REVISION,
                "html_url": job_html,
                "details_url": job_html,
                "app": {"slug": "github-actions"},
                "check_suite": {"id": 5000 + run_id},
            })
            self.jobs_by_run[run_id].append({
                "id": job_id,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "run_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}",
                "head_sha": REVISION,
                "url": f"https://api.github.com/repos/{REPOSITORY}/actions/jobs/{job_id}",
                "html_url": job_html,
                "status": "completed",
                "conclusion": "success",
                "name": CHECK_NAMES[gate],
                "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{check_id}",
            })
        self.refs = [
            {
                "ref": f"refs/status/{REVISION}/{gate}/success",
                "object": {
                    "type": "commit",
                    "sha": REVISION,
                    "url": f"https://api.github.com/repos/{REPOSITORY}/git/commits/{REVISION}",
                },
            }
            for gate in stability.REQUIRED_HOSTED_GATES
        ]
        self.artifacts_by_run: dict[int, list[dict[str, object]]] = {}
        for ordinal, run_id in enumerate(self.run_for_path.values(), 1):
            artifact_id = 3000 + ordinal
            archive = zip_bytes(
                f"artifact-{artifact_id}.txt",
                f"artifact-{artifact_id}\n".encode("ascii"),
            )
            digest = hashlib.sha256(archive).hexdigest()
            self.artifacts_by_run[run_id] = [{
                "id": artifact_id,
                "name": f"fixture-{artifact_id}",
                "size_in_bytes": len(archive),
                "expired": False,
                "digest": f"sha256:{digest}",
                "url": f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}",
                "archive_download_url": (
                    f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/"
                    f"{artifact_id}/zip"
                ),
                "workflow_run": {"id": run_id, "head_sha": REVISION},
            }]
            archive_path = self.input / "downloads" / "artifacts" / f"{artifact_id}.zip"
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_path.write_bytes(archive)
        self.write()

    def write(self) -> None:
        write_json(self.input / "selection.json", self.selection)
        write_json(
            self.input / "api" / "workflow-runs.json",
            {"total_count": len(self.runs), "workflow_runs": self.runs},
        )
        write_json(
            self.input / "api" / "check-suites.json",
            {
                "total_count": len(self.check_suites),
                "check_suites": self.check_suites,
            },
        )
        write_json(
            self.input / "api" / "check-runs.json",
            {"total_count": len(self.checks), "check_runs": self.checks},
        )
        write_json(self.input / "api" / "status-refs.json", self.refs)
        for run_id, artifacts in self.artifacts_by_run.items():
            write_json(
                self.input / "api" / "artifacts" / f"{run_id}.json",
                {"total_count": len(artifacts), "artifacts": artifacts},
            )
            attempt = next(run["run_attempt"] for run in self.runs if run["id"] == run_id)
            write_json(
                self.input / "api" / "jobs" / f"{run_id}-attempt-{attempt}.json",
                {
                    "total_count": len(self.jobs_by_run[run_id]),
                    "jobs": self.jobs_by_run[run_id],
                },
            )
            log = (
                self.input / "downloads" / "logs"
                / f"{run_id}-attempt-{attempt}.zip"
            )
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_bytes(zip_bytes(f"run-{run_id}/job.txt", b"log\n"))
            digest = hashlib.sha256(log.read_bytes()).hexdigest()
            write_json(
                self.input / "api" / "log-downloads"
                / f"{run_id}-attempt-{attempt}.json",
                {
                    "schema": hosted.LOG_DOWNLOAD_SCHEMA,
                    "repository": REPOSITORY,
                    "run_id": run_id,
                    "run_attempt": attempt,
                    "request_url": (
                        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                        f"{run_id}/attempts/{attempt}/logs"
                    ),
                    "api_version": "2022-11-28",
                    "redirect_http_status": 302,
                    "redirect_url_origin": (
                        "https://results-receiver.actions.githubusercontent.com"
                    ),
                    "redirect_url_sha256": hashlib.sha256(
                        f"https://results-receiver.actions.githubusercontent.com/"
                        f"logs/{run_id}?token=fixture".encode("ascii")
                    ).hexdigest(),
                    "download_http_status": 200,
                    "content_type": "application/zip",
                    "archive_sha256": digest,
                    "archive_size": log.stat().st_size,
                },
            )
        for artifacts in self.artifacts_by_run.values():
            for artifact in artifacts:
                artifact_id = int(artifact["id"])
                archive_path = (
                    self.input / "downloads" / "artifacts" / f"{artifact_id}.zip"
                )
                redirect_url = (
                    "https://results-receiver.actions.githubusercontent.com/"
                    f"artifacts/{artifact_id}?token=fixture"
                )
                write_json(
                    self.input / "api" / "artifact-downloads" / f"{artifact_id}.json",
                    {
                        "schema": hosted.ARTIFACT_DOWNLOAD_SCHEMA,
                        "repository": REPOSITORY,
                        "artifact_id": artifact_id,
                        "request_url": artifact["archive_download_url"],
                        "api_version": "2022-11-28",
                        "redirect_http_status": 302,
                        "redirect_url_origin": (
                            "https://results-receiver.actions.githubusercontent.com"
                        ),
                        "redirect_url_sha256": hashlib.sha256(
                            redirect_url.encode("ascii")
                        ).hexdigest(),
                        "download_http_status": 200,
                        "content_type": "application/zip",
                        "archive_sha256": hashlib.sha256(
                            archive_path.read_bytes()
                        ).hexdigest(),
                        "archive_size": archive_path.stat().st_size,
                    },
                )

    def seal(self) -> dict[str, object]:
        return hosted.seal_evidence(
            self.output,
            repository=REPOSITORY,
            revision=REVISION,
            source=self.source,
            inputs=hosted.OfflineSnapshotInputs(self.input),
        )

    def verify(self) -> dict[str, object]:
        return hosted.verify_evidence(
            self.output,
            repository=REPOSITORY,
            revision=REVISION,
            source=self.source,
        )


def reseal_outer(root: Path) -> None:
    receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
    receipt_bytes = canonical_bytes(receipt)
    (root / "receipt.json").write_bytes(receipt_bytes)
    digest = hashlib.sha256(receipt_bytes).hexdigest()
    (root / "receipt.json.sha256").write_text(
        f"{digest}  receipt.json\n", encoding="ascii"
    )
    files = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
            for name in files
        ),
        encoding="ascii",
    )


class HostedExactHeadReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_round_trip_is_canonical_and_matches_stability_projector(self) -> None:
        receipt = self.fixture.seal()
        verified = self.fixture.verify()
        self.assertEqual(verified, receipt)
        projection = stability.project_hosted_exact_head_receipt(
            receipt, repository=REPOSITORY, revision=REVISION
        )
        self.assertEqual(projection["gate_count"], 10)
        self.assertEqual(projection["workflow_run_count"], 5)
        self.assertEqual(
            (self.fixture.output / "receipt.json").read_bytes(),
            canonical_bytes(receipt),
        )
        self.assertEqual(receipt["required_gates"], stability.REQUIRED_HOSTED_GATES)
        self.assertEqual(
            [gate["gate_id"] for gate in receipt["gates"]],
            stability.REQUIRED_HOSTED_GATES,
        )
        self.assertEqual(len(receipt["logs"]), 5)
        self.assertEqual(len(receipt["artifacts"]), 5)
        self.assertGreaterEqual(len(receipt["snapshots"]), 1)
        first_gate = receipt["gates"][0]
        self.assertRegex(
            first_gate["url"],
            rf"^https://github\.com/{re.escape(REPOSITORY)}/actions/runs/"
            r"[1-9][0-9]*/job/[1-9][0-9]*$",
        )

    def test_run_event_head_conclusion_attempt_and_repository_are_fail_closed(self) -> None:
        mutations = [
            ("event", "pull_request", "event"),
            ("head_sha", "c" * 40, "exact-head"),
            ("conclusion", "failure", "success"),
            ("run_attempt", 0, "attempt"),
            ("status", "in_progress", "completed"),
            ("repository", {"full_name": "other/repo"}, "repository"),
        ]
        for field, value, message in mutations:
            with self.subTest(field=field):
                fixture = Fixture(Path(self.temporary.name) / field)
                fixture.runs[0][field] = value
                fixture.write()
                with self.assertRaisesRegex(hosted.HostedEvidenceError, message):
                    fixture.seal()

    def test_check_run_and_workflow_run_binding_is_fail_closed(self) -> None:
        cases = [
            ("head_sha", "c" * 40, "exact-head"),
            ("conclusion", "failure", "success"),
            ("status", "queued", "completed"),
            ("name", "wrong-job", "name"),
            ("details_url", "https://github.com/example/CodeSkeptic/actions/runs/9/job/1", "attempt-specific job"),
            ("app", {"slug": "other"}, "GitHub Actions"),
        ]
        for field, value, message in cases:
            with self.subTest(field=field):
                fixture = Fixture(Path(self.temporary.name) / f"check-{field}")
                fixture.checks[0][field] = value
                fixture.write()
                with self.assertRaisesRegex(hosted.HostedEvidenceError, message):
                    fixture.seal()

    def test_status_ref_target_and_github_sha_workflow_policy_are_required(self) -> None:
        self.fixture.refs[0]["object"]["sha"] = "c" * 40
        self.fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "status ref target"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "head-policy")
        path = GATE_WORKFLOWS[stability.REQUIRED_HOSTED_GATES[0]]
        fixture.source.blobs[path] = fixture.source.blobs[path].replace(
            b"${{ github.sha }}:refs/status/", b"HEAD:refs/status/", 1
        )
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "github.sha"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "comment-decoy")
        path = GATE_WORKFLOWS[stability.REQUIRED_HOSTED_GATES[0]]
        expected = status_template("build-and-test").encode("utf-8")
        fixture.source.blobs[path] = fixture.source.blobs[path].replace(
            b'git push --force origin "' + expected + b'"',
            b'echo disabled\n          # git push --force origin "' + expected + b'"',
            1,
        )
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "executable.*github.sha"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "dead-job")
        path = GATE_WORKFLOWS["build-and-test"]
        fixture.source.blobs[path] = fixture.source.blobs[path].replace(
            b"  build-and-test:\n",
            b"  build-and-test:\n    if: false\n",
            1,
        )
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "job.*reachable"):
            fixture.seal()

        for field in ("shell: bash -n {0}", "shell: true {0}", "continue-on-error: true"):
            with self.subTest(dead_step=field):
                fixture = Fixture(
                    Path(self.temporary.name) / ("dead-step-" + field.split(":", 1)[0])
                )
                path = GATE_WORKFLOWS["build-and-test"]
                fixture.source.blobs[path] = fixture.source.blobs[path].replace(
                    b"        run: |\n",
                    f"        {field}\n        run: |\n".encode("utf-8"),
                    1,
                )
                with self.assertRaisesRegex(
                    hosted.HostedEvidenceError, "status step execution policy"
                ):
                    fixture.seal()

    def test_status_policy_parses_only_executable_yaml_structure(self) -> None:
        template = status_template("build-and-test")
        command = f'git push --force origin "{template}"'

        scalar_decoy = f"""name: |
  build-and-test:
    runs-on: fixture
    steps:
      - name: Decoy
        if: always()
        run: |
          {command}
jobs:
  "build-and-test":
    if: false
    runs-on: fixture
    steps:
      - run: echo disabled
""".encode("utf-8")
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "scalar|reachable|structure"
        ):
            hosted._validate_status_policy(scalar_decoy, "build-and-test")

        explicit_key_decoy = scalar_decoy.replace(
            b'  "build-and-test":\n', b"  ? build-and-test\n  :\n", 1
        )
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "reachable|executable|structure"
        ):
            hosted._validate_status_policy(explicit_key_decoy, "build-and-test")

        env_decoy = f"""name: fixture
jobs:
  build-and-test:
    env:
      DECOY: |
        steps:
          - name: Decoy
            if: always()
            run: |
              {command}
    runs-on: fixture
    steps:
      - run: echo disabled
""".encode("utf-8")
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "scalar|executable|structure"
        ):
            hosted._validate_status_policy(env_decoy, "build-and-test")

        aliased_key = f"""name: fixture
x-condition: &condition if
jobs:
  build-and-test:
    *condition: false
    runs-on: fixture
    steps:
      - name: Mirror status
        if: always()
        run: |
          {command}
""".encode("utf-8")
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "anchor|alias|reachable"
        ):
            hosted._validate_status_policy(aliased_key, "build-and-test")

        merged_policy = f"""name: fixture
x-policy: &policy
  continue-on-error: true
jobs:
  build-and-test:
    <<: *policy
    runs-on: fixture
    steps:
      - name: Mirror status
        if: always()
        run: |
          {command}
""".encode("utf-8")
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "anchor|alias|merge|defaults"
        ):
            hosted._validate_status_policy(merged_policy, "build-and-test")

        valid = workflow_blobs()[GATE_WORKFLOWS["build-and-test"]]
        valid_with_name_decoy = valid.replace(
            b"name: fixture\n",
            f"name: |\n  {command}\n".encode("utf-8"),
            1,
        )
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "executable.*github.sha"
        ):
            hosted._validate_status_policy(valid_with_name_decoy, "build-and-test")

        valid_with_env_decoy = valid.replace(
            b"  build-and-test:\n",
            (
                "  build-and-test:\n"
                "    env:\n"
                "      DECOY: |\n"
                f"        {command}\n"
            ).encode("utf-8"),
            1,
        )
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "executable.*github.sha"
        ):
            hosted._validate_status_policy(valid_with_env_decoy, "build-and-test")

        for field in (
            "shell: bash -n {0}",
            "shell: python {0}",
            "continue-on-error: true",
        ):
            with self.subTest(post_run_field=field):
                mutated = valid.replace(
                    f'          {command}\n'.encode("utf-8"),
                    f'          {command}\n        {field}\n'.encode("utf-8"),
                    1,
                )
                with self.assertRaisesRegex(
                    hosted.HostedEvidenceError, "status step execution policy|structure"
                ):
                    hosted._validate_status_policy(mutated, "build-and-test")

        folded = valid.replace(b"        run: |\n", b"        run: >\n", 1)
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "scalar|literal|executable|structure"
        ):
            hosted._validate_status_policy(folded, "build-and-test")

        trailing_shell_space = valid.replace(
            f"          {command}\n".encode("utf-8"),
            f"          {command} \n".encode("utf-8"),
            1,
        )
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "executable.*github.sha"
        ):
            hosted._validate_status_policy(trailing_shell_space, "build-and-test")

        duplicate_key = valid.replace(
            b"name: fixture\n", b"name: first\nname: fixture\n", 1
        )
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "duplicate"):
            hosted._validate_status_policy(duplicate_key, "build-and-test")

    def test_repository_workflows_satisfy_structural_status_policy(self) -> None:
        for gate, relative in hosted.GATE_WORKFLOWS.items():
            with self.subTest(gate=gate):
                hosted._validate_status_policy((ROOT / relative).read_bytes(), gate)

    def test_every_selected_run_requires_a_downloaded_log(self) -> None:
        run_id = next(iter(self.fixture.run_for_path.values()))
        attempt = next(
            run["run_attempt"] for run in self.fixture.runs if run["id"] == run_id
        )
        (
            self.fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        ).unlink()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "log archive"):
            self.fixture.seal()

    def test_log_zip_and_attempt_specific_job_authority_are_required(self) -> None:
        run_id = next(iter(self.fixture.run_for_path.values()))
        attempt = next(
            run["run_attempt"] for run in self.fixture.runs if run["id"] == run_id
        )
        log = (
            self.fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        log.write_bytes(b"not a zip")
        metadata = (
            self.fixture.input / "api" / "log-downloads"
            / f"{run_id}-attempt-{attempt}.json"
        )
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["archive_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        value["archive_size"] = log.stat().st_size
        write_json(metadata, value)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "ZIP"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "attempt-job")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.jobs_by_run[run_id][0]["run_id"] = 999
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "attempt.*job"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "attempt-number")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.jobs_by_run[run_id][0]["run_attempt"] = 2
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "job.*attempt"):
            fixture.seal()

    def test_download_authority_requires_exact_two_hop_302_to_200(self) -> None:
        run_id = next(iter(self.fixture.run_for_path.values()))
        attempt = next(
            run["run_attempt"] for run in self.fixture.runs if run["id"] == run_id
        )
        log_authority = (
            self.fixture.input / "api" / "log-downloads"
            / f"{run_id}-attempt-{attempt}.json"
        )
        for field, value, message in (
            ("redirect_http_status", 200, "log download authority"),
            ("download_http_status", 302, "log download authority"),
            ("api_version", "unversioned", "API version"),
            ("redirect_url_origin", "https://api.github.com", "redirect origin"),
            ("redirect_url_sha256", "not-a-sha256", "redirect URL"),
        ):
            with self.subTest(field=field):
                fixture = Fixture(Path(self.temporary.name) / f"log-hop-{field}")
                path = (
                    fixture.input / "api" / "log-downloads"
                    / f"{run_id}-attempt-{attempt}.json"
                )
                value_object = json.loads(path.read_text(encoding="utf-8"))
                value_object[field] = value
                write_json(path, value_object)
                with self.assertRaisesRegex(hosted.HostedEvidenceError, message):
                    fixture.seal()

        artifact_id = int(self.fixture.artifacts_by_run[run_id][0]["id"])
        artifact_authority = (
            self.fixture.input / "api" / "artifact-downloads" / f"{artifact_id}.json"
        )
        value_object = json.loads(artifact_authority.read_text(encoding="utf-8"))
        value_object["download_http_status"] = 302
        write_json(artifact_authority, value_object)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "artifact download authority"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "missing-attempt-number")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.jobs_by_run[run_id][0].pop("run_attempt")
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "job.*attempt"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "boolean-attempt-number")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.jobs_by_run[run_id][0]["run_attempt"] = True
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "job.*attempt"):
            fixture.seal()

    def test_log_zip_rejects_trailing_non_zip_bytes(self) -> None:
        run_id = next(iter(self.fixture.run_for_path.values()))
        attempt = next(
            run["run_attempt"] for run in self.fixture.runs if run["id"] == run_id
        )
        log = (
            self.fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        log.write_bytes(log.read_bytes() + b"untrusted trailer")
        metadata = (
            self.fixture.input / "api" / "log-downloads"
            / f"{run_id}-attempt-{attempt}.json"
        )
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["archive_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        value["archive_size"] = log.stat().st_size
        write_json(metadata, value)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "ZIP framing"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "concatenated-zips")
        run_id = next(iter(fixture.run_for_path.values()))
        attempt = next(run["run_attempt"] for run in fixture.runs if run["id"] == run_id)
        log = (
            fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        log.write_bytes(zip_bytes("hidden.txt", b"hidden") + zip_bytes("shown.txt", b"shown"))
        metadata = (
            fixture.input / "api" / "log-downloads"
            / f"{run_id}-attempt-{attempt}.json"
        )
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["archive_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        value["archive_size"] = log.stat().st_size
        write_json(metadata, value)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "ZIP framing"):
            fixture.seal()

    def test_artifact_provider_digest_size_and_local_sha_are_bound(self) -> None:
        run_id = next(iter(self.fixture.run_for_path.values()))
        artifact = self.fixture.artifacts_by_run[run_id][0]
        artifact["digest"] = "sha256:" + "0" * 64
        self.fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "provider digest"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "artifact-size")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.artifacts_by_run[run_id][0]["size_in_bytes"] = 999
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "artifact size"):
            fixture.seal()

    def test_artifacts_are_bound_to_the_selected_workflow_attempt(self) -> None:
        fixture = Fixture(Path(self.temporary.name) / "rerun-unprovable", run_attempt=2)
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "artifact.*attempt.*provenance"
        ):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "rerun-mismatch", run_attempt=2)
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.artifacts_by_run[run_id][0]["run_attempt"] = 1
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "artifact.*attempt"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "rerun-exact", run_attempt=2)
        for artifacts in fixture.artifacts_by_run.values():
            for artifact in artifacts:
                artifact["run_attempt"] = 2
        fixture.write()
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "artifact.*attempt.*provenance"
        ):
            fixture.seal()

    def test_api_pagination_snapshots_must_be_complete(self) -> None:
        write_json(
            self.fixture.input / "api" / "check-runs.json",
            {"total_count": len(self.fixture.checks) + 1, "check_runs": self.fixture.checks},
        )
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "incomplete"):
            self.fixture.seal()

    def test_complete_suite_authority_and_provider_caps_are_required(self) -> None:
        fixture = Fixture(Path(self.temporary.name) / "missing-suite")
        fixture.check_suites.pop()
        fixture.write()
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "absent from complete suite authority"
        ):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "workflow-cap")
        with mock.patch.object(
            hosted,
            "PROVIDER_FILTERED_RESULT_CAP",
            len(fixture.runs),
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "workflow-run authority is ambiguous"
        ):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "suite-cap")
        extra_suite_id = 999_999
        fixture.check_suites.append({
            "id": extra_suite_id,
            "head_sha": REVISION,
            "status": "completed",
            "conclusion": "success",
            "url": (
                f"https://api.github.com/repos/{REPOSITORY}/check-suites/"
                f"{extra_suite_id}"
            ),
            "check_runs_url": (
                f"https://api.github.com/repos/{REPOSITORY}/check-suites/"
                f"{extra_suite_id}/check-runs"
            ),
            "app": {"slug": "github-actions"},
            "repository": {"full_name": REPOSITORY},
        })
        fixture.write()
        with mock.patch.object(
            hosted,
            "PROVIDER_FILTERED_RESULT_CAP",
            len(fixture.check_suites),
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "check-suite authority is ambiguous"
        ):
            fixture.seal()

    def test_selected_suite_lifecycle_app_and_repository_are_bound(self) -> None:
        cases = (
            ("status", "status", "in_progress"),
            ("conclusion", "conclusion", "failure"),
            ("app", "app", {"slug": "foreign-app"}),
            (
                "repository",
                "repository",
                {"full_name": "foreign/repository"},
            ),
        )
        for case, field, value in cases:
            with self.subTest(case=case):
                fixture = Fixture(
                    Path(self.temporary.name) / f"suite-binding-{case}"
                )
                fixture.check_suites[0][field] = value
                fixture.write()
                with self.assertRaisesRegex(
                    hosted.HostedEvidenceError,
                    "no admissible attempt-one workflow run",
                ):
                    fixture.seal()

    def test_selection_must_be_exact_ordered_and_coherent_by_workflow(self) -> None:
        self.fixture.selection["gates"].reverse()
        self.fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "required gate order"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "mixed-run")
        fixture.selection["gates"][1]["workflow_run_id"] = fixture.run_for_path[
            ".github/workflows/windows.yml"
        ]
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "workflow run binding"):
            fixture.seal()

    def test_valid_manual_alternative_is_rejected_by_offline_rederivation(self) -> None:
        fixture = Fixture(Path(self.temporary.name) / "manual-alternative")
        gate_id = "juliet"
        original_run_id = fixture.run_for_path[GATE_WORKFLOWS[gate_id]]
        original_run = next(
            run for run in fixture.runs if run["id"] == original_run_id
        )
        original_check = next(
            check for check in fixture.checks
            if check["name"] == CHECK_NAMES[gate_id]
        )
        original_job = fixture.jobs_by_run[original_run_id][0]
        original_artifact_ids = [
            int(artifact["id"])
            for artifact in fixture.artifacts_by_run[original_run_id]
        ]
        alternative_run_id = 90_001
        alternative_suite_id = 90_002
        alternative_check_id = 90_003
        alternative_job_id = 90_004
        job_html = (
            f"https://github.com/{REPOSITORY}/actions/runs/"
            f"{alternative_run_id}/job/{alternative_job_id}"
        )
        alternative_run = json.loads(json.dumps(original_run))
        alternative_run.update({
            "id": alternative_run_id,
            "url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                f"{alternative_run_id}"
            ),
            "html_url": (
                f"https://github.com/{REPOSITORY}/actions/runs/"
                f"{alternative_run_id}"
            ),
            "jobs_url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                f"{alternative_run_id}/jobs"
            ),
            "logs_url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                f"{alternative_run_id}/logs"
            ),
            "check_suite_id": alternative_suite_id,
            "check_suite_url": (
                f"https://api.github.com/repos/{REPOSITORY}/check-suites/"
                f"{alternative_suite_id}"
            ),
        })
        alternative_check = json.loads(json.dumps(original_check))
        alternative_check.update({
            "id": alternative_check_id,
            "html_url": job_html,
            "details_url": job_html,
            "check_suite": {"id": alternative_suite_id},
        })
        alternative_job = json.loads(json.dumps(original_job))
        alternative_job.update({
            "id": alternative_job_id,
            "run_id": alternative_run_id,
            "run_url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                f"{alternative_run_id}"
            ),
            "url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/jobs/"
                f"{alternative_job_id}"
            ),
            "html_url": job_html,
            "check_run_url": (
                f"https://api.github.com/repos/{REPOSITORY}/check-runs/"
                f"{alternative_check_id}"
            ),
        })
        fixture.runs.append(alternative_run)
        fixture.check_suites.append({
            "id": alternative_suite_id,
            "head_sha": REVISION,
            "status": "completed",
            "conclusion": "success",
            "url": alternative_run["check_suite_url"],
            "check_runs_url": (
                f"{alternative_run['check_suite_url']}/check-runs"
            ),
            "app": {"slug": "github-actions"},
            "repository": {"full_name": REPOSITORY},
        })
        fixture.checks.append(alternative_check)
        fixture.jobs_by_run[alternative_run_id] = [alternative_job]
        fixture.artifacts_by_run[alternative_run_id] = []
        fixture.artifacts_by_run[original_run_id] = []
        next(
            gate for gate in fixture.selection["gates"]
            if gate["gate_id"] == gate_id
        ).update({
            "workflow_run_id": alternative_run_id,
            "check_run_id": alternative_check_id,
        })
        fixture.write()

        attempt = int(original_run["run_attempt"])
        for path in (
            fixture.input / "api/artifacts" / f"{original_run_id}.json",
            fixture.input / "api/jobs"
            / f"{original_run_id}-attempt-{attempt}.json",
            fixture.input / "api/log-downloads"
            / f"{original_run_id}-attempt-{attempt}.json",
            fixture.input / "downloads/logs"
            / f"{original_run_id}-attempt-{attempt}.zip",
        ):
            path.unlink()
        for artifact_id in original_artifact_ids:
            (
                fixture.input / "api/artifact-downloads"
                / f"{artifact_id}.json"
            ).unlink()
            (
                fixture.input / "downloads/artifacts" / f"{artifact_id}.zip"
            ).unlink()

        with self.assertRaisesRegex(
            hosted.HostedEvidenceError,
            "differs from deterministic provider selection",
        ):
            fixture.seal()

    def test_workflow_path_ref_shape_is_normalized_but_must_match_head(self) -> None:
        receipt = self.fixture.seal()
        self.assertEqual(receipt["runs"][0]["workflow_path"], ".github/workflows/ci.yml")

        fixture = Fixture(Path(self.temporary.name) / "wrong-workflow-ref")
        fixture.runs[0]["path"] = ".github/workflows/ci.yml@other"
        fixture.write()
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "workflow.*ref"):
            fixture.seal()

    def test_provider_urls_are_bound_to_their_exact_ids(self) -> None:
        mutations = []
        fixture = Fixture(Path(self.temporary.name) / "run-url")
        fixture.runs[0]["html_url"] = (
            f"https://github.com/{REPOSITORY}/actions/runs/999"
        )
        mutations.append((fixture, "workflow run URL"))

        fixture = Fixture(Path(self.temporary.name) / "check-url")
        fixture.checks[0]["html_url"] = f"https://github.com/{REPOSITORY}/runs/999"
        mutations.append((fixture, "check-run URL"))

        fixture = Fixture(Path(self.temporary.name) / "artifact-url")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.artifacts_by_run[run_id][0]["url"] = (
            f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/999"
        )
        mutations.append((fixture, "artifact URL"))

        fixture = Fixture(Path(self.temporary.name) / "job-html-url")
        run_id = next(iter(fixture.run_for_path.values()))
        fixture.jobs_by_run[run_id][0]["html_url"] = (
            f"https://github.com/{REPOSITORY}/actions/runs/999/job/888"
        )
        fixture.checks[0]["details_url"] = fixture.jobs_by_run[run_id][0]["html_url"]
        mutations.append((fixture, "attempt job URL"))

        fixture = Fixture(Path(self.temporary.name) / "status-url")
        fixture.refs[0]["object"]["url"] = (
            f"https://api.github.com/repos/{REPOSITORY}/git/commits/{'c' * 40}"
        )
        mutations.append((fixture, "status-ref.*URL"))

        for fixture, message in mutations:
            with self.subTest(root=fixture.root.name):
                fixture.write()
                with self.assertRaisesRegex(hosted.HostedEvidenceError, message):
                    fixture.seal()

    def test_input_inventory_rejects_unknown_files_and_symlinks(self) -> None:
        (self.fixture.input / "unexpected.txt").write_text("no\n", encoding="ascii")
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "input inventory"):
            self.fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "symlink")
        target = fixture.root / "outside.zip"
        target.write_bytes(b"outside")
        run_id = next(iter(fixture.run_for_path.values()))
        attempt = next(run["run_attempt"] for run in fixture.runs if run["id"] == run_id)
        log = (
            fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        log.unlink()
        log.symlink_to(target)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "symlink"):
            fixture.seal()

        fixture = Fixture(Path(self.temporary.name) / "hardlink")
        run_id = next(iter(fixture.run_for_path.values()))
        attempt = next(run["run_attempt"] for run in fixture.runs if run["id"] == run_id)
        log = (
            fixture.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        os.link(log, fixture.root / "outside-hardlink.zip")
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "hardlink"):
            fixture.seal()

    def test_bundle_tampering_extras_and_resealed_receipt_are_rejected(self) -> None:
        self.fixture.seal()
        run_id = next(iter(self.fixture.run_for_path.values()))
        attempt = next(
            run["run_attempt"] for run in self.fixture.runs if run["id"] == run_id
        )
        log = (
            self.fixture.output / "raw" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        )
        log.write_bytes(b"changed")
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "SHA256SUMS"):
            self.fixture.verify()

        fixture = Fixture(Path(self.temporary.name) / "extra")
        fixture.seal()
        (fixture.output / "extra.txt").write_text("extra\n", encoding="ascii")
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "inventory"):
            fixture.verify()

        fixture = Fixture(Path(self.temporary.name) / "receipt")
        fixture.seal()
        receipt_path = fixture.output / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["gates"][0]["check_run_id"] += 100
        receipt_path.write_bytes(canonical_bytes(receipt))
        reseal_outer(fixture.output)
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "rederived"):
            fixture.verify()

    def test_verification_rederives_git_tree_and_workflow_blobs(self) -> None:
        self.fixture.seal()
        self.fixture.source.tree = "c" * 40
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "tree"):
            self.fixture.verify()

        fixture = Fixture(Path(self.temporary.name) / "workflow-drift")
        fixture.seal()
        path = ".github/workflows/ci.yml"
        fixture.source.blobs[path] += b"# drift\n"
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "workflow blob"):
            fixture.verify()

    def test_verification_rejects_evidence_changed_during_rederivation(self) -> None:
        receipt = self.fixture.seal()
        retained_log = self.fixture.output / receipt["logs"][0]["path"]
        original_snapshot_record = hosted._snapshot_record
        mutated = False

        def mutate_after_logs(
            root: Path, relative: str, label: str
        ) -> dict[str, object]:
            nonlocal mutated
            if not mutated:
                retained_log.write_bytes(b"changed after log verification\n")
                mutated = True
            return original_snapshot_record(root, relative, label)

        with mock.patch.object(
            hosted, "_snapshot_record", side_effect=mutate_after_logs
        ):
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "changed during verification"
            ):
                self.fixture.verify()

    def test_seal_and_verify_enforce_aggregate_input_budgets(self) -> None:
        fixture = Fixture(Path(self.temporary.name) / "collection-budget")
        artifact_api = next((fixture.input / "api" / "artifacts").iterdir())
        value = json.loads(artifact_api.read_text(encoding="utf-8"))
        value["total_count"] = hosted.MAX_COLLECTION_ITEMS + 1
        artifact_api.write_bytes(canonical_bytes(value))
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "collection item budget"
        ):
            fixture.seal()
        self.assertFalse(fixture.output.exists())

        fixture = Fixture(Path(self.temporary.name) / "archive-byte-budget")
        archives = sorted((fixture.input / "downloads").rglob("*.zip"))
        compressed_total = sum(path.stat().st_size for path in archives)
        with mock.patch.object(
            hosted, "MAX_ARCHIVE_TOTAL_BYTES", compressed_total - 1
        ):
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "aggregate archive byte budget"
            ):
                fixture.seal()
        self.assertFalse(fixture.output.exists())

        fixture = Fixture(Path(self.temporary.name) / "zip-expansion-budget")
        archives = sorted((fixture.input / "downloads").rglob("*.zip"))
        expanded_total = 0
        for archive_path in archives:
            with zipfile.ZipFile(archive_path, "r") as archive:
                expanded_total += sum(item.file_size for item in archive.infolist())
        with mock.patch.object(
            hosted,
            "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            expanded_total - 1,
        ):
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "ZIP expands|expansion budget"
            ):
                fixture.seal()
        self.assertFalse(fixture.output.exists())

        fixture = Fixture(Path(self.temporary.name) / "verify-archive-budget")
        fixture.seal()
        retained_archives = sorted((fixture.output / "raw").rglob("*.zip"))
        retained_total = sum(path.stat().st_size for path in retained_archives)
        with mock.patch.object(
            hosted, "MAX_ARCHIVE_TOTAL_BYTES", retained_total - 1
        ):
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "aggregate archive byte budget"
            ):
                fixture.verify()

    def test_output_is_not_overwritten_and_failed_seal_is_not_published(self) -> None:
        self.fixture.output.mkdir()
        sentinel = self.fixture.output / "sentinel"
        sentinel.write_text("keep\n", encoding="ascii")
        with self.assertRaisesRegex(hosted.HostedEvidenceError, "already exists"):
            self.fixture.seal()
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep\n")

        fixture = Fixture(Path(self.temporary.name) / "failed")
        fixture.runs[0]["conclusion"] = "failure"
        fixture.write()
        with self.assertRaises(hosted.HostedEvidenceError):
            fixture.seal()
        self.assertFalse(fixture.output.exists())

    def test_seal_publication_interrupts_are_identity_safe(self) -> None:
        root = Path(self.temporary.name)
        fixture = Fixture(root / "temporary-interrupt")
        fixture.output.parent.mkdir(parents=True, exist_ok=True)
        real_mkdir = hosted.os.mkdir

        def mkdir_then_interrupt(path, mode=0o777, *args, **kwargs):
            result = real_mkdir(path, mode, *args, **kwargs)
            if Path(path).name.startswith(f".{fixture.output.name}.tmp-"):
                raise KeyboardInterrupt()
            return result

        with mock.patch.object(
            hosted.os, "mkdir", side_effect=mkdir_then_interrupt
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "cleanup withheld"
        ):
            fixture.seal()
        self.assertFalse(fixture.output.exists())
        retained = list(
            fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")
        )
        self.assertEqual(len(retained), 1)
        retained[0].rmdir()

        fixture = Fixture(root / "publication-interrupt")
        real_rename = hosted._rename_noreplace

        def rename_then_interrupt(source, destination):
            real_rename(source, destination)
            raise KeyboardInterrupt()

        with mock.patch.object(
            hosted, "_rename_noreplace", side_effect=rename_then_interrupt
        ), self.assertRaises(KeyboardInterrupt):
            fixture.seal()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

        fixture = Fixture(root / "publication-replacement")
        marker = fixture.output / "owner-data"

        def rename_replace_then_interrupt(source, destination):
            real_rename(source, destination)
            shutil.rmtree(destination)
            Path(destination).mkdir()
            marker.write_text("preserve\n", encoding="utf-8")
            raise KeyboardInterrupt()

        with mock.patch.object(
            hosted,
            "_rename_noreplace",
            side_effect=rename_replace_then_interrupt,
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "identity changed"
        ):
            fixture.seal()
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

        fixture = Fixture(root / "publication-replacement-return")
        marker = fixture.output / "owner-data"

        def rename_replace_then_return(source, destination):
            real_rename(source, destination)
            shutil.rmtree(destination)
            Path(destination).mkdir()
            marker.write_text("preserve\n", encoding="utf-8")

        with mock.patch.object(
            hosted,
            "_rename_noreplace",
            side_effect=rename_replace_then_return,
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "identity changed"
        ):
            fixture.seal()
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_hosted_cleanup_quarantine_preserves_concurrent_foreign_tree(
        self,
    ) -> None:
        root = Path(self.temporary.name) / "cleanup-quarantine"
        root.mkdir()
        owned = root / "published"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        metadata = owned.lstat()
        marker = owned / "foreign-data"
        real_rename_at = hosted._rename_noreplace_at
        injected = False

        def quarantine_then_replace(
            source_directory, source, target_directory, target,
        ):
            nonlocal injected
            result = real_rename_at(
                source_directory,
                source,
                target_directory,
                target,
            )
            if not injected and target.startswith(
                ".codeskeptic-hosted-cleanup-"
            ):
                injected = True
                owned.mkdir()
                marker.write_text("preserve\n", encoding="utf-8")
            return result

        with mock.patch.object(
            hosted,
            "_rename_noreplace_at",
            side_effect=quarantine_then_replace,
        ):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertEqual(
            list(root.glob(".codeskeptic-hosted-cleanup-*")), []
        )

        owned = root / "predelete-interrupted"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        metadata = owned.lstat()
        real_make_removable = hosted._make_tree_removable_at
        interrupted = False

        def make_removable_then_interrupt(parent_descriptor, name):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return real_make_removable(parent_descriptor, name)

        with mock.patch.object(
            hosted,
            "_make_tree_removable_at",
            side_effect=make_removable_then_interrupt,
        ), self.assertRaises(KeyboardInterrupt):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertFalse(owned.exists())
        self.assertEqual(
            list(root.glob(".codeskeptic-hosted-cleanup-*")), []
        )

        owned = root / "chmod-interrupted"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        owned.chmod(0o500)
        metadata = owned.lstat()
        real_fchmod = hosted.os.fchmod
        interrupted = False

        def fchmod_then_interrupt(descriptor, mode):
            nonlocal interrupted
            result = real_fchmod(descriptor, mode)
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return result

        with mock.patch.object(
            hosted.os,
            "fchmod",
            side_effect=fchmod_then_interrupt,
        ), self.assertRaises(KeyboardInterrupt):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertFalse(owned.exists())
        self.assertEqual(
            list(root.glob(".codeskeptic-hosted-cleanup-*")), []
        )

        owned = root / "delete-interrupted"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        metadata = owned.lstat()
        real_rmtree = hosted.shutil.rmtree
        interrupted = False

        def rmtree_then_interrupt(path, *args, **kwargs):
            nonlocal interrupted
            if not interrupted and str(path).startswith(
                ".codeskeptic-hosted-cleanup-"
            ):
                interrupted = True
                raise KeyboardInterrupt()
            return real_rmtree(path, *args, **kwargs)

        with mock.patch.object(
            hosted.shutil,
            "rmtree",
            side_effect=rmtree_then_interrupt,
        ), self.assertRaises(KeyboardInterrupt):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertFalse(owned.exists())
        self.assertEqual(
            list(root.glob(".codeskeptic-hosted-cleanup-*")), []
        )

        owned = root / "interrupted"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        metadata = owned.lstat()
        real_rename_at = hosted._rename_noreplace_at
        interrupted = False

        def quarantine_then_interrupt(
            source_directory, source, target_directory, target,
        ):
            nonlocal interrupted
            result = real_rename_at(
                source_directory,
                source,
                target_directory,
                target,
            )
            if not interrupted and target.startswith(
                ".codeskeptic-hosted-cleanup-"
            ):
                interrupted = True
                raise KeyboardInterrupt()
            return result

        with mock.patch.object(
            hosted,
            "_rename_noreplace_at",
            side_effect=quarantine_then_interrupt,
        ), self.assertRaises(KeyboardInterrupt):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertTrue((owned / "owned-data").is_file())
        self.assertEqual(
            list(root.glob(".codeskeptic-hosted-cleanup-*")), []
        )

    def test_private_staging_pin_failure_preserves_replacement(self) -> None:
        root = Path(self.temporary.name) / "private-creator-race"
        root.mkdir()
        replacement: Path | None = None

        def replace_then_fail(path, *_arguments, **_keywords):
            nonlocal replacement
            replacement = Path(path)
            replacement.rmdir()
            replacement.mkdir(mode=0o700)
            (replacement / "foreign-data").write_text(
                "preserve\n", encoding="utf-8"
            )
            raise hosted.HostedEvidenceError(
                "identity changed while pinning"
            )

        with mock.patch.object(
            hosted,
            "_open_tree_identity_pin",
            side_effect=replace_then_fail,
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "cleanup withheld"
        ):
            hosted._create_private_staging_directory(
                root, ".creator-race-", "creator fixture"
            )
        assert replacement is not None
        self.assertEqual(
            (replacement / "foreign-data").read_text(encoding="utf-8"),
            "preserve\n",
        )

    def test_hosted_cleanup_restore_collision_preserves_every_tree(self) -> None:
        root = Path(self.temporary.name) / "cleanup-restore-collision"
        root.mkdir()
        owned = root / "published"
        owned.mkdir()
        (owned / "owned-data").write_text("owned\n", encoding="utf-8")
        metadata = owned.lstat()
        moved_owned = root / "moved-owned"
        real_rename_at = hosted._rename_noreplace_at
        injected = False

        def quarantine_then_conflict(
            source_directory, source, target_directory, target,
        ):
            nonlocal injected
            result = real_rename_at(
                source_directory,
                source,
                target_directory,
                target,
            )
            if not injected and target.startswith(
                ".codeskeptic-hosted-cleanup-"
            ):
                injected = True
                os.rename(
                    target,
                    moved_owned.name,
                    src_dir_fd=target_directory,
                    dst_dir_fd=target_directory,
                )
                os.mkdir(target, dir_fd=target_directory)
                Path(root / target / "quarantined-foreign").write_text(
                    "preserve\n", encoding="utf-8"
                )
                owned.mkdir()
                (owned / "path-foreign").write_text(
                    "preserve\n", encoding="utf-8"
                )
            return result

        with mock.patch.object(
            hosted,
            "_rename_noreplace_at",
            side_effect=quarantine_then_conflict,
        ), self.assertRaisesRegex(
            hosted.HostedEvidenceError, "retained quarantine"
        ):
            hosted._remove_tree_identity(
                owned, metadata.st_dev, metadata.st_ino
            )
        self.assertTrue((moved_owned / "owned-data").is_file())
        self.assertTrue((owned / "path-foreign").is_file())
        quarantines = list(root.glob(".codeskeptic-hosted-cleanup-*"))
        self.assertEqual(len(quarantines), 1)
        self.assertTrue((quarantines[0] / "quarantined-foreign").is_file())

    def test_raw_api_mutation_is_rejected_even_when_json_stays_valid(self) -> None:
        self.fixture.seal()
        snapshot = self.fixture.output / "raw" / "api" / "workflow-runs.json"
        value = json.loads(snapshot.read_text(encoding="utf-8"))
        value["workflow_runs"][0]["run_attempt"] = 3
        snapshot.write_bytes(canonical_bytes(value))
        reseal_outer(self.fixture.output)
        receipt = json.loads(
            (self.fixture.output / "receipt.json").read_text(encoding="utf-8")
        )
        for record in receipt["snapshots"]:
            if record["path"] == "raw/api/workflow-runs.json":
                record["sha256"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                record["size"] = snapshot.stat().st_size
        (self.fixture.output / "receipt.json").write_bytes(canonical_bytes(receipt))
        reseal_outer(self.fixture.output)
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "attempt-specific job|rederived"
        ):
            self.fixture.verify()

    def test_git_source_disables_replace_objects_and_ambient_git_state(self) -> None:
        repository = Path(self.temporary.name) / "git-source"
        repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Fixture"], cwd=repository, check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.invalid"],
            cwd=repository,
            check=True,
        )
        subprocess.run(
            ["git", "remote", "add", "origin", f"https://github.com/{REPOSITORY}.git"],
            cwd=repository,
            check=True,
        )
        workflow = repository / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("original\n", encoding="ascii")
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "original"], cwd=repository, check=True)
        original = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
        original_tree = subprocess.check_output(
            ["git", "--no-replace-objects", "rev-parse", f"{original}^{{tree}}"],
            cwd=repository,
        ).decode().strip()
        workflow.write_text("replacement\n", encoding="ascii")
        subprocess.run(["git", "commit", "-qam", "replacement"], cwd=repository, check=True)
        replacement = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
        subprocess.run(["git", "replace", original, replacement], cwd=repository, check=True)

        subprocess.run(["git", "remote", "remove", "origin"], cwd=repository, check=True)
        source = hosted.GitSourceAuthority(repository, repository=REPOSITORY)
        with mock.patch.dict(
            os.environ,
            {"GIT_DIR": "/definitely/not/the/repository", "GIT_REPLACE_REF_BASE": "refs/replace/"},
        ):
            self.assertEqual(source.repository_identity(), REPOSITORY)
            self.assertEqual(source.resolve_revision(original), original)
            self.assertEqual(source.tree_sha1(original), original_tree)
            self.assertEqual(
                source.read_file(original, ".github/workflows/ci.yml"), b"original\n"
            )

    def test_git_source_rejects_oversized_workflow_before_blob_capture(self) -> None:
        repository = Path(self.temporary.name) / "oversized-git-source"
        repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Fixture"], cwd=repository, check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.invalid"],
            cwd=repository,
            check=True,
        )
        workflow = repository / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(b"x" * (hosted.MAX_WORKFLOW_BYTES + 1))
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "oversized"], cwd=repository, check=True)
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository
        ).decode("ascii").strip()

        source = hosted.GitSourceAuthority(repository, repository=REPOSITORY)
        with self.assertRaisesRegex(
            hosted.HostedEvidenceError, "workflow blob size exceeds"
        ):
            source.read_file(revision, ".github/workflows/ci.yml")

    def test_source_command_runner_bounds_stdout_and_stderr(self) -> None:
        runner = hosted.SubprocessCommandRunner()
        cases = (
            (
                "stdout",
                [sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
                1024,
                4096,
            ),
            (
                "stderr",
                [sys.executable, "-c", "import os; os.write(2, b'x' * 65536)"],
                4096,
                1024,
            ),
        )
        for label, argv, stdout_limit, stderr_limit in cases:
            with self.subTest(label=label):
                started = time.monotonic()
                with self.assertRaisesRegex(
                    hosted.HostedEvidenceError, f"{label}.*size limit"
                ):
                    runner.run(
                        argv,
                        cwd=Path(self.temporary.name),
                        maximum_stdout=stdout_limit,
                        maximum_stderr=stderr_limit,
                        timeout_seconds=2.0,
                    )
                self.assertLess(time.monotonic() - started, 1.5)

    def test_source_command_timeout_reaps_detached_descendant(self) -> None:
        root = Path(self.temporary.name) / "timeout-source-command"
        root.mkdir()
        pid_path = root / "detached.pid"
        child_program = (
            "import os,time; "
            "raw=open('/proc/self/stat').read(); "
            "started=raw[raw.rfind(')')+2:].split()[19]; "
            f"open({str(pid_path)!r},'w').write(f'{{os.getpid()}}:{{started}}'); "
            "time.sleep(30)"
        )
        leader_program = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{child_program!r}],"
            "start_new_session=True); time.sleep(30)"
        )
        runner = hosted.SubprocessCommandRunner()
        started = time.monotonic()
        identity: tuple[int, int] | None = None
        try:
            with self.assertRaisesRegex(hosted.HostedEvidenceError, "timed out"):
                runner.run(
                    [sys.executable, "-c", leader_program],
                    cwd=root,
                    maximum_stdout=4096,
                    maximum_stderr=4096,
                    timeout_seconds=0.2,
                )
            self.assertLess(time.monotonic() - started, 2.0)
            deadline = time.monotonic() + 1.0
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pid_path.exists())
            pid_text, started_text = pid_path.read_text(encoding="ascii").split(":")
            identity = (int(pid_text), int(started_text))
            deadline = time.monotonic() + 2.0
            while Path(f"/proc/{identity[0]}").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{identity[0]}").exists())
        finally:
            if identity is not None:
                proc_path = Path(f"/proc/{identity[0]}/stat")
                try:
                    raw = proc_path.read_text(encoding="ascii")
                    actual_started = int(raw[raw.rfind(")") + 2 :].split()[19])
                    if actual_started == identity[1]:
                        os.kill(identity[0], 9)
                except (FileNotFoundError, ProcessLookupError):
                    pass

    def test_source_command_rejects_preexisting_child_without_signalling_it(self) -> None:
        unrelated = subprocess.Popen(["/usr/bin/sleep", "30"])
        try:
            runner = hosted.SubprocessCommandRunner()
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "pre-existing child"
            ):
                runner.run(
                    ["/usr/bin/true"],
                    cwd=Path(self.temporary.name),
                    maximum_stdout=4096,
                    maximum_stderr=4096,
                    timeout_seconds=1.0,
                )
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2.0)

    def test_source_command_rejects_multithreaded_controller(self) -> None:
        stop = threading.Event()
        thread = threading.Thread(target=stop.wait, daemon=True)
        thread.start()
        try:
            runner = hosted.SubprocessCommandRunner()
            with self.assertRaisesRegex(
                hosted.HostedEvidenceError, "single-thread"
            ):
                runner.run(
                    ["/usr/bin/true"],
                    cwd=Path(self.temporary.name),
                    maximum_stdout=4096,
                    maximum_stderr=4096,
                    timeout_seconds=1.0,
                )
        finally:
            stop.set()
            thread.join(timeout=2.0)
        self.assertFalse(thread.is_alive())

    def test_source_selector_registration_failure_reaps_started_process(self) -> None:
        real_selector = hosted.selectors.DefaultSelector
        real_popen = hosted.subprocess.Popen
        captured: list[subprocess.Popen[bytes]] = []

        class FailingSelector:
            def __init__(self) -> None:
                self.inner = real_selector()
                self.registrations = 0

            def register(self, *args, **kwargs):  # noqa: ANN002,ANN003
                self.registrations += 1
                if self.registrations == 2:
                    raise OSError("fixture selector registration failure")
                return self.inner.register(*args, **kwargs)

            def close(self) -> None:
                self.inner.close()

        def capture_process(*args, **kwargs):  # noqa: ANN002,ANN003
            process = real_popen(*args, **kwargs)
            captured.append(process)
            return process

        with (
            mock.patch.object(
                hosted.selectors, "DefaultSelector", FailingSelector
            ),
            mock.patch.object(
                hosted.subprocess, "Popen", side_effect=capture_process
            ),
            self.assertRaisesRegex(
                hosted.HostedEvidenceError, "selector registration"
            ),
        ):
            hosted.SubprocessCommandRunner().run(
                ["/usr/bin/sleep", "30"],
                cwd=Path(self.temporary.name),
                maximum_stdout=4096,
                maximum_stderr=4096,
                timeout_seconds=1.0,
            )
        self.assertEqual(len(captured), 1)
        self.assertIsNotNone(captured[0].poll())

    @unittest.skipUnless(
        hasattr(os, "fork") and Path("/proc").is_dir(),
        "Linux fork/subreaper semantics unavailable",
    )
    def test_source_subreaper_cache_is_revalidated_after_fork(self) -> None:
        hosted._enable_source_subreaper()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:  # pragma: no cover - assertion is returned to the parent.
            os.close(read_fd)
            result = b"0"
            try:
                hosted._enable_source_subreaper()
                state = hosted.ctypes.c_int(0)
                library = hosted.ctypes.CDLL(None, use_errno=True)
                if library.prctl(37, hosted.ctypes.byref(state), 0, 0, 0) == 0:
                    result = b"1" if state.value == 1 else b"0"
            finally:
                os.write(write_fd, result)
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            observed = os.read(read_fd, 1)
        finally:
            os.close(read_fd)
        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertEqual(observed, b"1")


if __name__ == "__main__":
    unittest.main()
