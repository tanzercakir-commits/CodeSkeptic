#!/usr/bin/env python3
"""Network-bound capture contracts for hosted exact-head raw evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hosted = load_module(
    "hosted_exact_head_capture_contract",
    ROOT / "scripts" / "seal_hosted_exact_head.py",
)
capture = load_module(
    "capture_hosted_exact_head_contract",
    ROOT / "scripts" / "capture_hosted_exact_head.py",
)
fixture_module = load_module(
    "hosted_exact_head_fixture_contract", ROOT / "tests" / "HostedExactHeadReceiptTest.py"
)

REPOSITORY = fixture_module.REPOSITORY
REVISION = fixture_module.REVISION


class FakeTransport:
    def __init__(self) -> None:
        self.routes: dict[str, deque[object]] = defaultdict(deque)
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def add(self, url: str, response: object) -> None:
        self.routes[url].append(response)

    def request(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum: int,
        deadline: float | None = None,
    ) -> object:
        self.calls.append((url, dict(headers), maximum))
        if not self.routes[url]:
            raise capture.HostedCaptureError(f"unexpected request: {url}")
        return self.routes[url].popleft()


class FakeStreamingTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.streamed: list[tuple[str, dict[str, str], Path]] = []

    def download_to_file(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum: int,
        target: Path,
        deadline: float | None = None,
    ) -> object:
        response = self.request(
            url, headers=headers, maximum=maximum, deadline=deadline
        )
        capture._write_new(target, response.body)
        self.streamed.append((url, dict(headers), target))
        return capture.StreamedHttpResponse(
            status=response.status,
            headers=response.headers,
            sha256=hashlib.sha256(response.body).hexdigest(),
            size=len(response.body),
        )


def response_json(value: object, *, link: str | None = None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if link is not None:
        headers["Link"] = link
    return capture.HttpResponse(
        status=200,
        headers=headers,
        body=fixture_module.canonical_bytes(value),
    )


class CaptureFixture:
    def __init__(
        self,
        root: Path,
        *,
        paginate_checks: bool = False,
        streaming: bool = False,
        mixed_authoritative_events: bool = False,
    ) -> None:
        self.root = root
        self.exact = fixture_module.Fixture(root / "exact")
        self.output = root / "capture"
        self.transport = FakeStreamingTransport() if streaming else FakeTransport()
        self.paginate_checks = paginate_checks
        if mixed_authoritative_events:
            juliet = next(
                gate for gate in self.exact.selection["gates"]
                if gate["gate_id"] == "juliet"
            )
            run_id = int(juliet["workflow_run_id"])
            next(
                run for run in self.exact.runs if int(run["id"]) == run_id
            )["event"] = "workflow_dispatch"
        self._populate_api_routes()
        self._populate_download_routes()

    @property
    def api(self) -> str:
        return f"https://api.github.com/repos/{REPOSITORY}"

    def _twice(self, url: str, value: object) -> None:
        self.transport.add(url, response_json(value))
        self.transport.add(url, response_json(value))

    def _populate_api_routes(self) -> None:
        runs_url = (
            f"{self.api}/actions/runs?head_sha={REVISION}&status=completed"
            "&per_page=100&page=1"
        )
        self._twice(
            runs_url,
            {"total_count": len(self.exact.runs), "workflow_runs": self.exact.runs},
        )

        checks_url = (
            f"{self.api}/commits/{REVISION}/check-runs?filter=all"
            "&per_page=100&page=1"
        )
        checks_value = {
            "total_count": len(self.exact.checks),
            "check_runs": self.exact.checks,
        }
        if self.paginate_checks:
            page_two = checks_url[:-1] + "2"
            next_link = f'<{page_two}>; rel="next"'
            for _ in range(2):
                self.transport.add(
                    checks_url,
                    response_json(
                        {
                            "total_count": len(self.exact.checks),
                            "check_runs": self.exact.checks[:6],
                        },
                        link=next_link,
                    ),
                )
                self.transport.add(
                    page_two,
                    response_json(
                        {
                            "total_count": len(self.exact.checks),
                            "check_runs": self.exact.checks[6:],
                        }
                    ),
                )
        else:
            self._twice(checks_url, checks_value)

        refs_url = (
            f"{self.api}/git/matching-refs/status/{REVISION}/"
            "?per_page=100&page=1"
        )
        self._twice(refs_url, self.exact.refs)

        for run in self.exact.runs:
            run_id = int(run["id"])
            attempt = int(run["run_attempt"])
            jobs_url = (
                f"{self.api}/actions/runs/{run_id}/attempts/{attempt}/jobs"
                "?per_page=100&page=1"
            )
            jobs = self.exact.jobs_by_run[run_id]
            self._twice(
                jobs_url, {"total_count": len(jobs), "jobs": jobs}
            )
            artifacts_url = (
                f"{self.api}/actions/runs/{run_id}/artifacts?per_page=100&page=1"
            )
            artifacts = self.exact.artifacts_by_run[run_id]
            self._twice(
                artifacts_url,
                {"total_count": len(artifacts), "artifacts": artifacts},
            )

    def _populate_download_routes(self) -> None:
        for run in self.exact.runs:
            run_id = int(run["id"])
            attempt = int(run["run_attempt"])
            request_url = (
                f"{self.api}/actions/runs/{run_id}/attempts/{attempt}/logs"
            )
            redirect_url = (
                "https://results-receiver.actions.githubusercontent.com/"
                f"logs/{run_id}?token=fixture"
            )
            archive = (
                self.exact.input / "downloads" / "logs"
                / f"{run_id}-attempt-{attempt}.zip"
            ).read_bytes()
            self.transport.add(
                request_url,
                capture.HttpResponse(
                    status=302,
                    headers={"Location": redirect_url},
                    body=b"",
                ),
            )
            self.transport.add(
                redirect_url,
                capture.HttpResponse(
                    status=200,
                    headers={"Content-Type": "application/zip"},
                    body=archive,
                ),
            )
        for artifacts in self.exact.artifacts_by_run.values():
            for artifact in artifacts:
                artifact_id = int(artifact["id"])
                request_url = str(artifact["archive_download_url"])
                redirect_url = (
                    "https://results-receiver.actions.githubusercontent.com/"
                    f"artifacts/{artifact_id}?token=fixture"
                )
                archive = (
                    self.exact.input / "downloads" / "artifacts"
                    / f"{artifact_id}.zip"
                ).read_bytes()
                self.transport.add(
                    request_url,
                    capture.HttpResponse(
                        status=302,
                        headers={"Location": redirect_url},
                        body=b"",
                    ),
                )
                self.transport.add(
                    redirect_url,
                    capture.HttpResponse(
                        status=200,
                        headers={"Content-Type": "application/zip"},
                        body=archive,
                    ),
                )

    def capture(self) -> None:
        capture.capture_snapshot(
            self.output,
            repository=REPOSITORY,
            revision=REVISION,
            selection=self.exact.input / "selection.json",
            token="top-secret-token",
            transport=self.transport,
        )


class HostedCaptureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_capture_round_trip_and_redirect_requests_never_leak_authorization(self) -> None:
        fixture = CaptureFixture(self.root)
        fixture.capture()
        evidence = self.root / "sealed"
        receipt = hosted.seal_evidence(
            evidence,
            repository=REPOSITORY,
            revision=REVISION,
            source=fixture.exact.source,
            inputs=hosted.OfflineSnapshotInputs(fixture.output),
        )
        self.assertEqual(receipt["source"]["revision"], REVISION)
        self.assertEqual(len(receipt["gates"]), 10)

        redirected = [
            (url, headers)
            for url, headers, _ in fixture.transport.calls
            if urlsplit(url).hostname != "api.github.com"
        ]
        self.assertGreater(len(redirected), 0)
        for _, headers in redirected:
            lowered = {name.lower() for name in headers}
            self.assertNotIn("authorization", lowered)
            self.assertNotIn("x-github-api-version", lowered)
            self.assertNotIn("accept", lowered)
        api_calls = [
            headers
            for url, headers, _ in fixture.transport.calls
            if urlsplit(url).hostname == "api.github.com"
        ]
        self.assertGreater(len(api_calls), 0)
        for headers in api_calls:
            self.assertEqual(headers["X-GitHub-Api-Version"], capture.API_VERSION)
            self.assertEqual(headers["Authorization"], "Bearer top-secret-token")

    def test_archive_bytes_use_the_bounded_streaming_path_when_available(self) -> None:
        fixture = CaptureFixture(self.root / "streamed", streaming=True)
        fixture.capture()
        self.assertGreater(len(fixture.transport.streamed), 0)
        for _, headers, _ in fixture.transport.streamed:
            self.assertNotIn("authorization", {key.lower() for key in headers})
        self.assertEqual(
            len(list((fixture.output / "downloads").rglob("*.zip"))),
            len(fixture.transport.streamed),
        )

    def test_capture_preserves_selected_push_and_dispatch_runs(self) -> None:
        fixture = CaptureFixture(
            self.root / "mixed-events", mixed_authoritative_events=True
        )
        fixture.capture()
        evidence = self.root / "mixed-events-sealed"
        receipt = hosted.seal_evidence(
            evidence,
            repository=REPOSITORY,
            revision=REVISION,
            source=fixture.exact.source,
            inputs=hosted.OfflineSnapshotInputs(fixture.output),
        )
        self.assertIn(
            "workflow_dispatch", {run["event"] for run in receipt["runs"]}
        )
        run_queries = [
            url for url, _headers, _maximum in fixture.transport.calls
            if "/actions/runs?" in url
        ]
        self.assertGreater(len(run_queries), 0)
        self.assertTrue(all("event=" not in url for url in run_queries))

    def test_all_api_pages_are_aggregated_and_a_cross_origin_next_link_is_rejected(self) -> None:
        fixture = CaptureFixture(self.root / "pages", paginate_checks=True)
        fixture.capture()
        value = json.loads(
            (fixture.output / "api" / "check-runs.json").read_text(encoding="utf-8")
        )
        self.assertEqual(value["total_count"], 10)
        self.assertEqual(len(value["check_runs"]), 10)

        fixture = CaptureFixture(self.root / "bad-next", paginate_checks=True)
        checks_url = (
            f"{fixture.api}/commits/{REVISION}/check-runs?filter=all"
            "&per_page=100&page=1"
        )
        fixture.transport.routes[checks_url].clear()
        bad = response_json(
            {"total_count": 10, "check_runs": fixture.exact.checks[:6]},
            link='<https://attacker.invalid/page/2>; rel="next"',
        )
        fixture.transport.add(checks_url, bad)
        with self.assertRaisesRegex(capture.HostedCaptureError, "pagination"):
            fixture.capture()
        self.assertFalse(fixture.output.exists())

    def test_capture_detects_api_race_and_does_not_publish_partial_output(self) -> None:
        fixture = CaptureFixture(self.root / "race")
        runs_url = (
            f"{fixture.api}/actions/runs?head_sha={REVISION}&status=completed"
            "&per_page=100&page=1"
        )
        first = fixture.transport.routes[runs_url].popleft()
        fixture.transport.routes[runs_url].clear()
        fixture.transport.routes[runs_url].append(first)
        changed = json.loads(first.body.decode("utf-8"))
        changed["workflow_runs"][0]["updated_at"] = "2099-01-01T00:00:00Z"
        fixture.transport.routes[runs_url].append(response_json(changed))
        with self.assertRaisesRegex(capture.HostedCaptureError, "changed during capture"):
            fixture.capture()
        self.assertFalse(fixture.output.exists())

    def test_collection_and_archive_budgets_leave_no_partial_capture(self) -> None:
        fixture = CaptureFixture(self.root / "collection-budget")
        runs_url = (
            f"{fixture.api}/actions/runs?head_sha={REVISION}&status=completed"
            "&per_page=100&page=1"
        )
        fixture.transport.routes[runs_url].clear()
        fixture.transport.add(
            runs_url,
            response_json({
                "total_count": capture.MAX_COLLECTION_ITEMS + 1,
                "workflow_runs": fixture.exact.runs,
            }),
        )
        with self.assertRaisesRegex(
            capture.HostedCaptureError, "collection item budget"
        ):
            fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

        fixture = CaptureFixture(self.root / "archive-budget")
        first_run = fixture.exact.runs[0]
        run_id = int(first_run["id"])
        attempt = int(first_run["run_attempt"])
        log_size = (
            fixture.exact.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip"
        ).stat().st_size
        first_artifact = fixture.exact.artifacts_by_run[run_id][0]
        artifact_size = (
            fixture.exact.input / "downloads" / "artifacts"
            / f"{int(first_artifact['id'])}.zip"
        ).stat().st_size
        with mock.patch.object(
            capture,
            "MAX_CAPTURE_ARCHIVE_BYTES",
            log_size + artifact_size - 1,
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "archive.*budget|size policy"
            ):
                fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

        fixture = CaptureFixture(self.root / "archive-expansion-budget")
        first_run = fixture.exact.runs[0]
        run_id = int(first_run["id"])
        attempt = int(first_run["run_attempt"])
        first_paths = [
            fixture.exact.input / "downloads" / "logs"
            / f"{run_id}-attempt-{attempt}.zip",
            fixture.exact.input / "downloads" / "artifacts"
            / f"{int(fixture.exact.artifacts_by_run[run_id][0]['id'])}.zip",
        ]
        expanded = 0
        for archive_path in first_paths:
            with zipfile.ZipFile(archive_path, "r") as archive:
                expanded += sum(item.file_size for item in archive.infolist())
        with mock.patch.object(
            capture.hosted,
            "MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES",
            expanded - 1,
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "ZIP expands|expansion budget"
            ):
                fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

        fixture = CaptureFixture(self.root / "archive-file-budget")
        with mock.patch.object(capture, "MAX_CAPTURE_ARCHIVE_FILES", 1):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "archive file budget"
            ):
                fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

    def test_collection_page_budget_is_fixed(self) -> None:
        transport = FakeTransport()
        first = (
            f"https://api.github.com/repos/{REPOSITORY}/fixture"
            "?per_page=100&page=1"
        )
        current = first
        for page in range(1, capture.MAX_API_PAGES + 1):
            next_url = current[:-len(str(page))] + str(page + 1)
            transport.add(
                current,
                response_json([], link=f'<{next_url}>; rel="next"'),
            )
            current = next_url
        with self.assertRaisesRegex(
            capture.HostedCaptureError, "page budget"
        ):
            capture._fetch_collection(
                transport,
                first,
                token="top-secret-token",
                label="bounded fixture",
                items_key=None,
            )
        self.assertEqual(len(transport.calls), capture.MAX_API_PAGES)

    def test_capture_and_streaming_download_have_absolute_wall_deadlines(self) -> None:
        fixture = CaptureFixture(self.root / "capture-deadline")
        with (
            mock.patch.object(capture, "MAX_CAPTURE_SECONDS", 1),
            mock.patch.object(
                capture.time, "monotonic", side_effect=[0.0, 2.0]
            ),
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "wall deadline"
            ):
                fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(
            list(fixture.output.parent.glob(f".{fixture.output.name}.tmp-*")),
            [],
        )

        response = mock.Mock()
        response.status = 200
        response.headers = {"Content-Type": "application/zip"}
        response.read.side_effect = [b"partial", b""]
        transport = capture.UrllibTransport()
        transport._opener = mock.Mock()
        transport._opener.open.return_value = response
        target = self.root / "slow-download.zip"
        with mock.patch.object(
            capture.time, "monotonic", side_effect=[0.0, 0.0, 2.0]
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "wall deadline"
            ):
                transport.download_to_file(
                    "https://results-receiver.actions.githubusercontent.com/a.zip",
                    headers={},
                    maximum=1024,
                    target=target,
                    deadline=1.0,
                )
        self.assertFalse(target.exists())
        response.close.assert_called_once_with()

        archive = self.root / "deadline-validation.zip"
        archive.write_bytes(fixture_module.zip_bytes("payload.txt", b"payload\n"))
        with mock.patch.object(
            capture.time, "monotonic", side_effect=[0.0, 2.0]
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "wall deadline"
            ):
                capture._validate_captured_zip(
                    archive,
                    label="deadline validation",
                    deadline=1.0,
                )
        with mock.patch.object(
            capture.time, "monotonic", side_effect=[0.0, 2.0]
        ):
            with self.assertRaisesRegex(
                capture.HostedCaptureError, "wall deadline"
            ):
                capture.hosted._hash_regular(
                    archive,
                    1024,
                    "deadline hash",
                    progress=lambda: capture._check_deadline(
                        1.0, "deadline hash"
                    ),
                )

    def test_capture_is_create_new_and_never_touches_an_existing_output(self) -> None:
        fixture = CaptureFixture(self.root / "existing")
        fixture.output.mkdir(parents=True)
        sentinel = fixture.output / "sentinel"
        sentinel.write_text("keep\n", encoding="ascii")
        with self.assertRaisesRegex(capture.HostedCaptureError, "already exists"):
            fixture.capture()
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep\n")
        self.assertEqual(fixture.transport.calls, [])

    def test_redirect_requires_two_hops_and_an_https_non_api_target(self) -> None:
        fixture = CaptureFixture(self.root / "redirect")
        run = fixture.exact.runs[0]
        run_id = int(run["id"])
        attempt = int(run["run_attempt"])
        request_url = (
            f"{fixture.api}/actions/runs/{run_id}/attempts/{attempt}/logs"
        )
        fixture.transport.routes[request_url].clear()
        fixture.transport.add(
            request_url,
            capture.HttpResponse(
                status=200,
                headers={"Content-Type": "application/zip"},
                body=b"not-authoritative",
            ),
        )
        with self.assertRaisesRegex(capture.HostedCaptureError, "302"):
            fixture.capture()
        self.assertFalse(fixture.output.exists())

        fixture = CaptureFixture(self.root / "redirect-host")
        run = fixture.exact.runs[0]
        run_id = int(run["id"])
        attempt = int(run["run_attempt"])
        request_url = (
            f"{fixture.api}/actions/runs/{run_id}/attempts/{attempt}/logs"
        )
        fixture.transport.routes[request_url].clear()
        fixture.transport.add(
            request_url,
            capture.HttpResponse(
                status=302,
                headers={"Location": "https://attacker.invalid/archive.zip"},
                body=b"",
            ),
        )
        with self.assertRaisesRegex(capture.HostedCaptureError, "redirect origin"):
            fixture.capture()
        self.assertFalse(fixture.output.exists())
        self.assertNotIn(
            "https://attacker.invalid/archive.zip",
            [url for url, _, _ in fixture.transport.calls],
        )

        fixture = CaptureFixture(self.root / "invalid-zip")
        run = fixture.exact.runs[0]
        run_id = int(run["id"])
        redirect_url = (
            "https://results-receiver.actions.githubusercontent.com/"
            f"logs/{run_id}?token=fixture"
        )
        fixture.transport.routes[redirect_url].clear()
        fixture.transport.add(
            redirect_url,
            capture.HttpResponse(
                status=200,
                headers={"Content-Type": "application/zip"},
                body=b"not-a-zip",
            ),
        )
        with self.assertRaisesRegex(capture.HostedCaptureError, "ZIP"):
            fixture.capture()
        self.assertFalse(fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
