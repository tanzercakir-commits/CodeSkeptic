#!/usr/bin/env python3
"""Capture complete GitHub inputs for the offline exact-head authority.

This is the only network-bearing half of the hosted evidence chain.  It writes
raw API snapshots plus exact log/artifact archive bytes into a fresh directory.
``seal_hosted_exact_head.py`` remains network-free and independently re-derives
the accepted receipt from this capture and exact local Git objects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import seal_hosted_exact_head as hosted  # noqa: E402


USER_AGENT = "CodeSkeptic-hosted-exact-head-capture/1"
API_VERSION = hosted.GITHUB_API_VERSION
MAX_REDIRECT_URL_BYTES = 32 * 1024
MAX_API_PAGES = 64
MAX_COLLECTION_ITEMS = hosted.MAX_COLLECTION_ITEMS
MAX_COLLECTION_RESPONSE_BYTES = hosted.MAX_JSON_BYTES
MAX_CAPTURE_ARCHIVE_FILES = hosted.MAX_ARCHIVE_FILES
MAX_CAPTURE_ARCHIVE_BYTES = hosted.MAX_ARCHIVE_TOTAL_BYTES
MAX_CAPTURE_SECONDS = 6 * 60 * 60
PROVIDER_FILTERED_RESULT_CAP = 1000
LINK_PART = re.compile(r'^<([^<>]+)>\s*;\s*rel="([a-z ]+)"(?:\s*;.*)?$')


class HostedCaptureError(RuntimeError):
    """The live provider capture is incomplete, mutable, or unsafe."""


def _check_deadline(deadline: float | None, label: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise HostedCaptureError(f"{label} exceeded the capture wall deadline")


def _request_timeout(deadline: float | None, label: str) -> float:
    if deadline is None:
        return 60.0
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise HostedCaptureError(f"{label} exceeded the capture wall deadline")
    return max(0.001, min(60.0, remaining))


class HttpResponse:
    """Small immutable-enough response value used by real and fake transports."""

    __slots__ = ("status", "headers", "body")

    def __init__(
        self,
        *,
        status: int,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body: bytes,
    ) -> None:
        self.status = status
        self.headers = tuple(headers.items() if isinstance(headers, Mapping) else headers)
        self.body = body


class StreamedHttpResponse:
    """Metadata returned after a response body is streamed to a new file."""

    __slots__ = ("status", "headers", "sha256", "size")

    def __init__(
        self,
        *,
        status: int,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        sha256: str,
        size: int,
    ) -> None:
        self.status = status
        self.headers = tuple(headers.items() if isinstance(headers, Mapping) else headers)
        self.sha256 = sha256
        self.size = size


class HttpTransport(Protocol):
    def request(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum: int,
        deadline: float | None = None,
    ) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibTransport:
    """HTTPS transport that never follows redirects implicitly."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum: int,
        deadline: float | None = None,
    ) -> HttpResponse:
        _check_deadline(deadline, "HTTPS request")
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = self._opener.open(
                request, timeout=_request_timeout(deadline, "HTTPS request")
            )
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            raise HostedCaptureError(f"HTTPS request failed for {url}: {error}") from error
        try:
            chunks: list[bytes] = []
            size = 0
            while True:
                _check_deadline(deadline, "HTTPS request")
                chunk = response.read(min(hosted.CHUNK_BYTES, maximum + 1 - size))
                _check_deadline(deadline, "HTTPS request")
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise HostedCaptureError(
                        f"HTTPS response exceeds size policy: {url}"
                    )
            body = b"".join(chunks)
            headers_value = tuple(response.headers.items())
            return HttpResponse(
                status=int(response.status), headers=headers_value, body=body
            )
        finally:
            response.close()

    def download_to_file(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum: int,
        target: Path,
        deadline: float | None = None,
    ) -> StreamedHttpResponse:
        """Stream one non-redirected response into an exclusive file."""

        _check_deadline(deadline, "signed archive download")
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = self._opener.open(
                request,
                timeout=_request_timeout(deadline, "signed archive download"),
            )
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            raise HostedCaptureError("signed archive HTTPS request failed") from error
        descriptor = -1
        try:
            status = int(response.status)
            response_headers = tuple(response.headers.items())
            if status != 200:
                raise HostedCaptureError(
                    f"signed archive second hop returned HTTP {status}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
                os, "O_CLOEXEC", 0
            )
            descriptor = os.open(target, flags, 0o600)
            digest = hashlib.sha256()
            size = 0
            while True:
                _check_deadline(deadline, "signed archive download")
                chunk = response.read(hosted.CHUNK_BYTES)
                _check_deadline(deadline, "signed archive download")
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise HostedCaptureError(
                        "signed archive response exceeds size policy"
                    )
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written < 1:
                        raise HostedCaptureError(
                            "short write while streaming signed archive"
                        )
                    view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            return StreamedHttpResponse(
                status=status,
                headers=response_headers,
                sha256=digest.hexdigest(),
                size=size,
            )
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            raise
        finally:
            response.close()


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _header(response: HttpResponse | StreamedHttpResponse, name: str) -> str | None:
    values = [
        value.strip()
        for key, value in response.headers
        if key.lower() == name.lower()
    ]
    if len(values) > 1:
        raise HostedCaptureError(f"HTTP response contains duplicate {name} headers")
    return values[0] if values else None


def _content_type(
    response: HttpResponse | StreamedHttpResponse, *, label: str
) -> str:
    value = _header(response, "Content-Type")
    if value is None:
        raise HostedCaptureError(f"{label} response has no Content-Type")
    media_type = value.split(";", 1)[0].strip().lower()
    if not media_type:
        raise HostedCaptureError(f"{label} response has a malformed Content-Type")
    return media_type


def _api_headers(token: str) -> dict[str, str]:
    if not isinstance(token, str) or not token or any(ch in token for ch in "\r\n"):
        raise HostedCaptureError("GitHub token is missing or malformed")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": API_VERSION,
    }


def _download_headers() -> dict[str, str]:
    # Signed storage URLs are bearer capabilities.  API credentials and API
    # negotiation headers must never cross the redirect-origin boundary.
    return {"User-Agent": USER_AGENT}


def _request(
    transport: HttpTransport,
    url: str,
    *,
    headers: dict[str, str],
    maximum: int,
    deadline: float | None = None,
) -> HttpResponse:
    _check_deadline(deadline, "HTTPS request")
    try:
        response = transport.request(
            url, headers=headers, maximum=maximum, deadline=deadline
        )
    except HostedCaptureError:
        raise
    except Exception as error:
        raise HostedCaptureError(f"HTTPS transport failed for {url}: {error}") from error
    if not isinstance(response, HttpResponse):
        raise HostedCaptureError("HTTPS transport returned an invalid response")
    if not isinstance(response.status, int) or isinstance(response.status, bool):
        raise HostedCaptureError("HTTPS transport returned an invalid status")
    if not isinstance(response.body, bytes) or len(response.body) > maximum:
        raise HostedCaptureError(f"HTTPS response exceeds size policy: {url}")
    _check_deadline(deadline, "HTTPS request")
    return response


def _api_json(
    transport: HttpTransport,
    url: str,
    *,
    token: str,
    label: str,
    deadline: float | None = None,
) -> tuple[Any, HttpResponse]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise HostedCaptureError(f"{label} API URL is inadmissible")
    response = _request(
        transport,
        url,
        headers=_api_headers(token),
        maximum=hosted.MAX_JSON_BYTES,
        deadline=deadline,
    )
    if response.status != 200:
        raise HostedCaptureError(f"{label} API request returned HTTP {response.status}")
    if _content_type(response, label=label) not in {
        "application/json",
        "application/vnd.github+json",
    }:
        raise HostedCaptureError(f"{label} API response is not JSON")
    try:
        value = hosted._parse_json(response.body, f"{label} API response")
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    return value, response


def _next_page_url(current: str) -> str:
    parsed = urlsplit(current)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    page_indexes = [index for index, (key, _) in enumerate(pairs) if key == "page"]
    if len(page_indexes) != 1:
        raise HostedCaptureError("pagination URL has no unique page parameter")
    index = page_indexes[0]
    try:
        page = int(pairs[index][1])
    except ValueError as error:
        raise HostedCaptureError("pagination page is malformed") from error
    if page < 1:
        raise HostedCaptureError("pagination page is malformed")
    pairs[index] = ("page", str(page + 1))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment)
    )


def _pagination_next(response: HttpResponse, current: str) -> str | None:
    header = _header(response, "Link")
    if header is None:
        return None
    relations: dict[str, str] = {}
    for raw in header.split(","):
        match = LINK_PART.fullmatch(raw.strip())
        if match is None:
            raise HostedCaptureError("pagination Link header is malformed")
        url, raw_relations = match.groups()
        for relation in raw_relations.split():
            if relation in relations:
                raise HostedCaptureError("pagination Link relations are duplicated")
            relations[relation] = url
    next_url = relations.get("next")
    if next_url is None:
        return None
    expected = _next_page_url(current)
    if next_url != expected:
        raise HostedCaptureError("pagination next URL is not the exact next API page")
    return next_url


def _fetch_collection(
    transport: HttpTransport,
    first_url: str,
    *,
    token: str,
    label: str,
    items_key: str | None,
    deadline: float | None = None,
    provider_result_cap: int | None = None,
) -> Any:
    current: str | None = first_url
    visited: set[str] = set()
    items: list[Any] = []
    total_count: int | None = None
    response_bytes = 0
    while current is not None:
        _check_deadline(deadline, label)
        if current in visited:
            raise HostedCaptureError(f"{label} pagination loop detected")
        if len(visited) >= MAX_API_PAGES:
            raise HostedCaptureError(f"{label} API page budget exceeded")
        visited.add(current)
        value, response = _api_json(
            transport,
            current,
            token=token,
            label=label,
            deadline=deadline,
        )
        response_bytes += len(response.body)
        if response_bytes > MAX_COLLECTION_RESPONSE_BYTES:
            raise HostedCaptureError(
                f"{label} aggregate API response budget exceeded"
            )
        if items_key is None:
            if not isinstance(value, list):
                raise HostedCaptureError(f"{label} API page is not an array")
            page_items = value
        else:
            if (
                not isinstance(value, dict)
                or set(value) != {"total_count", items_key}
                or isinstance(value["total_count"], bool)
                or not isinstance(value["total_count"], int)
                or value["total_count"] < 0
                or not isinstance(value[items_key], list)
            ):
                raise HostedCaptureError(f"{label} API page has an invalid collection shape")
            page_total = value["total_count"]
            if (
                provider_result_cap is not None
                and page_total >= provider_result_cap
            ):
                raise HostedCaptureError(
                    f"{label} is ambiguous at the provider "
                    f"{provider_result_cap}-result cap"
                )
            if page_total > MAX_COLLECTION_ITEMS:
                raise HostedCaptureError(
                    f"{label} collection item budget exceeded"
                )
            if total_count is None:
                total_count = page_total
            elif total_count != page_total:
                raise HostedCaptureError(f"{label} total count changed during pagination")
            page_items = value[items_key]
        if len(items) + len(page_items) > MAX_COLLECTION_ITEMS:
            raise HostedCaptureError(
                f"{label} collection item budget exceeded"
            )
        items.extend(page_items)
        next_url = _pagination_next(response, current)
        if items_key is None and next_url is None and len(page_items) >= 100:
            raise HostedCaptureError(
                f"{label} pagination is ambiguous at the provider page limit"
            )
        if items_key is not None and total_count is not None:
            if len(items) > total_count:
                raise HostedCaptureError(f"{label} pagination exceeds total count")
            if next_url is None and len(items) != total_count:
                raise HostedCaptureError(f"{label} pagination is incomplete")
            if next_url is not None and len(items) >= total_count:
                raise HostedCaptureError(f"{label} pagination has a spurious next page")
        current = next_url
    result: Any = (
        items if items_key is None
        else {"total_count": total_count, items_key: items}
    )
    if len(_canonical_bytes(result)) > hosted.MAX_JSON_BYTES:
        raise HostedCaptureError(
            f"{label} aggregate API document exceeds size policy"
        )
    return result


def _indexed(records: Any, *, label: str, key: str = "id") -> dict[int, dict[str, Any]]:
    if not isinstance(records, list):
        raise HostedCaptureError(f"{label} is not a list")
    result: dict[int, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise HostedCaptureError(f"{label} record is malformed")
        identifier = record.get(key)
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier < 1:
            raise HostedCaptureError(f"{label} ID is malformed")
        if identifier in result:
            raise HostedCaptureError(f"{label} IDs are duplicated")
        result[identifier] = record
    return result


def _snapshot_api(
    *,
    repository: str,
    revision: str,
    token: str,
    transport: HttpTransport,
    expected_selection_raw: bytes | None = None,
    deadline: float | None = None,
) -> tuple[
    dict[str, bytes],
    bytes,
    list[dict[str, int | str]],
]:
    base = f"https://api.github.com/repos/{repository}"
    runs = _fetch_collection(
        transport,
        f"{base}/actions/runs?head_sha={revision}&status=completed"
        "&per_page=100&page=1",
        token=token,
        label="workflow runs",
        items_key="workflow_runs",
        deadline=deadline,
        provider_result_cap=PROVIDER_FILTERED_RESULT_CAP,
    )
    suites = _fetch_collection(
        transport,
        f"{base}/commits/{revision}/check-suites?per_page=100&page=1",
        token=token,
        label="check suites",
        items_key="check_suites",
        deadline=deadline,
        provider_result_cap=PROVIDER_FILTERED_RESULT_CAP,
    )
    checks = _fetch_collection(
        transport,
        f"{base}/commits/{revision}/check-runs?filter=all&per_page=100&page=1",
        token=token,
        label="check runs",
        items_key="check_runs",
        deadline=deadline,
    )
    refs = _fetch_collection(
        transport,
        f"{base}/git/matching-refs/status/{revision}/?per_page=100&page=1",
        token=token,
        label="status refs",
        items_key=None,
        deadline=deadline,
    )
    try:
        selection_value = hosted.derive_canonical_selection(
            runs,
            suites,
            checks,
            refs,
            repository,
            revision,
        )
        selection_raw = _canonical_bytes(selection_value)
        selected = hosted._validate_selection(
            selection_value, repository, revision
        )
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    if (
        expected_selection_raw is not None
        and selection_raw != expected_selection_raw
    ):
        raise HostedCaptureError(
            "capture selection differs from deterministic provider selection"
        )
    run_records = _indexed(runs["workflow_runs"], label="workflow runs")
    selected_run_ids = list(
        dict.fromkeys(int(record["workflow_run_id"]) for record in selected)
    )
    snapshot = {
        "api/workflow-runs.json": _canonical_bytes(runs),
        "api/check-suites.json": _canonical_bytes(suites),
        "api/check-runs.json": _canonical_bytes(checks),
        "api/status-refs.json": _canonical_bytes(refs),
    }
    for run_id in selected_run_ids:
        run = run_records.get(run_id)
        if run is None:
            raise HostedCaptureError("selected workflow run is absent from API capture")
        try:
            attempt = hosted._positive_integer(
                run.get("run_attempt"), "workflow run attempt"
            )
        except hosted.HostedEvidenceError as error:
            raise HostedCaptureError(str(error)) from error
        jobs = _fetch_collection(
            transport,
            f"{base}/actions/runs/{run_id}/attempts/{attempt}/jobs"
            "?per_page=100&page=1",
            token=token,
            label=f"run {run_id} attempt {attempt} jobs",
            items_key="jobs",
            deadline=deadline,
        )
        artifacts = _fetch_collection(
            transport,
            f"{base}/actions/runs/{run_id}/artifacts?per_page=100&page=1",
            token=token,
            label=f"run {run_id} artifacts",
            items_key="artifacts",
            deadline=deadline,
        )
        snapshot[f"api/jobs/{run_id}-attempt-{attempt}.json"] = _canonical_bytes(jobs)
        snapshot[f"api/artifacts/{run_id}.json"] = _canonical_bytes(artifacts)
    return snapshot, selection_raw, selected


def _redirect_origin(url: str, *, label: str) -> str:
    if not isinstance(url, str) or len(url.encode("utf-8")) > MAX_REDIRECT_URL_BYTES:
        raise HostedCaptureError(f"{label} redirect URL is malformed")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path
    ):
        raise HostedCaptureError(f"{label} redirect URL is malformed")
    hostname = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError as error:
        raise HostedCaptureError(f"{label} redirect URL is malformed") from error
    if (
        port not in {None, 443}
        or not (
            hostname.endswith(".actions.githubusercontent.com")
            or hostname.endswith(".blob.core.windows.net")
        )
    ):
        raise HostedCaptureError(f"{label} redirect origin is inadmissible")
    return f"https://{hostname}"


def _download_archive(
    *,
    transport: HttpTransport,
    token: str,
    request_url: str,
    label: str,
    target: Path,
    maximum: int = hosted.MAX_ARCHIVE_BYTES,
    maximum_uncompressed: int = hosted.MAX_ZIP_UNCOMPRESSED_BYTES,
    deadline: float | None = None,
) -> tuple[dict[str, Any], int]:
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum < 1
        or maximum > hosted.MAX_ARCHIVE_BYTES
    ):
        raise HostedCaptureError(f"{label} archive budget is exhausted")
    if (
        isinstance(maximum_uncompressed, bool)
        or not isinstance(maximum_uncompressed, int)
        or maximum_uncompressed < 1
        or maximum_uncompressed > hosted.MAX_ZIP_UNCOMPRESSED_BYTES
    ):
        raise HostedCaptureError(
            f"{label} aggregate ZIP expansion budget is exhausted"
        )
    first = _request(
        transport,
        request_url,
        headers=_api_headers(token),
        maximum=hosted.MAX_JSON_BYTES,
        deadline=deadline,
    )
    if first.status != 302:
        raise HostedCaptureError(f"{label} download did not return the required 302")
    location = _header(first, "Location")
    if location is None:
        raise HostedCaptureError(f"{label} 302 response has no Location")
    origin = _redirect_origin(location, label=label)
    stream = getattr(transport, "download_to_file", None)
    if callable(stream):
        try:
            second = stream(
                location,
                headers=_download_headers(),
                maximum=maximum,
                target=target,
                deadline=deadline,
            )
        except HostedCaptureError:
            raise
        except Exception as error:
            raise HostedCaptureError(
                f"{label} signed archive streaming failed"
            ) from error
        if not isinstance(second, StreamedHttpResponse):
            raise HostedCaptureError(
                f"{label} streaming transport returned an invalid response"
            )
        archive_digest = second.sha256
        archive_size = second.size
    else:
        buffered = _request(
            transport,
            location,
            headers=_download_headers(),
            maximum=maximum,
            deadline=deadline,
        )
        second = buffered
        archive_digest = hashlib.sha256(buffered.body).hexdigest()
        archive_size = len(buffered.body)
        _write_new(target, buffered.body)
    if second.status != 200:
        raise HostedCaptureError(f"{label} second hop returned HTTP {second.status}")
    content_type = _content_type(second, label=label)
    if content_type not in {"application/zip", "application/octet-stream"}:
        raise HostedCaptureError(f"{label} second hop is not a ZIP download")
    if archive_size < 1:
        raise HostedCaptureError(f"{label} archive is empty")
    if archive_size > maximum:
        raise HostedCaptureError(f"{label} aggregate archive budget exceeded")
    _check_deadline(deadline, label)
    if hosted.SHA256.fullmatch(archive_digest) is None:
        raise HostedCaptureError(f"{label} archive digest is malformed")
    uncompressed_size = _validate_captured_zip(
        target,
        label=label,
        maximum_uncompressed=maximum_uncompressed,
        deadline=deadline,
    )
    try:
        retained_digest, retained_size = hosted._hash_regular(
            target,
            maximum,
            label,
            progress=lambda: _check_deadline(deadline, label),
        )
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    if retained_digest != archive_digest or retained_size != archive_size:
        raise HostedCaptureError(f"{label} streamed archive binding drift")
    _check_deadline(deadline, label)
    return {
        "request_url": request_url,
        "api_version": API_VERSION,
        "redirect_http_status": 302,
        "redirect_url_origin": origin,
        "redirect_url_sha256": hashlib.sha256(location.encode("utf-8")).hexdigest(),
        "download_http_status": 200,
        "content_type": content_type,
        "archive_sha256": archive_digest,
        "archive_size": archive_size,
    }, uncompressed_size


def _write_new(path: Path, value: bytes) -> None:
    descriptor = -1
    created = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
            os, "O_CLOEXEC", 0
        )
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise HostedCaptureError(f"short write while capturing {path}")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise HostedCaptureError(f"cannot write capture file {path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_captured_zip(
    path: Path,
    *,
    label: str,
    maximum_uncompressed: int = hosted.MAX_ZIP_UNCOMPRESSED_BYTES,
    deadline: float | None = None,
) -> int:
    try:
        return hosted._validate_zip(
            path,
            label,
            maximum_uncompressed=maximum_uncompressed,
            progress=lambda: _check_deadline(deadline, label),
        )
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error


def _read_selection(
    path: Path, repository: str, revision: str
) -> tuple[bytes, list[dict[str, int | str]]]:
    try:
        value, raw = hosted._read_json(path, "capture selection")
        selected = hosted._validate_selection(value, repository, revision)
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    canonical = _canonical_bytes(value)
    if raw != canonical:
        raise HostedCaptureError("capture selection is not canonical JSON")
    return raw, selected


def _snapshot_value(snapshot: dict[str, bytes], relative: str) -> Any:
    try:
        return hosted._parse_json(snapshot[relative], relative)
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error


def capture_snapshot(
    output: Path,
    *,
    repository: str,
    revision: str,
    selection: Path | None = None,
    token: str,
    transport: HttpTransport | None = None,
) -> None:
    """Capture a stable, complete provider snapshot into a fresh directory."""

    try:
        repository = hosted._repository(repository)
        revision = hosted._git_sha(revision, "capture revision")
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    _api_headers(token)
    if output.exists() or output.is_symlink():
        raise HostedCaptureError(f"output already exists: {output}")
    legacy_selection_raw: bytes | None = None
    if selection is not None:
        legacy_selection_raw, _legacy_selected = _read_selection(
            selection, repository, revision
        )
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        staging, staging_metadata, staging_descriptor = (
            hosted._create_private_staging_directory(
                output.parent,
                f".{output.name}.tmp-",
                "hosted capture staging creation failed",
            )
        )
    except hosted.HostedEvidenceError as error:
        raise HostedCaptureError(str(error)) from error
    except OSError as error:
        raise HostedCaptureError(f"cannot create capture staging directory: {error}") from error
    client = transport or UrllibTransport()
    deadline = time.monotonic() + MAX_CAPTURE_SECONDS
    publication_identity: tuple[int, int] | None = None
    publication_collision = False
    primary: BaseException | None = None
    try:
        before, selection_raw, selected = _snapshot_api(
            repository=repository,
            revision=revision,
            token=token,
            transport=client,
            expected_selection_raw=legacy_selection_raw,
            deadline=deadline,
        )
        runs_value = _snapshot_value(before, "api/workflow-runs.json")
        run_records = _indexed(runs_value["workflow_runs"], label="workflow runs")
        selected_run_ids = list(
            dict.fromkeys(int(record["workflow_run_id"]) for record in selected)
        )
        artifact_ids: set[int] = set()
        archive_count = 0
        archive_bytes = 0
        archive_uncompressed_bytes = 0
        for run_id in selected_run_ids:
            run = run_records[run_id]
            try:
                attempt = hosted._positive_integer(
                    run.get("run_attempt"), "workflow run attempt"
                )
            except hosted.HostedEvidenceError as error:
                raise HostedCaptureError(str(error)) from error
            request_url = (
                f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/"
                f"attempts/{attempt}/logs"
            )
            log_path = (
                staging / "downloads" / "logs"
                / f"{run_id}-attempt-{attempt}.zip"
            )
            if archive_count >= MAX_CAPTURE_ARCHIVE_FILES:
                raise HostedCaptureError("capture archive file budget exceeded")
            authority, uncompressed_size = _download_archive(
                transport=client,
                token=token,
                request_url=request_url,
                label=f"run {run_id} attempt {attempt} log",
                target=log_path,
                maximum=MAX_CAPTURE_ARCHIVE_BYTES - archive_bytes,
                maximum_uncompressed=(
                    hosted.MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES
                    - archive_uncompressed_bytes
                ),
                deadline=deadline,
            )
            archive_count += 1
            archive_bytes += int(authority["archive_size"])
            archive_uncompressed_bytes += uncompressed_size
            authority.update({
                "schema": hosted.LOG_DOWNLOAD_SCHEMA,
                "repository": repository,
                "run_id": run_id,
                "run_attempt": attempt,
            })
            _write_new(
                staging / "api" / "log-downloads"
                / f"{run_id}-attempt-{attempt}.json",
                _canonical_bytes(authority),
            )

            artifacts_value = _snapshot_value(
                before, f"api/artifacts/{run_id}.json"
            )
            artifacts = artifacts_value["artifacts"]
            for raw in artifacts:
                if not isinstance(raw, dict):
                    raise HostedCaptureError("artifact API record is malformed")
                try:
                    hosted._validate_artifact_attempt(raw, attempt)
                    artifact_id = hosted._positive_integer(raw.get("id"), "artifact ID")
                except hosted.HostedEvidenceError as error:
                    raise HostedCaptureError(str(error)) from error
                if artifact_id in artifact_ids:
                    raise HostedCaptureError("artifact IDs are duplicated")
                artifact_ids.add(artifact_id)
                artifact_request = (
                    f"https://api.github.com/repos/{repository}/actions/artifacts/"
                    f"{artifact_id}/zip"
                )
                if raw.get("archive_download_url") != artifact_request:
                    raise HostedCaptureError("artifact download URL drift")
                artifact_path = (
                    staging / "downloads" / "artifacts" / f"{artifact_id}.zip"
                )
                if archive_count >= MAX_CAPTURE_ARCHIVE_FILES:
                    raise HostedCaptureError(
                        "capture archive file budget exceeded"
                    )
                artifact_authority, uncompressed_size = _download_archive(
                    transport=client,
                    token=token,
                    request_url=artifact_request,
                    label=f"artifact {artifact_id}",
                    target=artifact_path,
                    maximum=MAX_CAPTURE_ARCHIVE_BYTES - archive_bytes,
                    maximum_uncompressed=(
                        hosted.MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES
                        - archive_uncompressed_bytes
                    ),
                    deadline=deadline,
                )
                archive_count += 1
                archive_bytes += int(artifact_authority["archive_size"])
                archive_uncompressed_bytes += uncompressed_size
                artifact_authority.update({
                    "schema": hosted.ARTIFACT_DOWNLOAD_SCHEMA,
                    "repository": repository,
                    "artifact_id": artifact_id,
                })
                _write_new(
                    staging / "api" / "artifact-downloads" / f"{artifact_id}.json",
                    _canonical_bytes(artifact_authority),
                )

        after, selection_after, selected_after = _snapshot_api(
            repository=repository,
            revision=revision,
            token=token,
            transport=client,
            expected_selection_raw=selection_raw,
            deadline=deadline,
        )
        if before != after:
            raise HostedCaptureError("GitHub API authority changed during capture")
        if selection_after != selection_raw or selected_after != selected:
            raise HostedCaptureError(
                "deterministic provider selection changed during capture"
            )
        if selection is not None:
            legacy_after, _ = _read_selection(
                selection, repository, revision
            )
            if legacy_after != legacy_selection_raw:
                raise HostedCaptureError("capture selection changed during capture")
        _write_new(staging / "selection.json", selection_raw)
        for relative, raw in sorted(before.items()):
            _write_new(staging / relative, raw)
        hosted._fsync_directories(staging)
        publication_metadata = staging.lstat()
        if (
            publication_metadata.st_dev != staging_metadata.st_dev
            or publication_metadata.st_ino != staging_metadata.st_ino
        ):
            raise HostedCaptureError("capture staging identity changed")
        publication_identity = (
            publication_metadata.st_dev,
            publication_metadata.st_ino,
        )
        try:
            hosted._rename_noreplace(staging, output)
        except hosted._HostedPublicationCollision as error:
            publication_collision = True
            raise HostedCaptureError(str(error)) from error
        hosted._fsync_directory(output.parent)
        published_metadata = output.lstat()
        if (
            not stat.S_ISDIR(published_metadata.st_mode)
            or (published_metadata.st_dev, published_metadata.st_ino)
            != publication_identity
        ):
            raise HostedCaptureError("published capture identity changed")
    except hosted.HostedEvidenceError as error:
        primary = HostedCaptureError(str(error))
    except OSError as error:
        primary = HostedCaptureError(
            f"capture filesystem operation failed: {error}"
        )
    except BaseException as error:
        primary = error
    cleanup_errors: list[Exception] = []
    try:
        try:
            remaining_staging = staging.lstat()
        except FileNotFoundError:
            remaining_staging = None
        if remaining_staging is not None:
            hosted._remove_tree_identity(
                staging, staging_metadata.st_dev, staging_metadata.st_ino
            )
    except Exception as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if (
        (primary is not None or cleanup_errors)
        and publication_identity is not None
        and not publication_collision
    ):
        try:
            try:
                published_metadata = output.lstat()
            except FileNotFoundError:
                published_metadata = None
            if published_metadata is not None and (
                published_metadata.st_dev,
                published_metadata.st_ino,
            ) == publication_identity:
                hosted._remove_tree_identity(
                    output, publication_identity[0], publication_identity[1]
                )
            elif published_metadata is not None:
                raise HostedCaptureError(
                    "published capture identity changed"
                )
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
    try:
        os.close(staging_descriptor)
    except OSError as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if primary is not None and cleanup_errors:
        detail = "; ".join(str(item) for item in cleanup_errors)
        raise HostedCaptureError(
            "capture publication failed: "
            f"primary failure: {primary}; cleanup failure: {detail}"
        ) from primary
    if primary is not None:
        if isinstance(primary, HostedCaptureError):
            raise primary
        if not isinstance(primary, Exception):
            raise primary
        raise HostedCaptureError(f"capture failed: {primary}") from primary
    if cleanup_errors:
        detail = "; ".join(str(item) for item in cleanup_errors)
        raise HostedCaptureError(
            f"capture publication cleanup failed: {detail}"
        ) from cleanup_errors[0]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    token = os.environ.get(arguments.token_env, "")
    try:
        capture_snapshot(
            arguments.output,
            repository=arguments.repository,
            revision=arguments.revision,
            selection=arguments.selection,
            token=token,
        )
        print(
            "CODESKEPTIC_HOSTED_EXACT_HEAD_CAPTURED "
            f"{arguments.repository} {arguments.revision} {arguments.output}"
        )
        return 0
    except HostedCaptureError as error:
        print(f"CODESKEPTIC_HOSTED_EXACT_HEAD_CAPTURE_FAIL {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
