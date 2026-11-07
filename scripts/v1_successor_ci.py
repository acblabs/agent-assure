"""Authenticated, bounded GitHub Actions read-back for S1 successor evidence.

The transport is the authentication boundary, not a Boolean in an imported
JSON document. Production callers supply a read-only token in memory and a
Git blob reader backed by the frozen host. Test transports are explicitly
synthetic. This module neither starts a workflow nor persists credentials.

Protocol references: GitHub REST workflow-runs and workflow-jobs, API version
2026-03-10, https://docs.github.com/en/rest/actions/workflow-runs and
https://docs.github.com/en/rest/actions/workflow-jobs .
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from scripts.v1_s1_successor import MANDATORY_CI_INSTANCES, ci_instance_id

REPOSITORY = "acblabs/agent-assure"
WORKFLOW_PATH = ".github/workflows/ci.yml"
API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_PAGES = 32
MAX_WORKFLOW_BYTES = 512 * 1024
_OID = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")
_PATH = re.compile(
    r"/repos/acblabs/agent-assure/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*"
    r"(?:/jobs\?per_page=(?:[1-9]|[1-9][0-9]|100)&page=[1-9][0-9]*)?\Z"
)


class CIReadbackError(ValueError):
    """A sanitized read-back failure, never containing credentials or raw bodies."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class CIReadback:
    """Pure-successor payload plus nonsensitive transport observation metadata."""

    payload: dict[str, Any]
    observation: dict[str, Any]


class AuthenticatedTransport(Protocol):
    """Only a trusted caller may inject a substitute transport."""

    def __call__(self, path: str) -> HttpResponse: ...


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise CIReadbackError("GitHub API redirects are forbidden")


class AuthenticatedGitHubTransport:
    """Fixed-host HTTPS, no proxies/redirects, bounded reads and explicit token.

    The total request budget is monotonic. No response, exception diagnostic,
    repr or observation includes the token, authorization header or API body.
    """

    def __init__(
        self,
        token: str,
        *,
        timeout_seconds: int = 30,
        total_timeout_seconds: int = 180,
    ) -> None:
        if (
            type(token) is not str
            or not 1 <= len(token) <= 4096
            or any(not 33 <= ord(character) <= 126 for character in token)
        ):
            raise CIReadbackError("a bounded non-whitespace ASCII API token is required")
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 60
            or type(total_timeout_seconds) is not int
            or not timeout_seconds <= total_timeout_seconds <= 600
        ):
            raise CIReadbackError("invalid bounded HTTPS timeout profile")
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._deadline = time.monotonic() + total_timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _RejectRedirects(),
        )

    def __repr__(self) -> str:
        return "AuthenticatedGitHubTransport(credential=<redacted>)"

    def __call__(self, path: str) -> HttpResponse:
        if type(path) is not str or _PATH.fullmatch(path) is None or len(path) > 256:
            raise CIReadbackError("unapproved GitHub API request path")
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise CIReadbackError("GitHub API total timeout exhausted")
        request = urllib.request.Request(
            "https://" + API_HOST + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "agent-assure-successor-verifier/1",
            },
            method="GET",
        )
        try:
            with self._opener.open(
                request, timeout=min(self._timeout_seconds, remaining)
            ) as response:
                if response.status != 200:
                    raise CIReadbackError("GitHub API did not return HTTP 200")
                if response.geturl() != request.full_url:
                    raise CIReadbackError("GitHub API response target changed")
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
                if content_type not in {"application/json", "application/vnd.github+json"}:
                    raise CIReadbackError("GitHub API content type is unsupported")
                content_length = response.headers.get("Content-Length")
                if content_length is not None and (
                    re.fullmatch(r"[0-9]{1,10}", content_length) is None
                    or int(content_length) > MAX_RESPONSE_BYTES
                ):
                    raise CIReadbackError("GitHub API body length exceeds the bound")
                chunks: list[bytes] = []
                size = 0
                while True:
                    if time.monotonic() >= self._deadline:
                        raise CIReadbackError("GitHub API total timeout exhausted")
                    chunk = response.read(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise CIReadbackError("GitHub API body exceeds the byte bound")
                if content_length is not None and size != int(content_length):
                    raise CIReadbackError("GitHub API body was truncated")
                if time.monotonic() >= self._deadline:
                    raise CIReadbackError("GitHub API total timeout exhausted")
                return HttpResponse(200, {"content-type": content_type}, b"".join(chunks))
        except CIReadbackError:
            raise
        except urllib.error.HTTPError as exc:
            # Do not stringify HTTP exceptions: their URL/body may be hostile.
            code = exc.code if type(exc.code) is int else 0
            exc.close()
            raise CIReadbackError(f"GitHub API HTTP failure ({code})") from None
        except (OSError, ValueError, http.client.HTTPException):
            raise CIReadbackError("GitHub API authenticated HTTPS read failed") from None


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise CIReadbackError(f"{label} must be a strict positive JSON-safe integer")
    return value


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _utc(value: object) -> datetime:
    if type(value) is not str or _TIME.fullmatch(value) is None:
        raise CIReadbackError("strict UTC API timestamp required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CIReadbackError("invalid API calendar timestamp") from None


def _json(payload: bytes) -> dict[str, Any]:
    if type(payload) is not bytes or len(payload) > MAX_RESPONSE_BYTES:
        raise CIReadbackError("bounded API JSON bytes required")
    depth = 0
    quoted = escaped = False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise CIReadbackError("API JSON nesting exceeds the bound")
        elif byte in (93, 125):
            depth -= 1

    def unique(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise CIReadbackError("duplicate API JSON key")
            result[key] = value
        return result

    def reject_number(_value: str) -> Any:
        raise CIReadbackError("API JSON noninteger or nonfinite number is unsupported")

    try:
        result = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise CIReadbackError("invalid bounded API JSON") from None
    if type(result) is not dict:
        raise CIReadbackError("API JSON object required")
    return cast(dict[str, Any], result)


def _display_names() -> dict[str, str]:
    """Authored mapping for the exact pinned workflow, not API-selected identity."""
    names = {
        f"test ({version})": ci_instance_id("test", {"python-version": version})
        for version in ("3.11", "3.12", "3.13", "3.14")
    }
    names.update(
        {
            f"dependency lower bounds / Python {version}": ci_instance_id(
                "dependency-lower-bounds", {"python-version": version}
            )
            for version in ("3.11", "3.14")
        }
    )
    names.update(
        {
            f"coverage / {shard}": ci_instance_id("coverage-shards", {"shard": shard})
            for shard in ("unit-a", "unit-b1", "unit-b2", "unit-top", "integration")
        }
    )
    names.update(
        {
            f"windows-containment ({version})": ci_instance_id(
                "windows-containment", {"python-version": version}
            )
            for version in ("3.11", "3.14")
        }
    )
    names.update(
        {
            job: ci_instance_id(job, {})
            for job in (
                "composite-action-smoke",
                "composite-action-strict-smoke",
                "coverage-gate",
                "schema-immutability",
                "langgraph-smoke",
                "adk-smoke",
                "otel-contract",
            )
        }
    )
    names["Windows governance / Python 3.12"] = ci_instance_id("windows-governance", {})
    return names


EXPECTED_DISPLAY_NAMES = _display_names()


def read_hosted_ci(
    *,
    transport: AuthenticatedTransport,
    run_id: int,
    run_attempt: int,
    expected_head_sha: str,
    expected_workflow_digest: str,
    workflow_blob_reader: Callable[[str, str], bytes],
    now: datetime,
    required_ci_instances: tuple[str, ...] = MANDATORY_CI_INSTANCES,
    page_size: int = 100,
) -> CIReadback:
    """Read a complete successful push-run attempt from authenticated GitHub.

    Only push executions are eligible: PR/PR-target workflows can execute a
    different merge/base workflow. The authenticated Git blob at the exact run
    SHA must equal the verifier's pinned workflow bytes. The attempt endpoint
    binds jobs to the requested attempt even where individual job responses do
    not expose ``run_attempt``. No API-provided URL is followed.
    """
    _positive_integer(run_id, "run ID")
    _positive_integer(run_attempt, "run attempt")
    if type(expected_head_sha) is not str or _OID.fullmatch(expected_head_sha) is None:
        raise CIReadbackError("full lowercase subject Git OID required")
    if (
        type(expected_workflow_digest) is not str
        or _DIGEST.fullmatch(expected_workflow_digest) is None
    ):
        raise CIReadbackError("pinned workflow digest required")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
        raise CIReadbackError("trusted UTC observation time required")
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise CIReadbackError("bounded API page size required")
    if (
        type(required_ci_instances) is not tuple
        or not all(type(instance) is str for instance in required_ci_instances)
        or len(set(required_ci_instances)) != len(required_ci_instances)
        or set(required_ci_instances) != set(EXPECTED_DISPLAY_NAMES.values())
    ):
        raise CIReadbackError("CI instance policy is incompatible with the pinned workflow mapping")
    workflow = workflow_blob_reader(expected_head_sha, WORKFLOW_PATH)
    if type(workflow) is not bytes or not 0 < len(workflow) <= MAX_WORKFLOW_BYTES:
        raise CIReadbackError("bounded authenticated workflow bytes required")
    if _digest(workflow) != expected_workflow_digest:
        raise CIReadbackError("authenticated subject workflow differs from the pinned digest")

    responses: list[dict[str, Any]] = []
    attempt_path = f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}"

    def fetch(path: str) -> dict[str, Any]:
        response = transport(path)
        if (
            type(response) is not HttpResponse
            or type(response.status) is not int
            or response.status != 200
        ):
            raise CIReadbackError("authenticated API returned an unsupported response")
        if not isinstance(response.headers, Mapping) or any(
            type(key) is not str or type(value) is not str
            for key, value in response.headers.items()
        ):
            raise CIReadbackError("authenticated API response headers are invalid")
        header_names = [key.lower() for key in response.headers]
        if len(set(header_names)) != len(header_names):
            raise CIReadbackError("authenticated API response headers are ambiguous")
        content_type = {key.lower(): value for key, value in response.headers.items()}.get(
            "content-type", ""
        )
        if content_type.split(";", 1)[0].strip() not in {
            "application/json",
            "application/vnd.github+json",
        }:
            raise CIReadbackError("authenticated API content type is unsupported")
        document = _json(response.body)
        responses.append(
            {
                "path": path,
                "status": 200,
                "size_bytes": len(response.body),
                "sha256": _digest(response.body),
            }
        )
        return document

    def validate_run(run: dict[str, Any]) -> tuple[datetime, datetime]:
        if (
            _positive_integer(run.get("id"), "response run ID") != run_id
            or _positive_integer(run.get("run_attempt"), "response attempt") != run_attempt
            or run.get("head_sha") != expected_head_sha
            or run.get("event") != "push"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != REPOSITORY
            or not isinstance(run.get("head_repository"), dict)
            or run["head_repository"].get("full_name") != REPOSITORY
        ):
            raise CIReadbackError("CI run identity, source, completion or conclusion differs")
        path = run.get("path")
        if type(path) is not str or not (
            path == WORKFLOW_PATH
            or (
                path.startswith(WORKFLOW_PATH + "@")
                and 0 < len(path) - len(WORKFLOW_PATH) - 1 <= 256
                and all(32 < ord(c) < 127 for c in path)
            )
        ):
            raise CIReadbackError("CI workflow path substitution")
        created, started, updated = (
            _utc(run.get(key)) for key in ("created_at", "run_started_at", "updated_at")
        )
        if not created <= started <= updated <= now:
            raise CIReadbackError("CI run observation chronology is invalid")
        return started, updated

    run = fetch(attempt_path)
    run_started, run_updated = validate_run(run)
    jobs: list[dict[str, Any]] = []
    job_ids: set[int] = set()
    instances: set[str] = set()
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        document = fetch(attempt_path + f"/jobs?per_page={page_size}&page={page}")
        page_total = _positive_integer(document.get("total_count"), "job count")
        if page_total != len(required_ci_instances) or (total is not None and page_total != total):
            raise CIReadbackError("CI job count differs from the complete required matrix")
        total = page_total
        page_jobs = document.get("jobs")
        remaining = total - len(jobs)
        if type(page_jobs) is not list or len(page_jobs) != min(page_size, remaining):
            raise CIReadbackError("CI page is missing jobs or exceeds its expected size")
        for job in page_jobs:
            if type(job) is not dict:
                raise CIReadbackError("CI job object required")
            job_id = _positive_integer(job.get("id"), "job ID")
            if job_id in job_ids:
                raise CIReadbackError("duplicate CI job ID")
            job_ids.add(job_id)
            name = job.get("name")
            if type(name) is not str or name not in EXPECTED_DISPLAY_NAMES:
                raise CIReadbackError("CI job name is not in the pinned matrix mapping")
            instance = EXPECTED_DISPLAY_NAMES[name]
            if instance in instances:
                raise CIReadbackError("duplicate CI matrix instance")
            instances.add(instance)
            if (
                _positive_integer(job.get("run_id"), "job run ID") != run_id
                or job.get("head_sha") != expected_head_sha
                or (
                    "run_attempt" in job
                    and _positive_integer(job["run_attempt"], "job attempt") != run_attempt
                )
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
            ):
                raise CIReadbackError("CI job subject, attempt, status or conclusion differs")
            started, completed = _utc(job.get("started_at")), _utc(job.get("completed_at"))
            if not run_started <= started <= completed <= run_updated <= now:
                raise CIReadbackError("CI job observation chronology is invalid")
            jobs.append(
                {
                    "instance_id": instance,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at_utc": job["started_at"],
                    "completed_at_utc": job["completed_at"],
                }
            )
        if len(jobs) == total:
            break
    else:
        raise CIReadbackError("CI pagination exceeded the bound")
    if instances != set(required_ci_instances):
        raise CIReadbackError("CI matrix is incomplete")
    # Read the attempt again so a mutable/inconsistent API view cannot be
    # silently assembled from unrelated snapshots. Compare semantic bindings.
    after = fetch(attempt_path)
    validate_run(after)
    stable_fields = (
        "id",
        "run_attempt",
        "head_sha",
        "path",
        "event",
        "status",
        "conclusion",
        "created_at",
        "run_started_at",
        "updated_at",
    )
    if any(after.get(key) != run.get(key) for key in stable_fields):
        raise CIReadbackError("CI run changed during authenticated read-back")
    payload = {
        "repository": REPOSITORY,
        "workflow_path": WORKFLOW_PATH,
        "workflow_digest": expected_workflow_digest,
        "head_sha": expected_head_sha,
        "run_id": str(run_id),
        "run_attempt": run_attempt,
        "status": "completed",
        "conclusion": "success",
        "jobs": sorted(jobs, key=lambda row: row["instance_id"]),
    }
    observation = {
        "format": "agent-assure-successor-ci-readback/1",
        "authorization_effect": "none",
        "transport_profile": "fixed-host-authenticated-https-no-redirect/v1",
        "api_host": API_HOST,
        "api_version": API_VERSION,
        "observed_at_utc": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "clock_basis": "maintainer_host_utc_externally_unattested",
        "workflow_blob_sha256": expected_workflow_digest,
        "responses": responses,
    }
    return CIReadback(payload, observation)
