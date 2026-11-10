"""Synthetic authentication-boundary tests; no hosted run or human acceptance."""

from __future__ import annotations

import copy
import hashlib
import json
import ssl
import sys
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import v1_successor_ci as ci  # noqa: E402

SHA = "a" * 40
WORKFLOW = b"name: reviewed frozen workflow\n"
DIGEST = "sha256:" + hashlib.sha256(WORKFLOW).hexdigest()
NOW = datetime(2026, 11, 7, 15, 0, tzinfo=UTC)
ATTEMPT = "/repos/acblabs/agent-assure/actions/runs/123/attempts/2"


def response(value: Any, *, status: int = 200) -> ci.HttpResponse:
    return ci.HttpResponse(status, {"content-type": "application/json"}, json.dumps(value).encode())


def run_record() -> dict[str, Any]:
    return {
        "id": 123,
        "run_attempt": 2,
        "head_sha": SHA,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "path": ci.WORKFLOW_PATH,
        "repository": {"full_name": ci.REPOSITORY},
        "head_repository": {"full_name": ci.REPOSITORY},
        "created_at": "2026-11-07T12:00:00Z",
        "run_started_at": "2026-11-07T13:00:00Z",
        "updated_at": "2026-11-07T14:00:00Z",
    }


def job_records() -> list[dict[str, Any]]:
    return [
        {
            "id": index,
            "run_id": 123,
            "head_sha": SHA,
            "run_attempt": 2,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-11-07T13:01:00Z",
            "completed_at": "2026-11-07T13:59:00Z",
        }
        for index, name in enumerate(ci.EXPECTED_DISPLAY_NAMES, 1)
    ]


class SyntheticTransport:
    def __init__(self) -> None:
        self.run = run_record()
        self.jobs = job_records()
        self.paths: list[str] = []
        self.final_run: dict[str, Any] | None = None
        self.run_reads = 0
        self.override: dict[str, ci.HttpResponse] = {}

    def __call__(self, path: str) -> ci.HttpResponse:
        self.paths.append(path)
        if path in self.override:
            return self.override[path]
        if path == ATTEMPT:
            self.run_reads += 1
            return response(self.final_run if self.run_reads > 1 and self.final_run else self.run)
        assert path.startswith(ATTEMPT + "/jobs?per_page=")
        query = path.split("?", 1)[1]
        size, page = [int(part.split("=", 1)[1]) for part in query.split("&")]
        return response(
            {"total_count": len(self.jobs), "jobs": self.jobs[(page - 1) * size : page * size]}
        )


def read(transport: SyntheticTransport, **overrides: Any) -> ci.CIReadback:
    options = {
        "transport": transport,
        "run_id": 123,
        "run_attempt": 2,
        "expected_head_sha": SHA,
        "expected_workflow_digest": DIGEST,
        "workflow_blob_reader": lambda sha, path: (
            WORKFLOW if (sha, path) == (SHA, ci.WORKFLOW_PATH) else b"wrong"
        ),
        "now": NOW,
    }
    options.update(overrides)
    return ci.read_hosted_ci(**options)


def test_complete_attempt_is_bound_to_every_expanded_instance_and_source() -> None:
    transport = SyntheticTransport()
    result = read(transport)
    assert set(result.payload) == {
        "repository",
        "workflow_path",
        "workflow_digest",
        "head_sha",
        "run_id",
        "run_attempt",
        "status",
        "conclusion",
        "jobs",
    }
    assert result.payload["run_id"] == "123"
    assert result.payload["run_attempt"] == 2
    assert {row["instance_id"] for row in result.payload["jobs"]} == set(ci.MANDATORY_CI_INSTANCES)
    assert len(result.payload["jobs"]) == 21
    assert transport.paths == [ATTEMPT, ATTEMPT + "/jobs?per_page=100&page=1", ATTEMPT]
    assert result.observation["authorization_effect"] == "none"
    assert result.observation["workflow_blob_sha256"] == DIGEST
    assert all(
        set(row) == {"path", "status", "size_bytes", "sha256"}
        for row in result.observation["responses"]
    )
    assert "steps" not in json.dumps(result.payload)


def test_pagination_follows_locally_constructed_paths_and_exact_total() -> None:
    transport = SyntheticTransport()
    result = read(transport, page_size=5)
    assert len(result.payload["jobs"]) == 21
    assert [p for p in transport.paths if "/jobs?" in p] == [
        ATTEMPT + f"/jobs?per_page=5&page={page}" for page in range(1, 6)
    ]


@pytest.mark.parametrize(
    "key,value",
    [
        ("id", 124),
        ("id", True),
        ("run_attempt", 1),
        ("head_sha", "b" * 40),
        ("event", "pull_request"),
        ("event", "pull_request_target"),
        ("status", "in_progress"),
        ("conclusion", "neutral"),
        ("conclusion", "skipped"),
        ("conclusion", "cancelled"),
        ("path", ".github/workflows/other.yml"),
        ("repository", {"full_name": "attacker/agent-assure"}),
        ("head_repository", {"full_name": "attacker/agent-assure"}),
        ("created_at", "2026-11-07T14:00:00Z"),
        ("updated_at", "2026-11-08T14:00:00Z"),
        ("run_started_at", "not-a-timestamp"),
    ],
)
def test_wrong_run_or_execution_context_is_rejected(key: str, value: Any) -> None:
    transport = SyntheticTransport()
    transport.run[key] = value
    with pytest.raises(ci.CIReadbackError):
        read(transport)


@pytest.mark.parametrize(
    "key,value",
    [
        ("id", True),
        ("run_id", 124),
        ("run_attempt", 1),
        ("head_sha", "b" * 40),
        ("status", "queued"),
        ("conclusion", "neutral"),
        ("conclusion", "skipped"),
        ("conclusion", "cancelled"),
        ("name", "test (3.10)"),
        ("started_at", "2026-11-07T12:59:59Z"),
        ("completed_at", "2026-11-07T14:00:01Z"),
        ("completed_at", "2026-11-07T13:00:59Z"),
    ],
)
def test_job_substitution_or_invalid_chronology_is_rejected(key: str, value: Any) -> None:
    transport = SyntheticTransport()
    transport.jobs[0][key] = value
    with pytest.raises(ci.CIReadbackError):
        read(transport)


def test_attempt_endpoint_is_used_when_job_api_does_not_supply_attempt_field() -> None:
    transport = SyntheticTransport()
    for job in transport.jobs:
        del job["run_attempt"]
    assert len(read(transport).payload["jobs"]) == 21
    assert all("/attempts/2" in path for path in transport.paths)


def test_missing_matrix_instance_and_extra_instance_are_rejected() -> None:
    transport = SyntheticTransport()
    transport.jobs.pop()
    with pytest.raises(ci.CIReadbackError, match="job count"):
        read(transport)
    transport.jobs.extend(copy.deepcopy(transport.jobs[:2]))
    with pytest.raises(ci.CIReadbackError, match="job count"):
        read(transport)


@pytest.mark.parametrize("field", ["id", "name"])
def test_duplicate_across_paginated_jobs_is_rejected(field: str) -> None:
    transport = SyntheticTransport()
    transport.jobs[5][field] = transport.jobs[0][field]
    with pytest.raises(ci.CIReadbackError, match="duplicate"):
        read(transport, page_size=5)


def test_truncated_page_cannot_hide_a_required_job() -> None:
    transport = SyntheticTransport()
    transport.override[ATTEMPT + "/jobs?per_page=5&page=2"] = response(
        {"total_count": 21, "jobs": transport.jobs[5:9]}
    )
    with pytest.raises(ci.CIReadbackError, match="missing jobs"):
        read(transport, page_size=5)


def test_changing_run_readback_is_rejected() -> None:
    transport = SyntheticTransport()
    transport.final_run = copy.deepcopy(transport.run)
    transport.final_run["updated_at"] = "2026-11-07T14:01:00Z"
    with pytest.raises(ci.CIReadbackError, match="changed"):
        read(transport)


@pytest.mark.parametrize(
    "options",
    [
        {"run_id": True},
        {"run_id": 0},
        {"run_attempt": 0},
        {"run_attempt": 2.0},
        {"expected_head_sha": "main"},
        {"expected_workflow_digest": "sha256:bad"},
        {"workflow_blob_reader": lambda _sha, _path: b"different"},
        {"workflow_blob_reader": lambda _sha, _path: b""},
        {"page_size": False},
        {"page_size": 101},
        {"required_ci_instances": (ci.MANDATORY_CI_INSTANCES[0],)},
        {"now": datetime(2026, 11, 7)},
    ],
)
def test_unbound_or_weakened_verifier_arguments_fail_before_network(
    options: dict[str, Any],
) -> None:
    transport = SyntheticTransport()
    with pytest.raises(ci.CIReadbackError):
        read(transport, **options)
    assert not transport.paths


@pytest.mark.parametrize(
    "body",
    [
        b'{"id":123,"id":123}',
        b'{"id":NaN}',
        b'{"id":123.0}',
        b"[]",
        b"\xff",
        b'{"a":' + b"[" * 41 + b"0" + b"]" * 41 + b"}",
        b" " * (ci.MAX_RESPONSE_BYTES + 1),
    ],
    ids=["duplicate", "nonfinite", "float", "array", "utf8", "depth", "byte-limit"],
)
def test_strict_bounded_api_json(body: bytes) -> None:
    transport = SyntheticTransport()
    transport.override[ATTEMPT] = ci.HttpResponse(200, {"content-type": "application/json"}, body)
    with pytest.raises(ci.CIReadbackError):
        read(transport)


@pytest.mark.parametrize(
    "status,headers",
    [
        (302, {"content-type": "application/json", "location": "https://evil.invalid"}),
        (401, {"content-type": "application/json"}),
        (200, {"content-type": "text/html"}),
    ],
)
def test_readback_rejects_redirect_error_or_nonjson_transport_response(
    status: int,
    headers: dict[str, str],
) -> None:
    transport = SyntheticTransport()
    transport.override[ATTEMPT] = ci.HttpResponse(status, headers, b"{}")
    with pytest.raises(ci.CIReadbackError):
        read(transport)


class FakeHTTPSResponse:
    status = 200

    def __init__(
        self,
        payload: bytes,
        *,
        url: str = "https://api.github.com" + ATTEMPT,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.payload = payload
        self.position = 0
        self.url = url
        self.headers = headers or {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
        }

    def __enter__(self) -> FakeHTTPSResponse:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def geturl(self) -> str:
        return self.url

    def read(self, size: int) -> bytes:
        result = self.payload[self.position : self.position + size]
        self.position += len(result)
        return result


def test_native_transport_has_fixed_verified_https_and_explicit_inmemory_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Opener:
        def open(self, request: Any, timeout: float) -> FakeHTTPSResponse:
            captured.update(request=request, timeout=timeout)
            return FakeHTTPSResponse(b"{}")

    def build(*handlers: Any) -> Opener:
        captured["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(ci.urllib.request, "build_opener", build)
    transport = ci.AuthenticatedGitHubTransport("secret-token")
    result = transport(ATTEMPT)
    assert result.body == b"{}"
    assert captured["request"].full_url == "https://api.github.com" + ATTEMPT
    assert captured["request"].get_header("Authorization") == "Bearer secret-token"
    assert captured["request"].get_method() == "GET"
    assert captured["timeout"] <= 30
    https = next(h for h in captured["handlers"] if isinstance(h, ci.urllib.request.HTTPSHandler))
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert https._context.check_hostname is True
    proxy = next(h for h in captured["handlers"] if isinstance(h, ci.urllib.request.ProxyHandler))
    assert proxy.proxies == {}
    assert "secret-token" not in repr(transport)
    assert "secret-token" not in repr(result)


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.invalid",
        "//evil.invalid/",
        ATTEMPT + "#fragment",
        ATTEMPT + "/../secrets",
        ATTEMPT + "?token=secret",
        ATTEMPT + "\nHeader:value",
        "/repos/attacker/agent-assure/actions/runs/123/attempts/2",
    ],
)
def test_transport_never_follows_candidate_paths(path: str) -> None:
    transport = ci.AuthenticatedGitHubTransport("secret-token")
    with pytest.raises(ci.CIReadbackError, match="unapproved"):
        transport(path)


@pytest.mark.parametrize(
    "token", ["", "secret\nInjected:value", "secret token", "\u2603", "a" * 4097]
)
def test_token_header_injection_and_unbounded_tokens_are_rejected(token: str) -> None:
    with pytest.raises(ci.CIReadbackError) as error:
        ci.AuthenticatedGitHubTransport(token)
    assert token not in str(error.value) if token else True


@pytest.mark.parametrize(
    "failure",
    [
        OSError("secret-token"),
        urllib.error.HTTPError("https://secret-token@evil.invalid", 401, "secret-token", {}, None),
    ],
)
def test_transport_errors_never_include_token_url_or_raw_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> Any:
            raise failure

    monkeypatch.setattr(ci.urllib.request, "build_opener", lambda *_handlers: Opener())
    transport = ci.AuthenticatedGitHubTransport("secret-token")
    with pytest.raises(ci.CIReadbackError) as error:
        transport(ATTEMPT)
    assert "secret-token" not in str(error.value)
    assert "evil.invalid" not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_redirect_handler_rejects_instead_of_forwarding_authorization() -> None:
    with pytest.raises(ci.CIReadbackError, match="redirect"):
        ci._RejectRedirects().redirect_request(None, None, 302, "move", {}, "https://evil.invalid")


@pytest.mark.parametrize(
    "headers,payload,url",
    [
        ({"Content-Type": "application/json", "Content-Length": "3"}, b"{}", None),
        ({"Content-Type": "application/json", "Content-Length": "99999999"}, b"{}", None),
        ({"Content-Type": "application/json", "Content-Length": "bad"}, b"{}", None),
        ({"Content-Type": "text/html"}, b"{}", None),
        ({"Content-Type": "application/json"}, b"{}", "https://evil.invalid"),
    ],
)
def test_transport_validates_actual_target_type_and_declared_body_length(
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str],
    payload: bytes,
    url: str | None,
) -> None:
    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> FakeHTTPSResponse:
            return FakeHTTPSResponse(
                payload, headers=headers, url=url or "https://api.github.com" + ATTEMPT
            )

    monkeypatch.setattr(ci.urllib.request, "build_opener", lambda *_handlers: Opener())
    with pytest.raises(ci.CIReadbackError):
        ci.AuthenticatedGitHubTransport("secret-token")(ATTEMPT)


def test_transport_monotonic_budget_is_not_reset_per_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter([0.0, 181.0])
    monkeypatch.setattr(ci.time, "monotonic", lambda: next(ticks))
    transport = ci.AuthenticatedGitHubTransport("secret-token")
    with pytest.raises(ci.CIReadbackError, match="timeout"):
        transport(ATTEMPT)


def test_raw_response_repr_never_discloses_headers_or_body() -> None:
    result = ci.HttpResponse(200, {"private-header": "secret-token"}, b"private API body")
    assert repr(result) == "HttpResponse(status=200)"


def test_unrelated_repository_metadata_change_does_not_change_run_identity() -> None:
    transport = SyntheticTransport()
    transport.run["repository"]["description"] = "earlier metadata"
    transport.final_run = copy.deepcopy(transport.run)
    transport.final_run["repository"]["description"] = "later metadata"
    assert len(read(transport).payload["jobs"]) == 21


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "application/json", "content-type": "text/html"},
        {"content-type": None},
    ],
)
def test_ambiguous_or_nonstring_response_headers_are_rejected(headers: Any) -> None:
    transport = SyntheticTransport()
    transport.override[ATTEMPT] = ci.HttpResponse(200, headers, b"{}")
    with pytest.raises(ci.CIReadbackError):
        read(transport)


def test_transport_rejects_response_that_finishes_after_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter([0.0, 1.0, 2.0, 3.0, 181.0])
    monkeypatch.setattr(ci.time, "monotonic", lambda: next(ticks))

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> FakeHTTPSResponse:
            return FakeHTTPSResponse(b"{}")

    monkeypatch.setattr(ci.urllib.request, "build_opener", lambda *_handlers: Opener())
    with pytest.raises(ci.CIReadbackError, match="timeout"):
        ci.AuthenticatedGitHubTransport("secret-token")(ATTEMPT)
