from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_assure.live.adapters import (
    ExternalScriptAdapter,
    LiveProviderRequest,
    TrustedLiveExecution,
)
from agent_assure.live.config import LiveAdapterConfig
from agent_assure.runner import subprocess_harness
from agent_assure.runner.subprocess_harness import ExternalScriptError
from agent_assure.telemetry.context import trace_context_for_seed


def test_external_script_adapter_invokes_script_with_trace_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHOULD_NOT_LEAK", "secret")
    script = tmp_path / "adapter.py"
    script.write_text(
        """
import json
import os
import sys

payload = json.loads(sys.stdin.read())
assert os.environ["TRACEPARENT"] == payload["trace_context"]["traceparent"]
assert os.environ["CUSTOM_FLAG"] == "enabled"
assert "SHOULD_NOT_LEAK" not in os.environ
print(json.dumps({
    "record": {
        "recommendation": "approve",
        "outcome": "approve",
        "output_summary": "subprocess approved",
        "tools": [],
        "evidence_refs": [],
        "evidence_items": [],
        "claims": [],
        "claim_evidence_links": [],
        "policy_results": []
    },
    "provider": "local-script",
    "model": "script-model",
    "resolved_model": "script-model@local",
    "prompt_tokens": 3,
    "completion_tokens": 4,
    "total_tokens": 7,
    "estimated_cost_usd": "0.000001"
}))
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
            script_env=({"name": "CUSTOM_FLAG", "value": "enabled"},),
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )
    trace_context = trace_context_for_seed("obs-001")

    response = adapter.complete(
        LiveProviderRequest(
            run_id="run-001",
            observation_id="obs-001",
            case_id="case-001",
            repetition_index=0,
            prompt="summarize the request",
            provider="local-script",
            model="script-model",
            traceparent=trace_context.traceparent,
        )
    )

    content = json.loads(response.content)
    assert content["recommendation"] == "approve"
    assert response.total_tokens == 7
    assert response.resolved_model == "script-model@local"


def test_external_script_failure_creates_redacted_emergency_record(tmp_path: Path) -> None:
    script = tmp_path / "bad_adapter.py"
    script.write_text(
        """
import sys

print("ssn: 123-45-6789", file=sys.stderr)
raise SystemExit(7)
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )
    trace_context = trace_context_for_seed("obs-002")

    with pytest.raises(ExternalScriptError) as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-002",
                observation_id="obs-002",
                case_id="case-002",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
                traceparent=trace_context.traceparent,
            )
        )

    emergency = raised.value.emergency_record
    dumped = json.dumps(emergency.model_dump(mode="json"))
    assert emergency.failure_kind == "nonzero_exit"
    assert emergency.exit_code == 7
    assert "123-45-6789" not in dumped
    assert "[REDACTED]" in dumped
    assert emergency.traceparent == trace_context.traceparent


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        pytest.param(
            f"{'x' * 483} Bearer {'T' * 40}",
            f"{'x' * 483} [REDACTED]",
            id="bearer-token",
        ),
        pytest.param(
            f"{'x' * 290} eyJ{'A' * 100}.{'B' * 100}.{'C' * 100}",
            f"{'x' * 290} [REDACTED]",
            id="json-web-token",
        ),
    ],
)
def test_emergency_summary_redacts_secret_crossing_truncation_boundary(
    stderr: str,
    expected: str,
) -> None:
    summary = subprocess_harness._summary(stderr)

    assert summary == expected
    assert len(summary) <= 500


def test_emergency_summary_remains_bounded_after_redaction() -> None:
    assert subprocess_harness._summary("x" * 600) == "x" * 500


@pytest.mark.parametrize(
    "stderr",
    (
        ("x" * 493) + " " + "a@b.co",
        ("x" * 499) + "Bearer " + ("T" * 40),
        ("x" * 499) + subprocess_harness.REDACTION_MASK_CHARACTER,
    ),
)
def test_emergency_summary_remains_bounded_when_mask_expands(stderr: str) -> None:
    summary = subprocess_harness._summary(stderr)

    assert summary is not None
    assert len(summary) <= 500


def test_emergency_summary_drops_short_truncated_source() -> None:
    clipped = "diagnostic" + (" " * 80) + "Bearer SHORT"

    assert subprocess_harness._summary(clipped, source_truncated=True) is None


def test_emergency_summary_redacts_sensitive_value_split_across_lines() -> None:
    summary = subprocess_harness._summary("card 4111\r\n1111\r\n1111\r\n1111")

    assert summary == "card [REDACTED]"


def test_external_script_path_cannot_escape_config_dir(tmp_path: Path) -> None:
    script = tmp_path / "adapter.py"
    script.write_text("print('{}')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="script_path"):
        ExternalScriptAdapter(
            LiveAdapterConfig(
                adapter_id="external-script",
                provider="local-script",
                model="script-model",
                script_path=str(script.resolve()),
                script_executable=sys.executable,
            ),
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_external_script=True),
        )


def test_external_script_adapter_requires_explicit_trust(tmp_path: Path) -> None:
    script = tmp_path / "adapter.py"
    script.write_text("print('{}')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="allow_external_script"):
        ExternalScriptAdapter(
            LiveAdapterConfig(
                adapter_id="external-script",
                provider="local-script",
                model="script-model",
                script_path=script.name,
                script_executable=sys.executable,
            ),
            base_dir=tmp_path,
        )


def test_external_script_stdout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness, "MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES", 32)
    script = tmp_path / "noisy_adapter.py"
    script.write_text(
        """
print("x" * 128)
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )

    with pytest.raises(ExternalScriptError, match="output exceeded byte limit") as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-oversized",
                observation_id="obs-oversized",
                case_id="case-oversized",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
            )
        )

    emergency = raised.value.emergency_record
    assert emergency.failure_kind == "invalid_output"
    assert emergency.stdout_bytes > 32


def test_external_script_stderr_summary_does_not_pull_clipped_secret_across_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 128
    monkeypatch.setattr(subprocess_harness, "MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES", limit)
    script = tmp_path / "boundary_adapter.py"
    script.write_text(
        "import sys\n\n"
        f"sys.stderr.write('diagnostic' + (' ' * {limit - 24}) + "
        "'Bearer ' + ('T' * 40))\n",
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )

    with pytest.raises(ExternalScriptError, match="output exceeded byte limit") as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-boundary",
                observation_id="obs-boundary",
                case_id="case-boundary",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
            )
        )

    emergency = raised.value.emergency_record
    assert emergency.stderr_bytes > limit
    assert emergency.stderr_summary is None
