from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_assure.live.adapters import ExternalScriptAdapter, LiveProviderRequest
from agent_assure.live.config import LiveAdapterConfig
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
