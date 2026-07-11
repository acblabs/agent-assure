from __future__ import annotations

import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli.live_cmd import _confirm_trusted_live_config, _trusted_live_config_reasons
from agent_assure.live.adapters import (
    MAX_PROVIDER_RESPONSE_BYTES,
    LiveProviderRequest,
    OpenAIChatCompletionsAdapter,
    StaticJsonlAdapter,
    _NoRedirectHandler,
    _read_provider_response,
)
from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.live.runner import (
    _is_rate_limit_error,
    _pace_request,
    _token_reservation,
    run_live_suite,
)
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.suite import CompiledSuite

SUITE = Path("examples/expense_approval_minimal/suite.yaml")


def test_rate_limit_detection_uses_status_or_retry_after_metadata() -> None:
    class StatusCodeError(Exception):
        status_code = 429

    class RetryAfterError(Exception):
        retry_after_seconds = "1.000000"

    assert _is_rate_limit_error(StatusCodeError("too many requests"))
    assert _is_rate_limit_error(RetryAfterError("provider backoff requested"))
    assert not _is_rate_limit_error(RuntimeError("generated accurately"))


def test_tokens_per_minute_reserves_prompt_chars_plus_max_output_tokens() -> None:
    config = _config(tokens_per_minute=20, max_output_tokens=7)

    assert _token_reservation("prompt", config) == 13


def test_tokens_per_minute_rejects_single_request_over_cap() -> None:
    config = _config(tokens_per_minute=10, max_output_tokens=7)

    with pytest.raises(ValueError, match="token reservation exceeds tokens_per_minute"):
        _pace_request(
            config,
            last_request_started=None,
            token_window_started=None,
            tokens_window_reserved=0,
            reserved_tokens=11,
        )


def test_live_cli_trust_detector_flags_external_scripts_and_network() -> None:
    config = LiveRunConfig(
        variant_id="external-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path="adapter.py",
            allow_network=True,
            script_env_allowlist=("OPENAI_API_KEY",),
        ),
        cases=(
            LivePromptCase(
                case_id="case-001",
                prompt_path="prompt.txt",
                input_summary="summary",
            ),
        ),
    )

    reasons = _trusted_live_config_reasons(config)

    assert any("external-script" in reason for reason in reasons)
    assert any("allow_network" in reason for reason in reasons)
    assert any("script_env_allowlist" in reason for reason in reasons)


def test_live_cli_ci_requires_trust_config_and_risk_specific_flags() -> None:
    config = LiveRunConfig(
        variant_id="external-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path="adapter.py",
            allow_network=True,
            script_env_allowlist=("OPENAI_API_KEY",),
        ),
        cases=(
            LivePromptCase(
                case_id="case-001",
                prompt_path="prompt.txt",
                input_summary="summary",
            ),
        ),
    )

    with pytest.raises(ValueError, match="requires --trust-config"):
        _confirm_trusted_live_config(
            config,
            trust_config=False,
            ci=True,
            allow_network=True,
            allow_external_script=True,
            allow_script_env=True,
        )

    with pytest.raises(ValueError, match="--allow-external-script"):
        _confirm_trusted_live_config(
            config,
            trust_config=True,
            ci=True,
            allow_network=True,
            allow_external_script=False,
            allow_script_env=True,
        )

    _confirm_trusted_live_config(
        config,
        trust_config=True,
        ci=True,
        allow_network=True,
        allow_external_script=True,
        allow_script_env=True,
    )


def test_live_runner_attaches_external_script_emergency_records(tmp_path: Path) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Return an expense decision.", encoding="utf-8")
    script = tmp_path / "bad_adapter.py"
    script.write_text(
        """
import sys

print("email jane@example.com", file=sys.stderr)
raise SystemExit(9)
""".lstrip(),
        encoding="utf-8",
    )
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(compiled))
    protocol_digest = sha256_hexdigest(protocol)
    config = LiveRunConfig(
        variant_id="external-live",
        pipeline_id="expense-live",
        tool_schema_digest="7" * 64,
        policy_bundle_digest="8" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        cases=(
            LivePromptCase(
                case_id="exp-001",
                prompt_path=prompt.name,
                input_summary="expense request",
            ),
        ),
        max_requests=1,
        max_total_cost_usd="1.000000",
        max_cost_per_observation_usd="1.000000",
        max_retries=0,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
    )

    runset = run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)

    assert len(runset.runs) == 1
    assert runset.runs[0].outcome == "runtime_error"
    assert len(runset.emergency_records) == 1
    emergency = runset.emergency_records[0]
    dumped = json.dumps(emergency.model_dump(mode="json"))
    assert emergency.failure_kind == "nonzero_exit"
    assert emergency.exit_code == 9
    assert emergency.traceparent == runset.runs[0].traceparent
    assert "jane@example.com" not in dumped
    assert "[REDACTED]" in dumped


def test_live_runner_marks_malformed_provider_output_as_structured_output_failure(
    tmp_path: Path,
) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    responses = tmp_path / "responses.jsonl"
    prompt.write_text("Return an expense decision.", encoding="utf-8")
    responses.write_text(
        '{"case_id":"exp-001","content":"not json","provider":"static","model":"model"}\n',
        encoding="utf-8",
    )
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(compiled))
    protocol_digest = sha256_hexdigest(protocol)
    config = _static_config(prompt, responses, protocol, protocol_digest)

    runset = run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)

    assert runset.runs[0].policy_results[0].reason_codes == (
        ReasonCode.STRUCTURED_OUTPUT_INVALID,
    )
    assert runset.runs[0].traceparent is not None


def test_live_prompt_digest_uses_exact_prompt_not_redacted_projection(tmp_path: Path) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    responses = tmp_path / "responses.jsonl"
    prompt_text = "patient=Jane ssn: 123-45-6789"
    prompt.write_text(prompt_text, encoding="utf-8")
    responses.write_text(
        json.dumps(
            {
                "case_id": "exp-001",
                "record": {
                    "recommendation": "approve",
                    "outcome": "approve",
                    "output_summary": "receipt-backed approval",
                },
                "provider": "static",
                "model": "model",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(compiled))
    protocol_digest = sha256_hexdigest(protocol)
    config = _static_config(prompt, responses, protocol, protocol_digest)

    runset = run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)

    assert runset.runs[0].provenance.prompt_digest == sha256_hexdigest({"prompt": prompt_text})
    assert "123-45-6789" not in json.dumps(runset.model_dump(mode="json"))


def test_static_jsonl_path_cannot_escape_config_dir(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="response_jsonl_path"):
        StaticJsonlAdapter(
            LiveAdapterConfig(
                adapter_id="static-jsonl",
                provider="static-provider",
                model="static-model",
                response_jsonl_path="../responses.jsonl",
            ),
            base_dir=tmp_path,
        )


def test_live_prompt_path_cannot_escape_config_dir(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    responses = config_dir / "responses.jsonl"
    responses.write_text(
        '{"case_id":"exp-001","content":"not json","provider":"static","model":"model"}\n',
        encoding="utf-8",
    )
    compiled = compile_suite(SUITE)
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(compiled))
    protocol_digest = sha256_hexdigest(protocol)
    config = _static_config(config_dir / "inside-prompt.txt", responses, protocol, protocol_digest)
    config = config.model_copy(
        update={
            "cases": (
                LivePromptCase(
                    case_id="exp-001",
                    prompt_path="../outside-prompt.txt",
                    input_summary="expense request",
                ),
            )
        }
    )

    with pytest.raises(ValueError, match="prompt_path"):
        run_live_suite(compiled, config, protocol=protocol, config_dir=config_dir)


def test_openai_adapter_requires_https_and_explicit_custom_host_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_TEST_KEY", "test-key")

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", fake_getaddrinfo)
    common = {
        "adapter_id": "openai-chat-completions",
        "provider": "openai",
        "model": "gpt-test",
        "api_key_env": "OPENAI_TEST_KEY",
        "allow_network": True,
    }

    with pytest.raises(ValueError, match="https"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="http://api.openai.com/v1/chat/completions",
            ),
            base_dir=tmp_path,
        )

    with pytest.raises(ValueError, match="allowed_endpoint_hosts"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="https://gateway.example.com/v1/chat/completions",
            ),
            base_dir=tmp_path,
        )

    with pytest.raises(ValueError, match="localhost, private"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="https://127.0.0.1/v1/chat/completions",
                allowed_endpoint_hosts=("127.0.0.1",),
            ),
            base_dir=tmp_path,
        )

    with pytest.raises(ValueError, match="localhost, private"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://localhost/v1/chat/completions",
            allowed_endpoint_hosts=("localhost",),
        )

    with pytest.raises(ValueError, match="bare hostnames"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://gateway.example.com/v1/chat/completions",
            allowed_endpoint_hosts=("https://gateway.example.com",),
        )

    adapter = OpenAIChatCompletionsAdapter(
        LiveAdapterConfig(
            **common,
            endpoint_url="https://gateway.example.com/v1/chat/completions",
            allowed_endpoint_hosts=("gateway.example.com",),
        ),
        base_dir=tmp_path,
    )

    assert adapter.adapter_id == "openai-chat-completions"


def test_openai_adapter_rejects_allowed_host_resolving_to_private_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_TEST_KEY", "test-key")

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("169.254.169.254", 443),
            )
        ]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="resolves to localhost, private"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                adapter_id="openai-chat-completions",
                provider="openai",
                model="gpt-test",
                api_key_env="OPENAI_TEST_KEY",
                allow_network=True,
                endpoint_url="https://gateway.example.com/v1/chat/completions",
                allowed_endpoint_hosts=("gateway.example.com",),
            ),
            base_dir=tmp_path,
        )


def test_openai_adapter_strict_resolution_rejects_unresolved_allowed_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_TEST_KEY", "test-key")

    def unresolved_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        raise OSError("resolver unavailable")

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", unresolved_getaddrinfo)
    config = LiveAdapterConfig(
        adapter_id="openai-chat-completions",
        provider="openai",
        model="gpt-test",
        api_key_env="OPENAI_TEST_KEY",
        allow_network=True,
        endpoint_url="https://gateway.example.com/v1/chat/completions",
        allowed_endpoint_hosts=("gateway.example.com",),
    )

    OpenAIChatCompletionsAdapter(config, base_dir=tmp_path)
    with pytest.raises(ValueError, match="could not be resolved"):
        OpenAIChatCompletionsAdapter(
            config,
            base_dir=tmp_path,
            require_resolvable_endpoint_host=True,
        )


def test_openai_adapter_rechecks_resolution_before_each_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_TEST_KEY", "test-key")
    responses = [
        ("93.184.216.34", 443),
        ("10.0.0.5", 443),
    ]

    def changing_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        address = responses.pop(0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", address)]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", changing_getaddrinfo)
    adapter = OpenAIChatCompletionsAdapter(
        LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="openai",
            model="gpt-test",
            api_key_env="OPENAI_TEST_KEY",
            allow_network=True,
            endpoint_url="https://gateway.example.com/v1/chat/completions",
            allowed_endpoint_hosts=("gateway.example.com",),
        ),
        base_dir=tmp_path,
        require_resolvable_endpoint_host=True,
    )

    with pytest.raises(ValueError, match="resolves to localhost, private"):
        adapter.complete(
            LiveProviderRequest(
                run_id="run-001",
                observation_id="obs-001",
                case_id="case-001",
                repetition_index=0,
                prompt="prompt",
                provider="openai",
                model="gpt-test",
            )
        )


def test_openai_adapter_redirect_handler_blocks_redirected_authorization() -> None:
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": "Bearer test-secret"},
        method="POST",
    )

    with pytest.raises(urllib.error.HTTPError, match="provider redirects are disabled"):
        _NoRedirectHandler().redirect_request(
            request,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="http://169.254.169.254/latest/meta-data/",
        )


def test_openai_provider_response_is_size_bounded() -> None:
    class OversizedResponse:
        def read(self, size: int = -1) -> bytes:
            del size
            return b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1)

    with pytest.raises(ValueError, match="provider response exceeded"):
        _read_provider_response(OversizedResponse())


def test_live_runner_records_post_response_budget_stop(tmp_path: Path) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    responses = tmp_path / "responses.jsonl"
    prompt.write_text("Return an expense decision.", encoding="utf-8")
    responses.write_text(
        json.dumps(
            {
                "case_id": "exp-001",
                "record": {
                    "recommendation": "approve",
                    "outcome": "approve",
                    "output_summary": "receipt-backed approval",
                },
                "provider": "static",
                "model": "model",
                "estimated_cost_usd": "2.000000",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    protocol = LiveProtocolRecord.model_validate(_protocol_payload(compiled))
    protocol_digest = sha256_hexdigest(protocol)
    config = _static_config(prompt, responses, protocol, protocol_digest)

    runset = run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)

    assert runset.completion_status == "incomplete"
    assert runset.stop_reasons == ("cost_budget_exceeded_after_response",)
    assert runset.runs[0].policy_results[0].reason_codes == (ReasonCode.POLICY_FAILED,)
    assert runset.runs[0].estimated_cost_usd == "2.000000"
    assert runset.runs[0].estimated_cost_source == "adapter_reported"


def test_live_runner_records_cumulative_total_token_budget_stop(tmp_path: Path) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    responses = tmp_path / "responses.jsonl"
    prompt.write_text("Return an expense decision.", encoding="utf-8")
    rows = []
    for repetition_index in range(2):
        rows.append(
            {
                "case_id": "exp-001",
                "repetition_index": repetition_index,
                "record": {
                    "recommendation": "approve",
                    "outcome": "approve",
                    "output_summary": "receipt-backed approval",
                },
                "provider": "static",
                "model": "model",
                "prompt_tokens": 12,
                "completion_tokens": 18,
                "total_tokens": 30,
                "estimated_cost_usd": "0.000000",
            }
        )
    responses.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    payload = _protocol_payload(compiled)
    payload.update(
        {
            "planned_observations": 2,
            "planned_repetitions": 2,
            "planned_observations_per_cluster": "2.000000",
            "design_effect": "1.200000",
            "planned_effective_n": "1.666667",
            "max_requests": 2,
            "max_total_tokens": 50,
        }
    )
    protocol = LiveProtocolRecord.model_validate(payload)
    protocol_digest = sha256_hexdigest(protocol)
    config = _static_config(prompt, responses, protocol, protocol_digest)

    runset = run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)

    assert runset.completion_status == "incomplete"
    assert runset.stop_reasons == ("token_budget_exceeded_after_response",)
    assert runset.runs[0].outcome == "approve"
    assert runset.runs[1].policy_results[0].reason_codes == (ReasonCode.POLICY_FAILED,)
    assert runset.runs[1].prompt_tokens == 12
    assert runset.runs[1].completion_tokens == 18
    assert runset.runs[1].total_tokens == 30


def _config(*, tokens_per_minute: int, max_output_tokens: int) -> LiveRunConfig:
    return LiveRunConfig(
        variant_id="static-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="static-jsonl",
            provider="static-provider",
            model="static-model",
            response_jsonl_path="responses.jsonl",
            max_output_tokens=max_output_tokens,
        ),
        cases=(
            LivePromptCase(
                case_id="case-001",
                prompt_path="prompt.txt",
                input_summary="summary",
            ),
        ),
        tokens_per_minute=tokens_per_minute,
    )


def _static_config(
    prompt: Path,
    responses: Path,
    protocol: LiveProtocolRecord,
    protocol_digest: str,
) -> LiveRunConfig:
    return LiveRunConfig(
        variant_id="static-live",
        pipeline_id="expense-live",
        tool_schema_digest="7" * 64,
        policy_bundle_digest="8" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="static-jsonl",
            provider="static-provider",
            model="static-model",
            response_jsonl_path=responses.name,
        ),
        cases=(
            LivePromptCase(
                case_id="exp-001",
                prompt_path=prompt.name,
                input_summary="expense request",
            ),
        ),
        repetitions=protocol.planned_repetitions or 1,
        max_requests=protocol.max_requests,
        max_total_cost_usd=protocol.max_total_cost_usd,
        max_cost_per_observation_usd=protocol.max_cost_per_observation_usd,
        max_total_tokens=protocol.max_total_tokens,
        max_generated_tokens=protocol.max_generated_tokens,
        max_retries=0,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
    )


def _protocol_payload(compiled: CompiledSuite) -> dict[str, object]:
    payload = compiled.model_dump(mode="json")
    return {
        "artifact_kind": "live-protocol-record",
        "schema_version": "0.2.0",
        "protocol_id": "protocol-external-live",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "suite_digest": sha256_hexdigest(payload),
        "baseline_mode": "concurrent_paired",
        "hypothesis_family": "governance_control_non_inferiority",
        "primary_endpoint": "expectation_pass_rate",
        "analysis_method": "paired_cluster_t_interval",
        "baseline_group_id": "overall",
        "candidate_group_id": "overall",
        "confidence_level": "0.950000",
        "non_inferiority_margin": "0.050000",
        "cluster_by": "case_id",
        "planned_observations": 1,
        "planned_clusters": 1,
        "planned_observations_per_cluster": "1.000000",
        "assumed_intraclass_correlation": "0.200000",
        "design_effect": "1.000000",
        "planned_effective_n": "1.000000",
        "sample_size_rationale": "unit test protocol fixture",
        "planned_repetitions": 1,
        "randomization_seed": 0,
        "randomization_blocking": "balanced_case_blocks",
        "max_requests": 1,
        "max_total_cost_usd": "1.000000",
        "max_cost_per_observation_usd": "1.000000",
        "max_retries": 0,
        "exclusion_policy": "only local runtime failures are captured as emergency records",
        "allowed_exclusion_reasons": [],
        "max_exclusion_rate": "0.000000",
        "provider_version_capture": ["resolved_model"],
        "stopping_rules": ["stop on sensitive persistence"],
        "tool_schema_digest": "7" * 64,
        "policy_bundle_digest": "8" * 64,
        "analysis_digest": "6" * 64,
        "approved_data_boundary": "synthetic local prompts",
        "safety_limits": ["no raw sensitive content"],
    }
