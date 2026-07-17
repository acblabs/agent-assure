from __future__ import annotations

import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import typer

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli.live_cmd import (
    _confirm_trusted_live_config,
    _require_resolvable_endpoint_hosts,
    _trusted_live_config_reasons,
)
from agent_assure.live.adapters import (
    MAX_PROVIDER_RESPONSE_BYTES,
    LiveProviderRequest,
    OpenAIChatCompletionsAdapter,
    StaticJsonlAdapter,
    TrustedLiveExecution,
    _NoRedirectHandler,
    _open_no_redirects,
    _read_provider_response,
)
from agent_assure.live.config import (
    LiveAdapterConfig,
    LivePromptCase,
    LiveRunConfig,
    is_disallowed_endpoint_host,
    load_live_run_config,
)
from agent_assure.live.output_contract import (
    LiveOutputContractError,
    parse_live_structured_content,
)
from agent_assure.live.paths import resolve_live_config_path
from agent_assure.live.runner import (
    _is_rate_limit_error,
    _pace_request,
    _token_reservation,
    run_live_suite,
)
from agent_assure.schema.common import MAX_SUMMARY_CHARS, ReasonCode
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


def test_live_cli_network_trust_reason_displays_only_endpoint_host() -> None:
    config = LiveRunConfig(
        variant_id="network-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="provider",
            model="model",
            endpoint_url="https://api.example.test/v1?token=do-not-display",
            allow_network=True,
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

    assert reasons == ("allow_network can send prompts and metadata to 'api.example.test'",)
    assert "do-not-display" not in reasons[0]


def test_live_cli_external_script_prompt_matches_direct_launcher_and_network_scope() -> None:
    config = LiveRunConfig(
        variant_id="external-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path="adapter.exe",
            endpoint_url="https://misleading.example.test/path?token=do-not-display",
            allow_network=True,
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

    assert "launcher='direct execution'" in reasons[0]
    assert "current Python" not in reasons[0]
    assert "arbitrary network connections" in reasons[1]
    assert "misleading.example.test" not in reasons[1]
    assert "do-not-display" not in reasons[1]


def test_live_cli_trust_reasons_redact_sensitive_configured_paths() -> None:
    secret = "Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    config = LiveRunConfig(
        variant_id="external-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=f"{secret}.py",
            script_executable=secret,
            script_env_allowlist=(secret,),
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

    assert all(secret not in reason for reason in reasons)
    assert all("[REDACTED]" in reason for reason in reasons)


def test_live_config_accepts_windows_style_script_allowlist_name() -> None:
    config = LiveAdapterConfig(
        adapter_id="external-script",
        provider="local-script",
        model="script-model",
        script_path="adapter.py",
        script_env_allowlist=("ProgramFiles(x86)",),
    )

    assert config.script_env_allowlist == ("ProgramFiles(x86)",)


def test_live_cli_interactive_trust_confirms_each_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
            script_executable="python",
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
    prompts: list[str] = []

    def approve(prompt: str, *, default: bool) -> bool:
        assert default is False
        prompts.append(prompt)
        return True

    monkeypatch.setattr(typer, "confirm", approve)

    trust = _confirm_trusted_live_config(
        config,
        trust_config=False,
        ci=False,
        allow_network=False,
        allow_external_script=False,
        allow_script_env=False,
    )

    assert trust == TrustedLiveExecution(
        allow_network=True,
        allow_external_script=True,
        allow_script_env=True,
    )
    assert len(prompts) == 3
    assert "adapter.py" in prompts[0]
    assert "network" in prompts[1]
    assert "OPENAI_API_KEY" in prompts[2]


def test_live_cli_interactive_trust_aborts_on_any_denied_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        ),
        cases=(
            LivePromptCase(
                case_id="case-001",
                prompt_path="prompt.txt",
                input_summary="summary",
            ),
        ),
    )
    answers = iter((True, False))
    prompts: list[str] = []

    def answer(prompt: str, *, default: bool) -> bool:
        assert default is False
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(typer, "confirm", answer)

    with pytest.raises(typer.Abort):
        _confirm_trusted_live_config(
            config,
            trust_config=False,
            ci=False,
            allow_network=False,
            allow_external_script=False,
            allow_script_env=False,
        )

    assert len(prompts) == 2
    assert "external-script" in prompts[0]
    assert "network" in prompts[1]


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

    trust = _confirm_trusted_live_config(
        config,
        trust_config=True,
        ci=True,
        allow_network=True,
        allow_external_script=True,
        allow_script_env=True,
    )

    assert trust.allow_network
    assert trust.allow_external_script
    assert trust.allow_script_env


def test_live_runner_requires_explicit_external_script_trust(tmp_path: Path) -> None:
    compiled = compile_suite(SUITE)
    prompt = tmp_path / "prompt.txt"
    script = tmp_path / "adapter.py"
    prompt.write_text("Return an expense decision.", encoding="utf-8")
    script.write_text("print('{}')\n", encoding="utf-8")
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

    with pytest.raises(ValueError, match="allow_external_script"):
        run_live_suite(compiled, config, protocol=protocol, config_dir=tmp_path)


def test_live_run_config_yaml_rejects_aliases_before_validation(tmp_path: Path) -> None:
    config_path = tmp_path / "live.yaml"
    config_path.write_text(
        """
variant_id: static-live
pipeline_id: pipeline
tool_schema_digest: '1111111111111111111111111111111111111111111111111111111111111111'
policy_bundle_digest: '2222222222222222222222222222222222222222222222222222222222222222'
adapter:
  adapter_id: static-jsonl
  provider: static-provider
  model: static-model
  response_jsonl_path: responses.jsonl
cases:
  - &case
    case_id: case-001
    prompt_path: prompt.txt
    input_summary: summary
  - *case
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="aliases are not supported"):
        load_live_run_config(config_path)


def test_live_cli_requires_strict_dns_for_any_configured_network_run() -> None:
    network_config = LiveRunConfig(
        variant_id="network-live",
        pipeline_id="pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
        adapter=LiveAdapterConfig(
            adapter_id="openai-chat-completions",
            provider="openai",
            model="gpt-test",
            api_key_env="OPENAI_TEST_KEY",
            endpoint_url="https://api.openai.com/v1/chat/completions",
            allow_network=True,
        ),
        cases=(
            LivePromptCase(
                case_id="case-001",
                prompt_path="prompt.txt",
                input_summary="summary",
            ),
        ),
    )
    local_config = _config(tokens_per_minute=20, max_output_tokens=7)

    assert _require_resolvable_endpoint_hosts(
        network_config,
        strict_endpoint_resolution=False,
    )
    assert _require_resolvable_endpoint_hosts(
        local_config,
        strict_endpoint_resolution=True,
    )
    assert not _require_resolvable_endpoint_hosts(
        local_config,
        strict_endpoint_resolution=False,
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

    runset = run_live_suite(
        compiled,
        config,
        protocol=protocol,
        config_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )

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

    assert runset.runs[0].policy_results[0].reason_codes == (ReasonCode.STRUCTURED_OUTPUT_INVALID,)
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


@pytest.mark.parametrize("path_value", ["", ".", "../responses.jsonl", "C:responses.jsonl"])
def test_live_config_paths_reject_empty_traversal_and_drive_relative_forms(
    tmp_path: Path,
    path_value: str,
) -> None:
    with pytest.raises(ValueError):
        resolve_live_config_path(tmp_path, path_value, field_name="response_jsonl_path")


def test_static_jsonl_rejects_duplicate_case_repetition_rows(tmp_path: Path) -> None:
    responses = tmp_path / "responses.jsonl"
    row = {
        "case_id": "exp-001",
        "repetition_index": 0,
        "content": "{}",
        "provider": "static",
        "model": "model",
    }
    responses.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for _index in range(2)) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate static response"):
        StaticJsonlAdapter(
            LiveAdapterConfig(
                adapter_id="static-jsonl",
                provider="static-provider",
                model="static-model",
                response_jsonl_path=responses.name,
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
            trust=TrustedLiveExecution(allow_network=True),
        )

    with pytest.raises(ValueError, match="allowed_endpoint_hosts"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="https://gateway.example.com/v1/chat/completions",
            ),
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_network=True),
        )

    with pytest.raises(ValueError, match="localhost, private"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="https://127.0.0.1/v1/chat/completions",
                allowed_endpoint_hosts=("127.0.0.1",),
            ),
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_network=True),
        )

    with pytest.raises(ValueError, match="localhost, private"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://localhost/v1/chat/completions",
            allowed_endpoint_hosts=("localhost",),
        )

    with pytest.raises(ValueError, match="localhost, private"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://metadata.google.internal/v1/chat/completions",
            allowed_endpoint_hosts=("metadata.google.internal",),
        )

    with pytest.raises(ValueError, match="localhost, private"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://100.100.100.200/v1/chat/completions",
            allowed_endpoint_hosts=("100.100.100.200",),
        )

    with pytest.raises(ValueError, match="bare hostnames"):
        LiveAdapterConfig(
            **common,
            endpoint_url="https://gateway.example.com/v1/chat/completions",
            allowed_endpoint_hosts=("https://gateway.example.com",),
        )

    with pytest.raises(ValueError, match="userinfo"):
        OpenAIChatCompletionsAdapter(
            LiveAdapterConfig(
                **common,
                endpoint_url="https://user:pass@gateway.example.com/v1/chat/completions",
                allowed_endpoint_hosts=("gateway.example.com",),
            ),
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_network=True),
        )

    adapter = OpenAIChatCompletionsAdapter(
        LiveAdapterConfig(
            **common,
            endpoint_url="https://gateway.example.com/v1/chat/completions",
            allowed_endpoint_hosts=("gateway.example.com",),
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_network=True),
    )

    assert adapter.adapter_id == "openai-chat-completions"


def test_endpoint_host_screening_normalizes_ipv4_mapped_addresses() -> None:
    assert is_disallowed_endpoint_host("::ffff:127.0.0.1")
    assert is_disallowed_endpoint_host("::ffff:100.100.100.200")


def test_openai_transport_disables_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class DummyOpener:
        def open(self, request: urllib.request.Request, *, timeout: int) -> object:
            captured["request"] = request
            captured["timeout"] = timeout
            return object()

    def fake_build_opener(*handlers: object) -> DummyOpener:
        captured["handlers"] = handlers
        return DummyOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    request = urllib.request.Request("https://api.openai.com/v1/chat/completions")

    _open_no_redirects(request, timeout_seconds=7)

    handlers = captured["handlers"]
    assert isinstance(handlers, tuple)
    proxy_handlers = [
        handler for handler in handlers if isinstance(handler, urllib.request.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert captured["timeout"] == 7


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
            trust=TrustedLiveExecution(allow_network=True),
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

    with pytest.raises(ValueError, match="could not be resolved"):
        OpenAIChatCompletionsAdapter(
            config,
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_network=True),
        )

    adapter = OpenAIChatCompletionsAdapter(
        config,
        base_dir=tmp_path,
        require_resolvable_endpoint_host=False,
        trust=TrustedLiveExecution(allow_network=True),
    )

    assert adapter.adapter_id == "openai-chat-completions"


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
        trust=TrustedLiveExecution(allow_network=True),
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


def test_live_structured_output_rejects_oversized_summary() -> None:
    content = json.dumps(
        {
            "recommendation": "approve",
            "outcome": "approve",
            "output_summary": "x" * (MAX_SUMMARY_CHARS + 1),
        },
        sort_keys=True,
    )

    with pytest.raises(LiveOutputContractError):
        parse_live_structured_content(content)


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
