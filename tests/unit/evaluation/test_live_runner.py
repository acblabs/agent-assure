from __future__ import annotations

import pytest

from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.live.runner import _is_rate_limit_error, _pace_request, _token_reservation


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
