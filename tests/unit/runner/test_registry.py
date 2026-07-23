from __future__ import annotations

import pytest

from agent_assure.runner import registry


def _runner(*args: object) -> object:
    return object()


def _replacement_runner(*args: object) -> object:
    return object()


def test_runner_registration_cannot_silently_replace_an_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "_RUNNER_REGISTRY", {})
    monkeypatch.setattr(registry, "_BUILTINS_REGISTERED", True)

    registry.register_runner("test.runner", _runner)  # type: ignore[arg-type]
    registry.register_runner("test.runner", _runner)  # idempotent exact registration

    with pytest.raises(ValueError, match="already registered"):
        registry.register_runner("test.runner", _replacement_runner)  # type: ignore[arg-type]

    assert registry.get_runner("test.runner") is _runner


@pytest.mark.parametrize("runner_id", ["", "../runner", "runner id", "x" * 129])
def test_runner_registration_rejects_unsafe_ids(
    monkeypatch: pytest.MonkeyPatch,
    runner_id: str,
) -> None:
    monkeypatch.setattr(registry, "_RUNNER_REGISTRY", {})
    monkeypatch.setattr(registry, "_BUILTINS_REGISTERED", True)

    with pytest.raises(ValueError, match="machine identifier"):
        registry.register_runner(runner_id, _runner)  # type: ignore[arg-type]
