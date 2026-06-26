from __future__ import annotations

import socket
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")


def test_pytest_socket_blocks_socket_creation() -> None:
    with pytest.warns(UserWarning, match="A test tried to use socket.socket"):
        with pytest.raises(SocketBlockedError):
            socket.socket()


def test_compile_does_not_open_socket(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    compiled = compile_suite(SUITE)
    assert compiled.suite_id


def test_fixture_run_does_not_open_socket(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    assert len(runset.runs) == 6
