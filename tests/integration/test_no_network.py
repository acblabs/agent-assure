from __future__ import annotations

import socket

from agent_assure.authoring.compiler import compile_suite


def test_compile_does_not_open_socket(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    compiled = compile_suite(__import__("pathlib").Path("examples/prior_auth_synthetic/suite.yaml"))
    assert compiled.suite_id
