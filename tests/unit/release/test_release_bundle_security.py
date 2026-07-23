from __future__ import annotations

from pathlib import Path

import pytest

import scripts.build_release_bundle as release_bundle
from scripts.build_release_bundle import _validated_distribution_paths


def test_release_bundle_distribution_set_is_exact(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.6.0-py3-none-any.whl"
    sdist = tmp_path / "agent_assure-0.6.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    assert _validated_distribution_paths(tmp_path) == tuple(
        sorted((wheel, sdist), key=lambda path: path.name)
    )

    (tmp_path / "unexpected.zip").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="unexpected=unexpected.zip"):
        _validated_distribution_paths(tmp_path)


def test_release_bundle_clean_source_check_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release_bundle, "git_output", lambda *_args, **_kwargs: None)
    assert not release_bundle._require_clean_source("before test")

    monkeypatch.setattr(
        release_bundle,
        "git_output",
        lambda *_args, **_kwargs: " M src/agent_assure/release_evidence.py",
    )
    assert not release_bundle._require_clean_source("after test")

    monkeypatch.setattr(release_bundle, "git_output", lambda *_args, **_kwargs: "")
    assert release_bundle._require_clean_source("after test")
