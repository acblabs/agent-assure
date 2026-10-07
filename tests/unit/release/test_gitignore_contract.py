from __future__ import annotations

from pathlib import Path


def test_agent_assure_runtime_locks_are_ignored_narrowly() -> None:
    patterns = {
        line.strip()
        for line in Path(".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert ".agent-assure-*.lock" in patterns
    assert "*.lock" not in patterns


def test_downstream_users_are_told_to_ignore_persistent_runtime_locks_narrowly() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    limitations = Path("docs/limitations.md").read_text(encoding="utf-8")

    for document in (readme, limitations):
        assert ".agent-assure-*.lock" in document
        assert "*.lock" in document
        assert "persistent" in document.lower() or "remain on disk" in document.lower()
        assert "unlink" in document.lower()
    assert "your repository's" in readme
