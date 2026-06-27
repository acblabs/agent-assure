from __future__ import annotations

from pathlib import Path

import scripts.check_docs_alignment as docs_alignment


def test_forbidden_patterns_catch_affirmative_certify_claims() -> None:
    forbidden_claims = (
        "This tool can certify safety for agent pipelines.",
        "This tool certifies compliance for governed workflows.",
        "This is certification compliance for AI systems.",
    )

    for claim in forbidden_claims:
        assert any(pattern.search(claim) for pattern in docs_alignment.FORBIDDEN_POSITIVE_PATTERNS)


def test_forbidden_patterns_allow_unsupported_capability_nouns() -> None:
    unsupported_phrases = (
        "Safety certification is explicitly unsupported.",
        "Regulatory compliance certification is explicitly unsupported.",
    )

    for phrase in unsupported_phrases:
        assert not any(
            pattern.search(phrase) for pattern in docs_alignment.FORBIDDEN_POSITIVE_PATTERNS
        )


def test_live_protocol_checker_accepts_current_documents() -> None:
    assert docs_alignment._check_live_protocol() == []


def test_live_protocol_checker_rejects_empty_required_section(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path
    protocol = root / "docs" / "measurement" / "experiment_protocol.md"
    roadmap = root / "docs" / "live_mode_roadmap.md"
    protocol.parent.mkdir(parents=True)
    roadmap.parent.mkdir(parents=True, exist_ok=True)
    protocol.write_text(_protocol_with_empty_hypotheses(), encoding="utf-8")
    roadmap.write_text("See docs/measurement/experiment_protocol.md.\n", encoding="utf-8")
    monkeypatch.setattr(docs_alignment, "ROOT", root)

    failures = docs_alignment._check_live_protocol()

    assert "live statistical protocol section is too short: ## Hypotheses" in failures


def test_live_protocol_checker_rejects_missing_required_section(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path
    protocol = root / "docs" / "measurement" / "experiment_protocol.md"
    roadmap = root / "docs" / "live_mode_roadmap.md"
    protocol.parent.mkdir(parents=True)
    roadmap.parent.mkdir(parents=True, exist_ok=True)
    protocol.write_text(_protocol_without_hypotheses(), encoding="utf-8")
    roadmap.write_text("See docs/measurement/experiment_protocol.md.\n", encoding="utf-8")
    monkeypatch.setattr(docs_alignment, "ROOT", root)

    failures = docs_alignment._check_live_protocol()

    assert "live statistical protocol missing section: ## Hypotheses" in failures


def test_markdown_section_content_ignores_headings_inside_fenced_code() -> None:
    text = """# Document

## Scope

Text before the fence.

```text
## Not A Section
This line belongs to the Scope section.
```

Text after the fence.

## Hypotheses

The next real section.
"""

    content = docs_alignment._markdown_section_content(text, "## Scope")

    assert content is not None
    assert "## Not A Section" in content
    assert "Text after the fence." in content
    assert "The next real section." not in content


def _protocol_with_empty_hypotheses() -> str:
    return _protocol_fixture(hypotheses_content="")


def _protocol_without_hypotheses() -> str:
    return _protocol_fixture(omit_hypotheses=True)


def _protocol_fixture(
    *,
    hypotheses_content: str | None = None,
    omit_hypotheses: bool = False,
) -> str:
    full_section = (
        "This section has enough concrete text to satisfy the documentation "
        "alignment content guard in the unit test protocol fixture."
    )
    sections = []
    for heading in docs_alignment.REQUIRED_LIVE_PROTOCOL_SECTIONS:
        if heading == "## Hypotheses" and omit_hypotheses:
            continue
        content = (
            hypotheses_content
            if heading == "## Hypotheses" and hypotheses_content is not None
            else full_section
        )
        sections.append(f"{heading}\n\n{content}")
    header = "# Experiment Protocol\n\nProtocol status: pre-live statistical protocol.\n\n"
    return header + "\n\n".join(sections)
