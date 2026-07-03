from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.check_docs_alignment as docs_alignment  # noqa: E402


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


def test_deprecated_report_terminology_checker_rejects_current_docs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_diff = tmp_path / "docs" / "evidence_diff.md"
    evidence_diff.parent.mkdir(parents=True)
    evidence_diff.write_text(
        "The page shows final-output equivalence and process evidence.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_deprecated_report_terminology()

    assert failures == [
        "deprecated report terminology in docs/evidence_diff.md: "
        "\\bfinal[- ]output equivalence\\b"
    ]


def test_deprecated_report_terminology_checker_allows_current_docs() -> None:
    assert docs_alignment._check_deprecated_report_terminology() == []


def test_live_protocol_checker_accepts_current_documents() -> None:
    assert docs_alignment._check_live_protocol() == []


def test_flagship_readme_diagram_checker_accepts_current_diagram() -> None:
    assert docs_alignment._check_flagship_readme_diagram() == []


def test_flagship_readme_diagram_required_snippets_use_showcase_facts() -> None:
    snippets = docs_alignment._flagship_readme_diagram_required_snippets()

    assert "Baseline output<br/>recommendation=approve<br/>outcome=approve" in snippets
    assert "Candidate output<br/>recommendation=approve<br/>outcome=approve" in snippets
    assert "Baseline evidence<br/>claim-duration linked" in snippets
    assert "Candidate evidence<br/>claim-duration missing link" in snippets


def test_flagship_readme_diagram_checker_rejects_inverted_equivalence_edge(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        _readme_with_flagship_diagram(_inverted_flagship_diagram()),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)
    monkeypatch.setattr(
        docs_alignment,
        "_flagship_readme_diagram_required_snippets",
        _canned_flagship_snippets,
    )

    failures = docs_alignment._check_flagship_readme_diagram()

    assert any("missing expected causal edge" in failure for failure in failures)
    assert any("must show fixture equivalence gating comparison" in failure for failure in failures)


def test_flagship_readme_diagram_checker_rejects_stale_flagship_fact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        _readme_with_flagship_diagram(
            _valid_flagship_diagram().replace(
                "MATERIAL_CLAIM_MISSING_EVIDENCE",
                "EXPECTED_OUTCOME_MISMATCH",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)
    monkeypatch.setattr(
        docs_alignment,
        "_flagship_readme_diagram_required_snippets",
        _canned_flagship_snippets,
    )

    failures = docs_alignment._check_flagship_readme_diagram()

    assert (
        "README.md flagship diagram missing expected fact: "
        "MATERIAL_CLAIM_MISSING_EVIDENCE"
    ) in failures


def test_flagship_readme_diagram_checker_rejects_missing_section(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# Agent Assure\n\n## Architecture\n", encoding="utf-8")
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_flagship_readme_diagram()

    assert failures == ["README.md missing flagship regression diagram section"]


def test_flagship_readme_diagram_checker_rejects_missing_mermaid_block(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Agent Assure\n\n"
        "### Flagship regression at a glance\n\n"
        "The diagram belongs here.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)

    failures = docs_alignment._check_flagship_readme_diagram()

    assert failures == ["README.md flagship regression section missing mermaid diagram"]


def test_flagship_readme_diagram_checker_ignores_fenced_heading_markers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        _readme_with_flagship_diagram(
            _valid_flagship_diagram(),
            section_prefix="```bash\n# Not a Markdown heading\n```\n\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)
    monkeypatch.setattr(
        docs_alignment,
        "_flagship_readme_diagram_required_snippets",
        _canned_flagship_snippets,
    )

    assert docs_alignment._check_flagship_readme_diagram() == []


def test_flagship_readme_diagram_checker_allows_equivocate_node_name(
    tmp_path: Path,
    monkeypatch,
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        _readme_with_flagship_diagram(
            _valid_flagship_diagram()
            + '    Compare --> Equivocate["Unrelated explanatory node"]\n'
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(docs_alignment, "ROOT", tmp_path)
    monkeypatch.setattr(
        docs_alignment,
        "_flagship_readme_diagram_required_snippets",
        _canned_flagship_snippets,
    )

    assert docs_alignment._check_flagship_readme_diagram() == []


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


def _readme_with_flagship_diagram(diagram: str, *, section_prefix: str = "") -> str:
    return f"""# Agent Assure

## What the demo shows

### Flagship regression at a glance

{section_prefix}
```mermaid
{diagram}
```

## Architecture
"""


def _canned_flagship_snippets() -> tuple[str, ...]:
    return (
        "Baseline output<br/>recommendation=approve<br/>outcome=approve",
        "Candidate output<br/>recommendation=approve<br/>outcome=approve",
        "Visible answer unchanged",
        "Baseline evidence<br/>claim-duration linked",
        "Candidate evidence<br/>claim-duration missing link",
        "Baseline evaluation: pass",
        "Candidate evaluation: fail",
        "MATERIAL_CLAIM_MISSING_EVIDENCE",
        "Output unchanged<br/>but governance invariant regressed",
        "Classification: new_failure",
        "Fixture equivalence: pass",
    )


def _valid_flagship_diagram() -> str:
    return """flowchart LR
    subgraph OutputCheck["Ordinary visible-output check"]
        BOut["Baseline output<br/>recommendation=approve<br/>outcome=approve"]
        COut["Candidate output<br/>recommendation=approve<br/>outcome=approve"]
        Same["Visible answer unchanged"]
        BOut --> Same
        COut --> Same
    end

    subgraph InvariantCheck["agent-assure invariant check"]
        BEv["Baseline evidence<br/>claim-duration linked"]
        CEv["Candidate evidence<br/>claim-duration missing link"]
        Pass["Baseline evaluation: pass"]
        Fail["Candidate evaluation: fail<br/>MATERIAL_CLAIM_MISSING_EVIDENCE"]
        BEv --> Pass
        CEv --> Fail
    end

    Same --> Tension["Output unchanged<br/>but governance invariant regressed"]
    Equiv["Fixture equivalence: pass"] --> Compare["Baseline-to-candidate comparison"]
    Pass --> Compare
    Fail --> Compare
    Tension --> Compare

    Compare --> NewFailure["Classification: new_failure"]
"""


def _inverted_flagship_diagram() -> str:
    return _valid_flagship_diagram().replace(
        'Equiv["Fixture equivalence: pass"] --> Compare["Baseline-to-candidate comparison"]',
        'Compare --> Equiv["Fixture equivalence: pass"]',
    )


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
    header = "# Experiment Protocol\n\nProtocol status: live statistical protocol.\n\n"
    return header + "\n\n".join(sections)
