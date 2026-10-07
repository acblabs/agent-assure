from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.release_metadata import (
    check_citation_release,
    check_readme_action_source,
    check_readme_release,
    parse_changelog,
    require_latest_release,
)

ROOT = Path(__file__).resolve().parents[3]


def test_canonical_changelog_establishes_unique_latest_release() -> None:
    changelog = parse_changelog(_canonical_changelog(), source="CHANGELOG.md")

    latest = require_latest_release(
        changelog,
        expected_version="1.2.3",
        source="CHANGELOG.md",
    )

    assert latest.version == "1.2.3"
    assert latest.date_text == "2026-10-06"
    assert [release.version for release in changelog.releases] == ["1.2.3", "1.2.2"]


def test_lower_newer_heading_cannot_satisfy_latest_release_binding() -> None:
    text = "# Changelog\n\n## Unreleased\n\n## 1.2.2 - 2026-10-05\n\n## 1.2.3 - 2026-10-06\n"

    with pytest.raises(ValueError, match="strictly descending SemVer order"):
        parse_changelog(text)


def test_body_substring_cannot_satisfy_latest_release_binding() -> None:
    text = _canonical_changelog(latest_version="1.2.2").replace(
        "## Unreleased\n",
        "## Unreleased\n\nBody text containing ## 1.2.3 - 2026-10-06.\n",
    )
    changelog = parse_changelog(text)

    with pytest.raises(ValueError, match="latest dated release '1.2.2'"):
        require_latest_release(changelog, expected_version="1.2.3")


@pytest.mark.parametrize("fence", ("```", "~~~"))
def test_fenced_heading_cannot_satisfy_latest_release_binding(fence: str) -> None:
    text = _canonical_changelog(latest_version="1.2.2").replace(
        "## Unreleased\n",
        f"## Unreleased\n\n{fence}markdown\n## 1.2.3 - 2026-10-06\n{fence}\n",
    )
    changelog = parse_changelog(text)

    with pytest.raises(ValueError, match="latest dated release '1.2.2'"):
        require_latest_release(changelog, expected_version="1.2.3")


def test_html_comment_heading_cannot_satisfy_latest_release_binding() -> None:
    text = _canonical_changelog(latest_version="1.2.2").replace(
        "## Unreleased\n",
        "## Unreleased\n\n<!--\n## 1.2.3 - 2026-10-06\n-->\n",
    )

    with pytest.raises(ValueError, match="must not contain HTML comments"):
        parse_changelog(text)


def test_inline_html_comment_cannot_synthesize_a_release_heading() -> None:
    text = _canonical_changelog(latest_version="1.2.2").replace(
        "## Unreleased\n",
        "## Unreleased\n\n<!--hidden-->## 1.2.3 - 2026-10-06\n",
    )

    with pytest.raises(ValueError, match="must not contain HTML comments"):
        parse_changelog(text)


def test_unterminated_html_comment_fails_closed() -> None:
    text = _canonical_changelog() + "\n<!-- unterminated\n"

    with pytest.raises(ValueError, match="must not contain HTML comments"):
        parse_changelog(text)


@pytest.mark.parametrize("tag", ("script", "pre", "div"))
def test_raw_html_block_cannot_supply_a_release_heading(tag: str) -> None:
    text = _canonical_changelog(latest_version="1.2.2").replace(
        "## Unreleased\n",
        f"## Unreleased\n\n<{tag}>\n## 1.2.3 - 2026-10-06\n</{tag}>\n",
    )

    with pytest.raises(ValueError, match="contains raw HTML"):
        parse_changelog(text)


@pytest.mark.parametrize(
    "raw_html",
    (
        "Body <div hidden>",
        "> <details>",
        "- <section>",
        "Body <?hide",
        "Body <!BOGUS",
        "Body -->",
        "Body --!>",
    ),
)
def test_inline_or_prefixed_raw_html_cannot_hide_release_heading(raw_html: str) -> None:
    text = _canonical_changelog().replace(
        "## 1.2.3 - 2026-10-06",
        f"{raw_html}\n## 1.2.3 - 2026-10-06",
    )

    with pytest.raises(ValueError, match="contains raw HTML"):
        parse_changelog(text)


def test_raw_html_example_inside_valid_changelog_fence_is_ignored() -> None:
    text = _canonical_changelog().replace(
        "## Unreleased\n",
        "## Unreleased\n\n```html\n<div hidden>example</div>\nBody --!>\n```\n",
    )

    assert parse_changelog(text).latest_release.version == "1.2.3"


def test_invalid_backtick_info_string_does_not_hide_real_release_heading() -> None:
    text = _canonical_changelog().replace(
        "## Unreleased\n",
        "## Unreleased\n\n```bad`info\n",
    )

    changelog = parse_changelog(text)

    assert changelog.latest_release.version == "1.2.3"


def test_unterminated_valid_markdown_fence_fails_closed() -> None:
    text = _canonical_changelog() + "\n```markdown\nnot closed\n"

    with pytest.raises(ValueError, match="unterminated Markdown fence"):
        parse_changelog(text)


def test_duplicate_release_version_is_rejected() -> None:
    text = _canonical_changelog() + "\n## 1.2.3 - 2026-10-04\n"

    with pytest.raises(ValueError, match="duplicate release version '1.2.3'"):
        parse_changelog(text)


def test_duplicate_unreleased_heading_is_rejected() -> None:
    text = _canonical_changelog() + "\n## Unreleased\n"

    with pytest.raises(ValueError, match="exactly one exact non-fenced"):
        parse_changelog(text)


def test_invalid_calendar_date_is_rejected() -> None:
    text = _canonical_changelog().replace("2026-10-06", "2026-02-30")

    with pytest.raises(ValueError, match="invalid ISO date '2026-02-30'"):
        parse_changelog(text)


def test_release_date_order_must_descend_with_version_order() -> None:
    text = _canonical_changelog().replace("1.2.2 - 2026-10-05", "1.2.2 - 2026-10-07")

    with pytest.raises(ValueError, match="release dates must be in descending order"):
        parse_changelog(text)


def test_noncanonical_h2_release_heading_is_rejected() -> None:
    text = _canonical_changelog().replace(
        "## 1.2.3 - 2026-10-06",
        "## 1.2.3 - 2026-10-06 trailing",
    )

    with pytest.raises(ValueError, match="noncanonical H2 heading"):
        parse_changelog(text)


def test_citation_and_readme_are_bound_to_same_changelog_identity() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    citation = "version: 1.2.2\ndate-released: 2026-10-05\n"
    readme = _canonical_readme(
        package_version="1.2.2",
        action_version="1.2.2",
    )

    assert check_citation_release(citation, expected=latest) == [
        "CITATION.cff version '1.2.2' does not match latest released version '1.2.3'",
        "CITATION.cff date-released '2026-10-05' does not match latest release date '2026-10-06'",
    ]
    assert check_readme_release(readme, expected=latest) == [
        "README.md package pin '1.2.2' does not match latest released version '1.2.3'",
        "README.md action version comment '1.2.2' does not match latest released version '1.2.3'",
    ]


def test_duplicate_citation_keys_cannot_hide_conflicting_release_metadata() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    citation = (
        "version: 1.2.3\nversion: 1.2.2\ndate-released: 2026-10-06\ndate-released: 2026-10-05\n"
    )

    assert check_citation_release(citation, expected=latest) == [
        "CITATION.cff:2 duplicates top-level key 'version' first declared at line 1",
        "CITATION.cff:4 duplicates top-level key 'date-released' first declared at line 3",
        "CITATION.cff must declare exactly one version",
        "CITATION.cff must declare exactly one date-released",
    ]


@pytest.mark.parametrize(
    "ambiguous_entry",
    (
        "version : 9.9.9",
        '"version": 9.9.9',
        '"ver\\u0073ion": 9.9.9',
        "? version\n: 9.9.9",
        "<<: *release-metadata",
        "---",
        "{version: 9.9.9}",
    ),
)
def test_citation_rejects_ambiguous_top_level_yaml_keys(ambiguous_entry: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    citation = f"version: 1.2.3\ndate-released: 2026-10-06\n{ambiguous_entry}\n"

    failures = check_citation_release(citation, expected=latest)

    assert any(
        "top-level CFF entry must use canonical" in failure
        or "must not use YAML flow collections" in failure
        for failure in failures
    )


def test_citation_rejects_duplicate_nonrelease_top_level_key() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    citation = "title: first\ntitle: second\nversion: 1.2.3\ndate-released: 2026-10-06\n"

    failures = check_citation_release(citation, expected=latest)

    assert failures == ["CITATION.cff:2 duplicates top-level key 'title' first declared at line 1"]


def test_citation_rejects_tabs_even_in_nested_content() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    citation = "authors:\n\t- name: ambiguous\nversion: 1.2.3\ndate-released: 2026-10-06\n"

    failures = check_citation_release(citation, expected=latest)

    assert failures == ["CITATION.cff:2 must not contain tab characters"]


@pytest.mark.parametrize(
    ("citation", "expected_failure"),
    (
        (
            "version: 1.2.3#not-a-comment\ndate-released: 2026-10-06\n",
            "CITATION.cff must declare a canonical stable X.Y.Z version",
        ),
        (
            "version: 1.2.3\ndate-released: 2026-10-06#not-a-comment\n",
            "CITATION.cff must declare a canonical YYYY-MM-DD date-released",
        ),
    ),
)
def test_citation_comment_marker_requires_separating_whitespace(
    citation: str,
    expected_failure: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release

    assert check_citation_release(citation, expected=latest) == [expected_failure]


@pytest.mark.parametrize(
    "absorbing_value",
    (
        'title: "absorbs\nversion: 1.2.3\ndate-released: 2026-10-06\n  both"',
        "authors:\n  - name: 'absorbs\nversion: 1.2.3\ndate-released: 2026-10-06\n    both'",
        "title: [absorbs\nversion: 1.2.3\ndate-released: 2026-10-06\n]",
    ),
)
def test_citation_physical_release_keys_cannot_be_absorbed_by_multiline_yaml(
    absorbing_value: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release

    failures = check_citation_release(absorbing_value + "\n", expected=latest)

    assert failures
    assert any(
        "multiline quoted YAML scalars" in failure or "YAML flow collections" in failure
        for failure in failures
    )


@pytest.mark.parametrize(
    "suffix",
    ("+local", "-suffix", "_suffix", "rc1", ".post1", ".dev1"),
)
def test_readme_package_pin_rejects_pep440_and_token_suffixes(suffix: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme(package_version=f"1.2.3{suffix}")

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        f"README.md package pin '1.2.3{suffix}' must be an exact stable X.Y.Z requirement"
    ]


def test_readme_package_pin_rejects_prefixed_distribution_near_miss() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme(package_name="evil-agent-assure")

    assert check_readme_release(readme, expected=latest) == [
        "README.md must pin the published agent-assure package version"
    ]


def test_readme_release_pins_inside_html_comment_are_rejected() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = "<!--\n" + _canonical_readme() + "-->\n"

    assert check_readme_release(readme, expected=latest) == [
        "README.md:1 must not contain HTML comments; release pins must remain human-visible"
    ]


@pytest.mark.parametrize(
    "wrapper",
    (
        "<?hide\n{readme}\n?>",
        "<![CDATA[\n{readme}\n]]>",
        "<!BOGUS\n{readme}\n>",
        "-->\n{readme}",
    ),
)
def test_readme_declarations_cannot_hide_canonical_release_block(wrapper: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = wrapper.format(readme=_canonical_readme())

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert "release pins must remain human-visible" in failures[0]


def test_readme_html_markers_inside_valid_fence_are_ignored() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = "```html\n<!-- <?hide ]]> -->\n```\n\n" + _canonical_readme()

    assert check_readme_release(readme, expected=latest) == []


@pytest.mark.parametrize("tag", ("script", "style", "template"))
def test_readme_release_pins_inside_hidden_html_blocks_are_rejected(tag: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = f'<{tag} type="text/plain">\n' + _canonical_readme() + f"</{tag}>\n"

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert f"must not contain raw HTML <{tag}>" in failures[0]


def test_readme_unterminated_hidden_html_block_fails_closed() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = '<script type="text/plain">\n' + _canonical_readme()

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert "must not contain raw HTML <script>" in failures[0]


def test_readme_rejects_closed_style_block_before_canonical_section() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = "<style>.release { display: none }</style>\n" + _canonical_readme()

    assert check_readme_release(readme, expected=latest) == [
        "README.md:1 must not contain raw HTML <style>; release pins must remain human-visible"
    ]


def test_readme_rejects_external_stylesheet_before_canonical_section() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = '<link href="hidden.css" rel="alternate stylesheet">\n' + _canonical_readme()

    assert check_readme_release(readme, expected=latest) == [
        "README.md:1 must not contain a stylesheet link; release pins must remain human-visible"
    ]


def test_readme_rejects_release_pins_in_body_instead_of_canonical_fence() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = (
        "pip install agent-assure==1.2.3\n"
        "# agent-assure v1.2.3\n"
        f"- uses: acblabs/agent-assure/.github/actions/agent-assure@{'a' * 40}\n\n"
        + _canonical_readme(block_content="name: no-release-pins")
    )

    failures = check_readme_release(readme, expected=latest)

    assert "README.md must pin the published agent-assure package version" in failures
    assert any("full commit SHA" in failure for failure in failures)


def test_readme_rejects_duplicate_release_pins_outside_canonical_fence() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme() + (
        "\npip install agent-assure==1.2.3\n"
        "# agent-assure v1.2.3\n"
        f"- uses: acblabs/agent-assure/.github/actions/agent-assure@{'a' * 40}\n"
    )

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md must not contain composite-action references outside the canonical "
        "release-workflow YAML block",
    ]


@pytest.mark.parametrize(
    "outside_requirement",
    (
        "pip install Agent_Assure==9.9.9",
        "python -m pip install agent.assure [extra]",
        "pip3 install AGENT___ASSURE[security]",
        "agent_assure ~= 9.9",
        "agent.assure @ https://example.invalid/archive.whl",
        "agent-assure==1.2.3,!=1.2.3",
        "agent-assure==1.2.3 , <=0",
        'agent-assure==1.2.3; python_version < "3.12"',
    ),
)
def test_readme_rejects_normalized_package_requirements_outside_canonical_block(
    outside_requirement: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme() + f"\n{outside_requirement}\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md must use exact requirement 'agent-assure==1.2.3' for every agent-assure "
        "installation reference"
    ]


def test_readme_allows_exact_duplicate_package_requirement_outside_canonical_block() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme() + "\npip install agent-assure==1.2.3  # quickstart\n"

    assert check_readme_release(readme, expected=latest) == []


@pytest.mark.parametrize(
    "outside_action",
    (
        "acblabs/agent-assure/.github/actions/agent-assure@main",
        "ACBLABS/AGENT-ASSURE/.GITHUB/ACTIONS/AGENT-ASSURE@v9.9.9",
        f"acblabs/agent-assure/.github/actions/agent-assure@{'b' * 40}",
    ),
)
def test_readme_rejects_every_action_reference_outside_canonical_block(
    outside_action: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme() + f"\n- uses: {outside_action}\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md must not contain composite-action references outside the canonical "
        "release-workflow YAML block"
    ]


@pytest.mark.parametrize("line_break", ("\n", "\r\n", "\r", "\x85", "\u2028", "\u2029"))
def test_readme_rejects_action_refs_split_across_yaml_line_breaks(
    line_break: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    continued_ref = f'"acblabs/agent-assure/.github/actions/agent-assure@\\{line_break}  v0.1.0"'
    readme = _canonical_readme() + f"\n- uses: {continued_ref}\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md must not contain composite-action references outside the canonical "
        "release-workflow YAML block"
    ]


@pytest.mark.parametrize("line_break", ("\n", "\r\n", "\r", "\x85", "\u2028", "\u2029"))
def test_readme_rejects_package_requirements_split_across_line_breaks(
    line_break: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    continued_requirement = f"agent-assure \\{line_break}  ==0.1.0"
    readme = _canonical_readme() + f"\n{continued_requirement}\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md must use exact requirement 'agent-assure==1.2.3' for every agent-assure "
        "installation reference"
    ]


def test_readme_canonical_action_path_is_not_misread_as_package_direct_reference() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release

    assert check_readme_release(_canonical_readme(), expected=latest) == []


def test_readme_rejects_additional_normalized_requirement_inside_canonical_block() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme(
        block_content=_release_pin_lines() + "\n- run: pip install Agent_Assure",
    )

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md canonical release-workflow YAML block must contain exactly one "
        "PEP 503-normalized agent-assure requirement"
    ]


def test_readme_rejects_release_pins_in_another_fenced_block() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme(block_content="name: no-release-pins") + (
        "\n### Another example\n\n```yaml\n"
        "- run: pip install agent-assure==1.2.3\n"
        "# agent-assure v1.2.3\n"
        f"- uses: acblabs/agent-assure/.github/actions/agent-assure@{'a' * 40}\n"
        "```\n"
    )

    failures = check_readme_release(readme, expected=latest)

    assert "README.md must pin the published agent-assure package version" in failures
    assert any("full commit SHA" in failure for failure in failures)


def test_readme_rejects_malformed_fence_around_release_pins() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    content = _release_pin_lines()
    readme = f"### GitHub Actions example using the bundled fixture\n\n```bad`info\n{content}\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md canonical release-workflow section must contain exactly one valid "
        "CommonMark fence with info string 'yaml'"
    ]


def test_readme_rejects_unterminated_canonical_yaml_fence() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = (
        f"### GitHub Actions example using the bundled fixture\n\n```yaml\n{_release_pin_lines()}\n"
    )

    failures = check_readme_release(readme, expected=latest)

    assert failures == ["README.md:3 contains an unterminated Markdown fence"]


@pytest.mark.parametrize(
    "wrapper",
    (
        "<div hidden>",
        '<div style="display:none">',
        '<div style="height:0;overflow:hidden">',
        "<article hidden>",
    ),
)
def test_readme_canonical_heading_must_not_be_inside_hidden_container(
    wrapper: str,
) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    tag = wrapper.removeprefix("<").split(maxsplit=1)[0].rstrip(">")
    readme = wrapper + "\n" + _canonical_readme() + f"</{tag}>\n"

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert f"unsupported raw HTML <{tag}>" in failures[0]


def test_readme_canonical_heading_must_not_be_inside_allowed_container() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = "<details>\n" + _canonical_readme() + "</details>\n"

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert "not nested in raw HTML <details>" in failures[0]


def test_readme_html_scanner_accepts_balanced_markup_autolinks_and_fenced_tags() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = (
        '<p align="center"><a href="#release"><strong>Release</strong></a></p>\n'
        '<img src="asset.svg"\n     alt="multiline image"\n     width="100%">\n'
        "<https://example.invalid> <release@example.invalid>\n"
        "```html\n<script hidden>fenced example</script>\n```\n\n" + _canonical_readme()
    )

    assert check_readme_release(readme, expected=latest) == []


def test_readme_html_scanner_rejects_mismatched_generic_containers() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = "<details><strong>text</details></strong>\n" + _canonical_readme()

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        "README.md:1 has mismatched closing HTML tag </details>; expected </strong>"
    ]


def test_readme_html_scanner_rejects_unterminated_multiline_tag() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme() + "\n<img\n  src='asset.svg'\n"

    failures = check_readme_release(readme, expected=latest)

    assert failures == ["README.md:13 contains unterminated raw HTML tag"]


@pytest.mark.parametrize("tag", ("details", "p", "strong"))
def test_readme_rejects_self_closing_nonvoid_html_wrapper(tag: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = f"<{tag}/>\n" + _canonical_readme()

    failures = check_readme_release(readme, expected=latest)

    assert failures == [
        f"README.md:1 must not use self-closing syntax for non-void HTML element <{tag}>"
    ]


def test_readme_rejects_fixed_overlay_before_canonical_section() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = (
        '<div style="position:fixed;inset:0;background:white">overlay</div>\n' + _canonical_readme()
    )

    assert check_readme_release(readme, expected=latest) == [
        "README.md:1 contains unsupported raw HTML <div>; release pins must remain human-visible"
    ]


def test_readme_rejects_meta_refresh_before_canonical_section() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = (
        '<meta http-equiv="refresh" content="0;url=https://example.invalid">\n'
        + _canonical_readme()
    )

    assert check_readme_release(readme, expected=latest) == [
        "README.md:1 contains unsupported raw HTML <meta>; release pins must remain human-visible"
    ]


@pytest.mark.parametrize(
    "attribute", ("hidden", 'style="display:none"', 'class="d-none"', "onload=x")
)
def test_readme_rejects_visibility_active_attributes_on_allowed_html(attribute: str) -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = f"<p {attribute}>visible</p>\n" + _canonical_readme()

    failures = check_readme_release(readme, expected=latest)

    assert len(failures) == 1
    assert "must not use visibility-active attribute" in failures[0]


def test_readme_rejects_pin_split_across_fence_boundary() -> None:
    latest = parse_changelog(_canonical_changelog()).latest_release
    readme = _canonical_readme(
        block_content="- run: pip install agent-assure==1.2.3",
    ) + (
        "\n# agent-assure v1.2.3\n"
        f"- uses: acblabs/agent-assure/.github/actions/agent-assure@{'a' * 40}\n"
    )

    failures = check_readme_release(readme, expected=latest)

    assert any("full commit SHA" in failure for failure in failures)


def test_release_workflow_uses_structural_stable_preflight_not_changelog_grep() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert 'check_version_matches_tag.py "${release_tag}" --require-stable' in workflow
    assert "grep" not in "\n".join(line for line in workflow.splitlines() if "CHANGELOG.md" in line)
    assert 'grep -Fq "## ${version} -"' not in workflow


def test_docs_workflow_fetches_release_tags_for_action_source_binding() -> None:
    workflow = (ROOT / ".github" / "workflows" / "docs.yml").read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow


def test_release_runbook_requires_action_freeze_then_final_collateral_commit() -> None:
    runbook = (ROOT / "docs" / "release_pypi.md").read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    assert "action-freeze commit" in normalized
    assert "descendant **final collateral commit**" in normalized
    assert "does not modify that action tree" in normalized
    assert "README action pin must name the action-freeze commit" in normalized
    assert "compares the exact Git tree OID" in normalized
    assert "non-ancestry, tree divergence, and Git inspection errors all fail closed" in normalized


def test_readme_action_source_accepts_reviewed_freeze_commit_before_tag(
    tmp_path: Path,
) -> None:
    freeze_commit = _initialize_action_freeze_repository(tmp_path)
    _commit_file(tmp_path, "release-collateral.txt", "final\n", "final collateral")

    assert (
        check_readme_action_source(
            tmp_path,
            release_version="1.2.3",
            pinned_commit=freeze_commit,
        )
        == []
    )


def test_readme_action_source_uses_existing_release_tag_as_target(tmp_path: Path) -> None:
    freeze_commit = _initialize_action_freeze_repository(tmp_path)
    _commit_file(tmp_path, "release-collateral.txt", "final\n", "final collateral")
    _git(tmp_path, "tag", "v1.2.3")
    _commit_file(
        tmp_path,
        ".github/actions/agent-assure/action.yml",
        "name: changed-after-release\n",
        "post-release action change",
    )

    assert (
        check_readme_action_source(
            tmp_path,
            release_version="1.2.3",
            pinned_commit=freeze_commit,
        )
        == []
    )


def test_readme_action_source_rejects_divergent_release_action_tree(
    tmp_path: Path,
) -> None:
    freeze_commit = _initialize_action_freeze_repository(tmp_path)
    _commit_file(
        tmp_path,
        ".github/actions/agent-assure/action.yml",
        "name: divergent\n",
        "diverge action",
    )

    failures = check_readme_action_source(
        tmp_path,
        release_version="1.2.3",
        pinned_commit=freeze_commit,
    )

    assert len(failures) == 1
    assert "does not match release-preparation HEAD action tree" in failures[0]


def test_readme_action_source_rejects_nonancestor_commit(tmp_path: Path) -> None:
    _initialize_action_freeze_repository(tmp_path)
    base_commit = _git_stdout(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "-b", "pin-branch")
    _commit_file(tmp_path, "pin.txt", "pin\n", "pin branch")
    nonancestor_pin = _git_stdout(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "main")
    assert _git_stdout(tmp_path, "rev-parse", "HEAD") == base_commit
    _commit_file(tmp_path, "target.txt", "target\n", "target branch")

    failures = check_readme_action_source(
        tmp_path,
        release_version="1.2.3",
        pinned_commit=nonancestor_pin,
    )

    assert len(failures) == 1
    assert "is not an ancestor of release-preparation HEAD" in failures[0]


def test_readme_action_source_rejects_noncommit_object(tmp_path: Path) -> None:
    _initialize_action_freeze_repository(tmp_path)
    blob_id = _git_stdout(
        tmp_path,
        "rev-parse",
        "HEAD:.github/actions/agent-assure/action.yml",
    )

    assert check_readme_action_source(
        tmp_path,
        release_version="1.2.3",
        pinned_commit=blob_id,
    ) == [f"README.md action SHA {blob_id!r} names a 'blob' object, not a commit"]


def test_readme_action_source_fails_closed_for_missing_object(tmp_path: Path) -> None:
    _initialize_action_freeze_repository(tmp_path)
    missing = "f" * 40

    failures = check_readme_action_source(
        tmp_path,
        release_version="1.2.3",
        pinned_commit=missing,
    )

    assert failures == [
        "README.md action source verification failed closed: git cat-file -t exited 128"
    ]


def _canonical_changelog(*, latest_version: str = "1.2.3") -> str:
    previous_version = "1.2.2" if latest_version == "1.2.3" else "1.2.1"
    return (
        "# Changelog\n\n"
        "## Unreleased\n\n"
        "- Pending.\n\n"
        f"## {latest_version} - 2026-10-06\n\n"
        "- Latest.\n\n"
        f"## {previous_version} - 2026-10-05\n\n"
        "- Previous.\n"
    )


def _canonical_readme(
    *,
    package_name: str = "agent-assure",
    package_version: str = "1.2.3",
    action_version: str = "1.2.3",
    action_sha: str | None = None,
    block_content: str | None = None,
) -> str:
    if block_content is None:
        block_content = _release_pin_lines(
            package_name=package_name,
            package_version=package_version,
            action_version=action_version,
            action_sha=action_sha,
        )
    return (
        "## Integrate your agent\n\n"
        "### GitHub Actions example using the bundled fixture\n\n"
        f"```yaml\n{block_content}\n```\n\n"
        "### Next section\n"
    )


def _release_pin_lines(
    *,
    package_name: str = "agent-assure",
    package_version: str = "1.2.3",
    action_version: str = "1.2.3",
    action_sha: str | None = None,
) -> str:
    return (
        f"- run: pip install {package_name}=={package_version}\n"
        f"# agent-assure v{action_version}\n"
        "- uses: acblabs/agent-assure/.github/actions/agent-assure@"
        f"{action_sha or 'a' * 40}"
    )


def _initialize_action_freeze_repository(root: Path) -> str:
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Release Test")
    _git(root, "config", "user.email", "release-test@example.invalid")
    action = root / ".github" / "actions" / "agent-assure" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text("name: frozen\n", encoding="utf-8")
    _git(root, "add", "--", ".github/actions/agent-assure/action.yml")
    _git(root, "commit", "-m", "freeze action")
    return _git_stdout(root, "rev-parse", "HEAD")


def _commit_file(root: Path, relative_path: str, content: str, message: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(root, "add", "--", relative_path)
    _git(root, "commit", "-m", message)


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _git_stdout(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip().lower()
