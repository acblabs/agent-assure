"""Standard-library release-collateral parsing and validation.

This module is deliberately dependency-free because the production release
preflight runs before project dependencies are installed.  It is the single
source of truth for the changelog release identity consumed by both the
release workflow and documentation validation.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import date
from pathlib import Path

STABLE_VERSION_PATTERN = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_DATED_RELEASE_HEADING_PATTERN = re.compile(
    rf"## (?P<version>{STABLE_VERSION_PATTERN.pattern}) - "
    r"(?P<release_date>\d{4}-\d{2}-\d{2})"
)
_H2_PATTERN = re.compile(r" {0,3}##(?:[ \t]|$)")
_FENCE_OPEN_PATTERN = re.compile(r" {0,3}(?P<marker>`{3,}|~{3,})(?P<info>.*)")
_RAW_HTML_PATTERN = re.compile(r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?=[ \t\r\n/>]|$)|[!?])|--!?>")
_CITATION_VERSION_LINE_PATTERN = re.compile(r"^version:.*$", re.MULTILINE)
_CITATION_VERSION_PATTERN = re.compile(
    rf"^version:\s*(?P<quote>['\"]?)(?P<value>{STABLE_VERSION_PATTERN.pattern})"
    r"(?P=quote)(?:[ \t]+(?:#.*)?|)$",
    re.MULTILINE,
)
_CITATION_DATE_LINE_PATTERN = re.compile(r"^date-released:.*$", re.MULTILINE)
_CITATION_DATE_PATTERN = re.compile(
    r"^date-released:\s*(?P<quote>['\"]?)(?P<value>\d{4}-\d{2}-\d{2})"
    r"(?P=quote)(?:[ \t]+(?:#.*)?|)$",
    re.MULTILINE,
)
_CITATION_TOP_LEVEL_MAPPING_PATTERN = re.compile(
    r"(?P<key>[a-z][a-z0-9]*(?:-[a-z0-9]+)*):(?P<value>(?:[ ]+.*)?)"
)
_README_PACKAGE_REQUIREMENT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._-])agent-assure==(?P<version>[^\s`'\"\\]+)"
)
_README_REQUIREMENT_REFERENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._/-])"
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:[ \t]*\[[^\]\r\n]*\])?[ \t]*(?:\([ \t]*)?"
    r"(?:===|==|~=|!=|<=|>=|<|>|@)[ \t]*"
    r"[^\s`'\"\\),;]*"
    r"(?:[ \t]*,[ \t]*(?:===|==|~=|!=|<=|>=|<|>)[ \t]*"
    r"[^\s`'\"\\),;]*)*"
    r"(?:[ \t]*;[^\r\n`]*)?",
    re.IGNORECASE,
)
_README_INSTALL_COMMAND_PATTERN = re.compile(
    r"\b(?:"
    r"(?:python|py)[ \t]+-m[ \t]+pip|"
    r"pip3?|"
    r"uv[ \t]+pip"
    r")[ \t]+install\b",
    re.IGNORECASE,
)
_README_DISTRIBUTION_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._-])"
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:[ \t]*\[[^\]\r\n]*\])?",
    re.IGNORECASE,
)
_README_ACTION_PIN_PATTERN = re.compile(
    rf"#\s*agent-assure v(?P<version>{STABLE_VERSION_PATTERN.pattern})\s*\n"
    r"\s*-\s*uses:\s*acblabs/agent-assure/\.github/actions/agent-assure@"
    r"(?P<sha>[0-9a-f]{40})(?:\s|$)"
)
_README_ACTION_REFERENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._-])"
    r"acblabs/agent-assure/\.github/actions/agent-assure@"
    r"[^\s`'\"\\]+",
    re.IGNORECASE,
)
_README_LINE_CONTINUATION_PATTERN = re.compile(r"\\(?:\r\n|[\n\r\x85\u2028\u2029])[ \t]*")
README_RELEASE_WORKFLOW_HEADING = "### GitHub Actions example using the bundled fixture"
_README_HEADING_PATTERN = re.compile(r"(?P<hashes>#{1,6})[ \t]+.+")
_README_HTML_TAG_START_PATTERN = re.compile(
    r"<(?P<closing>/)?(?P<tag>[A-Za-z][A-Za-z0-9-]*)(?=[ \t\r\n/>]|$)"
)
_README_ACTIVE_OR_INVISIBLE_ELEMENTS = frozenset({"noscript", "script", "style", "template"})
_README_ALLOWED_ELEMENTS = frozenset(
    {"a", "code", "details", "img", "p", "strong", "sub", "summary"}
)
_README_ALLOWED_ATTRIBUTES = {
    "a": frozenset({"href"}),
    "code": frozenset(),
    "details": frozenset(),
    "img": frozenset({"alt", "src", "width"}),
    "p": frozenset({"align"}),
    "strong": frozenset(),
    "sub": frozenset(),
    "summary": frozenset(),
}
_README_HTML_ATTRIBUTE_PATTERN = re.compile(
    r"\s+(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)"
    r"(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s'\"=<>`]+))?"
)
_README_VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)
_HTML_REL_ATTRIBUTE_PATTERN = re.compile(
    r"(?:^|\s)rel\s*=\s*(?:\"(?P<double>[^\"]*)\"|'(?P<single>[^']*)'|"
    r"(?P<bare>[^\s'\"=<>`]+))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ChangelogRelease:
    """One canonical stable release heading."""

    version: str
    release_date: date
    line_number: int

    @property
    def date_text(self) -> str:
        return self.release_date.isoformat()

    @property
    def version_key(self) -> tuple[int, int, int]:
        major, minor, patch = self.version.split(".")
        return int(major), int(minor), int(patch)


@dataclass(frozen=True)
class ChangelogDocument:
    """Canonical changelog structure and its ordered stable releases."""

    unreleased_line_number: int
    releases: tuple[ChangelogRelease, ...]

    @property
    def latest_release(self) -> ChangelogRelease:
        return self.releases[0]


@dataclass(frozen=True)
class ReadmeActionPin:
    """A composite-action release pin exposed in README.md."""

    version: str
    commit_sha: str


@dataclass(frozen=True)
class _MarkdownFence:
    start_line: int
    end_line: int
    info: str
    content: str


@dataclass(frozen=True)
class _ReadmeHtmlTag:
    start: int
    end: int
    line_number: int
    name: str
    closing: bool
    attributes: str


def parse_changelog(text: str, *, source: str = "CHANGELOG.md") -> ChangelogDocument:
    """Parse and validate the canonical non-fenced changelog release index.

    The parser accepts exactly one ``## Unreleased`` heading followed by one
    or more exact ``## X.Y.Z - YYYY-MM-DD`` headings.  Stable versions must be
    strictly descending and dates must be non-increasing.  Markdown headings
    inside valid backtick/tilde fences cannot establish a release.  Raw HTML
    and HTML comments are rejected because emulating CommonMark HTML-block
    semantics with a security boundary's dependency-free parser would be
    ambiguous.
    """

    lines = text.splitlines()
    if not lines or lines[0] != "# Changelog":
        raise ValueError(f"{source} must start with the exact heading '# Changelog'")
    if "<!--" in text:
        raise ValueError(
            f"{source} must not contain HTML comments; release headings must be "
            "unambiguously visible Markdown"
        )

    h2_entries: list[tuple[str, ChangelogRelease | None, int]] = []
    fence_character: str | None = None
    fence_length = 0
    fence_start_line = 0

    for line_number, raw_line in enumerate(lines, start=1):
        if fence_character is not None:
            if re.fullmatch(
                rf" {{0,3}}{re.escape(fence_character)}{{{fence_length},}}[ \t]*",
                raw_line,
            ):
                fence_character = None
                fence_length = 0
            continue

        if _RAW_HTML_PATTERN.search(raw_line) is not None:
            raise ValueError(
                f"{source}:{line_number} contains raw HTML; release headings must be "
                "unambiguously visible Markdown"
            )

        fence_match = _FENCE_OPEN_PATTERN.fullmatch(raw_line)
        if fence_match is not None:
            marker = fence_match.group("marker")
            info = fence_match.group("info")
            if marker[0] != "`" or "`" not in info:
                fence_character = marker[0]
                fence_length = len(marker)
                fence_start_line = line_number
                continue

        if _H2_PATTERN.match(raw_line) is None:
            continue
        if raw_line == "## Unreleased":
            h2_entries.append(("unreleased", None, line_number))
            continue

        release_match = _DATED_RELEASE_HEADING_PATTERN.fullmatch(raw_line)
        if release_match is None:
            raise ValueError(
                f"{source}:{line_number} has a noncanonical H2 heading; expected "
                "'## Unreleased' or '## X.Y.Z - YYYY-MM-DD'"
            )
        version = release_match.group("version")
        date_text = release_match.group("release_date")
        try:
            release_date = date.fromisoformat(date_text)
        except ValueError as exc:
            raise ValueError(
                f"{source}:{line_number} release {version} has invalid ISO date {date_text!r}"
            ) from exc
        if release_date.isoformat() != date_text:
            raise ValueError(
                f"{source}:{line_number} release {version} has noncanonical ISO date {date_text!r}"
            )
        h2_entries.append(
            (
                "release",
                ChangelogRelease(
                    version=version,
                    release_date=release_date,
                    line_number=line_number,
                ),
                line_number,
            )
        )

    if fence_character is not None:
        raise ValueError(f"{source}:{fence_start_line} contains an unterminated Markdown fence")

    unreleased_entries = [entry for entry in h2_entries if entry[0] == "unreleased"]
    if len(unreleased_entries) != 1:
        raise ValueError(
            f"{source} must contain exactly one exact non-fenced '## Unreleased' heading; "
            f"found {len(unreleased_entries)}"
        )
    if not h2_entries or h2_entries[0][0] != "unreleased":
        raise ValueError(f"{source} must place '## Unreleased' before every dated release")

    releases = tuple(
        release
        for kind, release, _line_number in h2_entries
        if kind == "release" and release is not None
    )
    if not releases:
        raise ValueError(f"{source} must contain at least one exact non-fenced dated release")

    versions: set[str] = set()
    for release in releases:
        if release.version in versions:
            raise ValueError(
                f"{source} contains duplicate release version {release.version!r} "
                f"(latest duplicate at line {release.line_number})"
            )
        versions.add(release.version)

    for newer, older in zip(releases, releases[1:], strict=False):
        if newer.version_key <= older.version_key:
            raise ValueError(
                f"{source} releases must be in strictly descending SemVer order: "
                f"{newer.version!r} at line {newer.line_number} is not newer than "
                f"{older.version!r} at line {older.line_number}"
            )
        if newer.release_date < older.release_date:
            raise ValueError(
                f"{source} release dates must be in descending order: "
                f"{newer.date_text!r} at line {newer.line_number} precedes "
                f"{older.date_text!r} at line {older.line_number}"
            )

    return ChangelogDocument(
        unreleased_line_number=unreleased_entries[0][2],
        releases=releases,
    )


def require_latest_release(
    changelog: ChangelogDocument,
    *,
    expected_version: str,
    source: str = "CHANGELOG.md",
) -> ChangelogRelease:
    """Require ``expected_version`` to be the unique latest stable release."""

    if STABLE_VERSION_PATTERN.fullmatch(expected_version) is None:
        raise ValueError(f"expected stable release version is invalid: {expected_version!r}")
    latest = changelog.latest_release
    if latest.version != expected_version:
        raise ValueError(
            f"{source} latest dated release {latest.version!r} does not match stable "
            f"release {expected_version!r}"
        )
    return latest


def check_citation_release(
    text: str,
    *,
    expected: ChangelogRelease,
    source: str = "CITATION.cff",
) -> list[str]:
    """Bind the unique CFF release version/date scalars to ``expected``."""

    failures = _check_citation_top_level_mapping(text, source=source)
    version_lines = _CITATION_VERSION_LINE_PATTERN.findall(text)
    date_lines = _CITATION_DATE_LINE_PATTERN.findall(text)
    version_match = (
        _CITATION_VERSION_PATTERN.fullmatch(version_lines[0]) if len(version_lines) == 1 else None
    )
    date_match = _CITATION_DATE_PATTERN.fullmatch(date_lines[0]) if len(date_lines) == 1 else None
    if not version_lines:
        failures.append(f"{source} must declare version")
    elif len(version_lines) != 1:
        failures.append(f"{source} must declare exactly one version")
    elif version_match is None:
        failures.append(f"{source} must declare a canonical stable X.Y.Z version")
    if not date_lines:
        failures.append(f"{source} must declare date-released")
    elif len(date_lines) != 1:
        failures.append(f"{source} must declare exactly one date-released")
    elif date_match is None:
        failures.append(f"{source} must declare a canonical YYYY-MM-DD date-released")
    if version_match is not None:
        actual_version = version_match.group("value")
        if actual_version != expected.version:
            failures.append(
                f"{source} version {actual_version!r} does not match latest released "
                f"version {expected.version!r}"
            )
    if date_match is not None:
        actual_date = date_match.group("value")
        try:
            parsed_date = date.fromisoformat(actual_date)
        except ValueError:
            parsed_date = None
        if parsed_date is None or parsed_date.isoformat() != actual_date:
            failures.append(f"{source} date-released {actual_date!r} is not a valid ISO date")
        elif actual_date != expected.date_text:
            failures.append(
                f"{source} date-released {actual_date!r} does not match latest release "
                f"date {expected.date_text!r}"
            )
    return failures


def _check_citation_top_level_mapping(text: str, *, source: str) -> list[str]:
    """Require a dependency-free, unambiguous top-level CFF mapping subset."""

    failures: list[str] = []
    seen_keys: dict[str, int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "\t" in line:
            failures.append(f"{source}:{line_number} must not contain tab characters")
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        scalar_failure = _citation_physical_line_failure(line)
        if scalar_failure is not None:
            failures.append(f"{source}:{line_number} {scalar_failure}")
            continue
        if line.startswith(" "):
            continue
        match = _CITATION_TOP_LEVEL_MAPPING_PATTERN.fullmatch(line)
        if match is None:
            failures.append(
                f"{source}:{line_number} top-level CFF entry must use canonical plain "
                "lower-kebab-key mapping syntax"
            )
            continue
        key = match.group("key")
        if key in seen_keys:
            failures.append(
                f"{source}:{line_number} duplicates top-level key {key!r} first declared "
                f"at line {seen_keys[key]}"
            )
        else:
            seen_keys[key] = line_number
    return failures


def _citation_physical_line_failure(line: str) -> str | None:
    """Reject YAML constructs that can absorb later physical mapping lines."""

    quote: str | None = None
    index = 0
    while index < len(line):
        character = line[index]
        if quote == '"':
            if character == "\\":
                index += 2
                continue
            if character == '"':
                quote = None
        elif quote == "'":
            if character == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
        else:
            if character == "#" and (index == 0 or line[index - 1].isspace()):
                break
            if character in {'"', "'"}:
                quote = character
            elif character in "[]{}":
                return "must not use YAML flow collections"
        index += 1
    if quote is not None:
        return "must not use multiline quoted YAML scalars"
    return None


def readme_action_pins(text: str) -> tuple[ReadmeActionPin, ...]:
    """Return exact full-SHA action pins paired with their release comments."""

    return tuple(
        ReadmeActionPin(
            version=match.group("version"),
            commit_sha=match.group("sha"),
        )
        for match in _README_ACTION_PIN_PATTERN.finditer(text)
    )


def _readme_agent_assure_requirement_references(text: str) -> tuple[str, ...]:
    """Find normalized agent-assure requirements, including bare installer tokens."""

    text = _README_LINE_CONTINUATION_PATTERN.sub("", text)
    references: dict[int, str] = {}
    for match in _README_REQUIREMENT_REFERENCE_PATTERN.finditer(text):
        if _normalized_distribution_name(match.group("name")) == "agent-assure":
            references[match.start("name")] = match.group(0)

    line_offset = 0
    for line in text.splitlines(keepends=True):
        command = _README_INSTALL_COMMAND_PATTERN.search(line)
        if command is not None:
            for match in _README_DISTRIBUTION_TOKEN_PATTERN.finditer(line, command.end()):
                if _normalized_distribution_name(match.group("name")) == "agent-assure":
                    start = line_offset + match.start("name")
                    references.setdefault(start, match.group(0))
        line_offset += len(line)
    return tuple(references[start] for start in sorted(references))


def _normalized_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _readme_action_references(text: str) -> tuple[str, ...]:
    logical_text = _README_LINE_CONTINUATION_PATTERN.sub("", text)
    return tuple(
        match.group(0) for match in _README_ACTION_REFERENCE_PATTERN.finditer(logical_text)
    )


def check_readme_release(
    text: str,
    *,
    expected: ChangelogRelease,
    source: str = "README.md",
) -> list[str]:
    """Bind README installation and immutable action pins to ``expected``."""

    try:
        release_block = _readme_release_workflow_block(text, source=source)
    except ValueError as exc:
        return [str(exc)]
    failures: list[str] = []
    package_versions = tuple(
        match.group("version")
        for match in _README_PACKAGE_REQUIREMENT_PATTERN.finditer(release_block)
    )
    action_pins = readme_action_pins(release_block)
    package_references = _readme_agent_assure_requirement_references(release_block)
    action_references = _readme_action_references(release_block)
    if not package_versions:
        failures.append(f"{source} must pin the published agent-assure package version")
    elif len(package_versions) != 1:
        failures.append(
            f"{source} must contain exactly one published agent-assure package version pin"
        )
    elif STABLE_VERSION_PATTERN.fullmatch(package_versions[0]) is None:
        failures.append(
            f"{source} package pin {package_versions[0]!r} must be an exact stable X.Y.Z "
            "requirement"
        )
    elif package_versions[0] != expected.version:
        failures.append(
            f"{source} package pin {package_versions[0]!r} does not match latest released "
            f"version {expected.version!r}"
        )
    if not action_pins:
        failures.append(
            f"{source} must pin the published composite action to a full commit SHA "
            "with its release-version comment"
        )
    elif len(action_pins) != 1:
        failures.append(
            f"{source} must pin the published composite action to exactly one full commit SHA "
            "with its release-version comment"
        )
    elif action_pins[0].version != expected.version:
        failures.append(
            f"{source} action version comment {action_pins[0].version!r} does not match latest "
            f"released version {expected.version!r}"
        )
    if len(package_references) > 1:
        failures.append(
            f"{source} canonical release-workflow YAML block must contain exactly one "
            "PEP 503-normalized agent-assure requirement"
        )
    if len(action_references) > 1:
        failures.append(
            f"{source} canonical release-workflow YAML block must contain exactly one "
            "composite-action reference"
        )
    global_package_references = _readme_agent_assure_requirement_references(text)
    global_action_references = _readme_action_references(text)
    expected_requirement = f"agent-assure=={expected.version}"
    outside_package_references = list(global_package_references)
    for canonical_reference in package_references:
        try:
            outside_package_references.remove(canonical_reference)
        except ValueError:
            continue
    if any(reference != expected_requirement for reference in outside_package_references):
        failures.append(
            f"{source} must use exact requirement {expected_requirement!r} for every "
            "agent-assure installation reference"
        )
    if len(global_action_references) > len(action_references):
        failures.append(
            f"{source} must not contain composite-action references outside the canonical "
            "release-workflow YAML block"
        )
    return failures


def readme_release_action_pin(text: str, *, source: str = "README.md") -> ReadmeActionPin:
    """Return the sole action pin from the canonical visible workflow block."""

    block = _readme_release_workflow_block(text, source=source)
    pins = readme_action_pins(block)
    if len(pins) != 1:
        raise ValueError(f"{source} canonical release-workflow YAML block lacks one action pin")
    return pins[0]


def _readme_release_workflow_block(text: str, *, source: str) -> str:
    """Extract the one visible, top-level canonical release-workflow YAML block."""

    lines = text.splitlines()
    fences, outside_fence = _scan_markdown_fences(lines, source=source)
    heading_lines = [
        index
        for index, line in enumerate(lines)
        if outside_fence[index] and line == README_RELEASE_WORKFLOW_HEADING
    ]
    if len(heading_lines) != 1:
        raise ValueError(
            f"{source} must contain exactly one visible top-level "
            f"{README_RELEASE_WORKFLOW_HEADING!r} heading"
        )
    heading_line = heading_lines[0]
    boundary_headings = [
        index
        for index, line in enumerate(lines)
        if outside_fence[index]
        and (match := _README_HEADING_PATTERN.fullmatch(line)) is not None
        and len(match.group("hashes")) <= 3
    ]
    prior_boundaries = [index for index in boundary_headings if index < heading_line]
    following_boundaries = [index for index in boundary_headings if index > heading_line]
    around_start = prior_boundaries[-1] if prior_boundaries else 0
    section_end = following_boundaries[0] if following_boundaries else len(lines)

    html_tags = _validate_readme_html_structure(
        lines,
        outside_fence=outside_fence,
        canonical_heading_line=heading_line,
        source=source,
    )

    for tag in html_tags:
        if around_start <= tag.line_number - 1 < section_end:
            raise ValueError(
                f"{source}:{tag.line_number} canonical release-workflow section must not contain "
                "raw HTML"
            )

    section_fences = [
        fence
        for fence in fences
        if heading_line < fence.start_line and fence.end_line < section_end
    ]
    if len(section_fences) != 1 or section_fences[0].info != "yaml":
        raise ValueError(
            f"{source} canonical release-workflow section must contain exactly one valid "
            "CommonMark fence with info string 'yaml'"
        )
    return section_fences[0].content


def _validate_readme_html_structure(
    lines: list[str],
    *,
    outside_fence: tuple[bool, ...],
    canonical_heading_line: int,
    source: str,
) -> tuple[_ReadmeHtmlTag, ...]:
    """Validate raw HTML without relying on a finite container-tag blacklist."""

    visible_text = "\n".join(
        line if outside_fence[index] else " " * len(line) for index, line in enumerate(lines)
    )
    for marker in ("<!--", "-->"):
        marker_offset = visible_text.find(marker)
        if marker_offset >= 0:
            line_number = visible_text.count("\n", 0, marker_offset) + 1
            raise ValueError(
                f"{source}:{line_number} must not contain HTML comments; "
                "release pins must remain human-visible"
            )
    for marker in ("<!", "<?", "?>", "]]>"):
        marker_offset = visible_text.find(marker)
        if marker_offset >= 0:
            line_number = visible_text.count("\n", 0, marker_offset) + 1
            raise ValueError(
                f"{source}:{line_number} must not contain HTML declarations, processing "
                "instructions, or CDATA markers; release pins must remain human-visible"
            )
    line_offsets: list[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line) + 1
    heading_offset = line_offsets[canonical_heading_line]

    tags: list[_ReadmeHtmlTag] = []
    position = 0
    while True:
        position = visible_text.find("<", position)
        if position < 0:
            break
        start_match = _README_HTML_TAG_START_PATTERN.match(visible_text, position)
        if start_match is None:
            position += 1
            continue
        line_number = visible_text.count("\n", 0, position) + 1
        tag_end = _readme_html_tag_end(
            visible_text,
            start_match.end(),
            source=source,
            line_number=line_number,
        )
        first_line = line_number - 1
        last_line = visible_text.count("\n", 0, tag_end)
        if not all(outside_fence[index] for index in range(first_line, last_line + 1)):
            raise ValueError(
                f"{source}:{line_number} raw HTML tag must not cross a Markdown fence boundary"
            )
        attributes = visible_text[start_match.end() : tag_end - 1]
        tags.append(
            _ReadmeHtmlTag(
                start=position,
                end=tag_end,
                line_number=line_number,
                name=start_match.group("tag").casefold(),
                closing=start_match.group("closing") is not None,
                attributes=attributes,
            )
        )
        position = tag_end

    open_containers: list[tuple[str, int]] = []
    heading_checked = False
    for tag in tags:
        if not heading_checked and tag.start >= heading_offset:
            _require_top_level_release_heading(open_containers, source=source)
            heading_checked = True
        if tag.start < heading_offset < tag.end:
            raise ValueError(
                f"{source} canonical release-workflow heading must not occur inside a raw "
                f"HTML <{tag.name}> tag"
            )
        if tag.name in _README_ACTIVE_OR_INVISIBLE_ELEMENTS:
            raise ValueError(
                f"{source}:{tag.line_number} must not contain raw HTML <{tag.name}>; "
                "release pins must remain human-visible"
            )
        if tag.name == "link" and _is_stylesheet_link(tag.attributes):
            raise ValueError(
                f"{source}:{tag.line_number} must not contain a stylesheet link; "
                "release pins must remain human-visible"
            )
        if tag.name not in _README_ALLOWED_ELEMENTS:
            raise ValueError(
                f"{source}:{tag.line_number} contains unsupported raw HTML <{tag.name}>; "
                "release pins must remain human-visible"
            )

        stripped_attributes = tag.attributes.strip()
        self_closing = stripped_attributes.endswith("/")
        if tag.closing:
            if stripped_attributes:
                raise ValueError(
                    f"{source}:{tag.line_number} has malformed closing HTML tag </{tag.name}>"
                )
            if tag.name in _README_VOID_ELEMENTS:
                raise ValueError(
                    f"{source}:{tag.line_number} must not close void HTML element <{tag.name}>"
                )
            if not open_containers or open_containers[-1][0] != tag.name:
                expected = open_containers[-1][0] if open_containers else "none"
                raise ValueError(
                    f"{source}:{tag.line_number} has mismatched closing HTML tag </{tag.name}>; "
                    f"expected </{expected}>"
                )
            open_containers.pop()
        else:
            _validate_readme_html_attributes(
                tag,
                self_closing=self_closing,
                source=source,
            )
            if tag.name not in _README_VOID_ELEMENTS and self_closing:
                raise ValueError(
                    f"{source}:{tag.line_number} must not use self-closing syntax for non-void "
                    f"HTML element <{tag.name}>"
                )
            if tag.name not in _README_VOID_ELEMENTS:
                open_containers.append((tag.name, tag.line_number))

    if not heading_checked:
        _require_top_level_release_heading(open_containers, source=source)
    if open_containers:
        open_tag, line_number = open_containers[-1]
        raise ValueError(f"{source}:{line_number} contains unclosed raw HTML <{open_tag}> element")
    return tuple(tags)


def _readme_html_tag_end(
    text: str,
    position: int,
    *,
    source: str,
    line_number: int,
) -> int:
    quote: str | None = None
    for index in range(position, len(text)):
        character = text[index]
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "<":
            raise ValueError(f"{source}:{line_number} contains malformed raw HTML tag")
        elif character == ">":
            return index + 1
    raise ValueError(f"{source}:{line_number} contains unterminated raw HTML tag")


def _require_top_level_release_heading(
    open_containers: list[tuple[str, int]],
    *,
    source: str,
) -> None:
    if open_containers:
        tag, _line_number = open_containers[-1]
        raise ValueError(
            f"{source} canonical release-workflow heading must be top-level visible Markdown, "
            f"not nested in raw HTML <{tag}>"
        )


def _is_stylesheet_link(attributes: str) -> bool:
    match = _HTML_REL_ATTRIBUTE_PATTERN.search(attributes)
    if match is None:
        return False
    value = next(value for value in match.group("double", "single", "bare") if value is not None)
    return "stylesheet" in {token.casefold() for token in value.split()}


def _validate_readme_html_attributes(
    tag: _ReadmeHtmlTag,
    *,
    self_closing: bool,
    source: str,
) -> None:
    attributes = tag.attributes
    if self_closing:
        attributes = attributes.rstrip()[:-1]
    names: list[str] = []
    position = 0
    while position < len(attributes):
        if attributes[position:].strip() == "":
            break
        match = _README_HTML_ATTRIBUTE_PATTERN.match(attributes, position)
        if match is None:
            raise ValueError(
                f"{source}:{tag.line_number} contains malformed attributes on raw HTML <{tag.name}>"
            )
        names.append(match.group("name").casefold())
        position = match.end()
    if len(names) != len(set(names)):
        raise ValueError(
            f"{source}:{tag.line_number} contains duplicate attributes on raw HTML <{tag.name}>"
        )
    forbidden = [
        name for name in names if name in {"class", "hidden", "style"} or name.startswith("on")
    ]
    if forbidden:
        raise ValueError(
            f"{source}:{tag.line_number} raw HTML <{tag.name}> must not use visibility-active "
            f"attribute {forbidden[0]!r}"
        )
    unsupported = [name for name in names if name not in _README_ALLOWED_ATTRIBUTES[tag.name]]
    if unsupported:
        raise ValueError(
            f"{source}:{tag.line_number} raw HTML <{tag.name}> uses unsupported attribute "
            f"{unsupported[0]!r}"
        )


def _scan_markdown_fences(
    lines: list[str],
    *,
    source: str,
) -> tuple[tuple[_MarkdownFence, ...], tuple[bool, ...]]:
    fences: list[_MarkdownFence] = []
    outside_fence = [True] * len(lines)
    fence_character: str | None = None
    fence_length = 0
    fence_start = 0
    fence_info = ""
    for index, line in enumerate(lines):
        if fence_character is not None:
            outside_fence[index] = False
            if re.fullmatch(
                rf" {{0,3}}{re.escape(fence_character)}{{{fence_length},}}[ \t]*",
                line,
            ):
                fences.append(
                    _MarkdownFence(
                        start_line=fence_start,
                        end_line=index,
                        info=fence_info,
                        content="\n".join(lines[fence_start + 1 : index]),
                    )
                )
                fence_character = None
                fence_length = 0
                fence_info = ""
            continue
        opener = _FENCE_OPEN_PATTERN.fullmatch(line)
        if opener is None:
            continue
        marker = opener.group("marker")
        info = opener.group("info")
        if marker[0] == "`" and "`" in info:
            continue
        outside_fence[index] = False
        fence_character = marker[0]
        fence_length = len(marker)
        fence_start = index
        fence_info = info.strip()
    if fence_character is not None:
        raise ValueError(f"{source}:{fence_start + 1} contains an unterminated Markdown fence")
    return tuple(fences), tuple(outside_fence)


def check_readme_action_source(
    repository_root: Path,
    *,
    release_version: str,
    pinned_commit: str,
    source: str = "README.md",
) -> list[str]:
    """Bind an immutable README action pin to the release action subtree.

    The pin must name a commit that is an ancestor of the release target and
    whose ``.github/actions/agent-assure`` tree is byte-identical to the target
    tree.  An existing release tag is authoritative; before tag creation, HEAD
    is the release-preparation target.
    """

    if re.fullmatch(r"[0-9a-f]{40}", pinned_commit) is None:
        return [f"{source} action pin must be a full lowercase 40-hex commit SHA"]
    if not (repository_root / ".git").exists():
        return [f"{source} action source cannot be verified: Git repository is unavailable"]

    try:
        pinned_type = _git_stdout(repository_root, "cat-file", "-t", pinned_commit)
        if pinned_type != "commit":
            return [
                f"{source} action SHA {pinned_commit!r} names a {pinned_type!r} object, "
                "not a commit"
            ]

        tag_ref = f"refs/tags/v{release_version}"
        tag_probe = _run_git(repository_root, "show-ref", "--verify", "--quiet", tag_ref)
        if tag_probe.returncode == 0:
            target_revision = f"v{release_version}^{{commit}}"
            target_label = f"v{release_version}"
        elif tag_probe.returncode == 1:
            target_revision = "HEAD^{commit}"
            target_label = "release-preparation HEAD"
        else:
            raise RuntimeError(f"git show-ref exited {tag_probe.returncode}")

        target_commit = _git_object_id(repository_root, target_revision)
        target_type = _git_stdout(repository_root, "cat-file", "-t", target_commit)
        if target_type != "commit":
            raise RuntimeError(f"release target resolved to {target_type!r}, not a commit")

        ancestry = _run_git(
            repository_root,
            "merge-base",
            "--is-ancestor",
            pinned_commit,
            target_commit,
        )
        if ancestry.returncode == 1:
            return [
                f"{source} action SHA {pinned_commit!r} is not an ancestor of "
                f"{target_label} commit {target_commit!r}"
            ]
        if ancestry.returncode != 0:
            raise RuntimeError(f"git merge-base exited {ancestry.returncode}")

        action_path = ".github/actions/agent-assure"
        pinned_tree = _git_object_id(repository_root, f"{pinned_commit}:{action_path}")
        target_tree = _git_object_id(repository_root, f"{target_commit}:{action_path}")
        for tree in (pinned_tree, target_tree):
            if _git_stdout(repository_root, "cat-file", "-t", tree) != "tree":
                raise RuntimeError(f"{action_path} did not resolve to a Git tree")
        if pinned_tree != target_tree:
            return [
                f"{source} action SHA {pinned_commit!r} has action tree {pinned_tree!r}, "
                f"which does not match {target_label} action tree {target_tree!r}"
            ]
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return [f"{source} action source verification failed closed: {exc}"]
    return []


def _run_git(repository_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _git_stdout(repository_root: Path, *arguments: str) -> str:
    completed = _run_git(repository_root, *arguments)
    if completed.returncode != 0:
        operation = " ".join(arguments[:2])
        raise RuntimeError(f"git {operation} exited {completed.returncode}")
    value = completed.stdout.strip().lower()
    if not value:
        operation = " ".join(arguments[:2])
        raise RuntimeError(f"git {operation} returned no value")
    return value


def _git_object_id(repository_root: Path, revision: str) -> str:
    object_id = _git_stdout(repository_root, "rev-parse", "--verify", revision)
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
        raise RuntimeError("git rev-parse returned a malformed object ID")
    return object_id
