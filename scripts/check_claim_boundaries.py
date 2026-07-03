from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RestrictedPattern:
    label: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class ClaimBoundaryViolation:
    path: Path
    line: int
    column: int
    label: str
    sentence: str


APPROVED_LIMITATION_SENTENCES = (
    "This is not a compliance attestation",
    "This is not a compliance attestation.",
    "This report is not a compliance attestation.",
    "This project is not a compliance attestation.",
    "This artifact does not certify safety.",
)

RESTRICTED_PATTERNS = (
    RestrictedPattern("compliant", re.compile(r"\bcompliant\b", re.IGNORECASE)),
    RestrictedPattern(
        "certified/certification",
        re.compile(r"\bcertif(?:y|ies|ied|ication)\b", re.IGNORECASE),
    ),
    RestrictedPattern("attestation", re.compile(r"\battestation\b", re.IGNORECASE)),
    RestrictedPattern("audit passed", re.compile(r"\baudit\s+passed\b", re.IGNORECASE)),
    RestrictedPattern(
        "ISO pass",
        re.compile(r"\bISO\b[^\n.!?]{0,40}\bPASS(?:ED)?\b", re.IGNORECASE),
    ),
    RestrictedPattern(
        "NIST pass",
        re.compile(r"\bNIST\b[^\n.!?]{0,40}\bPASS(?:ED)?\b", re.IGNORECASE),
    ),
    RestrictedPattern(
        "OWASP pass",
        re.compile(r"\bOWASP\b[^\n.!?]{0,40}\bPASS(?:ED)?\b", re.IGNORECASE),
    ),
    RestrictedPattern("guaranteed", re.compile(r"\bguaranteed\b", re.IGNORECASE)),
    RestrictedPattern("proves safety", re.compile(r"\bproves\s+safety\b", re.IGNORECASE)),
    RestrictedPattern(
        "proves compliance",
        re.compile(r"\bproves\s+compliance\b", re.IGNORECASE),
    ),
    RestrictedPattern("clinically valid", re.compile(r"\bclinically\s+valid\b", re.IGNORECASE)),
    RestrictedPattern(
        "regulatory approval",
        re.compile(r"\bregulatory\s+approval\b", re.IGNORECASE),
    ),
    RestrictedPattern("ROI", re.compile(r"\bROI\b", re.IGNORECASE)),
    RestrictedPattern(
        "bottom-line impact",
        re.compile(r"\bbottom-line\s+impact\b", re.IGNORECASE),
    ),
    RestrictedPattern(
        "business savings",
        re.compile(r"\bbusiness\s+savings\b", re.IGNORECASE),
    ),
    RestrictedPattern(
        "annualized savings",
        re.compile(r"\bannualized\s+savings\b", re.IGNORECASE),
    ),
    RestrictedPattern("labor savings", re.compile(r"\blabor\s+savings\b", re.IGNORECASE)),
)

DEFAULT_SCAN_FILES = (
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("docs/for_ai_leaders.md"),
    Path("docs/for_engineers.md"),
    Path("docs/what_this_measures.md"),
    Path("docs/demo_flagship.md"),
    Path("docs/demo_expense.md"),
    Path("docs/evidence_diff.md"),
    Path("docs/claim_boundary.md"),
    Path("docs/posts/output_equivalence_is_not_process_equivalence.md"),
    Path("docs/assets/flagship_demo_transcript.txt"),
    Path("docs/social/demo_video_script.md"),
)

DEFAULT_SCAN_GLOBS = (
    "docs/release_notes/*.md",
    "tests/golden/reports/**/*evidence-diff*.html",
)


def main(argv: list[str] | None = None) -> int:
    paths = _paths_from_args(argv if argv is not None else sys.argv[1:])
    violations = scan_files(paths)
    if violations:
        for violation in violations:
            print(_format_violation(violation), file=sys.stderr)
        return 1
    print("claim-boundary: ok")
    return 0


def scan_files(paths: tuple[Path, ...]) -> list[ClaimBoundaryViolation]:
    violations: list[ClaimBoundaryViolation] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        violations.extend(find_claim_boundary_violations(text, path=path))
    return violations


def find_claim_boundary_violations(
    text: str,
    *,
    path: Path = Path("<text>"),
) -> list[ClaimBoundaryViolation]:
    violations: list[ClaimBoundaryViolation] = []
    for restricted in RESTRICTED_PATTERNS:
        for match in restricted.pattern.finditer(text):
            sentence = _containing_sentence(text, match.start())
            if _is_approved_limitation_sentence(sentence):
                continue
            line, column = _line_column(text, match.start())
            violations.append(
                ClaimBoundaryViolation(
                    path=path,
                    line=line,
                    column=column,
                    label=restricted.label,
                    sentence=sentence,
                )
            )
    return violations


def default_scan_paths(root: Path = ROOT) -> tuple[Path, ...]:
    paths: list[Path] = []
    for relative_path in DEFAULT_SCAN_FILES:
        path = root / relative_path
        if path.exists():
            paths.append(path)
    for pattern in DEFAULT_SCAN_GLOBS:
        paths.extend(path for path in sorted(root.glob(pattern)) if path.is_file())
    return tuple(_dedupe_paths(paths))


def _paths_from_args(args: list[str]) -> tuple[Path, ...]:
    if not args:
        return default_scan_paths()
    return tuple(Path(arg) for arg in args)


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def _containing_sentence(text: str, offset: int) -> str:
    start = _last_boundary(text, offset)
    end = _next_boundary(text, offset)
    return " ".join(text[start:end].split())


def _last_boundary(text: str, offset: int) -> int:
    boundary = 0
    for index in range(offset - 1, -1, -1):
        if _is_sentence_boundary(text, index):
            boundary = index + 1
            break
    tag_boundary = text.rfind(">", 0, offset)
    if tag_boundary != -1:
        boundary = max(boundary, tag_boundary + 1)
    return boundary


def _next_boundary(text: str, offset: int) -> int:
    for index in range(offset, len(text)):
        if _is_sentence_boundary(text, index):
            return index + 1
    return len(text)


def _is_sentence_boundary(text: str, index: int) -> bool:
    char = text[index]
    if char in "!?":
        return True
    if char == "\n":
        return _is_blank_line_boundary(text, index) or _next_line_starts_markdown_item(
            text,
            index,
        )
    if char != ".":
        return False
    return _is_sentence_period(text, index)


def _is_blank_line_boundary(text: str, index: int) -> bool:
    return (
        (index > 0 and text[index - 1] == "\n")
        or (index + 1 < len(text) and text[index + 1] == "\n")
    )


def _next_line_starts_markdown_item(text: str, index: int) -> bool:
    next_line_end = text.find("\n", index + 1)
    next_line = text[index + 1 :] if next_line_end == -1 else text[index + 1 : next_line_end]
    return re.match(r"\s*(?:[-*+]\s+|\d+[.)]\s+)", next_line) is not None


def _is_sentence_period(text: str, index: int) -> bool:
    previous_char = text[index - 1] if index > 0 else ""
    next_char = text[index + 1] if index + 1 < len(text) else ""
    if previous_char.isdigit() and next_char.isdigit():
        return False
    prefix = text[max(0, index - 3) : index + 1].lower()
    if prefix in {"e.g.", "i.e."}:
        return False
    return True


def _is_approved_limitation_sentence(sentence: str) -> bool:
    key = " ".join(_normalize_sentence(sentence).rstrip(".!?").split())
    return key in _APPROVED_LIMITATION_KEYS


def _normalize_sentence(sentence: str) -> str:
    normalized = re.sub(r"<[^>]+>", " ", sentence)
    normalized = re.sub(r"(?m)^\s*(?:[-*+]\s+|>\s*)", "", normalized)
    normalized = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", normalized)
    normalized = re.sub(r"[`*_]+", "", normalized)
    return " ".join(normalized.split())


_APPROVED_LIMITATION_KEYS = frozenset(
    " ".join(_normalize_sentence(sentence).rstrip(".!?").split())
    for sentence in APPROVED_LIMITATION_SENTENCES
)


def _line_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset)
    column = offset + 1 if line_start == -1 else offset - line_start
    return line, column


def _format_violation(violation: ClaimBoundaryViolation) -> str:
    return (
        "claim-boundary: "
        f"{violation.path}:{violation.line}:{violation.column}: "
        f"restricted claim language ({violation.label}): {violation.sentence}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
