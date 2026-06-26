from __future__ import annotations

import re

SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\d[ -]?){12,15}\d\b"),
    re.compile(r"\b(?:dob|date of birth)\s*[:=]?\s*\d{4}-\d{2}-\d{2}\b", re.IGNORECASE),
    re.compile(r"\b(?:patient|member|ssn|dob)\s*[:=]\s*[^\r\n;]+", re.IGNORECASE),
)


def contains_sensitive_value(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in SENSITIVE_PATTERNS)
