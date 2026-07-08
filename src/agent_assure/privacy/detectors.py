from __future__ import annotations

import re

SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\d[ -]?){12,15}\d\b"),
    re.compile(r"\b(?:dob|date of birth)\s*[:=]?\s*\d{4}-\d{2}-\d{2}\b", re.IGNORECASE),
    re.compile(r"\b(?:patient|member|ssn|dob)\s*[:=]\s*[^\r\n;]+", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bA(?:KIA|SIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|secret|"
        r"password|passwd|authorization)\s*[:=]\s*"
        r"['\"]?[^'\"\s,;]{8,}",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://[^\s?#]+[^\s]*[?&](?:api[_-]?key|access[_-]?token|token|secret|password)="
        r"[^\s&#]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:phone|tel|mobile)\s*[:=]?\s*(?:\+?1[-.\s]?)?"
        r"\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def contains_sensitive_value(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in SENSITIVE_PATTERNS)
