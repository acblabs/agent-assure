from __future__ import annotations

from collections.abc import Iterator


def iter_jsonl_records(text: str) -> Iterator[tuple[str, str]]:
    """Yield logical JSONL text and its exact source record.

    JSON Lines records are delimited only by LF, with an optional CR immediately
    before that LF. Python's splitlines recognizes additional Unicode
    separators (including U+2028 and U+2029) that are valid characters inside a
    JSON string and must not create an extra record.
    """

    start = 0
    text_length = len(text)
    while start < text_length:
        newline = text.find("\n", start)
        if newline < 0:
            source_record = text[start:]
            yield source_record, source_record
            return
        source_record = text[start : newline + 1]
        line = text[start:newline]
        if line.endswith("\r"):
            line = line[:-1]
        yield line, source_record
        start = newline + 1
