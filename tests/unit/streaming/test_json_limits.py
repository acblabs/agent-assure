from __future__ import annotations

from pathlib import Path

import pytest

from agent_assure.io_limits import MAX_JSON_DEPTH
from agent_assure.streaming.ingestion import ingest_jsonl_events


def test_stream_jsonl_rejects_excessive_event_nesting(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"nested":' + ("[" * MAX_JSON_DEPTH) + "0" + ("]" * MAX_JSON_DEPTH) + "}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=r"line 1: stream JSONL event exceeds maximum supported nesting depth",
    ):
        ingest_jsonl_events(path, sequence_scope="global")
