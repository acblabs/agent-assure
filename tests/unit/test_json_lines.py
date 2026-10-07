from __future__ import annotations

from agent_assure.json_lines import iter_jsonl_records


def test_jsonl_records_accept_lf_and_crlf_and_preserve_exact_source() -> None:
    text = '{"value":1}\r\n{"value":2}\n{"value":3}'

    assert tuple(iter_jsonl_records(text)) == (
        ('{"value":1}', '{"value":1}\r\n'),
        ('{"value":2}', '{"value":2}\n'),
        ('{"value":3}', '{"value":3}'),
    )


def test_jsonl_records_do_not_split_unicode_line_separators() -> None:
    record = '{"value":"before\u2028after\u2029done"}'

    assert tuple(iter_jsonl_records(record)) == ((record, record),)


def test_jsonl_records_do_not_invent_trailing_empty_record() -> None:
    assert tuple(iter_jsonl_records("")) == ()
    assert tuple(iter_jsonl_records("\n")) == (("", "\n"),)
    assert tuple(iter_jsonl_records('{"value":1}\n')) == (('{"value":1}', '{"value":1}\n'),)
