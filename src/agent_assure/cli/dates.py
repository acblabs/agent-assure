from __future__ import annotations

from datetime import date

import typer


def parse_cli_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter("--today must use YYYY-MM-DD") from exc
