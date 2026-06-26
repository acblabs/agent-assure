from __future__ import annotations

import typer

app = typer.Typer(help="CI gates.")


@app.callback()
def callback() -> None:
    """CI gate is reserved for a future release."""
