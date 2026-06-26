from __future__ import annotations

import typer

app = typer.Typer(help="Evidence packet utilities.")


@app.callback()
def callback() -> None:
    """Evidence packets are reserved for a future release."""
