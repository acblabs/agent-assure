from __future__ import annotations

import typer

app = typer.Typer(help="Compare run sets.")


@app.callback()
def callback() -> None:
    """Comparison engine is reserved for a future release."""
