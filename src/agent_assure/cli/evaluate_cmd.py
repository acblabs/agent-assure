from __future__ import annotations

import typer

app = typer.Typer(help="Evaluate run sets.")


@app.callback()
def callback() -> None:
    """Evaluation engine is reserved for a future release."""
