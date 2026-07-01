from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))

    from agent_assure.cli.main import app

    app(prog_name="agent-assure")


if __name__ == "__main__":
    main()
