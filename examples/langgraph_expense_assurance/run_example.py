from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _main() -> int:
    from agent_assure.examples.langgraph_expense_assurance.runner import main

    return main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(_main())
