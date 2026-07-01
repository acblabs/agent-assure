from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def main() -> int:
    dist = DIST.resolve()
    root = ROOT.resolve()
    if dist.parent != root or dist.name != "dist":
        raise RuntimeError(f"refusing to clean unexpected dist path: {dist}")
    if dist.exists():
        for child in dist.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        dist.mkdir()
    print(f"clean-dist: ok ({dist})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
