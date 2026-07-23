from __future__ import annotations

from pathlib import Path


def source_checkout_component(
    module_file: str | Path,
    relative_path: str,
) -> Path | None:
    """Resolve a repository component only from a verified ``src`` checkout.

    Installed packages must use their packaged resources. Merely finding a
    sibling ``schemas`` directory near ``site-packages`` is not evidence that
    the package is executing from a reviewed source checkout.
    """
    module_path = Path(module_file).resolve()
    package_root = next(
        (
            parent
            for parent in module_path.parents
            if parent.name == "agent_assure" and parent.parent.name == "src"
        ),
        None,
    )
    if package_root is None:
        return None
    repository_root = package_root.parent.parent.resolve()
    if not (repository_root / "pyproject.toml").is_file():
        return None
    component = (repository_root / relative_path).resolve()
    if not component.is_relative_to(repository_root):
        raise ValueError("source-checkout component escaped the repository root")
    return component
