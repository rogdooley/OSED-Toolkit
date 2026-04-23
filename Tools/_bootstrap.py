"""Helpers for importing `Tools.*` from scripts in arbitrary directories."""

from __future__ import annotations

from pathlib import Path
import sys


def _walk_up(start: Path):
    current = start.resolve()
    yield current
    for parent in current.parents:
        yield parent


def find_repo_root(marker_dir: str = "Tools", start: str | Path | None = None) -> Path:
    """
    Find the repository root by walking upward until `marker_dir` exists.

    Args:
        marker_dir: Directory name used to identify the repo root (default: Tools)
        start: Start path for traversal. If omitted, uses current working directory.

    Returns:
        Absolute repo root path.

    Raises:
        RuntimeError: If no matching root is found.
    """
    start_path = Path(start) if start is not None else Path.cwd()

    # If a file path is passed, search from its parent directory.
    if start_path.exists() and start_path.is_file():
        search_root = start_path.parent
    else:
        search_root = start_path

    for candidate in _walk_up(search_root):
        if (candidate / marker_dir).is_dir():
            return candidate

    raise RuntimeError(f"Could not find repo root containing '{marker_dir}/' from: {search_root}")


def ensure_tools_on_path(start: str | Path | None = None) -> Path:
    """
    Ensure repo root is on sys.path so `from Tools...` imports work.

    Args:
        start: Optional file or directory path used as traversal start point.
               In scripts, pass `__file__` for best reliability.

    Returns:
        Absolute repo root path that was added/found.
    """
    root = find_repo_root(marker_dir="Tools", start=start)
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return root


__all__ = ["ensure_tools_on_path", "find_repo_root"]
