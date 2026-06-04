"""Narrow platform helpers: locate Wireshark CLI tools and normalize paths.

This module deliberately contains no parsing or extraction logic — only tool
discovery, availability, versions, and path normalization.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def find_executable(name: str) -> str | None:
    """Return the absolute path to ``name`` on PATH, or ``None``.

    Also honors an explicit override via the ``CALLSCOPE_<NAME>`` environment
    variable (e.g. ``CALLSCOPE_TSHARK=/opt/wireshark/bin/tshark``).
    """
    override = os.environ.get(f"CALLSCOPE_{name.upper()}")
    if override and Path(override).exists():
        return str(Path(override))
    return shutil.which(name)


def find_tshark() -> str | None:
    return find_executable("tshark")


def find_mergecap() -> str | None:
    return find_executable("mergecap")


def tool_available(name: str) -> bool:
    return find_executable(name) is not None


def _query_version(executable_path: str) -> str | None:
    """Run ``<tool> --version`` and return the first version-like token."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed args, shell=False
            [executable_path, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = f"{result.stdout}\n{result.stderr}"
    match = _VERSION_RE.search(output)
    return match.group(1) if match else None


def get_tool_version(name: str) -> str | None:
    path = find_executable(name)
    if path is None:
        return None
    return _query_version(path)


def get_tshark_version() -> str | None:
    return get_tool_version("tshark")


def get_mergecap_version() -> str | None:
    return get_tool_version("mergecap")


def normalize_path(path: str | os.PathLike[str]) -> Path:
    """Expand user (~) and environment variables, then resolve to absolute.

    Uses ``strict=False`` so non-existent output paths still normalize.
    """
    expanded = os.path.expandvars(os.path.expanduser(str(path)))
    return Path(expanded).resolve(strict=False)


__all__ = [
    "find_executable",
    "find_tshark",
    "find_mergecap",
    "tool_available",
    "get_tool_version",
    "get_tshark_version",
    "get_mergecap_version",
    "normalize_path",
]
