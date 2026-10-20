# Author: Sagar K | 2026 | MIT licence
"""Resolve app / resource paths for source runs and frozen (PyInstaller) builds."""
from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path:
    """Read-only resources extracted by PyInstaller, or project root in source."""
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def app_dir() -> Path:
    """Writable directory next to the executable (or project root in source)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def configs_dir() -> Path:
    """User configs live next to the app so they can be edited after install."""
    return app_dir() / "configs"


def bundled_roots_dir() -> Path:
    """CA roots shipped inside the package."""
    return bundle_dir() / "ssl_cert_tool" / "bundled_roots"