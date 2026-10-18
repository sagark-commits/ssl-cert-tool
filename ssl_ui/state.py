"""Remembers non-secret choices (paths, hosts, switches) between sessions. Never stores passwords."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

SECRET_HINTS = ("pass", "secret", "token")


def default_state_path() -> Path:
    return Path.home() / ".ssl-auto" / "studio.json"


class UiState:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self.data: Dict[str, Any] = {}
        if self.path and self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, ValueError):
                self.data = {}

    def get(self, key: str, default: Any = "") -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        if any(hint in key.lower() for hint in SECRET_HINTS):
            raise ValueError(f"refusing to persist {key!r}: secrets are never saved")
        if isinstance(value, Path):
            value = str(value)
        if self.data.get(key) == value:
            return
        self.data[key] = value
        self.save()

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass  # remembering is a convenience, never a failure
