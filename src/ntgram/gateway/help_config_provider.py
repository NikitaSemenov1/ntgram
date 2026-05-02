from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _default_help_config_path() -> Path:
    """Path to the bundled ntgram/config/help_get_config.json."""
    return Path(__file__).resolve().parents[3] / "config" / "help_get_config.json"


class HelpConfigProvider:
    """Lazy loader for help.getConfig JSON payload."""

    __slots__ = ("_path_override", "_cached")

    def __init__(self, path: str | Path | None = None) -> None:
        if isinstance(path, str):
            path = path.strip() or None
        self._path_override: Path | None = Path(path) if path else None
        self._cached: dict[str, Any] | None = None

    @property
    def path(self) -> Path:
        return self._path_override or _default_help_config_path()

    def load(self) -> dict[str, Any]:
        """Return the cached config TL payload, reading from disk on first use."""
        if self._cached is not None:
            return self._cached
        path = self.path
        if not path.is_file():
            raise FileNotFoundError(f"help.getConfig JSON not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("help_get_config.json must decode to a JSON object")
        if data.get("constructor") != "config":
            raise ValueError('help_get_config.json must have "constructor": "config"')
        self._cached = data
        return data
