"""Configuration loading and defaults for Zexec."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

# Absolute path to the project root (one level up from this file's package)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


class Config:
    """Holds runtime configuration, merging defaults with the YAML file."""

    def __init__(self, config_path: Path | None = None, overrides: dict | None = None):
        self.path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self.data: dict = {}
        self._load()
        if overrides:
            self._apply_overrides(overrides)

    def _load(self) -> None:
        if not self.path.exists():
            # Fall back to the bundled default
            bundled = PROJECT_ROOT / "config.yaml"
            self.path = bundled if bundled.exists() else self.path
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data = yaml.safe_load(fh) or {}
        else:
            self.data = {}

    def _apply_overrides(self, overrides: dict) -> None:
        for key, value in overrides.items():
            if value is None:
                continue
            # Support dotted keys like "safety.password_spray.enabled"
            if "." in key:
                section, rest = key.split(".", 1)
                self.data.setdefault(section, {})
                self._set_dotted(self.data[section], rest, value)
            else:
                self.data[key] = value

    @staticmethod
    def _set_dotted(d: dict, dotted: str, value) -> None:
        parts = dotted.split(".")
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = value

    def get(self, dotted_key: str, default=None):
        """Return a nested config value by dotted key."""
        node = self.data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict:
        return self.data.get(name, {}) or {}

    def __getitem__(self, key: str):
        return self.data[key]

    def __contains__(self, key: str) -> bool:
        return key in self.data

    def deep_copy(self) -> dict:
        return copy.deepcopy(self.data)


def load_config(config_path: str | None = None, overrides: dict | None = None) -> Config:
    path = Path(config_path) if config_path else None
    return Config(config_path=path, overrides=overrides)
