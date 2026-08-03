from __future__ import annotations
from pathlib import Path
from typing import Optional

import yaml

SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"


def load_config(config_path: Optional[str] = None) -> dict:
    path = Path(config_path) if config_path else SETTINGS_PATH
    if not path.exists():
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def merge_exclude_dirs(config: dict, cli_exclude: Optional[set[str]] = None) -> set[str]:
    result: set[str] = set()

    for d in config.get("exclude_dirs", []):
        result.add(d)

    if cli_exclude:
        result.update(cli_exclude)

    return result
