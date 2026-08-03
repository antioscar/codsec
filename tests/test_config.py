from __future__ import annotations
import tempfile
from pathlib import Path

import yaml

from src.config import load_config, merge_exclude_dirs


def test_load_config_defaults():
    config = load_config()
    assert "exclude_dirs" in config
    assert "exclude_files" in config
    assert "min_severity" in config
    assert "enabled_rules" in config


def test_load_config_custom():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "settings.yaml"
        cfg_path.write_text(
            "exclude_dirs:\n  - custom_dir\n  - another\nmin_severity: high\n"
        )
        config = load_config(str(cfg_path))
        assert config["exclude_dirs"] == ["custom_dir", "another"]
        assert config["min_severity"] == "high"


def test_load_config_missing():
    config = load_config("/nonexistent/settings.yaml")
    assert config == {}


def test_merge_exclude_dirs():
    config = {"exclude_dirs": ["dir_a", "dir_b"]}
    cli = {"dir_c", "dir_d"}
    result = merge_exclude_dirs(config, cli)
    assert result == {"dir_a", "dir_b", "dir_c", "dir_d"}


def test_merge_exclude_dirs_no_cli():
    config = {"exclude_dirs": ["dir_a"]}
    result = merge_exclude_dirs(config, None)
    assert result == {"dir_a"}


def test_merge_exclude_dirs_no_config():
    config = {}
    cli = {"dir_x"}
    result = merge_exclude_dirs(config, cli)
    assert result == {"dir_x"}
