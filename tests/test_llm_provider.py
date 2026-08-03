from __future__ import annotations
import os
import tempfile
from pathlib import Path


def test_load_llm_config_defaults():
    from src.llm.provider import load_llm_config, LLMConfig

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "llm.yaml")
        config = load_llm_config(cfg_path)
        assert isinstance(config, LLMConfig)
        assert config.provider == "ollama"
        assert config.base_url == "http://localhost:11434"
        assert config.model == "qwen2.5-coder"


def test_load_llm_config_ollama():
    import yaml
    from src.llm.provider import load_llm_config, LLMConfig

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "provider": "ollama",
            "base_url": "http://gpu2:11434",
            "model": "codellama:7b",
            "timeout": 30,
            "temperature": 0.2,
        }
        cfg_path = os.path.join(tmp, "llm.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        config = load_llm_config(cfg_path)
        assert config.provider == "ollama"
        assert config.base_url == "http://gpu2:11434"
        assert config.model == "codellama:7b"
        assert config.timeout == 30
        assert config.temperature == 0.2


def test_load_llm_config_openai():
    import yaml
    from src.llm.provider import load_llm_config

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "provider": "openai_compatible",
            "openai_compatible": {
                "base_url": "https://api.groq.com/openai/v1",
                "model": "llama3-70b",
                "api_key_env": "GROQ_API_KEY",
            },
        }
        cfg_path = os.path.join(tmp, "llm.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        config = load_llm_config(cfg_path)
        assert config.provider == "openai_compatible"
        assert config.openai_base_url == "https://api.groq.com/openai/v1"
        assert config.openai_model == "llama3-70b"
        assert config.api_key_env == "GROQ_API_KEY"


def test_get_features():
    import yaml
    from src.llm.provider import get_features

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "features": {
                "verify": False,
                "semantic": True,
                "remediation": False,
            }
        }
        cfg_path = os.path.join(tmp, "llm.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        features = get_features(cfg_path)
        assert features == {"verify": False, "semantic": True, "remediation": False}


def test_get_features_defaults():
    from src.llm.provider import get_features

    features = get_features("/nonexistent/path")
    assert features == {"verify": True, "semantic": True, "remediation": True}


def test_is_llm_enabled():
    import yaml
    from src.llm.provider import is_llm_enabled

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "llm.yaml")

        assert is_llm_enabled(cfg_path) is False

        with open(cfg_path, "w") as f:
            yaml.dump({"enabled": True}, f)

        assert is_llm_enabled(cfg_path) is True


def test_get_llm_caps():
    import yaml
    from src.llm.provider import get_llm_caps

    with tempfile.TemporaryDirectory() as tmp:
        cfg = {
            "max_verify_findings": 50,
            "max_semantic_files": 10,
        }
        cfg_path = os.path.join(tmp, "llm.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        caps = get_llm_caps(cfg_path)
        assert caps == {"max_verify_findings": 50, "max_semantic_files": 10}


def test_get_llm_caps_defaults():
    from src.llm.provider import get_llm_caps

    caps = get_llm_caps("/nonexistent/path")
    assert caps == {"max_verify_findings": 30, "max_semantic_files": 20}
