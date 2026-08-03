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


def test_llm_client_constructor():
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(provider="ollama", model="test-model")
    client = LLMClient(config)
    assert client.config is config
    assert client._client is None


def test_llm_client_get_client_lazy():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig()
    with patch("src.llm.provider.httpx.Client") as mock_httpx:
        client = LLMClient(config)
        c1 = client._get_client()
        c2 = client._get_client()
        assert c1 is c2
        assert mock_httpx.call_count == 1


def test_llm_client_close_when_none():
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig()
    client = LLMClient(config)
    client.close()


def test_llm_client_close_then_recreate():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig()
    with patch("src.llm.provider.httpx.Client") as mock_httpx:
        client = LLMClient(config)
        client._get_client()
        client.close()
        client._get_client()
        assert mock_httpx.call_count == 2


def test_llm_client_chat_dispatches():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(provider="ollama")
    client = LLMClient(config)
    with patch.object(client, "_chat_ollama", return_value="ollama response") as mock_ollama, \
         patch.object(client, "_chat_openai_compatible", return_value="openai response") as mock_openai:
        result = client.chat([{"role": "user", "content": "hi"}])
        assert result == "ollama response"
        mock_ollama.assert_called_once()
        mock_openai.assert_not_called()

    config2 = LLMConfig(provider="openai_compatible")
    client2 = LLMClient(config2)
    with patch.object(client2, "_chat_ollama", return_value="ollama response") as mock_ollama2, \
         patch.object(client2, "_chat_openai_compatible", return_value="openai response") as mock_openai2:
        result = client2.chat([{"role": "user", "content": "hi"}])
        assert result == "openai response"
        mock_openai2.assert_called_once()
        mock_ollama2.assert_not_called()


def test_llm_client_chat_ollama():
    from unittest.mock import MagicMock, patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig()
    client = LLMClient(config)
    mock_post = MagicMock()
    mock_post.json.return_value = {"message": {"content": "Hello from ollama"}}
    mock_httpx_client = MagicMock()
    mock_httpx_client.post.return_value = mock_post
    with patch.object(client, "_get_client", return_value=mock_httpx_client):
        result = client._chat_ollama([{"role": "user", "content": "hi"}], 0.1)
        assert result == "Hello from ollama"
        mock_httpx_client.post.assert_called_once()


def test_llm_client_chat_openai_compatible():
    from unittest.mock import MagicMock, patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(provider="openai_compatible", api_key_env="TEST_KEY")
    client = LLMClient(config)
    mock_post = MagicMock()
    mock_post.json.return_value = {"choices": [{"message": {"content": "Hello from openai"}}]}
    mock_httpx_client = MagicMock()
    mock_httpx_client.post.return_value = mock_post
    with patch.object(client, "_get_client", return_value=mock_httpx_client), \
         patch.object(client, "_resolve_api_key", return_value="test-api-key"):
        result = client._chat_openai_compatible([{"role": "user", "content": "hi"}], 0.1)
        assert result == "Hello from openai"
        mock_httpx_client.post.assert_called_once()


def test_llm_client_is_available_ollama():
    from unittest.mock import MagicMock, patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(provider="ollama")
    client = LLMClient(config)
    mock_get = MagicMock()
    mock_httpx_client = MagicMock()
    mock_httpx_client.get.return_value = mock_get
    with patch.object(client, "_get_client", return_value=mock_httpx_client):
        result = client.is_available()
        assert result is True
        mock_httpx_client.get.assert_called_once_with(
            f"{config.base_url}/api/tags"
        )


def test_llm_client_is_available_openai():
    from unittest.mock import MagicMock, patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(provider="openai_compatible", api_key_env="TEST_KEY")
    client = LLMClient(config)
    mock_get = MagicMock()
    mock_httpx_client = MagicMock()
    mock_httpx_client.get.return_value = mock_get
    with patch.object(client, "_get_client", return_value=mock_httpx_client), \
         patch.dict(os.environ, {"TEST_KEY": "test-key"}):
        result = client.is_available()
        assert result is True
        mock_httpx_client.get.assert_called_once()


def test_llm_client_resolve_api_key_from_env():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(api_key_env="MY_API_KEY")
    client = LLMClient(config)
    with patch.dict(os.environ, {"MY_API_KEY": "test-key"}, clear=True):
        result = client._resolve_api_key()
        assert result == "test-key"


def test_llm_client_resolve_api_key_fallback():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(api_key_env="MY_API_KEY")
    client = LLMClient(config)
    with patch.dict(os.environ, {"LLM_API_KEY": "fallback-key"}, clear=True):
        result = client._resolve_api_key()
        assert result == "fallback-key"


def test_llm_client_resolve_api_key_empty():
    from unittest.mock import patch
    from src.llm.provider import LLMClient, LLMConfig

    config = LLMConfig(api_key_env="NONEXISTENT_KEY")
    client = LLMClient(config)
    with patch.dict(os.environ, {}, clear=True):
        result = client._resolve_api_key()
        assert result == ""
