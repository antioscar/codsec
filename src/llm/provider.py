from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
import yaml

LLM_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "llm.yaml"


@dataclass
class LLMConfig:
    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5-coder"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    api_key_env: str = ""
    timeout: float = 60.0
    temperature: float = 0.1


def load_llm_config(config_path: Optional[str] = None) -> LLMConfig:
    path = Path(config_path) if config_path else LLM_CONFIG_PATH
    if not path.exists():
        return LLMConfig()

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    provider = data.get("provider", "ollama")

    config = LLMConfig(
        provider=provider,
        base_url=data.get("base_url", "http://localhost:11434"),
        model=data.get("model", "qwen2.5-coder"),
        timeout=float(data.get("timeout", 60)),
        temperature=float(data.get("temperature", 0.1)),
    )

    openai_cfg = data.get("openai_compatible") or {}
    config.openai_base_url = openai_cfg.get("base_url", "https://api.openai.com/v1")
    config.openai_model = openai_cfg.get("model", "gpt-4o-mini")
    config.api_key_env = openai_cfg.get("api_key_env", "OPENAI_API_KEY")

    return config


def get_features(config: Optional[str] = None) -> dict:
    path = Path(config) if config else LLM_CONFIG_PATH
    if not path.exists():
        return {"verify": True, "semantic": True, "remediation": True}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    features = data.get("features", {})
    return {
        "verify": features.get("verify", True),
        "semantic": features.get("semantic", True),
        "remediation": features.get("remediation", True),
    }


def is_llm_enabled(config_path: Optional[str] = None) -> bool:
    path = Path(config_path) if config_path else LLM_CONFIG_PATH
    if not path.exists():
        return False
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return bool(data.get("enabled", False))


def get_llm_caps(config_path: Optional[str] = None) -> dict:
    path = Path(config_path) if config_path else LLM_CONFIG_PATH
    if not path.exists():
        return {"max_verify_findings": 30, "max_semantic_files": 20}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {
        "max_verify_findings": int(data.get("max_verify_findings", 30)),
        "max_semantic_files": int(data.get("max_semantic_files", 20)),
    }


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.config.timeout)
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def is_available(self) -> bool:
        try:
            if self.config.provider == "ollama":
                resp = self._get_client().get(
                    f"{self.config.base_url}/api/tags"
                )
                resp.raise_for_status()
            else:
                headers = {}
                api_key = self._resolve_api_key()
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                resp = self._get_client().get(
                    f"{self.config.openai_base_url}/models",
                    headers=headers,
                )
                resp.raise_for_status()
            return True
        except Exception:
            return False

    def chat(self, messages: list[dict[str, str]], temperature: Optional[float] = None) -> str:
        temp = temperature if temperature is not None else self.config.temperature

        if self.config.provider == "ollama":
            return self._chat_ollama(messages, temp)
        else:
            return self._chat_openai_compatible(messages, temp)

    def _resolve_api_key(self) -> str:
        if self.config.api_key_env:
            key = os.environ.get(self.config.api_key_env, "")
            if key:
                return key
        key = os.environ.get("LLM_API_KEY", "")
        if key:
            return key
        return ""

    def _chat_ollama(self, messages: list[dict[str, str]], temperature: float) -> str:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        resp = self._get_client().post(
            f"{self.config.base_url}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "")

    def _chat_openai_compatible(self, messages: list[dict[str, str]], temperature: float) -> str:
        api_key = self._resolve_api_key()
        headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": self.config.openai_model,
            "messages": messages,
            "temperature": temperature,
        }
        resp = self._get_client().post(
            f"{self.config.openai_base_url}/chat/completions",
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
