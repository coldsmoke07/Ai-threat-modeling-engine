"""Ollama model auto-detection, fallback, and connectivity utilities.

Provides resilient model selection so pipeline scripts can run seamlessly
even if preferred model tags differ across local environments.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_PREFERRED_MODELS = [
    "qwen3:4b",
    "qwen2.5:7b",
    "qwen2.5",
    "qwen2.5:3b",
    "llama3:8b",
    "llama3",
    "mistral",
    "deepseek-r1",
]


def check_ollama_status(base_url: str = DEFAULT_OLLAMA_BASE_URL) -> tuple[bool, str]:
    """Check if Ollama service is reachable and responsive."""
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return True, "Ollama service is online."
    except urllib.error.URLError as err:
        return False, f"Could not connect to Ollama at {base_url}: {err.reason}"
    except Exception as err:
        return False, f"Ollama connection check failed: {err}"
    return False, "Ollama service returned non-200 status."


def get_available_models(base_url: str = DEFAULT_OLLAMA_BASE_URL) -> list[str]:
    """Fetch list of model names currently installed in Ollama."""
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = data.get("models", [])
            names = [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]
            return names
    except Exception:
        return []


def select_model(
    preferred_models: list[str] | None = None,
    base_url: str = DEFAULT_OLLAMA_BASE_URL,
    default_fallback: str = "qwen3:4b",
) -> str:
    """Select the best available model from installed Ollama models.
    
    Checks preferred list first, then available installed models, or defaults.
    """
    candidates = preferred_models or DEFAULT_PREFERRED_MODELS
    available = get_available_models(base_url)

    if not available:
        return candidates[0] if candidates else default_fallback

    # Match exact or base name
    for candidate in candidates:
        if candidate in available:
            return candidate
        # Check without tag or with tag matching
        cand_base = candidate.split(":")[0]
        for avail in available:
            avail_base = avail.split(":")[0]
            if cand_base == avail_base:
                return avail

    # Return first installed model if available, else preferred
    return available[0] if available else default_fallback
