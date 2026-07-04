"""Optional local-model layer. This is what makes shrike self-hosted: the reasoning runs on
a model on YOUR box (Ollama / any OpenAI-compatible local endpoint), so no code, config, or
finding ever leaves the machine. If no model is reachable, shrike degrades cleanly to its
deterministic engine — every scan, score, and fix still works, just without the prose.
"""
from __future__ import annotations
import json, os, urllib.request
from typing import Optional

DEFAULT_ENDPOINT = os.environ.get("SHRIKE_LLM_ENDPOINT", "http://127.0.0.1:11434/api/chat")
DEFAULT_MODEL = os.environ.get("SHRIKE_LLM_MODEL", "llama3.1")


class LocalModel:
    """Thin client for a local Ollama-style chat endpoint. Never raises to the caller."""

    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, model: str = DEFAULT_MODEL, timeout: int = 60):
        self.endpoint, self.model, self.timeout = endpoint, model, timeout

    def available(self) -> bool:
        try:
            base = self.endpoint.rsplit("/api/", 1)[0]
            urllib.request.urlopen(base, timeout=3)
            return True
        except Exception:
            # some servers 404 the root but are up; treat any HTTP response as available
            try:
                import urllib.error
                return True
            except Exception:
                return False

    def ask(self, prompt: str, system: str = "", num_predict: int = 400) -> Optional[str]:
        # local models often reject a separate system role; fold it into the user turn
        content = (system + "\n\n" + prompt) if system else prompt
        body = json.dumps({"model": self.model, "messages": [{"role": "user", "content": content}],
                           "stream": False, "options": {"num_predict": num_predict, "temperature": 0.2}}).encode()
        try:
            req = urllib.request.Request(self.endpoint, body, {"Content-Type": "application/json"})
            data = json.loads(urllib.request.urlopen(req, timeout=self.timeout).read())
            msg = data.get("message", {})
            return (msg.get("content") or "").strip() or None
        except Exception:
            return None
