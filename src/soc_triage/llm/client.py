import json
import logging

import requests

from soc_triage.config import LLM_TIMEOUT_S, OLLAMA_MODEL, OLLAMA_URL

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """The model server could not be reached or returned an error."""


def call_llm(system, user, model=OLLAMA_MODEL):
    """Return the model's raw text. Prompts are not logged: they contain evidence."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": "json",  # asks Ollama to constrain output to valid JSON
        "options": {"temperature": 0, "seed": 0, "num_ctx": 4096},
    }
    try:
        r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=LLM_TIMEOUT_S)
        r.raise_for_status()
    except requests.RequestException as e:
        raise LLMError(f"Ollama request failed ({type(e).__name__}). Is `ollama serve` running?") from e
    return r.json()["message"]["content"]


def parse_json(text):
    """Strip code fences if present, then parse strictly. Raises ValueError on failure."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    return json.loads(text)
