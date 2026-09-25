"""One function the rest of the app calls: complete(system, messages, json_mode).

LLM_PROVIDER=local (default)
    LOCAL_LLM_API=ollama  -> POST {base}/api/chat              (Ollama native API)
    LOCAL_LLM_API=openai  -> POST {base}/v1/chat/completions   (llama.cpp server, vLLM, LM Studio, ...)
LLM_PROVIDER=anthropic   -> hosted API, optional
LLM_PROVIDER=none        -> no model; callers use deterministic summaries

Why Ollama's native API rather than its OpenAI-compatible one: the native API
lets us set num_ctx per request. Ollama's default context window is small, and a
prompt that doesn't fit is silently truncated, which would drop evidence
without anyone noticing.
"""
import requests

from .. import config


class LLMError(RuntimeError):
    pass


def _local_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if config.LOCAL_LLM_API_KEY:
        h["Authorization"] = f"Bearer {config.LOCAL_LLM_API_KEY}"
    return h


def _ollama(system: str, messages: list[dict], json_mode: bool) -> str:
    body = {
        "model": config.LOCAL_LLM_MODEL,
        "messages": [{"role": "system", "content": system}] + messages,
        "stream": False,
        "options": {"num_ctx": config.LOCAL_LLM_CONTEXT, "num_predict": config.LLM_MAX_TOKENS,
                    "temperature": config.LLM_TEMPERATURE},
    }
    if json_mode:
        body["format"] = "json"
    r = requests.post(f"{config.LOCAL_LLM_BASE_URL}/api/chat", json=body, headers=_local_headers(),
                      timeout=config.LOCAL_LLM_TIMEOUT)
    if r.status_code == 404:
        raise LLMError(f"Model '{config.LOCAL_LLM_MODEL}' not found on the Ollama server. "
                       f"Run: ollama pull {config.LOCAL_LLM_MODEL}")
    r.raise_for_status()
    data = r.json()
    if data.get("done_reason") == "length":
        raise LLMError("Model output hit LLM_MAX_TOKENS before finishing")
    return data.get("message", {}).get("content", "")


def _openai_compatible(system: str, messages: list[dict], json_mode: bool) -> str:
    body = {
        "model": config.LOCAL_LLM_MODEL,
        "messages": [{"role": "system", "content": system}] + messages,
        "max_tokens": config.LLM_MAX_TOKENS,
        "temperature": config.LLM_TEMPERATURE,
        "stream": False,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    r = requests.post(f"{config.LOCAL_LLM_BASE_URL}/v1/chat/completions", json=body, headers=_local_headers(),
                      timeout=config.LOCAL_LLM_TIMEOUT)
    if r.status_code == 400 and json_mode:
        # Some servers reject response_format. Retry without it; the validator still checks the output.
        body.pop("response_format")
        r = requests.post(f"{config.LOCAL_LLM_BASE_URL}/v1/chat/completions", json=body,
                          headers=_local_headers(), timeout=config.LOCAL_LLM_TIMEOUT)
    r.raise_for_status()
    choice = r.json()["choices"][0]
    if choice.get("finish_reason") == "length":
        raise LLMError("Model output hit LLM_MAX_TOKENS before finishing")
    return choice["message"]["content"] or ""


def _anthropic(system: str, messages: list[dict], json_mode: bool) -> str:
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": config.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": config.ANTHROPIC_MODEL, "max_tokens": config.LLM_MAX_TOKENS, "system": system,
              "temperature": config.LLM_TEMPERATURE, "messages": messages},
        timeout=120)
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


def complete(system: str, messages: list[dict], json_mode: bool = False) -> str:
    if config.LLM_PROVIDER == "local":
        if config.LOCAL_LLM_API == "ollama":
            return _ollama(system, messages, json_mode)
        if config.LOCAL_LLM_API == "openai":
            return _openai_compatible(system, messages, json_mode)
        raise LLMError(f"Unknown LOCAL_LLM_API '{config.LOCAL_LLM_API}' (use ollama or openai)")
    if config.LLM_PROVIDER == "anthropic":
        return _anthropic(system, messages, json_mode)
    raise LLMError("LLM_PROVIDER is 'none'")


def context_budget_tokens() -> int:
    """How many prompt tokens we can send without the server truncating them."""
    if config.LLM_PROVIDER == "local":
        return config.LOCAL_LLM_CONTEXT - config.LLM_MAX_TOKENS
    return 100_000


def status() -> dict:
    """Quick reachability check for the dashboard. Never raises."""
    if config.LLM_PROVIDER == "none":
        return {"ok": False, "text": "No model configured (LLM_PROVIDER=none): deterministic summaries only"}
    if config.LLM_PROVIDER == "anthropic":
        return {"ok": config.llm_configured(), "text": f"Hosted model {config.ANTHROPIC_MODEL}"
                + ("" if config.llm_configured() else ", ANTHROPIC_API_KEY missing")}
    base, model = config.LOCAL_LLM_BASE_URL, config.LOCAL_LLM_MODEL
    try:
        if config.LOCAL_LLM_API == "ollama":
            r = requests.get(f"{base}/api/tags", timeout=3)
            r.raise_for_status()
            names = {m.get("name") for m in r.json().get("models", [])} | \
                    {m.get("model") for m in r.json().get("models", [])}
            present = model in names or f"{model}:latest" in names
        else:
            r = requests.get(f"{base}/v1/models", headers=_local_headers(), timeout=3)
            r.raise_for_status()
            present = model in {m.get("id") for m in r.json().get("data", [])}
    except Exception as exc:
        return {"ok": False, "text": f"Local model server at {base} is not reachable ({type(exc).__name__})"}
    if not present:
        return {"ok": False, "text": f"Local server reachable, but model '{model}' is not loaded"}
    return {"ok": True, "text": f"Local model {model} at {base}"}
