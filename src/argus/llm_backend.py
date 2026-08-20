"""LLM backend abstraction for ARGUS.

Two backends are available:

  subscription (default)
      Shells out to the `claude` CLI (Claude Code), which authenticates against
      a Claude subscription. No metered API charges are incurred.

  api
      The original Anthropic SDK path. Bills per token against ANTHROPIC_API_KEY.
      Kept as a fallback for environments without the CLI installed.

Select with the ARGUS_LLM_BACKEND environment variable or the `llm.backend`
key in ~/.argus/config.yaml. The environment variable wins.
"""

import json
import os
import shutil
import subprocess
from typing import Optional

from argus.config import get_api_key, load_config

DEFAULT_BACKEND = "subscription"
DEFAULT_TIMEOUT = 900

# Tools are disabled for CLI calls: ARGUS wants a text completion, not an
# agent that reads the filesystem or runs commands on its behalf.
_DISALLOWED_TOOLS = "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Task"


class LLMBackendError(RuntimeError):
    """Raised when an LLM backend cannot service a request."""


def get_backend() -> str:
    """Return the active backend name: 'subscription' or 'api'."""
    env = os.environ.get("ARGUS_LLM_BACKEND")
    if env:
        return env.strip().lower()

    try:
        cfg = load_config()
    except Exception:
        return DEFAULT_BACKEND

    return str(cfg.get("llm", {}).get("backend", DEFAULT_BACKEND)).strip().lower()


def _cli_model_arg(model: Optional[str]) -> Optional[str]:
    """Map an SDK model id to something the CLI's --model flag accepts.

    ARGUS agents carry full ids like 'claude-sonnet-4-20250514'. Passing a
    pinned, possibly-retired id to the CLI can fail, so reduce to the family
    alias, which the CLI resolves to its current version.
    """
    if not model:
        return None
    lowered = model.lower()
    for family in ("opus", "sonnet", "haiku"):
        if family in lowered:
            return family
    return model


def _subscription_env() -> dict:
    """Environment for the CLI subprocess.

    ANTHROPIC_API_KEY is deliberately stripped. If it were left in place the
    CLI could authenticate against the metered API instead of the
    subscription, which would silently defeat the entire point of this
    backend.
    """
    env = os.environ.copy()
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        env.pop(var, None)
    return env


def _call_subscription(
    prompt: str,
    system: Optional[str],
    model: Optional[str],
    timeout: int,
) -> tuple[str, dict]:
    """Call the `claude` CLI, passing the prompt on stdin."""
    exe = shutil.which("claude")
    if not exe:
        raise LLMBackendError(
            "The 'claude' CLI was not found on PATH. Install Claude Code, or "
            "select the API backend with ARGUS_LLM_BACKEND=api."
        )

    cmd = [exe, "-p", "--output-format", "json", "--disallowed-tools", _DISALLOWED_TOOLS]

    cli_model = _cli_model_arg(model)
    if cli_model:
        cmd += ["--model", cli_model]
    if system:
        cmd += ["--system-prompt", system]

    # The prompt goes on stdin, never argv: forensic context routinely runs to
    # tens of kilobytes and would blow past ARG_MAX as a command-line argument.
    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_subscription_env(),
        )
    except subprocess.TimeoutExpired:
        raise LLMBackendError(
            f"The 'claude' CLI did not return within {timeout}s. Raise the timeout "
            "with ARGUS_LLM_TIMEOUT, or reduce the amount of context being sent."
        )

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:500]
        raise LLMBackendError(
            f"The 'claude' CLI exited {proc.returncode}. If this is an auth failure, "
            f"run 'claude' once interactively to sign in. Detail: {detail}"
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise LLMBackendError(
            f"Could not parse JSON from the 'claude' CLI. First 500 chars: "
            f"{proc.stdout[:500]}"
        )

    if payload.get("is_error"):
        raise LLMBackendError(f"The 'claude' CLI reported an error: {payload.get('result')}")

    text = payload.get("result")
    if not isinstance(text, str):
        raise LLMBackendError(f"Unexpected CLI payload shape: keys={list(payload)}")

    usage_block = payload.get("usage", {}) or {}
    usage = {
        "input_tokens": usage_block.get("input_tokens", 0),
        "output_tokens": usage_block.get("output_tokens", 0),
        "backend": "subscription",
        # Reported by the CLI for information. Subscription usage is not billed
        # against API credits; this is not a charge against ANTHROPIC_API_KEY.
        "reported_cost_usd": payload.get("total_cost_usd"),
    }
    return text, usage


def _call_api(
    prompt: str,
    system: Optional[str],
    model: Optional[str],
    max_tokens: int,
    max_retries: int,
) -> tuple[str, dict]:
    """Call the Anthropic SDK. Bills per token against ANTHROPIC_API_KEY."""
    import re
    import time

    try:
        import anthropic
    except ImportError:
        raise LLMBackendError("anthropic package required for the API backend: pip install anthropic")

    api_key = get_api_key("anthropic") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMBackendError(
            "No Anthropic API key available. Set ANTHROPIC_API_KEY, or use the "
            "default subscription backend (ARGUS_LLM_BACKEND=subscription)."
        )

    client = anthropic.Anthropic(api_key=api_key)
    last_error = None

    for attempt in range(max_retries):
        try:
            kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                kwargs["system"] = system

            response = client.messages.create(**kwargs)
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "backend": "api",
            }
            return response.content[0].text, usage

        except Exception as e:
            last_error = e
            error_str = str(e)
            if "rate_limit" in error_str.lower() or "429" in error_str:
                wait_time = 60 + (attempt * 30)
                retry_match = re.search(r"retry.?after[:\s]+(\d+)", error_str, re.I)
                if retry_match:
                    wait_time = int(retry_match.group(1)) + 5
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    continue
            raise

    raise last_error


def call_llm(
    prompt: str,
    system: Optional[str] = None,
    model: Optional[str] = None,
    max_tokens: int = 4096,
    timeout: Optional[int] = None,
    max_retries: int = 5,
) -> tuple[str, dict]:
    """Send a prompt to the active LLM backend.

    Returns:
        (response_text, usage_dict). usage_dict always carries a 'backend' key
        so callers can tell which path served the request.
    """
    backend = get_backend()

    if backend == "subscription":
        if timeout is None:
            timeout = int(os.environ.get("ARGUS_LLM_TIMEOUT", DEFAULT_TIMEOUT))
        return _call_subscription(prompt, system, model, timeout)

    if backend == "api":
        return _call_api(prompt, system, model, max_tokens, max_retries)

    raise LLMBackendError(
        f"Unknown LLM backend {backend!r}. Valid values: 'subscription', 'api'."
    )


def backend_available() -> tuple[bool, str]:
    """Check whether the active backend can service requests.

    Returns:
        (available, human_readable_reason)
    """
    backend = get_backend()

    if backend == "subscription":
        if not shutil.which("claude"):
            return False, "the 'claude' CLI is not on PATH"
        return True, "using the 'claude' CLI (subscription, no API charges)"

    if backend == "api":
        if get_api_key("anthropic") or os.environ.get("ANTHROPIC_API_KEY"):
            return True, "using the Anthropic API (billed per token)"
        return False, "ANTHROPIC_API_KEY is not set"

    return False, f"unknown backend {backend!r}"
