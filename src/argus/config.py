"""Configuration management for ARGUS.

Handles loading, saving, and accessing user configuration.
API keys are stored as environment variable references, never plaintext.
"""

import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml


ARGUS_HOME = Path.home() / ".argus"
CONFIG_FILE = ARGUS_HOME / "config.yaml"
CASES_LOG = ARGUS_HOME / "cases.log"
PATTERN_LIBRARY = ARGUS_HOME / "pattern_library"


DEFAULT_CONFIG = {
    "api_keys": {
        "anthropic": "${ANTHROPIC_API_KEY}",
        "virustotal": "${VIRUSTOTAL_API_KEY}",
        "abuseipdb": "${ABUSEIPDB_API_KEY}",
        "shodan": "${SHODAN_API_KEY}",
        "alienvault_otx": "${ALIENVAULT_OTX_KEY}",
    },
    "defaults": {
        "max_cost_per_case": 15.00,
        "timestamp_tolerance": 2,
        "max_tokens_per_call": 8000,
        "verbosity": "normal",
    },
    "preferences": {
        "auto_detect_systems": True,
        "generate_figures": True,
        "pdf_watermark": "CONFIDENTIAL",
    },
}


def ensure_argus_home() -> None:
    """Ensure ~/.argus/ directory structure exists."""
    ARGUS_HOME.mkdir(exist_ok=True)
    PATTERN_LIBRARY.mkdir(exist_ok=True)
    (ARGUS_HOME / "lessons_learned").mkdir(exist_ok=True)

    # Create cases.log if it doesn't exist
    if not CASES_LOG.exists():
        with open(CASES_LOG, "w") as f:
            f.write("# ARGUS Case Registry\n")
            f.write("# Format: case_name | path | date_created | status\n")
            f.write("# Status: initialized | in_progress | completed | archived\n")

    # Create pattern library files if they don't exist
    custom_regex = PATTERN_LIBRARY / "custom_regex.yaml"
    if not custom_regex.exists():
        with open(custom_regex, "w") as f:
            yaml.dump({"patterns": []}, f)

    false_positives = PATTERN_LIBRARY / "false_positives.yaml"
    if not false_positives.exists():
        with open(false_positives, "w") as f:
            yaml.dump({"false_positives": []}, f)


def load_config() -> dict:
    """Load configuration from ~/.argus/config.yaml.

    Returns default config if file doesn't exist.
    """
    ensure_argus_home()

    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()

    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f) or {}

    # Merge with defaults for any missing keys
    merged = DEFAULT_CONFIG.copy()
    for section, values in config.items():
        if section in merged and isinstance(merged[section], dict):
            merged[section].update(values)
        else:
            merged[section] = values

    return merged


def save_config(config: dict) -> None:
    """Save configuration to ~/.argus/config.yaml."""
    ensure_argus_home()

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def resolve_env_var(value: str) -> Optional[str]:
    """Resolve environment variable reference like ${VAR_NAME}.

    Returns None if the env var is not set.
    """
    if not isinstance(value, str):
        return value

    match = re.match(r"^\$\{([^}]+)\}$", value)
    if match:
        var_name = match.group(1)
        return os.environ.get(var_name)

    return value


def get_api_key(key_name: str) -> Optional[str]:
    """Get an API key by name, resolving environment variable reference.

    Args:
        key_name: One of 'anthropic', 'virustotal', 'abuseipdb', 'shodan', 'alienvault_otx'

    Returns:
        The API key value, or None if not configured/set.
    """
    config = load_config()
    api_keys = config.get("api_keys", {})
    key_ref = api_keys.get(key_name)

    if not key_ref:
        return None

    return resolve_env_var(key_ref)


def get_setting(section: str, key: str, default: Any = None) -> Any:
    """Get a configuration setting.

    Args:
        section: Config section ('defaults' or 'preferences')
        key: Setting key within the section
        default: Default value if not found

    Returns:
        The setting value or default.
    """
    config = load_config()
    return config.get(section, {}).get(key, default)


def set_api_key_env_var(key_name: str, env_var: str) -> None:
    """Set the environment variable reference for an API key.

    Args:
        key_name: The API key name (e.g., 'anthropic')
        env_var: The environment variable name (e.g., 'ANTHROPIC_API_KEY')
    """
    config = load_config()
    if "api_keys" not in config:
        config["api_keys"] = {}
    config["api_keys"][key_name] = f"${{{env_var}}}"
    save_config(config)


def check_api_keys() -> dict[str, bool]:
    """Check which API keys are configured and available.

    Returns:
        Dict mapping key names to availability (True if set, False if not).
    """
    config = load_config()
    api_keys = config.get("api_keys", {})

    status = {}
    for key_name, key_ref in api_keys.items():
        resolved = resolve_env_var(key_ref)
        status[key_name] = resolved is not None and len(resolved) > 0

    return status


def is_first_run() -> bool:
    """Check if this is the first run (no config file exists)."""
    return not CONFIG_FILE.exists()
