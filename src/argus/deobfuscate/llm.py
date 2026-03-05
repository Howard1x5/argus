"""ARGUS LLM-Assisted Deobfuscation Module.

Layer 3: Use Claude API for complex/novel obfuscation techniques.

This is the fallback layer when static and emulation methods fail.
It's the most powerful but also most expensive approach.

Cost controls:
- Only triggered when Layer 1 & 2 fail
- Token limits on input/output
- Caching of results
- Can be disabled in configuration
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .static import DeobfuscationResult, ObfuscationType, extract_iocs


@dataclass
class LLMConfig:
    """Configuration for LLM deobfuscation."""

    enabled: bool = True
    api_key_env: str = "ANTHROPIC_API_KEY"

    # Cost controls
    max_input_tokens: int = 4000  # Max tokens to send
    max_output_tokens: int = 2000  # Max response tokens
    cache_results: bool = True
    cache_dir: Optional[Path] = None

    # Model selection
    model: str = "claude-sonnet-4-20250514"  # Fast and capable

    @classmethod
    def from_yaml(cls, config_path: Path) -> "LLMConfig":
        """Load LLM config from argus.yaml."""
        import yaml

        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            config = yaml.safe_load(f) or {}

        llm_config = config.get("deobfuscate", {}).get("llm", {})

        cache_dir = llm_config.get("cache_dir")
        if cache_dir:
            cache_dir = Path(cache_dir)

        return cls(
            enabled=llm_config.get("enabled", True),
            api_key_env=llm_config.get("api_key_env", "ANTHROPIC_API_KEY"),
            max_input_tokens=llm_config.get("max_input_tokens", 4000),
            max_output_tokens=llm_config.get("max_output_tokens", 2000),
            cache_results=llm_config.get("cache_results", True),
            cache_dir=cache_dir,
            model=llm_config.get("model", "claude-sonnet-4-20250514"),
        )


DEOBFUSCATION_PROMPT = """You are a malware analyst expert at deobfuscating malicious scripts.

Analyze the following obfuscated code and:
1. Identify the obfuscation technique(s) used
2. Decode/deobfuscate the content step by step
3. Extract any IOCs (IPs, domains, URLs, file paths, registry keys)
4. Describe what the deobfuscated code does

IMPORTANT: Your response must be valid JSON with this structure:
{
  "obfuscation_techniques": ["list of techniques identified"],
  "deobfuscation_steps": ["step 1", "step 2", ...],
  "decoded_content": "the fully deobfuscated code or content",
  "iocs": {
    "ips": ["list of IP addresses"],
    "domains": ["list of domains"],
    "urls": ["list of URLs"],
    "file_paths": ["list of file paths"],
    "registry_keys": ["list of registry keys"],
    "other": ["any other IOCs"]
  },
  "behavior_summary": "brief description of what the code does",
  "confidence": 0.0 to 1.0
}

Obfuscated code to analyze:
```
{code}
```

Respond ONLY with the JSON object, no other text."""


class LLMDeobfuscator:
    """LLM-based deobfuscation using Claude API."""

    def __init__(self, config: LLMConfig):
        """Initialize the LLM deobfuscator.

        Args:
            config: LLM configuration
        """
        self.config = config
        self._client = None

        # Setup cache directory
        if config.cache_results:
            if config.cache_dir:
                self.cache_dir = config.cache_dir
            else:
                self.cache_dir = Path.home() / ".argus" / "deobfuscate_cache"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.cache_dir = None

    @property
    def client(self):
        """Lazy-load the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                api_key = os.environ.get(self.config.api_key_env)
                if not api_key:
                    raise ValueError(f"API key not found in {self.config.api_key_env}")
                self._client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
        return self._client

    def _get_cache_key(self, content: str) -> str:
        """Generate cache key for content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _check_cache(self, content: str) -> Optional[dict]:
        """Check if result is cached."""
        if not self.cache_dir:
            return None

        cache_key = self._get_cache_key(content)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        return None

    def _save_cache(self, content: str, result: dict) -> None:
        """Save result to cache."""
        if not self.cache_dir:
            return

        cache_key = self._get_cache_key(content)
        cache_file = self.cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except IOError:
            pass

    def _truncate_content(self, content: str) -> str:
        """Truncate content to fit token limits.

        Rough estimate: 4 chars per token for code.
        """
        max_chars = self.config.max_input_tokens * 4

        if len(content) <= max_chars:
            return content

        # Truncate with indicator
        truncated = content[:max_chars - 100]
        return truncated + "\n\n[... content truncated for API limits ...]"

    def is_available(self) -> bool:
        """Check if LLM deobfuscation is available."""
        if not self.config.enabled:
            return False

        api_key = os.environ.get(self.config.api_key_env)
        return bool(api_key)

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Deobfuscate content using LLM.

        Args:
            content: Obfuscated content

        Returns:
            DeobfuscationResult with decoded content
        """
        if not self.is_available():
            return DeobfuscationResult(
                success=False,
                obfuscation_type=ObfuscationType.UNKNOWN,
                original=content,
                warnings=["LLM deobfuscation not available (no API key or disabled)"],
                layer="llm",
            )

        # Check cache
        cached = self._check_cache(content)
        if cached:
            return self._result_from_response(content, cached, from_cache=True)

        # Truncate if needed
        truncated = self._truncate_content(content)

        # Build prompt
        prompt = DEOBFUSCATION_PROMPT.format(code=truncated)

        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_output_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            # Extract text from response
            response_text = response.content[0].text

            # Parse JSON response
            try:
                result = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                json_match = response_text.find('{')
                if json_match >= 0:
                    try:
                        result = json.loads(response_text[json_match:])
                    except json.JSONDecodeError:
                        return DeobfuscationResult(
                            success=False,
                            obfuscation_type=ObfuscationType.UNKNOWN,
                            original=content,
                            decoded=response_text,
                            warnings=["LLM response was not valid JSON"],
                            layer="llm",
                        )
                else:
                    return DeobfuscationResult(
                        success=False,
                        obfuscation_type=ObfuscationType.UNKNOWN,
                        original=content,
                        decoded=response_text,
                        warnings=["LLM response was not valid JSON"],
                        layer="llm",
                    )

            # Cache the result
            self._save_cache(content, result)

            return self._result_from_response(content, result)

        except Exception as e:
            return DeobfuscationResult(
                success=False,
                obfuscation_type=ObfuscationType.UNKNOWN,
                original=content,
                warnings=[f"LLM API error: {str(e)}"],
                layer="llm",
            )

    def _result_from_response(self, original: str, response: dict,
                               from_cache: bool = False) -> DeobfuscationResult:
        """Convert LLM response to DeobfuscationResult.

        Args:
            original: Original content
            response: Parsed JSON response
            from_cache: Whether result came from cache

        Returns:
            DeobfuscationResult
        """
        decoded = response.get("decoded_content", "")
        confidence = response.get("confidence", 0.7)

        # Extract IOCs from response
        iocs = []
        ioc_data = response.get("iocs", {})

        for ioc_type in ["ips", "domains", "urls", "file_paths", "registry_keys", "other"]:
            for ioc in ioc_data.get(ioc_type, []):
                iocs.append(f"{ioc_type}:{ioc}")

        # Also extract IOCs from decoded content
        if decoded:
            iocs.extend(extract_iocs(decoded))

        iocs = list(set(iocs))  # Deduplicate

        warnings = []
        if from_cache:
            warnings.append("Result from cache")

        # Include behavior summary in decoded output
        behavior = response.get("behavior_summary", "")
        if behavior:
            decoded = f"# Behavior: {behavior}\n\n{decoded}"

        # Include deobfuscation steps
        steps = response.get("deobfuscation_steps", [])
        if steps:
            steps_text = "\n".join(f"# Step {i+1}: {s}" for i, s in enumerate(steps))
            decoded = f"{steps_text}\n\n{decoded}"

        return DeobfuscationResult(
            success=bool(decoded),
            obfuscation_type=ObfuscationType.UNKNOWN,
            original=original,
            decoded=decoded,
            confidence=confidence,
            layer="llm",
            iocs_found=iocs,
            warnings=warnings,
        )


def create_llm_deobfuscator(config_path: Optional[Path] = None) -> Optional[LLMDeobfuscator]:
    """Factory function to create LLM deobfuscator if available.

    Args:
        config_path: Path to argus.yaml

    Returns:
        LLMDeobfuscator instance or None if not available
    """
    if config_path:
        config = LLMConfig.from_yaml(config_path)
    else:
        config = LLMConfig()

    deobfuscator = LLMDeobfuscator(config)

    if deobfuscator.is_available():
        return deobfuscator

    return None
