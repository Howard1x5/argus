"""Base agent framework for ARGUS LLM agents.

Provides common functionality for all LLM-powered analysis agents.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from argus.config import get_api_key


@dataclass
class AgentResult:
    """Result from an agent run."""
    agent_name: str
    run_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[dict] = field(default_factory=list)
    claims: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    token_usage: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "run_time": self.run_time,
            "findings": self.findings,
            "claims": self.claims,
            "warnings": self.warnings,
            "errors": self.errors,
            "token_usage": self.token_usage,
        }
    
    def add_finding(self, finding: dict) -> None:
        self.findings.append(finding)
    
    def add_claim(self, claim: dict) -> None:
        self.claims.append(claim)


class BaseAgent(ABC):
    """Base class for all ARGUS LLM agents."""
    
    name: str = "base_agent"
    description: str = "Base agent"
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or get_api_key("ANTHROPIC_API_KEY")
        self._client = None
    
    @property
    def client(self):
        """Lazy load Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package required: pip install anthropic")
        return self._client
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent."""
        pass
    
    @abstractmethod
    def build_user_prompt(self, context: dict) -> str:
        """Build the user prompt from context data."""
        pass
    
    # Define which extraction keys each agent type cares about
    # Override in subclass to customize
    relevant_extraction_keys: list[str] = ["extraction_summary"]

    def format_extraction_context(self, context: dict, max_chars: int = 8000) -> str:
        """Format extraction results for inclusion in agent prompt.

        Agents receive pre-analyzed data from ForensicExtractor (100% coverage).
        This method formats relevant extractions for the prompt.
        """
        extraction_results = context.get("extraction_results", {})
        if not extraction_results:
            return ""

        parts = []
        parts.append("## PRE-EXTRACTED FINDINGS (100% evidence coverage)")
        parts.append("The following data was extracted programmatically from ALL evidence.")
        parts.append("This is comprehensive — you are seeing everything, not a sample.")
        parts.append("")

        # Always include extraction summary if available
        summary = extraction_results.get("extraction_summary", {})
        if summary:
            parts.append("### Extraction Summary")
            summary_str = json.dumps(summary, indent=2, default=str)
            if len(summary_str) > 3000:
                summary_str = summary_str[:3000] + "\n... [truncated]"
            parts.append(summary_str)
            parts.append("")

        # Include extractions relevant to this agent
        keys_to_include = self.relevant_extraction_keys
        if "ALL" in keys_to_include:
            keys_to_include = list(extraction_results.keys())

        total_chars = len("\n".join(parts))
        for key in keys_to_include:
            if key == "extraction_summary":
                continue  # Already included above
            if key in extraction_results:
                data = extraction_results[key]
                data_str = json.dumps(data, indent=2, default=str)

                # Check if adding this would exceed limit
                if total_chars + len(data_str) > max_chars:
                    # Truncate this extraction
                    remaining = max_chars - total_chars - 100
                    if remaining > 500:
                        data_str = data_str[:remaining] + "\n... [truncated]"
                    else:
                        continue  # Skip if not enough room

                parts.append(f"### {key}")
                parts.append(data_str)
                parts.append("")
                total_chars += len(data_str) + len(key) + 10

        return "\n".join(parts)

    def chunk_events(self, events: list[dict], max_chars: int = 50000) -> list[list[dict]]:
        """Split events into chunks that fit token limits."""
        chunks = []
        current_chunk = []
        current_size = 0
        
        for event in events:
            event_str = json.dumps(event, default=str)
            event_size = len(event_str)
            
            if current_size + event_size > max_chars:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = [event]
                current_size = event_size
            else:
                current_chunk.append(event)
                current_size += event_size
        
        if current_chunk:
            chunks.append(current_chunk)
        
        return chunks
    
    def call_llm(self, user_prompt: str, max_retries: int = 5) -> tuple[str, dict]:
        """Make an LLM API call with rate limit handling.

        Returns:
            Tuple of (response_text, token_usage_dict)
        """
        import time
        import re

        last_error = None

        for attempt in range(max_retries):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=self.get_system_prompt(),
                    messages=[{"role": "user", "content": user_prompt}],
                )

                token_usage = {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                }

                return response.content[0].text, token_usage

            except Exception as e:
                last_error = e
                error_str = str(e)

                # Check if it's a rate limit error
                if "rate_limit" in error_str.lower() or "429" in error_str:
                    # Calculate backoff: 60s, 90s, 120s, 150s, 180s
                    wait_time = 60 + (attempt * 30)

                    # Try to extract retry-after from error message
                    retry_match = re.search(r'retry.?after[:\s]+(\d+)', error_str, re.I)
                    if retry_match:
                        wait_time = int(retry_match.group(1)) + 5

                    if attempt < max_retries - 1:
                        time.sleep(wait_time)
                        continue

                # For non-rate-limit errors, don't retry
                raise

        # If we exhausted retries, raise the last error
        raise last_error
    
    def parse_json_response(self, response: str) -> dict:
        """Extract JSON from LLM response."""
        # Try to find JSON in response
        import re
        
        # Look for JSON block
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try to find raw JSON object/array
        json_match = re.search(r'(\{[\s\S]*\}|\[[\s\S]*\])', response)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Return as wrapped text
        return {"raw_response": response}
    
    def run(self, context: dict) -> AgentResult:
        """Run the agent on the given context.
        
        Args:
            context: Dict containing events, scan_results, etc.
            
        Returns:
            AgentResult with findings
        """
        result = AgentResult(agent_name=self.name)
        
        try:
            user_prompt = self.build_user_prompt(context)
            response_text, token_usage = self.call_llm(user_prompt)
            result.token_usage = token_usage
            
            # Parse response
            parsed = self.parse_json_response(response_text)
            
            # Extract findings
            if isinstance(parsed, dict):
                if "findings" in parsed:
                    for finding in parsed["findings"]:
                        result.add_finding(finding)
                if "claims" in parsed:
                    for claim in parsed["claims"]:
                        result.add_claim(claim)
                if "raw_response" in parsed:
                    result.warnings.append("Could not parse structured response")
                    result.add_finding({"raw": parsed["raw_response"]})
            
        except Exception as e:
            result.errors.append(str(e))
        
        return result
