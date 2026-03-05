"""ARGUS Deobfuscation Pipeline Orchestrator.

Coordinates the layered deobfuscation approach:
Layer 0: Safety checks
Layer 1: Static pattern deobfuscation
Layer 2: REMnux emulation
Layer 3: LLM analysis (fallback)

Usage:
    from argus.deobfuscate import DeobfuscationPipeline

    pipeline = DeobfuscationPipeline()
    result = pipeline.deobfuscate(content)
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from .safety import (
    SafetyConfig,
    SafetyCheck,
    detect_environment,
    verify_safety,
    print_safety_warning,
    Environment,
)
from .static import (
    DeobfuscationResult,
    ObfuscationType,
    deobfuscate_static,
    detect_obfuscation_type,
    extract_iocs,
)
from .emulation import REMnuxEmulator, create_emulator
from .llm import LLMDeobfuscator, LLMConfig, create_llm_deobfuscator


class ScriptType(Enum):
    """Types of scripts that can be deobfuscated."""
    POWERSHELL = "powershell"
    JAVASCRIPT = "javascript"
    BATCH = "batch"
    VBA = "vba"
    PYTHON = "python"
    UNKNOWN = "unknown"


def detect_script_type(content: str, file_path: Optional[Path] = None) -> ScriptType:
    """Detect the type of script from content and filename.

    Args:
        content: Script content
        file_path: Optional file path for extension hint

    Returns:
        ScriptType enum
    """
    # Check file extension first
    if file_path:
        ext = file_path.suffix.lower()
        extension_map = {
            ".ps1": ScriptType.POWERSHELL,
            ".psm1": ScriptType.POWERSHELL,
            ".psd1": ScriptType.POWERSHELL,
            ".js": ScriptType.JAVASCRIPT,
            ".jse": ScriptType.JAVASCRIPT,
            ".bat": ScriptType.BATCH,
            ".cmd": ScriptType.BATCH,
            ".vbs": ScriptType.VBA,
            ".vba": ScriptType.VBA,
            ".py": ScriptType.PYTHON,
        }
        if ext in extension_map:
            return extension_map[ext]

    content_lower = content.lower()

    # PowerShell indicators
    ps_indicators = [
        "$", "function ", "param(", "invoke-", "new-object",
        "write-host", "get-", "set-", "-encodedcommand",
        "[system.", "add-type", "import-module",
    ]
    if any(ind in content_lower for ind in ps_indicators):
        return ScriptType.POWERSHELL

    # JavaScript indicators
    js_indicators = [
        "var ", "let ", "const ", "function(", "=>",
        "document.", "window.", "eval(", "wscript.",
        "activexobject", "new xmlhttprequest",
    ]
    if any(ind in content_lower for ind in js_indicators):
        return ScriptType.JAVASCRIPT

    # Batch indicators
    batch_indicators = [
        "@echo", "set ", "%~", "goto ", "::", "rem ",
        "if exist", "for /", "call ", "start /",
    ]
    if any(ind in content_lower for ind in batch_indicators):
        return ScriptType.BATCH

    # VBA indicators
    vba_indicators = [
        "sub ", "dim ", "private sub", "public function",
        "createobject(", "wscript.shell", "shell.application",
    ]
    if any(ind in content_lower for ind in vba_indicators):
        return ScriptType.VBA

    return ScriptType.UNKNOWN


@dataclass
class PipelineResult:
    """Result from the deobfuscation pipeline."""

    success: bool
    script_type: ScriptType
    layers_attempted: list[str] = field(default_factory=list)
    layer_results: dict[str, DeobfuscationResult] = field(default_factory=dict)
    final_result: Optional[DeobfuscationResult] = None
    all_iocs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def decoded_content(self) -> Optional[str]:
        """Get the final decoded content."""
        if self.final_result and self.final_result.decoded:
            return self.final_result.decoded
        return None


class DeobfuscationPipeline:
    """Orchestrates the layered deobfuscation approach."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        show_warnings: bool = True,
        skip_safety_warning: bool = False,
    ):
        """Initialize the deobfuscation pipeline.

        Args:
            config_path: Path to argus.yaml
            show_warnings: Whether to print warnings
            skip_safety_warning: Skip the initial safety warning banner
        """
        self.config_path = config_path

        # Load configuration
        if config_path:
            self.safety_config = SafetyConfig.from_yaml(config_path)
            self.llm_config = LLMConfig.from_yaml(config_path)
        else:
            self.safety_config = SafetyConfig()
            self.llm_config = LLMConfig()

        # Layer 0: Safety verification
        if show_warnings and not skip_safety_warning:
            self.environment = detect_environment()
            if self.environment == Environment.LOCAL_ENDPOINT:
                print_safety_warning()

        self.safety_check = verify_safety(self.safety_config, verbose=show_warnings)

        # Initialize components that are available
        self.emulator = create_emulator(self.safety_config, self.safety_check)
        self.llm_deobfuscator = create_llm_deobfuscator(config_path)

        self.show_warnings = show_warnings

    def deobfuscate(
        self,
        content: str,
        file_path: Optional[Path] = None,
        force_llm: bool = False,
        skip_emulation: bool = False,
    ) -> PipelineResult:
        """Deobfuscate content using the layered approach.

        Args:
            content: Content to deobfuscate
            file_path: Optional file path for type detection
            force_llm: Force use of LLM (skip other layers)
            skip_emulation: Skip emulation layer

        Returns:
            PipelineResult with deobfuscation results
        """
        script_type = detect_script_type(content, file_path)

        result = PipelineResult(
            success=False,
            script_type=script_type,
        )

        # Track all IOCs found
        all_iocs = set()

        # Force LLM if requested
        if force_llm:
            if self.llm_deobfuscator:
                llm_result = self.llm_deobfuscator.deobfuscate(content)
                result.layers_attempted.append("llm")
                result.layer_results["llm"] = llm_result

                if llm_result.success:
                    result.success = True
                    result.final_result = llm_result
                    all_iocs.update(llm_result.iocs_found)
            else:
                result.warnings.append("LLM deobfuscation requested but not available")

            result.all_iocs = list(all_iocs)
            return result

        # Layer 1: Static deobfuscation
        static_result = deobfuscate_static(content)
        result.layers_attempted.append("static")
        result.layer_results["static"] = static_result

        if static_result.success:
            all_iocs.update(static_result.iocs_found)

            # Check if result needs further deobfuscation
            if static_result.decoded:
                remaining_obfuscation = detect_obfuscation_type(static_result.decoded)
                if remaining_obfuscation == [ObfuscationType.UNKNOWN]:
                    # Fully deobfuscated
                    result.success = True
                    result.final_result = static_result
                    result.all_iocs = list(all_iocs)
                    return result

                # Continue to next layer with decoded content
                content = static_result.decoded

        # Layer 2: Emulation (if available and not skipped)
        if not skip_emulation and self.emulator:
            emulation_result = self._run_emulation(content, script_type)
            result.layers_attempted.append("emulation")
            result.layer_results["emulation"] = emulation_result

            if emulation_result.success:
                all_iocs.update(emulation_result.iocs_found)

                # Check if fully deobfuscated
                if emulation_result.decoded:
                    remaining = detect_obfuscation_type(emulation_result.decoded)
                    if remaining == [ObfuscationType.UNKNOWN]:
                        result.success = True
                        result.final_result = emulation_result
                        result.all_iocs = list(all_iocs)
                        return result

                    content = emulation_result.decoded

        elif skip_emulation:
            result.warnings.append("Emulation skipped by request")
        elif not self.emulator:
            result.warnings.append("Emulation not available (no sandbox)")

        # Layer 3: LLM (if available and previous layers didn't fully succeed)
        if self.llm_deobfuscator:
            llm_result = self.llm_deobfuscator.deobfuscate(content)
            result.layers_attempted.append("llm")
            result.layer_results["llm"] = llm_result

            if llm_result.success:
                all_iocs.update(llm_result.iocs_found)
                result.success = True
                result.final_result = llm_result

        elif self.llm_config.enabled:
            result.warnings.append("LLM not available (no API key)")

        # If no layer succeeded, use best partial result
        if not result.success:
            # Find best partial result
            for layer in ["emulation", "static"]:
                if layer in result.layer_results:
                    layer_result = result.layer_results[layer]
                    if layer_result.decoded:
                        result.final_result = layer_result
                        result.success = True
                        break

        result.all_iocs = list(all_iocs)
        return result

    def _run_emulation(self, content: str, script_type: ScriptType) -> DeobfuscationResult:
        """Run appropriate emulation based on script type.

        Args:
            content: Content to emulate
            script_type: Detected script type

        Returns:
            DeobfuscationResult from emulation
        """
        if script_type == ScriptType.POWERSHELL:
            return self.emulator.deobfuscate_powershell(content)

        elif script_type == ScriptType.JAVASCRIPT:
            return self.emulator.deobfuscate_javascript(content)

        elif script_type == ScriptType.BATCH:
            return self.emulator.deobfuscate_batch(content)

        else:
            # Generic approach: try multiple emulators
            for method in [
                self.emulator.deobfuscate_powershell,
                self.emulator.deobfuscate_batch,
            ]:
                try:
                    result = method(content)
                    if result.success:
                        return result
                except Exception:
                    continue

            return DeobfuscationResult(
                success=False,
                obfuscation_type=ObfuscationType.UNKNOWN,
                original=content,
                warnings=[f"No emulator available for script type: {script_type.value}"],
                layer="emulation",
            )

    def deobfuscate_file(self, file_path: Path) -> PipelineResult:
        """Deobfuscate a file.

        Args:
            file_path: Path to file to deobfuscate

        Returns:
            PipelineResult with deobfuscation results
        """
        content = file_path.read_text(errors='replace')
        return self.deobfuscate(content, file_path=file_path)

    def get_capabilities(self) -> dict:
        """Get current pipeline capabilities.

        Returns:
            Dict describing available capabilities
        """
        return {
            "environment": self.safety_check.environment.value,
            "static_analysis": True,
            "local_emulation": self.safety_check.can_local_emulation,
            "remote_emulation": self.safety_check.can_remote_emulation,
            "llm_analysis": self.llm_deobfuscator is not None,
            "sandbox_configured": self.safety_config.sandbox_host is not None,
        }


def quick_deobfuscate(content: str) -> Optional[str]:
    """Quick deobfuscation using only static methods.

    Safe to run anywhere, no external dependencies.

    Args:
        content: Content to deobfuscate

    Returns:
        Decoded content or None
    """
    result = deobfuscate_static(content)
    if result.success:
        return result.all_decoded_content()
    return None
