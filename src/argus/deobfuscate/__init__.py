"""ARGUS Deobfuscation Module.

Provides layered deobfuscation for malicious scripts and payloads.

Architecture:
    Layer 0: Safety checks and environment detection
    Layer 1: Static pattern-based deobfuscation
    Layer 2: Emulation-based deobfuscation (REMnux)
    Layer 3: LLM-assisted deobfuscation (Claude API)

Usage:
    from argus.deobfuscate import DeobfuscationPipeline, quick_deobfuscate

    # Full pipeline (uses all available layers)
    pipeline = DeobfuscationPipeline()
    result = pipeline.deobfuscate(obfuscated_content)
    print(result.decoded_content)
    print(result.all_iocs)

    # Quick static-only deobfuscation (safe anywhere)
    decoded = quick_deobfuscate(base64_content)

Safety:
    This module is designed with security in mind:
    - Detects if running in sandbox vs local endpoint
    - Restricts capabilities on local endpoints
    - Uses emulators (not actual execution) for scripts
    - Recommended to run on REMnux for full capabilities

Configuration (argus.yaml):
    deobfuscate:
      sandbox:
        host: "your-remnux-ip"  # e.g., 192.168.1.100
        port: 22
        user: "remnux"
      allow_local_emulation: false
      i_understand_the_risks: false
      static_only: false
      llm:
        enabled: true
        cache_results: true
"""

from .safety import (
    Environment,
    SafetyConfig,
    SafetyCheck,
    SafetyError,
    detect_environment,
    verify_safety,
    print_safety_warning,
)

from .static import (
    ObfuscationType,
    DeobfuscationResult,
    deobfuscate_static,
    detect_obfuscation_type,
    extract_iocs,
    extract_and_decode_embedded_base64,
    decode_base64,
    decode_powershell_encoded,
    decode_hex,
    decode_url,
    decode_xor_single_byte,
    decode_char_codes,
    decode_string_concat,
)

from .emulation import (
    EmulationTool,
    ToolResult,
    REMnuxEmulator,
    create_emulator,
)

from .llm import (
    LLMConfig,
    LLMDeobfuscator,
    create_llm_deobfuscator,
)

from .pipeline import (
    ScriptType,
    PipelineResult,
    DeobfuscationPipeline,
    detect_script_type,
    quick_deobfuscate,
)

__all__ = [
    # Safety
    "Environment",
    "SafetyConfig",
    "SafetyCheck",
    "SafetyError",
    "detect_environment",
    "verify_safety",
    "print_safety_warning",
    # Static
    "ObfuscationType",
    "DeobfuscationResult",
    "deobfuscate_static",
    "detect_obfuscation_type",
    "extract_iocs",
    "decode_base64",
    "decode_powershell_encoded",
    "decode_hex",
    "decode_url",
    "decode_xor_single_byte",
    "decode_char_codes",
    "decode_string_concat",
    # Emulation
    "EmulationTool",
    "ToolResult",
    "REMnuxEmulator",
    "create_emulator",
    # LLM
    "LLMConfig",
    "LLMDeobfuscator",
    "create_llm_deobfuscator",
    # Pipeline
    "ScriptType",
    "PipelineResult",
    "DeobfuscationPipeline",
    "detect_script_type",
    "quick_deobfuscate",
]
