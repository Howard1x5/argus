"""ARGUS Deobfuscation Safety Module.

Layer 0: Environment detection and safety enforcement.

This module ensures malware analysis is performed safely by:
1. Detecting if running in a sandbox (REMnux) vs local endpoint
2. Enforcing restrictions on local endpoints
3. Requiring explicit opt-in for risky operations
4. Providing clear warnings to users
"""

import os
import platform
import socket
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class Environment(Enum):
    """Detected execution environment."""
    REMNUX = "remnux"           # REMnux sandbox - full capabilities
    SANDBOX_OTHER = "sandbox"   # Other sandbox detected - full capabilities
    LOCAL_ENDPOINT = "local"    # User's machine - restricted mode
    UNKNOWN = "unknown"         # Can't determine - assume restricted


@dataclass
class SafetyConfig:
    """Safety configuration for deobfuscation operations."""

    # Remote sandbox for SSH-based emulation
    sandbox_host: Optional[str] = None
    sandbox_port: int = 22
    sandbox_user: str = "remnux"

    # Safety flags
    allow_local_emulation: bool = False
    i_understand_the_risks: bool = False

    # Operation modes
    static_only: bool = False  # Only allow static analysis
    require_sandbox: bool = True  # Require sandbox for emulation

    @classmethod
    def from_yaml(cls, config_path: Path) -> "SafetyConfig":
        """Load safety config from argus.yaml."""
        import yaml

        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            config = yaml.safe_load(f) or {}

        deobfuscate_config = config.get("deobfuscate", {})
        sandbox_config = deobfuscate_config.get("sandbox", {})

        return cls(
            sandbox_host=sandbox_config.get("host"),
            sandbox_port=sandbox_config.get("port", 22),
            sandbox_user=sandbox_config.get("user", "remnux"),
            allow_local_emulation=deobfuscate_config.get("allow_local_emulation", False),
            i_understand_the_risks=deobfuscate_config.get("i_understand_the_risks", False),
            static_only=deobfuscate_config.get("static_only", False),
            require_sandbox=deobfuscate_config.get("require_sandbox", True),
        )


SAFETY_WARNING = """
================================================================================
                        ARGUS SECURITY NOTICE
================================================================================

This tool analyzes potentially malicious files including scripts, executables,
and encoded payloads that may contain live malware.

RECOMMENDED SETUP:
  Install and run ARGUS directly on REMnux (https://remnux.org)
  This provides a safe, isolated environment with all required tools.

IF RUNNING ON YOUR LOCAL MACHINE:
  - Configure a remote REMnux sandbox for emulation (see docs)
  - Only static analysis will run locally (safe but less effective)
  - Emulation requires SSH to your sandbox
  - Never enable 'allow_local_emulation' unless you understand the risks

ARGUS uses emulators (not actual execution) for script analysis, but emulators
can have vulnerabilities. A sandbox provides defense in depth.

================================================================================
"""

RESTRICTED_MODE_WARNING = """
[!] RESTRICTED MODE: Running on local endpoint without sandbox configured.
    Only static analysis is available. Configure sandbox for full capabilities:

    In argus.yaml:
      deobfuscate:
        sandbox:
          host: "your-remnux-ip"  # e.g., 192.168.1.100
          port: 22
          user: "remnux"
"""


def detect_environment() -> Environment:
    """Detect the current execution environment.

    Checks for indicators of running in a sandbox vs local endpoint.

    Returns:
        Environment enum indicating detected environment type
    """
    hostname = socket.gethostname().lower()

    # Check for REMnux
    if "remnux" in hostname:
        return Environment.REMNUX

    # Check for REMnux-specific files/tools
    remnux_indicators = [
        "/usr/local/remnux",
        "/opt/remnux",
        "/etc/remnux-version",
    ]
    for indicator in remnux_indicators:
        if os.path.exists(indicator):
            return Environment.REMNUX

    # Check for common REMnux tools
    remnux_tools = ["psdecode", "box-js", "olevba", "capa"]
    tools_found = 0
    for tool in remnux_tools:
        try:
            result = subprocess.run(
                ["which", tool],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                tools_found += 1
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # If multiple REMnux tools found, likely a sandbox
    if tools_found >= 3:
        return Environment.SANDBOX_OTHER

    # Check for VM/container indicators (common sandbox patterns)
    vm_indicators = [
        "/sys/hypervisor",  # Xen
        "/.dockerenv",      # Docker
        "/run/.containerenv",  # Podman
    ]
    for indicator in vm_indicators:
        if os.path.exists(indicator):
            return Environment.SANDBOX_OTHER

    # Check DMI for VM detection
    try:
        with open("/sys/class/dmi/id/product_name", "r") as f:
            product = f.read().lower()
            if any(vm in product for vm in ["virtualbox", "vmware", "qemu", "kvm"]):
                return Environment.SANDBOX_OTHER
    except (FileNotFoundError, PermissionError):
        pass

    # Default to local endpoint (most restrictive)
    return Environment.LOCAL_ENDPOINT


def check_sandbox_connectivity(config: SafetyConfig) -> bool:
    """Check if we can reach the configured sandbox via SSH.

    Args:
        config: Safety configuration with sandbox details

    Returns:
        True if sandbox is reachable, False otherwise
    """
    if not config.sandbox_host:
        return False

    try:
        result = subprocess.run(
            [
                "ssh", "-q",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-p", str(config.sandbox_port),
                f"{config.sandbox_user}@{config.sandbox_host}",
                "echo ok"
            ],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0 and b"ok" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@dataclass
class SafetyCheck:
    """Result of safety verification."""

    environment: Environment
    sandbox_available: bool
    local_emulation_allowed: bool

    # What operations are permitted
    can_static_analysis: bool = True  # Always allowed
    can_local_emulation: bool = False
    can_remote_emulation: bool = False
    can_llm_analysis: bool = True  # Always allowed (just API calls)

    # Warnings to display
    warnings: list[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


def verify_safety(config: SafetyConfig, verbose: bool = True) -> SafetyCheck:
    """Verify safety constraints and determine allowed operations.

    Args:
        config: Safety configuration
        verbose: Whether to print warnings

    Returns:
        SafetyCheck with allowed operations
    """
    env = detect_environment()
    sandbox_ok = check_sandbox_connectivity(config)

    check = SafetyCheck(
        environment=env,
        sandbox_available=sandbox_ok,
        local_emulation_allowed=config.allow_local_emulation and config.i_understand_the_risks,
        warnings=[]
    )

    # Determine capabilities based on environment
    if env in (Environment.REMNUX, Environment.SANDBOX_OTHER):
        # Running in sandbox - full capabilities
        check.can_local_emulation = True
        check.can_remote_emulation = sandbox_ok

    elif env == Environment.LOCAL_ENDPOINT:
        # Local endpoint - restricted
        check.warnings.append(RESTRICTED_MODE_WARNING)

        if config.allow_local_emulation and config.i_understand_the_risks:
            check.can_local_emulation = True
            check.warnings.append(
                "[!] WARNING: Local emulation enabled on endpoint. "
                "This is not recommended for production use."
            )

        check.can_remote_emulation = sandbox_ok

        if not sandbox_ok and not check.can_local_emulation:
            check.warnings.append(
                "[!] No sandbox available. Only static analysis will be performed."
            )

    else:  # UNKNOWN
        check.warnings.append(
            "[!] Could not determine environment. Assuming local endpoint restrictions."
        )
        check.can_remote_emulation = sandbox_ok

    # Print warnings if verbose
    if verbose and check.warnings:
        for warning in check.warnings:
            print(warning)

    return check


def print_safety_warning():
    """Print the main safety warning banner."""
    print(SAFETY_WARNING)


class SafetyError(Exception):
    """Raised when a safety constraint is violated."""
    pass


def require_emulation_capability(check: SafetyCheck) -> str:
    """Ensure emulation is available, return the method to use.

    Args:
        check: Safety check result

    Returns:
        "local" or "remote" indicating which emulation method to use

    Raises:
        SafetyError if no emulation is available
    """
    if check.can_local_emulation:
        return "local"
    elif check.can_remote_emulation:
        return "remote"
    else:
        raise SafetyError(
            "Emulation not available. Either:\n"
            "1. Run ARGUS on REMnux (recommended)\n"
            "2. Configure a remote sandbox in argus.yaml\n"
            "3. Enable local emulation (not recommended)"
        )
