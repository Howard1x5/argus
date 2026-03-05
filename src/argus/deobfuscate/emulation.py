"""ARGUS Emulation-Based Deobfuscation Module.

Layer 2: Script emulation using REMnux tools.

This module provides script emulation capabilities using tools available
on REMnux. It can run either locally (if on REMnux) or remotely via SSH.

Supported emulators:
- PSDecode: PowerShell deobfuscation
- box-js: JavaScript emulation
- olevba: Office VBA macro extraction
- BatchDeobfuscator: Batch script deobfuscation

Static analyzers (no execution):
- capa: Capability detection
- YARA: Pattern matching
- strings: String extraction
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from .safety import SafetyConfig, SafetyCheck, SafetyError
from .static import DeobfuscationResult, ObfuscationType, extract_iocs


class EmulationTool(Enum):
    """Available emulation/analysis tools."""
    PSDECODE = "psdecode"
    BOXJS = "box-js"
    OLEVBA = "olevba"
    BATCH_DEOBFUSCATOR = "batch-deobfuscator"
    CAPA = "capa"
    STRINGS = "strings"


@dataclass
class ToolResult:
    """Result from running an emulation tool."""
    tool: EmulationTool
    success: bool
    output: str
    error: Optional[str] = None
    execution_method: str = "local"  # "local" or "remote"


class REMnuxEmulator:
    """Interface for running emulation tools on REMnux.

    Can run tools either locally (if on REMnux) or via SSH.
    """

    def __init__(self, config: SafetyConfig, safety_check: SafetyCheck):
        """Initialize the emulator.

        Args:
            config: Safety configuration
            safety_check: Result of safety verification
        """
        self.config = config
        self.safety = safety_check

        # Determine execution method
        if safety_check.can_local_emulation:
            self.execution_method = "local"
        elif safety_check.can_remote_emulation:
            self.execution_method = "remote"
        else:
            raise SafetyError(
                "No emulation capability available. "
                "Run on REMnux or configure a sandbox."
            )

    def _run_local(self, command: list[str], input_file: Optional[Path] = None,
                   stdin_data: Optional[str] = None, timeout: int = 60) -> ToolResult:
        """Run a command locally.

        Args:
            command: Command and arguments
            input_file: Optional input file path
            stdin_data: Optional data to send to stdin
            timeout: Timeout in seconds

        Returns:
            ToolResult with output
        """
        tool_name = command[0]

        try:
            result = subprocess.run(
                command,
                input=stdin_data.encode() if stdin_data else None,
                capture_output=True,
                timeout=timeout,
            )

            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=result.returncode == 0,
                output=result.stdout.decode('utf-8', errors='replace'),
                error=result.stderr.decode('utf-8', errors='replace') if result.stderr else None,
                execution_method="local",
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=False,
                output="",
                error=f"Command timed out after {timeout} seconds",
                execution_method="local",
            )

        except FileNotFoundError:
            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=False,
                output="",
                error=f"Tool not found: {tool_name}",
                execution_method="local",
            )

    def _run_remote(self, command: list[str], input_file: Optional[Path] = None,
                    stdin_data: Optional[str] = None, timeout: int = 120) -> ToolResult:
        """Run a command on remote REMnux via SSH.

        Args:
            command: Command and arguments
            input_file: Optional input file to copy to remote
            stdin_data: Optional data to send to stdin
            timeout: Timeout in seconds

        Returns:
            ToolResult with output
        """
        if not self.config.sandbox_host:
            return ToolResult(
                tool=EmulationTool.STRINGS,
                success=False,
                output="",
                error="No sandbox host configured",
                execution_method="remote",
            )

        tool_name = command[0]
        ssh_base = [
            "ssh", "-q",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-p", str(self.config.sandbox_port),
            f"{self.config.sandbox_user}@{self.config.sandbox_host}",
        ]

        remote_file = None

        try:
            # If there's an input file, copy it to remote
            if input_file and input_file.exists():
                remote_file = f"/tmp/argus_deobfuscate_{os.getpid()}_{input_file.name}"

                # Copy file to remote
                scp_cmd = [
                    "scp", "-q",
                    "-o", "BatchMode=yes",
                    "-P", str(self.config.sandbox_port),
                    str(input_file),
                    f"{self.config.sandbox_user}@{self.config.sandbox_host}:{remote_file}"
                ]
                subprocess.run(scp_cmd, timeout=30, check=True)

                # Update command to use remote file
                command = [c if c != str(input_file) else remote_file for c in command]

            # Build the remote command
            remote_cmd = " ".join(f'"{c}"' if " " in c else c for c in command)
            full_cmd = ssh_base + [remote_cmd]

            result = subprocess.run(
                full_cmd,
                input=stdin_data.encode() if stdin_data else None,
                capture_output=True,
                timeout=timeout,
            )

            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=result.returncode == 0,
                output=result.stdout.decode('utf-8', errors='replace'),
                error=result.stderr.decode('utf-8', errors='replace') if result.stderr else None,
                execution_method="remote",
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=False,
                output="",
                error=f"Remote command timed out after {timeout} seconds",
                execution_method="remote",
            )

        except subprocess.CalledProcessError as e:
            return ToolResult(
                tool=EmulationTool(tool_name) if tool_name in [e.value for e in EmulationTool] else EmulationTool.STRINGS,
                success=False,
                output="",
                error=f"SCP failed: {str(e)}",
                execution_method="remote",
            )

        finally:
            # Clean up remote file
            if remote_file:
                try:
                    cleanup_cmd = ssh_base + [f"rm -f {remote_file}"]
                    subprocess.run(cleanup_cmd, timeout=10, capture_output=True)
                except Exception:
                    pass

    def run_tool(self, command: list[str], input_file: Optional[Path] = None,
                 stdin_data: Optional[str] = None, timeout: int = 60) -> ToolResult:
        """Run a tool using the appropriate method.

        Args:
            command: Command and arguments
            input_file: Optional input file path
            stdin_data: Optional data to send to stdin
            timeout: Timeout in seconds

        Returns:
            ToolResult with output
        """
        if self.execution_method == "local":
            return self._run_local(command, input_file, stdin_data, timeout)
        else:
            return self._run_remote(command, input_file, stdin_data, timeout)

    def deobfuscate_powershell(self, content: str) -> DeobfuscationResult:
        """Deobfuscate PowerShell script using PSDecode.

        Args:
            content: PowerShell script content

        Returns:
            DeobfuscationResult with decoded content
        """
        # Write content to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write(content)
            temp_file = Path(f.name)

        try:
            result = self.run_tool(["psdecode", str(temp_file)], input_file=temp_file)

            if result.success and result.output:
                iocs = extract_iocs(result.output)
                return DeobfuscationResult(
                    success=True,
                    obfuscation_type=ObfuscationType.UNKNOWN,
                    original=content,
                    decoded=result.output,
                    confidence=0.85,
                    layer="emulation",
                    iocs_found=iocs,
                )
            else:
                return DeobfuscationResult(
                    success=False,
                    obfuscation_type=ObfuscationType.UNKNOWN,
                    original=content,
                    warnings=[result.error or "PSDecode returned no output"],
                    layer="emulation",
                )

        finally:
            temp_file.unlink(missing_ok=True)

    def deobfuscate_javascript(self, content: str) -> DeobfuscationResult:
        """Deobfuscate JavaScript using box-js.

        Args:
            content: JavaScript content

        Returns:
            DeobfuscationResult with decoded content
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(content)
            temp_file = Path(f.name)

        try:
            # box-js outputs to a directory
            output_dir = tempfile.mkdtemp(prefix="boxjs_")

            result = self.run_tool(
                ["box-js", str(temp_file), "--output-dir", output_dir],
                input_file=temp_file,
                timeout=120
            )

            # Read output files
            decoded_parts = []
            output_path = Path(output_dir)

            for output_file in output_path.glob("*.js"):
                decoded_parts.append(output_file.read_text())

            # Also check for IOC files
            for ioc_file in output_path.glob("*.json"):
                try:
                    ioc_data = json.loads(ioc_file.read_text())
                    decoded_parts.append(json.dumps(ioc_data, indent=2))
                except json.JSONDecodeError:
                    pass

            if decoded_parts:
                decoded = "\n".join(decoded_parts)
                iocs = extract_iocs(decoded)
                return DeobfuscationResult(
                    success=True,
                    obfuscation_type=ObfuscationType.UNKNOWN,
                    original=content,
                    decoded=decoded,
                    confidence=0.8,
                    layer="emulation",
                    iocs_found=iocs,
                )
            else:
                return DeobfuscationResult(
                    success=False,
                    obfuscation_type=ObfuscationType.UNKNOWN,
                    original=content,
                    warnings=["box-js produced no output"],
                    layer="emulation",
                )

        finally:
            temp_file.unlink(missing_ok=True)
            # Cleanup output dir
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)

    def deobfuscate_batch(self, content: str) -> DeobfuscationResult:
        """Deobfuscate batch script.

        Attempts to decode batch variable indexing and other patterns.

        Args:
            content: Batch script content

        Returns:
            DeobfuscationResult with decoded content
        """
        # Try batch-deobfuscator if available
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
            f.write(content)
            temp_file = Path(f.name)

        try:
            # Try batch-deobfuscator first
            result = self.run_tool(["batch-deobfuscator", str(temp_file)], input_file=temp_file)

            if result.success and result.output:
                iocs = extract_iocs(result.output)
                return DeobfuscationResult(
                    success=True,
                    obfuscation_type=ObfuscationType.BATCH_VAR_INDEX,
                    original=content,
                    decoded=result.output,
                    confidence=0.8,
                    layer="emulation",
                    iocs_found=iocs,
                )

            # Fallback: try to emulate basic variable indexing
            decoded = self._emulate_batch_vars(content)
            if decoded and decoded != content:
                iocs = extract_iocs(decoded)
                return DeobfuscationResult(
                    success=True,
                    obfuscation_type=ObfuscationType.BATCH_VAR_INDEX,
                    original=content,
                    decoded=decoded,
                    confidence=0.6,
                    layer="emulation",
                    iocs_found=iocs,
                    warnings=["Used fallback batch emulation"],
                )

            return DeobfuscationResult(
                success=False,
                obfuscation_type=ObfuscationType.BATCH_VAR_INDEX,
                original=content,
                warnings=["Could not deobfuscate batch script"],
                layer="emulation",
            )

        finally:
            temp_file.unlink(missing_ok=True)

    def _emulate_batch_vars(self, content: str) -> Optional[str]:
        """Simple batch variable indexing emulator.

        Handles patterns like: %varname:~index,length%

        Args:
            content: Batch script content

        Returns:
            Decoded content or None
        """
        # Extract variable definitions
        # Pattern: set "varname=value" or set varname=value
        var_pattern = r'set\s+"?([^"=]+)=([^"\n]+)"?'
        variables = {}

        for match in re.finditer(var_pattern, content, re.IGNORECASE):
            var_name = match.group(1).strip()
            var_value = match.group(2).strip()
            variables[var_name.lower()] = var_value

        if not variables:
            return None

        # Now try to decode indexed access
        # Pattern: %varname:~start,length%
        decoded_parts = []
        index_pattern = r'%([^%:]+):~(\d+),(\d+)%'

        def decode_indexed_var(match):
            var_name = match.group(1).lower()
            start = int(match.group(2))
            length = int(match.group(3))

            if var_name in variables:
                value = variables[var_name]
                if start < len(value):
                    return value[start:start + length]
            return match.group(0)

        decoded = re.sub(index_pattern, decode_indexed_var, content)

        # Check if we actually decoded anything meaningful
        if decoded != content:
            return decoded

        return None

    def extract_vba_macros(self, file_path: Path) -> DeobfuscationResult:
        """Extract VBA macros from Office document using olevba.

        Args:
            file_path: Path to Office document

        Returns:
            DeobfuscationResult with extracted macros
        """
        result = self.run_tool(["olevba", "--decode", str(file_path)], input_file=file_path)

        if result.success and result.output:
            iocs = extract_iocs(result.output)
            return DeobfuscationResult(
                success=True,
                obfuscation_type=ObfuscationType.UNKNOWN,
                original=str(file_path),
                decoded=result.output,
                confidence=0.9,
                layer="emulation",
                iocs_found=iocs,
            )

        return DeobfuscationResult(
            success=False,
            obfuscation_type=ObfuscationType.UNKNOWN,
            original=str(file_path),
            warnings=[result.error or "olevba extraction failed"],
            layer="emulation",
        )

    def analyze_capabilities(self, file_path: Path) -> dict:
        """Analyze file capabilities using capa.

        Args:
            file_path: Path to file to analyze

        Returns:
            Dict with capability analysis results
        """
        result = self.run_tool(
            ["capa", "--json", str(file_path)],
            input_file=file_path,
            timeout=120
        )

        if result.success and result.output:
            try:
                return json.loads(result.output)
            except json.JSONDecodeError:
                return {"error": "Failed to parse capa output"}

        return {"error": result.error or "capa analysis failed"}

    def extract_strings(self, file_path: Path, min_length: int = 6) -> list[str]:
        """Extract strings from file.

        Args:
            file_path: Path to file
            min_length: Minimum string length

        Returns:
            List of extracted strings
        """
        result = self.run_tool(
            ["strings", "-n", str(min_length), str(file_path)],
            input_file=file_path
        )

        if result.success and result.output:
            return result.output.strip().split('\n')

        return []


def create_emulator(config: SafetyConfig, safety_check: SafetyCheck) -> Optional[REMnuxEmulator]:
    """Factory function to create an emulator if possible.

    Args:
        config: Safety configuration
        safety_check: Result of safety verification

    Returns:
        REMnuxEmulator instance or None if not available
    """
    if not (safety_check.can_local_emulation or safety_check.can_remote_emulation):
        return None

    try:
        return REMnuxEmulator(config, safety_check)
    except SafetyError:
        return None
