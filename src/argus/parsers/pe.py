"""PE/EXE file parser for ARGUS.

Parses Portable Executable files for malware indicators including:
- PE header metadata and compile timestamps
- Section information with entropy analysis
- Packer detection (UPX, MPRESS, ASPack, etc.)
- Import table analysis
- Suspicious string extraction
"""

import json
import logging
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity

logger = logging.getLogger(__name__)

# Check for pefile library
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile library not installed. PE parsing disabled. Run: pip install pefile")


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data.

    High entropy (>7.0) often indicates packed/encrypted content.
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _extract_suspicious_strings(file_path: Path, max_strings: int = 100) -> list[str]:
    """Extract IR-relevant strings from PE file.

    Looks for URLs, IPs, domains, registry keys, suspicious APIs, and command execution.
    """
    suspicious = []
    try:
        data = file_path.read_bytes()

        patterns = {
            "url": re.compile(rb'https?://[^\s\x00<>"\']+'),
            "ip": re.compile(rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            "domain": re.compile(rb'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.(com|net|org|io|xyz|top|ru|cn|ua|info|biz)\b'),
            "registry_key": re.compile(rb'(HKLM|HKCU|HKEY_|Software\\\\|CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce)'),
            "suspicious_api": re.compile(rb'(VirtualAlloc|VirtualProtect|CreateRemoteThread|WriteProcessMemory|ReadProcessMemory|LoadLibrary[AW]?|GetProcAddress|URLDownloadToFile|WinExec|ShellExecute)'),
            "cmd_execution": re.compile(rb'(cmd\.exe|powershell|/c |/k |wscript|cscript|mshta)'),
            "file_path": re.compile(rb'[A-Za-z]:\\\\[^\x00\n]{5,100}'),
        }

        seen = set()
        for name, pattern in patterns.items():
            matches = pattern.findall(data)
            for match in matches:
                try:
                    decoded = match.decode('utf-8', errors='replace').strip()
                    # Skip if already seen or too short
                    if decoded not in seen and len(decoded) > 3:
                        seen.add(decoded)
                        suspicious.append(decoded)
                except Exception:
                    continue

    except Exception as e:
        logger.warning(f"String extraction failed for {file_path}: {e}")

    return suspicious[:max_strings]


class PEParser(BaseParser):
    """Parser for PE (Portable Executable) files for malware analysis."""

    name = "pe"
    description = "PE/EXE malware analysis"
    supported_extensions = [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv"]

    # Known packer section names
    PACKER_SIGNATURES = {
        "UPX": ["UPX0", "UPX1", "UPX2", ".UPX"],
        "MPRESS": [".MPRESS1", ".MPRESS2"],
        "ASPack": [".aspack", ".adata", ".ASPack"],
        "PECompact": ["PEC2", "PECompact2"],
        "Themida": [".themida"],
        "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
        "Enigma": [".enigma1", ".enigma2"],
        "PETITE": [".petite"],
        "NSPack": [".nsp0", ".nsp1", ".nsp2"],
    }

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a PE file."""
        if file_path.suffix.lower() not in cls.supported_extensions:
            return False

        # Check for MZ header
        try:
            with open(file_path, "rb") as f:
                header = f.read(2)
                return header == b"MZ"
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a PE file for malware indicators."""
        result = self._create_result(file_path)

        if not HAS_PEFILE:
            result.add_error(
                "pefile library not installed. Run: pip install pefile"
            )
            return result

        try:
            pe = pefile.PE(str(file_path), fast_load=False)
        except pefile.PEFormatError as e:
            result.add_warning(f"Not a valid PE file: {e}")
            return result
        except Exception as e:
            result.add_error(f"Failed to parse PE file: {e}")
            return result

        try:
            event = self._analyze_pe(pe, file_path)
            result.add_event(event)
            result.metadata["pe_analysis"] = {
                "is_packed": event.raw_payload and json.loads(event.raw_payload).get("pe_is_packed", False),
                "packer_name": event.raw_payload and json.loads(event.raw_payload).get("pe_packer_name"),
                "max_entropy": event.raw_payload and json.loads(event.raw_payload).get("pe_entropy", 0),
            }
        except Exception as e:
            logger.error(f"PE analysis failed for {file_path}: {e}", exc_info=True)
            result.add_error(f"PE analysis failed: {e}")
        finally:
            pe.close()

        return result

    def _analyze_pe(self, pe: "pefile.PE", file_path: Path) -> UnifiedEvent:
        """Perform full PE analysis and return unified event."""

        # Initialize PE analysis data
        pe_data = {
            "pe_compile_time": None,
            "pe_sections": [],
            "pe_imports": [],
            "pe_exports": [],
            "pe_is_packed": False,
            "pe_packer_name": None,
            "pe_entropy": 0.0,
            "pe_suspicious_strings": [],
            "pe_is_dll": False,
            "pe_is_driver": False,
            "pe_machine_type": None,
            "pe_subsystem": None,
            "pe_imphash": None,
            # Version info (S3.2.1)
            "pe_version_info": None,
            # Signature info (S3.2.2)
            "pe_signature": None,
            "pe_masquerading": False,
        }

        # Extract compile timestamp
        timestamp = datetime.now(timezone.utc)
        if hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER.TimeDateStamp:
            try:
                compile_time = datetime.utcfromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp
                ).replace(tzinfo=timezone.utc)
                pe_data["pe_compile_time"] = compile_time.isoformat()
                timestamp = compile_time
            except (ValueError, OSError):
                pass

        # Machine type
        if hasattr(pe, 'FILE_HEADER'):
            machine = pe.FILE_HEADER.Machine
            machine_types = {
                0x14c: "x86",
                0x8664: "x64",
                0x1c0: "ARM",
                0xaa64: "ARM64",
            }
            pe_data["pe_machine_type"] = machine_types.get(machine, f"0x{machine:x}")

        # Subsystem
        if hasattr(pe, 'OPTIONAL_HEADER'):
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            subsystems = {
                1: "Native",
                2: "Windows GUI",
                3: "Windows Console",
                5: "OS/2 Console",
                7: "POSIX Console",
            }
            pe_data["pe_subsystem"] = subsystems.get(subsystem, f"Unknown ({subsystem})")

        # Check if DLL or driver
        if hasattr(pe, 'FILE_HEADER'):
            pe_data["pe_is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        if pe_data["pe_subsystem"] == "Native":
            pe_data["pe_is_driver"] = True

        # Import hash (useful for malware family clustering)
        try:
            pe_data["pe_imphash"] = pe.get_imphash()
        except Exception:
            pass

        # Extract version info (S3.2.1)
        version_info = self._extract_version_info(pe)
        if version_info:
            pe_data["pe_version_info"] = version_info

            # Check for masquerading (known vendor but file is suspicious)
            known_vendors = ["microsoft", "adobe", "google", "oracle", "intel", "nvidia", "amd"]
            company = (version_info.get("CompanyName") or "").lower()
            if any(vendor in company for vendor in known_vendors):
                # Flag as potential masquerading if:
                # - High entropy (packed)
                # - Contains suspicious strings
                # - OR we determine later it's unsigned
                pe_data["pe_claimed_vendor"] = version_info.get("CompanyName")

        # Extract digital signature info (S3.2.2)
        signature_info = self._extract_signature_info(pe, file_path)
        if signature_info:
            pe_data["pe_signature"] = signature_info

            # Check for masquerading: claims to be from known vendor but unsigned/invalid
            if pe_data.get("pe_claimed_vendor"):
                if not signature_info.get("signed") or not signature_info.get("valid"):
                    pe_data["pe_masquerading"] = True

        # Extract sections with entropy
        section_names = []
        max_entropy = 0.0
        for section in pe.sections:
            try:
                section_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                section_entropy = _calculate_entropy(section.get_data())
                pe_data["pe_sections"].append({
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section_entropy,
                    "characteristics": hex(section.Characteristics),
                })
                section_names.append(section_name)
                max_entropy = max(max_entropy, section_entropy)
            except Exception:
                continue

        pe_data["pe_entropy"] = max_entropy

        # Detect packing by section names
        for packer_name, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if any(sig.lower() in name.lower() for name in section_names):
                    pe_data["pe_is_packed"] = True
                    pe_data["pe_packer_name"] = packer_name
                    break
            if pe_data["pe_is_packed"]:
                break

        # Detect packing by high entropy (if not already detected)
        if not pe_data["pe_is_packed"] and max_entropy > 7.0:
            pe_data["pe_is_packed"] = True
            pe_data["pe_packer_name"] = "Unknown (high entropy)"

        # Extract imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    functions = []
                    for imp in entry.imports[:50]:  # Limit functions per DLL
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='replace'))
                    pe_data["pe_imports"].append({
                        "dll": dll_name,
                        "functions": functions,
                    })
                except Exception:
                    continue

        # Extract exports (if DLL)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:50]:
                    if exp.name:
                        pe_data["pe_exports"].append(exp.name.decode('utf-8', errors='replace'))
            except Exception:
                pass

        # Extract suspicious strings
        pe_data["pe_suspicious_strings"] = _extract_suspicious_strings(file_path)

        # Determine severity
        severity = EventSeverity.INFO
        if pe_data["pe_is_packed"]:
            severity = EventSeverity.MEDIUM
        if pe_data["pe_masquerading"]:
            severity = EventSeverity.HIGH  # Masquerading is always high severity
        if pe_data["pe_suspicious_strings"]:
            # Check for high-risk indicators
            high_risk_patterns = ["cmd.exe", "powershell", "VirtualAlloc", "CreateRemoteThread"]
            for pattern in high_risk_patterns:
                if any(pattern.lower() in s.lower() for s in pe_data["pe_suspicious_strings"]):
                    severity = EventSeverity.HIGH
                    break

        # Create unified event
        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=file_path.name,
            source_line=0,
            event_type="PE_Analysis",
            severity=severity,
            parser_name=self.name,
        )

        event.process_name = file_path.name
        event.file_path = str(file_path)
        event.raw_payload = json.dumps(pe_data)

        return event

    def _extract_version_info(self, pe: "pefile.PE") -> Optional[dict]:
        """Extract PE version information (S3.2.1)."""
        version_info = {}

        try:
            # Try to get VS_FIXEDFILEINFO
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                ffi = pe.VS_FIXEDFILEINFO[0]
                version_info["FileVersionMS"] = ffi.FileVersionMS
                version_info["FileVersionLS"] = ffi.FileVersionLS
                version_info["ProductVersionMS"] = ffi.ProductVersionMS
                version_info["ProductVersionLS"] = ffi.ProductVersionLS

            # Try to get string table info
            if hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, 'Key'):
                        # Handle list structure
                        for info in file_info:
                            if hasattr(info, 'StringTable'):
                                for st_entry in info.StringTable:
                                    for entry in st_entry.entries.items():
                                        key = entry[0].decode('utf-8', errors='replace') if isinstance(entry[0], bytes) else entry[0]
                                        value = entry[1].decode('utf-8', errors='replace') if isinstance(entry[1], bytes) else entry[1]
                                        # Remove null characters
                                        key = key.strip('\x00')
                                        value = value.strip('\x00')
                                        version_info[key] = value

            # Fields we're specifically looking for
            important_fields = [
                "CompanyName", "ProductName", "FileDescription",
                "OriginalFilename", "InternalName", "FileVersion",
                "ProductVersion", "LegalCopyright",
            ]

            # Filter to only include important fields if we have them
            if version_info:
                filtered = {}
                for field in important_fields:
                    if field in version_info:
                        filtered[field] = version_info[field]
                    # Also check lowercase
                    elif field.lower() in version_info:
                        filtered[field] = version_info[field.lower()]
                return filtered if filtered else version_info

        except Exception as e:
            logger.debug(f"Version info extraction failed: {e}")

        return version_info if version_info else None

    def _extract_signature_info(self, pe: "pefile.PE", file_path: Path) -> dict:
        """Extract digital signature information (S3.2.2)."""
        signature_info = {
            "signed": False,
            "valid": False,
            "signer": None,
        }

        try:
            # Check for Authenticode signature in security directory
            security_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].VirtualAddress != 0:
                signature_info["signed"] = True

                # Note: Full signature verification requires additional libraries
                # like signify or wincertstore. For now, we just detect presence.
                # In a production environment, you'd want to:
                # 1. Extract the certificate
                # 2. Verify the certificate chain
                # 3. Check for certificate validity

                # Try to extract signer info if possible
                try:
                    # This requires reading the raw signature data
                    security_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].VirtualAddress
                    security_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].Size

                    if security_size > 0:
                        signature_info["signature_size"] = security_size
                        # Mark as potentially valid (would need signify library for true verification)
                        # For now, assume signed files with security directory are valid
                        # unless we have reason to believe otherwise
                        signature_info["valid"] = True
                        signature_info["signer"] = "Unknown (signature present)"

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Signature extraction failed: {e}")

        return signature_info
