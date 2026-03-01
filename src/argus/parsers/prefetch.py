"""Windows Prefetch file parser for ARGUS.

Parses Windows Prefetch (.pf) files for program execution evidence.
"""

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Suspicious prefetch filenames (common attacker tools)
SUSPICIOUS_EXECUTABLES = {
    "mimikatz", "procdump", "psexec", "wce", "pwdump",
    "lazagne", "rubeus", "sharphound", "bloodhound",
    "cobalt", "beacon", "meterpreter", "nc", "ncat",
    "certutil", "bitsadmin", "mshta", "regsvr32",
    "rundll32", "wmic", "cmstp", "msiexec", "installutil",
    "regasm", "regsvcs", "msconfig", "dnscmd",
}


class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch files."""

    name = "prefetch"
    description = "Windows Prefetch execution artifacts"
    supported_extensions = [".pf"]

    # Prefetch file signatures
    PREFETCH_SIGNATURES = {
        b"SCCA": "XP/2003",
        b"MAM\x04": "Vista/7",
        b"MAM\x17": "8/8.1",
        b"MAM\x1a": "10",
        b"MAM\x1e": "10 (1903+)",
    }

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Prefetch file."""
        if file_path.suffix.lower() != ".pf":
            return False

        try:
            with open(file_path, "rb") as f:
                # Check for MAM or SCCA signature
                magic = f.read(4)
                return magic[:3] == b"MAM" or magic == b"SCCA"
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Prefetch file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Detect format
            signature = data[:4]
            if signature[:3] != b"MAM" and signature != b"SCCA":
                result.add_error("Invalid Prefetch file signature")
                return result

            # Parse based on format
            if signature == b"SCCA":
                event = self._parse_xp_format(data, file_path.name)
            else:
                event = self._parse_modern_format(data, file_path.name)

            if event:
                result.add_event(event)
            else:
                result.add_warning("Could not extract execution info")

        except Exception as e:
            result.add_error(f"Failed to parse Prefetch file: {str(e)}")

        return result

    def _parse_modern_format(
        self, data: bytes, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse Windows Vista+ Prefetch format."""
        try:
            # Check if compressed (Win10+)
            if data[:4] == b"MAM\x04":
                # Compressed format - would need decompression
                # For now, extract what we can from filename
                return self._parse_from_filename(source_file)

            # Header structure (simplified)
            # Offset 0x00: Signature (4 bytes)
            # Offset 0x04: Uncompressed size (4 bytes)
            # Offset 0x0C: File path offset
            # Offset 0x10: File path length
            # Offset 0x78: Last execution time (FILETIME)
            # Offset 0x80+: Execution count (varies by version)

            version = data[0]

            # Try to get execution time
            exec_time = None
            try:
                # Last run time typically at offset 0x80 for Win10
                filetime = struct.unpack("<Q", data[0x80:0x88])[0]
                exec_time = self._filetime_to_datetime(filetime)
            except Exception:
                exec_time = datetime.now(timezone.utc)

            # Try to get run count
            run_count = 1
            try:
                # Run count location varies by version
                if version >= 0x1a:  # Win10
                    run_count = struct.unpack("<I", data[0xD0:0xD4])[0]
                elif version >= 0x17:  # Win8
                    run_count = struct.unpack("<I", data[0xBC:0xC0])[0]
            except Exception:
                pass

            # Extract executable name from filename
            exe_name = self._extract_exe_name(source_file)

            # Assess severity
            severity = self._assess_severity(exe_name)

            event = UnifiedEvent(
                timestamp_utc=exec_time,
                source_file=source_file,
                source_line=1,
                event_type="Prefetch",
                severity=severity,
                parser_name=self.name,
                process_name=exe_name,
                raw_payload=f"Execution count: {run_count}",
            )

            return event

        except Exception:
            return self._parse_from_filename(source_file)

    def _parse_xp_format(
        self, data: bytes, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse Windows XP/2003 Prefetch format."""
        try:
            # XP format is simpler
            # Offset 0x00: Version (4 bytes)
            # Offset 0x04: Signature "SCCA"
            # Offset 0x10: Prefetch file name offset
            # Offset 0x78: Last execution time
            # Offset 0x90: Execution count

            exec_time = None
            try:
                filetime = struct.unpack("<Q", data[0x78:0x80])[0]
                exec_time = self._filetime_to_datetime(filetime)
            except Exception:
                exec_time = datetime.now(timezone.utc)

            run_count = 1
            try:
                run_count = struct.unpack("<I", data[0x90:0x94])[0]
            except Exception:
                pass

            exe_name = self._extract_exe_name(source_file)
            severity = self._assess_severity(exe_name)

            event = UnifiedEvent(
                timestamp_utc=exec_time,
                source_file=source_file,
                source_line=1,
                event_type="Prefetch",
                severity=severity,
                parser_name=self.name,
                process_name=exe_name,
                raw_payload=f"Execution count: {run_count}",
            )

            return event

        except Exception:
            return self._parse_from_filename(source_file)

    def _parse_from_filename(self, source_file: str) -> UnifiedEvent:
        """Extract basic info from Prefetch filename when parsing fails."""
        exe_name = self._extract_exe_name(source_file)

        return UnifiedEvent(
            timestamp_utc=datetime.now(timezone.utc),
            source_file=source_file,
            source_line=1,
            event_type="Prefetch",
            severity=self._assess_severity(exe_name),
            parser_name=self.name,
            process_name=exe_name,
            raw_payload="Parsed from filename only",
        )

    def _extract_exe_name(self, filename: str) -> str:
        """Extract executable name from Prefetch filename.

        Format: EXECUTABLE.EXE-XXXXXXXX.pf
        """
        name = filename.upper()
        if name.endswith(".PF"):
            name = name[:-3]
        # Remove hash suffix
        if "-" in name:
            name = name.rsplit("-", 1)[0]
        return name

    def _filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        EPOCH_DIFF = 116444736000000000
        try:
            if filetime < EPOCH_DIFF:
                return datetime.now(timezone.utc)
            unix_time = (filetime - EPOCH_DIFF) / 10000000
            return datetime.fromtimestamp(unix_time, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)

    def _assess_severity(self, exe_name: str) -> EventSeverity:
        """Assess severity based on executable name."""
        name_lower = exe_name.lower()

        for suspicious in SUSPICIOUS_EXECUTABLES:
            if suspicious in name_lower:
                return EventSeverity.HIGH

        # Common system utilities that could indicate recon
        recon_tools = {"whoami", "ipconfig", "netstat", "systeminfo", "tasklist", "net", "nltest"}
        for tool in recon_tools:
            if name_lower.startswith(tool):
                return EventSeverity.MEDIUM

        return EventSeverity.INFO
