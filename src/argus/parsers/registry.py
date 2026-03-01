"""Windows Registry hive parser for ARGUS.

Parses Windows Registry hive files using regipy.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from regipy.registry import RegistryHive
from regipy.exceptions import RegistryParsingException

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-interest registry paths for IR
PERSISTENCE_PATHS = {
    "\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    "\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "\\ControlSet001\\Services",
    "\\ControlSet002\\Services",
    "\\ControlSet001\\Control\\Session Manager",
}

SERVICE_SUSPICIOUS_PATTERNS = [
    "cmd.exe",
    "powershell",
    "mshta",
    "wscript",
    "cscript",
    "regsvr32",
    "rundll32",
    "msiexec",
]


class RegistryParser(BaseParser):
    """Parser for Windows Registry hive files."""

    name = "registry"
    description = "Windows Registry hive files"
    supported_extensions = [".reg", ""]  # Hives often have no extension

    # Known hive file names
    HIVE_NAMES = {
        "sam", "security", "software", "system", "ntuser.dat",
        "usrclass.dat", "default", "amcache.hve"
    }

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Registry hive file."""
        # Check by filename
        name_lower = file_path.name.lower()
        if name_lower in cls.HIVE_NAMES:
            return True

        # Check magic bytes: "regf"
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                return magic == b"regf"
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Registry hive file."""
        result = self._create_result(file_path)

        try:
            hive = RegistryHive(str(file_path))
            result.metadata["hive_type"] = self._detect_hive_type(file_path, hive)

            # Recursively enumerate keys and values
            line_num = 0
            for key in self._enumerate_keys(hive.root):
                line_num += 1
                try:
                    event = self._parse_key(key, line_num, file_path.name)
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Key {line_num}: {str(e)}")

            result.metadata["key_count"] = line_num

        except RegistryParsingException as e:
            result.add_error(f"Failed to parse registry hive: {str(e)}")
        except Exception as e:
            result.add_error(f"Error reading registry hive: {str(e)}")

        return result

    def _detect_hive_type(self, file_path: Path, hive: RegistryHive) -> str:
        """Detect the type of registry hive."""
        name = file_path.name.lower()

        if name == "sam":
            return "SAM"
        elif name == "security":
            return "SECURITY"
        elif name == "software":
            return "SOFTWARE"
        elif name == "system":
            return "SYSTEM"
        elif name == "ntuser.dat":
            return "NTUSER"
        elif name == "usrclass.dat":
            return "USRCLASS"
        elif name == "amcache.hve":
            return "AMCACHE"
        else:
            return "UNKNOWN"

    def _enumerate_keys(self, key, depth: int = 0, max_depth: int = 50):
        """Recursively enumerate registry keys."""
        if depth > max_depth:
            return

        yield key

        try:
            for subkey in key.iter_subkeys():
                yield from self._enumerate_keys(subkey, depth + 1, max_depth)
        except Exception:
            pass

    def _parse_key(
        self, key, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a registry key into an event."""
        try:
            key_path = key.path
            timestamp = key.header.last_modified

            # Convert Windows FILETIME to datetime
            if timestamp:
                ts_dt = self._filetime_to_datetime(timestamp)
            else:
                ts_dt = datetime.now(timezone.utc)

            # Determine severity based on key path
            severity = self._assess_severity(key_path)

            event = UnifiedEvent(
                timestamp_utc=ts_dt,
                source_file=source_file,
                source_line=line_num,
                event_type="Registry",
                severity=severity,
                parser_name=self.name,
                registry_key=key_path,
            )

            # Extract values
            values = []
            try:
                for value in key.iter_values():
                    val_name = value.name or "(Default)"
                    val_data = str(value.value)[:500]  # Truncate long values
                    values.append(f"{val_name}={val_data}")

                    # Check for suspicious service paths
                    if self._is_suspicious_value(val_data):
                        event.severity = EventSeverity.HIGH
            except Exception:
                pass

            if values:
                event.registry_value = "; ".join(values[:10])  # Limit values
                event.raw_payload = "\n".join(values)

            return event

        except Exception:
            return None

    def _filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        # FILETIME is 100-nanosecond intervals since Jan 1, 1601
        EPOCH_DIFF = 116444736000000000  # Difference between 1601 and 1970
        try:
            unix_time = (filetime - EPOCH_DIFF) / 10000000
            return datetime.fromtimestamp(unix_time, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)

    def _assess_severity(self, key_path: str) -> EventSeverity:
        """Assess severity based on registry key path."""
        path_upper = key_path.upper()

        for persist_path in PERSISTENCE_PATHS:
            if persist_path.upper() in path_upper:
                return EventSeverity.MEDIUM

        if "\\SERVICES\\" in path_upper:
            return EventSeverity.LOW

        return EventSeverity.INFO

    def _is_suspicious_value(self, value: str) -> bool:
        """Check if a registry value contains suspicious patterns."""
        value_lower = value.lower()
        return any(pattern in value_lower for pattern in SERVICE_SUSPICIOUS_PATTERNS)
