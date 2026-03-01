"""Palo Alto firewall log parser for ARGUS.

Parses Palo Alto Networks firewall logs (traffic, threat, system).
"""

import csv
import re
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Palo Alto log types
LOG_TYPES = {
    "TRAFFIC": "traffic",
    "THREAT": "threat",
    "SYSTEM": "system",
    "CONFIG": "config",
    "GLOBALPROTECT": "globalprotect",
}

# Threat severity mapping
THREAT_SEVERITY = {
    "critical": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
    "informational": EventSeverity.INFO,
}


class PaloAltoParser(BaseParser):
    """Parser for Palo Alto firewall logs."""

    name = "paloalto"
    description = "Palo Alto Networks firewall logs"
    supported_extensions = [".log", ".csv"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Palo Alto log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    # Palo Alto logs are comma-separated with specific fields
                    # Check for log type indicators
                    if any(lt in line.upper() for lt in LOG_TYPES.keys()):
                        # Verify it's comma-separated with expected field count
                        parts = line.split(",")
                        if len(parts) > 20:  # PA logs have many fields
                            return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Palo Alto log file."""
        result = self._create_result(file_path)

        line_num = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = self._parse_line(line, line_num, file_path.name)
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Palo Alto log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single Palo Alto log line."""
        # Parse CSV
        try:
            reader = csv.reader(StringIO(line))
            fields = next(reader)
        except Exception:
            return None

        if len(fields) < 15:
            return None

        # Determine log type (field index varies by format)
        log_type = self._detect_log_type(fields)

        if log_type == "traffic":
            return self._parse_traffic(fields, line, line_num, source_file)
        elif log_type == "threat":
            return self._parse_threat(fields, line, line_num, source_file)
        else:
            return self._parse_generic(fields, line, line_num, source_file, log_type)

    def _detect_log_type(self, fields: list) -> str:
        """Detect the Palo Alto log type."""
        # Log type is typically in early fields
        for i, field in enumerate(fields[:10]):
            field_upper = field.upper()
            for log_type, name in LOG_TYPES.items():
                if log_type == field_upper:
                    return name
        return "unknown"

    def _parse_traffic(
        self, fields: list, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse traffic log entry."""
        # Standard traffic log field positions (may vary)
        # These are approximate - PA logs can vary by version
        timestamp = self._extract_timestamp(fields)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="PaloAlto_traffic",
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Try to extract network fields from common positions
        self._extract_network_fields(event, fields)

        event.raw_payload = line
        return event

    def _parse_threat(
        self, fields: list, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse threat log entry."""
        timestamp = self._extract_timestamp(fields)

        # Threat logs are high priority
        severity = EventSeverity.HIGH

        # Try to find severity field
        for field in fields:
            field_lower = field.lower()
            if field_lower in THREAT_SEVERITY:
                severity = THREAT_SEVERITY[field_lower]
                break

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="PaloAlto_threat",
            severity=severity,
            parser_name=self.name,
        )

        self._extract_network_fields(event, fields)

        # Try to find threat name
        for field in fields:
            if any(indicator in field.lower() for indicator in
                   ["malware", "virus", "spyware", "vulnerability", "flood", "scan"]):
                event.process_name = field  # Store threat name
                break

        event.raw_payload = line
        return event

    def _parse_generic(
        self, fields: list, line: str, line_num: int, source_file: str, log_type: str
    ) -> UnifiedEvent:
        """Parse generic Palo Alto log entry."""
        timestamp = self._extract_timestamp(fields)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"PaloAlto_{log_type}",
            severity=EventSeverity.INFO,
            parser_name=self.name,
            raw_payload=line,
        )

        self._extract_network_fields(event, fields)
        return event

    def _extract_timestamp(self, fields: list) -> datetime:
        """Extract timestamp from fields."""
        # Look for timestamp patterns in fields
        for field in fields[:10]:
            # Try various formats
            for fmt in [
                "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%dT%H:%M:%S",
            ]:
                try:
                    dt = datetime.strptime(field, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        return datetime.now(timezone.utc)

    def _extract_network_fields(self, event: UnifiedEvent, fields: list) -> None:
        """Extract network fields from log entry."""
        # Look for IP addresses
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        ips_found = []
        ports_found = []

        for field in fields:
            if ip_pattern.match(field):
                ips_found.append(field)
            elif field.isdigit():
                port = int(field)
                if 1 <= port <= 65535:
                    ports_found.append(port)

        # Assign source/dest (first two IPs typically src/dst)
        if len(ips_found) >= 1:
            event.source_ip = ips_found[0]
        if len(ips_found) >= 2:
            event.dest_ip = ips_found[1]

        # Assign ports
        if len(ports_found) >= 1:
            event.source_port = ports_found[0]
        if len(ports_found) >= 2:
            event.dest_port = ports_found[1]

        # Look for username
        for field in fields:
            if "@" in field or "\\" in field:
                event.username = field
                break
