"""Cisco ASA firewall log parser for ARGUS.

Parses Cisco ASA/Firepower syslog format logs.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Cisco ASA message ID patterns and severity
# Format: %ASA-severity-message_id
ASA_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?\s*"
    r"(?P<hostname>\S+)?\s*"
    r"%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s*"
    r"(?P<message>.*)$"
)

# Alternative pattern for newer format
ASA_ALT_PATTERN = re.compile(
    r"^(?P<timestamp>[\d-]+T[\d:]+(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s*"
    r"(?P<message>.*)$"
)

# High-interest ASA message IDs
HIGH_INTEREST_MSGIDS = {
    # Denied connections
    "106001", "106006", "106007", "106014", "106015", "106023",
    # Failed authentication
    "113004", "113005", "113012", "113015",
    # VPN events
    "713228", "722051", "722037",
    # Threat detection
    "733100", "733101", "733102", "733103", "733104", "733105",
    # Access denied
    "419001", "419002",
    # Connection teardown with threat
    "710003",
}


class CiscoASAParser(BaseParser):
    """Parser for Cisco ASA firewall logs."""

    name = "cisco_asa"
    description = "Cisco ASA/Firepower firewall logs"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Cisco ASA log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 20:
                        break
                    if "%ASA-" in line:
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Cisco ASA log file."""
        result = self._create_result(file_path)
        current_year = datetime.now().year

        line_num = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = self._parse_line(line, line_num, file_path.name, current_year)
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Cisco ASA log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str, year: int
    ) -> Optional[UnifiedEvent]:
        """Parse a single ASA log line."""
        # Try standard pattern
        match = ASA_PATTERN.match(line)
        if not match:
            match = ASA_ALT_PATTERN.match(line)

        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(data.get("timestamp"), year)

        # Map severity (ASA uses 0-7, 0=emergency, 7=debug)
        asa_severity = int(data.get("severity", 6))
        severity = self._map_severity(asa_severity, data.get("msgid", ""))

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"CiscoASA_{data['msgid']}",
            source_system=data.get("hostname"),
            severity=severity,
            parser_name=self.name,
            raw_payload=line,
        )

        # Parse message content for network info
        self._parse_message(event, data.get("message", ""))

        return event

    def _parse_timestamp(self, ts_str: Optional[str], year: int) -> datetime:
        """Parse ASA timestamp."""
        if not ts_str:
            return datetime.now(timezone.utc)

        # Try ISO format first
        try:
            if "T" in ts_str:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        # Try syslog format: "Mar 15 10:30:45"
        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

        return datetime.now(timezone.utc)

    def _map_severity(self, asa_level: int, msgid: str) -> EventSeverity:
        """Map ASA severity level to EventSeverity."""
        # Check for high-interest message IDs first
        if msgid in HIGH_INTEREST_MSGIDS:
            return EventSeverity.HIGH

        # Map by ASA level
        if asa_level <= 2:  # Emergency, Alert, Critical
            return EventSeverity.CRITICAL
        elif asa_level == 3:  # Error
            return EventSeverity.HIGH
        elif asa_level == 4:  # Warning
            return EventSeverity.MEDIUM
        elif asa_level == 5:  # Notice
            return EventSeverity.LOW
        else:  # Info, Debug
            return EventSeverity.INFO

    def _parse_message(self, event: UnifiedEvent, message: str) -> None:
        """Parse ASA message content for network info."""
        # Extract IP addresses
        ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ips = re.findall(ip_pattern, message)

        if len(ips) >= 1:
            event.source_ip = ips[0]
        if len(ips) >= 2:
            event.dest_ip = ips[1]

        # Extract ports
        port_pattern = r"/(\d{1,5})"
        ports = re.findall(port_pattern, message)
        if len(ports) >= 1:
            try:
                event.source_port = int(ports[0])
            except ValueError:
                pass
        if len(ports) >= 2:
            try:
                event.dest_port = int(ports[1])
            except ValueError:
                pass

        # Extract username
        user_patterns = [
            r"user[=:\s]+['\"]?(\S+)['\"]?",
            r"User\s+'([^']+)'",
            r"username=(\S+)",
        ]
        for pattern in user_patterns:
            user_match = re.search(pattern, message, re.IGNORECASE)
            if user_match:
                event.username = user_match.group(1)
                break

        # Check for deny/drop
        if re.search(r"\b(denied|dropped|teardown|failed)\b", message, re.IGNORECASE):
            if event.severity == EventSeverity.INFO:
                event.severity = EventSeverity.LOW
