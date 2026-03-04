"""IIS W3C Extended Log Format parser for ARGUS.

Parses IIS web server logs in W3C Extended Log Format.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Status code to severity mapping
STATUS_SEVERITY = {
    range(200, 300): EventSeverity.INFO,      # Success
    range(300, 400): EventSeverity.INFO,      # Redirect
    range(400, 500): EventSeverity.LOW,       # Client error
    range(500, 600): EventSeverity.MEDIUM,    # Server error
}

# Suspicious patterns in URIs
SUSPICIOUS_URI_PATTERNS = [
    r"\.\.[\\/]",                    # Path traversal
    r"['\"].*(?:or|and).*['\"]",     # SQL injection
    r"<script",                      # XSS
    r"cmd\.exe|powershell",          # Command execution
    r"\.(?:asp|php|jsp)x?\?",        # Webshell access patterns
    r"union\s+select",               # SQL injection
    r"exec\s*\(",                    # SQL injection
]


class IISParser(BaseParser):
    """Parser for IIS W3C Extended Log Format."""

    name = "iis"
    description = "IIS W3C Extended Log Format"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an IIS W3C log file."""
        if file_path.suffix.lower() != ".log":
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                # Read first few lines
                for i, line in enumerate(f):
                    if i > 20:
                        break
                    # Look for W3C header
                    if line.startswith("#Software: Microsoft Internet Information Services"):
                        return True
                    if line.startswith("#Fields:") and any(
                        field in line for field in ["s-ip", "cs-uri-stem", "sc-status"]
                    ):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an IIS log file."""
        result = self._create_result(file_path)

        # Try to extract system name from filename (e.g., WEB01_u_ex25030904.log)
        system_name = self._extract_system_name(file_path)
        result.metadata["system_name"] = system_name

        fields = None
        line_num = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()

                    if not line:
                        continue

                    # Parse directive lines
                    if line.startswith("#"):
                        if line.startswith("#Fields:"):
                            fields = line[8:].strip().split()
                            result.metadata["fields"] = fields
                        elif line.startswith("#Date:"):
                            result.metadata["log_date"] = line[6:].strip()
                        continue

                    # Parse data lines
                    if not fields:
                        result.add_warning(f"Line {line_num}: No #Fields directive found")
                        continue

                    try:
                        event = self._parse_line(
                            line, fields, line_num, file_path.name, system_name
                        )
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse IIS log: {str(e)}")

        return result

    def _extract_system_name(self, file_path: Path) -> str:
        """Extract system name from IIS log filename."""
        # IIS log naming: u_exYYMMDD.log or u_extendYYMMDD.log
        # Often prefixed with server name: WEB01_u_ex250309.log
        name = file_path.stem
        parts = name.split("_")
        if len(parts) > 1 and parts[0].upper() not in ["U", "EX", "EXTEND"]:
            return parts[0].upper()
        return "WEBSERVER"

    def _parse_line(
        self, line: str, fields: list, line_num: int, source_file: str, system_name: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single log line."""
        # Parse IIS log line handling quoted strings (User-Agent, etc.)
        values = self._split_iis_line(line)

        # Handle field count mismatch
        if len(values) < len(fields):
            # Pad with empty values
            values.extend(["-"] * (len(fields) - len(values)))
        elif len(values) > len(fields):
            # IIS logs sometimes have extra fields at the end, truncate
            values = values[:len(fields)]

        data = dict(zip(fields, values))

        # Extract timestamp
        timestamp = self._extract_timestamp(data)
        if not timestamp:
            return None

        # Extract status code for severity
        status_code = self._get_int(data, "sc-status")
        severity = self._get_severity(status_code)

        # Check for suspicious patterns
        uri = data.get("cs-uri-stem", "")
        query = data.get("cs-uri-query", "")
        full_uri = f"{uri}?{query}" if query and query != "-" else uri

        if self._is_suspicious(full_uri):
            severity = EventSeverity.HIGH

        # Create event
        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="IIS",
            source_system=system_name,
            severity=severity,
            parser_name=self.name,
        )

        # Apply fields
        event.source_ip = self._get_field(data, "c-ip")
        event.source_port = self._get_int(data, "c-port")
        event.dest_ip = self._get_field(data, "s-ip")
        event.dest_port = self._get_int(data, "s-port")

        event.username = self._get_field(data, "cs-username")

        event.http_method = self._get_field(data, "cs-method")
        event.uri = uri if uri != "-" else None
        event.query_string = query if query != "-" else None
        event.status_code = status_code
        event.user_agent = self._decode_field(data.get("cs(User-Agent)", "-"))
        event.referrer = self._decode_field(data.get("cs(Referer)", "-"))

        # Store raw data
        event.raw_payload = line

        return event

    def _extract_timestamp(self, data: dict) -> Optional[datetime]:
        """Extract timestamp from log fields."""
        date_str = data.get("date")
        time_str = data.get("time")

        if not date_str or not time_str:
            return None

        try:
            dt_str = f"{date_str} {time_str}"
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _get_field(self, data: dict, key: str) -> Optional[str]:
        """Get a field value, returning None for '-'."""
        value = data.get(key, "-")
        return value if value != "-" else None

    def _get_int(self, data: dict, key: str) -> Optional[int]:
        """Get an integer field value."""
        value = data.get(key, "-")
        if value == "-":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _decode_field(self, value: str) -> Optional[str]:
        """Decode URL-encoded field."""
        if value == "-":
            return None
        try:
            # IIS encodes spaces as + and other chars as %XX
            decoded = unquote(value.replace("+", " "))
            return decoded
        except Exception:
            return value

    def _get_severity(self, status_code: Optional[int]) -> EventSeverity:
        """Get severity based on HTTP status code."""
        if status_code is None:
            return EventSeverity.INFO

        for status_range, severity in STATUS_SEVERITY.items():
            if status_code in status_range:
                return severity

        return EventSeverity.INFO

    def _is_suspicious(self, uri: str) -> bool:
        """Check if URI contains suspicious patterns."""
        uri_lower = uri.lower()

        for pattern in SUSPICIOUS_URI_PATTERNS:
            if re.search(pattern, uri_lower, re.IGNORECASE):
                return True

        return False

    def _split_iis_line(self, line: str) -> list:
        """Split IIS log line handling quoted strings and empty fields.

        IIS logs use double-quotes for fields containing spaces (like User-Agent).
        Empty fields are represented as '-' or double spaces.
        """
        values = []
        current = []
        in_quotes = False
        i = 0

        # Handle empty query string (double space before port)
        line = line.replace("  ", " - ")

        while i < len(line):
            char = line[i]

            if char == '"':
                in_quotes = not in_quotes
            elif char == ' ' and not in_quotes:
                if current:
                    values.append(''.join(current))
                    current = []
            else:
                current.append(char)
            i += 1

        # Don't forget the last value
        if current:
            values.append(''.join(current))

        return values
