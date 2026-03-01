"""Apache and Nginx log parser for ARGUS.

Parses Apache Combined Log Format and Nginx access logs.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Apache Combined Log Format regex
# LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+'                      # Client IP
    r'(?P<ident>\S+)\s+'                           # RFC 1413 identity
    r'(?P<user>\S+)\s+'                            # User
    r'\[(?P<timestamp>[^\]]+)\]\s+'                # Timestamp
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'  # Request
    r'(?P<status>\d+)\s+'                          # Status
    r'(?P<size>\S+)'                               # Size
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'  # Optional Referer and UA
)

# Nginx default log format (similar to Apache combined)
NGINX_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+-\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


class ApacheParser(BaseParser):
    """Parser for Apache Combined Log Format."""

    name = "apache"
    description = "Apache Combined Log Format"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Apache log file."""
        if file_path.suffix.lower() != ".log":
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Try to match Apache combined format
                    if APACHE_COMBINED_PATTERN.match(line):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Apache log file."""
        result = self._create_result(file_path)
        system_name = file_path.stem.upper()

        line_num = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = self._parse_line(line, line_num, file_path.name, system_name)
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Apache log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str, system_name: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single log line."""
        match = APACHE_COMBINED_PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp: "10/Oct/2000:13:55:36 -0700"
        timestamp = self._parse_timestamp(data.get("timestamp", ""))
        if not timestamp:
            return None

        # Get status code
        status_code = int(data.get("status", 0))
        severity = self._get_severity(status_code)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Apache",
            source_system=system_name,
            severity=severity,
            parser_name=self.name,
            source_ip=data.get("client_ip"),
            username=data.get("user") if data.get("user") != "-" else None,
            http_method=data.get("method"),
            uri=data.get("uri"),
            status_code=status_code,
            user_agent=data.get("user_agent"),
            referrer=data.get("referer") if data.get("referer") != "-" else None,
            raw_payload=line,
        )

        # Extract query string from URI
        if "?" in (event.uri or ""):
            uri, query = event.uri.split("?", 1)
            event.uri = uri
            event.query_string = query

        return event

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse Apache timestamp format."""
        # Format: 10/Oct/2000:13:55:36 -0700
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        # Try without timezone
        try:
            dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _get_severity(self, status_code: int) -> EventSeverity:
        """Get severity based on HTTP status code."""
        if status_code >= 500:
            return EventSeverity.MEDIUM
        elif status_code >= 400:
            return EventSeverity.LOW
        return EventSeverity.INFO


class NginxParser(BaseParser):
    """Parser for Nginx access logs."""

    name = "nginx"
    description = "Nginx access logs"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Nginx log file."""
        if file_path.suffix.lower() != ".log":
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Nginx format is very similar to Apache
                    # Differentiate by checking for nginx-specific patterns
                    if NGINX_PATTERN.match(line):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Nginx log file."""
        result = self._create_result(file_path)
        system_name = file_path.stem.upper()

        line_num = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = self._parse_line(line, line_num, file_path.name, system_name)
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Nginx log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str, system_name: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single log line."""
        match = NGINX_PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(data.get("timestamp", ""))
        if not timestamp:
            return None

        status_code = int(data.get("status", 0))
        severity = EventSeverity.INFO
        if status_code >= 500:
            severity = EventSeverity.MEDIUM
        elif status_code >= 400:
            severity = EventSeverity.LOW

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Nginx",
            source_system=system_name,
            severity=severity,
            parser_name=self.name,
            source_ip=data.get("client_ip"),
            username=data.get("user") if data.get("user") != "-" else None,
            http_method=data.get("method"),
            uri=data.get("uri"),
            status_code=status_code,
            user_agent=data.get("user_agent"),
            referrer=data.get("referer") if data.get("referer") != "-" else None,
            raw_payload=line,
        )

        # Extract query string
        if "?" in (event.uri or ""):
            uri, query = event.uri.split("?", 1)
            event.uri = uri
            event.query_string = query

        return event

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse Nginx timestamp format."""
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        try:
            dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
