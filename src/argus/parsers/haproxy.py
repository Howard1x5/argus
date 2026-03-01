"""HAProxy log parser for ARGUS.

Parses HAProxy access and error logs.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# HAProxy HTTP log format
# <frontend_name> <bind_name>/<server_name> <Tq>/<Tw>/<Tc>/<Tr>/<Tt>
# <status_code> <bytes_read> <captured_request_cookie> <captured_response_cookie>
# <termination_state> <actconn>/<feconn>/<beconn>/<srv_conn>/<retries>
# <srv_queue>/<backend_queue> "<http_request>"
HAPROXY_HTTP_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<client_ip>[\d.]+):(?P<client_port>\d+)\s+"
    r"\[(?P<accept_date>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+"
    r"(?P<backend>\S+)/(?P<server>\S+)\s+"
    r"(?P<timers>\S+)\s+"
    r"(?P<status_code>\d+)\s+"
    r"(?P<bytes_read>\d+)\s+"
    r"(?P<cookies>\S+)\s+"
    r"(?P<cookies2>\S+)\s+"
    r"(?P<term_state>\S+)\s+"
    r"(?P<connections>\S+)\s+"
    r"(?P<queues>\S+)\s+"
    r'[{"]*(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"}\s]+)'
)

# Simplified pattern for when full pattern doesn't match
HAPROXY_SIMPLE_PATTERN = re.compile(
    r"(?P<client_ip>[\d.]+):(?P<client_port>\d+).*?"
    r"(?P<status_code>\d{3}).*?"
    r'(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<uri>\S+)'
)


class HAProxyParser(BaseParser):
    """Parser for HAProxy logs."""

    name = "haproxy"
    description = "HAProxy load balancer logs"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an HAProxy log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 20:
                        break
                    # Check for HAProxy indicators
                    if "haproxy" in line.lower():
                        return True
                    # Check for HAProxy log patterns
                    if HAPROXY_HTTP_PATTERN.search(line):
                        return True
                    # Check for frontend/backend pattern
                    if re.search(r"\S+/\S+\s+\d+/\d+/\d+/\d+/\d+\s+\d{3}", line):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an HAProxy log file."""
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
            result.add_error(f"Failed to parse HAProxy log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str, year: int
    ) -> Optional[UnifiedEvent]:
        """Parse a single HAProxy log line."""
        # Try full pattern
        match = HAPROXY_HTTP_PATTERN.search(line)
        if match:
            return self._parse_full_match(match, line, line_num, source_file, year)

        # Try simple pattern
        match = HAPROXY_SIMPLE_PATTERN.search(line)
        if match:
            return self._parse_simple_match(match, line, line_num, source_file)

        return None

    def _parse_full_match(
        self, match: re.Match, line: str, line_num: int, source_file: str, year: int
    ) -> UnifiedEvent:
        """Parse full HAProxy log match."""
        data = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(data.get("timestamp"), year)

        # Get status code
        status_code = int(data.get("status_code", 0))
        severity = self._get_severity(status_code)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="HAProxy",
            source_system=data.get("hostname"),
            severity=severity,
            parser_name=self.name,
            source_ip=data.get("client_ip"),
            http_method=data.get("method"),
            uri=data.get("uri"),
            status_code=status_code,
            raw_payload=line,
        )

        # Parse client port
        if data.get("client_port"):
            try:
                event.source_port = int(data["client_port"])
            except ValueError:
                pass

        return event

    def _parse_simple_match(
        self, match: re.Match, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse simple HAProxy log match."""
        data = match.groupdict()

        status_code = int(data.get("status_code", 0))
        severity = self._get_severity(status_code)

        event = UnifiedEvent(
            timestamp_utc=datetime.now(timezone.utc),
            source_file=source_file,
            source_line=line_num,
            event_type="HAProxy",
            severity=severity,
            parser_name=self.name,
            source_ip=data.get("client_ip"),
            http_method=data.get("method"),
            uri=data.get("uri"),
            status_code=status_code,
            raw_payload=line,
        )

        if data.get("client_port"):
            try:
                event.source_port = int(data["client_port"])
            except ValueError:
                pass

        return event

    def _parse_timestamp(self, ts_str: Optional[str], year: int) -> datetime:
        """Parse HAProxy timestamp."""
        if not ts_str:
            return datetime.now(timezone.utc)

        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)

    def _get_severity(self, status_code: int) -> EventSeverity:
        """Get severity based on HTTP status code."""
        if status_code >= 500:
            return EventSeverity.MEDIUM
        elif status_code >= 400:
            return EventSeverity.LOW
        return EventSeverity.INFO
