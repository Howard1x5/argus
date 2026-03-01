"""Syslog parser for ARGUS.

Parses Linux/Unix syslog format logs including auth.log, syslog, secure.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Standard syslog pattern: Month Day HH:MM:SS hostname process[pid]: message
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# RFC 5424 syslog pattern
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)?\s*"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<message>.*)$"
)

# Month mapping
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Suspicious patterns in syslog
SUSPICIOUS_PATTERNS = [
    (r"authentication failure", EventSeverity.MEDIUM),
    (r"failed password", EventSeverity.MEDIUM),
    (r"invalid user", EventSeverity.MEDIUM),
    (r"did not receive identification", EventSeverity.LOW),
    (r"break-in attempt", EventSeverity.HIGH),
    (r"refused connect", EventSeverity.LOW),
    (r"accepted.*root", EventSeverity.MEDIUM),
    (r"sudo:.*command", EventSeverity.LOW),
    (r"su\[.*\].*to root", EventSeverity.MEDIUM),
    (r"new user", EventSeverity.MEDIUM),
    (r"useradd", EventSeverity.MEDIUM),
    (r"usermod", EventSeverity.MEDIUM),
    (r"userdel", EventSeverity.MEDIUM),
    (r"passwd.*changed", EventSeverity.MEDIUM),
]


class SyslogParser(BaseParser):
    """Parser for syslog format logs."""

    name = "syslog"
    description = "Linux/Unix syslog format (auth.log, syslog, secure)"
    supported_extensions = [".log", ""]

    # Common syslog file names
    SYSLOG_NAMES = {
        "syslog", "auth.log", "secure", "messages", "daemon.log",
        "kern.log", "cron.log", "maillog", "auth", "authlog"
    }

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a syslog file."""
        # Check by filename
        name_lower = file_path.name.lower()
        if name_lower in cls.SYSLOG_NAMES:
            return True

        # Check content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Try matching syslog patterns
                    if SYSLOG_PATTERN.match(line) or RFC5424_PATTERN.match(line):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a syslog file."""
        result = self._create_result(file_path)

        # Determine current year (syslog doesn't include year)
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
                        event = self._parse_line(
                            line, line_num, file_path.name, current_year
                        )
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse syslog: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str, year: int
    ) -> Optional[UnifiedEvent]:
        """Parse a single syslog line."""
        # Try standard syslog format
        match = SYSLOG_PATTERN.match(line)
        if match:
            return self._parse_standard_syslog(match, line, line_num, source_file, year)

        # Try RFC 5424 format
        match = RFC5424_PATTERN.match(line)
        if match:
            return self._parse_rfc5424(match, line, line_num, source_file)

        return None

    def _parse_standard_syslog(
        self, match: re.Match, line: str, line_num: int, source_file: str, year: int
    ) -> UnifiedEvent:
        """Parse standard syslog format."""
        data = match.groupdict()

        # Build timestamp
        month = MONTHS.get(data["month"], 1)
        day = int(data["day"])
        time_parts = data["time"].split(":")
        hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])

        timestamp = datetime(
            year=year, month=month, day=day,
            hour=hour, minute=minute, second=second,
            tzinfo=timezone.utc
        )

        # Determine severity from message
        severity = self._assess_severity(data["message"])

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Syslog",
            source_system=data["hostname"],
            severity=severity,
            parser_name=self.name,
            process_name=data["process"],
            raw_payload=line,
        )

        if data["pid"]:
            try:
                event.process_id = int(data["pid"])
            except ValueError:
                pass

        # Extract additional fields from message
        self._parse_message(event, data["message"])

        return event

    def _parse_rfc5424(
        self, match: re.Match, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse RFC 5424 syslog format."""
        data = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_rfc5424_timestamp(data["timestamp"])
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        severity = self._assess_severity(data["message"])

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Syslog",
            source_system=data["hostname"],
            severity=severity,
            parser_name=self.name,
            process_name=data["appname"],
            raw_payload=line,
        )

        if data["procid"] and data["procid"] != "-":
            try:
                event.process_id = int(data["procid"])
            except ValueError:
                pass

        self._parse_message(event, data["message"])

        return event

    def _parse_rfc5424_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse RFC 5424 timestamp."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue

        return None

    def _assess_severity(self, message: str) -> EventSeverity:
        """Assess severity based on message content."""
        message_lower = message.lower()

        for pattern, severity in SUSPICIOUS_PATTERNS:
            if re.search(pattern, message_lower):
                return severity

        return EventSeverity.INFO

    def _parse_message(self, event: UnifiedEvent, message: str) -> None:
        """Extract additional fields from syslog message."""
        # Extract IP addresses
        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", message)
        if ip_match:
            event.source_ip = ip_match.group(1)

        # Extract username
        user_patterns = [
            r"user[=:\s]+(\S+)",
            r"for\s+(?:user\s+)?(\S+)",
            r"USER=(\S+)",
            r"user\s+'([^']+)'",
        ]
        for pattern in user_patterns:
            user_match = re.search(pattern, message, re.IGNORECASE)
            if user_match:
                event.username = user_match.group(1)
                break

        # Extract port
        port_match = re.search(r"port\s+(\d+)", message)
        if port_match:
            try:
                event.source_port = int(port_match.group(1))
            except ValueError:
                pass
