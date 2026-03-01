"""Proxy log parsers for ARGUS.

Parses Squid, Blue Coat, and generic proxy log formats.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Squid native log format
# timestamp elapsed client action/code size method URL ident hierarchy/from content
SQUID_NATIVE_PATTERN = re.compile(
    r"^(?P<timestamp>\d+\.\d+)\s+"
    r"(?P<elapsed>\d+)\s+"
    r"(?P<client_ip>\S+)\s+"
    r"(?P<result_code>\S+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<hierarchy>\S+)\s+"
    r"(?P<content_type>\S+)"
)

# Squid common log format (CLF)
SQUID_CLF_PATTERN = re.compile(
    r"^(?P<client_ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<size>\d+)"
)


class SquidParser(BaseParser):
    """Parser for Squid proxy logs."""

    name = "squid"
    description = "Squid proxy access logs"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Squid log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Check for Squid patterns
                    if SQUID_NATIVE_PATTERN.match(line):
                        return True
                    if SQUID_CLF_PATTERN.match(line):
                        return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Squid log file."""
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
            result.add_error(f"Failed to parse Squid log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single Squid log line."""
        # Try native format first
        match = SQUID_NATIVE_PATTERN.match(line)
        if match:
            return self._parse_native(match, line, line_num, source_file)

        # Try CLF format
        match = SQUID_CLF_PATTERN.match(line)
        if match:
            return self._parse_clf(match, line, line_num, source_file)

        return None

    def _parse_native(
        self, match: re.Match, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse Squid native format."""
        data = match.groupdict()

        # Parse Unix timestamp
        timestamp = datetime.fromtimestamp(
            float(data["timestamp"]), tz=timezone.utc
        )

        # Parse result code (e.g., TCP_MISS/200)
        result_code = data["result_code"]
        status_code = None
        if "/" in result_code:
            try:
                status_code = int(result_code.split("/")[1])
            except (ValueError, IndexError):
                pass

        severity = self._assess_severity(result_code, data["url"])

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Squid",
            severity=severity,
            parser_name=self.name,
            source_ip=data["client_ip"],
            http_method=data["method"],
            uri=data["url"],
            status_code=status_code,
            username=data["user"] if data["user"] != "-" else None,
            raw_payload=line,
        )

        return event

    def _parse_clf(
        self, match: re.Match, line: str, line_num: int, source_file: str
    ) -> UnifiedEvent:
        """Parse Squid CLF format."""
        data = match.groupdict()

        # Parse timestamp: [10/Oct/2000:13:55:36 -0700]
        try:
            timestamp = datetime.strptime(
                data["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
            ).astimezone(timezone.utc)
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        status_code = int(data["status"]) if data["status"] else None
        severity = self._assess_severity(str(status_code), data["url"])

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Squid",
            severity=severity,
            parser_name=self.name,
            source_ip=data["client_ip"],
            http_method=data["method"],
            uri=data["url"],
            status_code=status_code,
            username=data["user"] if data["user"] != "-" else None,
            raw_payload=line,
        )

        return event

    def _assess_severity(self, result: str, url: str) -> EventSeverity:
        """Assess severity based on result and URL."""
        # Check for denied/blocked
        if "DENIED" in result.upper() or "BLOCKED" in result.upper():
            return EventSeverity.MEDIUM

        # Check for suspicious URLs
        suspicious_patterns = [
            r"\.exe$", r"\.dll$", r"\.ps1$", r"\.bat$",
            r"pastebin\.", r"raw\.github", r"bit\.ly", r"tinyurl",
        ]
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return EventSeverity.MEDIUM

        return EventSeverity.INFO
