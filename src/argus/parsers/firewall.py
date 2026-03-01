"""Windows Firewall log parser for ARGUS.

Parses Windows Firewall log files (pfirewall.log).
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class WindowsFirewallParser(BaseParser):
    """Parser for Windows Firewall logs."""

    name = "windows_firewall"
    description = "Windows Firewall logs (pfirewall.log)"
    supported_extensions = [".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Windows Firewall log."""
        # Check filename
        if "firewall" in file_path.name.lower():
            return True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = []
                for i, line in enumerate(f):
                    if i > 10:
                        break
                    lines.append(line)

                content = "".join(lines)

                # Must have Windows Firewall specific header
                if "#Software: Microsoft Windows Firewall" in content:
                    return True

                # Or have firewall-specific fields (action, protocol, src-ip, dst-ip)
                if "#Fields:" in content and "action" in content.lower():
                    # Make sure it's NOT an IIS log
                    if "Microsoft Internet Information Services" in content:
                        return False
                    if any(iis_field in content for iis_field in ["cs-uri-stem", "sc-status", "cs-method"]):
                        return False
                    return True

                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Windows Firewall log file."""
        result = self._create_result(file_path)

        fields = None
        line_num = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()

                    if not line:
                        continue

                    # Parse header lines
                    if line.startswith("#"):
                        if line.startswith("#Fields:"):
                            # Parse field names
                            fields = line[8:].strip().split()
                            result.metadata["fields"] = fields
                        continue

                    # Need fields to parse data
                    if not fields:
                        continue

                    try:
                        event = self._parse_line(
                            line, fields, line_num, file_path.name
                        )
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse firewall log: {str(e)}")

        return result

    def _parse_line(
        self, line: str, fields: list, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single firewall log line."""
        values = line.split()

        if len(values) < len(fields):
            return None

        data = {fields[i]: values[i] for i in range(len(fields))}

        # Get timestamp
        timestamp = self._extract_timestamp(data)
        if not timestamp:
            return None

        # Determine action and severity
        action = data.get("action", "").upper()
        severity = EventSeverity.INFO
        if action == "DROP":
            severity = EventSeverity.MEDIUM
        elif action == "ALLOW" and data.get("direction", "").upper() == "IN":
            severity = EventSeverity.LOW

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"Firewall_{action}",
            severity=severity,
            parser_name=self.name,
        )

        # Network fields
        event.source_ip = self._get_field(data, "src-ip")
        event.dest_ip = self._get_field(data, "dst-ip")

        src_port = self._get_field(data, "src-port")
        if src_port:
            try:
                event.source_port = int(src_port)
            except ValueError:
                pass

        dst_port = self._get_field(data, "dst-port")
        if dst_port:
            try:
                event.dest_port = int(dst_port)
            except ValueError:
                pass

        # Protocol
        proto = self._get_field(data, "protocol")
        if proto:
            event.event_type = f"Firewall_{action}_{proto}"

        # Path (for local process)
        event.file_path = self._get_field(data, "path")

        # Store raw line
        event.raw_payload = line

        return event

    def _extract_timestamp(self, data: dict) -> Optional[datetime]:
        """Extract timestamp from parsed fields."""
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
        """Get field value, returning None for '-'."""
        value = data.get(key, "-")
        return value if value != "-" else None
