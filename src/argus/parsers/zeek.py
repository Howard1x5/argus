"""Zeek (formerly Bro) log parser for ARGUS.

Parses Zeek network security monitor logs.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class ZeekParser(BaseParser):
    """Parser for Zeek log files."""

    name = "zeek"
    description = "Zeek (Bro) network security monitor logs"
    supported_extensions = [".log", ".zeek"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Zeek log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Zeek logs start with #separator
                    if line.startswith("#separator"):
                        return True
                    # Or check for typical Zeek header
                    if line.startswith("#fields"):
                        return True
                    # Skip other comment lines
                    if line.startswith("#"):
                        continue
                    # Non-comment line reached, not a Zeek log
                    break
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Zeek log file."""
        result = self._create_result(file_path)

        separator = "\t"
        fields = None
        types = None
        line_num = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.rstrip("\n")

                    if not line:
                        continue

                    # Parse header directives
                    if line.startswith("#"):
                        if line.startswith("#separator"):
                            # Format: #separator \x09
                            sep_str = line.split(None, 1)[1] if " " in line else "\\x09"
                            separator = self._decode_separator(sep_str)
                        elif line.startswith("#fields"):
                            fields = line.split(separator)[1:]
                            result.metadata["fields"] = fields
                        elif line.startswith("#types"):
                            types = line.split(separator)[1:]
                        elif line.startswith("#path"):
                            result.metadata["log_type"] = line.split(separator)[1]
                        continue

                    if not fields:
                        continue

                    try:
                        event = self._parse_line(
                            line, separator, fields, line_num, file_path.name
                        )
                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Zeek log: {str(e)}")

        return result

    def _decode_separator(self, sep_str: str) -> str:
        """Decode Zeek separator string (e.g., \\x09 for tab)."""
        if sep_str.startswith("\\x"):
            try:
                return chr(int(sep_str[2:], 16))
            except ValueError:
                pass
        return sep_str

    def _parse_line(
        self, line: str, separator: str, fields: list, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single log line."""
        values = line.split(separator)

        if len(values) != len(fields):
            return None

        data = {fields[i]: values[i] for i in range(len(fields))}

        # Get timestamp (Zeek uses Unix epoch)
        timestamp = self._parse_timestamp(data.get("ts"))
        if not timestamp:
            return None

        # Determine event type from log type or fields
        event_type = self._determine_event_type(data, fields)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"Zeek_{event_type}",
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Apply common Zeek fields
        self._apply_fields(event, data)

        # Store raw data
        event.raw_payload = line

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse Zeek timestamp (Unix epoch with microseconds)."""
        if not ts_str or ts_str == "-":
            return None

        try:
            # Zeek timestamps are Unix epoch with decimal seconds
            ts = float(ts_str)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _determine_event_type(self, data: dict, fields: list) -> str:
        """Determine Zeek log type from fields."""
        # Check for common Zeek log types based on fields
        if "query" in fields and "answers" in fields:
            return "dns"
        elif "method" in fields and "uri" in fields:
            return "http"
        elif "certificate" in fields or "validation_status" in fields:
            return "ssl"
        elif "service" in fields and "duration" in fields:
            return "conn"
        elif "user" in fields and "command" in fields:
            return "ftp"
        elif "mailfrom" in fields:
            return "smtp"
        elif "file_id" in fields:
            return "files"
        return "unknown"

    def _apply_fields(self, event: UnifiedEvent, data: dict) -> None:
        """Apply Zeek fields to event."""
        # Skip unset values
        def get_val(key: str) -> Optional[str]:
            val = data.get(key)
            return val if val and val not in ("-", "(empty)") else None

        # Network fields (common across most Zeek logs)
        event.source_ip = get_val("id.orig_h") or get_val("src")
        event.dest_ip = get_val("id.resp_h") or get_val("dst")

        try:
            port = get_val("id.orig_p") or get_val("src_port")
            if port:
                event.source_port = int(port)
        except (ValueError, TypeError):
            pass

        try:
            port = get_val("id.resp_p") or get_val("dst_port")
            if port:
                event.dest_port = int(port)
        except (ValueError, TypeError):
            pass

        # HTTP fields
        event.http_method = get_val("method")
        event.uri = get_val("uri")
        event.user_agent = get_val("user_agent")
        event.referrer = get_val("referrer")

        try:
            status = get_val("status_code")
            if status:
                event.status_code = int(status)
        except (ValueError, TypeError):
            pass

        # DNS fields
        query = get_val("query")
        if query:
            event.uri = query  # Store DNS query in URI field

        # Username
        event.username = get_val("user") or get_val("username")

        # File hash
        event.file_hash = get_val("md5") or get_val("sha1") or get_val("sha256")
