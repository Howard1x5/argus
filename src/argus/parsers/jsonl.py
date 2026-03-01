"""JSON Lines (NDJSON) parser for ARGUS.

Parses newline-delimited JSON files, common export format from SIEMs and tools.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class JSONLinesParser(BaseParser):
    """Parser for JSON Lines / NDJSON format."""

    name = "jsonl"
    description = "JSON Lines / NDJSON format"
    supported_extensions = [".jsonl", ".ndjson", ".json"]

    # Common timestamp field names
    TIMESTAMP_FIELDS = [
        "timestamp", "@timestamp", "time", "datetime", "date", "ts",
        "eventTime", "event_time", "created", "createdAt", "logged_at",
        "TimeCreated", "eventTimestamp"
    ]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a JSON Lines file."""
        # Must be .jsonl or .ndjson, or .json with multiple lines
        ext = file_path.suffix.lower()

        if ext in [".jsonl", ".ndjson"]:
            return True

        if ext != ".json":
            return False

        # For .json files, check if it's actually NDJSON
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                second_line = f.readline().strip()

                # Must have multiple lines that are each valid JSON
                if not first_line or not second_line:
                    return False

                try:
                    json.loads(first_line)
                    json.loads(second_line)
                    return True
                except json.JSONDecodeError:
                    return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a JSON Lines file."""
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
                        record = json.loads(line)
                        event = self._parse_record(record, line_num, file_path.name)
                        if event:
                            result.add_event(event)
                    except json.JSONDecodeError as e:
                        result.add_warning(f"Line {line_num}: Invalid JSON - {str(e)}")
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse JSONL file: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single JSON record."""
        if not isinstance(record, dict):
            return None

        # Extract timestamp
        timestamp = self._extract_timestamp(record)
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Determine event type
        event_type = self._determine_event_type(record)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=event_type,
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Map common fields
        self._apply_common_fields(event, record)

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _extract_timestamp(self, record: dict) -> Optional[datetime]:
        """Extract timestamp from record."""
        for field in self.TIMESTAMP_FIELDS:
            if field in record:
                ts = self._parse_timestamp_value(record[field])
                if ts:
                    return ts

        # Check nested fields
        for key in ["event", "data", "metadata"]:
            if key in record and isinstance(record[key], dict):
                for field in self.TIMESTAMP_FIELDS:
                    if field in record[key]:
                        ts = self._parse_timestamp_value(record[key][field])
                        if ts:
                            return ts

        return None

    def _parse_timestamp_value(self, value) -> Optional[datetime]:
        """Parse a timestamp value."""
        if isinstance(value, (int, float)):
            # Unix timestamp
            try:
                if value > 1e12:  # Milliseconds
                    value = value / 1000
                return datetime.fromtimestamp(value, tz=timezone.utc)
            except (ValueError, OSError):
                return None

        if isinstance(value, str):
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ]

            for fmt in formats:
                try:
                    dt = datetime.strptime(value.replace("Z", "+0000"), fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except ValueError:
                    continue

        return None

    def _determine_event_type(self, record: dict) -> str:
        """Determine event type from record."""
        # Check common type indicators
        for field in ["event_type", "eventType", "type", "action", "category"]:
            if field in record and record[field]:
                return f"JSONL_{record[field]}"

        # Check for nested event info
        if "event" in record and isinstance(record["event"], dict):
            event_info = record["event"]
            for field in ["type", "action", "category"]:
                if field in event_info and event_info[field]:
                    return f"JSONL_{event_info[field]}"

        return "JSONL"

    def _apply_common_fields(self, event: UnifiedEvent, record: dict) -> None:
        """Apply common fields from record."""
        # Flatten nested structures for field extraction
        flat = self._flatten_dict(record)

        # Source IP
        for key in ["source_ip", "src_ip", "srcip", "client_ip", "ip", "sourceAddress"]:
            if key in flat and flat[key]:
                event.source_ip = str(flat[key])
                break

        # Destination IP
        for key in ["dest_ip", "dst_ip", "dstip", "destination_ip", "destinationAddress"]:
            if key in flat and flat[key]:
                event.dest_ip = str(flat[key])
                break

        # Ports
        for key in ["source_port", "src_port", "srcport"]:
            if key in flat and flat[key]:
                try:
                    event.source_port = int(flat[key])
                except (ValueError, TypeError):
                    pass
                break

        for key in ["dest_port", "dst_port", "dstport", "destination_port"]:
            if key in flat and flat[key]:
                try:
                    event.dest_port = int(flat[key])
                except (ValueError, TypeError):
                    pass
                break

        # Username
        for key in ["user", "username", "user_name", "account", "principal"]:
            if key in flat and flat[key]:
                event.username = str(flat[key])
                break

        # Hostname
        for key in ["host", "hostname", "computer", "machine", "source_host"]:
            if key in flat and flat[key]:
                event.source_system = str(flat[key])
                break

        # Process
        for key in ["process", "process_name", "executable", "command"]:
            if key in flat and flat[key]:
                event.process_name = str(flat[key])
                break

        # Command line
        for key in ["command_line", "cmdline", "args", "arguments"]:
            if key in flat and flat[key]:
                event.command_line = str(flat[key])
                break

    def _flatten_dict(self, d: dict, parent_key: str = "", sep: str = "_") -> dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            else:
                items.append((k, v))  # Keep short key for common field matching
                items.append((new_key, v))
        return dict(items)
