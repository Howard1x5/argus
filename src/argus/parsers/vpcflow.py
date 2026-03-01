"""AWS VPC Flow Logs parser for ARGUS.

Parses AWS VPC Flow Logs in various formats (text, Parquet, JSON).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Default VPC Flow Log v2 fields
VPC_FLOW_FIELDS_V2 = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status"
]

# Protocol number to name mapping
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


class VPCFlowParser(BaseParser):
    """Parser for AWS VPC Flow Logs."""

    name = "vpcflow"
    description = "AWS VPC Flow Logs"
    supported_extensions = [".log", ".txt", ".json"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a VPC Flow Log."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()

                # Check for header line
                if first_line.startswith("version account-id"):
                    return True

                # Check for space-separated format with expected fields
                parts = first_line.split()
                if len(parts) >= 14:
                    # Check if it looks like VPC flow log
                    try:
                        # Version should be 2-5
                        version = int(parts[0])
                        if 2 <= version <= 5:
                            return True
                    except ValueError:
                        pass

                # Check for JSON format
                if first_line.startswith("{"):
                    try:
                        record = json.loads(first_line)
                        return any(k in record for k in ["srcaddr", "dstaddr", "srcport"])
                    except json.JSONDecodeError:
                        pass

                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a VPC Flow Log file."""
        result = self._create_result(file_path)

        fields = VPC_FLOW_FIELDS_V2.copy()
        line_num = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    # Check for header line
                    if line.startswith("version account-id") or line.startswith("version,account-id"):
                        fields = line.replace(",", " ").split()
                        result.metadata["fields"] = fields
                        continue

                    try:
                        # Try JSON format first
                        if line.startswith("{"):
                            record = json.loads(line)
                            event = self._parse_json_record(record, line_num, file_path.name)
                        else:
                            event = self._parse_text_record(line, fields, line_num, file_path.name)

                        if event:
                            result.add_event(event)
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse VPC Flow Log: {str(e)}")

        return result

    def _parse_text_record(
        self, line: str, fields: list, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a text format VPC Flow Log record."""
        # Handle both space and comma separated
        if "," in line:
            values = line.split(",")
        else:
            values = line.split()

        if len(values) < len(fields):
            return None

        data = {fields[i]: values[i] for i in range(len(fields))}

        return self._create_event(data, line, line_num, source_file)

    def _parse_json_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a JSON format VPC Flow Log record."""
        # Map JSON keys to standard field names
        data = {}
        key_mapping = {
            "srcaddr": "srcaddr",
            "dstaddr": "dstaddr",
            "srcport": "srcport",
            "dstport": "dstport",
            "protocol": "protocol",
            "action": "action",
            "start": "start",
            "end": "end",
            "packets": "packets",
            "bytes": "bytes",
        }

        for json_key, field in key_mapping.items():
            if json_key in record:
                data[field] = record[json_key]

        return self._create_event(data, json.dumps(record), line_num, source_file)

    def _create_event(
        self, data: dict, raw: str, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Create event from parsed data."""
        # Get timestamp from start time (Unix epoch)
        timestamp = datetime.now(timezone.utc)
        start_time = data.get("start")
        if start_time and start_time != "-":
            try:
                timestamp = datetime.fromtimestamp(int(start_time), tz=timezone.utc)
            except (ValueError, TypeError):
                pass

        # Determine severity based on action
        action = data.get("action", "").upper()
        severity = EventSeverity.INFO
        if action == "REJECT":
            severity = EventSeverity.MEDIUM
        elif data.get("log-status", "").upper() in ["NODATA", "SKIPDATA"]:
            severity = EventSeverity.LOW

        # Get protocol name
        proto_num = data.get("protocol")
        proto_name = "UNKNOWN"
        if proto_num and proto_num != "-":
            try:
                proto_name = PROTOCOLS.get(int(proto_num), f"PROTO_{proto_num}")
            except ValueError:
                proto_name = proto_num

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"VPCFlow_{action}_{proto_name}",
            severity=severity,
            parser_name=self.name,
        )

        # Network fields
        srcaddr = data.get("srcaddr")
        if srcaddr and srcaddr != "-":
            event.source_ip = srcaddr

        dstaddr = data.get("dstaddr")
        if dstaddr and dstaddr != "-":
            event.dest_ip = dstaddr

        srcport = data.get("srcport")
        if srcport and srcport != "-":
            try:
                event.source_port = int(srcport)
            except ValueError:
                pass

        dstport = data.get("dstport")
        if dstport and dstport != "-":
            try:
                event.dest_port = int(dstport)
            except ValueError:
                pass

        event.raw_payload = raw
        return event
