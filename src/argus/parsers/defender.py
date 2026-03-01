"""Windows Defender log parser for ARGUS.

Parses Windows Defender/Microsoft Defender operational logs.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Defender Event IDs
DEFENDER_EVENTS = {
    # Detection events
    1006: ("Malware_Detected", EventSeverity.HIGH),
    1007: ("Malware_Action_Taken", EventSeverity.HIGH),
    1008: ("Malware_Action_Failed", EventSeverity.CRITICAL),
    1009: ("Restore_From_Quarantine", EventSeverity.MEDIUM),
    1010: ("Malware_Not_Removed", EventSeverity.CRITICAL),
    1011: ("Quarantine_Item_Deleted", EventSeverity.LOW),
    1116: ("Malware_Detected", EventSeverity.HIGH),
    1117: ("Malware_Action_Taken", EventSeverity.HIGH),
    1118: ("Malware_Action_Failed", EventSeverity.CRITICAL),
    1119: ("Malware_Action_Critical_Failed", EventSeverity.CRITICAL),

    # Behavior monitoring
    1015: ("Behavior_Detected", EventSeverity.HIGH),
    1116: ("Threat_Detected", EventSeverity.HIGH),

    # Scan events
    1000: ("Scan_Started", EventSeverity.INFO),
    1001: ("Scan_Completed", EventSeverity.INFO),
    1002: ("Scan_Cancelled", EventSeverity.LOW),
    1003: ("Scan_Paused", EventSeverity.INFO),
    1004: ("Scan_Resumed", EventSeverity.INFO),
    1005: ("Scan_Failed", EventSeverity.MEDIUM),

    # Real-time protection
    5000: ("RTP_Enabled", EventSeverity.INFO),
    5001: ("RTP_Disabled", EventSeverity.HIGH),
    5004: ("RTP_Config_Changed", EventSeverity.MEDIUM),
    5007: ("Platform_Update", EventSeverity.INFO),
    5008: ("Engine_Update_Failed", EventSeverity.MEDIUM),
    5010: ("Scan_Disabled", EventSeverity.HIGH),
    5012: ("Virus_Scan_Disabled", EventSeverity.HIGH),

    # Exclusions
    5007: ("Exclusion_Changed", EventSeverity.MEDIUM),

    # Tamper protection
    5013: ("Tamper_Protection", EventSeverity.HIGH),
}


class DefenderParser(BaseParser):
    """Parser for Windows Defender logs."""

    name = "defender"
    description = "Windows Defender/Microsoft Defender logs"
    supported_extensions = [".log", ".evtx", ".json"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Defender log file."""
        name_lower = file_path.name.lower()

        # Check filename
        if any(x in name_lower for x in ["defender", "mplog", "malware"]):
            return True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
                # Check for Defender-specific content
                if any(x in content for x in [
                    "Windows Defender",
                    "Microsoft Defender",
                    "MpCmdRun",
                    "ThreatID",
                    "MALWAREPROTECTION",
                ]):
                    return True
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Windows Defender log file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Try JSON format first
            if content.strip().startswith("{") or content.strip().startswith("["):
                self._parse_json(content, result, file_path.name)
            else:
                self._parse_text(content, result, file_path.name)

        except Exception as e:
            result.add_error(f"Failed to parse Defender log: {str(e)}")

        return result

    def _parse_json(self, content: str, result: ParseResult, source_file: str) -> None:
        """Parse JSON format Defender logs."""
        line_num = 0

        # Handle NDJSON or array
        if content.strip().startswith("["):
            try:
                records = json.loads(content)
            except json.JSONDecodeError:
                return
        else:
            records = []
            for line in content.split("\n"):
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for record in records:
            line_num += 1
            try:
                event = self._parse_record(record, line_num, source_file)
                if event:
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Record {line_num}: {str(e)}")

    def _parse_text(self, content: str, result: ParseResult, source_file: str) -> None:
        """Parse text format Defender logs (MPLog)."""
        lines = content.split("\n")
        line_num = 0

        for line in lines:
            line_num += 1
            line = line.strip()
            if not line:
                continue

            try:
                event = self._parse_mplog_line(line, line_num, source_file)
                if event:
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Line {line_num}: {str(e)}")

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a JSON Defender record."""
        # Extract event ID
        event_id = record.get("EventId") or record.get("event_id") or record.get("Id")
        if event_id:
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                event_id = None

        # Get event info
        event_info = DEFENDER_EVENTS.get(event_id, ("Defender_Event", EventSeverity.INFO))

        # Parse timestamp
        timestamp = self._extract_timestamp(record)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"Defender_{event_info[0]}",
            event_id=event_id,
            severity=event_info[1],
            parser_name=self.name,
        )

        # Extract threat info
        event.process_name = (
            record.get("ThreatName")
            or record.get("Threat Name")
            or record.get("threat_name")
        )

        event.file_path = (
            record.get("Path")
            or record.get("ResourcePath")
            or record.get("FWLink")
        )

        event.file_hash = record.get("SHA256") or record.get("sha256")

        # Store raw
        event.raw_payload = json.dumps(record)

        return event

    def _parse_mplog_line(
        self, line: str, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse MPLog text format line."""
        # MPLog format: timestamp process message
        # Example: 2023-10-15T10:30:45.123Z MpCmdRun.exe Starting scan...

        # Try to extract timestamp
        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(.*)$",
            line
        )

        if timestamp_match:
            ts_str = timestamp_match.group(1)
            message = timestamp_match.group(2)
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                timestamp = timestamp.astimezone(timezone.utc)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)
            message = line

        # Determine severity based on content
        severity = EventSeverity.INFO
        if any(x in message.lower() for x in ["threat", "malware", "trojan", "virus"]):
            severity = EventSeverity.HIGH
        elif any(x in message.lower() for x in ["warning", "failed", "error"]):
            severity = EventSeverity.MEDIUM
        elif "disabled" in message.lower():
            severity = EventSeverity.HIGH

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Defender_Log",
            severity=severity,
            parser_name=self.name,
            raw_payload=line,
        )

        return event

    def _extract_timestamp(self, record: dict) -> datetime:
        """Extract timestamp from record."""
        for key in ["TimeCreated", "timestamp", "time", "EventTime", "CreatedTime"]:
            if key in record:
                val = record[key]
                if isinstance(val, str):
                    try:
                        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                        return dt.astimezone(timezone.utc)
                    except ValueError:
                        continue
                elif isinstance(val, (int, float)):
                    try:
                        return datetime.fromtimestamp(val, tz=timezone.utc)
                    except (ValueError, OSError):
                        continue

        return datetime.now(timezone.utc)
