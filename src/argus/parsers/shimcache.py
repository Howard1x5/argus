"""Shimcache/Amcache parser for ARGUS.

Parses Windows Application Compatibility Cache artifacts.
Expects output from tools like ShimCacheParser, AppCompatCacheParser, or AmcacheParser.
"""

import csv
import json
import re
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Suspicious executable patterns
SUSPICIOUS_PATTERNS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\users\\public\\",
    r"\\programdata\\",
    r"\\appdata\\local\\temp\\",
    r"\\downloads\\",
    r"\\recycle",
    r"mimikatz",
    r"procdump",
    r"psexec",
    r"cobalt",
    r"beacon",
    r"meterpreter",
]


class ShimcacheParser(BaseParser):
    """Parser for Shimcache/Amcache exports."""

    name = "shimcache"
    description = "Windows Shimcache/Amcache execution artifacts"
    supported_extensions = [".csv", ".json", ".txt"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Shimcache/Amcache export."""
        name_lower = file_path.name.lower()

        # Check filename
        if any(x in name_lower for x in ["shimcache", "amcache", "appcompat"]):
            return True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)

                # Check for common Shimcache tool output patterns
                # Require at least 2 indicators to avoid false positives
                indicators = [
                    "Last Modified",
                    "LastModified",
                    "Executed",
                    "AppCompatCache",
                    "AmcacheInventoryApplication",
                    "InventoryApplicationFile",
                    "ShimCache",
                ]

                matches = sum(1 for ind in indicators if ind in content)
                return matches >= 2
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Shimcache/Amcache export file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Detect format
            if content.strip().startswith("{") or content.strip().startswith("["):
                self._parse_json(content, result, file_path.name)
            elif "," in content.split("\n")[0]:
                self._parse_csv(content, result, file_path.name)
            else:
                self._parse_text(content, result, file_path.name)

        except Exception as e:
            result.add_error(f"Failed to parse Shimcache/Amcache: {str(e)}")

        return result

    def _parse_csv(self, content: str, result: ParseResult, source_file: str) -> None:
        """Parse CSV format Shimcache export."""
        reader = csv.DictReader(StringIO(content))

        for idx, row in enumerate(reader):
            try:
                event = self._parse_row(row, idx + 2, source_file)
                if event:
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Row {idx + 2}: {str(e)}")

    def _parse_json(self, content: str, result: ParseResult, source_file: str) -> None:
        """Parse JSON format Shimcache export."""
        try:
            if content.strip().startswith("["):
                records = json.loads(content)
            else:
                records = []
                for line in content.split("\n"):
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except json.JSONDecodeError:
            return

        for idx, record in enumerate(records):
            try:
                event = self._parse_row(record, idx + 1, source_file)
                if event:
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Record {idx + 1}: {str(e)}")

    def _parse_text(self, content: str, result: ParseResult, source_file: str) -> None:
        """Parse text format Shimcache export."""
        lines = content.split("\n")

        for idx, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                # Try to extract path and timestamp from line
                event = self._parse_text_line(line, idx + 1, source_file)
                if event:
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Line {idx + 1}: {str(e)}")

    def _parse_row(
        self, row: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single row/record into an event."""
        # Find path field
        path = None
        for key in ["Path", "path", "FilePath", "FullPath", "Name", "ApplicationName"]:
            if key in row and row[key]:
                path = row[key]
                break

        if not path:
            return None

        # Find timestamp
        timestamp = None
        for key in ["LastModified", "Last Modified", "ModifiedTime", "LastWriteTime",
                    "InstallDate", "LinkDate", "CompileTime"]:
            if key in row and row[key]:
                timestamp = self._parse_timestamp(row[key])
                if timestamp:
                    break

        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Determine severity
        severity = self._assess_severity(path)

        # Check executed flag
        executed = row.get("Executed", row.get("executed", ""))
        if executed and str(executed).lower() in ["true", "yes", "1"]:
            if severity == EventSeverity.INFO:
                severity = EventSeverity.LOW

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Shimcache",
            severity=severity,
            parser_name=self.name,
            file_path=path,
            process_name=path.split("\\")[-1] if "\\" in path else path,
        )

        # Get hash if available
        for key in ["SHA256", "SHA1", "MD5", "Hash", "FileHash"]:
            if key in row and row[key]:
                event.file_hash = row[key]
                break

        event.raw_payload = json.dumps(row) if isinstance(row, dict) else str(row)
        return event

    def _parse_text_line(
        self, line: str, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a text format line."""
        # Try to extract Windows path
        path_match = re.search(r"([A-Za-z]:\\[^\s,|]+)", line)
        if not path_match:
            return None

        path = path_match.group(1)

        # Try to extract timestamp
        timestamp = datetime.now(timezone.utc)
        ts_match = re.search(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", line)
        if ts_match:
            timestamp = self._parse_timestamp(ts_match.group(1)) or timestamp

        severity = self._assess_severity(path)

        return UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Shimcache",
            severity=severity,
            parser_name=self.name,
            file_path=path,
            process_name=path.split("\\")[-1],
            raw_payload=line,
        )

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None

    def _assess_severity(self, path: str) -> EventSeverity:
        """Assess severity based on file path."""
        path_lower = path.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, path_lower, re.IGNORECASE):
                return EventSeverity.HIGH

        return EventSeverity.INFO
