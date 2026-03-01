"""CSV event log parser for ARGUS.

Parses CSV-formatted event logs with automatic header detection.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class CSVParser(BaseParser):
    """Parser for CSV-formatted event logs."""

    name = "csv"
    description = "CSV-formatted event logs"
    supported_extensions = [".csv"]

    # Common timestamp column names
    TIMESTAMP_COLUMNS = [
        "timestamp", "time", "datetime", "date", "timecreated", "time_created",
        "eventtime", "event_time", "@timestamp", "ts", "created", "logged"
    ]

    # Common event ID column names
    EVENT_ID_COLUMNS = [
        "eventid", "event_id", "id", "eventcode", "event_code", "code"
    ]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a parseable CSV file."""
        if file_path.suffix.lower() != ".csv":
            return False

        try:
            # Check if it's a valid CSV with headers
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                sample = f.read(4096)
                dialect = csv.Sniffer().sniff(sample)
                return csv.Sniffer().has_header(sample)
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a CSV event log file."""
        result = self._create_result(file_path)

        try:
            # Read CSV with pandas for better handling
            df = pd.read_csv(file_path, low_memory=False)
            result.metadata["row_count"] = len(df)
            result.metadata["columns"] = list(df.columns)

            # Normalize column names
            df.columns = df.columns.str.lower().str.strip()

            # Find timestamp column
            ts_col = self._find_column(df.columns, self.TIMESTAMP_COLUMNS)
            if not ts_col:
                result.add_warning("No timestamp column found")

            # Find event ID column
            id_col = self._find_column(df.columns, self.EVENT_ID_COLUMNS)

            # Process rows
            for idx, row in df.iterrows():
                try:
                    event = self._parse_row(
                        row, idx + 2, file_path.name, ts_col, id_col
                    )
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Row {idx + 2}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse CSV file: {str(e)}")

        return result

    def _find_column(self, columns: pd.Index, candidates: list) -> Optional[str]:
        """Find a column matching one of the candidate names."""
        for col in columns:
            if col in candidates:
                return col
        return None

    def _parse_row(
        self, row: pd.Series, line_num: int, source_file: str,
        ts_col: Optional[str], id_col: Optional[str]
    ) -> Optional[UnifiedEvent]:
        """Parse a single row into a UnifiedEvent."""
        # Get timestamp
        timestamp = None
        if ts_col and pd.notna(row.get(ts_col)):
            try:
                ts = pd.to_datetime(row[ts_col])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
                timestamp = ts.to_pydatetime()
            except Exception:
                pass

        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Get event ID
        event_id = None
        if id_col and pd.notna(row.get(id_col)):
            try:
                event_id = int(row[id_col])
            except (ValueError, TypeError):
                pass

        # Create event
        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="CSV",
            event_id=event_id,
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Try to map common fields
        self._apply_common_fields(event, row)

        # Store all columns as raw payload
        event.raw_payload = row.to_json()

        return event

    def _apply_common_fields(self, event: UnifiedEvent, row: pd.Series) -> None:
        """Try to map common field names to event attributes."""
        # Username
        for col in ["username", "user", "account", "subject", "targetusername"]:
            if col in row.index and pd.notna(row[col]):
                event.username = str(row[col])
                break

        # Source IP
        for col in ["sourceip", "source_ip", "src_ip", "srcip", "client_ip", "clientip", "ipaddress"]:
            if col in row.index and pd.notna(row[col]):
                event.source_ip = str(row[col])
                break

        # Destination IP
        for col in ["destip", "dest_ip", "dst_ip", "dstip", "destinationip", "destination_ip"]:
            if col in row.index and pd.notna(row[col]):
                event.dest_ip = str(row[col])
                break

        # Process name
        for col in ["process", "processname", "process_name", "image", "application"]:
            if col in row.index and pd.notna(row[col]):
                event.process_name = str(row[col])
                break

        # Command line
        for col in ["commandline", "command_line", "cmd", "command"]:
            if col in row.index and pd.notna(row[col]):
                event.command_line = str(row[col])
                break

        # System/Host
        for col in ["computer", "hostname", "host", "system", "machinename"]:
            if col in row.index and pd.notna(row[col]):
                event.source_system = str(row[col])
                break
