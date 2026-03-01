"""Excel event log parser for ARGUS.

Handles Excel-exported Windows event logs with special attention to:
1. The Payload column which may contain JSON (often truncated by Excel)
2. PayloadData1-6 columns from tools like EvtxECmd/EvtxExplorer
3. ExecutableInfo column which contains command lines

These alternative column formats are critical for proper field extraction
when JSON in the Payload column is truncated.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity

logger = logging.getLogger(__name__)


# Windows Event ID to severity mapping
EVENT_SEVERITY = {
    # Authentication failures
    4625: EventSeverity.MEDIUM,  # Failed logon
    4771: EventSeverity.MEDIUM,  # Kerberos pre-auth failed

    # Privilege events
    4672: EventSeverity.LOW,     # Special privileges assigned
    4673: EventSeverity.MEDIUM,  # Sensitive privilege use
    4674: EventSeverity.MEDIUM,  # Operation on privileged object

    # Account management
    4720: EventSeverity.MEDIUM,  # User account created
    4722: EventSeverity.LOW,     # User account enabled
    4724: EventSeverity.MEDIUM,  # Password reset attempt
    4725: EventSeverity.LOW,     # User account disabled
    4726: EventSeverity.MEDIUM,  # User account deleted
    4732: EventSeverity.MEDIUM,  # Member added to security group
    4733: EventSeverity.MEDIUM,  # Member removed from security group
    4728: EventSeverity.HIGH,    # Member added to global group
    4756: EventSeverity.HIGH,    # Member added to universal group

    # Logon events
    4624: EventSeverity.INFO,    # Successful logon
    4634: EventSeverity.INFO,    # Logoff
    4647: EventSeverity.INFO,    # User initiated logoff
    4648: EventSeverity.LOW,     # Explicit credentials logon

    # Service events
    7045: EventSeverity.MEDIUM,  # Service installed
    7034: EventSeverity.LOW,     # Service crashed
    7036: EventSeverity.INFO,    # Service state change
    4697: EventSeverity.MEDIUM,  # Service installed (security log)

    # Process events
    4688: EventSeverity.INFO,    # Process created
    4689: EventSeverity.INFO,    # Process terminated

    # Scheduled tasks
    4698: EventSeverity.MEDIUM,  # Scheduled task created
    4699: EventSeverity.LOW,     # Scheduled task deleted
    4700: EventSeverity.INFO,    # Scheduled task enabled
    4701: EventSeverity.INFO,    # Scheduled task disabled
    4702: EventSeverity.LOW,     # Scheduled task updated

    # Kerberos
    4768: EventSeverity.INFO,    # Kerberos TGT requested
    4769: EventSeverity.INFO,    # Kerberos service ticket requested
    4770: EventSeverity.INFO,    # Kerberos service ticket renewed

    # Sysmon events
    1: EventSeverity.INFO,       # Process create
    2: EventSeverity.INFO,       # File creation time changed
    3: EventSeverity.INFO,       # Network connection
    5: EventSeverity.INFO,       # Process terminated
    6: EventSeverity.INFO,       # Driver loaded
    7: EventSeverity.INFO,       # Image loaded
    8: EventSeverity.MEDIUM,     # CreateRemoteThread
    9: EventSeverity.INFO,       # RawAccessRead
    10: EventSeverity.MEDIUM,    # ProcessAccess
    11: EventSeverity.INFO,      # FileCreate
    12: EventSeverity.INFO,      # RegistryEvent (Object create/delete)
    13: EventSeverity.INFO,      # RegistryEvent (Value Set)
    14: EventSeverity.INFO,      # RegistryEvent (Key/Value Rename)
    15: EventSeverity.INFO,      # FileCreateStreamHash
    17: EventSeverity.INFO,      # PipeEvent (Pipe Created)
    18: EventSeverity.INFO,      # PipeEvent (Pipe Connected)
    19: EventSeverity.INFO,      # WmiEvent (WmiEventFilter)
    20: EventSeverity.INFO,      # WmiEvent (WmiEventConsumer)
    21: EventSeverity.INFO,      # WmiEvent (WmiEventConsumerToFilter)
    22: EventSeverity.INFO,      # DNSEvent
    23: EventSeverity.INFO,      # FileDelete
    24: EventSeverity.INFO,      # ClipboardChange
    25: EventSeverity.MEDIUM,    # ProcessTampering
    26: EventSeverity.INFO,      # FileDeleteDetected
}


class ExcelParser(BaseParser):
    """Parser for Excel-exported Windows event logs."""

    name = "excel"
    description = "Excel-exported Windows event logs"
    supported_extensions = [".xlsx", ".xls"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Excel file."""
        return file_path.suffix.lower() in cls.supported_extensions

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Excel event log file."""
        result = self._create_result(file_path)
        logger.info(f"Parsing Excel file: {file_path}")

        try:
            # Read Excel file
            df = pd.read_excel(file_path, engine="openpyxl")
            result.metadata["row_count"] = len(df)
            result.metadata["columns"] = list(df.columns)
            logger.info(f"Loaded {len(df)} rows with columns: {list(df.columns)}")

            # Detect if this is a Windows event log export
            if not self._is_event_log(df):
                result.add_warning("File does not appear to be a Windows event log export")
                logger.warning("File does not appear to be a Windows event log export")

            # Check for PayloadData columns (EvtxECmd/EvtxExplorer format)
            payload_data_cols = [c for c in df.columns if c.startswith("PayloadData")]
            has_executable_info = "ExecutableInfo" in df.columns
            if payload_data_cols or has_executable_info:
                logger.info(f"Detected EvtxECmd format with PayloadData columns: {payload_data_cols}")
                if has_executable_info:
                    logger.info("ExecutableInfo column present - will extract command lines")
                result.metadata["format"] = "evtxecmd"
                result.metadata["payload_data_columns"] = payload_data_cols
            else:
                result.metadata["format"] = "standard"

            # Flag that this is Excel export (may have truncated fields)
            result.add_warning(
                "Analysis based on Excel-exported logs. "
                "Some fields may be truncated or missing."
            )

            # Try to detect the system name from filename or content
            system_name = self._detect_system_name(file_path, df)
            result.metadata["system_name"] = system_name
            logger.info(f"Detected system name: {system_name}")

            # Track extraction statistics
            stats = {
                "total_rows": len(df),
                "events_parsed": 0,
                "command_lines_extracted": 0,
                "process_names_extracted": 0,
                "network_events": 0,
                "file_events": 0,
                "registry_events": 0,
            }

            # Process each row
            for idx, row in df.iterrows():
                try:
                    event = self._parse_row(row, idx + 2, file_path.name, system_name)
                    if event:
                        result.add_event(event)
                        stats["events_parsed"] += 1
                        if event.command_line:
                            stats["command_lines_extracted"] += 1
                        if event.process_name:
                            stats["process_names_extracted"] += 1
                        if event.dest_ip or event.source_ip:
                            stats["network_events"] += 1
                        if event.file_path:
                            stats["file_events"] += 1
                        if event.registry_key:
                            stats["registry_events"] += 1
                except Exception as e:
                    result.add_warning(f"Row {idx + 2}: {str(e)}")
                    logger.debug(f"Error parsing row {idx + 2}: {e}")

            # Log extraction statistics
            logger.info(f"Extraction stats for {file_path.name}: {stats}")
            result.metadata["extraction_stats"] = stats

        except Exception as e:
            result.add_error(f"Failed to parse Excel file: {str(e)}")
            logger.error(f"Failed to parse Excel file {file_path}: {e}")

        return result

    def _is_event_log(self, df: pd.DataFrame) -> bool:
        """Check if DataFrame appears to be a Windows event log export."""
        # Look for common Windows event log columns
        common_cols = {"EventId", "Event ID", "TimeCreated", "Payload", "Message"}
        return len(common_cols.intersection(set(df.columns))) >= 2

    def _detect_system_name(self, file_path: Path, df: pd.DataFrame) -> str:
        """Try to detect the system name from filename or log content."""
        # Try filename first (e.g., "DCSRV.xlsx")
        name = file_path.stem.upper()
        if name and not name.startswith("EVENT"):
            return name

        # Try to find in DataFrame columns
        for col in ["Computer", "ComputerName", "MachineName"]:
            if col in df.columns:
                values = df[col].dropna().unique()
                if len(values) > 0:
                    return str(values[0])

        return "UNKNOWN"

    def _parse_row(
        self, row: pd.Series, line_num: int, source_file: str, system_name: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single row into a UnifiedEvent."""
        # Get timestamp
        timestamp = self._extract_timestamp(row)
        if not timestamp:
            return None

        # Get event ID
        event_id = self._extract_event_id(row)

        # Get event type - include event_id for better agent filtering
        event_type = self._determine_event_type(row, event_id)

        # Create base event
        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=event_type,
            event_id=event_id,
            source_system=system_name,
            severity=EVENT_SEVERITY.get(event_id, EventSeverity.INFO),
            parser_name=self.name,
        )

        # Parse Payload column if present (may be truncated in Excel)
        payload = self._extract_payload(row)
        if payload:
            self._apply_payload_fields(event, payload)
            event.raw_payload = json.dumps(payload) if isinstance(payload, dict) else str(payload)

        # CRITICAL: Extract from PayloadData1-6 columns (EvtxECmd format)
        # These columns contain the REAL data when Payload JSON is truncated
        payload_data = self._extract_payload_data_columns(row, event_id)
        if payload_data:
            self._apply_payload_fields(event, payload_data)
            # Merge into raw_payload for reference
            if event.raw_payload:
                try:
                    existing = json.loads(event.raw_payload)
                    existing.update(payload_data)
                    event.raw_payload = json.dumps(existing)
                except (json.JSONDecodeError, TypeError):
                    event.raw_payload = json.dumps(payload_data)
            else:
                event.raw_payload = json.dumps(payload_data)

        # Extract common fields from direct columns (UserName, ExecutableInfo, etc.)
        self._apply_direct_fields(event, row, event_id)

        return event

    def _extract_timestamp(self, row: pd.Series) -> Optional[datetime]:
        """Extract and normalize timestamp from row."""
        for col in ["TimeCreated", "Time Created", "Timestamp", "EventTime", "Date"]:
            if col in row.index and pd.notna(row[col]):
                try:
                    ts = pd.to_datetime(row[col])
                    # Ensure UTC
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    else:
                        ts = ts.astimezone(timezone.utc)
                    return ts.to_pydatetime()
                except Exception:
                    continue
        return None

    def _extract_event_id(self, row: pd.Series) -> Optional[int]:
        """Extract event ID from row."""
        for col in ["EventId", "Event ID", "EventID", "Id"]:
            if col in row.index and pd.notna(row[col]):
                try:
                    return int(row[col])
                except (ValueError, TypeError):
                    continue
        return None

    def _determine_event_type(self, row: pd.Series, event_id: Optional[int]) -> str:
        """Determine event type from row data.

        Returns a string that helps agents filter for relevant events.
        For Sysmon events, includes the event ID (e.g., "Sysmon_1" for process create).
        """
        channel = None
        provider = None

        # Check for channel/provider info
        for col in ["Channel", "LogName"]:
            if col in row.index and pd.notna(row[col]):
                channel = str(row[col])
                break

        for col in ["Provider"]:
            if col in row.index and pd.notna(row[col]):
                provider = str(row[col])
                break

        # Determine if this is Sysmon based on channel or provider
        is_sysmon = False
        if channel and "sysmon" in channel.lower():
            is_sysmon = True
        if provider and "sysmon" in provider.lower():
            is_sysmon = True

        # For Sysmon events, return "Sysmon_<EventID>" for better agent filtering
        if is_sysmon and event_id:
            # Map common Sysmon event IDs to descriptive names
            sysmon_names = {
                1: "ProcessCreate",
                2: "FileCreateTime",
                3: "NetworkConnect",
                5: "ProcessTerminate",
                6: "DriverLoad",
                7: "ImageLoad",
                8: "CreateRemoteThread",
                9: "RawAccessRead",
                10: "ProcessAccess",
                11: "FileCreate",
                12: "RegistryCreate",
                13: "RegistrySetValue",
                14: "RegistryRename",
                15: "FileCreateStreamHash",
                17: "PipeCreate",
                18: "PipeConnect",
                22: "DNSQuery",
                23: "FileDelete",
            }
            name = sysmon_names.get(event_id, str(event_id))
            return f"Sysmon_{event_id}_{name}"

        # For Windows Security events, include event ID for filtering
        if event_id:
            if event_id in [4624, 4625, 4634, 4647, 4648]:
                return f"Security_{event_id}_Authentication"
            elif event_id in [4688, 4689]:
                return f"Security_{event_id}_Process"
            elif event_id in [7045, 7034, 7036, 4697]:
                return f"System_{event_id}_Service"
            elif event_id in [4698, 4699, 4700, 4701, 4702]:
                return f"Security_{event_id}_ScheduledTask"

        # Return channel if available, otherwise generic
        if channel:
            return channel

        return "WindowsEvent"

    def _extract_payload(self, row: pd.Series) -> Optional[dict]:
        """Extract and parse the Payload column.

        Handles three JSON formats:
        1. Flat key-value: {"key1": "value1", "key2": "value2"}
        2. Nested objects: {"EventData": {"key1": "value1"}}
        3. Mixed formats: Combination of above
        """
        for col in ["Payload", "Message", "EventData", "Data"]:
            if col not in row.index or pd.isna(row[col]):
                continue

            payload_str = str(row[col])

            # Try direct JSON parse
            try:
                data = json.loads(payload_str)
                return self._normalize_payload(data)
            except json.JSONDecodeError:
                pass

            # Try extracting JSON from string (may have prefix/suffix)
            json_match = re.search(r'\{.*\}', payload_str, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                    return self._normalize_payload(data)
                except json.JSONDecodeError:
                    pass

            # Try XML-like EventData format
            if "<EventData>" in payload_str or "<Data " in payload_str:
                return self._parse_xml_payload(payload_str)

            # Return as raw text in dict
            return {"_raw": payload_str}

        return None

    def _normalize_payload(self, data: dict) -> dict:
        """Normalize payload data to flat dictionary.

        Handles multiple JSON formats including:
        1. Flat key-value: {"key1": "value1"}
        2. Nested EventData dict: {"EventData": {"key1": "value1"}}
        3. Nested EventData with Data array: {"EventData": {"Data": [{"@Name": "key", "#text": "val"}]}}
        """
        result = {}

        # Handle nested EventData
        if "EventData" in data and isinstance(data["EventData"], dict):
            event_data = data["EventData"]

            # Check for Data array format (Sysmon JSON)
            # Format: {"EventData": {"Data": [{"@Name": "key", "#text": "value"}, ...]}}
            if "Data" in event_data and isinstance(event_data["Data"], list):
                for item in event_data["Data"]:
                    if isinstance(item, dict) and "@Name" in item:
                        name = item["@Name"]
                        # Value can be in #text or as direct value
                        value = item.get("#text", item.get("text", ""))
                        if value:
                            result[name] = value
                logger.debug(f"Parsed EventData array format: {len(result)} fields")
            else:
                # Direct dict format
                result.update(event_data)

        # Handle nested UserData
        if "UserData" in data and isinstance(data["UserData"], dict):
            result.update(data["UserData"])

        # Handle flat data
        for key, value in data.items():
            if key not in ["EventData", "UserData"]:
                if isinstance(value, dict):
                    # Flatten nested dict
                    for k, v in value.items():
                        result[f"{key}_{k}"] = v
                else:
                    result[key] = value

        return result

    def _parse_xml_payload(self, payload_str: str) -> dict:
        """Parse XML-style EventData payload."""
        result = {}

        # Extract Data elements: <Data Name="Key">Value</Data>
        pattern = r'<Data\s+Name="([^"]+)"[^>]*>([^<]*)</Data>'
        matches = re.findall(pattern, payload_str)
        for name, value in matches:
            result[name] = value

        return result

    def _extract_payload_data_columns(
        self, row: pd.Series, event_id: Optional[int]
    ) -> dict:
        """Extract fields from PayloadData1-6 columns (EvtxECmd/EvtxExplorer format).

        These columns contain pre-parsed Sysmon/Windows event data in formats like:
        - "Key: Value"
        - "Key=Value"
        - "Key1: Val1, Key2: Val2"

        This is CRITICAL because the Payload column JSON is often truncated by Excel.
        """
        result = {}

        # Process PayloadData1-6 columns
        for col_num in range(1, 7):
            col_name = f"PayloadData{col_num}"
            if col_name not in row.index or pd.isna(row[col_name]):
                continue

            col_value = str(row[col_name])
            if not col_value or col_value == "nan":
                continue

            # Parse key-value pairs from this column
            parsed = self._parse_payload_data_value(col_value)
            result.update(parsed)

            logger.debug(f"PayloadData{col_num}: extracted {len(parsed)} fields from '{col_value[:100]}'")

        # Log what we extracted
        if result:
            logger.debug(f"Event ID {event_id}: extracted {len(result)} fields from PayloadData columns")

        return result

    def _parse_payload_data_value(self, value: str) -> dict:
        """Parse a PayloadData column value into key-value pairs.

        Handles formats like:
        - "ProcessID: 2136, ProcessGUID: abc-123"
        - "MD5=abc123,SHA256=def456,IMPHASH=ghi789"
        - "ParentProcess: C:\\Windows\\explorer.exe"
        - "SourceIp: 192.168.1.1"
        """
        result = {}

        if not value or value == "nan":
            return result

        # First try: "Key: Value" format (may have multiple comma-separated pairs)
        # Pattern: word characters followed by colon and value
        colon_pattern = r'([A-Za-z][A-Za-z0-9_]*)\s*:\s*([^,]+(?:,[^,]+)*?)(?=\s*,\s*[A-Za-z][A-Za-z0-9_]*\s*:|$)'
        colon_matches = re.findall(colon_pattern, value)
        if colon_matches:
            for key, val in colon_matches:
                result[key.strip()] = val.strip()
            return result

        # Second try: "Key=Value" format (hash strings like MD5=xxx,SHA256=yyy)
        if "=" in value:
            # Split on comma but be careful with paths
            parts = re.split(r',(?=[A-Z][A-Z0-9]*=)', value)
            for part in parts:
                if "=" in part:
                    key, _, val = part.partition("=")
                    if key and val:
                        result[key.strip()] = val.strip()
            if result:
                return result

        # Third try: simple "Key: Value" single pair
        if ": " in value:
            key, _, val = value.partition(": ")
            if key and val:
                result[key.strip()] = val.strip()
                return result

        # If no pattern matched, store the raw value with a generic key
        # This preserves data we couldn't parse
        if value.strip():
            result["_unparsed"] = value

        return result

    def _apply_payload_fields(self, event: UnifiedEvent, payload: dict) -> None:
        """Apply payload fields to the event."""
        # Identity fields
        for key in ["TargetUserName", "SubjectUserName", "UserName", "User"]:
            if key in payload and payload[key]:
                event.username = str(payload[key])
                break

        for key in ["TargetDomainName", "SubjectDomainName", "Domain"]:
            if key in payload and payload[key]:
                event.domain = str(payload[key])
                break

        if "LogonType" in payload:
            try:
                event.logon_type = int(payload["LogonType"])
            except (ValueError, TypeError):
                pass

        # Network fields - handle both Sysmon field names and PayloadData formats
        for key in ["IpAddress", "SourceAddress", "SourceIp", "ClientAddress"]:
            if key in payload and payload[key] and str(payload[key]) not in ["-", "nan", ""]:
                event.source_ip = str(payload[key])
                logger.debug(f"Set source_ip from {key}: {event.source_ip}")
                break

        for key in ["SourcePort", "IpPort", "ClientPort"]:
            if key in payload and payload[key]:
                try:
                    val = str(payload[key])
                    if val and val != "nan":
                        event.source_port = int(val)
                except (ValueError, TypeError):
                    pass
                break

        for key in ["DestinationIp", "DestAddress", "DestinationAddress"]:
            if key in payload and payload[key] and str(payload[key]) not in ["-", "nan", ""]:
                event.dest_ip = str(payload[key])
                logger.debug(f"Set dest_ip from {key}: {event.dest_ip}")
                break

        for key in ["DestinationPort", "DestPort"]:
            if key in payload and payload[key]:
                try:
                    val = str(payload[key])
                    if val and val != "nan":
                        event.dest_port = int(val)
                except (ValueError, TypeError):
                    pass
                break

        # Hostname fields for network context
        for key in ["SourceHostname"]:
            if key in payload and payload[key] and str(payload[key]) not in ["nan", ""]:
                # Store in source_system if not already set
                if not event.source_system:
                    event.source_system = str(payload[key])

        # Process fields
        for key in ["Image", "NewProcessName", "ProcessName", "Application"]:
            if key in payload and payload[key]:
                event.process_name = str(payload[key])
                break

        for key in ["ProcessId", "NewProcessId"]:
            if key in payload and payload[key]:
                try:
                    # Handle hex format (0x...)
                    val = str(payload[key])
                    if val.startswith("0x"):
                        event.process_id = int(val, 16)
                    else:
                        event.process_id = int(val)
                except (ValueError, TypeError):
                    pass
                break

        # Parent process fields - critical for process tree analysis
        for key in ["ParentImage", "ParentProcessName", "ParentProcess"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if val and val != "nan":
                    event.parent_process_name = val
                    logger.debug(f"Set parent_process_name from {key}: {val}")
                    break

        for key in ["ParentProcessId", "ParentProcessID"]:
            if key in payload and payload[key]:
                try:
                    val = str(payload[key])
                    if val.startswith("0x"):
                        event.parent_process_id = int(val, 16)
                    else:
                        # Handle "ParentProcessID: 2480" format
                        val = val.split(",")[0].strip()  # Take first value if comma-separated
                        event.parent_process_id = int(val)
                except (ValueError, TypeError):
                    pass
                break

        # Command line - primary process, not parent
        for key in ["CommandLine"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if val and val != "nan":
                    event.command_line = val
                    break

        # Parent command line - separate field for parent process
        for key in ["ParentCommandLine"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if val and val != "nan":
                    event.parent_command_line = val
                    logger.debug(f"Set parent_command_line: {val[:100]}")
                    break

        # File fields - handle both standard and PayloadData formats
        for key in ["TargetFilename", "FileName", "ObjectName"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if val and val != "nan":
                    event.file_path = val
                    logger.debug(f"Set file_path from {key}: {val[:100]}")
                    break

        # Hash fields - Sysmon provides multiple hash types
        for key in ["Hashes", "Hash", "FileHash", "MD5", "SHA256", "SHA1"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if val and val != "nan":
                    event.file_hash = val
                    break

        # Image field for FileCreate events (Sysmon 11) - process that created the file
        if not event.process_name:
            for key in ["Image"]:
                if key in payload and payload[key]:
                    val = str(payload[key])
                    if val and val != "nan":
                        event.process_name = val
                        break

        # Service fields
        for key in ["ServiceName"]:
            if key in payload and payload[key]:
                event.service_name = str(payload[key])
                break

        for key in ["ImagePath", "ServiceFileName"]:
            if key in payload and payload[key]:
                event.service_path = str(payload[key])
                break

        # Registry fields
        for key in ["TargetObject", "ObjectName"]:
            if key in payload and payload[key]:
                val = str(payload[key])
                if "\\REGISTRY\\" in val.upper() or val.startswith("HK"):
                    event.registry_key = val
                break

        for key in ["Details"]:
            if key in payload and payload[key]:
                event.registry_value = str(payload[key])
                break

    def _apply_direct_fields(
        self, event: UnifiedEvent, row: pd.Series, event_id: Optional[int] = None
    ) -> None:
        """Apply fields directly from row columns (not from Payload).

        This handles columns that exist directly in the Excel file, including:
        - Computer/ComputerName: System name
        - UserName: Account that performed the action
        - ExecutableInfo: CRITICAL - contains command line for process events
        - MapDescription: Human-readable event description
        """
        # Computer/System name
        for col in ["Computer", "ComputerName", "MachineName"]:
            if col in row.index and pd.notna(row[col]):
                event.source_system = str(row[col])
                break

        # Username if not already set
        if not event.username:
            for col in ["UserName", "User", "Account"]:
                if col in row.index and pd.notna(row[col]):
                    val = str(row[col])
                    if val and val != "nan":
                        event.username = val
                        logger.debug(f"Set username from {col}: {val}")
                        break

        # CRITICAL: ExecutableInfo contains command line for Sysmon Event ID 1
        # This is THE most important field for process analysis
        if "ExecutableInfo" in row.index and pd.notna(row["ExecutableInfo"]):
            exec_info = str(row["ExecutableInfo"])
            if exec_info and exec_info != "nan":
                # For Sysmon Event ID 1 (Process Create), this IS the command line
                if event_id == 1:
                    if not event.command_line:
                        event.command_line = exec_info
                        logger.debug(f"Set command_line from ExecutableInfo: {exec_info[:100]}")
                    # Also extract process name from the path
                    if not event.process_name:
                        # Extract executable name from command line
                        # Handle quoted paths: "C:\path\to\exe.exe" args
                        # and unquoted paths: C:\path\to\exe.exe args
                        match = re.match(r'^"([^"]+)"', exec_info)
                        if match:
                            event.process_name = match.group(1)
                        else:
                            # Take first space-delimited token
                            event.process_name = exec_info.split()[0] if exec_info else None
                        if event.process_name:
                            logger.debug(f"Extracted process_name: {event.process_name}")
                # For Sysmon Event ID 3 (Network), this is the process image
                elif event_id == 3:
                    if not event.process_name:
                        event.process_name = exec_info
                        logger.debug(f"Set process_name from ExecutableInfo (network): {exec_info}")

        # Process name if not already set - try direct columns
        if not event.process_name:
            for col in ["Process", "ProcessName", "Image"]:
                if col in row.index and pd.notna(row[col]):
                    val = str(row[col])
                    if val and val != "nan":
                        event.process_name = val
                        break

        # MapDescription provides human-readable event context
        if "MapDescription" in row.index and pd.notna(row["MapDescription"]):
            desc = str(row["MapDescription"])
            if desc and desc != "nan":
                event.description = desc
