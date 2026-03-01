"""EVTX (Windows Event Log) parser for ARGUS.

Parses raw Windows Event Log files using python-evtx library.
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity
from argus.parsers.excel import EVENT_SEVERITY


# XML namespaces used in EVTX
NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}


class EvtxParser(BaseParser):
    """Parser for Windows EVTX files."""

    name = "evtx"
    description = "Windows Event Log (EVTX) files"
    supported_extensions = [".evtx"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an EVTX file."""
        if file_path.suffix.lower() != ".evtx":
            return False

        # Verify EVTX magic bytes
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
                return magic[:7] == b"ElfFile"
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an EVTX file."""
        result = self._create_result(file_path)

        # Try to detect system name from filename
        system_name = file_path.stem.upper()
        if system_name in ["SECURITY", "SYSTEM", "APPLICATION", "SYSMON"]:
            system_name = "UNKNOWN"
        result.metadata["system_name"] = system_name

        try:
            with Evtx(str(file_path)) as evtx:
                event_count = 0
                for record in evtx.records():
                    try:
                        xml_str = record.xml()
                        event = self._parse_event_xml(
                            xml_str, event_count + 1, file_path.name, system_name
                        )
                        if event:
                            result.add_event(event)
                            event_count += 1
                    except Exception as e:
                        result.add_warning(f"Record {event_count + 1}: {str(e)}")

                result.metadata["event_count"] = event_count

        except Exception as e:
            result.add_error(f"Failed to parse EVTX file: {str(e)}")

        return result

    def _parse_event_xml(
        self, xml_str: str, line_num: int, source_file: str, system_name: str
    ) -> Optional[UnifiedEvent]:
        """Parse an event from its XML representation."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        # Extract System element
        system = root.find("e:System", NS)
        if system is None:
            return None

        # Get timestamp
        time_created = system.find("e:TimeCreated", NS)
        if time_created is None:
            return None

        timestamp_str = time_created.get("SystemTime")
        timestamp = self._parse_timestamp(timestamp_str)
        if not timestamp:
            return None

        # Get event ID
        event_id_elem = system.find("e:EventID", NS)
        event_id = int(event_id_elem.text) if event_id_elem is not None else None

        # Get channel/provider
        channel = system.find("e:Channel", NS)
        channel_name = channel.text if channel is not None else "Unknown"

        provider = system.find("e:Provider", NS)
        provider_name = provider.get("Name") if provider is not None else None

        # Get computer name
        computer = system.find("e:Computer", NS)
        computer_name = computer.text if computer is not None else system_name

        # Determine event type
        event_type = provider_name or channel_name

        # Create event
        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=event_type,
            event_id=event_id,
            source_system=computer_name,
            severity=EVENT_SEVERITY.get(event_id, EventSeverity.INFO),
            parser_name=self.name,
            raw_payload=xml_str,
        )

        # Parse EventData
        event_data = root.find("e:EventData", NS)
        if event_data is not None:
            self._apply_event_data(event, event_data)

        # Parse UserData (some events use this instead)
        user_data = root.find("e:UserData", NS)
        if user_data is not None:
            self._apply_user_data(event, user_data)

        return event

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse EVTX timestamp string to datetime."""
        if not timestamp_str:
            return None

        # Handle various EVTX timestamp formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.rstrip("Z"), fmt.rstrip("Z"))
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None

    def _apply_event_data(self, event: UnifiedEvent, event_data: ET.Element) -> None:
        """Extract fields from EventData element."""
        data = {}

        for elem in event_data:
            name = elem.get("Name")
            value = elem.text

            if name and value:
                data[name] = value
            elif value:
                # Unnamed data element
                tag = elem.tag.split("}")[-1]  # Remove namespace
                data[tag] = value

        self._apply_data_fields(event, data)

    def _apply_user_data(self, event: UnifiedEvent, user_data: ET.Element) -> None:
        """Extract fields from UserData element."""
        data = {}

        def extract_recursive(elem, prefix=""):
            for child in elem:
                tag = child.tag.split("}")[-1]  # Remove namespace
                key = f"{prefix}{tag}" if prefix else tag

                if len(child) > 0:
                    # Has children, recurse
                    extract_recursive(child, f"{key}_")
                elif child.text:
                    data[key] = child.text

        extract_recursive(user_data)
        self._apply_data_fields(event, data)

    def _apply_data_fields(self, event: UnifiedEvent, data: dict) -> None:
        """Apply extracted data fields to event."""
        # Identity fields
        for key in ["TargetUserName", "SubjectUserName", "UserName", "User", "AccountName"]:
            if key in data and data[key] and data[key] != "-":
                event.username = data[key]
                break

        for key in ["TargetDomainName", "SubjectDomainName", "Domain"]:
            if key in data and data[key] and data[key] != "-":
                event.domain = data[key]
                break

        if "LogonType" in data:
            try:
                event.logon_type = int(data["LogonType"])
            except (ValueError, TypeError):
                pass

        # Network fields
        for key in ["IpAddress", "SourceAddress", "SourceIp", "ClientAddress"]:
            if key in data and data[key] and data[key] not in ("-", "::1", "127.0.0.1"):
                event.source_ip = data[key]
                break

        for key in ["SourcePort", "IpPort", "ClientPort"]:
            if key in data and data[key]:
                try:
                    event.source_port = int(data[key])
                except (ValueError, TypeError):
                    pass
                break

        for key in ["DestinationIp", "DestAddress", "DestinationAddress"]:
            if key in data and data[key]:
                event.dest_ip = data[key]
                break

        for key in ["DestinationPort", "DestPort"]:
            if key in data and data[key]:
                try:
                    event.dest_port = int(data[key])
                except (ValueError, TypeError):
                    pass
                break

        # Process fields
        for key in ["Image", "NewProcessName", "ProcessName", "Application"]:
            if key in data and data[key]:
                event.process_name = data[key]
                break

        for key in ["ProcessId", "NewProcessId"]:
            if key in data and data[key]:
                try:
                    val = data[key]
                    if isinstance(val, str) and val.startswith("0x"):
                        event.process_id = int(val, 16)
                    else:
                        event.process_id = int(val)
                except (ValueError, TypeError):
                    pass
                break

        for key in ["ParentImage", "ParentProcessName"]:
            if key in data and data[key]:
                event.parent_process_name = data[key]
                break

        for key in ["ParentProcessId"]:
            if key in data and data[key]:
                try:
                    val = data[key]
                    if isinstance(val, str) and val.startswith("0x"):
                        event.parent_process_id = int(val, 16)
                    else:
                        event.parent_process_id = int(val)
                except (ValueError, TypeError):
                    pass
                break

        for key in ["CommandLine", "ParentCommandLine"]:
            if key in data and data[key]:
                event.command_line = data[key]
                break

        # File fields
        for key in ["TargetFilename", "FileName", "ObjectName"]:
            if key in data and data[key]:
                event.file_path = data[key]
                break

        for key in ["Hashes", "Hash", "FileHash"]:
            if key in data and data[key]:
                event.file_hash = data[key]
                break

        # Service fields
        if "ServiceName" in data:
            event.service_name = data["ServiceName"]

        for key in ["ImagePath", "ServiceFileName"]:
            if key in data and data[key]:
                event.service_path = data[key]
                break

        # Registry fields
        for key in ["TargetObject", "ObjectName"]:
            if key in data and data[key]:
                val = data[key]
                if "\\REGISTRY\\" in val.upper() or val.startswith("HK"):
                    event.registry_key = val
                break

        if "Details" in data:
            event.registry_value = data["Details"]

        # DNS fields (Sysmon EventID 22)
        if "QueryName" in data:
            event.uri = data["QueryName"]
