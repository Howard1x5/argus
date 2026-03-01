"""Office 365 / Microsoft 365 Unified Audit Log parser for ARGUS.

Parses O365/M365 audit logs exported from compliance center.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-risk O365 operations
HIGH_RISK_OPERATIONS = {
    # Account compromise indicators
    "UserLoggedIn",
    "UserLoginFailed",
    "ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken",

    # Mailbox access
    "MailboxLogin",
    "MailItemsAccessed",
    "SendAs",
    "SendOnBehalf",

    # Data exfiltration
    "FileDownloaded",
    "FileSyncDownloadedFull",
    "FileAccessed",

    # Admin actions
    "Add-MailboxPermission",
    "Set-Mailbox",
    "New-InboxRule",
    "Set-InboxRule",
    "New-TransportRule",
    "Add member to role",
    "Add application",
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment grant to user",
    "Add service principal credentials",
    "Update application",

    # Security changes
    "Disable account",
    "Reset user password",
    "Set domain authentication",
    "Set federation settings on domain",
}


class O365Parser(BaseParser):
    """Parser for Office 365 Unified Audit Logs."""

    name = "o365"
    description = "Office 365 / Microsoft 365 Unified Audit Logs"
    supported_extensions = [".json", ".csv"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an O365 audit log."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)

                # Check for O365 indicators
                indicators = [
                    "Workload",
                    "RecordType",
                    "UserType",
                    "AzureActiveDirectory",
                    "Exchange",
                    "SharePoint",
                    "Operation",
                ]

                if any(ind in content for ind in indicators):
                    # Verify it's JSON
                    try:
                        # Try parsing first line/record
                        if content.strip().startswith("["):
                            data = json.loads(content)
                            return True
                        else:
                            first_line = content.split("\n")[0].strip()
                            if first_line.startswith("{"):
                                json.loads(first_line)
                                return True
                    except json.JSONDecodeError:
                        pass

                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an O365 audit log file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            records = []

            # Try as JSON array
            if content.strip().startswith("["):
                try:
                    records = json.loads(content)
                except json.JSONDecodeError:
                    pass
            else:
                # Try as NDJSON
                for line in content.split("\n"):
                    line = line.strip()
                    if line and line.startswith("{"):
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            result.metadata["record_count"] = len(records)

            for idx, record in enumerate(records):
                try:
                    event = self._parse_record(record, idx + 1, file_path.name)
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Record {idx + 1}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse O365 log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single O365 audit record."""
        # Get timestamp
        timestamp = self._parse_timestamp(record.get("CreationTime"))
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Get operation
        operation = record.get("Operation", "Unknown")
        workload = record.get("Workload", "O365")

        # Determine severity
        severity = EventSeverity.INFO
        if operation in HIGH_RISK_OPERATIONS:
            severity = EventSeverity.HIGH
        elif "Failed" in operation or "Error" in operation:
            severity = EventSeverity.MEDIUM

        # Check result status
        result_status = record.get("ResultStatus", "")
        if result_status.lower() in ["failed", "partialfailure"]:
            severity = EventSeverity.MEDIUM

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"O365_{workload}",
            severity=severity,
            parser_name=self.name,
        )

        # User information
        event.username = record.get("UserId") or record.get("UserKey")

        # Client IP
        event.source_ip = record.get("ClientIP") or record.get("ActorIpAddress")

        # User agent
        event.user_agent = record.get("UserAgent")

        # Store operation in process_name for searchability
        event.process_name = operation

        # File/object information
        event.file_path = (
            record.get("SourceFileName")
            or record.get("ObjectId")
            or record.get("TargetUserOrGroupName")
        )

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse O365 timestamp."""
        if not ts_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None
