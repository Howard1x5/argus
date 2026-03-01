"""Azure AD audit log parser for ARGUS.

Parses Azure Active Directory audit and sign-in logs.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-risk Azure AD activities
HIGH_RISK_ACTIVITIES = {
    "Add member to role",
    "Add owner to application",
    "Add owner to service principal",
    "Add app role assignment grant to user",
    "Consent to application",
    "Add delegated permission grant",
    "Add application credentials",
    "Update application - Certificates and secrets management",
    "Add service principal credentials",
    "Reset password",
    "Add user",
    "Delete user",
    "Hard delete user",
    "Update user",
    "Add member to group",
    "Add owner to group",
}


class AzureADParser(BaseParser):
    """Parser for Azure AD audit logs."""

    name = "azure_ad"
    description = "Azure Active Directory audit logs"
    supported_extensions = [".json"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Azure AD log file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                # Azure AD logs can be array or object with value array
                if isinstance(data, list):
                    records = data
                elif isinstance(data, dict) and "value" in data:
                    records = data["value"]
                else:
                    return False

                if records and isinstance(records[0], dict):
                    # Check for Azure AD specific fields
                    return any(
                        key in records[0]
                        for key in ["activityDisplayName", "operationType", "category"]
                    )
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Azure AD log file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Handle both array and object formats
            if isinstance(data, list):
                records = data
            else:
                records = data.get("value", [])

            result.metadata["record_count"] = len(records)

            for idx, record in enumerate(records):
                try:
                    event = self._parse_record(record, idx + 1, file_path.name)
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Record {idx + 1}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Azure AD log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single Azure AD record."""
        # Get timestamp
        timestamp = self._parse_timestamp(
            record.get("activityDateTime")
            or record.get("createdDateTime")
        )
        if not timestamp:
            return None

        activity = record.get("activityDisplayName") or record.get("operationType", "Unknown")
        category = record.get("category", "AzureAD")

        # Determine severity
        severity = EventSeverity.INFO
        if activity in HIGH_RISK_ACTIVITIES:
            severity = EventSeverity.HIGH
        elif record.get("result") == "failure":
            severity = EventSeverity.MEDIUM

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"AzureAD_{category}",
            source_system="AzureAD",
            severity=severity,
            parser_name=self.name,
        )

        # User information
        initiated_by = record.get("initiatedBy", {})
        user = initiated_by.get("user", {})
        event.username = (
            user.get("userPrincipalName")
            or user.get("displayName")
            or record.get("userPrincipalName")
        )

        # IP address
        event.source_ip = user.get("ipAddress") or record.get("ipAddress")

        # Store activity name
        event.process_name = activity

        # Target resources
        target_resources = record.get("targetResources", [])
        if target_resources:
            target = target_resources[0]
            event.file_path = target.get("userPrincipalName") or target.get("displayName")

        # User agent
        event.user_agent = record.get("userAgent")

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse Azure AD timestamp."""
        if not ts_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.rstrip("Z"), fmt.rstrip("Z"))
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        return None
