"""GCP Audit log parser for ARGUS.

Parses Google Cloud Platform audit logs.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-risk GCP methods
HIGH_RISK_METHODS = {
    "SetIamPolicy",
    "CreateServiceAccount",
    "CreateServiceAccountKey",
    "CreateRole",
    "UpdateRole",
    "CreateInstance",
    "DeleteInstance",
    "CreateFirewallRule",
    "UpdateFirewallRule",
    "CreateBucket",
    "UpdateBucket",
    "CreateSecret",
    "AccessSecretVersion",
    "AddMember",
    "RemoveMember",
}


class GCPAuditParser(BaseParser):
    """Parser for GCP audit logs."""

    name = "gcp"
    description = "Google Cloud Platform audit logs"
    supported_extensions = [".json"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a GCP audit log file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                # GCP logs may be NDJSON
                first_line = f.readline()
                data = json.loads(first_line)

                # Check for GCP-specific fields
                if isinstance(data, dict):
                    # Look for protoPayload or audit log structure
                    return (
                        "protoPayload" in data
                        or "logName" in data
                        or (
                            "resource" in data
                            and "type" in data.get("resource", {})
                        )
                    )
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a GCP audit log file."""
        result = self._create_result(file_path)

        try:
            records = []

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()

                # Try as NDJSON (newline-delimited JSON)
                if "\n" in content and not content.startswith("["):
                    for line in content.split("\n"):
                        if line.strip():
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                else:
                    # Try as regular JSON
                    data = json.loads(content)
                    if isinstance(data, list):
                        records = data
                    else:
                        records = [data]

            result.metadata["record_count"] = len(records)

            for idx, record in enumerate(records):
                try:
                    event = self._parse_record(record, idx + 1, file_path.name)
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Record {idx + 1}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse GCP log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single GCP audit record."""
        # Get timestamp
        timestamp = self._parse_timestamp(record.get("timestamp"))
        if not timestamp:
            return None

        # Extract proto payload (contains audit details)
        proto = record.get("protoPayload", {})
        method_name = proto.get("methodName", "Unknown")
        service_name = proto.get("serviceName", "gcp")

        # Determine severity
        severity = EventSeverity.INFO
        # Check if any high-risk method is in the method name
        for risk_method in HIGH_RISK_METHODS:
            if risk_method.lower() in method_name.lower():
                severity = EventSeverity.HIGH
                break

        # Check for errors
        if proto.get("status", {}).get("code", 0) != 0:
            severity = EventSeverity.MEDIUM

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"GCP_{service_name}",
            source_system="GCP",
            severity=severity,
            parser_name=self.name,
        )

        # User information
        auth_info = proto.get("authenticationInfo", {})
        event.username = auth_info.get("principalEmail")

        # IP address
        request_metadata = proto.get("requestMetadata", {})
        event.source_ip = request_metadata.get("callerIp")

        # User agent
        event.user_agent = request_metadata.get("callerSuppliedUserAgent")

        # Store method name
        event.process_name = method_name

        # Resource information
        resource = record.get("resource", {})
        event.source_system = resource.get("labels", {}).get("project_id", "GCP")

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse GCP timestamp."""
        if not ts_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue

        return None
