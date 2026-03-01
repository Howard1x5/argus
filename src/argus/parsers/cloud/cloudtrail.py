"""AWS CloudTrail log parser for ARGUS.

Parses AWS CloudTrail JSON logs.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-risk CloudTrail event names
HIGH_RISK_EVENTS = {
    "ConsoleLogin",
    "CreateUser",
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateRole",
    "AssumeRole",
    "GetSecretValue",
    "CreateKeyPair",
    "RunInstances",
    "CreateSecurityGroup",
    "AuthorizeSecurityGroupIngress",
    "ModifySnapshotAttribute",
    "CreateDBSnapshot",
    "ModifyDBSnapshotAttribute",
}


class CloudTrailParser(BaseParser):
    """Parser for AWS CloudTrail logs."""

    name = "cloudtrail"
    description = "AWS CloudTrail logs"
    supported_extensions = [".json"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a CloudTrail log file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # CloudTrail logs have "Records" array
                if isinstance(data, dict) and "Records" in data:
                    records = data["Records"]
                    if records and isinstance(records[0], dict):
                        return "eventSource" in records[0] and "eventName" in records[0]
                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a CloudTrail log file."""
        result = self._create_result(file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            records = data.get("Records", [])
            result.metadata["record_count"] = len(records)

            for idx, record in enumerate(records):
                try:
                    event = self._parse_record(record, idx + 1, file_path.name)
                    if event:
                        result.add_event(event)
                except Exception as e:
                    result.add_warning(f"Record {idx + 1}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse CloudTrail log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single CloudTrail record."""
        # Get timestamp
        timestamp = self._parse_timestamp(record.get("eventTime"))
        if not timestamp:
            return None

        event_name = record.get("eventName", "Unknown")
        event_source = record.get("eventSource", "aws")

        # Determine severity
        severity = EventSeverity.INFO
        if event_name in HIGH_RISK_EVENTS:
            severity = EventSeverity.HIGH
        elif record.get("errorCode"):
            severity = EventSeverity.MEDIUM

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"CloudTrail_{event_source}",
            source_system=record.get("awsRegion", "aws"),
            severity=severity,
            parser_name=self.name,
        )

        # User identity
        user_identity = record.get("userIdentity", {})
        event.username = (
            user_identity.get("userName")
            or user_identity.get("principalId")
            or user_identity.get("arn")
        )

        # Source IP
        event.source_ip = record.get("sourceIPAddress")

        # User agent
        event.user_agent = record.get("userAgent")

        # Store event name in process_name for searchability
        event.process_name = event_name

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse CloudTrail timestamp."""
        if not ts_str:
            return None

        try:
            # CloudTrail format: 2023-01-15T10:30:00Z
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

        try:
            # With milliseconds
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
