"""Okta System Log parser for ARGUS.

Parses Okta identity provider audit logs.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# High-risk Okta event types
HIGH_RISK_EVENTS = {
    # Authentication issues
    "user.session.start",
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",

    # Account compromise indicators
    "user.account.lock",
    "user.account.unlock",
    "user.mfa.factor.deactivate",
    "user.mfa.factor.reset_all",

    # Admin actions
    "user.lifecycle.create",
    "user.lifecycle.delete.initiated",
    "user.lifecycle.suspend",
    "user.lifecycle.unsuspend",
    "user.lifecycle.activate",
    "user.lifecycle.deactivate",
    "group.user_membership.add",
    "group.user_membership.remove",
    "application.user_membership.add",
    "application.user_membership.remove",
    "policy.lifecycle.update",
    "policy.rule.update",

    # Security events
    "security.threat.detected",
    "security.password_spray.detected",
    "security.brute_force.detected",

    # API token events
    "system.api_token.create",
    "system.api_token.revoke",
}


class OktaParser(BaseParser):
    """Parser for Okta System Logs."""

    name = "okta"
    description = "Okta identity provider system logs"
    supported_extensions = [".json", ".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is an Okta log file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)

                # Check for Okta-specific indicators
                indicators = [
                    "eventType",
                    "actor",
                    "client",
                    "authenticationContext",
                    "displayMessage",
                    "outcome",
                    "target",
                    "transaction",
                    "uuid",  # Okta uses uuid for event IDs
                ]

                if sum(1 for ind in indicators if ind in content) >= 4:
                    return True

                return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Okta log file."""
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
            result.add_error(f"Failed to parse Okta log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single Okta log record."""
        # Get timestamp
        timestamp = self._parse_timestamp(record.get("published"))
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Get event type
        event_type = record.get("eventType", "unknown")

        # Determine severity
        severity = EventSeverity.INFO

        if event_type in HIGH_RISK_EVENTS:
            severity = EventSeverity.HIGH

        # Check outcome
        outcome = record.get("outcome", {})
        if isinstance(outcome, dict):
            result = outcome.get("result", "").upper()
            if result == "FAILURE":
                severity = EventSeverity.MEDIUM
            elif result == "DENY":
                severity = EventSeverity.MEDIUM

        # Check for security events
        if record.get("securityContext", {}).get("isThreat"):
            severity = EventSeverity.HIGH

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"Okta_{event_type}",
            severity=severity,
            parser_name=self.name,
        )

        # Actor (user who performed action)
        actor = record.get("actor", {})
        if isinstance(actor, dict):
            event.username = (
                actor.get("alternateId")
                or actor.get("displayName")
                or actor.get("id")
            )

        # Client information
        client = record.get("client", {})
        if isinstance(client, dict):
            event.source_ip = client.get("ipAddress")
            event.user_agent = client.get("userAgent", {}).get("rawUserAgent")

            # Geographic context
            geo = client.get("geographicalContext", {})
            if geo:
                event.source_system = f"{geo.get('city', '')}, {geo.get('country', '')}"

        # Target (what was acted upon)
        targets = record.get("target", [])
        if targets and isinstance(targets, list) and len(targets) > 0:
            target = targets[0]
            if isinstance(target, dict):
                event.file_path = (
                    target.get("alternateId")
                    or target.get("displayName")
                )

        # Store action in process_name for searchability
        event.process_name = event_type

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse Okta timestamp."""
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
