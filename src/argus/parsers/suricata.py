"""Suricata EVE JSON parser for ARGUS.

Parses Suricata IDS/IPS EVE JSON log format.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Suricata severity mapping
SEVERITY_MAP = {
    1: EventSeverity.HIGH,     # High priority alerts
    2: EventSeverity.MEDIUM,   # Medium priority
    3: EventSeverity.LOW,      # Low priority
    4: EventSeverity.INFO,     # Informational
}


class SuricataParser(BaseParser):
    """Parser for Suricata EVE JSON logs."""

    name = "suricata"
    description = "Suricata IDS/IPS EVE JSON logs"
    supported_extensions = [".json", ".log"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a Suricata EVE log."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False

                try:
                    record = json.loads(first_line)
                    # Suricata EVE logs have event_type field
                    return (
                        isinstance(record, dict)
                        and "event_type" in record
                        and any(
                            key in record
                            for key in ["src_ip", "dest_ip", "flow_id", "alert"]
                        )
                    )
                except json.JSONDecodeError:
                    return False
        except Exception:
            return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Suricata EVE log file."""
        result = self._create_result(file_path)

        line_num = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                        event = self._parse_record(record, line_num, file_path.name)
                        if event:
                            result.add_event(event)
                    except json.JSONDecodeError:
                        result.add_warning(f"Line {line_num}: Invalid JSON")
                    except Exception as e:
                        result.add_warning(f"Line {line_num}: {str(e)}")

        except Exception as e:
            result.add_error(f"Failed to parse Suricata log: {str(e)}")

        return result

    def _parse_record(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single Suricata EVE record."""
        # Get timestamp
        timestamp = self._parse_timestamp(record.get("timestamp"))
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        event_type = record.get("event_type", "unknown")

        # Determine severity
        severity = EventSeverity.INFO
        if event_type == "alert":
            alert = record.get("alert", {})
            sev = alert.get("severity", 4)
            severity = SEVERITY_MAP.get(sev, EventSeverity.INFO)
        elif event_type == "anomaly":
            severity = EventSeverity.MEDIUM

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"Suricata_{event_type}",
            severity=severity,
            parser_name=self.name,
        )

        # Network fields
        event.source_ip = record.get("src_ip")
        event.dest_ip = record.get("dest_ip")

        if "src_port" in record:
            try:
                event.source_port = int(record["src_port"])
            except (ValueError, TypeError):
                pass

        if "dest_port" in record:
            try:
                event.dest_port = int(record["dest_port"])
            except (ValueError, TypeError):
                pass

        # Protocol info
        proto = record.get("proto", "")
        app_proto = record.get("app_proto", "")

        # Event-type specific parsing
        if event_type == "alert":
            self._parse_alert(event, record)
        elif event_type == "http":
            self._parse_http(event, record)
        elif event_type == "dns":
            self._parse_dns(event, record)
        elif event_type == "tls":
            self._parse_tls(event, record)
        elif event_type == "fileinfo":
            self._parse_fileinfo(event, record)
        elif event_type == "flow":
            self._parse_flow(event, record)

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse Suricata timestamp."""
        if not ts_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
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

    def _parse_alert(self, event: UnifiedEvent, record: dict) -> None:
        """Parse alert-specific fields."""
        alert = record.get("alert", {})

        # Store signature info in process_name for searchability
        event.process_name = alert.get("signature", "Unknown Alert")

        # Store category
        category = alert.get("category", "")
        if category:
            event.event_type = f"Suricata_alert_{category}"

    def _parse_http(self, event: UnifiedEvent, record: dict) -> None:
        """Parse HTTP-specific fields."""
        http = record.get("http", {})

        event.http_method = http.get("http_method")
        event.uri = http.get("url") or http.get("uri")
        event.user_agent = http.get("http_user_agent")
        event.referrer = http.get("http_refer")

        if "status" in http:
            try:
                event.status_code = int(http["status"])
            except (ValueError, TypeError):
                pass

        # Hostname
        hostname = http.get("hostname")
        if hostname and event.uri and not event.uri.startswith("http"):
            event.uri = f"http://{hostname}{event.uri}"

    def _parse_dns(self, event: UnifiedEvent, record: dict) -> None:
        """Parse DNS-specific fields."""
        dns = record.get("dns", {})

        # Query name
        if "rrname" in dns:
            event.uri = dns["rrname"]
        elif "queries" in dns and dns["queries"]:
            event.uri = dns["queries"][0].get("rrname", "")

    def _parse_tls(self, event: UnifiedEvent, record: dict) -> None:
        """Parse TLS-specific fields."""
        tls = record.get("tls", {})

        # Server name (SNI)
        event.uri = tls.get("sni")

        # Certificate info
        if "subject" in tls:
            event.file_path = tls["subject"]

    def _parse_fileinfo(self, event: UnifiedEvent, record: dict) -> None:
        """Parse file info fields."""
        fileinfo = record.get("fileinfo", {})

        event.file_path = fileinfo.get("filename")
        event.file_hash = (
            fileinfo.get("sha256")
            or fileinfo.get("sha1")
            or fileinfo.get("md5")
        )

    def _parse_flow(self, event: UnifiedEvent, record: dict) -> None:
        """Parse flow-specific fields."""
        flow = record.get("flow", {})

        # Flow state can indicate connection issues
        state = flow.get("state", "")
        if state in ["closed", "established"]:
            event.severity = EventSeverity.INFO
