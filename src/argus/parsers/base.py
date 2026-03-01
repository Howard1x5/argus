"""Base parser class and unified event schema for ARGUS.

All evidence parsers inherit from BaseParser and output events
conforming to the UnifiedEvent schema.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


class EventSeverity(Enum):
    """Event severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UnifiedEvent:
    """Unified event schema for all evidence types.

    All parsers normalize their output to this schema.
    """

    # Required fields
    timestamp_utc: datetime
    source_file: str
    source_line: int
    event_type: str

    # Common optional fields
    event_id: Optional[int] = None
    severity: EventSeverity = EventSeverity.INFO
    source_system: Optional[str] = None

    # Network fields
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    # Identity fields
    username: Optional[str] = None
    domain: Optional[str] = None
    logon_type: Optional[int] = None

    # Process fields
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    parent_command_line: Optional[str] = None

    # File fields
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Web fields
    http_method: Optional[str] = None
    uri: Optional[str] = None
    query_string: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None

    # Service fields
    service_name: Optional[str] = None
    service_path: Optional[str] = None

    # Registry fields
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None

    # Raw data
    raw_payload: Optional[str] = None

    # Metadata
    parser_name: Optional[str] = None
    parse_warnings: list[str] = field(default_factory=list)
    description: Optional[str] = None  # Human-readable event description

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for DataFrame creation."""
        return {
            "timestamp_utc": self.timestamp_utc,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "severity": self.severity.value if self.severity else None,
            "source_system": self.source_system,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "username": self.username,
            "domain": self.domain,
            "logon_type": self.logon_type,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process_name": self.parent_process_name,
            "parent_process_id": self.parent_process_id,
            "command_line": self.command_line,
            "parent_command_line": self.parent_command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "http_method": self.http_method,
            "uri": self.uri,
            "query_string": self.query_string,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "referrer": self.referrer,
            "service_name": self.service_name,
            "service_path": self.service_path,
            "registry_key": self.registry_key,
            "registry_value": self.registry_value,
            "raw_payload": self.raw_payload,
            "parser_name": self.parser_name,
            "parse_warnings": ";".join(self.parse_warnings) if self.parse_warnings else None,
            "description": self.description,
        }


# PyArrow schema for Parquet output
PARQUET_SCHEMA = pa.schema([
    ("timestamp_utc", pa.timestamp("us", tz="UTC")),
    ("source_file", pa.string()),
    ("source_line", pa.int64()),
    ("event_type", pa.string()),
    ("event_id", pa.int64()),
    ("severity", pa.string()),
    ("source_system", pa.string()),
    ("source_ip", pa.string()),
    ("source_port", pa.int64()),
    ("dest_ip", pa.string()),
    ("dest_port", pa.int64()),
    ("username", pa.string()),
    ("domain", pa.string()),
    ("logon_type", pa.int64()),
    ("process_name", pa.string()),
    ("process_id", pa.int64()),
    ("parent_process_name", pa.string()),
    ("parent_process_id", pa.int64()),
    ("command_line", pa.string()),
    ("parent_command_line", pa.string()),
    ("file_path", pa.string()),
    ("file_hash", pa.string()),
    ("http_method", pa.string()),
    ("uri", pa.string()),
    ("query_string", pa.string()),
    ("status_code", pa.int64()),
    ("user_agent", pa.string()),
    ("referrer", pa.string()),
    ("service_name", pa.string()),
    ("service_path", pa.string()),
    ("registry_key", pa.string()),
    ("registry_value", pa.string()),
    ("raw_payload", pa.string()),
    ("parser_name", pa.string()),
    ("parse_warnings", pa.string()),
    ("description", pa.string()),
])


class ParseResult:
    """Result of parsing an evidence file."""

    def __init__(self, source_file: Path):
        self.source_file = source_file
        self.events: list[UnifiedEvent] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.metadata: dict[str, Any] = {}

    @property
    def success(self) -> bool:
        """Returns True if parsing completed without critical errors."""
        return len(self.errors) == 0

    @property
    def event_count(self) -> int:
        """Number of events parsed."""
        return len(self.events)

    def add_event(self, event: UnifiedEvent) -> None:
        """Add a parsed event."""
        self.events.append(event)

    def add_error(self, error: str) -> None:
        """Add a parsing error."""
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Add a parsing warning."""
        self.warnings.append(warning)

    def to_dataframe(self) -> pd.DataFrame:
        """Convert all events to a pandas DataFrame."""
        if not self.events:
            return pd.DataFrame()
        return pd.DataFrame([e.to_dict() for e in self.events])

    def to_parquet(self, output_path: Path) -> None:
        """Write events to a Parquet file."""
        df = self.to_dataframe()
        if df.empty:
            # Create empty file with schema
            table = pa.Table.from_pydict(
                {col: [] for col in PARQUET_SCHEMA.names},
                schema=PARQUET_SCHEMA
            )
        else:
            # Convert timestamp to proper format
            df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True)
            table = pa.Table.from_pandas(df, schema=PARQUET_SCHEMA, preserve_index=False)

        pq.write_table(table, output_path)


class BaseParser(ABC):
    """Abstract base class for all evidence parsers.

    Subclasses must implement:
    - can_parse(): Check if this parser can handle a file
    - parse(): Parse the file and return events
    """

    # Parser identification
    name: str = "base"
    description: str = "Base parser"
    supported_extensions: list[str] = []

    def __init__(self):
        self.warnings: list[str] = []

    @classmethod
    @abstractmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this parser can handle the given file.

        Args:
            file_path: Path to the evidence file

        Returns:
            True if this parser can handle the file
        """
        pass

    @abstractmethod
    def parse(self, file_path: Path) -> ParseResult:
        """Parse an evidence file.

        Args:
            file_path: Path to the evidence file

        Returns:
            ParseResult containing normalized events
        """
        pass

    def _create_result(self, file_path: Path) -> ParseResult:
        """Create a new ParseResult for this file."""
        result = ParseResult(file_path)
        result.metadata["parser"] = self.name
        return result

    def _warn(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)
