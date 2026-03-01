"""Browser history parser for ARGUS.

Parses browser history from Chrome, Firefox, and Edge SQLite databases
or exported CSV/JSON files.
"""

import csv
import json
import sqlite3
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r"pastebin\.",
    r"raw\.github",
    r"githubusercontent\.com/.*\.(exe|ps1|bat|vbs|dll)",
    r"bit\.ly",
    r"tinyurl\.com",
    r"file://",
    r"\.onion",
    r"transfer\.sh",
    r"temp\.sh",
    r"wetransfer\.com",
    r"mega\.nz",
    r"sendspace\.com",
]


class BrowserHistoryParser(BaseParser):
    """Parser for browser history artifacts."""

    name = "browser"
    description = "Browser history (Chrome, Firefox, Edge)"
    supported_extensions = [".sqlite", ".db", ".csv", ".json"]

    # Browser database filenames
    BROWSER_DBS = {
        "history": "chrome",
        "places.sqlite": "firefox",
        "history.db": "edge",
        "webdata": "chrome",
    }

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a browser history file."""
        name_lower = file_path.name.lower()

        # Check known database names
        if name_lower in cls.BROWSER_DBS:
            return True

        # Check for SQLite database
        if file_path.suffix.lower() in [".sqlite", ".db"]:
            try:
                with open(file_path, "rb") as f:
                    magic = f.read(16)
                    if magic.startswith(b"SQLite format 3"):
                        # Check if it has browser tables
                        conn = sqlite3.connect(str(file_path))
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                        tables = {row[0].lower() for row in cursor.fetchall()}
                        conn.close()

                        browser_tables = {"urls", "visits", "moz_places", "moz_historyvisits"}
                        return bool(tables & browser_tables)
            except Exception:
                pass

        # Check for CSV/JSON with browser data
        if file_path.suffix.lower() in [".csv", ".json"]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2048)
                    indicators = ["url", "visit_time", "visit_count", "http", "https"]
                    return sum(1 for ind in indicators if ind.lower() in content.lower()) >= 3
            except Exception:
                pass

        return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse browser history file."""
        result = self._create_result(file_path)

        try:
            # Detect format
            if file_path.suffix.lower() in [".sqlite", ".db"]:
                self._parse_sqlite(file_path, result)
            elif file_path.suffix.lower() == ".json":
                self._parse_json(file_path, result)
            elif file_path.suffix.lower() == ".csv":
                self._parse_csv(file_path, result)

        except Exception as e:
            result.add_error(f"Failed to parse browser history: {str(e)}")

        return result

    def _parse_sqlite(self, file_path: Path, result: ParseResult) -> None:
        """Parse SQLite browser database."""
        conn = sqlite3.connect(str(file_path))
        cursor = conn.cursor()

        # Get table list
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0].lower() for row in cursor.fetchall()}

        line_num = 0

        # Chrome/Edge format
        if "urls" in tables:
            result.metadata["browser"] = "chrome/edge"
            try:
                cursor.execute("""
                    SELECT u.url, u.title, u.visit_count, u.last_visit_time
                    FROM urls u
                    ORDER BY u.last_visit_time DESC
                """)

                for row in cursor.fetchall():
                    line_num += 1
                    event = self._create_chrome_event(row, line_num, file_path.name)
                    if event:
                        result.add_event(event)
            except Exception as e:
                result.add_warning(f"Chrome/Edge query failed: {e}")

        # Firefox format
        if "moz_places" in tables:
            result.metadata["browser"] = "firefox"
            try:
                cursor.execute("""
                    SELECT p.url, p.title, p.visit_count, h.visit_date
                    FROM moz_places p
                    LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                    ORDER BY h.visit_date DESC
                """)

                for row in cursor.fetchall():
                    line_num += 1
                    event = self._create_firefox_event(row, line_num, file_path.name)
                    if event:
                        result.add_event(event)
            except Exception as e:
                result.add_warning(f"Firefox query failed: {e}")

        conn.close()

    def _parse_json(self, file_path: Path, result: ParseResult) -> None:
        """Parse JSON browser export."""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        try:
            if content.strip().startswith("["):
                records = json.loads(content)
            else:
                records = []
                for line in content.split("\n"):
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except json.JSONDecodeError:
            return

        for idx, record in enumerate(records):
            event = self._create_generic_event(record, idx + 1, file_path.name)
            if event:
                result.add_event(event)

    def _parse_csv(self, file_path: Path, result: ParseResult) -> None:
        """Parse CSV browser export."""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)

            for idx, row in enumerate(reader):
                event = self._create_generic_event(row, idx + 2, file_path.name)
                if event:
                    result.add_event(event)

    def _create_chrome_event(
        self, row: tuple, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Create event from Chrome/Edge database row."""
        url, title, visit_count, last_visit = row

        if not url:
            return None

        # Chrome timestamps are microseconds since 1601-01-01
        timestamp = datetime.now(timezone.utc)
        if last_visit:
            try:
                # Convert Chrome timestamp
                epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                delta = last_visit / 1_000_000  # Convert microseconds to seconds
                timestamp = epoch + datetime.timedelta(seconds=delta)
            except Exception:
                pass

        severity = self._assess_url_severity(url)

        return UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Browser_Chrome",
            severity=severity,
            parser_name=self.name,
            uri=url,
            raw_payload=f"title={title}, visits={visit_count}",
        )

    def _create_firefox_event(
        self, row: tuple, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Create event from Firefox database row."""
        url, title, visit_count, visit_date = row

        if not url:
            return None

        # Firefox timestamps are microseconds since Unix epoch
        timestamp = datetime.now(timezone.utc)
        if visit_date:
            try:
                timestamp = datetime.fromtimestamp(
                    visit_date / 1_000_000, tz=timezone.utc
                )
            except Exception:
                pass

        severity = self._assess_url_severity(url)

        return UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Browser_Firefox",
            severity=severity,
            parser_name=self.name,
            uri=url,
            raw_payload=f"title={title}, visits={visit_count}",
        )

    def _create_generic_event(
        self, record: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Create event from generic browser export."""
        # Find URL field
        url = None
        for key in ["url", "URL", "uri", "URI", "address", "link"]:
            if key in record and record[key]:
                url = record[key]
                break

        if not url:
            return None

        # Find timestamp
        timestamp = datetime.now(timezone.utc)
        for key in ["visit_time", "timestamp", "time", "date", "last_visit"]:
            if key in record and record[key]:
                try:
                    val = record[key]
                    if isinstance(val, (int, float)):
                        timestamp = datetime.fromtimestamp(val, tz=timezone.utc)
                    else:
                        timestamp = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
                except Exception:
                    continue
                break

        severity = self._assess_url_severity(url)

        return UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type="Browser",
            severity=severity,
            parser_name=self.name,
            uri=url,
            raw_payload=json.dumps(record) if isinstance(record, dict) else str(record),
        )

    def _assess_url_severity(self, url: str) -> EventSeverity:
        """Assess URL severity based on patterns."""
        import re

        url_lower = url.lower()

        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                return EventSeverity.MEDIUM

        return EventSeverity.INFO
