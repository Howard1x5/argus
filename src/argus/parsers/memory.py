"""Memory dump parser for ARGUS.

Parses memory dumps using Volatility 3 subprocess.
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class MemoryParser(BaseParser):
    """Parser for memory dumps using Volatility 3."""

    name = "memory"
    description = "Memory dumps via Volatility 3"
    supported_extensions = [".dmp", ".raw", ".vmem", ".mem", ".img"]

    # Memory dump magic bytes
    MAGIC_BYTES = {
        b"MDMP": "Windows Minidump",
        b"PAGEDU": "Windows Full Dump",
        b"KDUMP": "Linux Kdump",
    }

    # Volatility plugins to run for triage
    TRIAGE_PLUGINS = [
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.malfind",
    ]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a memory dump file."""
        if file_path.suffix.lower() not in cls.supported_extensions:
            return False

        # Check file size (memory dumps are usually large)
        try:
            if file_path.stat().st_size < 1024 * 1024:  # < 1MB
                return False

            # Check for known magic bytes
            with open(file_path, "rb") as f:
                header = f.read(8)
                for magic in cls.MAGIC_BYTES:
                    if header.startswith(magic):
                        return True

                # Check for raw memory (no specific magic)
                # These files are typically large and have certain patterns
                return True
        except Exception:
            return False

    @classmethod
    def is_volatility_available(cls) -> bool:
        """Check if Volatility 3 is installed."""
        return shutil.which("vol") is not None or shutil.which("vol3") is not None

    def _get_vol_command(self) -> str:
        """Get the Volatility command name."""
        if shutil.which("vol3"):
            return "vol3"
        return "vol"

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a memory dump using Volatility."""
        result = self._create_result(file_path)

        if not self.is_volatility_available():
            result.add_error(
                "Volatility 3 not found. Install with: pip install volatility3"
            )
            return result

        vol_cmd = self._get_vol_command()
        line_num = 0

        # Run triage plugins
        for plugin in self.TRIAGE_PLUGINS:
            try:
                events = self._run_plugin(file_path, vol_cmd, plugin)
                for event in events:
                    line_num += 1
                    event.source_line = line_num
                    result.add_event(event)
            except Exception as e:
                result.add_warning(f"Plugin {plugin} failed: {str(e)}")

        result.metadata["plugins_run"] = self.TRIAGE_PLUGINS
        return result

    def _run_plugin(
        self, file_path: Path, vol_cmd: str, plugin: str
    ) -> list[UnifiedEvent]:
        """Run a Volatility plugin and parse output."""
        events = []

        try:
            cmd = [
                vol_cmd,
                "-f", str(file_path),
                "-r", "json",
                plugin,
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout per plugin
            )

            if proc.returncode != 0:
                return events

            # Parse JSON output
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                # Try line-by-line JSON
                for line in proc.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            record = json.loads(line)
                            event = self._parse_record(record, plugin, file_path.name)
                            if event:
                                events.append(event)
                        except json.JSONDecodeError:
                            continue
                return events

            # Handle array output
            if isinstance(data, list):
                for record in data:
                    event = self._parse_record(record, plugin, file_path.name)
                    if event:
                        events.append(event)

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return events

    def _parse_record(
        self, record: dict, plugin: str, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a Volatility output record."""
        if not isinstance(record, dict):
            return None

        # Extract common fields
        timestamp = datetime.now(timezone.utc)  # Vol3 doesn't always provide timestamps

        # Determine event type and extract fields based on plugin
        event_type = f"Memory_{plugin.split('.')[-1]}"

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=0,
            event_type=event_type,
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Plugin-specific parsing
        if "pslist" in plugin or "pstree" in plugin:
            event.process_name = record.get("ImageFileName") or record.get("Name")
            event.process_id = record.get("PID")
            event.parent_process_id = record.get("PPID")
            event.command_line = record.get("CommandLine")

        elif "cmdline" in plugin:
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            event.command_line = record.get("Args") or record.get("CommandLine")

        elif "netscan" in plugin:
            event.source_ip = record.get("LocalAddr")
            event.source_port = record.get("LocalPort")
            event.dest_ip = record.get("ForeignAddr")
            event.dest_port = record.get("ForeignPort")
            event.process_id = record.get("PID")
            event.process_name = record.get("Owner")

        elif "malfind" in plugin:
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            event.severity = EventSeverity.HIGH  # Malfind hits are suspicious

        # Store raw record
        event.raw_payload = json.dumps(record)

        return event
