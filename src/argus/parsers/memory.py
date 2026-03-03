"""Memory dump parser for ARGUS.

Parses memory dumps using Volatility 3 subprocess.
"""

import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity

logger = logging.getLogger(__name__)

# Common locations for Volatility3 symbol files
SYMBOL_SEARCH_PATHS = [
    Path.home() / "volatility3_symbols",
    Path.home() / ".volatility3" / "symbols",
    Path("/opt/volatility3/symbols"),
    Path("/usr/share/volatility3/symbols"),
]


def _find_symbols_path(case_config: Optional[dict] = None) -> Optional[Path]:
    """Find Volatility3 symbols directory.

    Priority: case config > global config > env var > common paths.
    """
    # 1. Check case config
    if case_config and "volatility_symbols_path" in case_config:
        p = Path(case_config["volatility_symbols_path"])
        if p.exists() and p.is_dir():
            return p

    # 2. Check global ARGUS config
    global_config = Path.home() / ".argus" / "config.yaml"
    if global_config.exists():
        try:
            import yaml
            with open(global_config) as f:
                cfg = yaml.safe_load(f)
            if cfg and "volatility_symbols_path" in cfg:
                p = Path(cfg["volatility_symbols_path"])
                if p.exists() and p.is_dir():
                    return p
        except Exception:
            pass

    # 3. Check environment variable
    env_path = os.environ.get("VOLATILITY_SYMBOLS_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_dir():
            return p

    # 4. Check common locations
    for path in SYMBOL_SEARCH_PATHS:
        if path.exists() and path.is_dir():
            return path

    return None


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

        # Find symbols path
        symbols_path = _find_symbols_path()
        if symbols_path:
            logger.info(f"Using Volatility symbols from: {symbols_path}")
        else:
            logger.warning(
                "No Volatility3 symbols directory found. "
                "Memory parsing will likely fail. "
                "Set VOLATILITY_SYMBOLS_PATH env var or place symbols in ~/volatility3_symbols/"
            )
            result.add_warning(
                "No Volatility symbols found - memory parsing may fail. "
                "Set VOLATILITY_SYMBOLS_PATH or install symbols to ~/volatility3_symbols/"
            )

        line_num = 0
        file_size_gb = file_path.stat().st_size / (1024**3)

        # Run triage plugins
        for plugin in self.TRIAGE_PLUGINS:
            try:
                logger.info(
                    f"Running Volatility plugin '{plugin}' on {file_path.name} "
                    f"({file_size_gb:.1f} GB)"
                )
                events, warnings = self._run_plugin(
                    file_path, vol_cmd, plugin, symbols_path
                )
                for event in events:
                    line_num += 1
                    event.source_line = line_num
                    result.add_event(event)
                for warning in warnings:
                    result.add_warning(warning)

                logger.info(f"Plugin '{plugin}' returned {len(events)} events")

            except Exception as e:
                logger.error(f"Plugin {plugin} failed with exception: {e}", exc_info=True)
                result.add_warning(f"Plugin {plugin} failed: {str(e)}")

        result.metadata["plugins_run"] = self.TRIAGE_PLUGINS
        result.metadata["symbols_path"] = str(symbols_path) if symbols_path else None
        return result

    def _run_plugin(
        self,
        file_path: Path,
        vol_cmd: str,
        plugin: str,
        symbols_path: Optional[Path] = None,
        timeout: int = 600,  # 10 minutes per plugin (increased from 300)
    ) -> tuple[list[UnifiedEvent], list[str]]:
        """Run a Volatility plugin and parse output.

        Returns:
            Tuple of (events list, warnings list)
        """
        events = []
        warnings = []

        # Check for timeout override from environment
        timeout = int(os.environ.get("ARGUS_VOL_TIMEOUT", timeout))

        try:
            # Build command
            cmd = [vol_cmd]

            # Add symbols path if available
            if symbols_path:
                cmd.extend(["-s", str(symbols_path)])

            cmd.extend([
                "-f", str(file_path),
                "-r", "json",
                plugin,
            ])

            logger.debug(f"Running command: {' '.join(cmd)}")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Handle non-zero return code
            if proc.returncode != 0:
                logger.warning(
                    f"Volatility plugin '{plugin}' exited with code {proc.returncode}. "
                    f"Stdout (first 500): {proc.stdout[:500] if proc.stdout else 'empty'}. "
                    f"Stderr (first 500): {proc.stderr[:500] if proc.stderr else 'empty'}"
                )
                # Don't return yet - check if there's still usable output
                if not proc.stdout or not proc.stdout.strip():
                    warnings.append(
                        f"Plugin {plugin} failed (exit code {proc.returncode}): "
                        f"{proc.stderr[:200] if proc.stderr else 'no error message'}"
                    )
                    return events, warnings

            # Parse JSON output
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                # Try line-by-line JSON (some plugins output JSONL)
                for line in proc.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            record = json.loads(line)
                            event = self._parse_record(record, plugin, file_path.name)
                            if event:
                                events.append(event)
                        except json.JSONDecodeError:
                            continue
                return events, warnings

            # Handle array output
            if isinstance(data, list):
                for record in data:
                    event = self._parse_record(record, plugin, file_path.name)
                    if event:
                        events.append(event)

        except subprocess.TimeoutExpired as e:
            logger.error(
                f"Volatility plugin '{plugin}' timed out after {timeout}s "
                f"on file {file_path.name}"
            )
            warnings.append(f"Plugin {plugin} timed out after {timeout}s")
        except subprocess.SubprocessError as e:
            logger.error(f"Volatility subprocess error for plugin '{plugin}': {e}")
            warnings.append(f"Plugin {plugin} subprocess error: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Volatility JSON output for plugin '{plugin}': {e}")
            warnings.append(f"Plugin {plugin} JSON parse error: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error running Volatility plugin '{plugin}': {e}",
                exc_info=True
            )
            warnings.append(f"Plugin {plugin} unexpected error: {type(e).__name__}: {e}")

        return events, warnings

    def _parse_record(
        self, record: dict, plugin: str, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a Volatility output record."""
        if not isinstance(record, dict):
            return None

        # Extract timestamp from record if available
        timestamp = datetime.now(timezone.utc)
        if "CreateTime" in record and record["CreateTime"]:
            try:
                # Vol3 returns ISO format timestamps
                ts_str = record["CreateTime"]
                if isinstance(ts_str, str):
                    # Handle various timestamp formats
                    timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

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
