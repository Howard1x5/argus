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
    # Tier 1: Critical for IR (run always)
    TRIAGE_PLUGINS = [
        "windows.info",       # System metadata, kernel base address (fast, run first)
        "windows.pslist",     # Process list
        "windows.pstree",     # Process tree
        "windows.cmdline",    # Command lines
        "windows.netscan",    # Network connections
        "windows.malfind",    # Injected code detection
        "windows.filescan",   # Find files in memory
        # Tier 1 additions (S2.7.1) - HIGH priority
        "windows.dlllist",    # DLL injection detection
        "windows.handles",    # Open file/registry handles
        "windows.svcscan",    # Service enumeration
        "windows.netstat",    # Active connections (alternative to netscan)
        "windows.registry.hivelist",  # Available registry hives
        "windows.getsids",    # SID information for processes
        # Tier 2 additions (S2.7.2) - MEDIUM priority
        "windows.envars",     # Environment variables
        "windows.registry.userassist",  # UserAssist registry data
        # Tier 3 additions (S2.7.3) - LOWER priority (useful for deeper analysis)
        "windows.callbacks",  # Kernel callbacks (rootkit detection)
        "windows.ssdt",       # SSDT hooks (rootkit detection)
        # Tier 4: Memory-specific forensic plugins (added from walkthrough gap analysis)
        "windows.hashdump",       # Password hashes from SAM
        # NOTE: windows.connscan and windows.connections are Vol2-only (removed).
        # Vol3 netscan/netstat do not support WinXP (NT 5.1). XP network data
        # cannot be extracted without Vol2 or a custom scanner.
        "windows.ldrmodules",     # DLL injection detection (PEB vs VAD)
        "windows.mutantscan",     # Named mutexes (malware IOCs)
        # NOTE: windows.mftscan.ADS and windows.mftscan.MFTScan are not valid
        # Vol3 CLI plugins. Only windows.mftscan exists but is not in this
        # Vol3 version's plugin list. Removed to avoid exit code 2 errors.
        "windows.psxview",        # Hidden process detection (DKOM rootkits)
        "windows.vadinfo",        # VAD tree analysis (injection detection)
    ]

    # Additional plugins that can be run on demand (slower or less common)
    EXTENDED_PLUGINS = [
        "windows.hollowprocesses",  # Process hollowing detection
        "windows.suspicious_threads",  # Suspicious thread detection
        "windows.scheduled_tasks",  # Scheduled tasks
        "windows.lsadump",    # LSA secrets
        "windows.cachedump",  # Cached credentials
        "windows.cmdscan",    # Command history (cmd.exe)
        "windows.consoles",   # Console history
        "windows.shimcachemem",  # Shimcache from memory
        "windows.amcache",    # Amcache from memory
        "windows.dumpfiles",  # Dump files from memory
        "windows.threads",    # Thread information
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

        # Run strings extraction for IOCs not captured by Vol3 plugins
        try:
            strings_events = self._run_strings_extraction(file_path, line_num)
            for event in strings_events:
                result.add_event(event)
            logger.info(f"Strings extraction returned {len(strings_events)} events")
        except Exception as e:
            logger.error(f"Strings extraction failed: {e}", exc_info=True)
            result.add_warning(f"Strings extraction failed: {str(e)}")

        # Run process dump + file carving for suspicious PIDs (malfind hits)
        try:
            malfind_pids = set()
            for event in result.events:
                ed = event.to_dict() if hasattr(event, 'to_dict') else event
                if 'malfind' in str(ed.get('event_type', '')).lower():
                    pid = ed.get('process_id')
                    if pid:
                        malfind_pids.add(int(pid))
            if malfind_pids:
                carve_events = self._run_file_carving(
                    file_path, vol_cmd, symbols_path, malfind_pids, line_num + len(strings_events)
                )
                for event in carve_events:
                    result.add_event(event)
                logger.info(f"File carving returned {len(carve_events)} events from {len(malfind_pids)} PIDs")
        except Exception as e:
            logger.error(f"File carving failed: {e}", exc_info=True)
            result.add_warning(f"File carving failed: {str(e)}")

        result.metadata["plugins_run"] = self.TRIAGE_PLUGINS + ["strings_analysis", "file_carving"]
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

    def _run_strings_extraction(
        self, file_path: Path, start_line: int
    ) -> list:
        """Run strings on memory dump and extract IOCs (IPs, URLs, domains, suspicious patterns).

        This catches artifacts that Vol3 plugins miss — especially network IOCs
        on older OS versions (e.g., WinXP) and in-memory URLs/domains.
        """
        import re

        logger.info(f"Running strings extraction on {file_path.name}")

        # Run both ASCII and Unicode strings
        try:
            ascii_proc = subprocess.run(
                ["strings", "-a", str(file_path)],
                capture_output=True, text=True, timeout=300
            )
            unicode_proc = subprocess.run(
                ["strings", "-a", "-el", str(file_path)],
                capture_output=True, text=True, timeout=300
            )
            all_strings = ascii_proc.stdout + "\n" + unicode_proc.stdout
        except subprocess.TimeoutExpired:
            logger.warning("Strings extraction timed out")
            return []
        except FileNotFoundError:
            logger.warning("strings command not found")
            return []

        # Patterns to extract
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
        )
        url_pattern = re.compile(
            r'https?://[^\s<>"\'}\)\]]{1,500}', re.IGNORECASE
        )
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|info|biz|ru|cn|tk|cc|pw|xyz|top|php)\b',
            re.IGNORECASE
        )
        # Suspicious function/variable names (JS obfuscation, shellcode)
        js_func_pattern = re.compile(
            r'\bfunction\s+([A-Za-z_]\w{4,})\s*\(', re.IGNORECASE
        )
        eval_pattern = re.compile(
            r'\beval\s*\(', re.IGNORECASE
        )
        php_url_pattern = re.compile(
            r'[a-zA-Z0-9./~_-]+\.php\b', re.IGNORECASE
        )
        # Known exploit API patterns (map to CVEs in extractor)
        exploit_api_patterns = [
            re.compile(r'\butil\.printf\b'),
            re.compile(r'\bCollab\.collectEmailInfo\b'),
            re.compile(r'\bCollab\.getIcon\b'),
            re.compile(r'\bmedia\.newPlayer\b'),
        ]

        events = []
        line_num = start_line

        # Deduplicate — track what we've already added
        seen_ips = set()
        seen_urls = set()
        seen_domains = set()
        seen_php = set()
        seen_js_funcs = set()
        seen_exploit_apis = set()

        # Skip common private/broadcast IPs that aren't interesting
        boring_ips = {
            "0.0.0.0", "127.0.0.1", "255.255.255.255",
            "255.255.255.0", "255.0.0.0", "224.0.0.0",
        }

        for raw_line in all_strings.split("\n"):
            line = raw_line.strip()
            if not line or len(line) < 5:
                continue

            # Extract IPs
            for match in ip_pattern.finditer(line):
                ip = match.group()
                if ip in boring_ips or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                line_num += 1
                events.append(UnifiedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_file=file_path.name,
                    source_line=line_num,
                    event_type="Memory_strings_ioc",
                    severity=EventSeverity.MEDIUM,
                    source_ip=ip,
                    process_name=f"strings_ip:{ip}",
                    raw_payload=json.dumps({
                        "ioc_type": "ip_address",
                        "value": ip,
                        "context": line[:500],
                    }),
                ))

            # Extract URLs
            for match in url_pattern.finditer(line):
                url = match.group()
                if url in seen_urls or len(url) < 10:
                    continue
                seen_urls.add(url)
                line_num += 1
                events.append(UnifiedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_file=file_path.name,
                    source_line=line_num,
                    event_type="Memory_strings_ioc",
                    severity=EventSeverity.HIGH,
                    dest_ip=url,
                    process_name=f"strings_url:{url[:100]}",
                    raw_payload=json.dumps({
                        "ioc_type": "url",
                        "value": url,
                        "context": line[:500],
                    }),
                ))

            # Extract domains
            for match in domain_pattern.finditer(line):
                domain = match.group().lower()
                if domain in seen_domains or len(domain) < 5:
                    continue
                # Skip if it's part of a URL we already captured
                if any(domain in u for u in seen_urls):
                    continue
                seen_domains.add(domain)
                line_num += 1
                events.append(UnifiedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_file=file_path.name,
                    source_line=line_num,
                    event_type="Memory_strings_ioc",
                    severity=EventSeverity.MEDIUM,
                    process_name=f"strings_domain:{domain}",
                    raw_payload=json.dumps({
                        "ioc_type": "domain",
                        "value": domain,
                        "context": line[:500],
                    }),
                ))

            # Extract PHP URLs (catch partial paths like /~produkt/file.php)
            for match in php_url_pattern.finditer(line):
                php_path = match.group()
                if php_path in seen_php or len(php_path) < 5:
                    continue
                seen_php.add(php_path)
                line_num += 1
                events.append(UnifiedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_file=file_path.name,
                    source_line=line_num,
                    event_type="Memory_strings_ioc",
                    severity=EventSeverity.HIGH,
                    process_name=f"strings_php:{php_path}",
                    raw_payload=json.dumps({
                        "ioc_type": "php_path",
                        "value": php_path,
                        "context": line[:500],
                    }),
                ))

            # Extract JS function names (obfuscation indicators)
            for match in js_func_pattern.finditer(line):
                func_name = match.group(1)
                if func_name in seen_js_funcs:
                    continue
                seen_js_funcs.add(func_name)
                line_num += 1
                events.append(UnifiedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_file=file_path.name,
                    source_line=line_num,
                    event_type="Memory_strings_ioc",
                    severity=EventSeverity.MEDIUM,
                    process_name=f"strings_js_func:{func_name}",
                    raw_payload=json.dumps({
                        "ioc_type": "js_function",
                        "value": func_name,
                        "context": line[:500],
                    }),
                ))

            # Extract known exploit API calls
            for pat in exploit_api_patterns:
                match = pat.search(line)
                if match:
                    api_name = match.group()
                    if api_name in seen_exploit_apis:
                        continue
                    seen_exploit_apis.add(api_name)
                    line_num += 1
                    events.append(UnifiedEvent(
                        timestamp_utc=datetime.now(timezone.utc),
                        source_file=file_path.name,
                        source_line=line_num,
                        event_type="Memory_strings_ioc",
                        severity=EventSeverity.HIGH,
                        process_name=f"strings_exploit_api:{api_name}",
                        raw_payload=json.dumps({
                            "ioc_type": "exploit_api",
                            "value": api_name,
                            "context": line[:500],
                        }),
                    ))

        logger.info(
            f"Strings extraction: {len(seen_ips)} IPs, {len(seen_urls)} URLs, "
            f"{len(seen_domains)} domains, {len(seen_php)} PHP paths, "
            f"{len(seen_js_funcs)} JS functions, {len(seen_exploit_apis)} exploit APIs"
        )
        return events

    def _run_file_carving(
        self, file_path: Path, vol_cmd: str, symbols_path: Optional[Path],
        pids: set, start_line: int
    ) -> list:
        """Dump process memory for suspicious PIDs and carve files.

        Runs vol3 memmap --dump for each PID, then foremost to carve
        embedded files (PDFs, executables, etc.), and hashes the results.
        """
        import hashlib
        import tempfile

        if not shutil.which("foremost"):
            logger.warning("foremost not installed — skipping file carving")
            return []

        events = []
        line_num = start_line

        with tempfile.TemporaryDirectory(prefix="argus_carve_") as tmpdir:
            for pid in sorted(pids)[:10]:  # Limit to 10 PIDs
                dump_dir = Path(tmpdir) / f"pid_{pid}"
                dump_dir.mkdir()

                # Dump process memory
                cmd = [vol_cmd, "-f", str(file_path), "-o", str(dump_dir)]
                if symbols_path:
                    cmd.extend(["-s", str(symbols_path)])
                cmd.extend(["-q", "windows.memmap", "--pid", str(pid), "--dump"])

                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=120
                    )
                    if proc.returncode != 0:
                        logger.warning(f"memmap dump failed for PID {pid}")
                        continue
                except subprocess.TimeoutExpired:
                    logger.warning(f"memmap dump timed out for PID {pid}")
                    continue

                # Find the dump file
                dump_files = list(dump_dir.glob(f"pid.{pid}.dmp"))
                if not dump_files:
                    continue
                dump_file = dump_files[0]

                # Run foremost
                carve_dir = dump_dir / "carved"
                try:
                    subprocess.run(
                        ["foremost", "-t", "pdf,exe,zip",
                         "-i", str(dump_file), "-o", str(carve_dir)],
                        capture_output=True, timeout=120
                    )
                except subprocess.TimeoutExpired:
                    logger.warning(f"foremost timed out for PID {pid}")
                    continue

                # Hash all carved files
                for carved_file in sorted(carve_dir.rglob("*")):
                    if not carved_file.is_file() or carved_file.name == "audit.txt":
                        continue
                    try:
                        data = carved_file.read_bytes()
                        if len(data) < 100:  # Skip tiny fragments
                            continue
                        md5 = hashlib.md5(data).hexdigest()
                        sha256 = hashlib.sha256(data).hexdigest()
                        file_type = carved_file.suffix.lstrip(".")
                        line_num += 1
                        events.append(UnifiedEvent(
                            timestamp_utc=datetime.now(timezone.utc),
                            source_file=file_path.name,
                            source_line=line_num,
                            event_type="Memory_carved_file",
                            severity=EventSeverity.HIGH,
                            process_id=pid,
                            process_name=f"carved_{file_type}:pid_{pid}",
                            raw_payload=json.dumps({
                                "pid": pid,
                                "file_type": file_type,
                                "file_size": len(data),
                                "md5": md5,
                                "sha256": sha256,
                                "carved_name": carved_file.name,
                            }),
                        ))
                    except Exception as e:
                        logger.warning(f"Failed to hash carved file {carved_file}: {e}")

        logger.info(f"File carving: {len(events)} files carved from {len(pids)} PIDs")
        return events

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
        if "info" in plugin:
            # windows.info returns key-value pairs about system metadata
            # Format: {"Variable": "Kernel Base", "Value": "0xf80002a48000"}
            variable = record.get("Variable", "")
            value = record.get("Value", "")
            event.event_type = "Memory_system_info"
            # Store info variable in process_name field for easy access
            event.process_name = variable
            # Store value in command_line field
            event.command_line = str(value)
            # Also store raw for complete data
            event.raw_payload = json.dumps({"variable": variable, "value": value})
            return event

        elif "pslist" in plugin or "pstree" in plugin:
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
            event.process_name = record.get("ImageFileName") or record.get("Process")
            event.process_id = record.get("PID")
            event.severity = EventSeverity.HIGH  # Malfind hits are suspicious
            protection = record.get("Protection", "")
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": event.process_name,
                "protection": protection,
                "start_vpn": record.get("Start VPN"),
                "end_vpn": record.get("End VPN"),
                "hexdump": record.get("Hexdump"),
                "tag": record.get("Tag"),
            })

        elif "filescan" in plugin:
            # windows.filescan returns file objects in memory
            event.process_name = record.get("Name", "")  # File path
            event.command_line = record.get("Name", "")  # Also store in command_line
            # Store offset for forensic reference
            event.raw_payload = json.dumps({
                "offset": record.get("Offset"),
                "name": record.get("Name"),
                "size": record.get("Size"),
            })

        elif "dlllist" in plugin:
            # windows.dlllist - loaded DLLs per process
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            dll_path = record.get("Path") or record.get("FullDllName")
            event.command_line = dll_path  # Store DLL path in command_line
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "dll_base": record.get("Base"),
                "dll_path": dll_path,
                "dll_size": record.get("Size"),
            })

        elif "handles" in plugin:
            # windows.handles - open handles
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            handle_type = record.get("Type")
            handle_name = record.get("Name") or record.get("HandleValue")
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "handle_type": handle_type,
                "handle_name": handle_name,
                "granted_access": record.get("GrantedAccess"),
            })

        elif "svcscan" in plugin:
            # windows.svcscan - Windows services
            service_name = record.get("Name") or record.get("ServiceName")
            event.process_name = service_name
            event.command_line = record.get("Binary") or record.get("ImagePath")
            event.raw_payload = json.dumps({
                "service_name": service_name,
                "display_name": record.get("DisplayName"),
                "service_type": record.get("Type"),
                "start_type": record.get("Start"),
                "state": record.get("State"),
                "binary_path": record.get("Binary") or record.get("ImagePath"),
            })
            # Flag suspicious service states
            state = str(record.get("State", "")).lower()
            if "running" not in state and service_name:
                event.severity = EventSeverity.LOW

        elif "netstat" in plugin:
            # windows.netstat - alternative network connections
            event.source_ip = record.get("LocalAddr")
            event.source_port = record.get("LocalPort")
            event.dest_ip = record.get("ForeignAddr")
            event.dest_port = record.get("ForeignPort")
            event.process_id = record.get("PID")
            event.process_name = record.get("Owner")
            event.raw_payload = json.dumps({
                "state": record.get("State"),
                "protocol": record.get("Proto"),
            })

        elif "hivelist" in plugin:
            # windows.registry.hivelist - registry hives
            hive_path = record.get("FileFullPath") or record.get("Name")
            event.process_name = hive_path
            event.raw_payload = json.dumps({
                "hive_offset": record.get("Offset"),
                "file_path": hive_path,
            })

        elif "getsids" in plugin:
            # windows.getsids - SID information
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            event.username = record.get("SID") or record.get("Name")
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "sid": record.get("SID"),
                "name": record.get("Name"),
            })

        elif "envars" in plugin:
            # windows.envars - environment variables
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            var_name = record.get("Variable")
            var_value = record.get("Value")
            event.command_line = f"{var_name}={var_value}"
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "variable": var_name,
                "value": var_value,
            })

        elif "userassist" in plugin:
            # windows.registry.userassist - UserAssist data
            program = record.get("Path") or record.get("Name")
            event.process_name = program
            event.raw_payload = json.dumps({
                "path": program,
                "count": record.get("Count"),
                "focus_count": record.get("FocusCount"),
                "time_focused": record.get("TimeFocused"),
                "last_updated": record.get("LastUpdated"),
            })

        elif "callbacks" in plugin:
            # windows.callbacks - kernel callbacks
            event.severity = EventSeverity.MEDIUM  # Callbacks can indicate rootkits
            callback_type = record.get("Type")
            module = record.get("Module") or record.get("Symbol")
            event.process_name = module
            event.raw_payload = json.dumps({
                "callback_type": callback_type,
                "callback_address": record.get("Callback"),
                "module": module,
                "detail": record.get("Detail"),
            })

        elif "ssdt" in plugin:
            # windows.ssdt - SSDT hooks
            event.severity = EventSeverity.MEDIUM  # SSDT hooks can indicate rootkits
            event.process_name = record.get("Symbol") or record.get("Module")
            event.raw_payload = json.dumps({
                "index": record.get("Index"),
                "address": record.get("Address"),
                "module": record.get("Module"),
                "symbol": record.get("Symbol"),
            })

        elif "connscan" in plugin or "connections" in plugin:
            # windows.connscan / windows.connections (WinXP/Vista era network)
            event.source_ip = record.get("LocalAddr")
            event.source_port = record.get("LocalPort")
            event.dest_ip = record.get("ForeignAddr")
            event.dest_port = record.get("ForeignPort")
            event.process_id = record.get("PID")
            event.process_name = record.get("Owner") or record.get("ImageFileName")

        elif "ldrmodules" in plugin:
            # windows.ldrmodules — DLL injection detection (PEB vs VAD)
            event.process_name = record.get("ImageFileName")
            event.process_id = record.get("PID")
            in_load = record.get("InLoad", True)
            in_init = record.get("InInit", True)
            in_mem = record.get("InMem", True)
            mapped_path = record.get("MappedPath") or record.get("BaseDllName")
            # DLLs not in all three lists may be injected
            if not (in_load and in_init and in_mem):
                event.severity = EventSeverity.HIGH
            event.command_line = mapped_path
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "base": record.get("Base"),
                "in_load": in_load,
                "in_init": in_init,
                "in_mem": in_mem,
                "mapped_path": mapped_path,
            })

        elif "mutantscan" in plugin:
            # windows.mutantscan — named mutexes
            mutex_name = record.get("Name") or record.get("HandleValue")
            event.process_name = mutex_name
            event.raw_payload = json.dumps({
                "name": mutex_name,
                "offset": record.get("Offset"),
                "signal_state": record.get("SignalState"),
            })

        elif "hashdump" in plugin:
            # windows.hashdump — password hashes
            event.severity = EventSeverity.HIGH
            username = record.get("User") or record.get("Name")
            event.username = username
            event.process_name = username
            event.raw_payload = json.dumps({
                "user": username,
                "rid": record.get("rid") or record.get("RID") or record.get("Rid"),
                "lmhash": record.get("LMHash") or record.get("lmhash"),
                "nthash": record.get("NTHash") or record.get("nthash"),
            })

        elif "mftscan" in plugin and "ADS" in plugin:
            # windows.mftscan.ADS — NTFS Alternate Data Streams
            event.severity = EventSeverity.HIGH
            ads_name = record.get("ADS") or record.get("Name")
            filename = record.get("FileName") or record.get("Record")
            event.process_name = f"{filename}:{ads_name}"
            event.raw_payload = json.dumps({
                "filename": filename,
                "ads_name": ads_name,
                "offset": record.get("Offset"),
                "record_number": record.get("RecordNumber"),
            })

        elif "mftscan" in plugin and "MFTScan" in plugin:
            # windows.mftscan.MFTScan — full MFT file listing
            filename = record.get("FileName") or record.get("Name")
            event.process_name = filename
            event.command_line = filename  # Store in command_line for searchability
            event.raw_payload = json.dumps({
                "filename": filename,
                "offset": record.get("Offset"),
                "record_number": record.get("RecordNumber"),
                "record_type": record.get("RecordType"),
                "attribute_type": record.get("AttributeType"),
            })
            # Parse timestamp from MFT if available
            for ts_field in ["Created", "Modified", "MFTAltered", "Accessed"]:
                if record.get(ts_field):
                    try:
                        ts_str = record[ts_field]
                        if isinstance(ts_str, str):
                            event.timestamp_utc = datetime.fromisoformat(
                                ts_str.replace("Z", "+00:00")
                            )
                    except (ValueError, TypeError):
                        pass
                    break

        elif "psxview" in plugin:
            # windows.psxview — hidden process detection (cross-references lists)
            event.process_name = record.get("ImageFileName") or record.get("Name")
            event.process_id = record.get("PID")
            # Check if process is visible in all enumeration methods
            pslist = record.get("pslist", True)
            psscan = record.get("psscan", True)
            thrdproc = record.get("thrdproc", True)
            csrss = record.get("csrss", True)
            # Process hidden from any list is suspicious
            if not all([pslist, psscan, thrdproc, csrss]):
                event.severity = EventSeverity.HIGH
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "offset": record.get("Offset"),
                "pslist": pslist,
                "psscan": psscan,
                "thrdproc": thrdproc,
                "csrss": csrss,
                "session": record.get("Session"),
                "exit_time": record.get("ExitTime"),
            })

        elif "vadinfo" in plugin:
            # windows.vadinfo — VAD tree details (injection detection)
            event.process_name = record.get("ImageFileName") or record.get("Process")
            event.process_id = record.get("PID")
            protection = record.get("Protection") or ""
            # PAGE_EXECUTE_READWRITE is suspicious
            if "EXECUTE" in str(protection).upper() and "WRITE" in str(protection).upper():
                event.severity = EventSeverity.HIGH
            event.raw_payload = json.dumps({
                "pid": record.get("PID"),
                "process": record.get("ImageFileName"),
                "start": record.get("Start"),
                "end": record.get("End"),
                "tag": record.get("Tag"),
                "protection": protection,
                "committed_pages": record.get("CommittedPages"),
                "private_memory": record.get("PrivateMemory"),
            })

        # Store raw record for all other plugins
        if not event.raw_payload:
            event.raw_payload = json.dumps(record)

        return event
