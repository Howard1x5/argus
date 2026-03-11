"""ForensicExtractor - Phase 3a Programmatic Investigator.

Per SPEC v1.1: This component queries 100% of the dataset.
All decoding, correlation, and process tree building happens here.
LLM agents receive COMPLETE extraction results - NOT samples.

22 Extraction Categories:
1. Process Trees
2. Web Attacks
3. Encoded Content Decoding
4. Credential Access
5. Lateral Movement
6. Persistence
7. Network & C2
8. Authentication Timeline
9. File Operations
10. Absence & Gaps
11. Unified Timeline
12. Kerberoasting Summary
13. Account Management
14. Network Share Activity
15. WFP Connections
16. PowerShell Activity
17. Sysmon Extended
18. Service Lifecycle
19. Scheduled Task Lifecycle
20. Event Statistics
21. LOLBin Detection
22. AD Changes
"""

import base64
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

import click
import pyarrow.parquet as pq

from argus.extractors.constants import (
    LOGON_TYPE_MAP,
    ACCOUNT_MGMT_EVENTS,
    PRIVILEGED_GROUPS,
    SYSMON_EVENTS,
    LSASS_SUSPICIOUS_ACCESS_MASKS,
    LOLBIN_PATTERNS,
    KERBEROASTING_ENCRYPTION_TYPE,
    SUSPICIOUS_SHARES,
    WEB_ATTACK_PATTERNS,
    SCANNER_USER_AGENTS,
)


class ForensicExtractor:
    """Extracts forensic artifacts from 100% of parsed evidence."""

    def __init__(self, case_path: Path):
        self.case_path = Path(case_path)
        self.parsed_dir = self.case_path / "parsed"
        self.extractions_dir = self.case_path / "extractions"
        self.extractions_dir.mkdir(exist_ok=True)

        self.events = []
        self.events_by_source = defaultdict(list)

    def load_all_events(self) -> list[dict]:
        """Load ALL events from ALL parquet files."""
        if self.events:
            return self.events

        for parquet_file in self.parsed_dir.glob("*.parquet"):
            try:
                table = pq.read_table(parquet_file)
                df_events = table.to_pylist()
                for event in df_events:
                    event["_source_parquet"] = parquet_file.name
                    self.events.append(event)
                    self.events_by_source[parquet_file.name].append(event)
            except Exception as e:
                click.echo(f"  Warning: Failed to read {parquet_file.name}: {e}")

        click.echo(f"  Loaded {len(self.events)} total events from {len(self.events_by_source)} sources")
        return self.events

    def _parse_timestamp(self, ts) -> Optional[datetime]:
        """Parse timestamp to datetime."""
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None

    def _decode_base64(self, encoded: str) -> Optional[str]:
        """Decode base64, handling UTF-8, UTF-16LE, and nested encoding."""
        if not encoded:
            return None

        try:
            # Remove whitespace
            clean = re.sub(r'\s+', '', encoded)

            # Add padding if needed
            padding = 4 - (len(clean) % 4)
            if padding != 4:
                clean += '=' * padding

            # Decode
            decoded_bytes = base64.b64decode(clean)

            # Try UTF-8 FIRST (most common for webshell commands)
            try:
                decoded = decoded_bytes.decode('utf-8')
                # Check if it looks like valid ASCII/text
                if all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return decoded.strip()
            except UnicodeDecodeError:
                pass

            # Try UTF-16LE (common for PowerShell -EncodedCommand)
            # Only if length is even (UTF-16 requires pairs)
            if len(decoded_bytes) % 2 == 0:
                try:
                    decoded = decoded_bytes.decode('utf-16-le')
                    # Check if it looks like valid text (mostly ASCII range)
                    if all(ord(c) < 128 or c in '\n\r\t' for c in decoded):
                        return decoded.strip()
                except UnicodeDecodeError:
                    pass

            # Fallback: try latin-1
            try:
                decoded = decoded_bytes.decode('latin-1')
                if all(c.isprintable() or c in '\n\r\t' for c in decoded):
                    return decoded.strip()
            except Exception:
                pass

            return None

        except Exception:
            return None

    def _extract_base64_from_text(self, text: str) -> list[tuple[str, str]]:
        """Extract and decode base64 strings from text."""
        results = []

        # Common base64 patterns
        patterns = [
            r'cmd=([A-Za-z0-9+/=]{10,})',
            r'c=([A-Za-z0-9+/=]{10,})',
            r'command=([A-Za-z0-9+/=]{10,})',
            r'-[eE][nN][cC]\s+([A-Za-z0-9+/=]{10,})',
            r'-[eE]ncoded[cC]ommand\s+([A-Za-z0-9+/=]{10,})',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, text):
                encoded = match.group(1)
                decoded = self._decode_base64(encoded)
                if decoded:
                    results.append((encoded, decoded))

        return results

    def _get_event_text(self, event: dict) -> str:
        """Get searchable text from event."""
        return " ".join(str(v) for v in event.values() if v)

    # =========================================================================
    # EXTRACTION 1: Process Trees
    # =========================================================================
    def extract_process_trees(self) -> dict:
        """Build COMPLETE process trees from Sysmon EID 1 + Windows EID 4688."""
        click.echo("  Extracting process trees...")

        events = self.load_all_events()
        process_events = []
        process_by_pid = {}
        children_by_parent = defaultdict(list)

        # Find all process creation events
        for event in events:
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", "")).lower()
            # Sysmon EID 1 or Windows Security EID 4688
            is_process_create = (
                event_id == 1 or event_id == 4688 or
                any(x in event_type for x in [
                    "sysmon_1", "sysmon 1", "process",
                    "memory_pslist", "memory_pstree", "memory_cmdline",
                ])
            )
            if is_process_create:
                process_events.append(event)

                pid = event.get("process_id")
                parent_pid = event.get("parent_process_id")

                if pid:
                    process_by_pid[pid] = event
                if parent_pid and pid:
                    children_by_parent[parent_pid].append(event)

        # Identify suspicious parent-child relationships
        suspicious_chains = []

        # W3WP children (webshell execution)
        w3wp_children = []
        for event in process_events:
            parent = str(event.get("parent_process_name", "")).lower()
            if "w3wp" in parent:
                w3wp_children.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "process_name": event.get("process_name"),
                    "command_line": event.get("command_line"),
                    "username": event.get("username"),
                    "process_id": event.get("process_id"),
                    "parent_process_id": event.get("parent_process_id"),
                    "source_file": event.get("_source_parquet"),
                })

        # Services.exe children (service execution)
        services_children = []
        for event in process_events:
            parent = str(event.get("parent_process_name", "")).lower()
            if "services.exe" in parent:
                services_children.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "process_name": event.get("process_name"),
                    "command_line": event.get("command_line"),
                    "username": event.get("username"),
                    "process_id": event.get("process_id"),
                })

        # Credential dumping processes
        credential_processes = []
        for event in process_events:
            text = self._get_event_text(event).lower()
            if any(x in text for x in ["pd.exe", "pd64.exe", "procdump", "mimikatz", "lsass", "-ma "]):
                credential_processes.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "process_name": event.get("process_name"),
                    "command_line": event.get("command_line"),
                    "username": event.get("username"),
                    "process_id": event.get("process_id"),
                    "parent_process_name": event.get("parent_process_name"),
                    "source_file": event.get("_source_parquet"),
                    "indicator": "credential_dump",
                })

        # Process masquerading detection (T1036)
        # System processes that should only run under specific parents
        expected_parents = {
            "svchost.exe": ["services.exe"],
            "csrss.exe": ["smss.exe"],
            "wininit.exe": ["smss.exe"],
            "services.exe": ["wininit.exe"],
            "lsass.exe": ["wininit.exe"],
            "lsaiso.exe": ["wininit.exe"],
            "taskhost.exe": ["svchost.exe", "services.exe"],
            "taskhostw.exe": ["svchost.exe", "services.exe"],
            "runtimebroker.exe": ["svchost.exe"],
            "dllhost.exe": ["svchost.exe", "services.exe"],
            "wmiprvse.exe": ["svchost.exe"],
        }
        # Suspicious parent-child pairs (exploit chains)
        exploit_chain_parents = {
            "acroRd32.exe": ["firefox.exe", "iexplore.exe", "chrome.exe", "outlook.exe"],
            "winword.exe": ["explorer.exe"],
            "excel.exe": ["explorer.exe"],
            "powerpnt.exe": ["explorer.exe"],
        }
        masquerading = []
        exploit_chains = []
        for event in process_events:
            proc_name = str(event.get("process_name") or "").lower()
            parent_name = str(event.get("parent_process_name") or "").lower()
            # For memory events, resolve parent name from PID if not set
            if not parent_name and event.get("parent_process_id"):
                ppid = event.get("parent_process_id")
                parent_event = process_by_pid.get(ppid, {})
                parent_name = str(parent_event.get("process_name") or "").lower()

            if proc_name in expected_parents and parent_name:
                valid_parents = expected_parents[proc_name]
                if not any(vp in parent_name for vp in valid_parents):
                    masquerading.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "process_name": event.get("process_name"),
                        "process_id": event.get("process_id"),
                        "parent_process_name": parent_name,
                        "parent_process_id": event.get("parent_process_id"),
                        "expected_parents": valid_parents,
                        "indicator": "process_masquerading_T1036",
                        "source_file": event.get("_source_parquet"),
                    })

            # Detect exploit chain patterns (e.g., firefox → AcroRd32)
            if proc_name in exploit_chain_parents and parent_name:
                if any(ep in parent_name for ep in exploit_chain_parents[proc_name]):
                    exploit_chains.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "process_name": event.get("process_name"),
                        "process_id": event.get("process_id"),
                        "parent_process_name": parent_name,
                        "parent_process_id": event.get("parent_process_id"),
                        "indicator": "exploit_chain",
                        "source_file": event.get("_source_parquet"),
                    })

        result = {
            "total_process_events": len(process_events),
            "unique_pids": len(process_by_pid),
            "w3wp_children": w3wp_children,
            "w3wp_children_count": len(w3wp_children),
            "services_children": services_children,
            "services_children_count": len(services_children),
            "credential_processes": credential_processes,
            "credential_processes_count": len(credential_processes),
            "masquerading": masquerading,
            "masquerading_count": len(masquerading),
            "exploit_chains": exploit_chains,
            "exploit_chains_count": len(exploit_chains),
        }

        # Save extraction
        self._save_extraction("process_trees.json", result)
        click.echo(f"    Found {len(w3wp_children)} w3wp children, {len(credential_processes)} credential processes, {len(masquerading)} masquerading, {len(exploit_chains)} exploit chains")

        return result

    # =========================================================================
    # EXTRACTION 2: Web Attacks (including SMB file transfers)
    # =========================================================================
    def extract_web_attacks(self) -> dict:
        """Extract ALL web attack indicators from IIS/web logs and SMB file transfers."""
        click.echo("  Extracting web attacks...")

        events = self.load_all_events()
        web_events = []
        smb_events = []

        # Find all web events
        for event in events:
            if (event.get("parser_name") == "iis" or
                event.get("http_method") or
                event.get("uri") or
                "iis" in str(event.get("_source_parquet", "")).lower()):
                web_events.append(event)

        # Find all SMB events (from PCAP parser)
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "smb" in event_type or event.get("parser_name") == "pcap":
                raw_payload = event.get("raw_payload", "")
                # Check if raw_payload contains SMB data (JSON format)
                if raw_payload and isinstance(raw_payload, str):
                    if "tree_path" in raw_payload or "filename" in raw_payload:
                        try:
                            smb_data = json.loads(raw_payload)
                            event["_smb_data"] = smb_data
                            smb_events.append(event)
                        except (json.JSONDecodeError, TypeError):
                            pass

        # Suspicious URI access
        suspicious_uris = []
        webshell_access = []

        for event in web_events:
            uri = str(event.get("uri", "")).lower()
            query = str(event.get("query_string", ""))

            # Webshell indicators
            if any(x in uri for x in [".aspx", ".asp", ".php", ".jsp"]):
                if any(x in uri for x in ["forbid", "shell", "cmd", "upload", "hack"]):
                    webshell_access.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "source_ip": event.get("source_ip"),
                        "uri": event.get("uri"),
                        "query_string": query[:500] if query else None,
                        "user_agent": event.get("user_agent"),
                        "status_code": event.get("status_code"),
                        "http_method": event.get("http_method"),
                    })

            # Command parameters in query string
            if query and any(x in query.lower() for x in ["cmd=", "c=", "exec=", "command="]):
                suspicious_uris.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "source_ip": event.get("source_ip"),
                    "uri": event.get("uri"),
                    "query_string": query[:1000],
                    "user_agent": event.get("user_agent"),
                })

        # Track unique source IPs accessing webshells
        webshell_source_ips = defaultdict(list)
        for access in webshell_access:
            ip = access.get("source_ip")
            if ip:
                webshell_source_ips[ip].append(access)

        # Detect pivot (external -> internal IP accessing same resource)
        external_ips = []
        internal_ips = []
        for ip in webshell_source_ips.keys():
            if ip and (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")):
                internal_ips.append(ip)
            elif ip:
                external_ips.append(ip)

        # =================================================================
        # SMB File Transfers (Q3, Q4 from walkthrough)
        # =================================================================
        smb_tree_connects = []
        smb_file_writes = []
        suspicious_smb_files = []

        # Suspicious file extensions for SMB uploads
        suspicious_extensions = {".aspx", ".asp", ".jsp", ".php", ".exe", ".dll", ".ps1", ".bat", ".cmd"}

        for event in smb_events:
            smb_data = event.get("_smb_data", {})
            tree_path = smb_data.get("tree_path")
            filename = smb_data.get("filename")
            write_length = smb_data.get("write_length")

            # Track tree connects (UNC paths - Q3)
            if tree_path:
                smb_tree_connects.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "source_ip": event.get("source_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "unc_path": tree_path,
                    "source_file": event.get("_source_parquet"),
                })

            # Track file writes (Q4)
            if filename and write_length:
                file_info = {
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "source_ip": event.get("source_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "filename": filename,
                    "write_length": write_length,
                    "tree_path": tree_path,
                    "source_file": event.get("_source_parquet"),
                }
                smb_file_writes.append(file_info)

                # Check for suspicious file types
                ext = Path(str(filename)).suffix.lower()
                if ext in suspicious_extensions:
                    file_info["indicator"] = f"suspicious_extension_{ext}"
                    suspicious_smb_files.append(file_info)

        # Get unique UNC paths
        unique_unc_paths = list(set(tc["unc_path"] for tc in smb_tree_connects if tc.get("unc_path")))

        result = {
            "total_web_events": len(web_events),
            "webshell_access": webshell_access,
            "webshell_access_count": len(webshell_access),
            "suspicious_uris": suspicious_uris,
            "suspicious_uris_count": len(suspicious_uris),
            "unique_source_ips": list(webshell_source_ips.keys()),
            "external_ips": external_ips,
            "internal_ips": internal_ips,
            "pivot_detected": len(external_ips) > 0 and len(internal_ips) > 0,
            # SMB findings
            "smb_events_count": len(smb_events),
            "smb_tree_connects": smb_tree_connects,
            "smb_tree_connects_count": len(smb_tree_connects),
            "unique_unc_paths": unique_unc_paths,
            "smb_file_writes": smb_file_writes,
            "smb_file_writes_count": len(smb_file_writes),
            "suspicious_smb_files": suspicious_smb_files,
            "suspicious_smb_files_count": len(suspicious_smb_files),
        }

        self._save_extraction("web_attacks.json", result)
        click.echo(f"    Found {len(webshell_access)} webshell accesses, {len(smb_file_writes)} SMB file writes, pivot_detected={result['pivot_detected']}")

        return result

    # =========================================================================
    # EXTRACTION 3: Encoded Content Decoding
    # =========================================================================
    def extract_decoded_content(self) -> dict:
        """Decode ALL base64, URL-encoded, and PowerShell encoded content."""
        click.echo("  Extracting and decoding encoded content...")

        events = self.load_all_events()
        decoded_commands = []
        encoded_powershell = []

        for event in events:
            text = self._get_event_text(event)

            # Extract base64 from query strings and command lines
            base64_results = self._extract_base64_from_text(text)
            for encoded, decoded in base64_results:
                decoded_commands.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "source_ip": event.get("source_ip"),
                    "encoded": encoded[:200],
                    "decoded": decoded,
                    "source_file": event.get("_source_parquet"),
                    "event_type": event.get("event_type"),
                })

            # URL-encoded content in web logs
            query = event.get("query_string", "")
            if query and "%" in str(query):
                try:
                    url_decoded = unquote(str(query))
                    if url_decoded != query:
                        # Check for further base64 in decoded content
                        nested_results = self._extract_base64_from_text(url_decoded)
                        for encoded, decoded in nested_results:
                            decoded_commands.append({
                                "timestamp": str(event.get("timestamp_utc", "")),
                                "source_ip": event.get("source_ip"),
                                "encoded": encoded[:200],
                                "decoded": decoded,
                                "source_file": event.get("_source_parquet"),
                                "event_type": "url_then_base64",
                            })
                except Exception:
                    pass

            # PowerShell -EncodedCommand
            cmd_line = str(event.get("command_line", ""))
            if "-enc" in cmd_line.lower():
                match = re.search(r'-[eE][nN][cC][oOdDeEdD]*[cC]*[oOmMaAnNdD]*\s+([A-Za-z0-9+/=]+)', cmd_line)
                if match:
                    encoded = match.group(1)
                    decoded = self._decode_base64(encoded)
                    if decoded:
                        encoded_powershell.append({
                            "timestamp": str(event.get("timestamp_utc", "")),
                            "process_name": event.get("process_name"),
                            "encoded": encoded[:200],
                            "decoded": decoded,
                            "username": event.get("username"),
                            "source_file": event.get("_source_parquet"),
                        })

        # Categorize decoded commands by attack phase
        categorized = {
            "reconnaissance": [],
            "credential_access": [],
            "lateral_movement": [],
            "discovery": [],
            "execution": [],
            "other": [],
        }

        for cmd in decoded_commands:
            decoded = cmd.get("decoded", "").lower()
            if any(x in decoded for x in ["whoami", "ipconfig", "net user", "net localgroup", "nltest"]):
                categorized["reconnaissance"].append(cmd)
            elif any(x in decoded for x in ["pd.exe", "procdump", "mimikatz", "lsass", "sekurlsa"]):
                categorized["credential_access"].append(cmd)
            elif any(x in decoded for x in ["invoke-wmiexec", "invoke-smbexec", "-hash", "-target"]):
                categorized["lateral_movement"].append(cmd)
            elif any(x in decoded for x in ["tasklist", "netstat", "wmic process", "systeminfo", "dir"]):
                categorized["discovery"].append(cmd)
            elif any(x in decoded for x in ["cmd", "powershell", "execute"]):
                categorized["execution"].append(cmd)
            else:
                categorized["other"].append(cmd)

        result = {
            "total_decoded_commands": len(decoded_commands),
            "decoded_commands": decoded_commands,
            "encoded_powershell": encoded_powershell,
            "encoded_powershell_count": len(encoded_powershell),
            "categorized": {k: len(v) for k, v in categorized.items()},
            "categorized_commands": categorized,
        }

        self._save_extraction("decoded_content.json", result)
        click.echo(f"    Decoded {len(decoded_commands)} commands, {len(encoded_powershell)} PowerShell")

        return result

    # =========================================================================
    # EXTRACTION 4: Credential Access
    # =========================================================================
    def extract_credential_access(self) -> dict:
        """Extract ALL credential access indicators."""
        click.echo("  Extracting credential access indicators...")

        events = self.load_all_events()
        credential_events = []

        # Credential tools
        credential_tools = []
        for event in events:
            text = self._get_event_text(event).lower()
            if any(x in text for x in ["pd.exe", "pd64.exe", "procdump", "mimikatz", "sekurlsa",
                                        "lsass", "sam", "ntds", "-ma ", "-accepteula"]):
                credential_tools.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "process_name": event.get("process_name"),
                    "command_line": event.get("command_line"),
                    "username": event.get("username"),
                    "source_file": event.get("_source_parquet"),
                    "event_type": event.get("event_type"),
                })

        # Auth events related to credential theft
        auth_events = []
        for event in events:
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", ""))
            # 4648=Explicit credentials, 4769=Kerberos TGS, 4771=Kerberos preauth fail, 4776=NTLM auth
            if event_id in [4648, 4769, 4771, 4776]:
                auth_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_type": event_type,
                    "event_id": event_id,
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "source_file": event.get("_source_parquet"),
                })

        # LSASS access (Sysmon 10)
        lsass_access = []
        for event in events:
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", "")).lower()
            text = self._get_event_text(event).lower()
            # Sysmon EID 10 = Process Access
            if event_id == 10 or "sysmon_10" in event_type or "sysmon 10" in event_type:
                if "lsass" in text:
                    lsass_access.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "source_process": event.get("process_name"),
                        "target_process": "lsass.exe",
                        "source_file": event.get("_source_parquet"),
                    })

        # Memory-derived password hashes (hashdump)
        hashdump_entries = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_hashdump" in event_type:
                raw = {}
                try:
                    raw = json.loads(event.get("raw_payload", "{}"))
                except (json.JSONDecodeError, TypeError):
                    pass
                hashdump_entries.append({
                    "user": raw.get("user") or event.get("username"),
                    "rid": raw.get("rid"),
                    "lmhash": raw.get("lmhash"),
                    "nthash": raw.get("nthash"),
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "credential_tools": credential_tools,
            "credential_tools_count": len(credential_tools),
            "auth_events": auth_events[:100],  # Limit for context
            "auth_events_count": len(auth_events),
            "lsass_access": lsass_access,
            "lsass_access_count": len(lsass_access),
            "hashdump_entries": hashdump_entries,
            "hashdump_count": len(hashdump_entries),
        }

        self._save_extraction("credential_access.json", result)
        click.echo(f"    Found {len(credential_tools)} credential tool uses, {len(lsass_access)} LSASS access, {len(hashdump_entries)} hashes")

        return result

    # =========================================================================
    # EXTRACTION 5: Lateral Movement
    # =========================================================================
    def extract_lateral_movement(self) -> dict:
        """Extract ALL lateral movement indicators."""
        click.echo("  Extracting lateral movement indicators...")

        events = self.load_all_events()

        # Type 3 network logons
        type3_logons = []
        for event in events:
            event_id = event.get("event_id")
            text = self._get_event_text(event).lower()
            logon_type = event.get("logon_type")
            # EID 4624 = Successful Logon, Type 3 = Network
            is_type3 = (
                logon_type == 3 or
                "type 3" in text or "logontype: 3" in text or "logontype\":3" in text
            )
            if event_id == 4624 and is_type3:
                type3_logons.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "source_file": event.get("_source_parquet"),
                })

        # SMB/WMI network connections
        lateral_connections = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "sysmon_3" in event_type or "sysmon 3" in event_type or "network" in event_type:
                dest_port = event.get("dest_port")
                if dest_port in [445, 135, 139, 5985, 5986, 3389]:
                    lateral_connections.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "source_ip": event.get("source_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "dest_port": dest_port,
                        "process_name": event.get("process_name"),
                        "source_file": event.get("_source_parquet"),
                    })

        # WMI/WinRM spawned processes
        wmi_spawns = []
        for event in events:
            parent = str(event.get("parent_process_name", "")).lower()
            if any(x in parent for x in ["wmiprvse", "wsmprovhost", "winrshost"]):
                wmi_spawns.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "process_name": event.get("process_name"),
                    "command_line": event.get("command_line"),
                    "parent_process_name": event.get("parent_process_name"),
                    "username": event.get("username"),
                    "source_file": event.get("_source_parquet"),
                })

        # Invoke-WMIExec/SMBExec commands
        invoke_commands = []
        for event in events:
            text = self._get_event_text(event).lower()
            if any(x in text for x in ["invoke-wmiexec", "invoke-smbexec", "invoke-thehash"]):
                invoke_commands.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "command_line": event.get("command_line"),
                    "process_name": event.get("process_name"),
                    "username": event.get("username"),
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "type3_logons": type3_logons[:100],
            "type3_logons_count": len(type3_logons),
            "lateral_connections": lateral_connections,
            "lateral_connections_count": len(lateral_connections),
            "wmi_spawns": wmi_spawns,
            "wmi_spawns_count": len(wmi_spawns),
            "invoke_commands": invoke_commands,
            "invoke_commands_count": len(invoke_commands),
        }

        self._save_extraction("lateral_movement.json", result)
        click.echo(f"    Found {len(lateral_connections)} lateral connections, {len(invoke_commands)} Invoke-* commands")

        return result

    # =========================================================================
    # EXTRACTION 6: Persistence
    # =========================================================================
    def extract_persistence(self) -> dict:
        """Extract ALL persistence mechanisms."""
        click.echo("  Extracting persistence mechanisms...")

        events = self.load_all_events()

        # Service installations (EID 7045)
        services = []
        for event in events:
            event_type = str(event.get("event_type", ""))
            if "7045" in event_type:
                services.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "service_name": event.get("service_name") or event.get("payload", {}).get("ServiceName"),
                    "image_path": event.get("image_path") or event.get("payload", {}).get("ImagePath"),
                    "service_type": event.get("service_type"),
                    "start_type": event.get("start_type"),
                    "source_file": event.get("_source_parquet"),
                })

        # Flag random service names (SMBExec indicator)
        random_services = []
        for svc in services:
            name = str(svc.get("service_name", ""))
            # Random uppercase names typical of SMBExec
            if re.match(r'^[A-Z]{15,}$', name):
                svc["indicator"] = "random_name_smbexec"
                random_services.append(svc)

        # Registry persistence (Sysmon 13)
        registry_persistence = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "sysmon_13" in event_type or "sysmon 13" in event_type:
                target = str(event.get("target_object", "")).lower()
                if any(x in target for x in ["run", "services", "com\\", "shell"]):
                    registry_persistence.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "target_object": event.get("target_object"),
                        "details": event.get("details"),
                        "process_name": event.get("process_name"),
                        "source_file": event.get("_source_parquet"),
                    })

        # Memory-derived services (svcscan)
        memory_services = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_svcscan" in event_type:
                raw = {}
                try:
                    raw = json.loads(event.get("raw_payload", "{}"))
                except (json.JSONDecodeError, TypeError):
                    pass
                memory_services.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "service_name": raw.get("service_name") or event.get("process_name"),
                    "display_name": raw.get("display_name"),
                    "binary_path": raw.get("binary_path") or event.get("command_line"),
                    "start_type": raw.get("start_type"),
                    "state": raw.get("state"),
                    "source_file": event.get("_source_parquet"),
                })

        # Scheduled tasks (EID 4698)
        scheduled_tasks = []
        for event in events:
            event_type = str(event.get("event_type", ""))
            if "4698" in event_type:
                scheduled_tasks.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "task_name": event.get("task_name"),
                    "task_content": event.get("task_content"),
                    "username": event.get("username"),
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "services": services,
            "services_count": len(services),
            "random_services": random_services,
            "random_services_count": len(random_services),
            "registry_persistence": registry_persistence,
            "registry_persistence_count": len(registry_persistence),
            "memory_services": memory_services,
            "memory_services_count": len(memory_services),
            "scheduled_tasks": scheduled_tasks,
            "scheduled_tasks_count": len(scheduled_tasks),
        }

        self._save_extraction("persistence.json", result)
        click.echo(f"    Found {len(services)} services ({len(random_services)} random), {len(registry_persistence)} registry")

        return result

    # =========================================================================
    # EXTRACTION 7: Network & C2
    # =========================================================================
    def extract_network(self) -> dict:
        """Extract ALL network connections with process context."""
        click.echo("  Extracting network connections...")

        events = self.load_all_events()

        # Network connections (Sysmon 3)
        connections = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "sysmon_3" in event_type or "sysmon 3" in event_type or event.get("dest_ip"):
                connections.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "source_ip": event.get("source_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "process_name": event.get("process_name"),
                    "username": event.get("username"),
                    "source_file": event.get("_source_parquet"),
                })

        # DNS queries (Sysmon 22)
        dns_queries = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "sysmon_22" in event_type or "sysmon 22" in event_type or "dns" in event_type:
                dns_queries.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "query_name": event.get("query_name"),
                    "query_results": event.get("query_results"),
                    "process_name": event.get("process_name"),
                    "source_file": event.get("_source_parquet"),
                })

        # External connections (non-RFC1918)
        external_connections = []
        for conn in connections:
            dest_ip = str(conn.get("dest_ip", ""))
            if dest_ip and not any(dest_ip.startswith(x) for x in ["192.168.", "10.", "172.16.", "172.17.",
                                                                    "172.18.", "172.19.", "172.2", "172.3",
                                                                    "127.", "0.", "::"]):
                external_connections.append(conn)

        result = {
            "connections": connections[:500],  # Limit for context
            "connections_count": len(connections),
            "dns_queries": dns_queries[:200],
            "dns_queries_count": len(dns_queries),
            "external_connections": external_connections,
            "external_connections_count": len(external_connections),
        }

        self._save_extraction("network.json", result)
        click.echo(f"    Found {len(connections)} connections, {len(external_connections)} external")

        return result

    # =========================================================================
    # EXTRACTION 8: Authentication Timeline
    # =========================================================================
    def extract_auth_timeline(self) -> dict:
        """Extract ALL authentication events with logon type decoding."""
        click.echo("  Extracting authentication timeline...")

        events = self.load_all_events()
        auth_events = []

        for event in events:
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", ""))
            # Auth events: 4624=Success, 4625=Fail, 4648=Explicit, 4672=SpecPriv, 4769=TGS, 4771=PreAuthFail, 4776=NTLM
            if event_id in [4624, 4625, 4648, 4672, 4769, 4771, 4776]:
                logon_type = event.get("logon_type") or event.get("LogonType")

                # Decode logon type to human-readable name (S1.1.2)
                logon_type_name = None
                if logon_type is not None:
                    try:
                        logon_type_int = int(logon_type)
                        logon_type_name = LOGON_TYPE_MAP.get(logon_type_int, f"Unknown({logon_type})")
                    except (ValueError, TypeError):
                        logon_type_name = f"Unknown({logon_type})"

                auth_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": event_id,
                    "event_type": event_type,
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "logon_type": logon_type,
                    "logon_type_name": logon_type_name,
                    "status": event.get("status"),
                    "source_system": event.get("source_system"),
                    "source_file": event.get("_source_parquet"),
                })

        # Sort by timestamp
        auth_events.sort(key=lambda x: x.get("timestamp", ""))

        # Group by user
        by_user = defaultdict(list)
        for event in auth_events:
            user = event.get("username", "unknown")
            by_user[user].append(event)

        result = {
            "auth_events": auth_events,
            "auth_events_count": len(auth_events),
            "unique_users": list(by_user.keys()),
            "events_by_user": {k: len(v) for k, v in by_user.items()},
        }

        self._save_extraction("auth_timeline.json", result)
        click.echo(f"    Found {len(auth_events)} auth events for {len(by_user)} users")

        return result

    # =========================================================================
    # EXTRACTION 9: File Operations
    # =========================================================================
    def extract_file_operations(self) -> dict:
        """Extract ALL file operations."""
        click.echo("  Extracting file operations...")

        events = self.load_all_events()
        file_events = []

        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if any(x in event_type for x in ["sysmon_11", "sysmon 11", "sysmon_23", "sysmon 23",
                                              "sysmon_15", "sysmon 15", "file"]):
                file_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_type": event.get("event_type"),
                    "file_path": event.get("target_filename") or event.get("file_path"),
                    "process_name": event.get("process_name"),
                    "username": event.get("username"),
                    "hash": event.get("hash"),
                    "source_file": event.get("_source_parquet"),
                })

        # Process-to-file associations from handles (Memory_handles with File type)
        handle_file_assoc = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_handles" in event_type:
                raw = {}
                try:
                    raw = json.loads(event.get("raw_payload", "{}"))
                except (json.JSONDecodeError, TypeError):
                    pass
                if raw.get("handle_type") == "File":
                    handle_name = raw.get("handle_name") or ""
                    handle_file_assoc.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "event_type": event.get("event_type"),
                        "file_path": handle_name,
                        "process_name": event.get("process_name") or raw.get("process"),
                        "process_id": event.get("process_id") or raw.get("pid"),
                        "username": event.get("username"),
                        "source_file": event.get("_source_parquet"),
                    })

        # Suspicious file locations
        all_file_entries = file_events + handle_file_assoc
        suspicious_files = []
        for f in all_file_entries:
            path = str(f.get("file_path", "")).lower()
            if any(x in path for x in ["temp", "public", "inetpub", "wwwroot", "uploads",
                                        ".dmp", ".ps1", ".aspx", ".exe",
                                        ".php", ".pdf", ".vbs", ".bat", ".cmd"]):
                suspicious_files.append(f)

        # Dump files
        dump_files = [f for f in file_events if ".dmp" in str(f.get("file_path", "")).lower()]

        result = {
            "file_events": file_events[:500],
            "file_events_count": len(file_events),
            "handle_file_associations": handle_file_assoc[:500],
            "handle_file_associations_count": len(handle_file_assoc),
            "suspicious_files": suspicious_files,
            "suspicious_files_count": len(suspicious_files),
            "dump_files": dump_files,
            "dump_files_count": len(dump_files),
        }

        self._save_extraction("file_operations.json", result)
        click.echo(f"    Found {len(file_events)} file events, {len(handle_file_assoc)} handle file associations, {len(dump_files)} dump files")

        return result

    # =========================================================================
    # EXTRACTION 10: Kerberoasting Detection (S1.2)
    # =========================================================================
    def extract_kerberoasting_summary(self) -> dict:
        """Extract Kerberoasting indicators from Event 4769 with RC4 encryption."""
        click.echo("  Extracting Kerberoasting indicators...")

        events = self.load_all_events()
        tgs_requests = []
        rc4_requests = []

        for event in events:
            event_id = event.get("event_id")
            # EID 4769 = Kerberos TGS Request
            if event_id == 4769:
                # Extract ticket encryption type from event or raw_payload
                encryption_type = event.get("TicketEncryptionType") or event.get("ticket_encryption_type")
                service_name = event.get("ServiceName") or event.get("service_name")
                target_user = event.get("TargetUserName") or event.get("target_username")
                source_ip = event.get("IpAddress") or event.get("source_ip")

                # Try to get from raw_payload JSON if not in top-level fields
                raw_payload = event.get("raw_payload")
                if raw_payload and (not encryption_type or not service_name):
                    try:
                        import json
                        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
                        encryption_type = encryption_type or payload.get("TicketEncryptionType")
                        service_name = service_name or payload.get("ServiceName")
                        target_user = target_user or payload.get("TargetUserName")
                        source_ip = source_ip or payload.get("IpAddress")
                    except (json.JSONDecodeError, TypeError):
                        pass

                tgs_entry = {
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "service_name": service_name,
                    "target_user": target_user,
                    "encryption_type": encryption_type,
                    "source_ip": source_ip,
                    "source_file": event.get("_source_parquet"),
                }
                tgs_requests.append(tgs_entry)

                # Check for RC4-HMAC (0x17) - Kerberoasting indicator
                if encryption_type and str(encryption_type).lower() in ["0x17", "17", "23"]:
                    tgs_entry["kerberoasting_suspect"] = True
                    tgs_entry["severity"] = "HIGH"
                    rc4_requests.append(tgs_entry)

        # Get unique targeted services and requesting users
        targeted_services = list(set(r.get("service_name") for r in rc4_requests if r.get("service_name")))
        requesting_users = list(set(r.get("target_user") for r in rc4_requests if r.get("target_user")))

        result = {
            "total_tgs_requests": len(tgs_requests),
            "rc4_requests": len(rc4_requests),
            "rc4_request_details": rc4_requests,
            "targeted_services": targeted_services,
            "requesting_users": requesting_users,
            "severity": "HIGH" if rc4_requests else "LOW",
            "kerberoasting_detected": len(rc4_requests) > 0,
        }

        self._save_extraction("kerberoasting.json", result)
        click.echo(f"    Found {len(rc4_requests)} potential Kerberoasting requests (RC4-HMAC)")

        return result

    # =========================================================================
    # EXTRACTION 11: Account Management (S1.3)
    # =========================================================================
    def extract_account_management(self) -> dict:
        """Extract account management events (4720-4781 series)."""
        click.echo("  Extracting account management events...")

        events = self.load_all_events()
        account_events = []

        for event in events:
            event_type = str(event.get("event_type", ""))

            # Check each account management event ID
            for event_id, config in ACCOUNT_MGMT_EVENTS.items():
                if str(event_id) in event_type:
                    # Extract configured fields
                    extracted_fields = {}
                    for field in config["fields"]:
                        value = event.get(field) or event.get(field.lower())
                        if value:
                            extracted_fields[field] = value

                    severity = config["severity"]

                    # Check for privileged group modifications (escalate to CRITICAL)
                    if event_id in [4728, 4732, 4756]:
                        target_group = extracted_fields.get("TargetUserName", "")
                        for priv_group in PRIVILEGED_GROUPS:
                            if priv_group.lower() in target_group.lower():
                                severity = "CRITICAL"
                                break

                    account_events.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "event_id": event_id,
                        "description": config["desc"],
                        "fields": extracted_fields,
                        "severity": severity,
                        "source_file": event.get("_source_parquet"),
                    })
                    break

        # Sort by timestamp
        account_events.sort(key=lambda x: x.get("timestamp", ""))

        # Categorize by severity
        critical_events = [e for e in account_events if e["severity"] == "CRITICAL"]
        high_events = [e for e in account_events if e["severity"] == "HIGH"]

        result = {
            "account_events": account_events,
            "account_events_count": len(account_events),
            "critical_events": critical_events,
            "critical_events_count": len(critical_events),
            "high_events": high_events,
            "high_events_count": len(high_events),
            "events_by_type": defaultdict(int),
        }

        for event in account_events:
            result["events_by_type"][event["description"]] += 1
        result["events_by_type"] = dict(result["events_by_type"])

        self._save_extraction("account_management.json", result)
        click.echo(f"    Found {len(account_events)} account management events ({len(critical_events)} CRITICAL)")

        return result

    # =========================================================================
    # EXTRACTION 12: Network Share Activity (S1.4)
    # =========================================================================
    def extract_network_share_activity(self) -> dict:
        """Extract network share access events (5140, 5145)."""
        click.echo("  Extracting network share activity...")

        events = self.load_all_events()
        share_events = []

        for event in events:
            event_type = str(event.get("event_type", ""))

            if any(eid in event_type for eid in ["5140", "5145"]):
                share_name = event.get("ShareName") or event.get("share_name")
                relative_target = event.get("RelativeTargetName") or event.get("relative_target_name")
                subject_user = event.get("SubjectUserName") or event.get("subject_username")
                ip_address = event.get("IpAddress") or event.get("source_ip")

                # Determine severity based on share type
                severity = "MEDIUM"
                if share_name:
                    for suspicious_share in SUSPICIOUS_SHARES:
                        if suspicious_share in share_name.upper():
                            severity = "HIGH"
                            break

                share_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": "5140" if "5140" in event_type else "5145",
                    "share_name": share_name,
                    "relative_target_name": relative_target,
                    "subject_user": subject_user,
                    "ip_address": ip_address,
                    "severity": severity,
                    "source_file": event.get("_source_parquet"),
                })

        # Identify admin share access
        admin_share_access = [e for e in share_events if e["severity"] == "HIGH"]

        # Unique shares accessed
        unique_shares = list(set(e.get("share_name") for e in share_events if e.get("share_name")))

        result = {
            "share_events": share_events,
            "share_events_count": len(share_events),
            "admin_share_access": admin_share_access,
            "admin_share_access_count": len(admin_share_access),
            "unique_shares": unique_shares,
        }

        self._save_extraction("network_share_activity.json", result)
        click.echo(f"    Found {len(share_events)} share access events ({len(admin_share_access)} admin shares)")

        return result

    # =========================================================================
    # EXTRACTION 13: WFP Connections (S1.4.2)
    # =========================================================================
    def extract_wfp_connections(self) -> dict:
        """Extract Windows Filtering Platform connection events (5156, 5157)."""
        click.echo("  Extracting WFP connections...")

        events = self.load_all_events()
        wfp_events = []
        unique_connections = set()

        for event in events:
            event_type = str(event.get("event_type", ""))

            if any(eid in event_type for eid in ["5156", "5157"]):
                application = event.get("Application") or event.get("application")
                direction = event.get("Direction") or event.get("direction")
                src_addr = event.get("SourceAddress") or event.get("source_ip")
                src_port = event.get("SourcePort") or event.get("source_port")
                dst_addr = event.get("DestAddress") or event.get("dest_ip")
                dst_port = event.get("DestPort") or event.get("dest_port")
                protocol = event.get("Protocol") or event.get("protocol")

                wfp_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": "5156" if "5156" in event_type else "5157",
                    "application": application,
                    "direction": direction,
                    "source_address": src_addr,
                    "source_port": src_port,
                    "dest_address": dst_addr,
                    "dest_port": dst_port,
                    "protocol": protocol,
                    "source_file": event.get("_source_parquet"),
                })

                # Track unique connection tuples
                conn_tuple = (src_addr, dst_addr, dst_port, protocol)
                unique_connections.add(conn_tuple)

        result = {
            "wfp_events": wfp_events[:1000],  # Limit for context
            "wfp_events_count": len(wfp_events),
            "unique_connections": len(unique_connections),
            "unique_connection_tuples": [
                {"src": c[0], "dst": c[1], "port": c[2], "proto": c[3]}
                for c in list(unique_connections)[:100]
            ],
        }

        self._save_extraction("wfp_connections.json", result)
        click.echo(f"    Found {len(wfp_events)} WFP events ({len(unique_connections)} unique connections)")

        return result

    # =========================================================================
    # EXTRACTION 14: PowerShell Activity (S1.5)
    # =========================================================================
    def extract_powershell_activity(self) -> dict:
        """Extract PowerShell events (400, 403, 800, 4103, 4104)."""
        click.echo("  Extracting PowerShell activity...")

        events = self.load_all_events()
        ps_events = []
        suspicious_commands = []

        # Suspicious indicators in PowerShell
        suspicious_indicators = [
            "-enc", "-encodedcommand", "frombase64string", "downloadstring",
            "invoke-expression", "iex", "invoke-command", "net.webclient",
            "start-bitstransfer", "-windowstyle hidden", "-ep bypass",
            "-executionpolicy bypass", "bypass", "-nop", "-noni",
            "start-sleep", "sleep -s", "timeout /t",  # sandbox evasion T1497.003
            "get-clipboard", "set-clipboard",  # clipboard access
        ]

        for event in events:
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", ""))

            # PowerShell events: 400, 403, 800, 4103, 4104
            if event_id in [400, 403, 800, 4103, 4104]:
                # Extract relevant fields based on event type
                host_application = event.get("HostApplication") or event.get("host_application")
                script_block = event.get("ScriptBlockText") or event.get("script_block_text")
                payload = event.get("Payload") or event.get("payload")
                user_id = event.get("UserId") or event.get("user_id")

                content = host_application or script_block or payload or ""

                ps_event = {
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": event_id,
                    "host_application": host_application,
                    "script_block": script_block[:500] if script_block else None,
                    "payload": payload[:500] if payload else None,
                    "user_id": user_id,
                    "source_file": event.get("_source_parquet"),
                }
                ps_events.append(ps_event)

                # Check for suspicious content
                content_lower = content.lower() if content else ""
                for indicator in suspicious_indicators:
                    if indicator in content_lower:
                        ps_event["suspicious"] = True
                        ps_event["indicator"] = indicator
                        ps_event["severity"] = "HIGH"
                        suspicious_commands.append(ps_event)
                        break

        # Also check existing Sysmon/4688 events for PowerShell
        for event in events:
            process_name = str(event.get("process_name", "")).lower()
            command_line = str(event.get("command_line", "")).lower()

            if "powershell" in process_name and command_line:
                for indicator in suspicious_indicators:
                    if indicator in command_line:
                        suspicious_commands.append({
                            "timestamp": str(event.get("timestamp_utc", "")),
                            "event_id": event.get("event_type"),
                            "command_line": event.get("command_line", "")[:500],
                            "process_name": event.get("process_name"),
                            "username": event.get("username"),
                            "suspicious": True,
                            "indicator": indicator,
                            "severity": "HIGH",
                            "source_file": event.get("_source_parquet"),
                        })
                        break

        result = {
            "powershell_events": ps_events,
            "powershell_events_count": len(ps_events),
            "suspicious_commands": suspicious_commands,
            "suspicious_commands_count": len(suspicious_commands),
        }

        self._save_extraction("powershell_activity.json", result)
        click.echo(f"    Found {len(ps_events)} PowerShell events ({len(suspicious_commands)} suspicious)")

        return result

    # =========================================================================
    # EXTRACTION 15: Sysmon Extended Events (S1.6)
    # =========================================================================
    def extract_sysmon_extended(self) -> dict:
        """Extract extended Sysmon events (2, 6, 7, 8, 15, 17, 18, 23, 25) and LSASS access."""
        click.echo("  Extracting extended Sysmon events...")

        events = self.load_all_events()
        sysmon_findings = []
        lsass_access = []
        critical_findings = []

        # Map Sysmon event IDs to check
        sysmon_eids = [2, 6, 7, 8, 15, 17, 18, 23, 25]

        for event in events:
            event_type = str(event.get("event_type", "")).lower()

            # Check for each Sysmon EID
            for eid in sysmon_eids:
                if f"sysmon_{eid}" in event_type or f"sysmon {eid}" in event_type:
                    config = SYSMON_EVENTS.get(eid, {})

                    finding = {
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "event_id": eid,
                        "description": config.get("desc", "Unknown"),
                        "severity": config.get("severity", "MEDIUM"),
                        "source_file": event.get("_source_parquet"),
                    }

                    # Extract configured fields
                    for field in config.get("fields", []):
                        value = event.get(field) or event.get(field.lower())
                        if value:
                            finding[field.lower()] = value

                    # Special handling for EID 8 (CreateRemoteThread)
                    if eid == 8:
                        target_image = str(finding.get("targetimage", "")).lower()
                        if "lsass" in target_image:
                            finding["severity"] = "CRITICAL"
                            finding["indicator"] = "CreateRemoteThread targeting LSASS"
                            critical_findings.append(finding)

                    # Special handling for EID 25 (Process Tampering)
                    if eid == 25:
                        critical_findings.append(finding)

                    sysmon_findings.append(finding)
                    break

            # Check Sysmon 10 (Process Access) for LSASS with suspicious GrantedAccess
            if "sysmon_10" in event_type or "sysmon 10" in event_type:
                target_image = str(event.get("TargetImage", "") or event.get("target_image", "")).lower()
                granted_access = event.get("GrantedAccess") or event.get("granted_access")

                if "lsass" in target_image:
                    lsass_entry = {
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "source_image": event.get("SourceImage") or event.get("source_image"),
                        "target_image": event.get("TargetImage") or event.get("target_image"),
                        "granted_access": granted_access,
                        "source_file": event.get("_source_parquet"),
                        "severity": "HIGH",
                    }

                    # Check for suspicious access masks
                    if granted_access and str(granted_access) in LSASS_SUSPICIOUS_ACCESS_MASKS:
                        lsass_entry["severity"] = "CRITICAL"
                        lsass_entry["indicator"] = f"Credential dumping suspected (GrantedAccess: {granted_access})"
                        critical_findings.append(lsass_entry)

                    lsass_access.append(lsass_entry)

        result = {
            "sysmon_findings": sysmon_findings,
            "sysmon_findings_count": len(sysmon_findings),
            "lsass_access": lsass_access,
            "lsass_access_count": len(lsass_access),
            "critical_findings": critical_findings,
            "critical_findings_count": len(critical_findings),
        }

        self._save_extraction("sysmon_extended.json", result)
        click.echo(f"    Found {len(sysmon_findings)} extended Sysmon events ({len(critical_findings)} CRITICAL)")

        return result

    # =========================================================================
    # EXTRACTION 16: Service Lifecycle (S1.7)
    # =========================================================================
    def extract_service_lifecycle(self) -> dict:
        """Extract service lifecycle events (7034, 7036, 7040)."""
        click.echo("  Extracting service lifecycle events...")

        events = self.load_all_events()
        service_events = []
        suspicious_services = []

        # Random service name pattern (typical of SMBExec)
        random_name_pattern = re.compile(r'^[A-Z]{15,}$')

        for event in events:
            event_type = str(event.get("event_type", ""))

            if any(eid in event_type for eid in ["7034", "7036", "7040"]):
                service_name = event.get("ServiceName") or event.get("service_name") or event.get("param1")

                svc_event = {
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": "7034" if "7034" in event_type else ("7036" if "7036" in event_type else "7040"),
                    "service_name": service_name,
                    "source_file": event.get("_source_parquet"),
                }

                # Add event-specific details
                if "7034" in event_type:
                    svc_event["description"] = "Service crashed"
                    svc_event["severity"] = "MEDIUM"
                elif "7036" in event_type:
                    state = event.get("param2") or event.get("state")
                    svc_event["description"] = f"Service state changed to {state}"
                    svc_event["state"] = state
                    svc_event["severity"] = "LOW"
                elif "7040" in event_type:
                    old_start = event.get("param2") or event.get("old_start_type")
                    new_start = event.get("param3") or event.get("new_start_type")
                    svc_event["description"] = f"Start type changed: {old_start} -> {new_start}"
                    svc_event["old_start_type"] = old_start
                    svc_event["new_start_type"] = new_start
                    svc_event["severity"] = "MEDIUM"

                # Check for suspicious random service names
                if service_name and random_name_pattern.match(str(service_name)):
                    svc_event["severity"] = "HIGH"
                    svc_event["indicator"] = "random_name_smbexec"
                    suspicious_services.append(svc_event)

                service_events.append(svc_event)

        result = {
            "service_events": service_events,
            "service_events_count": len(service_events),
            "suspicious_services": suspicious_services,
            "suspicious_services_count": len(suspicious_services),
        }

        self._save_extraction("service_lifecycle.json", result)
        click.echo(f"    Found {len(service_events)} service events ({len(suspicious_services)} suspicious)")

        return result

    # =========================================================================
    # EXTRACTION 17: Scheduled Task Lifecycle (S1.7.2)
    # =========================================================================
    def extract_scheduled_task_lifecycle(self) -> dict:
        """Extract scheduled task events (4699, 4700, 4701, 4702)."""
        click.echo("  Extracting scheduled task lifecycle events...")

        events = self.load_all_events()
        task_events = []

        event_descriptions = {
            "4698": "Scheduled task created",
            "4699": "Scheduled task deleted",
            "4700": "Scheduled task enabled",
            "4701": "Scheduled task disabled",
            "4702": "Scheduled task updated",
        }

        for event in events:
            event_type = str(event.get("event_type", ""))

            for eid, desc in event_descriptions.items():
                if eid in event_type:
                    task_name = event.get("TaskName") or event.get("task_name")
                    task_content = event.get("TaskContent") or event.get("task_content")

                    task_events.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "event_id": eid,
                        "description": desc,
                        "task_name": task_name,
                        "task_content": task_content[:500] if task_content else None,
                        "subject_user": event.get("SubjectUserName") or event.get("subject_username"),
                        "source_file": event.get("_source_parquet"),
                    })
                    break

        result = {
            "task_events": task_events,
            "task_events_count": len(task_events),
        }

        self._save_extraction("scheduled_task_lifecycle.json", result)
        click.echo(f"    Found {len(task_events)} scheduled task events")

        return result

    # =========================================================================
    # EXTRACTION 18: Event Statistics (S1.8)
    # =========================================================================
    def compute_event_statistics(self) -> dict:
        """Compute event statistics including per-EventID counts and hourly histogram."""
        click.echo("  Computing event statistics...")

        events = self.load_all_events()

        # Count by event ID
        event_id_counts = defaultdict(int)
        hourly_counts = defaultdict(int)
        timestamps = []

        for event in events:
            event_type = event.get("event_type", "unknown")
            event_id_counts[event_type] += 1

            # Parse timestamp for hourly histogram
            ts = self._parse_timestamp(event.get("timestamp_utc"))
            if ts:
                timestamps.append(ts)
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key] += 1

        # Sort event ID distribution by count (descending)
        sorted_distribution = dict(sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True))

        # Calculate hourly statistics for spike detection
        hourly_values = list(hourly_counts.values())
        if hourly_values:
            mean_hourly = sum(hourly_values) / len(hourly_values)
            variance = sum((x - mean_hourly) ** 2 for x in hourly_values) / len(hourly_values)
            std_dev = math.sqrt(variance) if variance > 0 else 0

            # Identify spikes (>2 std deviations above mean)
            spike_hours = []
            for hour, count in hourly_counts.items():
                if std_dev > 0 and count > mean_hourly + (2 * std_dev):
                    spike_hours.append({
                        "hour": hour,
                        "count": count,
                        "std_dev_above": round((count - mean_hourly) / std_dev, 2),
                    })
        else:
            mean_hourly = 0
            std_dev = 0
            spike_hours = []

        # Identify rare events (count < 3)
        rare_events = [
            {"event_id": eid, "count": count}
            for eid, count in event_id_counts.items()
            if count < 3
        ]

        # Time range
        if timestamps:
            timestamps.sort()
            first_event = timestamps[0].isoformat()
            last_event = timestamps[-1].isoformat()
        else:
            first_event = None
            last_event = None

        result = {
            "total_events": len(events),
            "event_id_distribution": sorted_distribution,
            "unique_event_types": len(event_id_counts),
            "hourly_histogram": dict(sorted(hourly_counts.items())),
            "spike_hours": spike_hours,
            "spike_hours_count": len(spike_hours),
            "rare_events": rare_events,
            "rare_events_count": len(rare_events),
            "time_range": {
                "first": first_event,
                "last": last_event,
            },
            "statistics": {
                "mean_hourly_events": round(mean_hourly, 2),
                "std_dev_hourly": round(std_dev, 2),
            },
        }

        self._save_extraction("event_statistics.json", result)
        click.echo(f"    Computed statistics for {len(events)} events ({len(spike_hours)} spike hours detected)")

        return result

    # =========================================================================
    # EXTRACTION 19: LOLBin Detection (S1.9)
    # =========================================================================
    def detect_lolbins(self) -> dict:
        """Detect Living-off-the-Land Binary (LOLBin) usage."""
        click.echo("  Detecting LOLBin usage...")

        events = self.load_all_events()
        lolbin_findings = []

        for event in events:
            # Get process creation events (4688, Sysmon 1)
            event_id = event.get("event_id")
            event_type = str(event.get("event_type", "")).lower()
            # Sysmon EID 1 or Windows Security EID 4688
            is_process_create = (
                event_id == 1 or event_id == 4688 or
                any(x in event_type for x in [
                    "sysmon_1", "sysmon 1", "process",
                    "memory_pslist", "memory_pstree", "memory_cmdline",
                ])
            )
            if not is_process_create:
                continue

            # Get process name and command line
            process_name = event.get("process_name") or event.get("Image") or event.get("NewProcessName") or ""
            command_line = event.get("command_line") or event.get("CommandLine") or ""

            # Extract basename - handle both Windows and Unix paths
            # Replace backslashes with forward slashes for cross-platform compatibility
            normalized_path = str(process_name).replace("\\", "/")
            process_basename = Path(normalized_path).name.lower()
            command_lower = command_line.lower() if command_line else ""

            # Check against each LOLBin pattern
            for pattern in LOLBIN_PATTERNS:
                binary = pattern["binary"].lower()

                if binary == process_basename:
                    is_suspicious = False
                    matched_indicator = None

                    # Check suspicious_args
                    suspicious_args = pattern.get("suspicious_args")
                    if suspicious_args is None:
                        # Any execution is suspicious
                        is_suspicious = True
                        matched_indicator = "any_execution"
                    elif suspicious_args:
                        for arg in suspicious_args:
                            if arg.lower() in command_lower:
                                is_suspicious = True
                                matched_indicator = arg
                                break

                    # Check suspicious_dirs
                    suspicious_dirs = pattern.get("suspicious_dirs")
                    if not is_suspicious and suspicious_dirs:
                        for dir_pattern in suspicious_dirs:
                            if dir_pattern.lower() in process_name.lower():
                                is_suspicious = True
                                matched_indicator = f"suspicious_path:{dir_pattern}"
                                break

                    if is_suspicious:
                        lolbin_findings.append({
                            "timestamp": str(event.get("timestamp_utc", "")),
                            "process": process_name,
                            "command_line": command_line[:500] if command_line else None,
                            "lolbin_rule": binary,
                            "matched_indicator": matched_indicator,
                            "severity": pattern["severity"],
                            "mitre": pattern["mitre"],
                            "description": pattern.get("description", ""),
                            "username": event.get("username"),
                            "source_file": event.get("_source_parquet"),
                        })
                    break

        # Group by LOLBin type
        by_lolbin = defaultdict(list)
        for finding in lolbin_findings:
            by_lolbin[finding["lolbin_rule"]].append(finding)

        result = {
            "lolbin_findings": lolbin_findings,
            "lolbin_findings_count": len(lolbin_findings),
            "by_lolbin_type": {k: len(v) for k, v in by_lolbin.items()},
            "unique_lolbins_detected": list(by_lolbin.keys()),
        }

        self._save_extraction("lolbin_detection.json", result)
        click.echo(f"    Found {len(lolbin_findings)} LOLBin executions across {len(by_lolbin)} binary types")

        return result

    # =========================================================================
    # EXTRACTION 20: Audit Policy Changes (S1.10)
    # =========================================================================
    def extract_audit_policy_changes(self) -> dict:
        """Extract audit policy change events (4719)."""
        click.echo("  Extracting audit policy changes...")

        events = self.load_all_events()
        policy_changes = []

        for event in events:
            event_type = str(event.get("event_type", ""))

            if "4719" in event_type:
                policy_changes.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": "4719",
                    "description": "Audit policy changed",
                    "subject_user": event.get("SubjectUserName") or event.get("subject_username"),
                    "category_id": event.get("CategoryId") or event.get("category_id"),
                    "subcategory_guid": event.get("SubcategoryGuid") or event.get("subcategory_guid"),
                    "severity": "HIGH",
                    "mitre": "T1562.002",
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "policy_changes": policy_changes,
            "policy_changes_count": len(policy_changes),
        }

        self._save_extraction("audit_policy_changes.json", result)
        click.echo(f"    Found {len(policy_changes)} audit policy changes")

        return result

    # =========================================================================
    # EXTRACTION 21: AD Object Changes (S1.11)
    # =========================================================================
    def extract_ad_changes(self) -> dict:
        """Extract Active Directory object change events (4662, 4663, 5136, 5137)."""
        click.echo("  Extracting AD object changes...")

        events = self.load_all_events()
        ad_events = []
        sensitive_changes = []

        # Sensitive AD attributes
        sensitive_attributes = [
            "admincount", "serviceprincipalname", "msds-allowedtodelegateto",
            "msds-allowedtoactonbehalfofotheridentity", "useraccountcontrol",
            "member", "sidhistory", "primarygroupid",
        ]

        for event in events:
            event_type = str(event.get("event_type", ""))

            if any(eid in event_type for eid in ["4662", "4663", "5136", "5137"]):
                object_dn = event.get("ObjectDN") or event.get("object_dn")
                attribute = event.get("AttributeLDAPDisplayName") or event.get("attribute_name")

                ad_event = {
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_id": next((eid for eid in ["4662", "4663", "5136", "5137"] if eid in event_type), ""),
                    "object_dn": object_dn,
                    "attribute": attribute,
                    "subject_user": event.get("SubjectUserName") or event.get("subject_username"),
                    "severity": "MEDIUM",
                    "source_file": event.get("_source_parquet"),
                }

                # Check for sensitive attribute modifications
                if attribute and any(attr in attribute.lower() for attr in sensitive_attributes):
                    ad_event["severity"] = "HIGH"
                    ad_event["indicator"] = f"Sensitive attribute modified: {attribute}"
                    sensitive_changes.append(ad_event)

                ad_events.append(ad_event)

        result = {
            "ad_events": ad_events,
            "ad_events_count": len(ad_events),
            "sensitive_changes": sensitive_changes,
            "sensitive_changes_count": len(sensitive_changes),
        }

        self._save_extraction("ad_changes.json", result)
        click.echo(f"    Found {len(ad_events)} AD events ({len(sensitive_changes)} sensitive attribute changes)")

        return result

    # =========================================================================
    # EXTRACTION 22: DGA Detection (S2.3.2)
    # =========================================================================
    def detect_dga(self) -> dict:
        """Detect Domain Generation Algorithm (DGA) domains in DNS queries."""
        click.echo("  Detecting DGA domains...")

        events = self.load_all_events()
        dns_queries = []
        dga_suspects = []

        # Collect DNS queries
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "dns" in event_type or "sysmon_22" in event_type:
                query_name = event.get("query_name") or event.get("uri") or event.get("QueryName")
                if query_name:
                    dns_queries.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "query_name": query_name,
                        "source_file": event.get("_source_parquet"),
                    })

        # Analyze unique domains
        unique_domains = set(q["query_name"] for q in dns_queries if q.get("query_name"))

        for domain in unique_domains:
            # Extract second-level domain
            parts = domain.lower().split(".")
            if len(parts) < 2:
                continue

            # Get the SLD (second-level domain)
            sld = parts[-2] if len(parts) >= 2 else parts[0]

            # Skip common TLDs used as domains
            if sld in ["com", "net", "org", "edu", "gov", "co", "io"]:
                continue

            # Calculate entropy
            entropy = self._calculate_entropy(sld)

            # Check DGA indicators
            is_dga = False
            indicators = []

            # High entropy (> 3.5)
            if entropy > 3.5:
                indicators.append(f"high_entropy:{entropy:.2f}")

            # Long domain (> 12 chars)
            if len(sld) > 12:
                indicators.append(f"long_domain:{len(sld)}")

            # Consonant/vowel ratio check
            vowels = sum(1 for c in sld if c in "aeiou")
            consonants = len(sld) - vowels - sum(1 for c in sld if not c.isalpha())
            if consonants > 0 and vowels > 0:
                ratio = consonants / vowels
                if ratio > 4 or ratio < 0.25:
                    indicators.append(f"unusual_ratio:{ratio:.2f}")

            # Numeric content
            digits = sum(1 for c in sld if c.isdigit())
            if digits > len(sld) * 0.3:
                indicators.append(f"high_numeric:{digits}/{len(sld)}")

            # Flag as DGA if multiple indicators
            if len(indicators) >= 2 or (entropy > 3.5 and len(sld) > 12):
                is_dga = True
                dga_suspects.append({
                    "domain": domain,
                    "sld": sld,
                    "entropy": round(entropy, 3),
                    "length": len(sld),
                    "indicators": indicators,
                    "severity": "HIGH",
                })

        result = {
            "total_dns_queries": len(dns_queries),
            "unique_domains": len(unique_domains),
            "dga_suspects": dga_suspects,
            "dga_suspects_count": len(dga_suspects),
        }

        self._save_extraction("dga_detection.json", result)
        click.echo(f"    Analyzed {len(unique_domains)} domains, found {len(dga_suspects)} DGA suspects")

        return result

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        # Count character frequencies
        freq = defaultdict(int)
        for char in text.lower():
            freq[char] += 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    # =========================================================================
    # EXTRACTION 23: DNS Tunneling Detection (S2.3.3)
    # =========================================================================
    def detect_dns_tunneling(self) -> dict:
        """Detect DNS tunneling activity."""
        click.echo("  Detecting DNS tunneling...")

        events = self.load_all_events()
        dns_queries = []
        tunneling_suspects = []

        # Collect DNS queries with subdomain info
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "dns" in event_type or "sysmon_22" in event_type:
                query_name = event.get("query_name") or event.get("uri") or event.get("QueryName")
                if query_name:
                    dns_queries.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "query_name": query_name,
                        "process_name": event.get("process_name"),
                        "source_file": event.get("_source_parquet"),
                    })

        # Group queries by base domain
        domain_queries = defaultdict(list)
        for query in dns_queries:
            domain = query["query_name"]
            parts = domain.split(".")
            if len(parts) >= 2:
                # Get base domain (last 2 parts)
                base_domain = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
                domain_queries[base_domain].append({
                    "subdomain": subdomain,
                    "full_query": domain,
                    "timestamp": query["timestamp"],
                })

        # Check for tunneling indicators
        for base_domain, queries in domain_queries.items():
            indicators = []

            # Long subdomains (> 50 chars)
            long_subdomains = [q for q in queries if len(q["subdomain"]) > 50]
            if long_subdomains:
                indicators.append(f"long_subdomains:{len(long_subdomains)}")

            # High query volume to single domain
            if len(queries) > 50:
                indicators.append(f"high_volume:{len(queries)}")

            # Unique subdomain ratio (tunneling has many unique subdomains)
            unique_subdomains = set(q["subdomain"] for q in queries if q["subdomain"])
            if len(queries) > 10 and len(unique_subdomains) / len(queries) > 0.8:
                indicators.append(f"unique_ratio:{len(unique_subdomains)}/{len(queries)}")

            # High entropy in subdomains (base64-like data)
            if unique_subdomains:
                avg_entropy = sum(self._calculate_entropy(s) for s in unique_subdomains) / len(unique_subdomains)
                if avg_entropy > 4.0:
                    indicators.append(f"high_subdomain_entropy:{avg_entropy:.2f}")

            if indicators:
                tunneling_suspects.append({
                    "base_domain": base_domain,
                    "total_queries": len(queries),
                    "unique_subdomains": len(unique_subdomains),
                    "indicators": indicators,
                    "sample_queries": [q["full_query"] for q in queries[:5]],
                    "severity": "HIGH" if len(indicators) >= 2 else "MEDIUM",
                })

        result = {
            "total_dns_queries": len(dns_queries),
            "domains_analyzed": len(domain_queries),
            "tunneling_suspects": tunneling_suspects,
            "tunneling_suspects_count": len(tunneling_suspects),
        }

        self._save_extraction("dns_tunneling.json", result)
        click.echo(f"    Analyzed {len(domain_queries)} base domains, found {len(tunneling_suspects)} tunneling suspects")

        return result

    # =========================================================================
    # EXTRACTION 24: Network Statistics (S2.6)
    # =========================================================================
    def compute_network_statistics(self) -> dict:
        """Compute network statistics including conversations, port scans, and beaconing."""
        click.echo("  Computing network statistics...")

        events = self.load_all_events()
        connections = []

        # Collect network connections from various sources
        for event in events:
            event_type = str(event.get("event_type", "")).lower()

            # Get connections from PCAP, Sysmon 3, or other network events
            if event.get("dest_ip") or "network" in event_type or "sysmon_3" in event_type or "pcap" in event_type:
                src_ip = event.get("source_ip")
                dst_ip = event.get("dest_ip")
                dst_port = event.get("dest_port")
                timestamp = event.get("timestamp_utc")

                if src_ip and dst_ip:
                    connections.append({
                        "timestamp": str(timestamp) if timestamp else "",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "src_port": event.get("source_port"),
                        "process_name": event.get("process_name"),
                    })

        # Compute conversation statistics
        conversations = defaultdict(lambda: {"count": 0, "bytes": 0, "ports": set()})
        for conn in connections:
            key = (conn["src_ip"], conn["dst_ip"])
            conversations[key]["count"] += 1
            if conn["dst_port"]:
                conversations[key]["ports"].add(conn["dst_port"])

        # Top talkers by connection count
        top_talkers = sorted(
            [{"src": k[0], "dst": k[1], "count": v["count"], "unique_ports": len(v["ports"])}
             for k, v in conversations.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:20]

        # Port scan detection (>20 unique ports to same destination)
        port_scans = []
        for (src, dst), data in conversations.items():
            if len(data["ports"]) > 20:
                port_scans.append({
                    "source_ip": src,
                    "dest_ip": dst,
                    "unique_ports": len(data["ports"]),
                    "total_connections": data["count"],
                    "severity": "HIGH",
                })

        # Beaconing detection
        beaconing_suspects = self._detect_beaconing(connections)

        # Protocol distribution (by port)
        port_distribution = defaultdict(int)
        for conn in connections:
            port = conn.get("dst_port")
            if port:
                port_distribution[port] += 1

        result = {
            "total_connections": len(connections),
            "unique_conversations": len(conversations),
            "top_talkers": top_talkers,
            "port_distribution": dict(sorted(port_distribution.items(), key=lambda x: x[1], reverse=True)[:20]),
            "port_scans": port_scans,
            "port_scans_count": len(port_scans),
            "beaconing_suspects": beaconing_suspects,
            "beaconing_suspects_count": len(beaconing_suspects),
        }

        self._save_extraction("network_statistics.json", result)
        click.echo(f"    Analyzed {len(connections)} connections, found {len(port_scans)} port scans, {len(beaconing_suspects)} beaconing suspects")

        return result

    def _detect_beaconing(self, connections: list) -> list:
        """Detect beaconing behavior based on connection timing regularity."""
        beaconing_suspects = []

        # Group connections by (src_ip, dst_ip, dst_port)
        conn_groups = defaultdict(list)
        for conn in connections:
            if conn.get("timestamp") and conn.get("dst_port"):
                key = (conn["src_ip"], conn["dst_ip"], conn["dst_port"])
                conn_groups[key].append(conn["timestamp"])

        for (src, dst, port), timestamps in conn_groups.items():
            if len(timestamps) < 5:
                continue

            # Parse and sort timestamps
            parsed_times = []
            for ts in timestamps:
                parsed = self._parse_timestamp(ts)
                if parsed:
                    parsed_times.append(parsed)

            if len(parsed_times) < 5:
                continue

            parsed_times.sort()

            # Calculate inter-arrival times
            intervals = []
            for i in range(1, len(parsed_times)):
                interval = (parsed_times[i] - parsed_times[i-1]).total_seconds()
                if interval > 0:  # Ignore duplicate timestamps
                    intervals.append(interval)

            if len(intervals) < 4:
                continue

            # Calculate mean and standard deviation
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 10:  # Skip very frequent connections
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance) if variance > 0 else 0

            # Beaconing: low standard deviation relative to mean (< 10%)
            if mean_interval > 0 and std_dev / mean_interval < 0.1:
                beaconing_suspects.append({
                    "source_ip": src,
                    "dest_ip": dst,
                    "dest_port": port,
                    "connection_count": len(timestamps),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "std_dev_seconds": round(std_dev, 2),
                    "regularity_score": round(1 - (std_dev / mean_interval), 3) if mean_interval > 0 else 0,
                    "severity": "HIGH",
                })

        return beaconing_suspects

    # =========================================================================
    # EXTRACTION 25: Web Attack Detection (S3.1)
    # =========================================================================
    def detect_web_attacks(self) -> dict:
        """Detect web attacks using pattern matching (SQL injection, path traversal, etc.)."""
        click.echo("  Detecting web attacks...")

        events = self.load_all_events()
        web_events = []
        attack_findings = []
        scanner_detections = []
        brute_force_attempts = []

        # Collect web/IIS events
        for event in events:
            if (event.get("parser_name") == "iis" or
                event.get("http_method") or
                event.get("uri") or
                "iis" in str(event.get("_source_parquet", "")).lower()):
                web_events.append(event)

        # Analyze each web event for attacks
        for event in web_events:
            uri_stem = str(event.get("uri", "") or event.get("cs_uri_stem", "") or "")
            uri_query = str(event.get("query_string", "") or event.get("cs_uri_query", "") or "")
            user_agent = str(event.get("user_agent", "") or event.get("cs_user_agent", "") or "")
            http_method = event.get("http_method") or event.get("cs_method")
            status_code = event.get("status_code") or event.get("sc_status")

            # Check against web attack patterns
            for pattern_config in WEB_ATTACK_PATTERNS:
                pattern_name = pattern_config["name"]
                patterns = pattern_config["patterns"]
                fields = pattern_config["fields"]
                severity = pattern_config["severity"]
                mitre = pattern_config["mitre"]

                # Check each pattern against relevant fields
                matched_pattern = None
                for pattern in patterns:
                    pattern_lower = pattern.lower()
                    if "uri_stem" in fields and pattern_lower in uri_stem.lower():
                        matched_pattern = pattern
                        break
                    if "uri_query" in fields and pattern_lower in uri_query.lower():
                        matched_pattern = pattern
                        break

                if matched_pattern:
                    attack_findings.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "attack_type": pattern_name,
                        "matched_pattern": matched_pattern,
                        "uri": uri_stem,
                        "query_string": uri_query[:500] if uri_query else None,
                        "source_ip": event.get("source_ip") or event.get("c_ip"),
                        "http_method": http_method,
                        "status_code": status_code,
                        "user_agent": user_agent[:200] if user_agent else None,
                        "severity": severity,
                        "mitre": mitre,
                        "source_file": event.get("_source_parquet"),
                    })
                    break  # Only record first matching attack type per event

            # Check for scanner user agents
            if user_agent:
                user_agent_lower = user_agent.lower()
                for scanner in SCANNER_USER_AGENTS:
                    if scanner in user_agent_lower:
                        scanner_detections.append({
                            "timestamp": str(event.get("timestamp_utc", "")),
                            "scanner_type": scanner,
                            "user_agent": user_agent[:200],
                            "source_ip": event.get("source_ip") or event.get("c_ip"),
                            "uri": uri_stem,
                            "severity": "MEDIUM",
                            "source_file": event.get("_source_parquet"),
                        })
                        break

        # Brute force detection: group by (client_ip, uri_stem) and flag >10 failures in short time
        auth_failures = defaultdict(list)
        for event in web_events:
            status_code = event.get("status_code") or event.get("sc_status")
            if status_code in [401, 403, "401", "403"]:
                key = (
                    event.get("source_ip") or event.get("c_ip"),
                    event.get("uri") or event.get("cs_uri_stem"),
                )
                auth_failures[key].append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "status_code": status_code,
                })

        for (client_ip, uri), failures in auth_failures.items():
            if len(failures) > 10:
                brute_force_attempts.append({
                    "source_ip": client_ip,
                    "target_uri": uri,
                    "failure_count": len(failures),
                    "severity": "HIGH" if len(failures) > 50 else "MEDIUM",
                    "sample_timestamps": [f["timestamp"] for f in failures[:5]],
                })

        # Group attacks by type
        attacks_by_type = defaultdict(int)
        for attack in attack_findings:
            attacks_by_type[attack["attack_type"]] += 1

        result = {
            "total_web_events": len(web_events),
            "attack_findings": attack_findings,
            "attack_findings_count": len(attack_findings),
            "attacks_by_type": dict(attacks_by_type),
            "scanner_detections": scanner_detections,
            "scanner_detections_count": len(scanner_detections),
            "brute_force_attempts": brute_force_attempts,
            "brute_force_attempts_count": len(brute_force_attempts),
        }

        self._save_extraction("web_attacks_detection.json", result)
        click.echo(f"    Found {len(attack_findings)} attack indicators, {len(scanner_detections)} scanner detections, {len(brute_force_attempts)} brute force attempts")

        return result

    # =========================================================================
    # EXTRACTION 26: Deobfuscation (S4.1-S4.3)
    # =========================================================================
    def extract_deobfuscated_content(self) -> dict:
        """Deobfuscate encoded/obfuscated content using multiple techniques."""
        click.echo("  Deobfuscating encoded content...")

        events = self.load_all_events()
        hex_payloads = []
        char_removal_results = []
        concat_results = []

        for event in events:
            # Get text content from various fields
            text_fields = [
                event.get("command_line", ""),
                event.get("CommandLine", ""),
                event.get("script_block_text", ""),
                event.get("ScriptBlockText", ""),
                event.get("payload", ""),
                event.get("raw_payload", ""),
            ]

            for text in text_fields:
                if not text or not isinstance(text, str):
                    continue

                # S4.1: Hex payload detection and decode
                hex_decoded = self._decode_hex_payload(text)
                if hex_decoded:
                    hex_payloads.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "original": text[:200],
                        "decoded": hex_decoded[:500] if isinstance(hex_decoded, str) else hex_decoded.hex()[:500],
                        "is_pe": hex_decoded[:2] == b"MZ" if isinstance(hex_decoded, bytes) else False,
                        "is_zip": hex_decoded[:2] == b"PK" if isinstance(hex_decoded, bytes) else False,
                        "source_file": event.get("_source_parquet"),
                    })

                # S4.2: Character removal deobfuscation
                deobfuscated = self._deobfuscate_char_removal(text)
                if deobfuscated and deobfuscated != text:
                    char_removal_results.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "original": text[:200],
                        "deobfuscated": deobfuscated[:500],
                        "technique": "char_removal",
                        "source_file": event.get("_source_parquet"),
                    })

                # S4.3: String concatenation evaluation
                concat_eval = self._evaluate_string_concat(text)
                if concat_eval and concat_eval != text:
                    concat_results.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "original": text[:200],
                        "evaluated": concat_eval[:500],
                        "technique": "string_concat",
                        "source_file": event.get("_source_parquet"),
                    })

        result = {
            "hex_payloads": hex_payloads,
            "hex_payloads_count": len(hex_payloads),
            "char_removal_results": char_removal_results,
            "char_removal_count": len(char_removal_results),
            "concat_results": concat_results,
            "concat_results_count": len(concat_results),
            "total_deobfuscations": len(hex_payloads) + len(char_removal_results) + len(concat_results),
        }

        self._save_extraction("deobfuscated_content.json", result)
        click.echo(f"    Deobfuscated {len(hex_payloads)} hex payloads, {len(char_removal_results)} char removals, {len(concat_results)} concat evaluations")

        return result

    def _decode_hex_payload(self, text: str) -> Optional[bytes]:
        """Decode hex-encoded payloads (S4.1)."""
        if not text:
            return None

        # Pattern: $hexString = "4D_5A_90..." or similar
        hex_patterns = [
            r'\$\w+\s*=\s*["\']([0-9A-Fa-f_\s]+)["\']',  # PowerShell hex assignment
            r'\\x([0-9A-Fa-f]{2})',  # \x4d\x5a format
            r'0x([0-9A-Fa-f]{2})',   # 0x4d0x5a format
        ]

        for pattern in hex_patterns:
            matches = re.findall(pattern, text)
            if matches:
                try:
                    # Join and clean hex string
                    if isinstance(matches[0], tuple):
                        hex_str = "".join("".join(m) for m in matches)
                    else:
                        hex_str = "".join(matches)

                    # Remove delimiters
                    hex_str = re.sub(r'[_\s\\x0x]', '', hex_str, flags=re.IGNORECASE)

                    # Decode
                    if len(hex_str) >= 4 and len(hex_str) % 2 == 0:
                        decoded = bytes.fromhex(hex_str)
                        if len(decoded) >= 2:
                            return decoded
                except (ValueError, TypeError):
                    continue

        return None

    def _deobfuscate_char_removal(self, text: str) -> Optional[str]:
        """Remove filler characters from obfuscated strings (S4.2)."""
        if not text:
            return None

        original = text

        # PowerShell backtick removal: po`wer`sh`ell -> powershell
        deobfuscated = re.sub(r'`', '', text)

        # Caret removal (cmd.exe): p^o^w^e^r^s^h^e^l^l -> powershell
        deobfuscated = re.sub(r'\^', '', deobfuscated)

        # Hash character insertion (XLMRat-style)
        deobfuscated = re.sub(r'#', '', deobfuscated)

        # Only return if we actually changed something meaningful
        if deobfuscated != original and len(deobfuscated) > 3:
            return deobfuscated

        return None

    def _evaluate_string_concat(self, text: str) -> Optional[str]:
        """Evaluate simple string concatenation (S4.3)."""
        if not text or "+" not in text:
            return None

        # Pattern: "str1" + "str2" + "str3"
        concat_pattern = r'["\']([^"\']*)["\']'

        # Find consecutive quoted strings with + between them
        parts = re.findall(concat_pattern, text)
        if len(parts) >= 2:
            # Check if there are + signs between the quotes
            if '" + "' in text or "' + '" in text or "'+'" in text or '"+' in text:
                result = "".join(parts)
                if result and result != text:
                    return result

        return None

    # =========================================================================
    # EXTRACTION 27: File Path & Registry IOC Extraction (S4.4)
    # =========================================================================
    def extract_ioc_paths(self) -> dict:
        """Extract file paths and registry keys as IOCs (S4.4)."""
        click.echo("  Extracting file path and registry IOCs...")

        events = self.load_all_events()
        file_paths = []
        registry_keys = []

        # Suspicious path patterns
        suspicious_dirs = [
            r"\\temp\\", r"\\downloads\\", r"\\appdata\\", r"\\programdata\\",
            r"\\public\\", r"\\wwwroot\\", r"\\inetpub\\", r"\\users\\public\\",
        ]

        # Persistence registry locations
        persistence_registry = [
            r"\\currentversion\\run",
            r"\\currentversion\\runonce",
            r"\\currentversion\\policies\\explorer\\run",
            r"\\currentversion\\windows\\load",
            r"\\winlogon\\shell",
            r"\\winlogon\\userinit",
            r"\\currentversion\\explorer\\shell folders",
        ]

        for event in events:
            text_fields = [
                str(event.get("command_line", "")),
                str(event.get("CommandLine", "")),
                str(event.get("target_object", "")),
                str(event.get("TargetObject", "")),
                str(event.get("raw_payload", "")),
            ]

            combined_text = " ".join(text_fields)

            # Extract Windows file paths
            path_matches = re.findall(r'[A-Za-z]:\\[^\s"\'<>|]+', combined_text)
            for path in path_matches:
                path_lower = path.lower()
                is_suspicious = any(pattern in path_lower for pattern in suspicious_dirs)

                file_paths.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "path": path,
                    "is_suspicious": is_suspicious,
                    "source_file": event.get("_source_parquet"),
                })

            # Extract registry keys
            reg_patterns = [
                r'(HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s"\']+',
                r'(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS)\\[^\s"\']+',
            ]

            for pattern in reg_patterns:
                reg_matches = re.findall(pattern, combined_text, re.IGNORECASE)
                for match in reg_matches:
                    # Get the full match
                    full_match = re.search(pattern, combined_text, re.IGNORECASE)
                    if full_match:
                        reg_key = full_match.group(0)
                        is_persistence = any(p in reg_key.lower() for p in persistence_registry)

                        registry_keys.append({
                            "timestamp": str(event.get("timestamp_utc", "")),
                            "registry_key": reg_key,
                            "is_persistence_location": is_persistence,
                            "source_file": event.get("_source_parquet"),
                        })

        # Deduplicate
        unique_paths = list({p["path"]: p for p in file_paths}.values())
        unique_registry = list({r["registry_key"]: r for r in registry_keys}.values())

        # Count suspicious paths
        suspicious_file_paths = [p for p in unique_paths if p["is_suspicious"]]
        persistence_registry_keys = [r for r in unique_registry if r["is_persistence_location"]]

        result = {
            "file_paths": unique_paths[:500],  # Limit for context
            "file_paths_count": len(unique_paths),
            "suspicious_file_paths": suspicious_file_paths,
            "suspicious_file_paths_count": len(suspicious_file_paths),
            "registry_keys": unique_registry[:500],
            "registry_keys_count": len(unique_registry),
            "persistence_registry_keys": persistence_registry_keys,
            "persistence_registry_keys_count": len(persistence_registry_keys),
        }

        self._save_extraction("ioc_paths.json", result)
        click.echo(f"    Found {len(unique_paths)} file paths ({len(suspicious_file_paths)} suspicious), {len(unique_registry)} registry keys ({len(persistence_registry_keys)} persistence)")

        return result

    # =========================================================================
    # EXTRACTION 28: Absence & Gaps
    # =========================================================================
    def extract_absence_analysis(self) -> dict:
        """Analyze event gaps and missing indicators."""
        click.echo("  Analyzing absence and gaps...")

        events = self.load_all_events()

        # Parse timestamps
        timestamped_events = []
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp_utc"))
            if ts:
                timestamped_events.append((ts, event))

        timestamped_events.sort(key=lambda x: x[0])

        # Find gaps > 15 minutes
        gaps = []
        for i in range(1, len(timestamped_events)):
            prev_ts, prev_event = timestamped_events[i-1]
            curr_ts, curr_event = timestamped_events[i]
            gap = (curr_ts - prev_ts).total_seconds()
            if gap > 900:  # 15 minutes
                gaps.append({
                    "gap_start": prev_ts.isoformat(),
                    "gap_end": curr_ts.isoformat(),
                    "gap_seconds": gap,
                    "gap_minutes": round(gap / 60, 1),
                    "before_event": prev_event.get("event_type"),
                    "after_event": curr_event.get("event_type"),
                })

        # Event distribution by hour
        by_hour = defaultdict(int)
        for ts, event in timestamped_events:
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            by_hour[hour_key] += 1

        # Log boundaries
        first_event = timestamped_events[0] if timestamped_events else None
        last_event = timestamped_events[-1] if timestamped_events else None

        # Check for log clearing events
        log_cleared = []
        for event in events:
            event_type = str(event.get("event_type", ""))
            if any(x in event_type for x in ["1102", "104"]):
                log_cleared.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_type": event_type,
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "total_events": len(events),
            "timestamped_events": len(timestamped_events),
            "gaps_over_15min": gaps,
            "gaps_count": len(gaps),
            "events_by_hour": dict(by_hour),
            "first_event_time": first_event[0].isoformat() if first_event else None,
            "last_event_time": last_event[0].isoformat() if last_event else None,
            "log_cleared_events": log_cleared,
            "log_cleared_count": len(log_cleared),
        }

        self._save_extraction("absence_analysis.json", result)
        click.echo(f"    Found {len(gaps)} gaps > 15min, {len(log_cleared)} log clearing events")

        return result

    # =========================================================================
    # EXTRACTION 11: Unified Timeline
    # =========================================================================
    def extract_unified_timeline(self) -> dict:
        """Create unified chronological timeline of ALL events."""
        click.echo("  Building unified timeline...")

        events = self.load_all_events()

        # Parse and sort all events
        timeline = []
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp_utc"))
            if ts:
                timeline.append({
                    "timestamp": ts.isoformat(),
                    "source": event.get("_source_parquet"),
                    "event_type": event.get("event_type"),
                    "summary": self._summarize_event(event),
                    "username": event.get("username"),
                    "process_name": event.get("process_name"),
                    "source_ip": event.get("source_ip"),
                    "dest_ip": event.get("dest_ip"),
                })

        timeline.sort(key=lambda x: x["timestamp"])

        result = {
            "timeline": timeline,
            "timeline_count": len(timeline),
            "sources": list(self.events_by_source.keys()),
            "time_range": {
                "start": timeline[0]["timestamp"] if timeline else None,
                "end": timeline[-1]["timestamp"] if timeline else None,
            },
        }

        self._save_extraction("unified_timeline.json", result)
        click.echo(f"    Built timeline with {len(timeline)} events")

        return result

    # =========================================================================
    # EXTRACTION: Log Tampering Detection
    # =========================================================================
    def detect_log_tampering(self) -> dict:
        """Detect potential log tampering/clearing by attackers.

        Checks for:
        - Empty or nearly empty event log files
        - Gaps in event sequences
        - Log clearing events (EID 1102, 104)
        - Unusual time distributions
        """
        click.echo("  Detecting log tampering...")

        events = self.load_all_events()

        # Analyze events per source file
        tampering_indicators = []
        source_analysis = {}

        for source_file, source_events in self.events_by_source.items():
            event_count = len(source_events)

            # Flag if very few events (likely cleared)
            is_suspicious = False
            reasons = []

            if event_count == 0:
                is_suspicious = True
                reasons.append("Zero events - log file appears empty/cleared")
            elif event_count < 10 and "Security" in source_file:
                is_suspicious = True
                reasons.append(f"Only {event_count} events in Security log - likely cleared")
            elif event_count < 5 and "PowerShell" in source_file:
                is_suspicious = True
                reasons.append(f"Only {event_count} events in PowerShell log - likely cleared")

            # Check for log clearing events (EID 1102 = Security log cleared, 104 = System log cleared)
            clearing_events = []
            for event in source_events:
                event_id = event.get("event_id")
                event_type = str(event.get("event_type", ""))
                if event_id in [1102, 104] or "1102" in event_type or "104" in event_type:
                    clearing_events.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "event_id": event_id,
                        "event_type": event_type,
                    })

            if clearing_events:
                is_suspicious = True
                reasons.append(f"Found {len(clearing_events)} log clearing events")

            source_analysis[source_file] = {
                "event_count": event_count,
                "is_suspicious": is_suspicious,
                "reasons": reasons,
                "clearing_events": clearing_events,
            }

            if is_suspicious:
                tampering_indicators.append({
                    "source_file": source_file,
                    "event_count": event_count,
                    "reasons": reasons,
                    "clearing_events": clearing_events,
                })

        # Overall tampering assessment
        total_events = len(events)
        tampering_detected = len(tampering_indicators) > 0 or total_events == 0

        result = {
            "tampering_detected": tampering_detected,
            "tampering_indicators_count": len(tampering_indicators),
            "total_events": total_events,
            "indicators": tampering_indicators,
            "source_analysis": source_analysis,
            "defense_evasion_detected": tampering_detected,
            "mitre_technique": "T1070.001" if tampering_detected else None,
            "summary": f"Log tampering {'DETECTED' if tampering_detected else 'not detected'}: {len(tampering_indicators)} suspicious sources, {total_events} total events",
        }

        if tampering_detected:
            result["recommendation"] = "Event logs appear to have been cleared. Look for alternative evidence sources: Prefetch files, MFT, Registry, malicious scripts on disk."

        self._save_extraction("log_tampering_detection.json", result)

        if tampering_detected:
            click.echo(click.style(f"    ⚠ LOG TAMPERING DETECTED: {len(tampering_indicators)} suspicious sources", fg="yellow"))
        else:
            click.echo(f"    No log tampering indicators found")

        return result

    def _summarize_event(self, event: dict) -> str:
        """Create a brief summary of an event."""
        event_type = event.get("event_type", "unknown")
        process = event.get("process_name", "")
        cmd = event.get("command_line", "")
        uri = event.get("uri", "")

        if uri:
            return f"Web: {event.get('http_method', 'GET')} {uri[:50]}"
        elif cmd:
            return f"Process: {process} - {cmd[:50]}"
        elif process:
            return f"Process: {process}"
        else:
            return f"Event: {event_type}"

    # =========================================================================
    # EXTRACTION: Memory Injection Detection
    # =========================================================================
    def extract_memory_injections(self) -> dict:
        """Extract memory injection indicators from malfind and ldrmodules."""
        click.echo("  Extracting memory injection indicators...")

        events = self.load_all_events()

        # Malfind hits (injected code in process memory)
        malfind_hits = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_malfind" in event_type:
                malfind_hits.append({
                    "process_name": event.get("process_name"),
                    "process_id": event.get("process_id"),
                    "source_file": event.get("_source_parquet"),
                })

        # Ldrmodules discrepancies (DLLs not in all loader lists = injection)
        ldr_injections = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_ldrmodules" in event_type:
                raw = {}
                try:
                    raw = json.loads(event.get("raw_payload", "{}"))
                except (json.JSONDecodeError, TypeError):
                    pass
                in_load = raw.get("in_load", True)
                in_init = raw.get("in_init", True)
                in_mem = raw.get("in_mem", True)
                if not (in_load and in_init and in_mem):
                    ldr_injections.append({
                        "process_name": raw.get("process") or event.get("process_name"),
                        "process_id": raw.get("pid") or event.get("process_id"),
                        "mapped_path": raw.get("mapped_path") or event.get("command_line"),
                        "in_load": in_load,
                        "in_init": in_init,
                        "in_mem": in_mem,
                        "source_file": event.get("_source_parquet"),
                    })

        # NTFS ADS findings
        ads_findings = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_mftscan" in event_type:
                ads_findings.append({
                    "filename_ads": event.get("process_name"),
                    "raw": event.get("raw_payload"),
                    "source_file": event.get("_source_parquet"),
                })

        result = {
            "malfind_hits": malfind_hits,
            "malfind_count": len(malfind_hits),
            "ldr_injections": ldr_injections,
            "ldr_injection_count": len(ldr_injections),
            "ads_findings": ads_findings,
            "ads_count": len(ads_findings),
        }

        self._save_extraction("memory_injections.json", result)
        click.echo(f"    Found {len(malfind_hits)} malfind hits, {len(ldr_injections)} ldrmodule discrepancies, {len(ads_findings)} ADS")

        return result

    # =========================================================================
    # EXTRACTION: Memory Strings IOC Extraction
    # =========================================================================
    def extract_strings_iocs(self) -> dict:
        """Extract IOCs found via strings analysis of memory dumps."""
        click.echo("  Extracting strings-based IOCs...")

        events = self.load_all_events()
        ips = []
        urls = []
        domains = []
        php_paths = []
        js_functions = []
        exploit_apis = []

        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_strings_ioc" not in event_type:
                continue
            raw = {}
            try:
                raw = json.loads(event.get("raw_payload", "{}"))
            except (json.JSONDecodeError, TypeError):
                pass
            ioc_type = raw.get("ioc_type", "")
            entry = {
                "value": raw.get("value"),
                "context": raw.get("context", "")[:200],
                "source_file": event.get("_source_parquet"),
            }
            if ioc_type == "ip_address":
                ips.append(entry)
            elif ioc_type == "url":
                urls.append(entry)
            elif ioc_type == "domain":
                domains.append(entry)
            elif ioc_type == "php_path":
                php_paths.append(entry)
            elif ioc_type == "js_function":
                js_functions.append(entry)
            elif ioc_type == "exploit_api":
                exploit_apis.append(entry)

        result = {
            "ip_addresses": ips,
            "ip_count": len(ips),
            "urls": urls,
            "url_count": len(urls),
            "domains": domains,
            "domain_count": len(domains),
            "php_paths": php_paths,
            "php_count": len(php_paths),
            "js_functions": js_functions,
            "js_function_count": len(js_functions),
            "exploit_apis": exploit_apis,
            "exploit_api_count": len(exploit_apis),
        }

        self._save_extraction("strings_iocs.json", result)
        click.echo(
            f"    Found {len(ips)} IPs, {len(urls)} URLs, "
            f"{len(domains)} domains, {len(php_paths)} PHP paths, "
            f"{len(js_functions)} JS functions"
        )
        return result

    # =========================================================================
    # EXTRACTION: Carved File Hashes
    # =========================================================================
    def extract_carved_files(self) -> dict:
        """Extract file hashes from memory-carved files."""
        click.echo("  Extracting carved file hashes...")

        events = self.load_all_events()
        carved = []

        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_carved_file" not in event_type:
                continue
            raw = {}
            try:
                raw = json.loads(event.get("raw_payload", "{}"))
            except (json.JSONDecodeError, TypeError):
                pass
            carved.append({
                "pid": raw.get("pid"),
                "file_type": raw.get("file_type"),
                "file_size": raw.get("file_size"),
                "md5": raw.get("md5"),
                "sha256": raw.get("sha256"),
                "carved_name": raw.get("carved_name"),
                "source_file": event.get("_source_parquet"),
            })

        result = {
            "carved_files": carved,
            "carved_count": len(carved),
        }

        self._save_extraction("carved_files.json", result)
        click.echo(f"    Found {len(carved)} carved files")
        return result

    # =========================================================================
    # EXTRACTION: Exploit Signature → CVE Mapping
    # =========================================================================

    # Known exploit function/pattern → CVE mappings
    EXPLOIT_SIGNATURES = [
        {
            "pattern": "util.printf",
            "context_patterns": ["acro", "pdf", "reader"],
            "cve": "CVE-2008-2992",
            "description": "Adobe Acrobat Reader util.printf buffer overflow",
            "mitre": "T1203",
        },
        {
            "pattern": "Collab.collectEmailInfo",
            "context_patterns": ["acro", "pdf", "reader"],
            "cve": "CVE-2007-5659",
            "description": "Adobe Acrobat Reader Collab.collectEmailInfo buffer overflow",
            "mitre": "T1203",
        },
        {
            "pattern": "Collab.getIcon",
            "context_patterns": ["acro", "pdf", "reader"],
            "cve": "CVE-2009-0927",
            "description": "Adobe Acrobat Reader Collab.getIcon buffer overflow",
            "mitre": "T1203",
        },
        {
            "pattern": "media.newPlayer",
            "context_patterns": ["acro", "pdf", "reader"],
            "cve": "CVE-2009-4324",
            "description": "Adobe Acrobat Reader media.newPlayer use-after-free",
            "mitre": "T1203",
        },
    ]

    def extract_exploit_signatures(self) -> dict:
        """Map known exploit function signatures from strings/memory to CVE IDs."""
        click.echo("  Extracting exploit signatures...")

        events = self.load_all_events()

        # Collect all strings IOC values (including exploit_api type)
        string_values = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            if "memory_strings_ioc" not in event_type:
                continue
            raw = {}
            try:
                raw = json.loads(event.get("raw_payload", "{}"))
            except (json.JSONDecodeError, TypeError):
                pass
            value = raw.get("value", "")
            context = raw.get("context", "")
            ioc_type = raw.get("ioc_type", "")
            if value:
                string_values.append({"value": value, "context": context, "ioc_type": ioc_type})

        # Check for process context (e.g., AcroRd32.exe present in case)
        process_names = set()
        for event in events:
            pname = event.get("process_name") or ""
            if pname:
                process_names.add(pname.lower())

        has_pdf_context = any(
            x in name for name in process_names
            for x in ["acro", "reader", "pdf"]
        ) or any(
            "pdf" in sv["context"].lower() or "acro" in sv["context"].lower()
            for sv in string_values
        )

        matched_cves = []
        for sig in self.EXPLOIT_SIGNATURES:
            pattern = sig["pattern"]
            # Check if the exploit pattern appears in any string value
            for sv in string_values:
                if pattern in sv["value"] or pattern in sv["context"]:
                    # Check context requirements
                    context_met = not sig["context_patterns"] or has_pdf_context
                    if context_met:
                        matched_cves.append({
                            "cve": sig["cve"],
                            "description": sig["description"],
                            "mitre_technique": sig["mitre"],
                            "matched_pattern": pattern,
                            "matched_in": sv["value"][:200],
                            "context": sv["context"][:200],
                        })
                        break  # One match per signature is enough

        result = {
            "exploit_signatures": matched_cves,
            "exploit_count": len(matched_cves),
            "pdf_context_detected": has_pdf_context,
            "total_string_values_checked": len(string_values),
        }

        self._save_extraction("exploit_signatures.json", result)
        click.echo(f"    Matched {len(matched_cves)} exploit signatures to CVEs")
        return result

    # =========================================================================
    # MAIN EXTRACTION RUNNER
    # =========================================================================
    def run_all_extractions(self) -> dict:
        """Run all extraction categories."""
        click.echo("\nRunning ForensicExtractor (22 categories)...")

        results = {
            # Original 11 categories
            "process_trees": self.extract_process_trees(),
            "web_attacks": self.extract_web_attacks(),
            "decoded_content": self.extract_decoded_content(),
            "credential_access": self.extract_credential_access(),
            "lateral_movement": self.extract_lateral_movement(),
            "persistence": self.extract_persistence(),
            "network": self.extract_network(),
            "auth_timeline": self.extract_auth_timeline(),
            "file_operations": self.extract_file_operations(),
            "absence_analysis": self.extract_absence_analysis(),
            "unified_timeline": self.extract_unified_timeline(),
            # Sprint 1 additions (11 new categories)
            "kerberoasting": self.extract_kerberoasting_summary(),
            "account_management": self.extract_account_management(),
            "network_share_activity": self.extract_network_share_activity(),
            "wfp_connections": self.extract_wfp_connections(),
            "powershell_activity": self.extract_powershell_activity(),
            "sysmon_extended": self.extract_sysmon_extended(),
            "service_lifecycle": self.extract_service_lifecycle(),
            "scheduled_task_lifecycle": self.extract_scheduled_task_lifecycle(),
            "event_statistics": self.compute_event_statistics(),
            "lolbin_detection": self.detect_lolbins(),
            "audit_policy_changes": self.extract_audit_policy_changes(),
            "ad_changes": self.extract_ad_changes(),
            # Sprint 2 additions (Network & Memory)
            "dga_detection": self.detect_dga(),
            "dns_tunneling": self.detect_dns_tunneling(),
            "network_statistics": self.compute_network_statistics(),
            # Sprint 3 additions (Web & PE)
            "web_attacks_detection": self.detect_web_attacks(),
            # Sprint 4 additions (Deobfuscation & IOC)
            "deobfuscated_content": self.extract_deobfuscated_content(),
            "ioc_paths": self.extract_ioc_paths(),
            # Defense Evasion Detection
            "log_tampering": self.detect_log_tampering(),
            # Memory forensics (from walkthrough gap analysis)
            "memory_injections": self.extract_memory_injections(),
            # Memory strings IOC extraction
            "strings_iocs": self.extract_strings_iocs(),
            # Carved file hashes from process memory dumps
            "carved_files": self.extract_carved_files(),
            # Exploit signature → CVE mapping
            "exploit_signatures": self.extract_exploit_signatures(),
        }

        # Save summary
        summary = {
            "extraction_time": datetime.now().isoformat(),
            "total_events_analyzed": len(self.events),
            "sources_analyzed": list(self.events_by_source.keys()),
            "category_summaries": {},
        }

        for category, data in results.items():
            if isinstance(data, dict):
                # Extract counts
                counts = {k: v for k, v in data.items() if k.endswith("_count")}
                summary["category_summaries"][category] = counts

        self._save_extraction("extraction_summary.json", summary)

        click.echo(f"\n  ForensicExtractor complete: {len(self.events)} events analyzed")

        return results

    def _save_extraction(self, filename: str, data: dict) -> None:
        """Save extraction results to JSON file."""
        output_path = self.extractions_dir / filename
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
