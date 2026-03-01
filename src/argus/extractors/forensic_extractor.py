"""ForensicExtractor - Phase 3a Programmatic Investigator.

Per SPEC v1.1: This component queries 100% of the dataset.
All decoding, correlation, and process tree building happens here.
LLM agents receive COMPLETE extraction results - NOT samples.

11 Extraction Categories:
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
"""

import base64
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

import click
import pyarrow.parquet as pq


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
            event_type = str(event.get("event_type", "")).lower()
            if any(x in event_type for x in ["sysmon_1", "sysmon 1", "4688", "process"]):
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

        result = {
            "total_process_events": len(process_events),
            "unique_pids": len(process_by_pid),
            "w3wp_children": w3wp_children,
            "w3wp_children_count": len(w3wp_children),
            "services_children": services_children,
            "services_children_count": len(services_children),
            "credential_processes": credential_processes,
            "credential_processes_count": len(credential_processes),
        }

        # Save extraction
        self._save_extraction("process_trees.json", result)
        click.echo(f"    Found {len(w3wp_children)} w3wp children, {len(credential_processes)} credential processes")

        return result

    # =========================================================================
    # EXTRACTION 2: Web Attacks
    # =========================================================================
    def extract_web_attacks(self) -> dict:
        """Extract ALL web attack indicators from IIS/web logs."""
        click.echo("  Extracting web attacks...")

        events = self.load_all_events()
        web_events = []

        # Find all web events
        for event in events:
            if (event.get("parser_name") == "iis" or
                event.get("http_method") or
                event.get("uri") or
                "iis" in str(event.get("_source_parquet", "")).lower()):
                web_events.append(event)

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
        }

        self._save_extraction("web_attacks.json", result)
        click.echo(f"    Found {len(webshell_access)} webshell accesses, pivot_detected={result['pivot_detected']}")

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
            event_type = str(event.get("event_type", ""))
            if any(x in event_type for x in ["4648", "4769", "4771", "4776"]):
                auth_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_type": event_type,
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "source_file": event.get("_source_parquet"),
                })

        # LSASS access (Sysmon 10)
        lsass_access = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            text = self._get_event_text(event).lower()
            if "sysmon_10" in event_type or "sysmon 10" in event_type:
                if "lsass" in text:
                    lsass_access.append({
                        "timestamp": str(event.get("timestamp_utc", "")),
                        "source_process": event.get("process_name"),
                        "target_process": "lsass.exe",
                        "source_file": event.get("_source_parquet"),
                    })

        result = {
            "credential_tools": credential_tools,
            "credential_tools_count": len(credential_tools),
            "auth_events": auth_events[:100],  # Limit for context
            "auth_events_count": len(auth_events),
            "lsass_access": lsass_access,
            "lsass_access_count": len(lsass_access),
        }

        self._save_extraction("credential_access.json", result)
        click.echo(f"    Found {len(credential_tools)} credential tool uses, {len(lsass_access)} LSASS access")

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
            event_type = str(event.get("event_type", ""))
            text = self._get_event_text(event).lower()
            if "4624" in event_type and ("type 3" in text or "logontype: 3" in text or "logontype\":3" in text):
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
        """Extract ALL authentication events."""
        click.echo("  Extracting authentication timeline...")

        events = self.load_all_events()
        auth_events = []

        for event in events:
            event_type = str(event.get("event_type", ""))
            if any(x in event_type for x in ["4624", "4625", "4648", "4672", "4769", "4771", "4776"]):
                auth_events.append({
                    "timestamp": str(event.get("timestamp_utc", "")),
                    "event_type": event_type,
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "logon_type": event.get("logon_type"),
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

        # Suspicious file locations
        suspicious_files = []
        for f in file_events:
            path = str(f.get("file_path", "")).lower()
            if any(x in path for x in ["temp", "public", "inetpub", "wwwroot", "uploads",
                                        ".dmp", ".ps1", ".aspx", ".exe"]):
                suspicious_files.append(f)

        # Dump files
        dump_files = [f for f in file_events if ".dmp" in str(f.get("file_path", "")).lower()]

        result = {
            "file_events": file_events[:500],
            "file_events_count": len(file_events),
            "suspicious_files": suspicious_files,
            "suspicious_files_count": len(suspicious_files),
            "dump_files": dump_files,
            "dump_files_count": len(dump_files),
        }

        self._save_extraction("file_operations.json", result)
        click.echo(f"    Found {len(file_events)} file events, {len(dump_files)} dump files")

        return result

    # =========================================================================
    # EXTRACTION 10: Absence & Gaps
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
    # MAIN EXTRACTION RUNNER
    # =========================================================================
    def run_all_extractions(self) -> dict:
        """Run all 11 extraction categories."""
        click.echo("\nRunning ForensicExtractor (11 categories)...")

        results = {
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
