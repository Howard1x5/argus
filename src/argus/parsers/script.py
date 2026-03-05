"""Script file parser for ARGUS.

Parses PowerShell (.ps1), Batch (.bat, .cmd), VBScript (.vbs), and
JavaScript (.js) files to extract IOCs and malicious patterns.

This parser is critical for cases where event logs have been cleared
but malicious scripts remain on disk.
"""

import base64
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


# Regex patterns for IOC extraction
PATTERNS = {
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    "ipv4_port": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|info|biz|ru|cn|xyz|top|tk|ml|ga|cf|pw|cc|ws|su|onion)\b', re.IGNORECASE),
    "url": re.compile(r'https?://[^\s"\'<>\]\)]+', re.IGNORECASE),
    "file_path_windows": re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
    "file_path_unc": re.compile(r'\\\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+'),
    "base64_chunk": re.compile(r'[A-Za-z0-9+/]{50,}={0,2}'),
    "registry_key": re.compile(r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKCR|HKU)\\[^\s"\']+', re.IGNORECASE),
}

# Suspicious patterns indicating malicious behavior
SUSPICIOUS_PATTERNS = {
    "encoded_command": re.compile(r'-(?:enc(?:oded)?(?:command)?|ec)\s+[A-Za-z0-9+/=]+', re.IGNORECASE),
    "bypass_execution_policy": re.compile(r'-(?:ex(?:ecution)?)?(?:p(?:olicy)?)\s*(?:bypass|unrestricted)', re.IGNORECASE),
    "hidden_window": re.compile(r'-(?:w(?:indow)?(?:style)?)\s*(?:hidden|1)', re.IGNORECASE),
    "no_profile": re.compile(r'-(?:nop(?:rofile)?)', re.IGNORECASE),
    "download_string": re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|wget|curl|iwr|irm|start-bitstransfer)', re.IGNORECASE),
    "invoke_expression": re.compile(r'(?:invoke-expression|iex)\s', re.IGNORECASE),
    "certutil_decode": re.compile(r'certutil.*-decode', re.IGNORECASE),
    "bitsadmin_transfer": re.compile(r'bitsadmin.*(?:/transfer|/download)', re.IGNORECASE),
    "scheduled_task": re.compile(r'schtasks\s*/create', re.IGNORECASE),
    "service_create": re.compile(r'sc\s+(?:create|config)', re.IGNORECASE),
    "wmi_process": re.compile(r'(?:wmic|get-wmiobject).*process.*(?:create|call)', re.IGNORECASE),
    "reflection_assembly": re.compile(r'\[reflection\.assembly\]::load', re.IGNORECASE),
    "mimikatz_patterns": re.compile(r'(?:sekurlsa|kerberos|lsadump|privilege::debug)', re.IGNORECASE),
    "credential_access": re.compile(r'(?:get-credential|convertto-securestring|system\.security\.cryptography)', re.IGNORECASE),
    "disable_defender": re.compile(r'(?:set-mppreference|disable-windowsoptionalfeature|remove-windowsdefender)', re.IGNORECASE),
    "amsi_bypass": re.compile(r'(?:amsiutils|amsiscanbuffer|amsicontext)', re.IGNORECASE),
    "shellcode": re.compile(r'(?:virtualalloc|virtualallocex|writeprocessmemory|createremotethread)', re.IGNORECASE),
    "event_log_clear": re.compile(r'(?:clear-eventlog|wevtutil\s+cl|remove-eventlog)', re.IGNORECASE),
}

# Patterns to extract specific values from commands
EXTRACTION_PATTERNS = {
    # Extract scheduled task name from schtasks /tn "taskname" or /tn taskname
    "scheduled_task_name": re.compile(r'schtasks.*?/tn\s+["\']?([^"\'\s/]+)["\']?', re.IGNORECASE),
    # Extract bitsadmin job name
    "bitsadmin_job": re.compile(r'bitsadmin.*?/transfer\s+(\S+)', re.IGNORECASE),
    # Extract certutil input/output files
    "certutil_files": re.compile(r'certutil.*?-decode\s+(\S+)\s+(\S+)', re.IGNORECASE),
    # Detect RAR files (potential CVE-2023-38831)
    "rar_file": re.compile(r'[\w\s]+\.rar\b', re.IGNORECASE),
    # Detect potential CVE exploitation indicators
    "winrar_exploit": re.compile(r'(?:winrar|rar).*?(?:\.pdf|\.cmd|\.bat)', re.IGNORECASE),
}

# LOLBins - Living Off the Land Binaries
LOLBINS = [
    'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32',
    'certutil', 'bitsadmin', 'msiexec', 'installutil', 'regasm', 'regsvcs',
    'msbuild', 'cmstp', 'wmic', 'forfiles', 'pcalua', 'explorer', 'control',
    'eventvwr', 'dnscmd', 'ftp', 'replace', 'expand', 'extrac32', 'makecab',
    'hh', 'infdefaultinstall', 'ieexec', 'msconfig', 'msdeploy', 'msdt',
    'msiexec', 'odbcconf', 'pcwrun', 'presentationhost', 'rasautou', 'register-cimprovider',
    'rpcping', 'runscripthelper', 'sfc', 'syncappvpublishingserver', 'tttracer',
    'verclsid', 'wab', 'xwizard', 'bash', 'diskshadow', 'dnscmd', 'esentutl',
    'findstr', 'gpscript', 'mavinject', 'msdeploy', 'nltest', 'ntdsutil',
    'print', 'pubprn', 'replace', 'rpcping', 'runscripthelper', 'sc',
    'scriptrunner', 'sfc', 'syncappvpublishingserver', 'tttracer', 'verclsid',
]

# MITRE ATT&CK technique mapping for detected patterns
PATTERN_TO_MITRE = {
    "encoded_command": ("T1059.001", "PowerShell - Encoded Command"),
    "bypass_execution_policy": ("T1059.001", "PowerShell - Execution Policy Bypass"),
    "hidden_window": ("T1564.003", "Hidden Window"),
    "download_string": ("T1105", "Ingress Tool Transfer"),
    "invoke_expression": ("T1059.001", "PowerShell - Invoke-Expression"),
    "certutil_decode": ("T1140", "Deobfuscate/Decode Files or Information"),
    "bitsadmin_transfer": ("T1105", "Ingress Tool Transfer"),
    "scheduled_task": ("T1053.005", "Scheduled Task/Job"),
    "service_create": ("T1543.003", "Windows Service"),
    "wmi_process": ("T1047", "Windows Management Instrumentation"),
    "reflection_assembly": ("T1620", "Reflective Code Loading"),
    "mimikatz_patterns": ("T1003", "OS Credential Dumping"),
    "credential_access": ("T1555", "Credentials from Password Stores"),
    "disable_defender": ("T1562.001", "Impair Defenses - Disable or Modify Tools"),
    "amsi_bypass": ("T1562.001", "Impair Defenses - AMSI Bypass"),
    "shellcode": ("T1055", "Process Injection"),
    "event_log_clear": ("T1070.001", "Indicator Removal - Clear Windows Event Logs"),
}

# LOLBin to MITRE technique mapping
LOLBIN_TO_MITRE = {
    "powershell": ("T1059.001", "PowerShell"),
    "cmd": ("T1059.003", "Windows Command Shell"),
    "wscript": ("T1059.005", "Visual Basic"),
    "cscript": ("T1059.005", "Visual Basic"),
    "mshta": ("T1218.005", "Mshta"),
    "rundll32": ("T1218.011", "Rundll32"),
    "regsvr32": ("T1218.010", "Regsvr32"),
    "certutil": ("T1140", "Deobfuscate/Decode Files"),
    "bitsadmin": ("T1197", "BITS Jobs"),
    "msiexec": ("T1218.007", "Msiexec"),
    "installutil": ("T1218.004", "InstallUtil"),
    "regasm": ("T1218.009", "Regasm/Regsvcs"),
    "regsvcs": ("T1218.009", "Regasm/Regsvcs"),
    "msbuild": ("T1127.001", "MSBuild"),
    "cmstp": ("T1218.003", "CMSTP"),
    "wmic": ("T1047", "Windows Management Instrumentation"),
}

# Pattern to extract Windows usernames from file paths
USER_PATH_PATTERN = re.compile(r'C:\\Users\\([^\\]+)\\', re.IGNORECASE)


class ScriptParser(BaseParser):
    """Parser for malicious script files.

    Extracts IOCs, suspicious patterns, and decoded content from:
    - PowerShell scripts (.ps1)
    - Batch files (.bat, .cmd)
    - VBScript files (.vbs)
    - JavaScript files (.js)
    """

    name = "script"
    description = "Malicious script file analyzer (PS1, BAT, VBS, JS)"
    supported_extensions = [".ps1", ".bat", ".cmd", ".vbs", ".js"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a supported script file."""
        if file_path.suffix.lower() in cls.supported_extensions:
            return True

        # Also check for scripts without extension by reading first bytes
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline(500).lower()
                if any(x in first_line for x in ['powershell', '@echo', 'wscript', 'cscript']):
                    return True
        except Exception:
            pass

        return False

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a script file and extract IOCs and suspicious patterns."""
        result = self._create_result(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            result.add_error(f"Failed to read script file: {e}")
            return result

        # Get file metadata
        file_hash = self._compute_hash(file_path)
        file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)

        # Track unique IOCs to avoid duplicates
        seen_iocs = set()
        line_num = 0

        # Create a main event for the script file itself
        script_event = UnifiedEvent(
            timestamp_utc=file_mtime,
            source_file=str(file_path),
            source_line=0,
            event_type="Script_FileAnalysis",
            severity=EventSeverity.HIGH,
            file_path=str(file_path),
            file_hash=file_hash,
            raw_payload=content[:5000],  # First 5000 chars
            parser_name=self.name,
            description=f"Malicious script file: {file_path.name}",
        )
        result.add_event(script_event)

        # Extract IOCs line by line for context
        for line_num, line in enumerate(content.split('\n'), 1):
            # Extract IPs - include ALL IPs, even private ones
            # In forensic analysis, private IPs can be internal C2, lateral movement targets, etc.
            for match in PATTERNS["ipv4"].finditer(line):
                ip = match.group()
                if ip not in seen_iocs:
                    seen_iocs.add(ip)
                    is_private = self._is_private_ip(ip)
                    event = self._create_ioc_event(
                        file_path, file_mtime, line_num, "Script_IOC_IP",
                        ip, line,
                        EventSeverity.MEDIUM if is_private else EventSeverity.HIGH,
                        file_hash
                    )
                    # Annotate with network type for analyst review
                    event.description = f"IOC extracted: {ip} ({'internal' if is_private else 'external'})"
                    result.add_event(event)

            # Extract URLs
            for match in PATTERNS["url"].finditer(line):
                url = match.group()
                if url not in seen_iocs:
                    seen_iocs.add(url)
                    # Extract IP/domain from URL for dest_ip field
                    dest = self._extract_host_from_url(url)
                    event = self._create_ioc_event(
                        file_path, file_mtime, line_num, "Script_IOC_URL",
                        url, line, EventSeverity.HIGH, file_hash
                    )
                    event.dest_ip = dest
                    result.add_event(event)

            # Extract domains
            for match in PATTERNS["domain"].finditer(line):
                domain = match.group()
                if domain not in seen_iocs:
                    seen_iocs.add(domain)
                    result.add_event(self._create_ioc_event(
                        file_path, file_mtime, line_num, "Script_IOC_Domain",
                        domain, line, EventSeverity.MEDIUM, file_hash
                    ))

            # Extract file paths
            for pattern_name in ["file_path_windows", "file_path_unc"]:
                for match in PATTERNS[pattern_name].finditer(line):
                    path = match.group()
                    if path not in seen_iocs:
                        seen_iocs.add(path)
                        event = self._create_ioc_event(
                            file_path, file_mtime, line_num, "Script_IOC_FilePath",
                            path, line, EventSeverity.MEDIUM, file_hash
                        )
                        event.file_path = path
                        result.add_event(event)

            # Extract registry keys
            for match in PATTERNS["registry_key"].finditer(line):
                reg_key = match.group()
                if reg_key not in seen_iocs:
                    seen_iocs.add(reg_key)
                    event = self._create_ioc_event(
                        file_path, file_mtime, line_num, "Script_IOC_Registry",
                        reg_key, line, EventSeverity.MEDIUM, file_hash
                    )
                    event.registry_key = reg_key
                    result.add_event(event)

        # Extract Windows usernames from file paths (e.g., C:\Users\Administrator\)
        seen_users = set()
        for match in USER_PATH_PATTERN.finditer(content):
            username = match.group(1)
            # Skip generic/system accounts
            if username.lower() not in ['public', 'default', 'all users', 'default user']:
                if username not in seen_users:
                    seen_users.add(username)
                    # Find line for context
                    for line_num, line in enumerate(content.split('\n'), 1):
                        if username in line:
                            break
                    event = UnifiedEvent(
                        timestamp_utc=file_mtime,
                        source_file=str(file_path),
                        source_line=line_num,
                        event_type="Script_User_Account",
                        severity=EventSeverity.HIGH if username.lower() == 'administrator' else EventSeverity.MEDIUM,
                        file_path=str(file_path),
                        file_hash=file_hash,
                        user_name=username,
                        parser_name=self.name,
                        description=f"User account detected in script: {username}",
                    )
                    result.add_event(event)

        # Check for suspicious patterns in full content
        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                # Find line number of first match
                for line_num, line in enumerate(content.split('\n'), 1):
                    if pattern.search(line):
                        break

                # Get MITRE technique if mapped
                mitre_info = PATTERN_TO_MITRE.get(pattern_name)
                mitre_id = mitre_info[0] if mitre_info else None
                mitre_name = mitre_info[1] if mitre_info else None

                description = f"Suspicious pattern detected: {pattern_name}"
                if mitre_id:
                    description += f" [MITRE {mitre_id}: {mitre_name}]"

                event = UnifiedEvent(
                    timestamp_utc=file_mtime,
                    source_file=str(file_path),
                    source_line=line_num,
                    event_type=f"Script_Suspicious_{pattern_name}",
                    severity=EventSeverity.CRITICAL if 'bypass' in pattern_name or 'mimikatz' in pattern_name else EventSeverity.HIGH,
                    file_path=str(file_path),
                    file_hash=file_hash,
                    command_line=matches[0] if isinstance(matches[0], str) else str(matches[0]),
                    raw_payload=content[:2000],
                    parser_name=self.name,
                    description=description,
                    mitre_technique=mitre_id,
                )
                result.add_event(event)

                # Also create a dedicated MITRE event for technique tracking
                if mitre_id:
                    mitre_event = UnifiedEvent(
                        timestamp_utc=file_mtime,
                        source_file=str(file_path),
                        source_line=line_num,
                        event_type="Script_MITRE_Technique",
                        severity=EventSeverity.HIGH,
                        file_path=str(file_path),
                        file_hash=file_hash,
                        mitre_technique=mitre_id,
                        parser_name=self.name,
                        description=f"MITRE ATT&CK: {mitre_id} - {mitre_name}",
                    )
                    result.add_event(mitre_event)

        # Check for LOLBins usage
        content_lower = content.lower()
        for lolbin in LOLBINS:
            if lolbin in content_lower:
                # Find the line
                for line_num, line in enumerate(content.split('\n'), 1):
                    if lolbin in line.lower():
                        # Get MITRE technique if mapped
                        mitre_info = LOLBIN_TO_MITRE.get(lolbin)
                        mitre_id = mitre_info[0] if mitre_info else None
                        mitre_name = mitre_info[1] if mitre_info else None

                        description = f"LOLBin usage detected: {lolbin}"
                        if mitre_id:
                            description += f" [MITRE {mitre_id}: {mitre_name}]"

                        event = UnifiedEvent(
                            timestamp_utc=file_mtime,
                            source_file=str(file_path),
                            source_line=line_num,
                            event_type="Script_LOLBin",
                            severity=EventSeverity.HIGH,
                            file_path=str(file_path),
                            file_hash=file_hash,
                            process_name=lolbin,
                            command_line=line.strip()[:500],
                            raw_payload=line.strip(),
                            parser_name=self.name,
                            description=description,
                            mitre_technique=mitre_id,
                        )
                        result.add_event(event)
                        break

        # Extract specific values from commands using EXTRACTION_PATTERNS
        # Scheduled task names (e.g., whoisthebaba from schtasks /tn "whoisthebaba")
        for match in EXTRACTION_PATTERNS["scheduled_task_name"].finditer(content):
            task_name = match.group(1)
            for line_num, line in enumerate(content.split('\n'), 1):
                if task_name in line:
                    break
            event = UnifiedEvent(
                timestamp_utc=file_mtime,
                source_file=str(file_path),
                source_line=line_num,
                event_type="Script_ScheduledTask",
                severity=EventSeverity.CRITICAL,
                file_path=str(file_path),
                file_hash=file_hash,
                command_line=line.strip()[:500],
                parser_name=self.name,
                description=f"Scheduled task created: {task_name} [MITRE T1053.005: Scheduled Task/Job]",
                mitre_technique="T1053.005",
            )
            result.add_event(event)

        # certutil decode operations (e.g., certutil -decode input.jpg output.zip)
        for match in EXTRACTION_PATTERNS["certutil_files"].finditer(content):
            input_file = match.group(1)
            output_file = match.group(2)
            for line_num, line in enumerate(content.split('\n'), 1):
                if 'certutil' in line.lower() and '-decode' in line.lower():
                    break
            event = UnifiedEvent(
                timestamp_utc=file_mtime,
                source_file=str(file_path),
                source_line=line_num,
                event_type="Script_CertutilDecode",
                severity=EventSeverity.CRITICAL,
                file_path=str(file_path),
                file_hash=file_hash,
                command_line=line.strip()[:500],
                parser_name=self.name,
                description=f"certutil decode: {input_file} -> {output_file} [MITRE T1140: Deobfuscate/Decode Files]",
                mitre_technique="T1140",
            )
            result.add_event(event)

        # RAR file references (potential CVE-2023-38831 indicator)
        for match in EXTRACTION_PATTERNS["rar_file"].finditer(content):
            rar_file = match.group()
            for line_num, line in enumerate(content.split('\n'), 1):
                if rar_file.lower() in line.lower():
                    break
            event = UnifiedEvent(
                timestamp_utc=file_mtime,
                source_file=str(file_path),
                source_line=line_num,
                event_type="Script_RARFile",
                severity=EventSeverity.HIGH,
                file_path=str(file_path),
                file_hash=file_hash,
                raw_payload=line.strip(),
                parser_name=self.name,
                description=f"RAR file reference: {rar_file} (potential CVE-2023-38831 indicator)",
            )
            result.add_event(event)

        # Try to decode obfuscated content using the deobfuscation module
        decoded_content = self._deobfuscate_content(content)
        if decoded_content:
            event = UnifiedEvent(
                timestamp_utc=file_mtime,
                source_file=str(file_path),
                source_line=0,
                event_type="Script_DecodedContent",
                severity=EventSeverity.CRITICAL,
                file_path=str(file_path),
                file_hash=file_hash,
                raw_payload=decoded_content[:5000],
                parser_name=self.name,
                description="Decoded base64/obfuscated content from script",
            )
            result.add_event(event)

            # Re-extract IOCs from decoded content
            for match in PATTERNS["ipv4"].finditer(decoded_content):
                ip = match.group()
                if ip not in seen_iocs and not self._is_private_ip(ip):
                    seen_iocs.add(ip)
                    result.add_event(self._create_ioc_event(
                        file_path, file_mtime, 0, "Script_Decoded_IOC_IP",
                        ip, "Decoded content", EventSeverity.CRITICAL, file_hash
                    ))

            for match in PATTERNS["url"].finditer(decoded_content):
                url = match.group()
                if url not in seen_iocs:
                    seen_iocs.add(url)
                    result.add_event(self._create_ioc_event(
                        file_path, file_mtime, 0, "Script_Decoded_IOC_URL",
                        url, "Decoded content", EventSeverity.CRITICAL, file_hash
                    ))

        result.metadata["iocs_found"] = len(seen_iocs)
        result.metadata["suspicious_patterns"] = len([p for p in SUSPICIOUS_PATTERNS if SUSPICIOUS_PATTERNS[p].search(content)])

        return result

    def _create_ioc_event(
        self,
        file_path: Path,
        timestamp: datetime,
        line_num: int,
        event_type: str,
        ioc_value: str,
        context: str,
        severity: EventSeverity,
        file_hash: str,
    ) -> UnifiedEvent:
        """Create an IOC event."""
        return UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=str(file_path),
            source_line=line_num,
            event_type=event_type,
            severity=severity,
            dest_ip=ioc_value if "IP" in event_type else None,
            file_hash=file_hash,
            raw_payload=context[:1000],
            parser_name=self.name,
            description=f"IOC extracted: {ioc_value}",
        )

    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
        except ValueError:
            pass
        return False

    def _extract_host_from_url(self, url: str) -> Optional[str]:
        """Extract host (IP or domain) from URL."""
        try:
            # Remove protocol
            if '://' in url:
                url = url.split('://')[1]
            # Remove path
            host = url.split('/')[0]
            # Remove port
            if ':' in host:
                host = host.split(':')[0]
            return host
        except Exception:
            return None

    def _deobfuscate_content(self, content: str) -> Optional[str]:
        """Try to deobfuscate script content using the deobfuscation module.

        Uses the layered deobfuscation approach:
        1. Static pattern detection (Base64, reversed Base64, etc.)
        2. Falls back to legacy base64 decoder if needed
        """
        try:
            # Try the new deobfuscation module
            from argus.deobfuscate import deobfuscate_static

            result = deobfuscate_static(content)
            if result.success and result.decoded:
                return result.decoded
        except ImportError:
            # Deobfuscation module not available, fall back to legacy
            pass
        except Exception:
            # Any error in deobfuscation, fall back
            pass

        # Fall back to legacy base64 decoding
        return self._decode_base64_content(content)

    def _decode_base64_content(self, content: str) -> Optional[str]:
        """Legacy base64 decoder - fallback for deobfuscation module."""
        decoded_parts = []

        # Find potential base64 chunks
        for match in PATTERNS["base64_chunk"].finditer(content):
            chunk = match.group()
            try:
                # Try to decode
                decoded = base64.b64decode(chunk).decode('utf-8', errors='ignore')
                # Check if it looks like code/text (has printable chars)
                printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) if decoded else 0
                if printable_ratio > 0.7 and len(decoded) > 10:
                    decoded_parts.append(decoded)
            except Exception:
                continue

        # Also check for reversed base64 (common obfuscation)
        reversed_matches = re.findall(r'\$[a-zA-Z0-9_]+\.ToCharArray\(\)\s*;\s*\[array\]::Reverse', content, re.IGNORECASE)
        if reversed_matches:
            # Try to find the variable and reverse it
            for match in PATTERNS["base64_chunk"].finditer(content):
                chunk = match.group()
                try:
                    reversed_chunk = chunk[::-1]
                    decoded = base64.b64decode(reversed_chunk).decode('utf-8', errors='ignore')
                    printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) if decoded else 0
                    if printable_ratio > 0.7 and len(decoded) > 10:
                        decoded_parts.append(f"[REVERSED]: {decoded}")
                except Exception:
                    continue

        return '\n---\n'.join(decoded_parts) if decoded_parts else None
