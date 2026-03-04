"""Deep Analysis Agents for Phase 3.

Ten domain-specific agents plus a master synthesizer:
- Agent 1: Process Tree Forensics
- Agent 2: File Operations
- Agent 3: Registry Forensics
- Agent 4: Network Forensics
- Agent 5: Service Analysis
- Agent 6: Authentication Forensics
- Agent 7: Cross-System Correlation
- Agent 8: PowerShell Deep Dive
- Agent 9: IIS/Webshell Analysis (NEW - critical for webshell attacks)
- Agent 10: Anomaly Hunter
- Agent 11: Master Synthesizer
"""

import json
from pathlib import Path
from typing import Optional

import click

from argus.agents.base import BaseAgent, AgentResult
from argus.agents.investigation_playbooks import get_playbook_context


# Base system prompt for analysis agents
ANALYSIS_SYSTEM_PROMPT = """You are an expert incident response analyst performing deep forensic analysis.
Your task is to analyze evidence and produce structured claims that can be validated.

CRITICAL: Every claim MUST be traceable to specific evidence. Include:
- Exact timestamps
- Source file and line numbers where possible
- Specific field values from the logs
- The query or filter used to find this evidence

OUTPUT FORMAT - Return claims as JSON:
```json
{
    "claims": [
        {
            "claim_id": "A{agent_num}-{sequence}",
            "summary": "Brief description of the finding",
            "affected_entities": ["hostnames", "users", "IPs", "processes"],
            "timestamp_range": ["start_time", "end_time"],
            "log_sources": ["source files"],
            "event_ids": [list of relevant event IDs],
            "detection_method": "How this was detected",
            "confidence": "HIGH|MEDIUM|LOW",
            "mitre_technique": "T1234.001 if applicable",
            "mitre_tactic": "Tactic name",
            "raw_evidence_refs": [
                {"file": "filename", "filter": "query used", "timestamp": "exact time"}
            ],
            "supporting_evidence": "Detailed evidence description",
            "inferred_vs_direct": "DIRECT|INFERRED"
        }
    ],
    "summary": "Overall analysis summary",
    "gaps": ["Evidence gaps or limitations noted"]
}
```

Be precise. Reference actual data. Don't fabricate evidence.

MEMORY FORENSICS EVENTS:
When evidence includes memory dumps, you'll see Volatility-derived events with event_type prefixes:
- Memory_pslist / Memory_pstree: Process listing with PID, PPID, name, start time
- Memory_cmdline: Full command line arguments for each process
- Memory_netscan / Memory_netstat: Network connections with local/remote IP:port and owning PID
- Memory_getsids: Security identifiers - SHOWS WHICH USER ACCOUNT OWNS EACH PROCESS
- Memory_malfind: Injected/suspicious code regions in process memory
- Memory_dlllist: Loaded DLLs per process
- Memory_handles: Open handles (files, registry keys, mutexes)
- Memory_svcscan: Windows services from memory
- Memory_envars: Environment variables per process
- Memory_filescan: Files cached in memory

KEY MEMORY FORENSICS ANALYSIS PATTERNS:
1. User Attribution: Memory_getsids maps PIDs to usernames — use this to identify compromised accounts
2. Process Injection: Memory_malfind flags indicate injected code — correlate the target PID with pslist
3. Hidden Processes: Compare Memory_pslist vs Memory_pstree for process hiding
4. C2 Connections: Memory_netscan shows connections that may not appear in logs
5. Full Command Lines: Memory_cmdline often has complete commands truncated in event logs

When you see event_type starting with "Memory_", apply memory forensics analysis techniques."""


class ProcessTreeAgent(BaseAgent):
    """Agent 1: Process Tree Forensics."""

    name = "agent_01_process_trees"
    description = "Analyzes process creation and parent-child relationships"
    relevant_extraction_keys = [
        "extraction_summary", "process_trees", "credential_access", "lolbin_detection",
        "unified_timeline"
    ]

    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "1") + """

YOUR DOMAIN: Process Tree Forensics
Analyze Sysmon Event ID 1 and Windows Event 4688 for:
- Complete process trees: grandparent → parent → child → grandchild
- Extract: Image, CommandLine, ParentImage, ParentCommandLine, User, ProcessId
- Flag: web server children (w3wp.exe, httpd), services.exe spawns, encoded commands
- Identify LOLBIN abuse (certutil, mshta, regsvr32, rundll32, wmic, bitsadmin)
- Note if Sysmon data is missing (4688 lacks parent command lines)

CRITICAL WEBSHELL DETECTION:
- Flag ANY w3wp.exe → cmd.exe or w3wp.exe → powershell.exe chains (WEBSHELL INDICATOR)
- This pattern indicates command execution through a web shell (e.g., ASP/ASPX shell)
- Look for base64-encoded commands in these chains
- Common webshell file locations: C:\\inetpub\\, uploads\\, temp\\

CREDENTIAL DUMPING DETECTION:
- Flag pd.exe, procdump.exe, procdump64.exe execution
- Flag ANY process with command line containing "lsass" or "-ma" (memory dump)
- ProcDump with "-accepteula -ma <pid>" targeting LSASS = credential harvesting
- Look for output files: .dmp files, especially in Public, Temp folders

WEBSHELL COMMAND ANALYSIS (correlate with IIS logs if available):
1. Build w3wp.exe child process timeline
2. For each cmd.exe/powershell.exe child, extract:
   - Timestamp, command line, user context
   - Parent PID (should be w3wp.exe)
3. Categorize commands by attack phase:
   - Reconnaissance: whoami, ipconfig, net user, nltest, tasklist, netstat
   - Privilege check: whoami /priv, net localgroup Administrators
   - Discovery: wmic process list, dir /s, systeminfo
   - Credential access: pd.exe, procdump, mimikatz patterns
   - Lateral movement: Invoke-WMIExec, Invoke-SMBExec, psexec
4. Note command sophistication progression (recon → cred dump → lateral)

PROCESS TREE TIMELINE:
- Build chronological list of ALL w3wp.exe children
- Identify gaps >15 minutes between commands (attacker pauses)
- After gaps, look for: different command style, new techniques
- Count total webshell commands to assess attacker activity level"""
    
    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Include extraction results at the TOP (pre-analyzed 100% coverage data)
        extraction_section = self.format_extraction_context(context)

        # Use routed events if available (prioritized by suspiciousness)
        if routed.get("process"):
            process_events = routed["process"]
            source = "routed (prioritized by suspiciousness)"
        else:
            events = context.get("events", [])
            process_events = [e for e in events if
                any(x in str(e.get("event_type", "")).lower() for x in ["4688", "process", "sysmon_1", "sysmon 1", "memory_pslist", "memory_cmdline"])]
            source = "filtered"

        # Also include webshell-related process events (critical)
        webshell_data = routed.get("webshell", {})
        w3wp_children = webshell_data.get("w3wp_children", [])

        return f"""{extraction_section}

## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Webshell Process Chain (w3wp.exe children) - {len(w3wp_children)} events
These are commands executed through webshells - ANALYZE CAREFULLY:
{json.dumps(w3wp_children[:50], indent=2, default=str)}

## Process Events ({len(process_events)} total, {source})
{json.dumps(process_events[:100], indent=2, default=str)}

CRITICAL TASKS:
1. Analyze ALL w3wp.exe children - these are webshell commands
2. Build process trees for suspicious parent-child relationships
3. Identify credential dumping (pd.exe, procdump targeting LSASS)
4. Flag reconnaissance commands (whoami, ipconfig, net user)"""


class FileOperationsAgent(BaseAgent):
    """Agent 2: File Operations."""
    
    name = "agent_02_file_ops"
    description = "Analyzes file creation, modification, and deletion"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "2") + """

YOUR DOMAIN: File Operations
Analyze Sysmon Event ID 11 (FileCreate), 15 (FileCreateStreamHash), 23 (FileDelete):
- Extract: TargetFilename, CreationTime, ProcessId, Image, Hash
- Flag files in: Temp, Public, Downloads, inetpub, ProgramData
- Flag: executables, scripts (.ps1, .bat, .vbs), renamed extensions
- Cross-reference ProcessId to identify which process created each file
- Look for staging activity and suspicious file placement

WEBSHELL UPLOAD DETECTION (CRITICAL):
- .aspx, .asp, .php, .jsp files created in inetpub/wwwroot
- Files with suspicious names: forbiden.aspx, cmd.aspx, shell.aspx
- w3wp.exe as Image (IIS creating files) in uploads directories
- Look for multiple webshells: redirect.aspx, ok.aspx, forbidden.aspx variants

ATTACK TOOL STAGING:
- pd.exe, procdump.exe = credential harvesting tool
- iwe.ps1, ise.ps1 = Invoke-WMIExec/SMBExec (Invoke-TheHash toolkit)
- mimikatz, m.exe, kiwi = credential dumping
- Files renamed to hide purpose: cool_pic.png (was dumpfile.dmp)
- .dmp files = memory dumps (likely LSASS credentials)

CREDENTIAL EXFILTRATION CHAIN (track full lifecycle):
Phase 1 - Dump: ProcDump creates .dmp file (look for pd.exe -ma)
Phase 2 - Disguise: File renamed to innocent extension (.png, .jpg, .txt, .log)
  * Pattern: `move <original>.dmp <disguised>.png`
  * Location change: C:\\Users\\Public → C:\\inetpub\\wwwroot (web-accessible)
Phase 3 - Exfil: HTTP download of disguised file
  * In IIS logs: GET /uploads/<disguised_file> from INTERNAL IP
  * Large file (>1MB) download from unusual path
Phase 4 - Credential Use: Watch for Invoke-SMBExec/WMIExec with -Hash parameter

FILE DOWNLOAD TRACKING (IIS correlation):
- Match Sysmon file creation with IIS access logs
- Track: timestamp of file create → timestamp of download → client IP
- Flag downloads from internal IPs (pivot machine exfiltrating data)"""
    
    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Use routed events if available
        if routed.get("file"):
            file_events = routed["file"]
            source = "routed (prioritized)"
        else:
            events = context.get("events", [])
            file_events = [e for e in events if
                any(x in str(e.get("event_type", "")).lower() for x in ["file", "sysmon_11", "sysmon_15", "sysmon_23"])]
            source = "filtered"

        # Include credential-related events (dump files)
        credential_events = routed.get("credential", [])

        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Credential-Related File Events - {len(credential_events)} events
Look for .dmp files, file renames, and staging:
{json.dumps(credential_events[:50], indent=2, default=str)}

## File Events ({len(file_events)} total, {source})
{json.dumps(file_events[:100], indent=2, default=str)}

CRITICAL TASKS:
1. Find .dmp files (memory dumps, likely LSASS credentials)
2. Track file renames (dumpfile.dmp -> cool_pic.png pattern)
3. Identify webshell uploads (.aspx, .asp files in wwwroot)
4. Find staging locations (Public, Temp, inetpub directories)"""


class RegistryAgent(BaseAgent):
    """Agent 3: Registry Forensics."""
    
    name = "agent_03_registry"
    description = "Analyzes registry modifications for persistence"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "3") + """

YOUR DOMAIN: Registry Forensics
Analyze Sysmon Event ID 12 (CreateKey), 13 (SetValue), 14 (RenameKey):
- Extract: EventType, TargetObject, Details, ProcessId
- Flag persistence locations: Run keys, Services, COM objects
- Identify: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
- Identify: HKLM\\SYSTEM\\CurrentControlSet\\Services
- Look for encoded values, suspicious paths in registry data"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        reg_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["registry", "sysmon_12", "sysmon_13", "sysmon_14", "reg"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Registry Events ({len(reg_events)} total, showing sample)
{json.dumps(reg_events[:100], indent=2, default=str)}

Analyze registry modifications. Identify persistence mechanisms and suspicious registry changes."""


class NetworkAgent(BaseAgent):
    """Agent 4: Network Forensics."""

    name = "agent_04_network"
    description = "Analyzes network connections and DNS queries"
    relevant_extraction_keys = [
        "extraction_summary", "network", "lateral_movement", "dns_tunneling",
        "network_statistics", "dga_detection"
    ]

    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "4") + """

YOUR DOMAIN: Network Forensics
Analyze Sysmon Event ID 3 (NetworkConnect), 22 (DNSQuery), and PCAP data:
- Extract: SourceIp, DestinationIp, DestinationPort, ProcessId, QueryName
- Flag: external connections from internal hosts
- Flag: internal lateral movement (internal-to-internal on suspicious ports)
- Identify C2 patterns: beaconing intervals, known-bad ports (4444, 5555, etc.)
- Look for DNS tunneling or suspicious domain queries

LATERAL MOVEMENT DETECTION (CRITICAL):
- Port 445 (SMB) connections between internal hosts = potential SMBExec/PsExec
- Port 135 (RPC/WMI) connections = potential WMI-based lateral movement
- Port 5985/5986 (WinRM) connections = PowerShell remoting
- Correlate network connections with PowerShell process creation
- Map: Source IP → Destination IP → Service created on destination

PASS-THE-HASH INDICATORS:
- PowerShell.exe making SMB (445) or RPC (135) connections to domain controller
- Rapid succession of RPC then SMB connections = Invoke-WMIExec/SMBExec

ATTACKER PIVOT DETECTION (from IIS/Web logs):
- Track unique source IPs (c-ip) accessing webshells or admin panels
- Flag when SAME resource accessed from different IP ranges:
  * External (45.x, public IPs) → Internal (192.168.x, 10.x) = PIVOT OCCURRED
- User-Agent fingerprinting:
  * Windows UA → Linux UA = attacker switched to attack VM (likely Kali)
  * "Mozilla/5.0 (X11; Linux x86_64)" = common Kali/attack machine fingerprint
- VirtualBox network: 192.168.56.x is default host-only network
  * 192.168.56[.]1 = typically VirtualBox HOST machine
  * If Linux UA from .1 accessing Windows server = attacker VM

TIMELINE GAP ANALYSIS:
- Note gaps >15 minutes in attacker activity
- After gaps, check for: new source IP, different User-Agent, more sophisticated commands
- Gap pattern: credential dump → offline cracking → return with new access"""
    
    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Include extraction results at the TOP (pre-analyzed 100% coverage data)
        extraction_section = self.format_extraction_context(context)

        # Use routed events if available
        if routed.get("network"):
            net_events = routed["network"]
            source = "routed (prioritized)"
        else:
            events = context.get("events", [])
            net_events = [e for e in events if
                any(x in str(e.get("event_type", "")).lower() for x in ["network", "sysmon_3", "sysmon_22", "dns", "connection", "pcap"]) or
                e.get("dest_ip") or e.get("source_ip")]
            source = "filtered"

        # Include lateral movement events
        lateral_events = routed.get("lateral_movement", [])

        return f"""{extraction_section}

## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Lateral Movement Events - {len(lateral_events)} events
SMB (445), WMI (135), WinRM connections and related auth:
{json.dumps(lateral_events[:50], indent=2, default=str)}

## Network Events ({len(net_events)} total, {source})
{json.dumps(net_events[:100], indent=2, default=str)}

CRITICAL TASKS:
1. Identify SMB (445) and WMI (135) connections between internal hosts
2. Track source IP changes (external -> internal = pivot)
3. Correlate network connections with service creation timestamps
4. Flag connections from webserver to DC (lateral movement indicator)"""


class ServiceAgent(BaseAgent):
    """Agent 5: Service Analysis."""
    
    name = "agent_05_services"
    description = "Analyzes service installation and changes"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "5") + """

YOUR DOMAIN: Service Analysis
Analyze Event ID 7045 (ServiceInstall), 7034 (ServiceCrash), 7036 (ServiceStateChange), 4697:
- Extract: ServiceName, ImagePath, ServiceType, StartType, AccountName
- Flag: random service names (15+ chars, all caps, no spaces)
- Flag: cmd/powershell in ImagePath
- Flag: demand start services (often used for persistence)
- Build service installation timeline

SMBEXEC/PSEXEC DETECTION (CRITICAL):
- Invoke-SMBExec creates services with RANDOM 20-character UPPERCASE names (e.g., BTOBTOVAGGDXWCRQYEWL)
- ImagePath often contains: %COMSPEC% /C powershell/cmd with encoded commands
- These services execute and are immediately deleted
- Rapid service install → service delete within seconds = SMBExec pattern
- If you see multiple random-named services in sequence = coordinated lateral movement

FLAG HIGH SEVERITY: Any service where ServiceName matches pattern [A-Z]{15,20} (random uppercase)"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        svc_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["7045", "7034", "7036", "4697", "service"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Service Events ({len(svc_events)} total, showing sample)
{json.dumps(svc_events[:100], indent=2, default=str)}

Analyze service installations. Identify malicious services and persistence mechanisms."""


class AuthenticationAgent(BaseAgent):
    """Agent 6: Authentication Forensics."""

    name = "agent_06_auth"
    description = "Analyzes authentication events and credential usage"
    relevant_extraction_keys = [
        "extraction_summary", "auth_timeline", "kerberoasting", "credential_access",
        "lateral_movement", "account_management"
    ]

    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "6") + """

YOUR DOMAIN: Authentication Forensics
Analyze authentication events:
- 4624 (LogonSuccess), 4625 (LogonFail), 4648 (ExplicitCredentials)
- 4672 (SpecialPrivileges), 4769 (KerberosTGS), 4771 (KerberosPreAuth), 4776 (CredentialValidation)
- Group by LogonType: 2=interactive, 3=network, 10=RDP
- Identify: brute force, password spraying, Kerberoasting (RC4), pass-the-hash
- Build authentication timeline per user

PASS-THE-HASH DETECTION (CRITICAL):
- NTLM authentication (4776) from non-standard workstations
- LogonType 3 (network) with NTLM from compromised server to DC = lateral movement
- Machine accounts ($) authenticating rapidly = potential automated attack
- User authenticating from webserver IP immediately after webshell activity

CREDENTIAL DUMPING INDICATORS:
- After LSASS dump (pd.exe/procdump), watch for:
  1. New authentications using same user credentials
  2. Auth from different source IP than user's normal workstation
  3. LogonType 3 following webshell command execution
  4. Successful auth with no prior Kerberos TGT request (NTLM PTH)

POST-CREDENTIAL-DUMP TIMELINE:
1. Identify credential dump timestamp (ProcDump/mimikatz execution)
2. Search for authentications AFTER that timestamp using extracted credentials
3. Pattern: dump at T1 → auth from new IP at T2 → lateral movement at T3
4. The source IP at T2 reveals attacker's pivot machine

AUTHENTICATION SOURCE ANALYSIS:
- Map which IPs each user authenticates from
- Flag: user authenticating from webserver IP (WEB01$, or user from IIS context)
- Flag: internal IP appearing after external-only activity
- Correlate with User-Agent if IIS logs available (Linux UA = pivot machine)

ATTACK PHASE MARKERS IN AUTH LOGS:
1. Initial compromise: IIS AppPool account activity
2. Privilege escalation: Administrator/SYSTEM appearing
3. Credential harvest: No direct auth marker, but gap before lateral movement
4. Lateral movement: Target user (e.g., 'eugene') authenticating from web server IP
5. Domain compromise: Admin auth to DC from internal attacker IP"""
    
    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Include extraction results at the TOP (pre-analyzed 100% coverage data)
        extraction_section = self.format_extraction_context(context)

        # Use routed events if available
        if routed.get("auth"):
            auth_events = routed["auth"]
            source = "routed (prioritized)"
        else:
            events = context.get("events", [])
            auth_events = [e for e in events if
                any(x in str(e.get("event_type", "")).lower() for x in
                    ["4624", "4625", "4648", "4672", "4769", "4771", "4776", "logon", "auth", "kerberos"])]
            source = "filtered"

        # Include lateral movement events (contains auth for lateral movement)
        lateral_events = routed.get("lateral_movement", [])

        return f"""{extraction_section}

## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Lateral Movement Auth Events - {len(lateral_events)} events
NTLM and network logons related to lateral movement:
{json.dumps(lateral_events[:50], indent=2, default=str)}

## Authentication Events ({len(auth_events)} total, {source})
{json.dumps(auth_events[:100], indent=2, default=str)}

CRITICAL TASKS:
1. Identify pass-the-hash indicators (NTLM auth from unusual sources)
2. Track auth after credential dump timestamps
3. Flag LogonType 3 (network) from webserver to DC
4. Map user credentials appearing from new source IPs"""


class CrossSystemAgent(BaseAgent):
    """Agent 7: Cross-System Correlation."""
    
    name = "agent_07_cross_system"
    description = "Correlates activity across multiple systems"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "7") + """

YOUR DOMAIN: Cross-System Correlation
Analyze all evidence sources simultaneously:
- Map attack paths between systems
- Identify which commands on System A led to activity on System B
- Find network connections correlating with process creation
- Establish lateral movement chain with evidence from BOTH sides
- Identify credential reuse across systems
- Build complete timeline spanning all systems

PIVOT DETECTION (CRITICAL):
- Track when attacker changes source IPs (external → internal)
- Compare User-Agent strings across time (attacker tool changes)
- Map: Web server compromise → credential harvest → lateral movement
- Correlate IIS webshell commands with Sysmon process creation
- Look for internal IPs (192.168.x, 10.x) appearing after external compromise

LATERAL MOVEMENT CHAIN:
1. Initial access (external IP to webshell)
2. Credential dump (pd.exe/procdump on LSASS)
3. Pivot to internal machine (new internal source IP)
4. Lateral movement (SMB/WMI to domain controller)
5. Domain compromise (service creation on DC)

EVIDENCE CORRELATION MATRIX (cross-reference these):
- IIS Logs: HTTP requests with timestamps and client IPs (c-ip column)
- Sysmon Event 1: Process creation with command lines
- Sysmon Event 3: Network connections with source/dest IPs
- Sysmon Event 11: File creation with timestamps
- Security Events 4624/4625: Authentication with source IPs

CROSS-REFERENCE METHODOLOGY:
1. IIS request timestamp → Sysmon process within 2 seconds (same command)
2. Sysmon process PID → Sysmon network connection (same PID)
3. Auth event → subsequent process creation (same user, ~seconds later)
4. File creation timestamp → IIS download (same filename, later time)

TIMELINE GAP ANALYSIS:
1. Build chronological activity timeline per source IP
2. Identify quiet periods (>15 minutes gap)
3. After gaps, look for:
   - New source IP appearing (pivot complete)
   - Different User-Agent (new machine)
   - More sophisticated commands (credentials obtained)
4. Gap often means: credential extraction → offline cracking → return

MULTI-SYSTEM ATTACK FLOW:
Track commands that reference OTHER systems:
- `-Target 192.168.56[.]10` = attacking DC from web server
- Commands mentioning hostnames (DCSRV, WEB01)
- Correlate with destination system's logs for matching activity"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Group by source system
        by_system = {}
        for e in events:
            system = e.get("source_system") or e.get("_source_parquet", "unknown")
            if system not in by_system:
                by_system[system] = []
            by_system[system].append(e)

        # Get routed data
        webshell_data = routed.get("webshell", {})
        iis_events = webshell_data.get("iis_requests", [])
        w3wp_children = webshell_data.get("w3wp_children", [])
        lateral_events = routed.get("lateral_movement", [])
        credential_events = routed.get("credential", [])

        # Fallback if not routed
        if not iis_events:
            iis_events = [e for e in events if
                e.get("parser_name") == "iis" or
                "iis" in str(e.get("source_file", "")).lower() or
                e.get("http_method")]

        # Extract unique source IPs from IIS logs
        source_ips = set()
        for e in iis_events:
            if e.get("source_ip"):
                source_ips.add(e.get("source_ip"))

        prompt = f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Systems Found: {list(by_system.keys())}

## CRITICAL: Cross-System Attack Indicators

### Webshell Access (IIS) - {len(iis_events)} requests
Unique source IPs: {list(source_ips)[:20]}
{json.dumps(iis_events[:30], indent=2, default=str)}

### Webshell Command Execution (w3wp children) - {len(w3wp_children)} commands
{json.dumps(w3wp_children[:30], indent=2, default=str)}

### Lateral Movement Events - {len(lateral_events)} events
SMB/WMI connections and service installations:
{json.dumps(lateral_events[:30], indent=2, default=str)}

### Credential Events - {len(credential_events)} events
{json.dumps(credential_events[:20], indent=2, default=str)}

## Events by System (samples):
"""
        for system, sys_events in list(by_system.items())[:5]:
            prompt += f"\n### {system} ({len(sys_events)} events)\n{json.dumps(sys_events[:15], indent=2, default=str)}\n"

        prompt += """
CRITICAL CROSS-SYSTEM ANALYSIS:
1. Map attack path: External IP -> Webshell -> Credential Dump -> Pivot -> Lateral Movement
2. Correlate: IIS request timestamp -> w3wp child process (same command, ~2 seconds)
3. Track: Credential dump time -> New auth from different IP (pivot machine)
4. Identify: Commands on WEB01 targeting DCSRV (lateral movement)
5. Build complete timeline spanning all systems"""
        return prompt


class PowerShellAgent(BaseAgent):
    """Agent 8: PowerShell Deep Dive."""
    
    name = "agent_08_powershell"
    description = "Deep analysis of PowerShell activity"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "8") + """

YOUR DOMAIN: PowerShell Deep Dive
Analyze all PowerShell activity:
- Process creation with powershell.exe
- Engine events (400/403/600)
- ScriptBlock logging (4104)
- DECODE ALL encoded commands (-enc, -encodedcommand) - provide full base64 decode
- Identify: bypass flags (-ep bypass, -nop), download commands (IEX, Invoke-WebRequest)
- For web logs: decode URL-encoded PowerShell from query strings
- Identify obfuscation techniques (string concatenation, variable substitution)

PASS-THE-HASH / INVOKE-THEHASH DETECTION (CRITICAL):
- Look for: Invoke-WMIExec, Invoke-SMBExec, Invoke-Mimikatz, Invoke-TheHash
- Common script names: iwe.ps1, ise.ps1, itm.ps1 (Invoke-WMIExec/SMBExec/TheMash)
- Parameters to flag: -Hash (NTLM hash), -Target (IP), -Domain, -Username, -Command
- NTLM hash pattern: 32 hex characters (e.g., 847bfb693121775ad21ba7e42d47fd07)
- These indicate lateral movement via pass-the-hash technique

WEBSHELL COMMAND DECODING (CRITICAL):
- If base64 commands appear in HTTP query strings (cmd= parameter), decode them
- Common webshell patterns: base64 → cmd.exe /c <command>
- Track command sequence to build attacker activity timeline

BASE64 EXTRACTION AND DECODING:
1. In IIS logs, look for query string: cmd=<base64>
2. Decode each base64 value to reveal actual command
3. Build chronological command list with timestamps and source IPs
4. Group decoded commands by attack phase:
   - Recon: whoami, ipconfig, net user, net localgroup, nltest
   - Discovery: tasklist /v, netstat -ano, wmic process list
   - Credential: pd.exe -accepteula -ma <pid>, procdump
   - Lateral: Invoke-WMIExec, Invoke-SMBExec with -Hash parameter

LATERAL MOVEMENT COMMAND PATTERNS:
Look for these specific command structures:
- `Invoke-WMIExec -Target <IP> -Domain <domain> -Username <user> -Hash <32hex> -Command '<cmd>'`
- `Invoke-SMBExec -Target <IP> -Hash <hash> -Command '<cmd>'`
- PowerShell downloading scripts: `Invoke-WebRequest -Uri '<url>' -OutFile '<path>'`
- Execution of downloaded scripts: `-ExecutionPolicy Bypass -File <downloaded.ps1>`

PAYLOAD URL TRACKING:
- Extract URLs from Invoke-WebRequest, wget, curl commands
- Common malicious sources: pastebin.com/raw/, github raw, transfer.sh
- Track: URL → downloaded filename → execution timestamp"""
    
    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Use routed events if available
        if routed.get("powershell"):
            ps_events = routed["powershell"]
            source = "routed (prioritized)"
        else:
            events = context.get("events", [])
            ps_events = [e for e in events if
                any(x in str(e).lower() for x in ["powershell", "-enc", "invoke-", "iex", "4104", "scriptblock"])]
            source = "filtered"

        # Include webshell data for base64 command analysis
        webshell_data = routed.get("webshell", {})
        w3wp_children = webshell_data.get("w3wp_children", [])

        # Include credential events (may have Invoke-Mimikatz etc)
        credential_events = routed.get("credential", [])

        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Webshell Command Execution (w3wp children) - {len(w3wp_children)} events
Commands executed via webshell - may contain encoded PowerShell:
{json.dumps(w3wp_children[:40], indent=2, default=str)}

## CRITICAL: Credential-Related Events - {len(credential_events)} events
Look for Invoke-Mimikatz, Invoke-WMIExec, Invoke-SMBExec:
{json.dumps(credential_events[:40], indent=2, default=str)}

## PowerShell Events ({len(ps_events)} total, {source})
{json.dumps(ps_events[:80], indent=2, default=str)}

CRITICAL TASKS:
1. DECODE all base64/encoded commands
2. Identify Invoke-WMIExec, Invoke-SMBExec with -Hash parameter
3. Extract NTLM hashes from commands (32 hex characters)
4. Track iwe.ps1, ise.ps1 script execution
5. Build command timeline showing attack progression"""


class IISWebshellAgent(BaseAgent):
    """Agent 9: IIS and Webshell Analysis."""

    name = "agent_09_iis_webshell"
    description = "Deep analysis of IIS logs and webshell activity"

    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "9") + """

YOUR DOMAIN: IIS Log and Webshell Analysis (CRITICAL)

You analyze IIS web server logs to detect webshell activity, attacker pivots, and command execution.
This is often the PRIMARY entry point for attacks - PAY CLOSE ATTENTION.

IIS LOG FORMAT:
- date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status
- c-ip (client IP) = WHO is sending requests (attacker's IP)
- cs-uri-query = Query string - often contains base64-encoded commands
- cs(User-Agent) = Fingerprints the attacker's machine

WEBSHELL DETECTION (HIGHEST PRIORITY):
1. Look for .aspx, .asp, .php, .jsp files with suspicious names:
   - forbiden.aspx, forbidden.aspx, cmd.aspx, shell.aspx, ok.aspx
   - Files in /uploads/, /temp/, /scripts/ directories
2. Multiple requests to same suspicious file = webshell in use
3. Query parameters like: cmd=, c=, exec=, command= (often with base64)

BASE64 COMMAND EXTRACTION (CRITICAL):
1. Find all requests with query strings containing base64 patterns
2. Pattern: cmd=<base64> or c=<base64> or similar
3. DECODE each base64 value and list the actual command
4. Build chronological command list: timestamp + source IP + decoded command

ATTACKER PIVOT DETECTION:
1. Track ALL unique source IPs (c-ip) accessing webshells
2. FLAG when SAME webshell accessed from DIFFERENT IP ranges:
   - External IP (e.g., 45.x.x.x) = initial compromise
   - Internal IP (e.g., 192.168.x.x, 10.x.x.x) = PIVOT OCCURRED
3. This pattern indicates attacker has compromised internal infrastructure

USER-AGENT FINGERPRINTING:
1. Track User-Agent per source IP
2. FLAG changes that indicate platform switch:
   - Windows User-Agent → Linux User-Agent = attacker moved to attack VM
   - "Mozilla/5.0 (X11; Linux x86_64)" = likely Kali Linux
   - "python-requests", "curl", "wget" = scripted attacks
3. Different User-Agents from same "attacker" over time = multiple machines

VIRTUALBOX/VM PIVOT INDICATORS:
- 192.168.56.x network = VirtualBox host-only (common lab/attack setup)
- 192.168.56[.]1 = typically the VirtualBox HOST machine
- If internal IP appears with Linux UA on Windows network = VM pivot

COMMAND CATEGORIZATION:
After decoding base64 commands, categorize by attack phase:
1. RECONNAISSANCE: whoami, ipconfig, net user, nltest, tasklist
2. PRIVILEGE CHECK: whoami /priv, net localgroup Administrators
3. DISCOVERY: wmic process list, dir, systeminfo, netstat
4. CREDENTIAL ACCESS: pd.exe, procdump, mimikatz commands
5. STAGING: move, copy, rename commands (especially .dmp files)
6. LATERAL MOVEMENT: Invoke-WMIExec, Invoke-SMBExec, -Hash parameter

TIMELINE RECONSTRUCTION:
- Build complete webshell command timeline
- Note gaps >15 minutes (attacker pauses/credential cracking)
- Track command sophistication progression
- First external IP, then internal = pivot timestamp

OUTPUT REQUIREMENTS:
1. List ALL webshell files accessed
2. List ALL source IPs accessing webshells with User-Agent
3. DECODE all base64 commands with timestamps
4. Identify pivot point (when internal IP first appears)
5. Categorize decoded commands by attack phase"""

    def build_user_prompt(self, context: dict) -> str:
        hypotheses = context.get("hypotheses", [])
        routed = context.get("routed_events", {})

        # Get pre-routed webshell data
        webshell_data = routed.get("webshell", {})
        iis_events = webshell_data.get("iis_requests", [])
        w3wp_children = webshell_data.get("w3wp_children", [])
        total_iis = webshell_data.get("total_iis", 0)
        total_w3wp = webshell_data.get("total_w3wp_children", 0)

        # Fallback to manual filtering if routing not available
        if not iis_events:
            events = context.get("events", [])
            iis_events = [e for e in events if
                e.get("parser_name") == "iis" or
                "iis" in str(e.get("_source_parquet", "")).lower() or
                e.get("http_method") or
                e.get("uri")]
            total_iis = len(iis_events)

            w3wp_children = [e for e in events if
                "w3wp" in str(e.get("parent_process_name", "")).lower() or
                "w3wp" in str(e.get("process_name", "")).lower() or
                "iis apppool" in str(e.get("username", "")).lower() or
                "defaultapppool" in str(e.get("username", "")).lower()]
            total_w3wp = len(w3wp_children)

        # Find suspicious URI patterns from IIS events
        suspicious_uris = [e for e in iis_events if
            any(x in str(e.get("uri", "")).lower()
                for x in ["aspx", "asp", "cmd", "shell", "forbid", "upload"])]

        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## CRITICAL: Webshell Access Summary
- Total IIS requests: {total_iis}
- Total w3wp.exe children (webshell commands): {total_w3wp}
- Suspicious URI requests: {len(suspicious_uris)}

## PRIORITY 1: Suspicious URI Requests (webshell access)
{json.dumps(suspicious_uris[:60], indent=2, default=str)}

## PRIORITY 2: Webshell Command Execution (w3wp.exe children)
These are the actual commands executed through the webshell:
{json.dumps(w3wp_children[:60], indent=2, default=str)}

## IIS Events Sample (for User-Agent and IP tracking)
{json.dumps(iis_events[:80], indent=2, default=str)}

CRITICAL ANALYSIS TASKS:
1. List ALL webshell files accessed (forbiden.aspx, etc.)
2. Extract and DECODE all base64 commands from query strings (cmd= parameter)
3. Track ALL source IPs accessing webshells - flag external vs internal
4. Identify PIVOT POINT: when does internal IP (192.168.x) first appear?
5. Track User-Agent changes: Windows -> Linux indicates attacker moved to attack VM
6. Build complete command timeline with timestamps, IPs, and decoded commands"""


class AnomalyHunterAgent(BaseAgent):
    """Agent 10: Anomaly Hunter."""

    name = "agent_10_anomalies"
    description = "Finds anything other agents might miss"
    relevant_extraction_keys = ["ALL"]  # Gets all extraction data to find anomalies

    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "10") + """

YOUR DOMAIN: Anomaly Hunter (Wildcard)
Find anything other agents might miss:
- Rare Event IDs (not commonly seen)
- Time gaps in logging
- Unusual process names
- Cryptocurrency addresses or wallet references
- Cleanup activity (file deletion, log clearing)
- Log tampering evidence
- Anti-forensics indicators
- Events just before/after log boundaries (first/last events)
- Anything that looks out of place

ATTACK INFRASTRUCTURE DETECTION:
- 192.168.56.x network = VirtualBox host-only (common lab/attack setup)
  * 192.168.56[.]1 = typically the VirtualBox HOST machine
  * If this IP appears with Linux User-Agent = attacker's attack VM
- Different User-Agent strings from same logical "attacker" (Windows → Linux)
- Internal IPs appearing as sources mid-attack (pivot indicators)
- Traffic patterns: external first, then internal-only (attacker pivot complete)

VM/HYPERVISOR DETECTION:
- Look for: Get-VMSwitch, vmcompute, vboxsvc, VBoxHeadless processes
- Hyper-V cmdlets in PowerShell (Get-VM, New-VM)
- VirtualBox processes being started during attack window
- Network adapter changes (new virtual NICs)

DATA EXFILTRATION INDICATORS:
- Files renamed to innocent names (dumpfile.dmp → cool_pic.png)
- Large file downloads from internal paths
- .dmp files moved to web-accessible directories
- Archive creation (zip, rar) after data collection
- Downloads from pastebin.com, github raw, transfer.sh (payload staging)

STEALTH INDICATORS:
- Using legitimate tools for malicious purposes (Living off the Land)
- ProcDump instead of Mimikatz (signed Microsoft tool)
- cmd.exe spawned by w3wp.exe (webshell vs. GUI interaction)

USER-AGENT ANOMALIES:
- Track User-Agent changes per source IP
- Flag: Windows UA → Linux UA (platform switch = new attack machine)
- "Mozilla/5.0 (X11; Linux x86_64)" from internal IP = likely Kali VM
- "python-requests", "curl", "wget" = scripted/automated attacks

TIMELINE ANOMALY DETECTION:
- Activity bursts followed by long gaps (>15 minutes)
- Sudden change in command sophistication after gaps
- New source IPs appearing after credential dump events
- Correlate gaps with file exfil timestamps (offline analysis period)"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        triage_findings = context.get("triage_findings", [])

        # Include ALL extraction results (this agent hunts for anomalies)
        extraction_section = self.format_extraction_context(context, max_chars=12000)

        return f"""{extraction_section}

## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Triage Findings Already Identified
{json.dumps(triage_findings[:20], indent=2, default=str)}

## All Events (sample - look for anomalies)
{json.dumps(events[:150], indent=2, default=str)}

Hunt for anomalies. Find what other agents missed. Look for rare events and suspicious patterns.
Pay special attention to user accounts, PIDs, and process relationships in the extraction data."""


class SynthesizerAgent(BaseAgent):
    """Agent 11: Master Synthesizer."""

    name = "agent_11_synthesizer"
    description = "Synthesizes all agent findings into unified analysis"
    max_tokens = 8192
    relevant_extraction_keys = ["ALL"]  # Synthesizer sees everything

    def get_system_prompt(self) -> str:
        return """You are the Master Synthesizer for an incident response analysis.
You receive findings from 9 specialized forensic agents. Your task is to:
1. Create a unified attack reconstruction
2. Build a second-by-second timeline
3. Identify the complete attack chain narrative (as HYPOTHESIS, not validated fact)
4. Assess confidence per phase of the attack
5. Note unanswered questions and evidence gaps
6. Consolidate IOC list
7. Create consolidated MITRE ATT&CK mapping
8. Identify contradictions between agents

OUTPUT FORMAT:
```json
{
    "attack_timeline": [
        {"timestamp": "ISO timestamp", "event": "What happened", "source": "Evidence source", "confidence": "HIGH|MEDIUM|LOW"}
    ],
    "attack_narrative": "Detailed narrative of the attack chain",
    "attack_phases": [
        {"phase": "Initial Access|Execution|Persistence|etc", "description": "What happened", "confidence": "HIGH|MEDIUM|LOW", "evidence": ["references"]}
    ],
    "ioc_list": [
        {"type": "IP|Domain|Hash|File|etc", "value": "the IOC", "context": "Where/how seen"}
    ],
    "mitre_mapping": [
        {"technique_id": "T1234", "technique_name": "Name", "tactic": "Tactic", "evidence": "How observed"}
    ],
    "contradictions": ["List of conflicting findings between agents"],
    "evidence_gaps": ["Questions that remain unanswered"],
    "confidence_assessment": "Overall confidence in the reconstruction"
}
```"""
    
    def build_user_prompt(self, context: dict) -> str:
        agent_results = context.get("agent_results", {})
        hypotheses = context.get("hypotheses", [])

        # Include extraction summary for comprehensive synthesis
        extraction_section = self.format_extraction_context(context, max_chars=6000)

        prompt = f"""{extraction_section}

## Initial Hypotheses
{json.dumps(hypotheses, indent=2, default=str)}

## Agent Findings:

"""
        for agent_name, results in agent_results.items():
            claims = results.get("claims", [])
            findings = results.get("findings", [])
            prompt += f"### {agent_name}\nClaims: {len(claims)}, Findings: {len(findings)}\n"
            prompt += json.dumps(claims[:10] + findings[:10], indent=2, default=str)[:3000]
            prompt += "\n\n"

        prompt += """
Synthesize all findings into a unified attack reconstruction.
Build the timeline. Map to MITRE. Identify gaps and contradictions.
IMPORTANT: Include user accounts and compromised users from the extraction data in your IOC list."""

        return prompt


# Agent registry
ANALYSIS_AGENTS = [
    ProcessTreeAgent,
    FileOperationsAgent,
    RegistryAgent,
    NetworkAgent,
    ServiceAgent,
    AuthenticationAgent,
    CrossSystemAgent,
    PowerShellAgent,
    IISWebshellAgent,
    AnomalyHunterAgent,
]

SYNTHESIZER_AGENT = SynthesizerAgent


def run_analysis_agents(
    events: list[dict],
    hypotheses: list[dict],
    triage_findings: list[dict],
    output_dir: Path,
    routed_events: Optional[dict] = None,
    extraction_results: Optional[dict] = None,
) -> dict:
    """Run all analysis agents and synthesizer.

    Args:
        events: Parsed events (full set)
        hypotheses: Hypotheses from Phase 2
        triage_findings: Findings from triage
        output_dir: Directory for output files
        routed_events: Pre-categorized and prioritized events from EventRouter
        extraction_results: Complete extraction results from ForensicExtractor (100% coverage)

    Returns:
        Dict with all agent results and synthesis
    """
    results = {}
    agents_dir = output_dir / "agents"
    agents_dir.mkdir(exist_ok=True)

    # Use routed events if available, otherwise fall back to full event set
    context = {
        "events": events,
        "hypotheses": hypotheses,
        "triage_findings": triage_findings,
        "routed_events": routed_events or {},
        "extraction_results": extraction_results or {},  # NEW: Pre-analyzed data from ForensicExtractor
    }
    
    # Run domain agents
    for agent_class in ANALYSIS_AGENTS:
        agent = agent_class()
        click.echo(f"  Running {agent.name}...")
        
        try:
            result = agent.run(context)
            results[agent.name] = result.to_dict()
            
            # Save result
            output_path = agents_dir / f"{agent.name}.json"
            with open(output_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            
            claim_count = len(result.claims)
            finding_count = len(result.findings)
            click.echo(f"    Claims: {claim_count}, Findings: {finding_count}")
            
            if result.errors:
                for error in result.errors:
                    click.echo(click.style(f"    Error: {error}", fg="red"))
                    
        except Exception as e:
            click.echo(click.style(f"    Failed: {e}", fg="red"))
            results[agent.name] = {"error": str(e)}
    
    # Run synthesizer
    click.echo(f"  Running synthesizer...")
    try:
        synth = SYNTHESIZER_AGENT()
        synth_context = {
            "agent_results": results,
            "hypotheses": hypotheses,
            "extraction_results": extraction_results or {},  # Pass extractions to synthesizer
        }
        synth_result = synth.run(synth_context)
        results["synthesis"] = synth_result.to_dict()
        
        # Save synthesis
        synth_path = output_dir / "synthesis.json"
        with open(synth_path, "w") as f:
            json.dump(synth_result.to_dict(), f, indent=2, default=str)
        
        click.echo(f"    Synthesis complete")
        
    except Exception as e:
        click.echo(click.style(f"    Synthesis failed: {e}", fg="red"))
        results["synthesis"] = {"error": str(e)}
    
    return results
