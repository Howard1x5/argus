"""Deep Analysis Agents for Phase 3.

Nine domain-specific agents plus a master synthesizer:
- Agent 1: Process Tree Forensics
- Agent 2: File Operations
- Agent 3: Registry Forensics
- Agent 4: Network Forensics
- Agent 5: Service Analysis
- Agent 6: Authentication Forensics
- Agent 7: Cross-System Correlation
- Agent 8: PowerShell Deep Dive
- Agent 9: Anomaly Hunter
- Agent 10: Master Synthesizer
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

Be precise. Reference actual data. Don't fabricate evidence."""


class ProcessTreeAgent(BaseAgent):
    """Agent 1: Process Tree Forensics."""
    
    name = "agent_01_process_trees"
    description = "Analyzes process creation and parent-child relationships"
    
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
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        # Filter for process events
        process_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["4688", "process", "sysmon_1", "sysmon 1"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Process Events ({len(process_events)} total, showing sample)
{json.dumps(process_events[:100], indent=2, default=str)}

Analyze process creation patterns. Build process trees. Identify suspicious parent-child relationships."""


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
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        file_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["file", "sysmon_11", "sysmon_15", "sysmon_23"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## File Events ({len(file_events)} total, showing sample)
{json.dumps(file_events[:100], indent=2, default=str)}

Analyze file operations. Identify suspicious file creation patterns and staging activity."""


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
  * 192.168.56.1 = typically VirtualBox HOST machine
  * If Linux UA from .1 accessing Windows server = attacker VM

TIMELINE GAP ANALYSIS:
- Note gaps >15 minutes in attacker activity
- After gaps, check for: new source IP, different User-Agent, more sophisticated commands
- Gap pattern: credential dump → offline cracking → return with new access"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        net_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["network", "sysmon_3", "sysmon_22", "dns", "connection", "pcap"]) or
            e.get("dest_ip") or e.get("source_ip")]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Network Events ({len(net_events)} total, showing sample)
{json.dumps(net_events[:100], indent=2, default=str)}

Analyze network activity. Identify external connections, lateral movement, and C2 patterns."""


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
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        auth_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in 
                ["4624", "4625", "4648", "4672", "4769", "4771", "4776", "logon", "auth", "kerberos"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Authentication Events ({len(auth_events)} total, showing sample)
{json.dumps(auth_events[:100], indent=2, default=str)}

Analyze authentication patterns. Identify credential attacks and suspicious logon activity."""


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
- `-Target 192.168.56.10` = attacking DC from web server
- Commands mentioning hostnames (DCSRV, WEB01)
- Correlate with destination system's logs for matching activity"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])

        # Group by source system
        by_system = {}
        for e in events:
            system = e.get("source_system") or e.get("_source_parquet", "unknown")
            if system not in by_system:
                by_system[system] = []
            by_system[system].append(e)

        # Extract IIS events for webshell analysis
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

## IIS/Web Log Analysis
- Total web requests: {len(iis_events)}
- Unique source IPs (clients): {list(source_ips)[:20]}

### IIS Events (for pivot detection - check client IPs and User-Agents):
{json.dumps(iis_events[:30], indent=2, default=str)}

## Events by System (samples):
"""
        for system, sys_events in list(by_system.items())[:5]:
            prompt += f"\n### {system} ({len(sys_events)} events)\n{json.dumps(sys_events[:20], indent=2, default=str)}\n"

        prompt += """
Correlate activity across systems. Map the attack path. Identify lateral movement.

KEY ANALYSIS TASKS:
1. Track source IP changes in IIS logs (external → internal = pivot)
2. Correlate IIS requests with Sysmon process creation (webshell commands)
3. Map credential dump timestamps to subsequent authentications
4. Build cross-system timeline showing attack flow between hosts
"""
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
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        ps_events = [e for e in events if 
            any(x in str(e).lower() for x in ["powershell", "-enc", "invoke-", "iex", "4104", "scriptblock"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## PowerShell-Related Events ({len(ps_events)} total, showing sample)
{json.dumps(ps_events[:100], indent=2, default=str)}

Deep dive into PowerShell. DECODE all encoded commands. Identify malicious scripts."""


class AnomalyHunterAgent(BaseAgent):
    """Agent 9: Anomaly Hunter."""
    
    name = "agent_09_anomalies"
    description = "Finds anything other agents might miss"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "9") + """

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
  * 192.168.56.1 = typically the VirtualBox HOST machine
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
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Triage Findings Already Identified
{json.dumps(triage_findings[:20], indent=2, default=str)}

## All Events (sample - look for anomalies)
{json.dumps(events[:150], indent=2, default=str)}

Hunt for anomalies. Find what other agents missed. Look for rare events and suspicious patterns."""


class SynthesizerAgent(BaseAgent):
    """Agent 10: Master Synthesizer."""
    
    name = "agent_10_synthesizer"
    description = "Synthesizes all agent findings into unified analysis"
    max_tokens = 8192
    
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
        
        prompt = f"""## Initial Hypotheses
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
Build the timeline. Map to MITRE. Identify gaps and contradictions."""
        
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
    AnomalyHunterAgent,
]

SYNTHESIZER_AGENT = SynthesizerAgent


def run_analysis_agents(
    events: list[dict],
    hypotheses: list[dict],
    triage_findings: list[dict],
    output_dir: Path,
) -> dict:
    """Run all analysis agents and synthesizer.
    
    Args:
        events: Parsed events
        hypotheses: Hypotheses from Phase 2
        triage_findings: Findings from triage
        output_dir: Directory for output files
        
    Returns:
        Dict with all agent results and synthesis
    """
    results = {}
    agents_dir = output_dir / "agents"
    agents_dir.mkdir(exist_ok=True)
    
    context = {
        "events": events,
        "hypotheses": hypotheses,
        "triage_findings": triage_findings,
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
