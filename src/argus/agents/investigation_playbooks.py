"""Investigation Playbooks for Deep Analysis Agents.

These playbooks contain specific investigation techniques learned from real IR cases.
Each playbook provides focused context for detecting specific attack patterns.
"""

# Playbook 1: Attacker Pivot Detection
PIVOT_DETECTION_PLAYBOOK = """
## ATTACKER PIVOT DETECTION PLAYBOOK

When attackers compromise a system, they often pivot from external to internal infrastructure.
Look for these patterns:

### Source IP Changes
1. Track all unique source IPs accessing sensitive resources (webshells, admin panels)
2. Flag when the SAME resource is accessed from DIFFERENT IP ranges:
   - External IP (e.g., 45.x.x.x) → Internal IP (e.g., 192.168.x.x, 10.x.x.x)
   - This indicates the attacker has pivoted to internal infrastructure

### User-Agent Fingerprinting
1. Track User-Agent strings per source IP
2. Flag User-Agent changes that indicate platform switch:
   - Windows → Linux (attacker moved to Kali/attack VM)
   - Desktop → Mobile (unusual for same "user")
   - Browser version jumps (different machines)
3. Common attack User-Agents:
   - "Mozilla/5.0 (X11; Linux x86_64)" = Kali/Linux attack machine
   - "python-requests", "curl", "wget" = scripted attacks

### VirtualBox/VM Network Indicators
1. 192.168.56.x network = VirtualBox host-only (common lab/attack setup)
2. 192.168.56.1 = typically the VirtualBox HOST machine
3. If internal IP appears with Linux UA on Windows network = VM pivot

### Timeline Gap Analysis
1. Note gaps in attacker activity (>15 minutes)
2. After gaps, check for:
   - New source IP appearing
   - Different User-Agent
   - More sophisticated commands
3. Gap often indicates: credential extraction → offline cracking → return with new access
"""

# Playbook 2: Credential Dump & Exfiltration Chain
CREDENTIAL_EXFIL_PLAYBOOK = """
## CREDENTIAL DUMP & EXFILTRATION PLAYBOOK

Track the full lifecycle of credential theft:

### Phase 1: Credential Dumping
1. ProcDump pattern: `pd.exe -accepteula -ma <PID>` or `procdump.exe -ma lsass.exe`
2. LSASS PID identification: Look for process targeting PID of lsass.exe
3. Output files: .dmp files in Public, Temp, or web-accessible directories

### Phase 2: Staging & Disguise
1. File rename to hide exfil: `move dumpfile.dmp cool_pic.png`
2. Common disguises: .png, .jpg, .txt, .log extensions
3. Location moves: from C:\\Users\\Public to C:\\inetpub\\wwwroot (web-accessible)

### Phase 3: Exfiltration
1. HTTP download of disguised file from INTERNAL IP (pivot machine)
2. Track: Who downloaded what files and when
3. Large file downloads (>1MB) from unusual directories

### Phase 4: Credential Use
1. After dump download, watch for:
   - New authentications using same username from different IP
   - NTLM authentication (pass-the-hash)
   - Invoke-WMIExec/Invoke-SMBExec with -Hash parameter
2. NTLM hash pattern: 32 hex characters (e.g., 847bfb693121775ad21ba7e42d47fd07)
"""

# Playbook 3: Webshell Command Analysis
WEBSHELL_ANALYSIS_PLAYBOOK = """
## WEBSHELL COMMAND ANALYSIS PLAYBOOK

When analyzing webshell activity:

### IIS Log Correlation
1. IIS log format: date time s-ip method uri query s-port user c-ip user-agent status
2. Key fields:
   - c-ip (column 9): Client IP - WHO is sending commands
   - cs-uri-query (column 6): Query string - often contains base64 commands
   - cs(User-Agent): Fingerprint the attacker's machine

### Base64 Command Extraction
1. Look for patterns: cmd=<base64>, c=<base64>, command=<base64>
2. Decode ALL base64 in query strings
3. Build command timeline: timestamp + source IP + decoded command

### Process Tree Correlation
1. Match IIS timestamps with Sysmon Event ID 1
2. Pattern: w3wp.exe (IIS) → cmd.exe /c <decoded command>
3. Command execution delay: typically <2 seconds from HTTP request

### Attack Phase Detection
1. Reconnaissance: whoami, ipconfig, net user, nltest
2. Privilege check: whoami /priv, net localgroup Administrators
3. Discovery: tasklist, netstat, wmic process list
4. Credential access: procdump, mimikatz
5. Lateral movement: Invoke-WMIExec, Invoke-SMBExec, psexec

### Multi-Source Tracking
1. Same webshell accessed from multiple IPs = attacker has multiple access points
2. Track command sophistication by source IP
3. External IP: often reconnaissance
4. Internal IP: often credential dumping and lateral movement
"""

# Playbook 4: Infrastructure Detection
INFRASTRUCTURE_DETECTION_PLAYBOOK = """
## ATTACK INFRASTRUCTURE DETECTION PLAYBOOK

Identify attacker-controlled infrastructure:

### Internal Attack Machines
1. VirtualBox networks: 192.168.56.x (host-only default)
2. VMware networks: 192.168.x.x or custom ranges
3. Look for: get-vmswitch, vmcompute, vboxsvc processes

### Indicators of VM/Lab Environment
1. Multiple NICs on servers (192.168.x AND 10.x)
2. DNS queries returning multiple IP ranges for same host
3. Hyper-V cmdlets: Get-VMSwitch, Get-VM

### Attacker Tooling Detection
1. Invoke-TheHash toolkit:
   - iwe.ps1 = Invoke-WMIExec
   - ise.ps1 = Invoke-SMBExec
   - itm.ps1 = Invoke-TheHash
2. Credential tools: pd.exe (ProcDump), mimikatz, m.exe
3. Web shells: .aspx, .asp, .php, .jsp in wwwroot/uploads

### Payload Staging
1. Downloads from pastebin, github raw, transfer.sh
2. Files saved to C:\\Temp\\, C:\\Users\\Public\\
3. Execution: -ExecutionPolicy Bypass -File <downloaded.ps1>
"""

# Playbook 5: Timeline Reconstruction
TIMELINE_RECONSTRUCTION_PLAYBOOK = """
## TIMELINE RECONSTRUCTION PLAYBOOK

Build a complete attack timeline:

### Evidence Correlation Matrix
1. IIS Logs: HTTP requests with timestamps and client IPs
2. Sysmon Event 1: Process creation with command lines
3. Sysmon Event 3: Network connections with source/dest IPs
4. Sysmon Event 11: File creation
5. Security Events: Authentication (4624/4625)

### Cross-Reference Methodology
1. IIS request → Sysmon process (within 2 seconds)
2. Sysmon process → Sysmon network connection (same PID)
3. Authentication event → subsequent process creation (same user)
4. File creation → file access in IIS logs (same filename)

### Gap Analysis
1. Identify quiet periods (no attacker activity)
2. Mark: last_command_time → next_command_time
3. Gaps >15 minutes often indicate:
   - Credential extraction and offline cracking
   - Pivot to different attack machine
   - Attacker break/planning

### Attack Phase Markers
1. Initial Access: First webshell request
2. Execution: First w3wp→cmd chain
3. Persistence: Service install, registry modification
4. Credential Access: ProcDump/mimikatz execution
5. Lateral Movement: SMB/RPC to other hosts
6. Exfiltration: File downloads to attacker IP
"""

# Combined context for agents
def get_playbook_context(agent_type: str) -> str:
    """Get relevant playbook context for an agent type."""
    playbooks = {
        "network": [PIVOT_DETECTION_PLAYBOOK, INFRASTRUCTURE_DETECTION_PLAYBOOK],
        "process": [WEBSHELL_ANALYSIS_PLAYBOOK, CREDENTIAL_EXFIL_PLAYBOOK],
        "file": [CREDENTIAL_EXFIL_PLAYBOOK, WEBSHELL_ANALYSIS_PLAYBOOK],
        "auth": [PIVOT_DETECTION_PLAYBOOK, CREDENTIAL_EXFIL_PLAYBOOK],
        "cross_system": [TIMELINE_RECONSTRUCTION_PLAYBOOK, PIVOT_DETECTION_PLAYBOOK],
        "anomaly": [INFRASTRUCTURE_DETECTION_PLAYBOOK, PIVOT_DETECTION_PLAYBOOK],
        "powershell": [WEBSHELL_ANALYSIS_PLAYBOOK, CREDENTIAL_EXFIL_PLAYBOOK],
    }

    selected = playbooks.get(agent_type, [])
    return "\n\n".join(selected)
