# ARGUS Extraction Gap Fix Specification
# Atomic Substep Implementation Guide for Claude Code

**Purpose:** This document tells Claude Code exactly what to build, in what order, with what inputs/outputs/tests. Every gap from MASTER_EXTRACTION_GAP_REPORT.md is broken into atomic substeps. Each substep is one function, one test, one commit.

**How to use:** Work through Sprint 1 first, then 2, then 3, then 4. Within each sprint, work top to bottom. Each substep has: Location (which file), Function signature, Input, Action, Output, Test criteria.

**Architecture Rule:** All new extraction functions go in the ForensicExtractor. They are called programmatically during Phase 2 (Triage). Agents in Phase 3 receive the structured output. Never have agents parse raw data.

---

# SPRINT 1: EVTX ENHANCEMENT (44 gaps -> 80% coverage)
**Estimated effort: 4-6 hours**
**Impact: Covers the most common evidence type in IR**

---

## S1.1: Logon Type Decoder

**Gap:** Logon Type not decoded to human-readable names (currently raw integers)

### Substep S1.1.1: Create logon type lookup
- **Location:** `src/argus/extractors/constants.py` (create if not exists)
- **Function:** `LOGON_TYPE_MAP: dict[int, str]`
- **Action:** Define constant dictionary mapping integer logon types to names
- **Content:**
```python
LOGON_TYPE_MAP = {
    0: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}
```
- **Test:** `assert LOGON_TYPE_MAP[10] == "RemoteInteractive"`

### Substep S1.1.2: Apply logon type decode in event extraction
- **Location:** ForensicExtractor, wherever 4624/4625/4634 events are processed
- **Function:** In the event field extraction, after extracting LogonType as integer
- **Action:** Add `LogonTypeName` field using lookup: `LOGON_TYPE_MAP.get(int(logon_type), f"Unknown({logon_type})")`
- **Output:** Every 4624/4625/4634 event now has both `LogonType: 10` and `LogonTypeName: "RemoteInteractive"`
- **Test:** Process a 4624 event with LogonType=3, verify LogonTypeName="Network"

---

## S1.2: Kerberoasting Detection

**Gap:** No TicketEncryptionType=0x17 flagging on Event 4769

### Substep S1.2.1: Add Kerberoasting flag to 4769 processing
- **Location:** ForensicExtractor, Kerberos extraction section
- **Function:** Within the 4769 handler, after extracting TicketEncryptionType
- **Action:** Check if TicketEncryptionType == "0x17" (RC4-HMAC). If yes, add field `kerberoasting_suspect: true` and severity "HIGH"
- **Output:** Each 4769 event gets `kerberoasting_suspect: bool`
- **Test:** Process a 4769 with TicketEncryptionType=0x17, verify flag is True. Process one with 0x12, verify False.

### Substep S1.2.2: Aggregate Kerberoasting summary
- **Location:** ForensicExtractor, summary/findings output
- **Function:** `extract_kerberoasting_summary(events) -> dict`
- **Input:** All 4769 events
- **Action:** Count total 4769s, count those with 0x17, list unique ServiceNames targeted with RC4, list requesting users
- **Output:** `{"total_tgs_requests": N, "rc4_requests": M, "targeted_services": [...], "requesting_users": [...], "severity": "HIGH" if M > 0}`
- **Test:** Given 100 4769 events where 5 have 0x17, verify rc4_requests=5 and severity=HIGH

---

## S1.3: Account Management Event Handlers

**Gap:** Events 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4733, 4738, 4740, 4756, 4781 not handled

### Substep S1.3.1: Define account management event ID set
- **Location:** `src/argus/extractors/constants.py`
- **Function:** `ACCOUNT_MGMT_EVENTS: dict[int, dict]`
- **Action:** Define mapping of event IDs to their description and critical fields:
```python
ACCOUNT_MGMT_EVENTS = {
    4720: {"desc": "Account created", "fields": ["TargetUserName", "SubjectUserName", "TargetSid"], "severity": "HIGH"},
    4722: {"desc": "Account enabled", "fields": ["TargetUserName"], "severity": "MEDIUM"},
    4724: {"desc": "Password reset", "fields": ["TargetUserName", "SubjectUserName"], "severity": "HIGH"},
    4725: {"desc": "Account disabled", "fields": ["TargetUserName"], "severity": "MEDIUM"},
    4726: {"desc": "Account deleted", "fields": ["TargetUserName"], "severity": "HIGH"},
    4728: {"desc": "Member added to global group", "fields": ["MemberName", "TargetUserName", "SubjectUserName"], "severity": "HIGH"},
    4732: {"desc": "Member added to local group", "fields": ["MemberName", "TargetUserName", "SubjectUserName"], "severity": "HIGH"},
    4733: {"desc": "Member removed from local group", "fields": ["MemberName", "TargetUserName"], "severity": "MEDIUM"},
    4738: {"desc": "User account changed", "fields": ["TargetUserName", "SubjectUserName"], "severity": "MEDIUM"},
    4740: {"desc": "Account locked out", "fields": ["TargetUserName", "TargetDomainName"], "severity": "MEDIUM"},
    4756: {"desc": "Member added to universal group", "fields": ["MemberName", "TargetUserName"], "severity": "HIGH"},
    4781: {"desc": "Account renamed", "fields": ["OldTargetUserName", "NewTargetUserName"], "severity": "HIGH"},
}
```
- **Test:** `assert 4720 in ACCOUNT_MGMT_EVENTS`

### Substep S1.3.2: Add account management extraction function
- **Location:** ForensicExtractor
- **Function:** `extract_account_management(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter events where EventId is in ACCOUNT_MGMT_EVENTS. For each match, extract the fields listed in the constant, add description and severity. Sort by timestamp.
- **Output:** List of dicts: `{"timestamp": str, "event_id": int, "description": str, "fields": {field: value}, "severity": str}`
- **Test:** Given events including a 4720 with TargetUserName="hacker", verify output contains account creation finding with severity HIGH

### Substep S1.3.3: Flag group membership changes to privileged groups
- **Location:** Inside extract_account_management
- **Action:** For 4728/4732/4756 events, check if TargetUserName (group name) contains: "Admin", "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators", "Remote Desktop Users". If yes, escalate severity to CRITICAL.
- **Test:** 4732 adding user to "Domain Admins" -> severity CRITICAL. 4732 adding to "Print Operators" -> severity HIGH.

---

## S1.4: Network Share Event Handlers

**Gap:** Events 5140, 5145, 5156, 5157 not handled

### Substep S1.4.1: Add network/share event extraction
- **Location:** ForensicExtractor
- **Function:** `extract_network_share_activity(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 5140, 5145. Extract ShareName, RelativeTargetName, SubjectUserName, IpAddress. Flag access to ADMIN$, C$, IPC$ as HIGH severity.
- **Output:** List of share access events with fields and severity
- **Test:** 5140 with ShareName="\\*\ADMIN$" -> severity HIGH

### Substep S1.4.2: Add WFP (Windows Filtering Platform) extraction
- **Location:** ForensicExtractor
- **Function:** `extract_wfp_connections(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 5156, 5157. Extract Application, Direction, SourceAddress, SourcePort, DestAddress, DestPort, Protocol. Track unique connection tuples.
- **Output:** List of connection events + summary of unique connections
- **Test:** 5156 with DestPort=445 -> connection recorded

---

## S1.5: PowerShell Extended Events

**Gap:** Events 400, 403, 800, 4103 not handled

### Substep S1.5.1: Add PowerShell lifecycle tracking
- **Location:** ForensicExtractor
- **Function:** `extract_powershell_activity(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 400, 403, 800, 4103, 4104. For 400/403: extract HostApplication (the full command line that started/stopped PS). For 800: extract UserId and HostApplication. For 4103: extract Payload. For 4104: extract ScriptBlockText. Correlate 400->403 pairs to determine PS session duration.
- **Output:** List of PowerShell events with decoded fields, plus session timeline
- **Test:** Given 400 event with HostApplication containing "-enc SQBF...", verify it is flagged as suspicious

---

## S1.6: Sysmon Extended Events

**Gap:** Sysmon EIDs 2, 6, 7, 8, 15, 17, 18, 23, 25 not handled. LSASS GrantedAccess not checked.

### Substep S1.6.1: Define Sysmon event handlers
- **Location:** `src/argus/extractors/constants.py`
- **Function:** `SYSMON_EVENTS: dict[int, dict]`
- **Action:** Map each Sysmon EID to description and key fields:
```python
SYSMON_EVENTS = {
    2: {"desc": "File creation time changed", "fields": ["Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"], "severity": "HIGH"},
    6: {"desc": "Driver loaded", "fields": ["ImageLoaded", "Hashes", "Signature", "SignatureStatus"], "severity": "MEDIUM"},
    7: {"desc": "Image loaded (DLL)", "fields": ["Image", "ImageLoaded", "Hashes", "Signature"], "severity": "LOW"},
    8: {"desc": "CreateRemoteThread", "fields": ["SourceImage", "TargetImage", "SourceProcessGuid"], "severity": "HIGH"},
    15: {"desc": "File stream (ADS)", "fields": ["Image", "TargetFilename", "Contents"], "severity": "HIGH"},
    17: {"desc": "Named pipe created", "fields": ["Image", "PipeName"], "severity": "MEDIUM"},
    18: {"desc": "Named pipe connected", "fields": ["Image", "PipeName"], "severity": "MEDIUM"},
    23: {"desc": "File delete archived", "fields": ["Image", "TargetFilename", "Hashes"], "severity": "MEDIUM"},
    25: {"desc": "Process tampering", "fields": ["Image", "Type"], "severity": "CRITICAL"},
}
```

### Substep S1.6.2: Add Sysmon extended extraction
- **Location:** ForensicExtractor
- **Function:** `extract_sysmon_extended(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for Sysmon EIDs in SYSMON_EVENTS. Extract listed fields. For EID 8 (CreateRemoteThread): always flag as HIGH, check if TargetImage is lsass.exe -> CRITICAL. For EID 2 (timestomping): flag as HIGH. For EID 25 (process tampering): flag as CRITICAL.
- **Output:** List of findings with fields and severity
- **Test:** Sysmon 8 targeting lsass.exe -> CRITICAL

### Substep S1.6.3: Fix LSASS GrantedAccess check
- **Location:** ForensicExtractor, existing Sysmon 10 handler
- **Action:** Currently checks TargetImage for "lsass" but does not check GrantedAccess mask. Add check: if GrantedAccess in ("0x1010", "0x1410", "0x1FFFFF", "0x01410", "0x001010"), escalate to CRITICAL and add note "Credential dumping suspected (GrantedAccess: {mask})"
- **Test:** Sysmon 10 with TargetImage=lsass.exe and GrantedAccess=0x1010 -> CRITICAL with credential note

---

## S1.7: Service Lifecycle Events

**Gap:** EIDs 7034, 7036, 7040 not handled. Also 4699, 4700, 4702 for scheduled tasks.

### Substep S1.7.1: Add service lifecycle extraction
- **Location:** ForensicExtractor
- **Function:** `extract_service_lifecycle(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 7034, 7036, 7040. For 7034 (crash): extract ServiceName, flag if service matches known malicious names. For 7036 (state change): extract ServiceName and running/stopped. For 7040 (start type change): extract ServiceName and old/new start type.
- **Output:** List of service events
- **Test:** 7034 crash of "XFBRJVUPQBBNMSAPIGNN" -> flagged as suspicious

### Substep S1.7.2: Add scheduled task lifecycle
- **Location:** ForensicExtractor
- **Function:** `extract_scheduled_task_lifecycle(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 4699, 4700, 4701, 4702. Extract TaskName. For 4702 (updated): extract TaskContent XML if available.
- **Output:** List of task events
- **Test:** 4699 deleting task "WmiPrvSE" -> recorded

---

## S1.8: Event Statistics

**Gap:** Per-EventID counts and hourly histogram not computed

### Substep S1.8.1: Add event statistics function
- **Location:** ForensicExtractor
- **Function:** `compute_event_statistics(events: list[dict]) -> dict`
- **Input:** All events from one evidence source
- **Action:** Count occurrences per EventId. Compute hourly histogram (events per hour). Identify spikes (hours with >2 standard deviations above mean). Identify rare events (count < 3).
- **Output:**
```python
{
    "total_events": int,
    "event_id_distribution": {event_id: count, ...},  # sorted by count desc
    "hourly_histogram": {hour_str: count, ...},
    "spike_hours": [{"hour": str, "count": int, "std_dev_above": float}],
    "rare_events": [{"event_id": int, "count": int, "description": str}],
    "time_range": {"first": str, "last": str},
}
```
- **Test:** Given 1000 events where 500 are in one hour, verify that hour appears in spike_hours

---

## S1.9: LOLBin Detection

**Gap:** 11 of 12 LOLBins not flagged

### Substep S1.9.1: Define LOLBin patterns
- **Location:** `src/argus/extractors/constants.py`
- **Function:** `LOLBIN_PATTERNS: list[dict]`
- **Action:** Define list of LOLBin detection rules:
```python
LOLBIN_PATTERNS = [
    {"binary": "certutil.exe", "suspicious_args": ["-urlcache", "-decode", "-encode", "-decodehex"], "severity": "HIGH", "mitre": "T1140"},
    {"binary": "mshta.exe", "suspicious_args": None, "severity": "HIGH", "mitre": "T1218.005"},  # None = any execution
    {"binary": "regsvr32.exe", "suspicious_args": ["/s", "/u", "/i:http", "scrobj.dll"], "severity": "HIGH", "mitre": "T1218.010"},
    {"binary": "rundll32.exe", "suspicious_dirs": ["\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\ProgramData\\"], "severity": "HIGH", "mitre": "T1218.011"},
    {"binary": "msiexec.exe", "suspicious_args": ["/q", "http://", "https://"], "severity": "HIGH", "mitre": "T1218.007"},
    {"binary": "regsvcs.exe", "suspicious_args": None, "severity": "MEDIUM", "mitre": "T1218.009"},
    {"binary": "regasm.exe", "suspicious_args": None, "severity": "MEDIUM", "mitre": "T1218.009"},
    {"binary": "installutil.exe", "suspicious_args": None, "severity": "MEDIUM", "mitre": "T1218.004"},
    {"binary": "wmic.exe", "suspicious_args": ["process call create", "/node:", "os get"], "severity": "HIGH", "mitre": "T1047"},
    {"binary": "bitsadmin.exe", "suspicious_args": ["/transfer", "/create", "/addfile"], "severity": "HIGH", "mitre": "T1197"},
    {"binary": "schtasks.exe", "suspicious_args": ["/create"], "severity": "MEDIUM", "mitre": "T1053.005"},
    {"binary": "net.exe", "suspicious_args": ["user /add", "localgroup administrators /add", "group \"Domain Admins\""], "severity": "HIGH", "mitre": "T1136.001"},
    {"binary": "net1.exe", "suspicious_args": ["user /add", "localgroup administrators /add"], "severity": "HIGH", "mitre": "T1136.001"},
    {"binary": "nltest.exe", "suspicious_args": ["/dclist", "/domain_trusts", "/dsgetdc"], "severity": "MEDIUM", "mitre": "T1482"},
    {"binary": "dsquery.exe", "suspicious_args": None, "severity": "MEDIUM", "mitre": "T1018"},
    {"binary": "cscript.exe", "suspicious_dirs": ["\\Temp\\", "\\Downloads\\"], "severity": "MEDIUM", "mitre": "T1059.005"},
    {"binary": "wscript.exe", "suspicious_dirs": ["\\Temp\\", "\\Downloads\\"], "severity": "MEDIUM", "mitre": "T1059.005"},
    {"binary": "powershell.exe", "suspicious_args": ["-nop", "-w hidden", "-ep bypass", "IEX", "Invoke-Expression", "downloadstring", "Net.WebClient", "-enc"], "severity": "HIGH", "mitre": "T1059.001"},
]
```

### Substep S1.9.2: Add LOLBin detection function
- **Location:** ForensicExtractor
- **Function:** `detect_lolbins(events: list[dict]) -> list[dict]`
- **Input:** All process creation events (4688, Sysmon 1)
- **Action:** For each event, extract Image/NewProcessName and CommandLine. Check if process name (case-insensitive, basename only) matches any LOLBIN_PATTERNS entry. If match: check if suspicious_args is None (any execution flagged) or if any suspicious_arg substring exists in CommandLine. Also check suspicious_dirs if defined. If match, create finding.
- **Output:** List of findings: `{"timestamp": str, "process": str, "command_line": str, "lolbin_rule": str, "severity": str, "mitre": str}`
- **Test:** Event with Image="C:\Windows\System32\certutil.exe" and CommandLine containing "-urlcache" -> flagged as HIGH with T1140

---

## S1.10: Audit Policy Change Detection

**Gap:** EID 4719 not handled

### Substep S1.10.1: Add audit policy change extraction
- **Location:** ForensicExtractor, within defense_evasion or absence_analysis section
- **Function:** Extend existing log cleared detection to include 4719
- **Action:** Filter for EID 4719. Extract SubjectUserName, CategoryId, SubcategoryGuid. Flag as HIGH severity with MITRE T1562.002.
- **Test:** 4719 event -> extracted with HIGH severity

---

## S1.11: AD Event Handlers

**Gap:** EIDs 4662, 4663, 5136, 5137 not handled

### Substep S1.11.1: Add AD object change extraction
- **Location:** ForensicExtractor
- **Function:** `extract_ad_changes(events: list[dict]) -> list[dict]`
- **Input:** All events
- **Action:** Filter for EIDs 4662, 4663, 5136, 5137. Extract relevant fields (ObjectDN, AttributeLDAPDisplayName for 5136). Flag 5136 modifications to sensitive attributes (adminCount, servicePrincipalName, msDS-AllowedToDelegateTo) as HIGH.
- **Test:** 5136 modifying servicePrincipalName -> HIGH (possible Kerberoasting setup)

---

# SPRINT 2: NETWORK & MEMORY (34 gaps -> 90% coverage)
**Estimated effort: 3-4 hours**

---

## S2.1: PCAP Response Code & Content-Type

**Gap:** HTTP response code and content-type not extracted

### Substep S2.1.1: Add HTTP response extraction to PCAP parser
- **Location:** PCAP extraction module (tshark wrapper)
- **Action:** Add fields to tshark command: `http.response.code`, `http.content_type`, `http.content_length`
- **Output:** Each HTTP transaction now includes response data
- **Test:** PCAP with a 200 response -> response_code=200 in output

---

## S2.2: HTTP Object Extraction

**Gap:** No file carving from PCAP

### Substep S2.2.1: Add tshark HTTP object export
- **Location:** PCAP extraction module
- **Function:** `extract_http_objects(pcap_path: str, output_dir: str) -> list[dict]`
- **Action:** Run `tshark -r {pcap} --export-objects http,{output_dir}`. Then for each extracted file: compute MD5/SHA256, identify file type via magic bytes, record source URL.
- **Output:** List of extracted objects: `{"filename": str, "size": int, "md5": str, "sha256": str, "content_type": str, "source_url": str}`
- **Test:** PCAP containing an exe download -> exe extracted with correct hash

---

## S2.3: DNS Extended Fields & Anomaly Detection

**Gap:** Query type, rcode, DGA detection, DNS tunneling not implemented

### Substep S2.3.1: Add DNS extended field extraction
- **Location:** PCAP DNS extraction
- **Action:** Add tshark fields: `dns.qry.type`, `dns.flags.rcode`, `dns.resp.ttl`
- **Test:** DNS query for TXT record -> type=16 extracted

### Substep S2.3.2: Add DGA detection
- **Location:** PCAP DNS analysis
- **Function:** `detect_dga(dns_queries: list[dict]) -> list[dict]`
- **Input:** All DNS query events
- **Action:** For each unique domain queried: compute entropy of second-level domain, check length, check consonant/vowel ratio. Flag domains where entropy > 3.5 AND length > 12 AND unusual character distribution.
- **Output:** List of suspected DGA domains with entropy scores
- **Test:** Domain "xkjhfwqemnbv.com" -> flagged as DGA. Domain "google.com" -> not flagged.

### Substep S2.3.3: Add DNS tunneling detection
- **Location:** PCAP DNS analysis
- **Function:** `detect_dns_tunneling(dns_queries: list[dict]) -> list[dict]`
- **Action:** Flag domains where subdomain length > 50 chars, or where TXT query volume to single domain > 10 queries.
- **Test:** Queries to "base64encodeddata.evil.com" with 50+ char subdomains -> flagged

---

## S2.4: Network Kerberos Extraction

**Gap:** No Kerberos protocol extraction from PCAP

### Substep S2.4.1: Add Kerberos tshark extraction
- **Location:** PCAP extraction module
- **Action:** Add tshark fields: `kerberos.msg_type`, `kerberos.CNameString`, `kerberos.SNameString`, `kerberos.etype`, `kerberos.realm`
- **Output:** Kerberos transactions with user, service, encryption type
- **Test:** PCAP with AS-REQ -> msg_type and CNameString extracted

---

## S2.5: JA3/JA3S Fingerprinting

**Gap:** No TLS fingerprinting

### Substep S2.5.1: Add JA3 extraction
- **Location:** PCAP TLS extraction
- **Action:** Add tshark field `tls.handshake.ja3` (requires tshark 3.x+) or compute from ClientHello fields. Also `tls.handshake.ja3s`.
- **Output:** JA3/JA3S hash per TLS connection
- **Test:** TLS handshake present -> JA3 hash computed

---

## S2.6: Network Statistics

**Gap:** Conversation matrix, top talkers, protocol distribution, port scan, beaconing not computed

### Substep S2.6.1: Add conversation statistics
- **Location:** PCAP extraction module
- **Function:** `compute_network_statistics(pcap_path: str) -> dict`
- **Action:** Run `tshark -r {pcap} -q -z conv,ip` and parse output. Also `-z io,stat,60` for time-based stats.
- **Output:** `{"conversations": [...], "top_talkers_by_bytes": [...], "top_talkers_by_packets": [...], "protocol_distribution": {...}}`

### Substep S2.6.2: Add port scan detection
- **Function:** `detect_port_scans(conversations: list) -> list[dict]`
- **Action:** For each source IP, count unique destination ports contacted. If > 20 unique ports to same dest, flag as port scan.
- **Test:** Source IP hitting 50 ports on one dest -> flagged

### Substep S2.6.3: Add beaconing detection
- **Function:** `detect_beaconing(connections: list) -> list[dict]`
- **Action:** Group connections by (src_ip, dst_ip, dst_port). For each group with > 5 connections, compute inter-arrival time standard deviation. If std_dev < 10% of mean interval -> flag as beaconing.
- **Test:** Connections every 60s (+/- 2s) -> flagged as beacon

---

## S2.7: Volatility Plugin Expansion

**Gap:** 22 of 30 plugins not in TRIAGE_PLUGINS

### Substep S2.7.1: Add Tier 1 plugins (HIGH priority)
- **Location:** Memory analysis module, TRIAGE_PLUGINS list
- **Action:** Add these plugins to the execution list:
  - `windows.dlllist` (DLL injection detection)
  - `windows.handles` (open file/registry handles)
  - `windows.svcscan` (service enumeration)
  - `windows.svclist` (service details)
  - `windows.netstat` (active connections)
  - `windows.hashdump` (credential extraction)
  - `windows.registry.hivelist` (available hives)
- **Output:** Each plugin's output parsed into structured dict
- **Test:** Run against test memory dump, verify output is non-empty dict

### Substep S2.7.2: Add Tier 2 plugins (MEDIUM priority)
- **Action:** Add:
  - `windows.hollowprocesses`
  - `windows.suspicious_threads`
  - `windows.psxview`
  - `windows.scheduled_tasks`
  - `windows.envars`
  - `windows.getsids`
  - `windows.registry.printkey`
  - `windows.registry.userassist`
  - `windows.lsadump`
  - `windows.cachedump`

### Substep S2.7.3: Add Tier 3 plugins (LOWER priority)
- **Action:** Add:
  - `windows.cmdscan`
  - `windows.consoles`
  - `windows.shimcachemem`
  - `windows.amcache`
  - `windows.dumpfiles`
  - `windows.callbacks`
  - `windows.ssdt`
  - `windows.threads`

---

# SPRINT 3: WEB & PE ENHANCEMENT (8 gaps -> 94% coverage)
**Estimated effort: 2-3 hours**

---

## S3.1: Web Attack Detection Patterns

**Gap:** SQL injection, path traversal, scanner UA, brute force detection missing

### Substep S3.1.1: Define web attack pattern library
- **Location:** `src/argus/extractors/constants.py`
- **Function:** `WEB_ATTACK_PATTERNS: list[dict]`
```python
WEB_ATTACK_PATTERNS = [
    {"name": "SQL Injection", "patterns": ["UNION SELECT", "UNION ALL SELECT", "' OR 1=1", "' OR '1'='1", "WAITFOR DELAY", "xp_cmdshell", "INFORMATION_SCHEMA", "sysobjects", "BENCHMARK(", "SLEEP("], "fields": ["uri_query", "uri_stem"], "severity": "CRITICAL", "mitre": "T1190"},
    {"name": "Command Injection", "patterns": ["; ls", "| cat ", "&& whoami", "; id", "| nc ", "; wget ", "; curl ", "%0a", "`id`"], "fields": ["uri_query"], "severity": "CRITICAL", "mitre": "T1059"},
    {"name": "Path Traversal", "patterns": ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "....//"], "fields": ["uri_stem", "uri_query"], "severity": "HIGH", "mitre": "T1083"},
    {"name": "Webshell Upload", "patterns": [".aspx", ".asp", ".php", ".jsp", ".jspx"], "fields": ["uri_stem"], "conditions": {"method": "PUT", "status": [200, 201]}, "severity": "CRITICAL", "mitre": "T1505.003"},
]

SCANNER_USER_AGENTS = ["nikto", "sqlmap", "dirbuster", "gobuster", "wfuzz", "burp", "nmap", "masscan", "zgrab", "nuclei", "httpx"]
```

### Substep S3.1.2: Implement web attack detection
- **Location:** ForensicExtractor, web log analysis
- **Function:** `detect_web_attacks(iis_events: list[dict]) -> list[dict]`
- **Input:** Parsed IIS log entries
- **Action:** For each request, check URI stem/query against WEB_ATTACK_PATTERNS. Also check User-Agent against SCANNER_USER_AGENTS (case insensitive substring). For brute force: group by (client_ip, uri_stem), flag if > 10 requests with status 401/403 in 1 minute.
- **Output:** List of attack findings with pattern name, severity, MITRE
- **Test:** Request with "UNION SELECT" in query -> SQL Injection CRITICAL

---

## S3.2: PE Version Info & Signature

**Gap:** PE version info and digital signature not extracted

### Substep S3.2.1: Add PE version info extraction
- **Location:** PE analysis module
- **Action:** Use pefile library: `pe.VS_FIXEDFILEINFO` and `pe.FileInfo` to extract CompanyName, ProductName, FileDescription, OriginalFilename, InternalName, FileVersion.
- **Output:** Version info dict. Flag masquerading: if CompanyName is a known vendor (Microsoft, Adobe, Google) but file is unsigned or hash unknown.
- **Test:** PE with CompanyName="Adobe" but invalid signature -> masquerading flag

### Substep S3.2.2: Add digital signature check
- **Location:** PE analysis module
- **Action:** Check for Authenticode signature presence. If present, verify if valid/invalid. Extract signer common name.
- **Output:** `{"signed": bool, "valid": bool, "signer": str}`

---

## S3.3: VirusTotal Behavior & WHOIS

**Gap:** VT behavior tab not pulled, WHOIS not implemented

### Substep S3.3.1: Add VT behavior extraction
- **Location:** IOC enrichment module
- **Action:** After hash lookup, call VT behavior endpoint: `/files/{hash}/behaviours`. Extract: dropped files, registry modifications, processes spawned, DNS lookups, HTTP requests.
- **Output:** Behavior summary dict

### Substep S3.3.2: Add WHOIS lookup
- **Location:** IOC enrichment module
- **Function:** `whois_lookup(ip_or_domain: str) -> dict`
- **Action:** Use python-whois or ipwhois library. Extract: registrant, ASN, ISP, country, registration date.
- **Output:** WHOIS data dict
- **Test:** WHOIS for 8.8.8.8 -> returns Google info

---

# SPRINT 4: DEOBFUSCATION & IOC ENHANCEMENT (12 gaps -> 97% coverage)
**Estimated effort: 2 hours**

---

## S4.1: Hex Decode

### Substep S4.1.1: Add hex payload detection and decode
- **Location:** Deobfuscation module
- **Function:** `decode_hex_payload(text: str) -> Optional[bytes]`
- **Action:** Detect patterns like `$hexString = "4D_5A_90..."` or `\x4d\x5a\x90`. Remove delimiters (_, \x, 0x, spaces). Convert to bytes via `bytes.fromhex()`. Check if result starts with MZ (PE) or PK (ZIP) and flag accordingly.
- **Test:** Input `"4D_5A_90_00"` -> returns bytes starting with MZ

## S4.2: Character Removal Deobfuscation

### Substep S4.2.1: Add filler character removal
- **Location:** Deobfuscation module
- **Function:** `deobfuscate_char_removal(text: str) -> str`
- **Action:** Detect and remove PowerShell backtick obfuscation (e.g., `` `p`o`w`e`r`s`h`e`l`l `` -> `powershell`). Also detect # insertion (from XLMRat walkthrough). Also detect caret insertion (e.g., `p^o^w^e^r^s^h^e^l^l`).
- **Test:** Input `` "po`wer`sh`ell" `` -> "powershell"

## S4.3: String Concatenation Evaluation

### Substep S4.3.1: Add string concat evaluation
- **Location:** Deobfuscation module
- **Function:** `evaluate_string_concat(text: str) -> str`
- **Action:** Detect PowerShell string concatenation patterns: `"str1" + "str2"`, `$a = "part1"; $b = "part2"; $a + $b`. Evaluate simple cases. Return deobfuscated result.
- **Test:** Input `'"Down" + "load" + "String"'` -> "DownloadString"

## S4.4: File Path & Registry IOC Extraction

### Substep S4.4.1: Add file path IOC extraction
- **Location:** IOC extraction module
- **Action:** Add regex for Windows file paths: `[A-Za-z]:\\[^\s"'<>|]+`. Filter to only include suspicious paths (Temp, Downloads, AppData, ProgramData, wwwroot, inetpub). Track unique paths.
- **Test:** CommandLine with "C:\Windows\Temp\evil.exe" -> path extracted

### Substep S4.4.2: Add registry key IOC extraction
- **Location:** IOC extraction module
- **Action:** Add regex for registry keys: `(HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s"']+` and `(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"']+`. Track unique keys, flag persistence-related locations.
- **Test:** Registry path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -> extracted and flagged as persistence

---

# SPRINT 5: DISK ARTIFACTS (Phase 3-4 items, lower priority)
**Estimated effort: 4-6 hours (larger parsers)**
**Do this AFTER validating Sprints 1-4 against benchmarks**

---

## S5.1: Amcache Parser
- **Function:** `parse_amcache(hive_path: str) -> list[dict]`
- **Action:** Parse Amcache.hve registry hive. Extract: file path, SHA1 hash, first execution timestamp, publisher, version, program ID.
- **Library:** python-registry or regipy

## S5.2: LNK File Parser
- **Function:** `parse_lnk_files(lnk_dir: str) -> list[dict]`
- **Action:** Parse .lnk files. Extract: target path, target MAC timestamps, volume serial, working directory.
- **Library:** pylnk3 or LnkParse3

## S5.3: Jump List Parser
- **Function:** `parse_jump_lists(jumplist_dir: str) -> list[dict]`
- **Library:** python-ole or custom

## S5.4: Registry Persistence Deep Check
- **Function:** `check_registry_persistence(hive_paths: dict) -> list[dict]`
- **Action:** Load NTUSER.DAT, SYSTEM, SOFTWARE hives. Check all persistence locations from Section 4.3 of the checklist. Extract values, flag non-standard entries.

## S5.5: System Configuration Extraction
- **Function:** `extract_system_config(hive_paths: dict) -> dict`
- **Action:** From SYSTEM hive: ComputerName, TimeZone, Network interfaces, Last shutdown. From SOFTWARE hive: OS version, installed software.

---

# VERIFICATION PROTOCOL

After each sprint, run this verification:

1. **Unit Tests:** Every new function has at least one test. Run all tests, 0 failures.
2. **Integration Test:** Run ARGUS against the Daylight Security evidence (DCSRV.xlsx, WEB01.xlsx, IIS logs). Compare output to known findings from the manual analysis. New extractions should surface findings that were previously missed.
3. **Regression Check:** Existing findings should still appear. No extraction should disappear.

After Sprint 1+2, run against CyberDefenders Lockdown case. Target: 80%+ of walkthrough findings detected.

After Sprint 3+4, run against a second case. Target: 85%+ findings detected.

---

# SUMMARY

| Sprint | Gaps Fixed | Coverage After | Key Capabilities Added |
|--------|-----------|---------------|----------------------|
| 1 | 44 EVTX gaps | ~65% | Account mgmt, LOLBins, Kerberoasting, Sysmon extended, PowerShell lifecycle, network shares, statistics |
| 2 | 34 network+memory gaps | ~80% | HTTP objects, DNS anomaly, JA3, Kerberos PCAP, beaconing, 22 Volatility plugins |
| 3 | 8 web+PE gaps | ~90% | SQL injection, web scanner, PE version info, VT behavior, WHOIS |
| 4 | 12 deobfuscation+IOC gaps | ~95% | Hex decode, char removal, concat eval, path/registry IOCs |
| 5 | 17 disk artifact gaps | ~97% | Amcache, LNK, Jump Lists, registry persistence deep check |

**Total: 119 NO items + 20 PARTIAL items addressed across 5 sprints**
**From 44% to 97% extraction coverage**
