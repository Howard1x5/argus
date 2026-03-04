# ARGUS Master Extraction Coverage Checklist

**Purpose:** This is the definitive list of every forensic artifact ARGUS must be able to extract from evidence. If the ForensicExtractor covers every item on this list, ARGUS will catch 95%+ of findings in any IR case. The remaining 5% is interpretation, handled by the LLM agent layer.

**How to use this document:**
1. Claude Code: For each item, check if ARGUS has an extraction function. Mark YES/NO/PARTIAL.
2. Every NO becomes a fix spec with atomic substeps.
3. Implement in priority order (Section 1 first, then 2, etc.)
4. Validate against 3-5 CyberDefenders cases.

**Sources:** SANS FOR500 Windows Forensic Analysis poster, MITRE ATT&CK Data Sources (DS0001-DS0042), Volatility 3 v2.27 plugin list, Wireshark/tshark protocol dissectors, DFIR community artifact references.

---

## EVIDENCE TYPE 1: WINDOWS EVENT LOGS (EVTX / Excel Export)
**Priority: CRITICAL**

### 1.1 Critical Security Event IDs

#### Authentication & Logon

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4624 | Security | Successful logon | LogonType, TargetUserName, TargetDomainName, IpAddress, IpPort, LogonProcessName, WorkstationName, LogonGuid |
| 4625 | Security | Failed logon | LogonType, TargetUserName, Status, SubStatus, IpAddress, WorkstationName, FailureReason |
| 4634 | Security | Logoff | TargetUserName, TargetLogonId, LogonType |
| 4647 | Security | User-initiated logoff | TargetUserName, TargetLogonId |
| 4648 | Security | Logon with explicit credentials | SubjectUserName, TargetUserName, TargetServerName, TargetInfo, IpAddress |
| 4672 | Security | Special privileges assigned | SubjectUserName, PrivilegeList |
| 4776 | Security | NTLM credential validation | TargetUserName, Workstation, Status |

**Logon Type Reference (must be decoded in output):**
- Type 2: Interactive (local)
- Type 3: Network (SMB, net use)
- Type 4: Batch
- Type 5: Service
- Type 7: Unlock
- Type 8: NetworkCleartext
- Type 9: NewCredentials (runas /netonly)
- Type 10: RemoteInteractive (RDP)
- Type 11: CachedInteractive

#### Kerberos

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4768 | Security | TGT requested | TargetUserName, IpAddress, TicketEncryptionType, Status |
| 4769 | Security | TGS requested | TargetUserName, ServiceName, IpAddress, TicketEncryptionType, Status |
| 4771 | Security | Kerberos pre-auth failed | TargetUserName, IpAddress, Status |

**Kerberoasting Detection:** Flag any 4769 where TicketEncryptionType = 0x17 (RC4-HMAC).

#### Process Execution

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4688 | Security | Process created | NewProcessName, CommandLine, ParentProcessName, SubjectUserName, TokenElevationType |
| 4689 | Security | Process exited | ProcessName, SubjectUserName |
| 1 | Sysmon | Process create | Image, CommandLine, ParentImage, ParentCommandLine, User, ProcessGuid, ParentProcessGuid, Hashes, IntegrityLevel |
| 5 | Sysmon | Process terminated | Image, ProcessGuid |

**Process Tree Reconstruction:** Link ParentProcessGuid to ProcessGuid. Flag: w3wp.exe spawning cmd.exe/powershell.exe (webshell), svchost.exe unusual children, encoded PowerShell chains.

#### Service & Scheduled Task

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4697 | Security | Service installed | ServiceName, ServiceFileName, ServiceType, ServiceStartType, ServiceAccount |
| 7045 | System | New service installed | ServiceName, ImagePath, ServiceType, StartType, AccountName |
| 7034 | System | Service crashed | ServiceName |
| 7036 | System | Service state change | ServiceName, param1 (running/stopped) |
| 7040 | System | Service start type changed | ServiceName, param1 (old), param2 (new) |
| 4698 | Security | Scheduled task created | TaskName, TaskContent (XML) |
| 4699 | Security | Scheduled task deleted | TaskName |
| 4700 | Security | Scheduled task enabled | TaskName |
| 4702 | Security | Scheduled task updated | TaskName, TaskContent |

**Service Name Anomaly Detection:** Flag names matching: random uppercase (^[A-Z]{15,}$), base64-like, known tools (PSEXESVC).

#### Account Management

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4720 | Security | Account created | TargetUserName, SubjectUserName, TargetSid |
| 4722 | Security | Account enabled | TargetUserName |
| 4724 | Security | Password reset | TargetUserName, SubjectUserName |
| 4725 | Security | Account disabled | TargetUserName |
| 4726 | Security | Account deleted | TargetUserName |
| 4728 | Security | Member added to global group | MemberName, TargetUserName (group), SubjectUserName |
| 4732 | Security | Member added to local group | MemberName, TargetUserName (group), SubjectUserName |
| 4733 | Security | Member removed from local group | MemberName, TargetUserName |
| 4738 | Security | User account changed | TargetUserName, SubjectUserName |
| 4740 | Security | Account locked out | TargetUserName, TargetDomainName |
| 4756 | Security | Member added to universal group | MemberName, TargetUserName |
| 4781 | Security | Account renamed | OldTargetUserName, NewTargetUserName |

#### Network & Shares

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 5140 | Security | Network share accessed | ShareName, SubjectUserName, IpAddress |
| 5145 | Security | Share object access checked | ShareName, RelativeTargetName, SubjectUserName, IpAddress, AccessMask |
| 5156 | Security | WFP connection allowed | Application, Direction, SourceAddress, SourcePort, DestAddress, DestPort, Protocol |
| 5157 | Security | WFP connection blocked | Application, Direction, SourceAddress, DestAddress, DestPort |

#### PowerShell

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4104 | PowerShell/Operational | Script block logging | ScriptBlockText, ScriptBlockId, Path |
| 400 | Windows PowerShell | Engine started | HostApplication, HostVersion |
| 403 | Windows PowerShell | Engine stopped | HostApplication |
| 800 | Windows PowerShell | Pipeline execution | UserId, HostApplication |
| 4103 | PowerShell/Operational | Module logging | Payload (cmdlet name + params) |

**PowerShell Decode:** Any content with -enc, -e, -EncodedCommand, or FromBase64String must be automatically Base64 decoded.

#### Sysmon Extended

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 2 | Sysmon | File creation time changed | Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime |
| 3 | Sysmon | Network connection | Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, User |
| 6 | Sysmon | Driver loaded | ImageLoaded, Hashes, Signature, SignatureStatus |
| 7 | Sysmon | Image loaded (DLL) | Image, ImageLoaded, Hashes, Signature |
| 8 | Sysmon | CreateRemoteThread | SourceImage, TargetImage, SourceProcessGuid |
| 10 | Sysmon | Process access | SourceImage, TargetImage, GrantedAccess |
| 11 | Sysmon | File created | Image, TargetFilename |
| 12 | Sysmon | Registry create/delete | EventType, Image, TargetObject |
| 13 | Sysmon | Registry value set | Image, TargetObject, Details |
| 15 | Sysmon | File stream (ADS) | Image, TargetFilename, Contents |
| 17 | Sysmon | Named pipe created | Image, PipeName |
| 18 | Sysmon | Named pipe connected | Image, PipeName |
| 22 | Sysmon | DNS query | Image, QueryName, QueryResults |
| 23 | Sysmon | File delete archived | Image, TargetFilename, Hashes |
| 25 | Sysmon | Process tampering | Image, Type |
| 26 | Sysmon | File delete logged | Image, TargetFilename |

**LSASS Access Detection:** Sysmon EID 10 where TargetImage contains lsass.exe AND GrantedAccess includes 0x1010 or 0x1410 or 0x1FFFFF.

#### Audit & Defense Evasion

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 1102 | Security | Audit log cleared | SubjectUserName, SubjectDomainName |
| 104 | System | Event log cleared | SubjectUserName |
| 4719 | Security | Audit policy changed | SubjectUserName, CategoryId, SubcategoryGuid |

#### Active Directory (Domain Controllers)

| Event ID | Log | Description | Key Fields to Extract |
|----------|-----|-------------|----------------------|
| 4662 | Security | Object accessed | ObjectName, ObjectType, SubjectUserName, AccessMask |
| 4663 | Security | File object accessed | ObjectName, ProcessName, AccessMask |
| 5136 | Security | Directory object modified | ObjectDN, AttributeLDAPDisplayName, OperationType |
| 5137 | Security | Directory object created | ObjectDN, ObjectClass |

### 1.2 Event Log Extraction Requirements

For ALL events:
- Parse TimeCreated to UTC datetime
- Extract EventId as integer
- Extract Provider/Channel name
- Parse ALL EventData fields into key-value pairs
- Handle nested XML payloads (Sysmon vs Security)
- Handle both EVTX native and Excel/CSV from EvtxECmd
- Compute per-EventID counts, flag anomalies
- Build hourly/minute histogram

---

## EVIDENCE TYPE 2: NETWORK CAPTURES (PCAP/PCAPNG)
**Priority: HIGH**

### 2.1 Protocol Extraction

#### HTTP/HTTPS

| Field | tshark Filter | Why It Matters |
|-------|--------------|----------------|
| Request method | http.request.method | GET/POST differentiation |
| Request URI | http.request.uri | Attack paths, webshell access |
| Full URL | http.request.full_uri | Complete request URL |
| Host header | http.host | Target identification |
| User-Agent | http.user_agent | Tool identification |
| Response code | http.response.code | Success/failure |
| Content-Type | http.content_type | File type identification |
| Request body | http.file_data | POST data, uploads |

**HTTP Object Extraction:** Extract all transferred files. Calculate hashes.

#### DNS

| Field | tshark Filter | Why It Matters |
|-------|--------------|----------------|
| Query name | dns.qry.name | Domain lookups |
| Query type | dns.qry.type | A, AAAA, TXT, MX |
| Response addresses | dns.a, dns.aaaa | Resolved IPs |
| Response flags | dns.flags.rcode | NXDOMAIN=recon |

**DNS Anomaly Detection:** DGA, TXT queries (C2), long subdomains (tunneling), non-standard resolvers.

#### SMB/SMB2

| Field | tshark Filter | Why It Matters |
|-------|--------------|----------------|
| Tree connect path | smb2.tree | Share access (ADMIN$, C$, IPC$) |
| File name | smb2.filename | Files accessed/written |
| Write length | smb2.write_length | Data volume |
| Command | smb2.cmd | Create, Read, Write, Close |
| NT Status | smb2.nt_status | Success/failure |

**Lateral Movement:** Flag ADMIN$/C$/IPC$ access, writes to Windows\Temp, PsExec pattern.

#### TLS/SSL

| Field | tshark Filter | Why It Matters |
|-------|--------------|----------------|
| SNI | tls.handshake.extensions_server_name | Domain over HTTPS |
| JA3 | tls.handshake.ja3 | Client fingerprint |
| JA3S | tls.handshake.ja3s | Server fingerprint |

#### Kerberos (Network)

| Field | tshark Filter | Why It Matters |
|-------|--------------|----------------|
| Message type | kerberos.msg_type | AS/TGS requests |
| Client name | kerberos.CNameString | Requesting user |
| Service name | kerberos.SNameString | Target service |
| Encryption type | kerberos.etype | RC4=Kerberoasting |

### 2.2 Network Statistics

- Conversation matrix (src/dst IP, bytes, packets, duration)
- Top talkers, protocol distribution
- External vs internal IP classification
- Port scan and beaconing detection
- GeoIP lookup for external IPs

---

## EVIDENCE TYPE 3: MEMORY DUMPS
**Priority: HIGH**

### 3.1 Volatility 3 Plugins

#### Process Analysis (CRITICAL)

| Plugin | IR Value |
|--------|----------|
| windows.info | OS version, build, architecture |
| windows.pslist | Active process list |
| windows.pstree | Process hierarchy |
| windows.cmdline | Process command lines |
| windows.dlllist | Loaded DLLs per process |
| windows.handles | Open handles |
| windows.envars | Environment variables |
| windows.getsids | Process privilege levels |

#### Malware Detection (HIGH)

| Plugin | IR Value |
|--------|----------|
| windows.malfind | Code injection detection |
| windows.hollowprocesses | Process hollowing |
| windows.suspicious_threads | Thread injection |
| windows.psxview | Hidden processes (DKOM) |

#### Network (HIGH)

| Plugin | IR Value |
|--------|----------|
| windows.netscan | TCP/UDP connections |
| windows.netstat | Active connections |

#### Persistence (HIGH)

| Plugin | IR Value |
|--------|----------|
| windows.svcscan | Registered services |
| windows.svclist | Service details |
| windows.scheduled_tasks | Scheduled tasks |

#### Registry (MEDIUM)

| Plugin | IR Value |
|--------|----------|
| windows.registry.hivelist | Available hives |
| windows.registry.printkey | Key values |
| windows.registry.userassist | Program execution |
| windows.shimcachemem | ShimCache entries |
| windows.amcache | AmCache entries |

#### Credentials (HIGH if authorized)

| Plugin | IR Value |
|--------|----------|
| windows.hashdump | SAM NTLM hashes |
| windows.lsadump | LSA secrets |
| windows.cachedump | Cached domain creds |

#### File System (MEDIUM)

| Plugin | IR Value |
|--------|----------|
| windows.filescan | File objects in memory |
| windows.dumpfiles | Extract files |

#### Advanced (LOWER)

| Plugin | IR Value |
|--------|----------|
| windows.cmdscan | Console history |
| windows.consoles | Full console output |
| windows.callbacks | Kernel callbacks (rootkit) |
| windows.ssdt | SSDT hooking |
| windows.threads | Thread enumeration |
| windows.timers | Kernel timers |
| windows.unloadedmodules | Removed drivers |
| windows.processghosting | Ghost processes |

### 3.2 Memory Analysis Workflow

1. windows.info
2. windows.pslist + pstree
3. windows.cmdline
4. windows.netscan
5. windows.malfind
6. windows.svcscan
7. windows.hashdump
8. windows.registry.hivelist
9. windows.filescan
10. Targeted dumpfiles/printkey

---

## EVIDENCE TYPE 4: WINDOWS ARTIFACTS (Disk/Triage)
**Priority: MEDIUM**

### 4.1 Program Execution Artifacts

| Artifact | Location | Key Fields |
|----------|----------|------------|
| Prefetch | C:\Windows\Prefetch\*.pf | Exe name, run count, last 8 times, referenced files |
| Amcache | C:\Windows\AppCompat\Programs\Amcache.hve | Path, SHA1, first exec time, publisher |
| ShimCache | SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache | Path, size, last modified, position |
| BAM/DAM | SYSTEM\Services\bam\State\UserSettings\{SID} | Path, last exec, user SID |
| UserAssist | NTUSER\...\Explorer\UserAssist\{GUID}\Count | ROT13 path, run count, last run |
| SRUM | C:\Windows\System32\sru\SRUDB.dat | App path, bytes sent/recv, CPU |
| WER | C:\ProgramData\Microsoft\Windows\WER\ | Module name, exception code |

### 4.2 File/Folder Interaction

| Artifact | Location | Key Fields |
|----------|----------|------------|
| LNK Files | C:\Users\{user}\...\Recent\ | Target path, timestamps, volume serial |
| Jump Lists | ...\AutomaticDestinations\ | App ID, target path, timestamps |
| Shellbags | USRCLASS\...\Shell\BagMRU + Bags | Folder path, timestamps |
| RecentDocs | NTUSER\...\Explorer\RecentDocs | MRU per extension |
| Open/Save MRU | NTUSER\...\ComDlg32\OpenSavePidlMRU | Paths from dialogs |

### 4.3 Persistence (Registry)

| Location | Hive |
|----------|------|
| Software\Microsoft\Windows\CurrentVersion\Run | NTUSER + HKLM |
| Software\Microsoft\Windows\CurrentVersion\RunOnce | NTUSER + HKLM |
| SYSTEM\CurrentControlSet\Services\{name} | SYSTEM |
| ...\Winlogon\Shell | HKLM |
| ...\Winlogon\Userinit | HKLM |
| ...\Image File Execution Options\{exe}\Debugger | HKLM |

### 4.4 Browser Artifacts

| Browser | History DB | Key Data |
|---------|-----------|----------|
| Chrome | %LocalAppData%\Google\Chrome\...\History | urls, downloads tables |
| Edge | %LocalAppData%\Microsoft\Edge\...\History | Same as Chrome |
| Firefox | %AppData%\Mozilla\Firefox\Profiles\{}\places.sqlite | moz_places, moz_historyvisits |

### 4.5 System Configuration

| Artifact | Location |
|----------|----------|
| Computer Name | SYSTEM\...\ComputerName |
| Time Zone | SYSTEM\...\TimeZoneInformation |
| Network Interfaces | SYSTEM\...\Tcpip\Parameters\Interfaces\{GUID} |
| OS Version | SOFTWARE\Microsoft\Windows NT\CurrentVersion |
| USB Devices | SYSTEM\...\Enum\USBSTOR |

### 4.6 Filesystem Artifacts

| Artifact | Key Data |
|----------|----------|
| $MFT | All file metadata: MACB timestamps, paths, sizes |
| USN Journal | File changes with timestamps |
| $Recycle.Bin | Deleted files: original path, deletion time |

---

## EVIDENCE TYPE 5: WEB SERVER LOGS
**Priority: HIGH for web compromise**

### 5.1 IIS Fields

| Field | W3C Name | IR Value |
|-------|----------|----------|
| Date/Time | date, time | Timeline |
| Client IP | c-ip | Attacker source |
| Method | cs-method | GET/POST/PUT |
| URI Stem | cs-uri-stem | Paths, webshells |
| URI Query | cs-uri-query | SQLi, command injection |
| Status | sc-status | 200/401/403/500 |
| Bytes | sc-bytes | Exfil volume |
| User-Agent | cs(User-Agent) | Tool identification |

### 5.2 Attack Detection

| Attack | Pattern | Check Fields |
|--------|---------|-------------|
| SQL Injection | UNION SELECT, OR 1=1, xp_cmdshell | query, stem |
| Command Injection | ; ls, && whoami | query |
| Path Traversal | ../, %2e%2e | stem |
| Webshell | .aspx/.php in upload dirs | stem, method |
| Scanner | Nikto/sqlmap/dirbuster UA | user-agent |
| Brute Force | Many 401s same IP | status, IP |

---

## EVIDENCE TYPE 6: PE/MALWARE
**Priority: MEDIUM**

### 6.1 Static Analysis

| Property | IR Value |
|----------|----------|
| Hashes (MD5, SHA1, SHA256) | IOC matching, VT lookup |
| Compile timestamp | Build time |
| Import table | Capability detection |
| Sections + entropy | Packing detection |
| Strings (ASCII+Unicode) | C2 URLs, paths, keys |
| Version info | Masquerading detection |
| Digital signature | Validity check |

### 6.2 Enrichment

| Source | Data |
|--------|------|
| VirusTotal hash | Detections, family, first/last seen |
| VirusTotal behavior | Dropped files, registry, network |
| VirusTotal relations | Contacted domains/IPs |
| AbuseIPDB | Abuse score, ISP, country |
| whois | Owner, ASN, registration |

---

## CROSS-CUTTING CAPABILITIES

### C.1 Deobfuscation

| Technique | Method |
|-----------|--------|
| Base64 | Decode, check UTF-16LE |
| PowerShell -enc | Extract after flag, decode UTF-16LE |
| Hex decode | Remove delimiters, bytes.fromhex() |
| Char removal | Strip # backtick filler |
| String concat | Evaluate joins |
| URL decode | Standard %XX decode |

### C.2 IOC Extraction

| Type | Pattern |
|------|---------|
| IPv4 | \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b |
| Domain | hostname.tld pattern |
| URL | https?:// prefix |
| MD5/SHA1/SHA256 | Hex strings 32/40/64 chars |
| File path | Drive letter + backslash path |
| Registry key | HK prefix + backslash path |

### C.3 Timeline Generation

Unified format from ALL sources: Timestamp(UTC), Source System, Evidence Source, Event Type, Description, Key Entities, Severity, MITRE Technique.

### C.4 LOLBin Detection

| Binary | Suspicious When |
|--------|----------------|
| certutil.exe | -urlcache, -decode |
| mshta.exe | Any execution |
| regsvr32.exe | /s /u /i:http |
| rundll32.exe | DLLs from Temp/Downloads |
| msiexec.exe | /q with remote URL |
| RegSvcs/RegAsm | Non-dev execution |
| wmic.exe | process call create, /node: |
| bitsadmin.exe | /transfer with URL |
| powershell.exe | -enc, -nop, -w hidden, IEX |
| cmd.exe | Child of w3wp/httpd/java |
| schtasks.exe | /create suspicious |
| net.exe | user /add, localgroup admin |
| nltest.exe | /dclist, /domain_trusts |

---

## PRIORITY BUILD ORDER

**Phase 1 (CRITICAL, covers 80%):**
1. EVTX full event ID extraction with all fields
2. Timeline generation from EVTX
3. IOC auto-extraction
4. Base64/PowerShell deobfuscation
5. IIS/web log parsing with attack detection

**Phase 2 (HIGH, covers next 10%):**
6. PCAP: HTTP, DNS, SMB, TLS extraction
7. Volatility 3 core: info, pslist, pstree, cmdline, netscan, malfind
8. PE static analysis: hashes, imports, strings, timestamps
9. VirusTotal API enrichment
10. LOLBin detection

**Phase 3 (MEDIUM, covers next 4%):**
11. Full Volatility plugin set
12. Prefetch, Amcache, ShimCache parsing
13. Browser history: Chrome, Edge, Firefox
14. Registry persistence checks
15. PCAP remaining: Kerberos, RDP, SMTP, FTP

**Phase 4 (ENHANCEMENT, final 1%):**
16. MFT/USN journal parsing
17. Shellbags, Jump Lists, LNK
18. SRUM database
19. Advanced Volatility: callbacks, SSDT, timers
20. Hex/XOR deobfuscation

---

## AGENT ARCHITECTURE NOTE

Keep agents independent with a synthesis layer:
- 10 specialized agents analyze their domain in parallel
- 1 synthesizer combines ALL findings into attack chain
- Add SECOND synthesizer pass for: conflicting findings, timeline gaps, unlinked events, missing MITRE techniques
- The synthesizer IS the team lead
- Do NOT have agents communicate with each other (context overhead, dependency chains, error propagation)

---

*Version 1.0 | Created 2026-03-03*
*Sources: SANS FOR500, MITRE ATT&CK v18, Volatility 3 v2.27, DFIR community*
*Total extraction functions: ~250-300 across all evidence types*
