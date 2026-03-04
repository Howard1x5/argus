"""Constants for ForensicExtractor.

Contains lookup tables, event ID mappings, and detection patterns
for EVTX parsing and forensic analysis.
"""

# =============================================================================
# S1.1: Logon Type Mappings
# =============================================================================
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

# =============================================================================
# S1.3: Account Management Event Mappings
# =============================================================================
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

# Privileged groups that escalate severity to CRITICAL when modified
PRIVILEGED_GROUPS = [
    "Admin",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Backup Operators",
    "Remote Desktop Users",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
]

# =============================================================================
# S1.6: Sysmon Event Mappings
# =============================================================================
SYSMON_EVENTS = {
    1: {"desc": "Process creation", "fields": ["Image", "CommandLine", "ParentImage", "User", "Hashes"], "severity": "LOW"},
    2: {"desc": "File creation time changed", "fields": ["Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"], "severity": "HIGH"},
    3: {"desc": "Network connection", "fields": ["Image", "DestinationIp", "DestinationPort", "Protocol"], "severity": "LOW"},
    6: {"desc": "Driver loaded", "fields": ["ImageLoaded", "Hashes", "Signature", "SignatureStatus"], "severity": "MEDIUM"},
    7: {"desc": "Image loaded (DLL)", "fields": ["Image", "ImageLoaded", "Hashes", "Signature"], "severity": "LOW"},
    8: {"desc": "CreateRemoteThread", "fields": ["SourceImage", "TargetImage", "SourceProcessGuid"], "severity": "HIGH"},
    10: {"desc": "Process access", "fields": ["SourceImage", "TargetImage", "GrantedAccess"], "severity": "MEDIUM"},
    11: {"desc": "File created", "fields": ["Image", "TargetFilename", "Hashes"], "severity": "LOW"},
    12: {"desc": "Registry object added/deleted", "fields": ["Image", "TargetObject", "EventType"], "severity": "LOW"},
    13: {"desc": "Registry value set", "fields": ["Image", "TargetObject", "Details"], "severity": "LOW"},
    15: {"desc": "File stream (ADS)", "fields": ["Image", "TargetFilename", "Contents"], "severity": "HIGH"},
    17: {"desc": "Named pipe created", "fields": ["Image", "PipeName"], "severity": "MEDIUM"},
    18: {"desc": "Named pipe connected", "fields": ["Image", "PipeName"], "severity": "MEDIUM"},
    22: {"desc": "DNS query", "fields": ["Image", "QueryName", "QueryResults"], "severity": "LOW"},
    23: {"desc": "File delete archived", "fields": ["Image", "TargetFilename", "Hashes"], "severity": "MEDIUM"},
    25: {"desc": "Process tampering", "fields": ["Image", "Type"], "severity": "CRITICAL"},
}

# LSASS access masks that indicate credential dumping
LSASS_SUSPICIOUS_ACCESS_MASKS = [
    "0x1010",     # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    "0x1410",     # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
    "0x1FFFFF",   # PROCESS_ALL_ACCESS
    "0x01410",    # Alternate format
    "0x001010",   # Alternate format
    "0x1038",     # Common mimikatz pattern
    "0x1000",     # PROCESS_QUERY_LIMITED_INFORMATION
]

# =============================================================================
# S1.9: LOLBin Detection Patterns
# =============================================================================
LOLBIN_PATTERNS = [
    {
        "binary": "certutil.exe",
        "suspicious_args": ["-urlcache", "-decode", "-encode", "-decodehex", "-verifyctl"],
        "severity": "HIGH",
        "mitre": "T1140",
        "description": "Certificate utility abuse for download/decode",
    },
    {
        "binary": "mshta.exe",
        "suspicious_args": None,  # Any execution is suspicious
        "severity": "HIGH",
        "mitre": "T1218.005",
        "description": "HTML Application execution",
    },
    {
        "binary": "regsvr32.exe",
        "suspicious_args": ["/s", "/u", "/i:http", "scrobj.dll"],
        "severity": "HIGH",
        "mitre": "T1218.010",
        "description": "Regsvr32 proxy execution",
    },
    {
        "binary": "rundll32.exe",
        "suspicious_dirs": ["\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\ProgramData\\", "\\Public\\"],
        "severity": "HIGH",
        "mitre": "T1218.011",
        "description": "Rundll32 execution from suspicious location",
    },
    {
        "binary": "msiexec.exe",
        "suspicious_args": ["/q", "http://", "https://", "/i http", "/i https"],
        "severity": "HIGH",
        "mitre": "T1218.007",
        "description": "MSI installer abuse",
    },
    {
        "binary": "regsvcs.exe",
        "suspicious_args": None,
        "severity": "MEDIUM",
        "mitre": "T1218.009",
        "description": ".NET services registration utility",
    },
    {
        "binary": "regasm.exe",
        "suspicious_args": None,
        "severity": "MEDIUM",
        "mitre": "T1218.009",
        "description": ".NET assembly registration utility",
    },
    {
        "binary": "installutil.exe",
        "suspicious_args": None,
        "severity": "MEDIUM",
        "mitre": "T1218.004",
        "description": ".NET installation utility",
    },
    {
        "binary": "wmic.exe",
        "suspicious_args": ["process call create", "/node:", "os get", "/format:"],
        "severity": "HIGH",
        "mitre": "T1047",
        "description": "WMI command execution",
    },
    {
        "binary": "bitsadmin.exe",
        "suspicious_args": ["/transfer", "/create", "/addfile", "/resume"],
        "severity": "HIGH",
        "mitre": "T1197",
        "description": "BITS job abuse for download",
    },
    {
        "binary": "schtasks.exe",
        "suspicious_args": ["/create"],
        "severity": "MEDIUM",
        "mitre": "T1053.005",
        "description": "Scheduled task creation",
    },
    {
        "binary": "net.exe",
        "suspicious_args": ["user /add", "localgroup administrators /add", 'group "Domain Admins"', "user /domain", "accounts /domain"],
        "severity": "HIGH",
        "mitre": "T1136.001",
        "description": "Net command for user/group manipulation",
    },
    {
        "binary": "net1.exe",
        "suspicious_args": ["user /add", "localgroup administrators /add"],
        "severity": "HIGH",
        "mitre": "T1136.001",
        "description": "Net1 command for user/group manipulation",
    },
    {
        "binary": "nltest.exe",
        "suspicious_args": ["/dclist", "/domain_trusts", "/dsgetdc", "/trusted_domains"],
        "severity": "MEDIUM",
        "mitre": "T1482",
        "description": "Domain trust enumeration",
    },
    {
        "binary": "dsquery.exe",
        "suspicious_args": None,
        "severity": "MEDIUM",
        "mitre": "T1018",
        "description": "Active Directory query",
    },
    {
        "binary": "cscript.exe",
        "suspicious_dirs": ["\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\Public\\"],
        "severity": "MEDIUM",
        "mitre": "T1059.005",
        "description": "VBScript execution from suspicious location",
    },
    {
        "binary": "wscript.exe",
        "suspicious_dirs": ["\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\Public\\"],
        "severity": "MEDIUM",
        "mitre": "T1059.005",
        "description": "VBScript execution from suspicious location",
    },
    {
        "binary": "powershell.exe",
        "suspicious_args": [
            "-nop", "-w hidden", "-ep bypass", "-executionpolicy bypass",
            "IEX", "Invoke-Expression", "downloadstring", "Net.WebClient",
            "-enc", "-encodedcommand", "FromBase64String", "DownloadFile",
            "Start-BitsTransfer", "Invoke-WebRequest", "iwr", "curl",
            "-WindowStyle Hidden", "bypass", "-noni", "-noninteractive",
        ],
        "severity": "HIGH",
        "mitre": "T1059.001",
        "description": "PowerShell suspicious execution",
    },
    {
        "binary": "cmd.exe",
        "suspicious_args": ["/c echo", "/c powershell", "^", "%%", "|", "&"],
        "severity": "MEDIUM",
        "mitre": "T1059.003",
        "description": "Command shell with obfuscation/chaining",
    },
    {
        "binary": "msbuild.exe",
        "suspicious_args": None,
        "severity": "HIGH",
        "mitre": "T1127.001",
        "description": "MSBuild inline task execution",
    },
    {
        "binary": "cmstp.exe",
        "suspicious_args": ["/s", "/ni", "/au"],
        "severity": "HIGH",
        "mitre": "T1218.003",
        "description": "CMSTP UAC bypass",
    },
    {
        "binary": "forfiles.exe",
        "suspicious_args": ["/c", "cmd", "powershell"],
        "severity": "MEDIUM",
        "mitre": "T1202",
        "description": "Forfiles indirect command execution",
    },
    {
        "binary": "pcalua.exe",
        "suspicious_args": ["-a"],
        "severity": "HIGH",
        "mitre": "T1202",
        "description": "Program Compatibility Assistant proxy execution",
    },
]

# =============================================================================
# S3.1: Web Attack Patterns
# =============================================================================
WEB_ATTACK_PATTERNS = [
    {
        "name": "SQL Injection",
        "patterns": [
            "UNION SELECT", "UNION ALL SELECT", "' OR 1=1", "' OR '1'='1",
            "WAITFOR DELAY", "xp_cmdshell", "INFORMATION_SCHEMA", "sysobjects",
            "BENCHMARK(", "SLEEP(", "' AND '", "1=1--", "' OR ''='",
            "CAST(", "CONVERT(", "@@version", "sys.databases",
        ],
        "fields": ["uri_query", "uri_stem"],
        "severity": "CRITICAL",
        "mitre": "T1190",
    },
    {
        "name": "Command Injection",
        "patterns": [
            "; ls", "| cat ", "&& whoami", "; id", "| nc ", "; wget ", "; curl ",
            "%0a", "`id`", "$(whoami)", "${IFS}", "; ping ", "| bash",
        ],
        "fields": ["uri_query"],
        "severity": "CRITICAL",
        "mitre": "T1059",
    },
    {
        "name": "Path Traversal",
        "patterns": [
            "../", "..\\", "%2e%2e%2f", "%2e%2e/", "....//", "..%2f",
            "..%5c", "%252e%252e%252f", "....\\\\",
        ],
        "fields": ["uri_stem", "uri_query"],
        "severity": "HIGH",
        "mitre": "T1083",
    },
    {
        "name": "XSS",
        "patterns": [
            "<script", "javascript:", "onerror=", "onload=", "onclick=",
            "<img src", "<svg", "alert(", "document.cookie", "eval(",
        ],
        "fields": ["uri_query"],
        "severity": "HIGH",
        "mitre": "T1189",
    },
    {
        "name": "Local File Inclusion",
        "patterns": [
            "/etc/passwd", "/etc/shadow", "boot.ini", "win.ini",
            "php://filter", "php://input", "expect://", "data://",
        ],
        "fields": ["uri_stem", "uri_query"],
        "severity": "HIGH",
        "mitre": "T1083",
    },
    {
        "name": "Remote File Inclusion",
        "patterns": [
            "=http://", "=https://", "=ftp://",
        ],
        "fields": ["uri_query"],
        "severity": "CRITICAL",
        "mitre": "T1105",
    },
]

SCANNER_USER_AGENTS = [
    "nikto", "sqlmap", "dirbuster", "gobuster", "wfuzz", "burp",
    "nmap", "masscan", "zgrab", "nuclei", "httpx", "ffuf",
    "acunetix", "nessus", "openvas", "qualys", "w3af", "skipfish",
    "arachni", "zap", "owasp", "spider", "crawler", "scanner",
]

# =============================================================================
# Network Share Event Constants
# =============================================================================
SUSPICIOUS_SHARES = ["ADMIN$", "C$", "IPC$", "D$", "E$", "SYSVOL", "NETLOGON"]

# =============================================================================
# Kerberos Encryption Types
# =============================================================================
KERBEROS_ENCRYPTION_TYPES = {
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS-HMAC-SHA1-96",
    "0x12": "AES256-CTS-HMAC-SHA1-96",
    "0x17": "RC4-HMAC",  # Suspicious - Kerberoasting indicator
    "0x18": "RC4-HMAC-EXP",
}

# RC4 encryption type indicates Kerberoasting
KERBEROASTING_ENCRYPTION_TYPE = "0x17"
