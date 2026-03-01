"""
STAGE 4: PATTERN DETECTION

Goal: Match evidence against known attack signatures and IR-relevant patterns.

Steps:
- 4.1: Signature Matcher (4 substeps)
- 4.2: Event ID Analyzer (4 substeps)
- 4.3: MITRE Technique Detector (3 substeps)
- 4.4: IOC Scanner (4 substeps)

Total: 16 substeps
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


# =============================================================================
# PATTERN DEFINITIONS (Step 4.1.1)
# =============================================================================

@dataclass
class Pattern:
    """Defines a detection pattern."""
    name: str
    regex: str
    compiled: re.Pattern
    target_fields: List[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_technique: Optional[str]
    description: str


# Built-in pattern library
PATTERN_LIBRARY = [
    # Credential Dumping
    ("procdump_lsass", r"(?:procdump|pd)(?:64)?\.exe.*?(?:-ma|-accepteula).*?(?:lsass|588)", ["command_line"], "CRITICAL", "T1003.001", "ProcDump targeting LSASS for credential dumping"),
    ("mimikatz", r"(?:mimikatz|sekurlsa|logonpasswords)", ["command_line", "process_name"], "CRITICAL", "T1003", "Mimikatz credential dumping tool"),
    ("ntds_dit", r"(?:ntds\.dit|ntdsutil)", ["command_line", "target_filename"], "CRITICAL", "T1003.003", "NTDS.dit access (domain credential extraction)"),
    ("sam_dump", r"(?:reg\s+save.*?sam|secretsdump)", ["command_line"], "CRITICAL", "T1003.002", "SAM database extraction"),

    # Lateral Movement
    ("invoke_wmiexec", r"Invoke-WMIExec", ["command_line"], "CRITICAL", "T1047", "PowerShell WMI execution for lateral movement"),
    ("invoke_smbexec", r"Invoke-SMBExec", ["command_line"], "CRITICAL", "T1021.002", "PowerShell SMB execution for lateral movement"),
    ("invoke_psexec", r"(?:Invoke-PSExec|PsExec)", ["command_line", "process_name"], "CRITICAL", "T1569.002", "PSExec lateral movement"),
    ("wmic_process", r"wmic.*?(?:process\s+call\s+create|/node:)", ["command_line"], "HIGH", "T1047", "WMIC remote process creation"),
    ("psexec_service", r"PSEXESVC", ["service_name"], "HIGH", "T1569.002", "PSExec service indicator"),

    # Webshell Indicators
    ("webshell_aspx", r"(?:forbiden|cmd|shell|hack|c99|r57|b374k)\.aspx?", ["uri", "target_filename"], "CRITICAL", "T1505.003", "Known webshell filename"),
    ("w3wp_child", r"w3wp\.exe.*?(?:cmd|powershell|whoami|net|ipconfig)", ["command_line", "parent_process_name"], "CRITICAL", "T1505.003", "IIS worker spawning suspicious child"),
    ("webshell_cmd_param", r"cmd=|exec=|command=|c=", ["query_string", "uri"], "HIGH", "T1505.003", "Webshell command parameter"),

    # Reconnaissance
    ("recon_whoami", r"whoami(?:\.exe)?(?:\s+/all)?", ["command_line"], "MEDIUM", "T1033", "User identity discovery"),
    ("recon_ipconfig", r"ipconfig(?:\.exe)?(?:\s+/all)?", ["command_line"], "MEDIUM", "T1016", "Network configuration discovery"),
    ("recon_net_user", r"net(?:1)?\.exe\s+(?:user|group|localgroup)", ["command_line"], "MEDIUM", "T1087", "Account discovery"),
    ("recon_systeminfo", r"systeminfo(?:\.exe)?", ["command_line"], "MEDIUM", "T1082", "System information discovery"),
    ("recon_tasklist", r"tasklist(?:\.exe)?", ["command_line"], "LOW", "T1057", "Process discovery"),
    ("recon_netstat", r"netstat(?:\.exe)?", ["command_line"], "LOW", "T1049", "Network connections discovery"),

    # Persistence
    ("schtasks_create", r"schtasks(?:\.exe)?\s+/create", ["command_line"], "HIGH", "T1053.005", "Scheduled task creation"),
    ("reg_run_key", r"reg(?:\.exe)?\s+add.*?(?:Run|RunOnce)", ["command_line"], "HIGH", "T1547.001", "Registry run key persistence"),
    ("service_create", r"sc(?:\.exe)?\s+create", ["command_line"], "HIGH", "T1543.003", "Service creation"),
    ("random_service_name", r"^[A-Z]{20}$", ["service_name"], "CRITICAL", "T1543.003", "Randomly named service (SMBExec indicator)"),

    # Defense Evasion
    ("event_log_clear", r"(?:wevtutil.*?cl|Clear-EventLog)", ["command_line"], "CRITICAL", "T1070.001", "Event log clearing"),
    ("disable_defender", r"(?:Set-MpPreference.*?DisableRealtimeMonitoring|sc\s+stop\s+WinDefend)", ["command_line"], "CRITICAL", "T1562.001", "Disabling Windows Defender"),
    ("timestomp", r"(?:timestomp|touch.*?-t|-SetCreationTime)", ["command_line"], "HIGH", "T1070.006", "Timestamp modification"),

    # Execution
    ("encoded_powershell", r"powershell.*?(?:-enc|-encodedcommand|-e\s)", ["command_line"], "HIGH", "T1059.001", "Encoded PowerShell execution"),
    ("download_cradle", r"(?:DownloadString|DownloadFile|Invoke-WebRequest|wget|curl).*?http", ["command_line"], "HIGH", "T1105", "Download cradle"),
    ("certutil_download", r"certutil.*?(?:-urlcache|-split)", ["command_line"], "HIGH", "T1105", "Certutil file download"),
    ("bitsadmin_download", r"bitsadmin.*?/transfer", ["command_line"], "HIGH", "T1105", "BITS file download"),

    # Collection
    ("archive_compress", r"(?:7z|rar|zip|tar).*?(?:-p|password)", ["command_line"], "MEDIUM", "T1560", "Password-protected archive creation"),
    ("clipboard_access", r"(?:Get-Clipboard|clip\.exe)", ["command_line"], "LOW", "T1115", "Clipboard access"),

    # Impact
    ("ransomware_extension", r"\.(?:encrypted|locked|crypt|enc|WNCRY|locky)", ["target_filename"], "CRITICAL", "T1486", "Ransomware file extension"),
    ("volume_shadow_delete", r"(?:vssadmin.*?delete|wmic.*?shadowcopy.*?delete)", ["command_line"], "CRITICAL", "T1490", "Volume shadow copy deletion"),
]


# =============================================================================
# EVENT ID DATABASE (Step 4.2.1)
# =============================================================================

EVENT_ID_DATABASE = {
    # Security Events
    4624: {"name": "Successful Logon", "category": "Credential", "significance": "INFO", "expected_volume": 1000},
    4625: {"name": "Failed Logon", "category": "Credential", "significance": "MEDIUM", "expected_volume": 50},
    4634: {"name": "Logoff", "category": "Credential", "significance": "INFO", "expected_volume": 1000},
    4648: {"name": "Explicit Credential Logon", "category": "Credential", "significance": "HIGH", "expected_volume": 10},
    4672: {"name": "Admin Logon", "category": "Credential", "significance": "MEDIUM", "expected_volume": 100},
    4688: {"name": "Process Created", "category": "Execution", "significance": "INFO", "expected_volume": 5000},
    4697: {"name": "Service Installed", "category": "Persistence", "significance": "HIGH", "expected_volume": 5},
    4698: {"name": "Scheduled Task Created", "category": "Persistence", "significance": "HIGH", "expected_volume": 5},
    4720: {"name": "User Created", "category": "Persistence", "significance": "HIGH", "expected_volume": 1},
    4732: {"name": "User Added to Group", "category": "Persistence", "significance": "HIGH", "expected_volume": 2},
    4768: {"name": "Kerberos TGT Request", "category": "Credential", "significance": "INFO", "expected_volume": 500},
    4769: {"name": "Kerberos TGS Request", "category": "Credential", "significance": "MEDIUM", "expected_volume": 100},
    4771: {"name": "Kerberos Pre-Auth Failed", "category": "Credential", "significance": "HIGH", "expected_volume": 10},
    4776: {"name": "Credential Validation", "category": "Credential", "significance": "INFO", "expected_volume": 1000},
    7045: {"name": "Service Installed", "category": "Persistence", "significance": "HIGH", "expected_volume": 5},
    1102: {"name": "Audit Log Cleared", "category": "Defense Evasion", "significance": "CRITICAL", "expected_volume": 0},

    # Sysmon Events
    1: {"name": "Process Create", "category": "Execution", "significance": "INFO", "expected_volume": 5000},
    3: {"name": "Network Connection", "category": "Lateral", "significance": "MEDIUM", "expected_volume": 1000},
    7: {"name": "Image Loaded", "category": "Execution", "significance": "LOW", "expected_volume": 10000},
    8: {"name": "CreateRemoteThread", "category": "Execution", "significance": "HIGH", "expected_volume": 10},
    10: {"name": "Process Access", "category": "Credential", "significance": "MEDIUM", "expected_volume": 100},
    11: {"name": "File Create", "category": "Collection", "significance": "LOW", "expected_volume": 5000},
    12: {"name": "Registry Create/Delete", "category": "Persistence", "significance": "MEDIUM", "expected_volume": 500},
    13: {"name": "Registry Value Set", "category": "Persistence", "significance": "MEDIUM", "expected_volume": 500},
    15: {"name": "File Stream Created", "category": "Collection", "significance": "MEDIUM", "expected_volume": 100},
    17: {"name": "Pipe Created", "category": "Lateral", "significance": "MEDIUM", "expected_volume": 50},
    18: {"name": "Pipe Connected", "category": "Lateral", "significance": "MEDIUM", "expected_volume": 50},
    22: {"name": "DNS Query", "category": "Discovery", "significance": "LOW", "expected_volume": 5000},
    23: {"name": "File Delete", "category": "Defense Evasion", "significance": "LOW", "expected_volume": 500},
}


# =============================================================================
# MITRE DETECTION RULES (Step 4.3.1)
# =============================================================================

MITRE_DETECTION_RULES = [
    {
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory",
        "tactic": "Credential Access",
        "required_indicators": ["procdump_lsass OR mimikatz"],
        "supporting_indicators": ["process_access_lsass", "suspicious_handle"],
    },
    {
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "tactic": "Persistence",
        "required_indicators": ["w3wp_child"],
        "supporting_indicators": ["webshell_aspx", "webshell_cmd_param"],
    },
    {
        "technique_id": "T1047",
        "technique_name": "WMI",
        "tactic": "Execution",
        "required_indicators": ["invoke_wmiexec OR wmic_process"],
        "supporting_indicators": ["wmiprvse_spawn"],
    },
    {
        "technique_id": "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "required_indicators": ["invoke_smbexec OR psexec_service"],
        "supporting_indicators": ["random_service_name"],
    },
    {
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic": "Persistence",
        "required_indicators": ["service_create OR event_7045"],
        "supporting_indicators": ["random_service_name"],
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "required_indicators": ["encoded_powershell"],
        "supporting_indicators": ["download_cradle"],
    },
    {
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "required_indicators": ["event_log_clear OR event_1102"],
        "supporting_indicators": [],
    },
]


def run(context) -> None:
    """Execute Stage 4: Pattern Detection."""
    logger.info("Stage 4: Pattern Detection starting")

    df = context.unified_df

    # Step 4.1: Signature Matcher
    pattern_matches = step_4_1_signature_matcher(df)
    context.pattern_matches = pattern_matches
    logger.info(f"Step 4.1: Found {len(pattern_matches)} pattern matches")

    # Step 4.2: Event ID Analyzer
    event_id_analysis = step_4_2_event_id_analyzer(df)
    context.event_id_analysis = event_id_analysis
    logger.info(f"Step 4.2: Analyzed {len(event_id_analysis.get('event_counts', {}))} event types")

    # Step 4.3: MITRE Technique Detector
    mitre_detections = step_4_3_mitre_detector(pattern_matches, event_id_analysis)
    context.mitre_detections = mitre_detections
    detected_count = sum(1 for m in mitre_detections if m['status'] in ['CONFIRMED', 'LIKELY'])
    logger.info(f"Step 4.3: Detected {detected_count} MITRE techniques")

    # Step 4.4: IOC Scanner
    iocs = step_4_4_ioc_scanner(df, context)
    context.iocs = iocs
    logger.info(f"Step 4.4: Extracted {len(iocs)} IOCs")

    # Update statistics
    context.statistics['stage4'] = {
        'pattern_matches': len(pattern_matches),
        'critical_matches': sum(1 for m in pattern_matches if m['severity'] == 'CRITICAL'),
        'high_matches': sum(1 for m in pattern_matches if m['severity'] == 'HIGH'),
        'mitre_techniques_detected': detected_count,
        'iocs_extracted': len(iocs),
    }

    logger.info("Stage 4: Pattern Detection completed")


# =============================================================================
# STEP 4.1: SIGNATURE MATCHER
# =============================================================================

def step_4_1_signature_matcher(df) -> List[Dict]:
    """
    Match patterns against evidence.

    Substeps:
    4.1.1: Load Pattern Library
    4.1.2: Group by Target Field
    4.1.3: Execute Matching
    4.1.4: Deduplicate
    """

    # Substep 4.1.1: Load Pattern Library (compile regexes)
    patterns = []
    for p in PATTERN_LIBRARY:
        name, regex, fields, severity, mitre, desc = p
        try:
            compiled = re.compile(regex, re.IGNORECASE)
            patterns.append(Pattern(
                name=name,
                regex=regex,
                compiled=compiled,
                target_fields=fields,
                severity=severity,
                mitre_technique=mitre,
                description=desc,
            ))
        except re.error as e:
            logger.warning(f"Invalid pattern {name}: {e}")

    logger.debug(f"Substep 4.1.1: Compiled {len(patterns)} patterns")

    # Substep 4.1.2: Group by Target Field
    field_patterns = {}
    for p in patterns:
        for field in p.target_fields:
            if field not in field_patterns:
                field_patterns[field] = []
            field_patterns[field].append(p)

    # Substep 4.1.3: Execute Matching
    matches = []
    for field, field_pats in field_patterns.items():
        if field not in df.columns:
            continue

        for idx, val in df[field].items():
            if pd.isna(val):
                continue

            val_str = str(val)
            for pattern in field_pats:
                match = pattern.compiled.search(val_str)
                if match:
                    matches.append({
                        'row_index': idx,
                        'column': field,
                        'pattern_name': pattern.name,
                        'matched_text': match.group(),
                        'full_value': val_str[:500],
                        'severity': pattern.severity,
                        'mitre': pattern.mitre_technique,
                        'description': pattern.description,
                        'timestamp': df.iloc[idx].get('timestamp_utc') if idx < len(df) else None,
                        'source_system': df.iloc[idx].get('source_system') if idx < len(df) else None,
                    })

    logger.debug(f"Substep 4.1.3: Found {len(matches)} raw matches")

    # Substep 4.1.4: Deduplicate (group by row)
    row_matches = {}
    for m in matches:
        row_idx = m['row_index']
        if row_idx not in row_matches:
            row_matches[row_idx] = {
                'row_index': row_idx,
                'matches': [],
                'severities': set(),
                'patterns': set(),
            }
        row_matches[row_idx]['matches'].append(m)
        row_matches[row_idx]['severities'].add(m['severity'])
        row_matches[row_idx]['patterns'].add(m['pattern_name'])

    # Flatten back to list but with dedup info
    deduped = []
    for row_idx, info in row_matches.items():
        for m in info['matches']:
            m['row_match_count'] = len(info['matches'])
            m['row_severities'] = list(info['severities'])
            deduped.append(m)

    return deduped


# =============================================================================
# STEP 4.2: EVENT ID ANALYZER
# =============================================================================

def step_4_2_event_id_analyzer(df) -> Dict:
    """
    Analyze event ID distribution and significance.

    Substeps:
    4.2.1: Load Event ID Database
    4.2.2: Count Per Event ID Per System
    4.2.3: Flag Significant Volumes
    4.2.4: Map to IR Domains
    """

    result = {
        'event_counts': {},
        'flagged_events': [],
        'missing_events': [],
        'domain_findings': {},
    }

    # Substep 4.2.1: Already loaded as EVENT_ID_DATABASE

    # Substep 4.2.2: Count Per Event ID Per System
    if 'event_id' not in df.columns:
        return result

    counts = df.groupby(['source_system', 'event_id']).size().reset_index(name='count')

    for _, row in counts.iterrows():
        system = row['source_system']
        event_id = int(row['event_id'])
        count = row['count']

        key = f"{system}_{event_id}"
        result['event_counts'][key] = {
            'system': system,
            'event_id': event_id,
            'count': count,
            'info': EVENT_ID_DATABASE.get(event_id, {}),
        }

    # Substep 4.2.3: Flag Significant Volumes
    for key, data in result['event_counts'].items():
        event_id = data['event_id']
        count = data['count']
        info = data['info']

        if not info:
            continue

        significance = info.get('significance', 'INFO')
        expected = info.get('expected_volume', 1000)

        # Flag if count significantly exceeds expected
        if count > expected * 2 and significance in ['MEDIUM', 'HIGH', 'CRITICAL']:
            result['flagged_events'].append({
                'event_id': event_id,
                'system': data['system'],
                'count': count,
                'expected': expected,
                'reason': 'volume_exceeded',
                'significance': significance,
                'name': info.get('name', 'Unknown'),
            })

        # Always flag CRITICAL/HIGH events at any count
        if significance in ['CRITICAL', 'HIGH']:
            result['flagged_events'].append({
                'event_id': event_id,
                'system': data['system'],
                'count': count,
                'significance': significance,
                'name': info.get('name', 'Unknown'),
                'category': info.get('category', 'Unknown'),
            })

    # Check for missing expected events
    systems = df['source_system'].unique()
    for system in systems:
        system_events = set(df[df['source_system'] == system]['event_id'].unique())

        # Check for missing critical events
        for eid, info in EVENT_ID_DATABASE.items():
            if info.get('significance') == 'CRITICAL' and eid not in system_events:
                result['missing_events'].append({
                    'event_id': eid,
                    'system': system,
                    'name': info.get('name'),
                    'note': 'Expected but not present',
                })

    # Substep 4.2.4: Map to IR Domains
    domains = {}
    for item in result['flagged_events']:
        category = item.get('category', EVENT_ID_DATABASE.get(item['event_id'], {}).get('category', 'Unknown'))
        if category not in domains:
            domains[category] = []
        domains[category].append(item)

    result['domain_findings'] = domains

    return result


# =============================================================================
# STEP 4.3: MITRE TECHNIQUE DETECTOR
# =============================================================================

def step_4_3_mitre_detector(pattern_matches: List[Dict], event_analysis: Dict) -> List[Dict]:
    """
    Detect MITRE techniques based on collected evidence.

    Substeps:
    4.3.1: Load Detection Rules (built-in)
    4.3.2: Evaluate Each Technique
    4.3.3: Build Coverage Map
    """

    detections = []

    # Get all matched pattern names
    matched_patterns = set(m['pattern_name'] for m in pattern_matches)

    # Get all flagged event IDs
    flagged_event_ids = set()
    for item in event_analysis.get('flagged_events', []):
        flagged_event_ids.add(f"event_{item['event_id']}")

    all_indicators = matched_patterns | flagged_event_ids

    # Substep 4.3.2: Evaluate Each Technique
    for rule in MITRE_DETECTION_RULES:
        required = rule['required_indicators']
        supporting = rule['supporting_indicators']

        # Parse required indicators (supports OR)
        required_met = 0
        total_required = 0

        for req in required:
            total_required += 1
            # Handle OR conditions
            if ' OR ' in req:
                sub_reqs = req.split(' OR ')
                if any(sr.strip() in all_indicators for sr in sub_reqs):
                    required_met += 1
            else:
                if req in all_indicators:
                    required_met += 1

        # Count supporting indicators
        supporting_met = sum(1 for s in supporting if s in all_indicators)

        # Determine status
        if total_required > 0:
            if required_met == total_required:
                status = 'CONFIRMED'
            elif required_met >= total_required * 0.5:
                status = 'LIKELY'
            elif supporting_met > 0:
                status = 'POSSIBLE'
            else:
                status = 'NOT_DETECTED'
        else:
            status = 'NOT_DETECTED'

        detections.append({
            'technique_id': rule['technique_id'],
            'technique_name': rule['technique_name'],
            'tactic': rule['tactic'],
            'status': status,
            'required_met': required_met,
            'total_required': total_required,
            'supporting_met': supporting_met,
            'evidence_patterns': [p for p in matched_patterns if any(p in req for req in required)],
        })

    return detections


# =============================================================================
# STEP 4.4: IOC SCANNER
# =============================================================================

def step_4_4_ioc_scanner(df, context) -> List[Dict]:
    """
    Extract and classify IOCs.

    Substeps:
    4.4.1: Extract Raw IOCs
    4.4.2: Classify and Deduplicate
    4.4.3: Determine IOC Context
    4.4.4: Score Preliminary Risk
    """

    iocs = []
    ioc_set = {}  # For deduplication

    # Regex patterns for IOC extraction
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b')
    url_pattern = re.compile(r'https?://[^\s<>"]+')
    hash_patterns = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }

    # Substep 4.4.1: Extract Raw IOCs

    # First, extract from dedicated IP columns
    ip_columns = ['source_ip', 'dest_ip', 'src_ip', 'dst_ip', 'remote_ip', 'target_ip']
    for col in ip_columns:
        if col in df.columns:
            for idx, val in df[col].items():
                if pd.notna(val):
                    val_str = str(val)
                    # Check if it's a valid IPv4
                    if ipv4_pattern.match(val_str):
                        _add_ioc(ioc_set, 'ipv4', val_str, col, idx, df)

    # Then scan text columns
    text_cols = [c for c in df.columns if df[c].dtype == 'object']

    for col in text_cols:
        for idx, val in df[col].items():
            if pd.isna(val):
                continue

            val_str = str(val)

            # Extract IPs
            for ip in ipv4_pattern.findall(val_str):
                _add_ioc(ioc_set, 'ipv4', ip, col, idx, df)

            # Extract URLs
            for url in url_pattern.findall(val_str):
                _add_ioc(ioc_set, 'url', url, col, idx, df)

            # Extract domains (from URLs and standalone)
            for domain in domain_pattern.findall(val_str):
                # Skip internal/common domains
                if not any(x in domain.lower() for x in ['localhost', 'internal', '.local', 'microsoft.com', 'windows.com']):
                    _add_ioc(ioc_set, 'domain', domain, col, idx, df)

            # Extract hashes
            for hash_type, pattern in hash_patterns.items():
                for h in pattern.findall(val_str):
                    _add_ioc(ioc_set, hash_type, h, col, idx, df)

    # Also check decoded content
    for decoded in context.decoded_content_index:
        for ip in decoded.contains_ips:
            _add_ioc(ioc_set, 'ipv4', ip, 'decoded_content', decoded.source_row, df)
        for url in decoded.contains_urls:
            _add_ioc(ioc_set, 'url', url, 'decoded_content', decoded.source_row, df)

    # Substep 4.4.2: Classify and Deduplicate
    for key, ioc_data in ioc_set.items():
        ioc_type, value = key

        # Skip internal/loopback IPs
        ip_class = 'UNKNOWN'
        if ioc_type == 'ipv4':
            ip_class = context.ip_classifications.get(value, 'UNKNOWN')
            if ip_class in ['INTERNAL', 'LOOPBACK', 'LINK_LOCAL', 'UNSPECIFIED']:
                continue

        # Substep 4.4.3: Determine IOC Context
        ioc_entry = {
            'type': ioc_type,
            'value': value,
            'first_seen': ioc_data['first_seen'],
            'last_seen': ioc_data['last_seen'],
            'source_count': len(ioc_data['sources']),
            'sources': list(ioc_data['sources'])[:10],  # Limit for size
            'associated_processes': list(ioc_data['processes'])[:5],
            'associated_users': list(ioc_data['users'])[:5],
            'classification': ip_class if ioc_type == 'ipv4' else 'N/A',
        }

        # Substep 4.4.4: Score Preliminary Risk
        risk_score = 'LOW'

        # Higher risk if in decoded attack commands
        if any('decoded' in s for s in ioc_data['sources']):
            risk_score = 'HIGH'

        # Higher risk if associated with suspicious process
        if any(p in ['cmd.exe', 'powershell.exe', 'w3wp.exe'] for p in ioc_data['processes']):
            risk_score = 'HIGH'

        # Multiple sources = potentially more significant
        if len(ioc_data['sources']) >= 3:
            if risk_score == 'HIGH':
                risk_score = 'CRITICAL'
            else:
                risk_score = 'MEDIUM'

        ioc_entry['risk_score'] = risk_score
        iocs.append(ioc_entry)

    # Sort by risk
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    iocs.sort(key=lambda x: risk_order.get(x['risk_score'], 4))

    return iocs


def _add_ioc(ioc_set: Dict, ioc_type: str, value: str, source_col: str, row_idx: int, df) -> None:
    """Add IOC to the set with context."""
    key = (ioc_type, value)

    if key not in ioc_set:
        ioc_set[key] = {
            'first_seen': None,
            'last_seen': None,
            'sources': set(),
            'processes': set(),
            'users': set(),
        }

    data = ioc_set[key]
    data['sources'].add(source_col)

    # Get timestamp and context from row
    if row_idx < len(df):
        row = df.iloc[row_idx]
        ts = row.get('timestamp_utc')
        if ts is not None:
            if data['first_seen'] is None or ts < data['first_seen']:
                data['first_seen'] = ts
            if data['last_seen'] is None or ts > data['last_seen']:
                data['last_seen'] = ts

        proc = row.get('process_name')
        if proc and pd.notna(proc):
            data['processes'].add(str(proc))

        user = row.get('username')
        if user and pd.notna(user):
            data['users'].add(str(user))
