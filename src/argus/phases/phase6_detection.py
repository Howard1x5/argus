"""Phase 6: DETECTION ENGINEERING.

MITRE ATT&CK mapping, Sigma rule generation, and detection strategy.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from argus.config import get_api_key
from argus.phases.phase0_init import write_completion_marker
from argus.phases.phase2_triage import check_phase_complete


# MITRE ATT&CK technique mapping (expanded with sub-techniques)
MITRE_TECHNIQUES = {
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution"},
    "T1047": {"name": "WMI", "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},

    # Persistence
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence"},

    # Defense Evasion - Signed Binary Proxy Execution
    "T1218": {"name": "Signed Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1218.001": {"name": "Compiled HTML File", "tactic": "Defense Evasion"},
    "T1218.003": {"name": "CMSTP", "tactic": "Defense Evasion"},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion"},
    "T1218.007": {"name": "Msiexec", "tactic": "Defense Evasion"},
    "T1218.009": {"name": "Regsvcs/Regasm", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1218.014": {"name": "MMC", "tactic": "Defense Evasion"},

    # Defense Evasion - Other
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1055.001": {"name": "DLL Injection", "tactic": "Defense Evasion"},
    "T1055.002": {"name": "PE Injection", "tactic": "Defense Evasion"},
    "T1055.012": {"name": "Process Hollowing", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion"},
    "T1070.006": {"name": "Timestomp", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1027.002": {"name": "Software Packing", "tactic": "Defense Evasion"},
    "T1036.005": {"name": "Match Legitimate Name/Location", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion"},
    "T1197": {"name": "BITS Jobs", "tactic": "Defense Evasion"},
    "T1562.002": {"name": "Disable Windows Event Logging", "tactic": "Defense Evasion"},
    "T1564.003": {"name": "Hidden Window", "tactic": "Defense Evasion"},

    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1003.002": {"name": "Security Account Manager", "tactic": "Credential Access"},
    "T1003.003": {"name": "NTDS", "tactic": "Credential Access"},
    "T1003.006": {"name": "DCSync", "tactic": "Credential Access"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access"},
    "T1558.004": {"name": "AS-REP Roasting", "tactic": "Credential Access"},

    # Discovery
    "T1087.001": {"name": "Local Account", "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Account", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "Discovery"},

    # Lateral Movement
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.003": {"name": "DCOM", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement"},
    "T1550.003": {"name": "Pass the Ticket", "tactic": "Lateral Movement"},

    # Command and Control
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1102": {"name": "Web Service", "tactic": "Command and Control"},

    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},

    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
}

# LOLBin to MITRE mapping for automatic technique identification
LOLBIN_MITRE_MAP = {
    "rundll32.exe": "T1218.011",
    "rundll32": "T1218.011",
    "regsvr32.exe": "T1218.010",
    "regsvr32": "T1218.010",
    "mshta.exe": "T1218.005",
    "mshta": "T1218.005",
    "certutil.exe": "T1140",
    "certutil": "T1140",
    "bitsadmin.exe": "T1197",
    "bitsadmin": "T1197",
    "msiexec.exe": "T1218.007",
    "msiexec": "T1218.007",
    "cmstp.exe": "T1218.003",
    "cmstp": "T1218.003",
    "wmic.exe": "T1047",
    "wmic": "T1047",
    "powershell.exe": "T1059.001",
    "powershell": "T1059.001",
    "cmd.exe": "T1059.003",
    "cmd": "T1059.003",
    "schtasks.exe": "T1053.005",
    "schtasks": "T1053.005",
    "sc.exe": "T1543.003",
    "regsvcs.exe": "T1218.009",
    "regsvcs": "T1218.009",
    "regasm.exe": "T1218.009",
    "regasm": "T1218.009",
}


SIGMA_TEMPLATE = """title: {title}
id: {rule_id}
status: experimental
description: {description}
author: ARGUS Auto-generated
date: {date}
references:
    - https://attack.mitre.org/techniques/{technique_id}/
logsource:
    {logsource}
detection:
    selection:
        {detection}
    condition: selection
falsepositives:
    - {false_positives}
level: {level}
tags:
    - attack.{tactic}
    - attack.{technique_id}
"""


def load_validated_claims(case_path: Path) -> list[dict]:
    """Load validated claims from Phase 4."""
    claims_file = case_path / "validation" / "validated_claims.json"
    if claims_file.exists():
        with open(claims_file) as f:
            data = json.load(f)
            return data.get("claims", [])
    return []


def extract_mitre_mapping(claims: list[dict]) -> list[dict]:
    """Extract MITRE mappings from claims."""
    mappings = []
    seen = set()
    
    for claim in claims:
        technique_id = claim.get("mitre_technique", "")
        if not technique_id or technique_id in seen:
            continue
        
        seen.add(technique_id)
        
        technique_info = MITRE_TECHNIQUES.get(technique_id, {})
        
        mappings.append({
            "technique_id": technique_id,
            "technique_name": technique_info.get("name", claim.get("mitre_technique", "")),
            "tactic": technique_info.get("tactic", claim.get("mitre_tactic", "")),
            "evidence": [claim.get("summary", "")],
            "confidence": claim.get("confidence", "MEDIUM"),
            "claim_ids": [claim.get("claim_id", "")],
        })
    
    return mappings


def extract_iocs_from_claim(claim: dict) -> dict:
    """Extract IOCs from claim for Sigma rule generation.

    Parses claim summary and evidence to find concrete indicators:
    - Process names (exe files)
    - File paths
    - DLL names
    - IP addresses
    - Domain names
    """
    import re

    summary = claim.get("summary", "")
    evidence = claim.get("supporting_evidence", [])
    evidence_str = " ".join(str(e) for e in evidence) if evidence else ""
    full_text = f"{summary} {evidence_str}"

    iocs = {
        "processes": [],
        "dlls": [],
        "paths": [],
        "ips": [],
        "domains": [],
        "commands": [],
    }

    # Extract process names (*.exe)
    exe_pattern = r'\b([a-zA-Z0-9_\-]+\.exe)\b'
    exes = re.findall(exe_pattern, full_text, re.IGNORECASE)
    iocs["processes"] = list(set(e.lower() for e in exes))

    # Extract DLL names
    dll_pattern = r'\b([a-zA-Z0-9_\-]+\.dll)\b'
    dlls = re.findall(dll_pattern, full_text, re.IGNORECASE)
    iocs["dlls"] = list(set(d.lower() for d in dlls))

    # Extract file paths (Windows-style)
    path_pattern = r'([A-Za-z]:\\[^\s"\'<>|*?]+|\\\\[^\s"\'<>|*?]+)'
    paths = re.findall(path_pattern, full_text)
    iocs["paths"] = list(set(paths))

    # Extract IP addresses
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ip_pattern, full_text)
    # Filter out obviously invalid IPs
    valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split("."))]
    iocs["ips"] = list(set(valid_ips))

    # Extract potential domain names
    domain_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(com|net|org|io|xyz|ru|cn|tk|top|info|biz|cc))\b'
    domains = re.findall(domain_pattern, full_text, re.IGNORECASE)
    iocs["domains"] = list(set(d[0].lower() for d in domains))

    return iocs


def generate_sigma_rule(claim: dict, rule_num: int) -> Optional[str]:
    """Generate a Sigma rule from a claim."""
    technique_id = claim.get("mitre_technique", "")
    summary = claim.get("summary", "")

    if not technique_id or not summary:
        return None

    technique_info = MITRE_TECHNIQUES.get(technique_id, {})
    tactic = technique_info.get("tactic", "execution").lower().replace(" ", "_")

    # Extract IOCs from the claim for use in detection
    iocs = extract_iocs_from_claim(claim)

    # Determine logsource and detection based on technique
    if "powershell" in summary.lower() or technique_id == "T1059.001":
        logsource = """category: process_creation
    product: windows"""
        detection = """Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - '-nop'
            - '-w hidden'"""
        false_positives = "Legitimate PowerShell administration"

    elif "service" in summary.lower() or technique_id == "T1543.003":
        logsource = """product: windows
    service: system"""
        detection = """EventID: 7045
        ServiceName|re: '^[A-Z]{10,}$'"""
        false_positives = "Legitimate service installations"

    elif "lsass" in summary.lower() or technique_id == "T1003.001":
        logsource = """category: process_access
    product: windows"""
        detection = """TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'"""
        false_positives = "Antivirus scanning LSASS"

    elif "schtask" in summary.lower() or technique_id == "T1053.005":
        logsource = """category: process_creation
    product: windows"""
        detection = """Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'"""
        false_positives = "Legitimate scheduled task creation"

    elif technique_id == "T1218.011" or "rundll32" in summary.lower():
        # Rundll32 - use extracted DLLs if available
        logsource = """category: process_creation
    product: windows"""
        if iocs["dlls"]:
            dll_indicators = "\n            - ".join(f"'{d}'" for d in iocs["dlls"][:5])
            detection = f"""Image|endswith: '\\\\rundll32.exe'
        CommandLine|contains:
            - {dll_indicators}"""
        else:
            detection = """Image|endswith: '\\\\rundll32.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'http://'
            - 'https://'
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'"""
        false_positives = "Legitimate rundll32 usage"

    elif technique_id == "T1218.010" or "regsvr32" in summary.lower():
        # Regsvr32
        logsource = """category: process_creation
    product: windows"""
        if iocs["dlls"]:
            dll_indicators = "\n            - ".join(f"'{d}'" for d in iocs["dlls"][:5])
            detection = f"""Image|endswith: '\\\\regsvr32.exe'
        CommandLine|contains:
            - {dll_indicators}"""
        else:
            detection = """Image|endswith: '\\\\regsvr32.exe'
        CommandLine|contains:
            - '/s'
            - '/i:'
            - 'scrobj.dll'"""
        false_positives = "Legitimate regsvr32 usage"

    elif technique_id == "T1218.005" or "mshta" in summary.lower():
        # Mshta
        logsource = """category: process_creation
    product: windows"""
        detection = """Image|endswith: '\\\\mshta.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'http://'
            - 'https://'"""
        false_positives = "Legitimate mshta usage (rare)"

    elif technique_id.startswith("T1071") or iocs["ips"] or iocs["domains"]:
        # Network-based detection
        logsource = """category: firewall
    product: any"""
        indicators = []
        if iocs["ips"]:
            indicators.extend(f"'{ip}'" for ip in iocs["ips"][:5])
        if iocs["domains"]:
            indicators.extend(f"'{d}'" for d in iocs["domains"][:5])
        if indicators:
            detection = f"""dst_ip|contains:
            - {chr(10).join('            - ' + i for i in indicators).strip()}"""
        else:
            detection = """dst_port:
            - 443
            - 80
            - 8080"""
        false_positives = "Legitimate network traffic"

    else:
        # Fallback: Generate rule based on extracted IOCs
        logsource = """category: process_creation
    product: windows"""

        # Try to build detection from extracted IOCs
        detection_parts = []

        # Check for LOLBins in the claim
        lolbin_found = None
        for proc in iocs["processes"]:
            proc_lower = proc.lower()
            if proc_lower in LOLBIN_MITRE_MAP:
                lolbin_found = proc_lower
                break

        if lolbin_found:
            # Use the LOLBin as the primary indicator
            detection_parts.append(f"Image|endswith: '\\\\{lolbin_found}'")
            if iocs["dlls"]:
                dll_list = "\n            - ".join(f"'{d}'" for d in iocs["dlls"][:3])
                detection_parts.append(f"CommandLine|contains:\n            - {dll_list}")
            elif iocs["paths"]:
                path_list = "\n            - ".join(f"'{p}'" for p in iocs["paths"][:3])
                detection_parts.append(f"CommandLine|contains:\n            - {path_list}")
        elif iocs["processes"]:
            # Use any suspicious process found
            proc = iocs["processes"][0]
            detection_parts.append(f"Image|endswith: '\\\\{proc}'")
        elif iocs["dlls"]:
            # DLL loading detection
            dll_list = "\n            - ".join(f"'{d}'" for d in iocs["dlls"][:5])
            detection_parts.append(f"CommandLine|contains:\n            - {dll_list}")
        elif iocs["paths"]:
            # Path-based detection
            path_list = "\n            - ".join(f"'{p}'" for p in iocs["paths"][:3])
            detection_parts.append(f"CommandLine|contains:\n            - {path_list}")

        if detection_parts:
            detection = "\n        ".join(detection_parts)
        else:
            # Last resort: skip this claim as we can't generate a useful rule
            return None

        false_positives = "Requires environment-specific tuning"
    
    # Determine severity level
    confidence = claim.get("confidence", "MEDIUM")
    if confidence == "HIGH":
        level = "high"
    elif confidence == "MEDIUM":
        level = "medium"
    else:
        level = "low"
    
    rule = SIGMA_TEMPLATE.format(
        title=f"ARGUS Detection: {summary[:60]}",
        rule_id=f"argus-{rule_num:03d}",
        description=summary[:200],
        date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        logsource=logsource,
        detection=detection,
        false_positives=false_positives,
        level=level,
        tactic=tactic,
        technique_id=technique_id,
    )
    
    return rule


def generate_detection_strategy(mitre_mapping: list, claims: list, api_key: Optional[str] = None) -> str:
    """Generate detection strategy brief using LLM."""
    strategy = f"""# Detection Strategy Brief

Generated: {datetime.now(timezone.utc).isoformat()}

## Overview

Based on the analysis of this incident, the following MITRE ATT&CK techniques were observed:

| Technique | Name | Tactic | Confidence |
|-----------|------|--------|------------|
"""
    
    for mapping in mitre_mapping:
        strategy += f"| {mapping['technique_id']} | {mapping['technique_name']} | {mapping['tactic']} | {mapping['confidence']} |\n"
    
    strategy += """

## Risk-Ranked Detection Priorities

"""
    
    # Rank by tactic kill chain order
    tactic_priority = {
        "Initial Access": 1,
        "Execution": 2,
        "Persistence": 3,
        "Privilege Escalation": 4,
        "Defense Evasion": 5,
        "Credential Access": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Collection": 9,
        "Exfiltration": 10,
        "Command and Control": 11,
        "Impact": 12,
    }
    
    sorted_mappings = sorted(
        mitre_mapping,
        key=lambda x: tactic_priority.get(x['tactic'], 99)
    )
    
    for i, mapping in enumerate(sorted_mappings, 1):
        strategy += f"### {i}. {mapping['technique_name']} ({mapping['technique_id']})\n\n"
        strategy += f"**Tactic:** {mapping['tactic']}\n\n"
        strategy += f"**Why it matters:** Detecting this technique early can prevent {mapping['tactic'].lower()} activities.\n\n"
        strategy += f"**Recommended detection:** Deploy Sigma rules targeting this technique.\n\n"
    
    strategy += """
## Coverage Gaps

The following areas may need additional detection coverage:
- Monitor for variations of observed techniques
- Consider behavioral detection alongside signature-based
- Ensure logging is enabled for all critical event sources

## False Positive Guidance

Each generated Sigma rule includes false positive notes. Test rules in detection-only mode before enabling blocking.

## Recommended Next Steps

1. Deploy generated Sigma rules to SIEM
2. Create correlation rules for attack chain detection
3. Set up alerting thresholds based on environment baseline
4. Schedule regular rule tuning reviews
"""
    
    return strategy


def run_detection_engineering(case_path_str: str) -> bool:
    """Run Phase 6: Detection Engineering.

    Args:
        case_path_str: Path to case directory

    Returns:
        True if successful
    """
    case_path = Path(case_path_str).resolve()
    
    # Verify case exists
    if not (case_path / "argus.yaml").exists():
        click.echo("Error: Not a valid ARGUS case directory", err=True)
        return False

    # Check if Phase 5 is complete
    if not check_phase_complete(case_path, 5):
        click.echo("Phase 5 not complete. Running IOC extraction first...")
        from argus.phases.phase5_ioc import run_ioc_extraction
        if not run_ioc_extraction(case_path_str):
            click.echo("IOC extraction failed. Cannot proceed.")
            return False

    detection_dir = case_path / "detection"
    detection_dir.mkdir(exist_ok=True)
    sigma_dir = detection_dir / "sigma_rules"
    sigma_dir.mkdir(exist_ok=True)

    click.echo(f"\nPhase 6: DETECTION ENGINEERING")
    click.echo("=" * 40)

    # Load validated claims
    click.echo("\nLoading validated claims...")
    claims = load_validated_claims(case_path)
    click.echo(f"  Claims: {len(claims)}")

    # MITRE ATT&CK Mapping
    click.echo("\nGenerating MITRE ATT&CK mapping...")
    mitre_mapping = extract_mitre_mapping(claims)
    
    with open(detection_dir / "mitre_mapping.json", "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "techniques_observed": len(mitre_mapping),
            "mappings": mitre_mapping,
        }, f, indent=2)
    
    click.echo(f"  Techniques mapped: {len(mitre_mapping)}")

    # Sigma Rule Generation
    click.echo("\nGenerating Sigma rules...")
    rules_generated = 0
    
    for i, claim in enumerate(claims):
        rule = generate_sigma_rule(claim, i + 1)
        if rule:
            rule_file = sigma_dir / f"rule_{i+1:03d}.yml"
            with open(rule_file, "w") as f:
                f.write(rule)
            rules_generated += 1
    
    click.echo(f"  Rules generated: {rules_generated}")

    # Detection Strategy Brief
    click.echo("\nGenerating detection strategy...")
    strategy = generate_detection_strategy(mitre_mapping, claims)
    
    with open(detection_dir / "detection_strategy.md", "w") as f:
        f.write(strategy)

    # Summary
    click.echo("\n" + "=" * 40)
    click.echo("Detection Engineering Summary")
    click.echo("=" * 40)
    click.echo(f"  MITRE techniques: {len(mitre_mapping)}")
    click.echo(f"  Sigma rules:      {rules_generated}")
    click.echo(f"  Strategy brief:   detection_strategy.md")

    # Write completion marker
    write_completion_marker(case_path, 6)

    click.echo(f"\nPhase 6 complete. Results in: {detection_dir}")
    return True
