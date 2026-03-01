"""Phase 2: TRIAGE - Evidence triage and hypothesis generation.

Phase 2a: Programmatic scan (fast, deterministic)
Phase 2b: LLM triage agents (catch unknown unknowns)
Phase 2c: Merge findings
Phase 2d: Hypothesis generation
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import pyarrow.parquet as pq

from argus.phases.phase0_init import write_completion_marker


# Suspicious Event IDs to flag
SUSPICIOUS_EVENT_IDS = {
    # Authentication
    4624: "Logon Success",
    4625: "Logon Failure",
    4648: "Explicit Credentials",
    4672: "Special Privileges Assigned",
    4769: "Kerberos TGS Request",
    4771: "Kerberos Pre-Auth Failed",
    4776: "Credential Validation",
    # Account Management
    4720: "User Account Created",
    4732: "Member Added to Security Group",
    # Process/Service
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    7045: "Service Installed",
    # Sysmon
    1: "Sysmon Process Create",
    3: "Sysmon Network Connect",
    11: "Sysmon File Create",
    13: "Sysmon Registry Value Set",
    22: "Sysmon DNS Query",
}

# Pattern priority levels for stratified sampling
PRIORITY_CRITICAL = 1  # Must include in findings
PRIORITY_HIGH = 2      # High priority
PRIORITY_MEDIUM = 3    # Medium priority
PRIORITY_LOW = 4       # Low priority (background noise often)

# Suspicious patterns to search for - now with priority levels
SUSPICIOUS_PATTERNS = [
    # ===== CRITICAL: Webshell Execution Chain =====
    (r"w3wp\.exe", "IIS worker process (webshell indicator)", PRIORITY_CRITICAL),
    (r"forbiden\.aspx", "Known webshell filename", PRIORITY_CRITICAL),
    (r"forbidden\.aspx", "Known webshell filename variant", PRIORITY_CRITICAL),
    (r"cmd\.aspx", "Webshell filename", PRIORITY_CRITICAL),
    (r"shell\.aspx", "Webshell filename", PRIORITY_CRITICAL),
    (r"IIS APPPOOL", "IIS Application Pool user context", PRIORITY_CRITICAL),
    (r"DefaultAppPool", "Default IIS App Pool", PRIORITY_CRITICAL),

    # ===== CRITICAL: Credential Dumping =====
    (r"pd\.exe", "ProcDump (credential harvesting)", PRIORITY_CRITICAL),
    (r"pd64\.exe", "ProcDump 64-bit", PRIORITY_CRITICAL),
    (r"procdump\.exe", "ProcDump executable", PRIORITY_CRITICAL),
    (r"-accepteula.*-ma", "ProcDump memory dump flags", PRIORITY_CRITICAL),
    (r"-ma\s+\d+", "Memory dump with PID", PRIORITY_CRITICAL),
    (r"lsass", "LSASS process reference", PRIORITY_CRITICAL),
    (r"\.dmp", "Memory dump file", PRIORITY_CRITICAL),
    (r"mimikatz", "Mimikatz", PRIORITY_CRITICAL),
    (r"sekurlsa", "Sekurlsa (credential dump)", PRIORITY_CRITICAL),

    # ===== CRITICAL: Lateral Movement =====
    (r"Invoke-WMIExec", "WMI lateral movement", PRIORITY_CRITICAL),
    (r"Invoke-SMBExec", "SMB lateral movement", PRIORITY_CRITICAL),
    (r"Invoke-TheHash", "Pass-the-hash toolkit", PRIORITY_CRITICAL),
    (r"iwe\.ps1", "Invoke-WMIExec script", PRIORITY_CRITICAL),
    (r"ise\.ps1", "Invoke-SMBExec script", PRIORITY_CRITICAL),
    (r"-Hash\s+[a-fA-F0-9]{32}", "NTLM hash parameter", PRIORITY_CRITICAL),
    (r"-Target\s+\d+\.\d+\.\d+\.\d+", "Target IP in lateral movement", PRIORITY_CRITICAL),

    # ===== HIGH: Encoded/Obfuscated Commands =====
    (r"-[eE][nN][cC]\s", "Encoded PowerShell command", PRIORITY_HIGH),
    (r"-[eE]ncoded[cC]ommand\s", "Encoded PowerShell command", PRIORITY_HIGH),
    (r"[A-Za-z0-9+/]{50,}={0,2}", "Base64 string (50+ chars)", PRIORITY_HIGH),

    # ===== HIGH: Hidden PowerShell =====
    (r"-[wW]\s*[hH]idden", "Hidden PowerShell window", PRIORITY_HIGH),
    (r"-[nN]o[pP]", "PowerShell no profile", PRIORITY_HIGH),
    (r"-[eE]xec\s*[bB]ypass", "PowerShell execution bypass", PRIORITY_HIGH),

    # ===== HIGH: Command execution =====
    (r"cmd\.exe\s*/[cC]", "CMD command execution", PRIORITY_HIGH),
    (r"cmd\s*/[cC]", "CMD command execution", PRIORITY_HIGH),

    # ===== HIGH: LOLBins =====
    (r"certutil.*-urlcache", "Certutil download", PRIORITY_HIGH),
    (r"certutil.*-decode", "Certutil decode", PRIORITY_HIGH),
    (r"mshta\s+http", "MSHTA remote execution", PRIORITY_HIGH),
    (r"regsvr32.*\/s.*\/u.*http", "Regsvr32 remote load", PRIORITY_HIGH),
    (r"rundll32.*javascript", "Rundll32 script execution", PRIORITY_HIGH),
    (r"wmic.*process.*call.*create", "WMIC process creation", PRIORITY_HIGH),
    (r"bitsadmin.*\/transfer", "BITSAdmin download", PRIORITY_HIGH),

    # ===== HIGH: Scheduled tasks =====
    (r"schtasks.*\/create", "Scheduled task creation", PRIORITY_HIGH),

    # ===== HIGH: Lateral movement (generic) =====
    (r"psexec", "PsExec usage", PRIORITY_HIGH),
    (r"wmiexec", "WMI execution", PRIORITY_HIGH),
    (r"winrm", "WinRM usage", PRIORITY_HIGH),

    # ===== MEDIUM: Reconnaissance =====
    (r"net\s+user", "Net user enumeration", PRIORITY_MEDIUM),
    (r"net\s+localgroup", "Net localgroup enumeration", PRIORITY_MEDIUM),
    (r"nltest", "Domain trust enumeration", PRIORITY_MEDIUM),
    (r"whoami", "User context check", PRIORITY_MEDIUM),
    (r"ipconfig\s*/all", "Network config enumeration", PRIORITY_MEDIUM),
    (r"ipconfig", "Network config check", PRIORITY_MEDIUM),
    (r"systeminfo", "System info enumeration", PRIORITY_MEDIUM),
    (r"tasklist", "Process enumeration", PRIORITY_MEDIUM),
    (r"netstat", "Network connections enumeration", PRIORITY_MEDIUM),
    (r"wmic\s+process\s+list", "Process list via WMI", PRIORITY_MEDIUM),

    # ===== MEDIUM: Web attacks =====
    (r"SELECT.*FROM.*WHERE", "SQL injection attempt", PRIORITY_MEDIUM),
    (r"UNION\s+SELECT", "SQL UNION injection", PRIORITY_MEDIUM),
    (r"\.\./\.\./", "Path traversal", PRIORITY_MEDIUM),
    (r"%2e%2e%2f", "URL-encoded path traversal", PRIORITY_MEDIUM),
    (r"<script", "XSS attempt", PRIORITY_MEDIUM),
    (r"\.asp[x]?\?", "Webshell indicator", PRIORITY_MEDIUM),
    (r"cmd=", "Command parameter", PRIORITY_MEDIUM),
    (r"exec=", "Exec parameter", PRIORITY_MEDIUM),

    # ===== LOW: Potentially noisy but useful =====
    (r"powershell\.exe", "PowerShell execution", PRIORITY_LOW),
    (r"splunk-powershell", "Splunk PowerShell (usually benign)", PRIORITY_LOW),
]


def load_parquet_events(case_path: Path) -> list[dict]:
    """Load all events from Parquet files."""
    parsed_dir = case_path / "parsed"
    events = []

    for parquet_file in parsed_dir.glob("*.parquet"):
        try:
            table = pq.read_table(parquet_file)
            df_events = table.to_pylist()
            for event in df_events:
                event["_source_parquet"] = parquet_file.name
            events.extend(df_events)
        except Exception as e:
            click.echo(f"  Warning: Failed to read {parquet_file.name}: {e}")

    return events


def run_programmatic_scan(events: list[dict]) -> dict:
    """Run Phase 2a: Programmatic triage scan.

    Returns dict with all scan results.
    """
    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "event_id_distribution": {},
        "timeline": {},
        "entities": {},
        "web_stats": {},
        "suspicious_findings": [],
    }

    if not events:
        return results

    # Event ID distribution
    event_ids = Counter()
    for event in events:
        event_type = event.get("event_type", "")
        # Extract numeric ID if present
        id_match = re.search(r"(\d+)", str(event_type))
        if id_match:
            event_ids[int(id_match.group(1))] += 1
        else:
            event_ids[event_type] += 1

    # Sort by count and mark suspicious
    results["event_id_distribution"] = {
        "counts": dict(event_ids.most_common(50)),
        "suspicious": [
            {"id": eid, "count": event_ids[eid], "description": SUSPICIOUS_EVENT_IDS.get(eid, "")}
            for eid in event_ids
            if eid in SUSPICIOUS_EVENT_IDS
        ],
    }

    # Timeline analysis
    timestamps = []
    for event in events:
        ts = event.get("timestamp_utc")
        if ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    continue
            timestamps.append(ts)

    if timestamps:
        timestamps.sort()
        results["timeline"] = {
            "earliest": timestamps[0].isoformat(),
            "latest": timestamps[-1].isoformat(),
            "duration_hours": (timestamps[-1] - timestamps[0]).total_seconds() / 3600,
            "event_count": len(timestamps),
        }

        # Hourly histogram
        hourly = Counter()
        for ts in timestamps:
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            hourly[hour_key] += 1

        # Find spikes (hours with >2x average)
        if hourly:
            avg = sum(hourly.values()) / len(hourly)
            spikes = [
                {"hour": h, "count": c, "ratio": round(c / avg, 2)}
                for h, c in hourly.most_common(10)
                if c > avg * 2
            ]
            results["timeline"]["activity_spikes"] = spikes

    # Entity extraction
    usernames = set()
    source_ips = set()
    dest_ips = set()
    hostnames = set()
    processes = set()

    for event in events:
        if event.get("username"):
            usernames.add(event["username"])
        if event.get("source_ip"):
            source_ips.add(event["source_ip"])
        if event.get("dest_ip"):
            dest_ips.add(event["dest_ip"])
        if event.get("source_system"):
            hostnames.add(event["source_system"])
        if event.get("process_name"):
            processes.add(event["process_name"])

    results["entities"] = {
        "usernames": sorted(list(usernames))[:100],
        "source_ips": sorted(list(source_ips))[:100],
        "dest_ips": sorted(list(dest_ips))[:100],
        "hostnames": sorted(list(hostnames)),
        "processes": sorted(list(processes))[:100],
        "unique_counts": {
            "users": len(usernames),
            "source_ips": len(source_ips),
            "dest_ips": len(dest_ips),
            "hosts": len(hostnames),
            "processes": len(processes),
        },
    }

    # Web log statistics
    web_events = [e for e in events if e.get("http_method") or e.get("uri")]
    if web_events:
        methods = Counter(e.get("http_method", "UNKNOWN") for e in web_events)
        status_codes = Counter(e.get("status_code") for e in web_events if e.get("status_code"))
        uris = Counter(e.get("uri", "").split("?")[0] for e in web_events)  # Strip query strings
        user_agents = Counter(e.get("user_agent", "")[:100] for e in web_events if e.get("user_agent"))

        results["web_stats"] = {
            "total_requests": len(web_events),
            "methods": dict(methods),
            "status_codes": dict(status_codes.most_common(20)),
            "top_uris": dict(uris.most_common(20)),
            "top_user_agents": dict(user_agents.most_common(10)),
        }

        # Flag suspicious status codes
        error_codes = sum(1 for code in status_codes if code and code >= 400)
        if error_codes > len(web_events) * 0.1:
            results["web_stats"]["high_error_rate"] = True

    # Suspicious pattern scan with priority-based stratified sampling
    findings_by_priority = {
        PRIORITY_CRITICAL: [],
        PRIORITY_HIGH: [],
        PRIORITY_MEDIUM: [],
        PRIORITY_LOW: [],
    }

    # Also track findings by time bucket for time-stratified sampling
    findings_by_hour = defaultdict(list)

    for event in events:
        searchable = " ".join(str(v) for v in event.values() if v).lower()

        # Get timestamp for time stratification
        ts = event.get("timestamp_utc", "")
        hour_key = "unknown"
        if ts:
            if isinstance(ts, str):
                try:
                    ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hour_key = ts_dt.strftime("%Y-%m-%d %H:00")
                except ValueError:
                    pass
            elif hasattr(ts, 'strftime'):
                hour_key = ts.strftime("%Y-%m-%d %H:00")

        for pattern, description, priority in SUSPICIOUS_PATTERNS:
            if re.search(pattern, searchable, re.IGNORECASE):
                finding = {
                    "pattern": description,
                    "priority": priority,
                    "source_file": event.get("source_file", ""),
                    "source_line": event.get("source_line", 0),
                    "timestamp": event.get("timestamp_utc", ""),
                    "event_type": event.get("event_type", ""),
                    "matched_content": searchable[:500],
                    "hour_bucket": hour_key,
                }

                # Avoid exact duplicates
                is_dup = False
                for existing in findings_by_priority[priority]:
                    if (existing.get("source_file") == finding.get("source_file") and
                        existing.get("source_line") == finding.get("source_line") and
                        existing.get("pattern") == finding.get("pattern")):
                        is_dup = True
                        break

                if not is_dup:
                    findings_by_priority[priority].append(finding)
                    findings_by_hour[hour_key].append(finding)

    # Priority-based selection:
    # - ALL critical findings (up to 200)
    # - HIGH findings stratified by time (up to 200)
    # - MEDIUM findings stratified by time (up to 100)
    # - LOW findings only if space remains

    final_findings = []

    # 1. Include ALL critical findings (these are the attack indicators)
    critical = findings_by_priority[PRIORITY_CRITICAL][:200]
    final_findings.extend(critical)

    # 2. Time-stratified sampling for HIGH priority
    high_findings = findings_by_priority[PRIORITY_HIGH]
    if high_findings:
        # Group by hour and sample evenly
        high_by_hour = defaultdict(list)
        for f in high_findings:
            high_by_hour[f.get("hour_bucket", "unknown")].append(f)

        # Take up to 200, distributed across hours
        remaining = 200
        hours = sorted(high_by_hour.keys())
        per_hour = max(1, remaining // max(1, len(hours)))
        for hour in hours:
            take = min(per_hour, len(high_by_hour[hour]), remaining)
            final_findings.extend(high_by_hour[hour][:take])
            remaining -= take
            if remaining <= 0:
                break

    # 3. Time-stratified sampling for MEDIUM priority
    medium_findings = findings_by_priority[PRIORITY_MEDIUM]
    if medium_findings:
        medium_by_hour = defaultdict(list)
        for f in medium_findings:
            medium_by_hour[f.get("hour_bucket", "unknown")].append(f)

        remaining = 100
        hours = sorted(medium_by_hour.keys())
        per_hour = max(1, remaining // max(1, len(hours)))
        for hour in hours:
            take = min(per_hour, len(medium_by_hour[hour]), remaining)
            final_findings.extend(medium_by_hour[hour][:take])
            remaining -= take
            if remaining <= 0:
                break

    # 4. LOW priority only if we have space (skip noisy ones like Splunk)
    low_findings = [f for f in findings_by_priority[PRIORITY_LOW]
                    if "splunk" not in f.get("matched_content", "").lower()]
    if len(final_findings) < 500 and low_findings:
        remaining = 500 - len(final_findings)
        final_findings.extend(low_findings[:remaining])

    results["suspicious_findings"] = final_findings

    # Add summary of what was found by priority
    results["findings_summary"] = {
        "critical": len(findings_by_priority[PRIORITY_CRITICAL]),
        "high": len(findings_by_priority[PRIORITY_HIGH]),
        "medium": len(findings_by_priority[PRIORITY_MEDIUM]),
        "low": len(findings_by_priority[PRIORITY_LOW]),
        "hours_with_findings": len(findings_by_hour),
        "selected_for_analysis": len(final_findings),
    }

    return results


def check_phase_complete(case_path: Path, phase: int) -> bool:
    """Check if a phase has been completed."""
    marker = case_path / "logs" / "phase_completions" / f"phase_{phase}.complete"
    return marker.exists()


def run_triage(case_path_str: str, skip_llm_agents: bool = False) -> bool:
    """Run Phase 2: Triage.

    Args:
        case_path_str: Path to case directory
        skip_llm_agents: If True, only run programmatic scan

    Returns:
        True if successful
    """
    case_path = Path(case_path_str).resolve()

    # Verify case exists
    if not (case_path / "argus.yaml").exists():
        click.echo("Error: Not a valid ARGUS case directory", err=True)
        return False

    # Check if Phase 1 is complete, run it if not
    if not check_phase_complete(case_path, 1):
        click.echo("Phase 1 not complete. Running ingestion first...")
        from argus.phases.phase1_ingest import run_ingest
        if not run_ingest(case_path_str):
            click.echo("Ingestion failed. Cannot proceed with triage.")
            return False

    triage_dir = case_path / "triage"
    triage_dir.mkdir(exist_ok=True)

    click.echo(f"\nPhase 2: TRIAGE")
    click.echo("=" * 40)

    # Load events
    click.echo("\nLoading parsed events...")
    events = load_parquet_events(case_path)
    click.echo(f"  Loaded {len(events)} events")

    if not events:
        click.echo("Warning: No events to triage")
        write_completion_marker(case_path, 2)
        return True

    # Phase 2a: Programmatic scan
    click.echo("\nPhase 2a: Programmatic Scan")
    click.echo("-" * 30)

    scan_results = run_programmatic_scan(events)

    # Save results
    scan_path = triage_dir / "programmatic_scan.json"
    with open(scan_path, "w") as f:
        json.dump(scan_results, f, indent=2, default=str)

    # Print summary
    click.echo(f"  Events analyzed: {scan_results['total_events']}")
    click.echo(f"  Suspicious Event IDs: {len(scan_results['event_id_distribution'].get('suspicious', []))}")
    click.echo(f"  Pattern matches: {len(scan_results['suspicious_findings'])}")

    if scan_results.get("timeline", {}).get("activity_spikes"):
        click.echo(f"  Activity spikes: {len(scan_results['timeline']['activity_spikes'])}")

    if scan_results.get("web_stats"):
        click.echo(f"  Web requests: {scan_results['web_stats']['total_requests']}")

    # Phase 2b: LLM Triage Agents
    if not skip_llm_agents:
        click.echo("\nPhase 2b: LLM Triage Agents")
        click.echo("-" * 30)

        try:
            from argus.agents.triage_agents import run_triage_agents
            agent_results = run_triage_agents(events, scan_results, triage_dir)

            # Phase 2c: Merge findings
            click.echo("\nPhase 2c: Merging Findings")
            click.echo("-" * 30)

            merged = merge_findings(scan_results, agent_results)
            merged_path = triage_dir / "merged_findings.json"
            with open(merged_path, "w") as f:
                json.dump(merged, f, indent=2, default=str)

            click.echo(f"  Total unique findings: {len(merged['findings'])}")

            # Phase 2d: Hypothesis Generation
            click.echo("\nPhase 2d: Hypothesis Generation")
            click.echo("-" * 30)

            from argus.agents.hypothesis_agent import generate_hypotheses
            hypotheses = generate_hypotheses(merged, events)

            hypotheses_path = triage_dir / "hypotheses.json"
            with open(hypotheses_path, "w") as f:
                json.dump(hypotheses, f, indent=2, default=str)

            click.echo(f"  Hypotheses generated: {len(hypotheses.get('hypotheses', []))}")

        except ImportError as e:
            click.echo(click.style(f"  Skipping LLM agents: {e}", fg="yellow"))
            # Create placeholder merged findings from programmatic scan
            merged = {
                "findings": scan_results["suspicious_findings"],
                "sources": ["programmatic_scan"],
            }
            merged_path = triage_dir / "merged_findings.json"
            with open(merged_path, "w") as f:
                json.dump(merged, f, indent=2, default=str)

    else:
        click.echo("\n  Skipping LLM agents (--skip-llm)")
        # Create merged findings from programmatic scan only
        merged = {
            "findings": scan_results["suspicious_findings"],
            "sources": ["programmatic_scan"],
        }
        merged_path = triage_dir / "merged_findings.json"
        with open(merged_path, "w") as f:
            json.dump(merged, f, indent=2, default=str)

    # Write completion marker
    write_completion_marker(case_path, 2)

    click.echo(f"\nPhase 2 complete. Results in: {triage_dir}")
    return True


def merge_findings(programmatic: dict, agent_results: dict) -> dict:
    """Merge programmatic and agent findings, deduplicating."""
    merged = {
        "merged_at": datetime.now(timezone.utc).isoformat(),
        "sources": ["programmatic_scan"] + list(agent_results.keys()),
        "findings": [],
    }

    # Add programmatic findings
    for finding in programmatic.get("suspicious_findings", []):
        finding["source"] = "programmatic_scan"
        merged["findings"].append(finding)

    # Add agent findings
    for agent_name, results in agent_results.items():
        for finding in results.get("findings", []):
            finding["source"] = agent_name
            # Basic deduplication by checking if similar finding exists
            is_duplicate = False
            for existing in merged["findings"]:
                if (
                    existing.get("source_file") == finding.get("source_file")
                    and existing.get("source_line") == finding.get("source_line")
                    and existing.get("pattern") == finding.get("pattern")
                ):
                    is_duplicate = True
                    break

            if not is_duplicate:
                merged["findings"].append(finding)

    return merged
