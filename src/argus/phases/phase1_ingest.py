"""Phase 1: INGEST - Evidence parsing and normalization.

Verifies evidence integrity, auto-detects file types, parses through
appropriate parsers, normalizes to unified schema, stores as Parquet.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import pyarrow as pa
import pyarrow.parquet as pq

from argus.parsers import (
    detect_parser,
    parse_file,
    ParseResult,
    PARQUET_SCHEMA,
)
from argus.phases.phase0_init import compute_sha256, write_completion_marker


def verify_evidence_integrity(case_path: Path) -> tuple[bool, list[str]]:
    """Verify evidence files against stored hashes.

    Returns:
        Tuple of (all_valid, list of error messages)
    """
    evidence_dir = case_path / "evidence"
    hashes_file = evidence_dir / "hashes.json"

    if not hashes_file.exists():
        return False, ["hashes.json not found - evidence integrity cannot be verified"]

    with open(hashes_file) as f:
        hash_data = json.load(f)

    stored_hashes = hash_data.get("files", {})
    errors = []

    for filename, expected_hash in stored_hashes.items():
        file_path = evidence_dir / filename
        if not file_path.exists():
            errors.append(f"Missing: {filename}")
            continue

        actual_hash = compute_sha256(file_path)
        if actual_hash != expected_hash:
            errors.append(f"Modified: {filename} (hash mismatch)")

    return len(errors) == 0, errors


def get_evidence_files(case_path: Path) -> list[Path]:
    """Get list of evidence files to parse."""
    evidence_dir = case_path / "evidence"
    files = []

    for item in evidence_dir.iterdir():
        if item.is_file() and item.name != "hashes.json":
            files.append(item)

    return sorted(files)


def detect_systems(events: list[dict]) -> dict:
    """Auto-detect systems from parsed events.

    Returns dict with detected hostnames, IPs, and OS indicators.
    """
    systems = {
        "hostnames": set(),
        "source_ips": set(),
        "dest_ips": set(),
        "usernames": set(),
        "os_indicators": set(),
    }

    for event in events:
        # Hostnames
        if event.get("source_system"):
            systems["hostnames"].add(event["source_system"])

        # IPs
        if event.get("source_ip"):
            systems["source_ips"].add(event["source_ip"])
        if event.get("dest_ip"):
            systems["dest_ips"].add(event["dest_ip"])

        # Usernames
        if event.get("username"):
            systems["usernames"].add(event["username"])

        # OS detection from event types and paths
        event_type = event.get("event_type", "")
        file_path = event.get("file_path", "")

        if any(x in event_type for x in ["EVTX", "Windows", "Sysmon"]):
            systems["os_indicators"].add("Windows")
        elif any(x in event_type for x in ["syslog", "auth.log"]):
            systems["os_indicators"].add("Linux")

        if file_path:
            if "\\" in file_path or file_path.startswith("C:"):
                systems["os_indicators"].add("Windows")
            elif file_path.startswith("/"):
                systems["os_indicators"].add("Linux/Unix")

    # Convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in systems.items()}


def extract_iocs_from_binary(file_path: Path) -> list[dict]:
    """Extract IOCs from binary files like disk images using strings.

    This is a fallback for files we can't fully parse, to at least
    capture network indicators, URLs, and command patterns.

    Args:
        file_path: Path to binary file

    Returns:
        List of event dicts with extracted IOCs
    """
    import re
    import subprocess
    from datetime import datetime, timezone

    events = []
    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)

    # Use strings command to extract printable strings
    try:
        result = subprocess.run(
            ['strings', '-n', '10', str(file_path)],
            capture_output=True,
            timeout=120,  # 2 minute timeout for large files
        )
        strings_output = result.stdout.decode('utf-8', errors='replace')
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return events

    # IOC patterns
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    url_pattern = re.compile(r'(https?://[^\s"\'<>]{10,})')
    domain_pattern = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b')

    # Track seen IOCs to avoid duplicates
    seen_iocs = set()

    # Search for IPs
    for match in ip_pattern.finditer(strings_output):
        ip = match.group(1)
        if ip not in seen_iocs:
            # Validate IP octets
            try:
                octets = [int(x) for x in ip.split('.')]
                if all(0 <= x <= 255 for x in octets):
                    # Skip obviously invalid IPs
                    if octets[0] in (0, 255) or ip.startswith('0.'):
                        continue
                    seen_iocs.add(ip)
                    # Determine severity based on IP type
                    first, second = octets[0], octets[1]
                    is_private = (
                        first == 10 or
                        (first == 172 and 16 <= second <= 31) or
                        (first == 192 and second == 168) or
                        first == 127
                    )
                    events.append({
                        'timestamp_utc': file_mtime,
                        'source_file': str(file_path),
                        'event_type': 'DiskImage_IOC_IP',
                        'severity': 'medium' if is_private else 'high',
                        'dest_ip': ip,
                        'parser_name': 'binary_strings',
                        'description': f"IP extracted from disk image: {ip} ({'internal' if is_private else 'external'})",
                    })
            except ValueError:
                continue

    # Search for URLs
    for match in url_pattern.finditer(strings_output):
        url = match.group(1)
        if url not in seen_iocs:
            seen_iocs.add(url)
            events.append({
                'timestamp_utc': file_mtime,
                'source_file': str(file_path),
                'event_type': 'DiskImage_IOC_URL',
                'severity': 'high',
                'uri': url,
                'parser_name': 'binary_strings',
                'description': f"URL extracted from disk image: {url}",
            })

    # Search for known attack patterns (bitsadmin, certutil, powershell download, etc.)
    lolbin_patterns = {
        r'bitsadmin.*(/transfer|/download)': ('bitsadmin', 'T1105'),
        r'certutil.*(-decode|-urlcache)': ('certutil', 'T1140'),
        r'powershell.*(-enc|-e\s|downloadstring|invoke-webrequest)': ('powershell', 'T1059.001'),
        r'schtasks.*/create': ('schtasks', 'T1053.005'),
    }

    for pattern, (tool, mitre_id) in lolbin_patterns.items():
        for match in re.finditer(pattern, strings_output, re.IGNORECASE):
            cmd = match.group(0)[:500]  # Limit length
            if cmd not in seen_iocs:
                seen_iocs.add(cmd)
                events.append({
                    'timestamp_utc': file_mtime,
                    'source_file': str(file_path),
                    'event_type': 'DiskImage_LOLBin_Command',
                    'severity': 'critical',
                    'command_line': cmd,
                    'process_name': tool,
                    'parser_name': 'binary_strings',
                    'description': f"LOLBin command found in disk image: {tool} [{mitre_id}]",
                })

    return events


def events_to_parquet(events: list[dict], output_path: Path) -> int:
    """Convert events to Parquet file.

    Returns number of events written.
    """
    if not events:
        return 0

    # Build columns from events
    columns = {field: [] for field in PARQUET_SCHEMA.names}

    for event in events:
        for field in PARQUET_SCHEMA.names:
            value = event.get(field)
            columns[field].append(value)

    # Create table and write
    table = pa.table(columns, schema=PARQUET_SCHEMA)
    pq.write_table(table, output_path)

    return len(events)


def update_case_config(case_path: Path, systems: dict, stats: dict) -> None:
    """Update argus.yaml with detected systems and ingestion stats."""
    import yaml

    config_path = case_path / "argus.yaml"

    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Update systems
    config["systems"] = {
        "hostnames": systems.get("hostnames", []),
        "source_ips": systems.get("source_ips", [])[:20],  # Limit to top 20
        "dest_ips": systems.get("dest_ips", [])[:20],
        "users": systems.get("usernames", [])[:50],
        "os_detected": systems.get("os_indicators", []),
    }

    # Add ingestion stats
    config["ingestion"] = {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "files_parsed": stats["files_parsed"],
        "files_failed": stats["files_failed"],
        "total_events": stats["total_events"],
        "parsers_used": stats["parsers_used"],
    }

    # Update status
    config["case"]["status"] = "ingested"

    if 0 not in config.get("phases_completed", []):
        config["phases_completed"] = config.get("phases_completed", []) + [0]
    if 1 not in config["phases_completed"]:
        config["phases_completed"].append(1)

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def run_ingest(case_path_str: str, auto_generate_parsers: bool = False) -> bool:
    """Run Phase 1: Ingest and normalize evidence.

    Args:
        case_path_str: Path to case directory
        auto_generate_parsers: Whether to auto-generate parsers for unknown formats

    Returns:
        True if successful, False otherwise
    """
    case_path = Path(case_path_str).resolve()

    # Verify case exists
    if not (case_path / "argus.yaml").exists():
        click.echo("Error: Not a valid ARGUS case directory", err=True)
        return False

    click.echo(f"\nPhase 1: INGEST")
    click.echo("=" * 40)

    # Step 1: Verify evidence integrity
    click.echo("\nVerifying evidence integrity...")
    is_valid, errors = verify_evidence_integrity(case_path)

    if not is_valid:
        click.echo(click.style("CRITICAL: Evidence integrity check failed!", fg="red"))
        for error in errors:
            click.echo(f"  - {error}")
        click.echo("\nHALTING - Evidence may have been modified.")
        return False

    click.echo(click.style("  Integrity verified", fg="green"))

    # Step 2: Get evidence files
    evidence_files = get_evidence_files(case_path)

    if not evidence_files:
        click.echo("Warning: No evidence files found in evidence/")
        click.echo("Add evidence files and re-run ingestion.")
        return False

    click.echo(f"\nFound {len(evidence_files)} evidence file(s)")

    # Step 3: Parse each file
    parsed_dir = case_path / "parsed"
    all_events = []
    stats = {
        "files_parsed": 0,
        "files_failed": 0,
        "total_events": 0,
        "parsers_used": [],
        "failures": [],
    }

    for file_path in evidence_files:
        click.echo(f"\nProcessing: {file_path.name}")

        # Detect parser
        parser_class = detect_parser(file_path)

        if parser_class is None:
            if auto_generate_parsers:
                click.echo(f"  Unknown format - attempting auto-generation...")
                try:
                    result = parse_file(file_path, auto_generate=True)
                    if result.errors:
                        raise Exception(result.errors[0])
                    parser_name = result.metadata.get("detected_parser", "auto")
                    click.echo(click.style(f"  Generated parser: {parser_name}", fg="green"))
                except Exception as e:
                    click.echo(click.style(f"  Failed to generate parser: {e}", fg="yellow"))
                    stats["files_failed"] += 1
                    stats["failures"].append({
                        "file": file_path.name,
                        "reason": f"Unknown format, auto-generation failed: {e}",
                    })
                    continue
            else:
                # Try IOC extraction from binary files (disk images, etc.)
                disk_image_exts = {'.vhd', '.vhdx', '.vmdk', '.img', '.raw', '.dd', '.e01'}
                if file_path.suffix.lower() in disk_image_exts:
                    click.echo(f"  Disk image detected - extracting IOCs via strings")
                    ioc_events = extract_iocs_from_binary(file_path)
                    if ioc_events:
                        events = ioc_events
                        parquet_name = file_path.name + ".parquet"
                        parquet_path = parsed_dir / parquet_name
                        written = events_to_parquet(events, parquet_path)
                        click.echo(f"  Saved: {parquet_name} ({written} IOC events)")
                        stats["files_parsed"] += 1
                        stats["total_events"] += written
                        continue
                    else:
                        click.echo(click.style(f"  No IOCs extracted", fg="yellow"))

                click.echo(click.style(f"  Unknown format - skipping", fg="yellow"))
                stats["files_failed"] += 1
                stats["failures"].append({
                    "file": file_path.name,
                    "reason": "Unknown file format",
                    "suggestion": "Run with --auto-generate or use 'argus generate-parser'",
                })
                continue
        else:
            click.echo(f"  Detected: {parser_class.name}")

        # Parse file
        try:
            result = parse_file(file_path, auto_generate=auto_generate_parsers)

            if result.errors:
                click.echo(click.style(f"  Parse errors: {result.errors}", fg="red"))
                stats["files_failed"] += 1
                stats["failures"].append({
                    "file": file_path.name,
                    "reason": result.errors[0],
                })
                continue

            # Convert events to dicts
            events = [e.to_dict() for e in result.events]
            event_count = len(events)

            click.echo(f"  Parsed: {event_count} events")

            if result.warnings:
                for warning in result.warnings[:3]:
                    click.echo(click.style(f"  Warning: {warning}", fg="yellow"))
                if len(result.warnings) > 3:
                    click.echo(f"  ... and {len(result.warnings) - 3} more warnings")

            # Write to Parquet (use full filename to avoid collision, e.g., run.bat vs run.ps1)
            parquet_name = file_path.name + ".parquet"
            parquet_path = parsed_dir / parquet_name
            written = events_to_parquet(events, parquet_path)
            click.echo(f"  Saved: {parquet_name} ({written} events)")

            # Accumulate
            all_events.extend(events)
            stats["files_parsed"] += 1
            stats["total_events"] += event_count

            parser_name = result.metadata.get("detected_parser", "unknown")
            if parser_name not in stats["parsers_used"]:
                stats["parsers_used"].append(parser_name)

        except Exception as e:
            click.echo(click.style(f"  Error: {e}", fg="red"))
            stats["files_failed"] += 1
            stats["failures"].append({
                "file": file_path.name,
                "reason": str(e),
            })

    # Step 4: Detect systems
    click.echo("\nDetecting systems...")
    systems = detect_systems(all_events)

    if systems["hostnames"]:
        click.echo(f"  Hostnames: {', '.join(systems['hostnames'][:5])}")
    if systems["os_indicators"]:
        click.echo(f"  OS detected: {', '.join(systems['os_indicators'])}")
    if systems["usernames"]:
        click.echo(f"  Users found: {len(systems['usernames'])}")

    # Step 5: Update config
    update_case_config(case_path, systems, stats)

    # Step 6: Write failures log if any
    if stats["failures"]:
        failures_path = case_path / "logs" / "ingest_failures.json"
        with open(failures_path, "w") as f:
            json.dump(stats["failures"], f, indent=2)

    # Step 7: Write completion marker
    write_completion_marker(case_path, 1)

    # Summary
    click.echo("\n" + "=" * 40)
    click.echo("Ingestion Summary")
    click.echo("=" * 40)
    click.echo(f"  Files parsed:  {stats['files_parsed']}")
    click.echo(f"  Files failed:  {stats['files_failed']}")
    click.echo(f"  Total events:  {stats['total_events']}")
    click.echo(f"  Parsers used:  {', '.join(stats['parsers_used'])}")

    if stats["failures"]:
        click.echo(click.style(f"\n  {len(stats['failures'])} file(s) could not be parsed.", fg="yellow"))
        click.echo(f"  See: logs/ingest_failures.json")

    # Check for data quality issues
    if all_events:
        # Check for Sysmon
        has_sysmon = any("Sysmon" in e.get("event_type", "") for e in all_events)
        if not has_sysmon:
            click.echo(click.style(
                "\n  Note: No Sysmon telemetry detected.",
                fg="yellow"
            ))
            click.echo("  Process tree analysis will be limited to EID 4688.")

        # Check for Excel exports
        excel_sources = [f for f in evidence_files if f.suffix.lower() == ".xlsx"]
        if excel_sources:
            click.echo(click.style(
                "\n  Note: Excel-exported logs detected.",
                fg="yellow"
            ))
            click.echo("  Some fields may be truncated. Confidence scores adjusted.")

    click.echo(f"\nPhase 1 complete. Run 'argus triage {case_path}' for Phase 2.")
    return True
