"""Phase 8: OUTPUT PACKAGING.

Creates final deliverable package with all analysis artifacts.
"""

import json
import hashlib
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from argus.phases.phase0_init import write_completion_marker
from argus.phases.phase2_triage import check_phase_complete


PACKAGE_MANIFEST_TEMPLATE = {
    "package_version": "1.0",
    "tool": "ARGUS",
    "tool_version": "0.1.0",
    "created_at": None,
    "case_id": None,
    "contents": {
        "report": [],
        "iocs": [],
        "detection": [],
        "evidence_hashes": [],
        "logs": [],
    },
    "checksums": {},
}


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def collect_package_files(case_path: Path) -> dict:
    """Collect all files for the package."""
    files = {
        "report": [],
        "iocs": [],
        "detection": [],
        "evidence_hashes": [],
        "logs": [],
    }

    # Report files
    report_dir = case_path / "report"
    if report_dir.exists():
        for f in report_dir.glob("*"):
            if f.is_file():
                files["report"].append(f)

    # IOC files
    iocs_dir = case_path / "iocs"
    if iocs_dir.exists():
        for f in iocs_dir.glob("*.json"):
            files["iocs"].append(f)

    # Detection files (MITRE mapping, Sigma rules, strategy)
    detection_dir = case_path / "detection"
    if detection_dir.exists():
        for f in detection_dir.glob("*.json"):
            files["detection"].append(f)
        for f in detection_dir.glob("*.md"):
            files["detection"].append(f)
        sigma_dir = detection_dir / "sigma_rules"
        if sigma_dir.exists():
            for f in sigma_dir.glob("*.yml"):
                files["detection"].append(f)

    # Evidence manifest (hashes, not raw evidence)
    evidence_dir = case_path / "evidence"
    if evidence_dir.exists():
        manifest = evidence_dir / "manifest.json"
        if manifest.exists():
            files["evidence_hashes"].append(manifest)

    # Log files (completion markers, not full logs)
    logs_dir = case_path / "logs"
    if logs_dir.exists():
        completion_dir = logs_dir / "phase_completions"
        if completion_dir.exists():
            for f in completion_dir.glob("*.complete"):
                files["logs"].append(f)

    return files


def create_stix_bundle(case_path: Path, iocs: dict) -> Optional[Path]:
    """Create STIX 2.1 bundle from IOCs."""
    try:
        import uuid

        stix_objects = []
        bundle_id = f"bundle--{uuid.uuid4()}"

        # Create identity for ARGUS
        identity_id = f"identity--{uuid.uuid4()}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "modified": datetime.now(timezone.utc).isoformat() + "Z",
            "name": "ARGUS Automated Analysis",
            "identity_class": "system",
        })

        # Create indicators from IOCs
        for ioc in iocs.get("iocs", []):
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            risk_score = ioc.get("risk_score", 0)

            # Map IOC type to STIX pattern
            if ioc_type == "ipv4":
                pattern = f"[ipv4-addr:value = '{value}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{value}']"
            elif ioc_type in ["md5", "sha1", "sha256"]:
                pattern = f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
            elif ioc_type == "email":
                pattern = f"[email-addr:value = '{value}']"
            else:
                continue

            # Determine confidence level
            if risk_score >= 70:
                confidence = 85
            elif risk_score >= 50:
                confidence = 65
            elif risk_score >= 25:
                confidence = 45
            else:
                confidence = 25

            indicator_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": datetime.now(timezone.utc).isoformat() + "Z",
                "modified": datetime.now(timezone.utc).isoformat() + "Z",
                "name": f"{ioc_type.upper()}: {value[:50]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat() + "Z",
                "confidence": confidence,
                "created_by_ref": identity_id,
            })

        # Create bundle
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": stix_objects,
        }

        # Save STIX bundle
        stix_path = case_path / "iocs" / "stix_bundle.json"
        with open(stix_path, "w") as f:
            json.dump(bundle, f, indent=2)

        return stix_path

    except Exception as e:
        click.echo(f"  Warning: STIX bundle creation failed: {e}")
        return None


def create_csv_exports(case_path: Path, iocs: dict) -> list[Path]:
    """Create CSV exports of IOCs for easy import."""
    csv_files = []

    ioc_list = iocs.get("iocs", [])
    if not ioc_list:
        return csv_files

    # Full IOC CSV
    full_csv = case_path / "iocs" / "iocs_export.csv"
    with open(full_csv, "w") as f:
        f.write("type,value,risk_score,first_seen,context\n")
        for ioc in ioc_list:
            value = ioc.get("value", "").replace('"', '""')
            f.write(
                f'"{ioc.get("type", "")}","{value}",'
                f'{ioc.get("risk_score", 0)},'
                f'"{ioc.get("first_seen", "")}","{ioc.get("context", "")}"\n'
            )
    csv_files.append(full_csv)

    # High-risk only CSV
    high_risk = [i for i in ioc_list if i.get("risk_score", 0) >= 50]
    if high_risk:
        high_risk_csv = case_path / "iocs" / "high_risk_iocs.csv"
        with open(high_risk_csv, "w") as f:
            f.write("type,value,risk_score\n")
            for ioc in high_risk:
                value = ioc.get("value", "").replace('"', '""')
                f.write(f'"{ioc.get("type", "")}","{value}",{ioc.get("risk_score", 0)}\n')
        csv_files.append(high_risk_csv)

    return csv_files


def create_package_zip(
    case_path: Path,
    package_files: dict,
    manifest: dict,
    output_path: Optional[Path] = None,
) -> Path:
    """Create the final ZIP package."""
    if output_path is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = case_path / f"argus_package_{timestamp}.zip"

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add manifest
        manifest_json = json.dumps(manifest, indent=2)
        zf.writestr("MANIFEST.json", manifest_json)

        # Add files by category
        for category, files in package_files.items():
            for file_path in files:
                if file_path.exists():
                    arcname = f"{category}/{file_path.name}"
                    zf.write(file_path, arcname)

        # Add README
        readme = """# ARGUS Analysis Package

This package contains the results of an automated incident response analysis.

## Contents

- `MANIFEST.json` - Package manifest with checksums
- `report/` - Incident reports (Markdown and/or PDF)
- `iocs/` - Indicators of Compromise (JSON, CSV, STIX)
- `detection/` - MITRE mapping, Sigma rules, detection strategy
- `evidence_hashes/` - Evidence file hashes (not raw evidence)
- `logs/` - Phase completion markers

## Usage

1. Review `report/incident_report.md` or `.pdf` for the full analysis
2. Import IOCs from `iocs/` into your security tools
3. Deploy Sigma rules from `detection/sigma_rules/` to your SIEM
4. Use `detection/detection_strategy.md` for remediation planning

## Generated By

ARGUS - Automated Response & Guided Unified Security
"""
        zf.writestr("README.md", readme)

    return output_path


def run_output_packaging(
    case_path_str: str,
    include_stix: bool = True,
    include_csv: bool = True,
) -> bool:
    """Run Phase 8: Output Packaging.

    Args:
        case_path_str: Path to case directory
        include_stix: Whether to generate STIX bundle
        include_csv: Whether to generate CSV exports

    Returns:
        True if successful
    """
    case_path = Path(case_path_str).resolve()

    # Verify case exists
    if not (case_path / "argus.yaml").exists():
        click.echo("Error: Not a valid ARGUS case directory", err=True)
        return False

    # Check if Phase 7 is complete
    if not check_phase_complete(case_path, 7):
        click.echo("Phase 7 not complete. Running report generation first...")
        from argus.phases.phase7_report import run_report_generation
        if not run_report_generation(case_path_str):
            click.echo("Report generation failed. Cannot proceed.")
            return False

    click.echo(f"\nPhase 8: OUTPUT PACKAGING")
    click.echo("=" * 40)

    # Load case metadata
    import yaml
    with open(case_path / "argus.yaml") as f:
        case_meta = yaml.safe_load(f) or {}

    # Load IOCs for STIX/CSV
    iocs = {}
    ioc_file = case_path / "iocs" / "enriched_iocs.json"
    if ioc_file.exists():
        with open(ioc_file) as f:
            iocs = json.load(f)

    # Generate STIX bundle
    if include_stix and iocs:
        click.echo("\nGenerating STIX 2.1 bundle...")
        stix_path = create_stix_bundle(case_path, iocs)
        if stix_path:
            click.echo(f"  STIX bundle: {stix_path.name}")

    # Generate CSV exports
    if include_csv and iocs:
        click.echo("\nGenerating CSV exports...")
        csv_files = create_csv_exports(case_path, iocs)
        for csv_file in csv_files:
            click.echo(f"  CSV: {csv_file.name}")

    # Collect files for package
    click.echo("\nCollecting package files...")
    package_files = collect_package_files(case_path)

    total_files = sum(len(f) for f in package_files.values())
    click.echo(f"  Total files: {total_files}")

    # Build manifest
    manifest = PACKAGE_MANIFEST_TEMPLATE.copy()
    manifest["created_at"] = datetime.now(timezone.utc).isoformat()
    manifest["case_id"] = case_meta.get("case_id", case_path.name)

    # Add file listings and checksums
    checksums = {}
    for category, files in package_files.items():
        manifest["contents"][category] = [f.name for f in files]
        for file_path in files:
            if file_path.exists():
                checksums[f"{category}/{file_path.name}"] = calculate_file_hash(file_path)

    manifest["checksums"] = checksums

    # Create ZIP package
    click.echo("\nCreating ZIP package...")
    zip_path = create_package_zip(case_path, package_files, manifest)
    zip_size = zip_path.stat().st_size

    click.echo(f"  Package: {zip_path.name}")
    click.echo(f"  Size: {zip_size:,} bytes")

    # Summary
    click.echo("\n" + "=" * 40)
    click.echo("Output Packaging Summary")
    click.echo("=" * 40)
    click.echo(f"  Package file:  {zip_path.name}")
    click.echo(f"  Package size:  {zip_size:,} bytes")
    click.echo(f"  Files included: {total_files}")

    if include_stix:
        click.echo(f"  STIX bundle:   Included")
    if include_csv:
        click.echo(f"  CSV exports:   Included")

    # Write completion marker
    write_completion_marker(case_path, 8)

    click.echo(f"\nPhase 8 complete. Package ready: {zip_path}")
    click.echo("\n" + "=" * 40)
    click.echo("ANALYSIS PIPELINE COMPLETE")
    click.echo("=" * 40)

    return True
