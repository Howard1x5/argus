"""Phase 0: INIT - Case directory initialization.

Creates case directory structure, copies evidence, computes hashes,
sets read-only permissions, and generates case config.
"""

import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import yaml


CASE_STRUCTURE = [
    "evidence",
    "parsed",
    "triage",
    "analysis/agents",
    "validation",
    "iocs",
    "detection/sigma_rules",
    "report/figures",
    "logs/phase_completions",
    "output",
]


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def create_case_structure(case_path: Path) -> None:
    """Create all required directories for a case."""
    for subdir in CASE_STRUCTURE:
        (case_path / subdir).mkdir(parents=True, exist_ok=True)
    click.echo(f"  Created directory structure")


def copy_evidence(case_path: Path, evidence_source: Optional[Path] = None) -> dict:
    """Copy evidence files and compute hashes.

    Returns dict mapping filename to SHA-256 hash.
    """
    evidence_dir = case_path / "evidence"
    hashes = {}

    if evidence_source and evidence_source.exists():
        if evidence_source.is_file():
            # Single file
            dest = evidence_dir / evidence_source.name
            shutil.copy2(evidence_source, dest)
            hashes[evidence_source.name] = compute_sha256(dest)
            click.echo(f"  Copied: {evidence_source.name}")
        elif evidence_source.is_dir():
            # Directory of files
            for item in evidence_source.iterdir():
                if item.is_file():
                    dest = evidence_dir / item.name
                    shutil.copy2(item, dest)
                    hashes[item.name] = compute_sha256(dest)
                    click.echo(f"  Copied: {item.name}")

    # Write hashes file
    hashes_file = evidence_dir / "hashes.json"
    with open(hashes_file, "w") as f:
        json.dump(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "algorithm": "SHA-256",
                "files": hashes,
            },
            f,
            indent=2,
        )

    return hashes


def set_evidence_readonly(case_path: Path) -> None:
    """Set evidence directory to read-only permissions."""
    evidence_dir = case_path / "evidence"

    for root, dirs, files in os.walk(evidence_dir):
        for name in files:
            file_path = Path(root) / name
            # Set file to read-only (444)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    click.echo("  Set evidence files to read-only")


def generate_case_config(case_path: Path, case_name: str) -> None:
    """Generate argus.yaml case configuration."""
    config = {
        "case_id": case_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "classification": "INTERNAL",
        "case": {
            "name": case_name,
            "created": datetime.now(timezone.utc).isoformat(),
            "status": "initialized",
        },
        "systems": [],  # Auto-detected in Phase 1
        "settings": {
            "timestamp_tolerance_seconds": 2,
            "max_cost_usd": 15.00,
        },
        "phases_completed": [],
    }

    config_path = case_path / "argus.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"  Generated: argus.yaml")


def write_completion_marker(case_path: Path, phase: int) -> None:
    """Write phase completion marker with timestamp."""
    marker_path = case_path / "logs" / "phase_completions" / f"phase_{phase}.complete"
    with open(marker_path, "w") as f:
        f.write(f"completed_at: {datetime.now(timezone.utc).isoformat()}\n")


def register_case(case_path: Path, case_name: str) -> None:
    """Register case in ~/.argus/cases.log."""
    argus_home = Path.home() / ".argus"
    argus_home.mkdir(exist_ok=True)
    cases_log = argus_home / "cases.log"

    # Read existing entries to avoid duplicates
    existing = set()
    if cases_log.exists():
        with open(cases_log) as f:
            existing = {line.strip() for line in f if line.strip()}

    case_path_str = str(case_path.absolute())
    if case_path_str not in existing:
        with open(cases_log, "a") as f:
            f.write(f"{case_path_str}\n")


def run_init(case_path_str: str, evidence_source: Optional[str] = None) -> None:
    """Run Phase 0: Initialize a new case.

    Args:
        case_path_str: Path where case directory will be created
        evidence_source: Optional path to evidence files to copy
    """
    case_path = Path(case_path_str).resolve()
    case_name = case_path.name

    # Check if case already exists
    if case_path.exists() and (case_path / "argus.yaml").exists():
        click.echo(f"Error: Case already exists at {case_path}", err=True)
        raise click.Abort()

    # Create case directory
    case_path.mkdir(parents=True, exist_ok=True)
    click.echo(f"\nPhase 0: INIT")
    click.echo("=" * 40)

    # Create structure
    create_case_structure(case_path)

    # Copy evidence if provided
    evidence_path = Path(evidence_source) if evidence_source else None
    hashes = copy_evidence(case_path, evidence_path)

    if hashes:
        set_evidence_readonly(case_path)
        click.echo(f"  Hashed {len(hashes)} evidence file(s)")
    else:
        click.echo("  No evidence files provided (add later with evidence copy)")

    # Generate config
    generate_case_config(case_path, case_name)

    # Write completion marker
    write_completion_marker(case_path, 0)

    # Register in global case log
    register_case(case_path, case_name)

    click.echo(f"\nCase initialized: {case_path}")
    click.echo("Next: Copy evidence to ./evidence/ and run 'argus analyze'")
