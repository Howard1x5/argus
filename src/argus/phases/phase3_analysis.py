"""Phase 3: DEEP ANALYSIS

Phase 3a: ForensicExtractor (programmatic) - queries 100% of data, decodes, correlates
Phase 3b: LLM Agents - interpret complete extraction results

Per SPEC v1.1: Agents receive COMPLETE extraction results, NOT sampled events.
ForensicExtractor does DISCOVERY. Agents do INTERPRETATION.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import click
import pyarrow.parquet as pq

from argus.phases.phase0_init import write_completion_marker
from argus.phases.phase2_triage import check_phase_complete


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


def load_hypotheses(case_path: Path) -> list[dict]:
    """Load hypotheses from Phase 2."""
    hypotheses_file = case_path / "triage" / "hypotheses.json"
    if hypotheses_file.exists():
        with open(hypotheses_file) as f:
            data = json.load(f)
            return data.get("hypotheses", [])
    return []


def load_triage_findings(case_path: Path) -> list[dict]:
    """Load triage findings from Phase 2."""
    findings_file = case_path / "triage" / "merged_findings.json"
    if findings_file.exists():
        with open(findings_file) as f:
            data = json.load(f)
            return data.get("findings", [])
    return []


def load_extraction_results(case_path: Path) -> dict:
    """Load ALL extraction results produced by ForensicExtractor.

    These contain 100% of the evidence, pre-analyzed programmatically.
    Agents should interpret this data, not re-discover it from raw events.
    """
    extractions_dir = case_path / "extractions"
    if not extractions_dir.exists():
        return {}

    context = {}

    # Load every JSON file in the extractions directory
    for json_file in sorted(extractions_dir.glob("*.json")):
        try:
            with open(json_file) as f:
                data = json.load(f)
            key = json_file.stem  # filename without .json
            context[key] = data
        except (json.JSONDecodeError, IOError):
            continue

    return context


def run_analysis(case_path_str: str) -> bool:
    """Run Phase 3: Deep Analysis.

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

    # Check if Phase 2 is complete
    if not check_phase_complete(case_path, 2):
        click.echo("Phase 2 not complete. Running triage first...")
        from argus.phases.phase2_triage import run_triage
        if not run_triage(case_path_str):
            click.echo("Triage failed. Cannot proceed with analysis.")
            return False

    analysis_dir = case_path / "analysis"
    analysis_dir.mkdir(exist_ok=True)

    click.echo(f"\nPhase 3: DEEP ANALYSIS")
    click.echo("=" * 40)

    # Load data
    click.echo("\nLoading evidence...")
    events = load_parquet_events(case_path)
    hypotheses = load_hypotheses(case_path)
    triage_findings = load_triage_findings(case_path)

    click.echo(f"  Events: {len(events)}")
    click.echo(f"  Hypotheses: {len(hypotheses)}")
    click.echo(f"  Triage findings: {len(triage_findings)}")

    if not events:
        click.echo("Warning: No events to analyze")
        write_completion_marker(case_path, 3)
        return True

    # Phase 3a: Run ForensicExtractor (programmatic - queries 100% of data)
    click.echo("\nPhase 3a: Forensic Extraction")
    click.echo("-" * 30)

    extractions_dir = case_path / "extractions"
    extractions_dir.mkdir(exist_ok=True)

    try:
        from argus.extractors.forensic_extractor import ForensicExtractor

        extractor = ForensicExtractor(case_path)
        extractions = extractor.run_all_extractions()

        click.echo(f"  Extractions complete: {len(extractions)} categories")

    except ImportError:
        click.echo("  ForensicExtractor not yet implemented, skipping Phase 3a")
        extractions = {}

    # Load extraction results from disk (in case ForensicExtractor saved them)
    extraction_results = load_extraction_results(case_path)
    if extraction_results:
        click.echo(f"  Loaded {len(extraction_results)} extraction categories for agents")

    # Phase 3b: Run analysis agents with extraction results
    click.echo("\nPhase 3b: Deep Analysis (LLM Agents)")
    click.echo("-" * 30)

    try:
        from argus.agents.analysis_agents import run_analysis_agents

        results = run_analysis_agents(
            events=events,
            hypotheses=hypotheses,
            triage_findings=triage_findings,
            output_dir=analysis_dir,
            extraction_results=extraction_results,  # NEW: Pass extraction data to agents
        )

        # Count total claims
        total_claims = sum(
            len(r.get("claims", [])) 
            for r in results.values() 
            if isinstance(r, dict)
        )

        click.echo(f"\n  Total claims generated: {total_claims}")

        # Save summary
        summary = {
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "events_analyzed": len(events),
            "hypotheses_investigated": len(hypotheses),
            "agents_run": len([r for r in results.values() if isinstance(r, dict) and "error" not in r]),
            "total_claims": total_claims,
        }

        summary_path = analysis_dir / "analysis_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

    except ImportError as e:
        click.echo(click.style(f"  Analysis agents unavailable: {e}", fg="yellow"))
        click.echo("  Skipping LLM analysis.")

    except Exception as e:
        click.echo(click.style(f"  Analysis failed: {e}", fg="red"))
        return False

    # Write completion marker
    write_completion_marker(case_path, 3)

    click.echo(f"\nPhase 3 complete. Results in: {analysis_dir}")
    return True
