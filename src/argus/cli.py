"""ARGUS CLI - Command Line Interface for the IR analysis pipeline."""

import click
import sys
from pathlib import Path

from argus.banner import print_banner
from argus.config import is_first_run, check_api_keys, get_api_key


def check_required_api_key(key_name: str = "anthropic") -> bool:
    """Check if a required API key is available.

    Returns True if available, prints warning and returns False if not.
    """
    if not get_api_key(key_name):
        click.echo(click.style(f"\nError: {key_name} API key not configured.", fg="red"))
        click.echo("Run 'argus setup' to configure API keys.")
        click.echo("Then set the environment variable in your shell.\n")
        return False
    return True


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version and exit.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner output.")
@click.pass_context
def main(ctx: click.Context, version: bool, quiet: bool) -> None:
    """ARGUS - Automated Response & Guided Unified Security.

    CLI-based automated Incident Response analysis pipeline.
    """
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet

    if version:
        click.echo("ARGUS v0.1.0")
        sys.exit(0)

    if not quiet:
        print_banner(small=True)

    # Check for first run
    if is_first_run() and ctx.invoked_subcommand not in ("setup", None):
        click.echo(click.style("\nFirst run detected!", fg="yellow"))
        click.echo("Run 'argus setup' to configure API keys and preferences.\n")

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument("case_path", type=click.Path())
@click.option("--evidence", "-e", type=click.Path(exists=True), help="Path to evidence file or directory.")
@click.pass_context
def init(ctx: click.Context, case_path: str, evidence: str) -> None:
    """Initialize a new case directory with config template.

    CASE_PATH: Path where the case directory will be created.
    """
    from argus.phases.phase0_init import run_init

    if not ctx.obj.get("quiet"):
        click.echo(f"\nInitializing case: {case_path}")

    run_init(case_path, evidence)


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, help="Stream real-time detail.")
@click.option("--resume", is_flag=True, help="Resume from last completed phase.")
@click.option("--auto-generate", is_flag=True, help="Auto-generate parsers for unknown formats.")
@click.pass_context
def analyze(ctx: click.Context, case_path: str, verbose: bool, resume: bool, auto_generate: bool) -> None:
    """Run full analysis pipeline on a case.

    CASE_PATH: Path to an existing case directory.
    """
    from argus.phases.phase1_ingest import run_ingest
    from argus.phases.phase2_triage import run_triage

    # Phase 1: Ingest (doesn't require API key)
    click.echo(f"\nStarting analysis pipeline: {case_path}")

    if not run_ingest(case_path, auto_generate_parsers=auto_generate):
        click.echo("Ingestion failed. Fix errors and retry.")
        raise click.Abort()

    # Phase 2+ requires API key
    if not check_required_api_key("anthropic"):
        click.echo("\nPhase 1 complete. Configure API key to continue with triage.")
        raise click.Abort()

    # Phase 2: Triage
    if not run_triage(case_path):
        click.echo("Triage failed. Check logs for details.")
        raise click.Abort()

    # Phase 3: Deep Analysis
    from argus.phases.phase3_analysis import run_analysis
    if not run_analysis(case_path):
        click.echo("Analysis failed. Check logs for details.")
        raise click.Abort()

    # Phase 4: Validation (100% programmatic)
    from argus.phases.phase4_validation import run_validation
    if not run_validation(case_path):
        click.echo("Validation failed. Check logs for details.")
        raise click.Abort()

    # Phase 5: IOC Extraction
    from argus.phases.phase5_ioc import run_ioc_extraction
    if not run_ioc_extraction(case_path):
        click.echo("IOC extraction failed. Check logs for details.")
        raise click.Abort()

    # Phase 6: Detection Engineering
    from argus.phases.phase6_detection import run_detection_engineering
    if not run_detection_engineering(case_path):
        click.echo("Detection engineering failed. Check logs for details.")
        raise click.Abort()

    # Phase 7: Report Generation
    from argus.phases.phase7_report import run_report_generation
    if not run_report_generation(case_path):
        click.echo("Report generation failed. Check logs for details.")
        raise click.Abort()

    # Phase 8: Output Packaging
    from argus.phases.phase8_package import run_output_packaging
    if not run_output_packaging(case_path):
        click.echo("Output packaging failed. Check logs for details.")
        raise click.Abort()

    click.echo("\n" + "=" * 50)
    click.echo("ARGUS ANALYSIS PIPELINE COMPLETE")
    click.echo("=" * 50)


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--skip-llm", is_flag=True, help="Skip LLM triage agents (programmatic only).")
@click.pass_context
def triage(ctx: click.Context, case_path: str, skip_llm: bool) -> None:
    """Run only triage phases (Phase 0-2.5).

    CASE_PATH: Path to an existing case directory.
    """
    from argus.phases.phase2_triage import run_triage

    if not skip_llm and not check_required_api_key("anthropic"):
        click.echo("LLM triage requires API key. Use --skip-llm for programmatic only.")
        raise click.Abort()

    if not run_triage(case_path, skip_llm_agents=skip_llm):
        click.echo("Triage failed. Check logs for details.")
        raise click.Abort()


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--pdf/--no-pdf", default=True, help="Generate PDF version.")
@click.pass_context
def report(ctx: click.Context, case_path: str, pdf: bool) -> None:
    """Regenerate report from existing analysis.

    CASE_PATH: Path to an existing case directory with completed analysis.
    """
    from argus.phases.phase7_report import run_report_generation

    click.echo(f"\nRegenerating report for: {case_path}")

    if not run_report_generation(case_path, pdf=pdf):
        click.echo("Report generation failed. Check logs for details.")
        raise click.Abort()


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--skip-pdf", is_flag=True, help="Skip PDF generation.")
@click.option("--no-stix", is_flag=True, help="Skip STIX bundle generation.")
@click.option("--no-csv", is_flag=True, help="Skip CSV exports.")
@click.pass_context
def finalize(ctx: click.Context, case_path: str, skip_pdf: bool, no_stix: bool, no_csv: bool) -> None:
    """Convert reviewed draft to PDF and package output.

    CASE_PATH: Path to case directory with reviewed report_draft.md.
    """
    from argus.phases.phase7_report import run_report_generation
    from argus.phases.phase8_package import run_output_packaging

    click.echo(f"\nFinalizing case: {case_path}")

    # Regenerate report with PDF if not skipped
    if not run_report_generation(case_path, pdf=not skip_pdf):
        click.echo("Report generation failed.")
        raise click.Abort()

    # Create final package
    if not run_output_packaging(case_path, include_stix=not no_stix, include_csv=not no_csv):
        click.echo("Output packaging failed.")
        raise click.Abort()


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.pass_context
def status(ctx: click.Context, case_path: str) -> None:
    """Show pipeline progress for a case.

    CASE_PATH: Path to an existing case directory.
    """
    from pathlib import Path
    import yaml
    from argus.phases.phase2_triage import check_phase_complete

    case = Path(case_path).resolve()

    if not (case / "argus.yaml").exists():
        click.echo(click.style("Error: Not a valid ARGUS case directory", fg="red"))
        raise click.Abort()

    # Load case metadata
    with open(case / "argus.yaml") as f:
        meta = yaml.safe_load(f) or {}

    click.echo(f"\nCase: {meta.get('case_id', case.name)}")
    click.echo("=" * 50)

    # Phase status
    phases = [
        (0, "Init", "Case initialized"),
        (1, "Ingest", "Evidence parsed"),
        (2, "Triage", "Suspicious patterns found"),
        (3, "Analysis", "Deep analysis complete"),
        (4, "Validation", "Claims validated"),
        (5, "IOC", "IOCs extracted"),
        (6, "Detection", "Detection rules generated"),
        (7, "Report", "Report generated"),
        (8, "Package", "Output packaged"),
    ]

    click.echo("\nPhase Status:")
    click.echo("-" * 50)

    last_completed = -1
    for phase_num, name, desc in phases:
        complete = check_phase_complete(case, phase_num)
        if complete:
            last_completed = phase_num
            status_icon = click.style("✓", fg="green")
        else:
            status_icon = click.style("○", fg="yellow")
        click.echo(f"  {status_icon} Phase {phase_num}: {name} - {desc}")

    # Summary
    click.echo("-" * 50)
    if last_completed == 8:
        click.echo(click.style("  All phases complete!", fg="green"))
    elif last_completed >= 0:
        next_phase = phases[last_completed + 1] if last_completed < 8 else None
        if next_phase:
            click.echo(f"  Next: Phase {next_phase[0]} ({next_phase[1]})")
            click.echo(f"  Run: argus resume {case_path}")
    else:
        click.echo("  No phases complete yet.")
        click.echo(f"  Run: argus analyze {case_path}")

    # Key stats if available
    parsed_dir = case / "parsed"
    if parsed_dir.exists():
        parquet_count = len(list(parsed_dir.glob("*.parquet")))
        click.echo(f"\n  Evidence files parsed: {parquet_count}")

    triage_file = case / "triage" / "suspicious_findings.json"
    if triage_file.exists():
        import json
        with open(triage_file) as f:
            findings = json.load(f)
            click.echo(f"  Suspicious findings: {findings.get('total_findings', 0)}")

    ioc_file = case / "iocs" / "enriched_iocs.json"
    if ioc_file.exists():
        import json
        with open(ioc_file) as f:
            iocs = json.load(f)
            click.echo(f"  IOCs extracted: {iocs.get('total_iocs', 0)}")


@main.command("run-phase")
@click.argument("phase_num", type=int)
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--guidance", type=click.Path(exists=True), help="Analyst guidance document.")
@click.option("--force", is_flag=True, help="Force re-run even if already complete.")
@click.pass_context
def run_phase(ctx: click.Context, phase_num: int, case_path: str, guidance: str, force: bool) -> None:
    """Re-run a specific phase.

    PHASE_NUM: Phase number to run (0-8).
    CASE_PATH: Path to an existing case directory.
    """
    from pathlib import Path
    from argus.phases.phase2_triage import check_phase_complete

    case = Path(case_path).resolve()

    if phase_num < 0 or phase_num > 8:
        click.echo(click.style("Error: Phase number must be 0-8", fg="red"))
        raise click.Abort()

    if not force and check_phase_complete(case, phase_num):
        click.echo(f"Phase {phase_num} already complete. Use --force to re-run.")
        return

    click.echo(f"\nRunning Phase {phase_num} on: {case_path}")
    if guidance:
        click.echo(f"  with guidance: {guidance}")
        # TODO: Load guidance and inject into phase context

    # Phase dispatch
    phase_runners = {
        0: ("argus.phases.phase0_init", "run_init"),
        1: ("argus.phases.phase1_ingest", "run_ingest"),
        2: ("argus.phases.phase2_triage", "run_triage"),
        3: ("argus.phases.phase3_analysis", "run_analysis"),
        4: ("argus.phases.phase4_validation", "run_validation"),
        5: ("argus.phases.phase5_ioc", "run_ioc_extraction"),
        6: ("argus.phases.phase6_detection", "run_detection_engineering"),
        7: ("argus.phases.phase7_report", "run_report_generation"),
        8: ("argus.phases.phase8_package", "run_output_packaging"),
    }

    module_name, func_name = phase_runners[phase_num]

    # Check API key for LLM phases
    if phase_num in [2, 3] and not check_required_api_key("anthropic"):
        raise click.Abort()

    # Import and run
    import importlib
    module = importlib.import_module(module_name)
    runner = getattr(module, func_name)

    if not runner(str(case)):
        click.echo(f"Phase {phase_num} failed. Check logs for details.")
        raise click.Abort()

    click.echo(f"\nPhase {phase_num} complete.")


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.pass_context
def resume(ctx: click.Context, case_path: str) -> None:
    """Resume analysis from last completed phase.

    CASE_PATH: Path to an existing case directory.
    """
    from pathlib import Path
    from argus.phases.phase2_triage import check_phase_complete

    case = Path(case_path).resolve()

    if not (case / "argus.yaml").exists():
        click.echo(click.style("Error: Not a valid ARGUS case directory", fg="red"))
        raise click.Abort()

    # Find last completed phase
    last_completed = -1
    for phase_num in range(9):
        if check_phase_complete(case, phase_num):
            last_completed = phase_num
        else:
            break

    if last_completed == 8:
        click.echo("All phases already complete. Nothing to resume.")
        return

    next_phase = last_completed + 1
    click.echo(f"\nResuming from Phase {next_phase}...")

    # Phase runners
    phase_runners = [
        ("argus.phases.phase0_init", "run_init"),
        ("argus.phases.phase1_ingest", "run_ingest"),
        ("argus.phases.phase2_triage", "run_triage"),
        ("argus.phases.phase3_analysis", "run_analysis"),
        ("argus.phases.phase4_validation", "run_validation"),
        ("argus.phases.phase5_ioc", "run_ioc_extraction"),
        ("argus.phases.phase6_detection", "run_detection_engineering"),
        ("argus.phases.phase7_report", "run_report_generation"),
        ("argus.phases.phase8_package", "run_output_packaging"),
    ]

    # Check API key for LLM phases
    if next_phase in [2, 3] and not check_required_api_key("anthropic"):
        raise click.Abort()

    # Run remaining phases
    import importlib
    for phase_num in range(next_phase, 9):
        module_name, func_name = phase_runners[phase_num]

        # Check API key if entering LLM phase
        if phase_num in [2, 3] and not check_required_api_key("anthropic"):
            click.echo(f"\nStopped at Phase {phase_num} - API key required.")
            raise click.Abort()

        module = importlib.import_module(module_name)
        runner = getattr(module, func_name)

        if not runner(str(case)):
            click.echo(f"Phase {phase_num} failed. Check logs for details.")
            raise click.Abort()

    click.echo("\n" + "=" * 50)
    click.echo("ARGUS ANALYSIS PIPELINE COMPLETE")
    click.echo("=" * 50)


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.pass_context
def enrich(ctx: click.Context, case_path: str) -> None:
    """Run or re-run IOC enrichment.

    CASE_PATH: Path to an existing case directory.
    """
    from pathlib import Path
    import json
    import time
    from argus.config import get_api_key
    from argus.phases.phase5_ioc import (
        enrich_with_virustotal,
        enrich_with_abuseipdb,
        calculate_risk_score,
    )

    case = Path(case_path).resolve()

    ioc_file = case / "iocs" / "enriched_iocs.json"
    if not ioc_file.exists():
        click.echo(click.style("Error: No IOCs found. Run analysis first.", fg="red"))
        raise click.Abort()

    click.echo(f"\nEnriching IOCs for: {case_path}")

    # Check API keys
    vt_key = get_api_key("virustotal")
    abuseipdb_key = get_api_key("abuseipdb")

    if not vt_key and not abuseipdb_key:
        click.echo(click.style("No enrichment API keys configured.", fg="yellow"))
        click.echo("Configure via 'argus setup' and set environment variables:")
        click.echo("  - VIRUSTOTAL_API_KEY")
        click.echo("  - ABUSEIPDB_API_KEY")
        raise click.Abort()

    sources = []
    if vt_key:
        sources.append("VirusTotal")
    if abuseipdb_key:
        sources.append("AbuseIPDB")
    click.echo(f"  Using: {', '.join(sources)}")

    # Load existing IOCs
    with open(ioc_file) as f:
        data = json.load(f)

    ioc_records = data.get("iocs", [])
    enriched_count = 0

    click.echo(f"\nEnriching {len(ioc_records)} IOCs...")

    with click.progressbar(ioc_records[:100], label="Enriching") as bar:
        for ioc_record in bar:
            ioc = ioc_record["value"]
            ioc_type = ioc_record["type"]

            # Clear existing enrichment
            ioc_record["enrichment"] = []

            # VirusTotal
            if vt_key and ioc_type in ["ipv4", "domain", "md5", "sha1", "sha256"]:
                vt_data = enrich_with_virustotal(ioc, ioc_type, vt_key)
                if vt_data:
                    ioc_record["enrichment"].append(vt_data)
                    enriched_count += 1
                time.sleep(0.25)  # Rate limit

            # AbuseIPDB
            if abuseipdb_key and ioc_type == "ipv4":
                abuse_data = enrich_with_abuseipdb(ioc, abuseipdb_key)
                if abuse_data:
                    ioc_record["enrichment"].append(abuse_data)

            # Recalculate risk score
            ioc_record["risk_score"] = calculate_risk_score(
                ioc, ioc_type, ioc_record["enrichment"]
            )

    # Sort by risk score
    ioc_records.sort(key=lambda x: x["risk_score"], reverse=True)

    # Update file
    data["iocs"] = ioc_records
    data["high_risk"] = len([i for i in ioc_records if i["risk_score"] >= 50])
    data["enrichment_sources"] = sources

    with open(ioc_file, "w") as f:
        json.dump(data, f, indent=2)

    click.echo(f"\nEnriched: {enriched_count} IOCs")
    click.echo(f"High-risk (50+): {data['high_risk']}")
    click.echo(click.style("Enrichment complete!", fg="green"))


@main.command()
@click.argument("case_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for lessons learned.")
@click.pass_context
def debrief(ctx: click.Context, case_path: str, output: str) -> None:
    """Post-case lessons learned interview.

    CASE_PATH: Path to a completed case directory.
    """
    from pathlib import Path
    import json
    from datetime import datetime, timezone

    case = Path(case_path).resolve()

    if not (case / "argus.yaml").exists():
        click.echo(click.style("Error: Not a valid ARGUS case directory", fg="red"))
        raise click.Abort()

    click.echo(f"\n{'=' * 50}")
    click.echo("ARGUS POST-INCIDENT DEBRIEF")
    click.echo(f"{'=' * 50}")
    click.echo("\nThis debrief captures lessons learned for future analysis.")
    click.echo("Press Ctrl+C to skip any question.\n")

    lessons = {
        "case_path": str(case),
        "debrief_date": datetime.now(timezone.utc).isoformat(),
        "responses": {},
    }

    questions = [
        ("detection_gaps", "What detection gaps were identified? (What did we miss initially?)"),
        ("tool_limitations", "Were there any tool or data limitations during analysis?"),
        ("false_positives", "What false positives were encountered?"),
        ("process_improvements", "What process improvements would help in future cases?"),
        ("notable_techniques", "What notable attacker techniques were observed?"),
        ("additional_training", "What additional training or documentation would be helpful?"),
        ("analyst_notes", "Any other notes or observations?"),
    ]

    try:
        for key, question in questions:
            click.echo(f"\n{question}")
            response = click.prompt("  ", default="", show_default=False)
            if response.strip():
                lessons["responses"][key] = response.strip()
    except click.Abort:
        click.echo("\n\nDebrief cancelled.")
        return

    # Save lessons
    if output:
        output_path = Path(output)
    else:
        output_path = case / "debrief" / "lessons_learned.json"
        output_path.parent.mkdir(exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(lessons, f, indent=2)

    click.echo(f"\n\nLessons saved to: {output_path}")
    click.echo(click.style("Debrief complete!", fg="green"))


@main.command("list")
@click.pass_context
def list_cases(ctx: click.Context) -> None:
    """List all cases tracked by ARGUS."""
    from pathlib import Path
    import yaml
    from argus.config import ARGUS_HOME
    from argus.phases.phase2_triage import check_phase_complete

    cases_log = ARGUS_HOME / "cases.log"

    if not cases_log.exists():
        click.echo("\nNo cases tracked yet.")
        click.echo("Run 'argus init <path>' to create a new case.")
        return

    click.echo("\nTracked Cases:")
    click.echo("=" * 70)

    with open(cases_log) as f:
        lines = f.readlines()

    for line in lines:
        case_path = Path(line.strip())
        if not case_path.exists():
            continue

        yaml_file = case_path / "argus.yaml"
        if not yaml_file.exists():
            continue

        try:
            with open(yaml_file) as f:
                meta = yaml.safe_load(f) or {}
        except Exception:
            meta = {}

        case_id = meta.get("case_id", case_path.name)

        # Count completed phases
        completed = sum(1 for p in range(9) if check_phase_complete(case_path, p))

        status = "COMPLETE" if completed == 9 else f"Phase {completed}/9"
        status_color = "green" if completed == 9 else "yellow"

        click.echo(f"\n  {case_id}")
        click.echo(f"    Path: {case_path}")
        click.echo(f"    Status: {click.style(status, fg=status_color)}")
        click.echo(f"    Created: {meta.get('created_at', 'Unknown')[:19]}")


@main.command("add-pattern")
@click.argument("name")
@click.option("--regex", required=True, help="Regex pattern to match.")
@click.option("--severity", type=click.Choice(["low", "medium", "high"]), default="medium")
@click.option("--description", default="", help="Description of the pattern.")
@click.pass_context
def add_pattern(
    ctx: click.Context, name: str, regex: str, severity: str, description: str
) -> None:
    """Add a custom pattern to the pattern library.

    NAME: Name for the pattern.
    """
    import re
    import json
    from argus.config import ARGUS_HOME

    # Validate regex
    try:
        re.compile(regex)
    except re.error as e:
        click.echo(click.style(f"Invalid regex: {e}", fg="red"))
        raise click.Abort()

    patterns_file = ARGUS_HOME / "custom_patterns.json"

    if patterns_file.exists():
        with open(patterns_file) as f:
            patterns = json.load(f)
    else:
        patterns = {"patterns": [], "false_positives": []}

    # Check for duplicate
    for p in patterns["patterns"]:
        if p["name"] == name:
            click.echo(click.style(f"Pattern '{name}' already exists.", fg="yellow"))
            if not click.confirm("Overwrite?"):
                return
            patterns["patterns"].remove(p)
            break

    patterns["patterns"].append({
        "name": name,
        "regex": regex,
        "severity": severity,
        "description": description or f"Custom pattern: {name}",
    })

    with open(patterns_file, "w") as f:
        json.dump(patterns, f, indent=2)

    click.echo(click.style(f"Pattern '{name}' added successfully!", fg="green"))
    click.echo(f"  Regex: {regex}")
    click.echo(f"  Severity: {severity}")


@main.command("add-false-positive")
@click.argument("description")
@click.option("--pattern", required=True, help="Regex pattern to suppress.")
@click.pass_context
def add_false_positive(ctx: click.Context, description: str, pattern: str) -> None:
    """Add a false positive to the suppression list.

    DESCRIPTION: Description of why this is a false positive.
    """
    import re
    import json
    from datetime import datetime, timezone
    from argus.config import ARGUS_HOME

    # Validate regex
    try:
        re.compile(pattern)
    except re.error as e:
        click.echo(click.style(f"Invalid regex: {e}", fg="red"))
        raise click.Abort()

    patterns_file = ARGUS_HOME / "custom_patterns.json"

    if patterns_file.exists():
        with open(patterns_file) as f:
            patterns = json.load(f)
    else:
        patterns = {"patterns": [], "false_positives": []}

    patterns["false_positives"].append({
        "pattern": pattern,
        "description": description,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })

    with open(patterns_file, "w") as f:
        json.dump(patterns, f, indent=2)

    click.echo(click.style("False positive added successfully!", fg="green"))
    click.echo(f"  Pattern: {pattern}")
    click.echo(f"  Reason: {description}")


@main.command()
@click.pass_context
def setup(ctx: click.Context) -> None:
    """First-run setup and configuration."""
    from argus.config import (
        ensure_argus_home,
        load_config,
        save_config,
        check_api_keys,
        CONFIG_FILE,
    )

    click.echo("\nARGUS Setup")
    click.echo("=" * 40)

    # Ensure directory structure exists
    ensure_argus_home()

    click.echo("\nAPI keys are stored as environment variable references.")
    click.echo("Set the actual keys in your shell profile (~/.bashrc, ~/.zshrc, etc.)\n")

    # Define API keys to configure
    api_keys_info = [
        ("anthropic", "ANTHROPIC_API_KEY", "Anthropic Claude API (REQUIRED for analysis)"),
        ("virustotal", "VIRUSTOTAL_API_KEY", "VirusTotal (optional, IOC enrichment)"),
        ("abuseipdb", "ABUSEIPDB_API_KEY", "AbuseIPDB (optional, IOC enrichment)"),
        ("shodan", "SHODAN_API_KEY", "Shodan (optional, IOC enrichment)"),
        ("alienvault_otx", "ALIENVAULT_OTX_KEY", "AlienVault OTX (optional, IOC enrichment)"),
    ]

    config = load_config()
    if "api_keys" not in config:
        config["api_keys"] = {}

    click.echo("Configure environment variable names for API keys:\n")

    for key_name, default_env, description in api_keys_info:
        current = config.get("api_keys", {}).get(key_name, f"${{{default_env}}}")
        # Extract env var name from ${VAR} format
        if current.startswith("${") and current.endswith("}"):
            current_env = current[2:-1]
        else:
            current_env = default_env

        prompt = f"  {description}\n  Environment variable"
        env_var = click.prompt(prompt, default=current_env, show_default=True)
        config["api_keys"][key_name] = f"${{{env_var}}}"

    click.echo("\n" + "-" * 40)
    click.echo("Default settings:\n")

    # Configure defaults
    config["defaults"]["max_cost_per_case"] = click.prompt(
        "  Max API cost per case (USD)",
        default=config.get("defaults", {}).get("max_cost_per_case", 15.0),
        type=float,
    )

    config["defaults"]["timestamp_tolerance"] = click.prompt(
        "  Timestamp tolerance for correlation (seconds)",
        default=config.get("defaults", {}).get("timestamp_tolerance", 2),
        type=int,
    )

    # Save configuration
    save_config(config)
    click.echo(f"\nConfiguration saved to: {CONFIG_FILE}")

    # Check which keys are available
    click.echo("\n" + "-" * 40)
    click.echo("API Key Status:\n")

    key_status = check_api_keys()
    all_good = True
    for key_name, available in key_status.items():
        status = click.style("OK", fg="green") if available else click.style("NOT SET", fg="yellow")
        click.echo(f"  {key_name}: {status}")
        if key_name == "anthropic" and not available:
            all_good = False

    if not key_status.get("anthropic", False):
        click.echo(click.style("\nWARNING: Anthropic API key not set!", fg="red"))
        click.echo("Set it in your shell profile:")
        env_var = config["api_keys"]["anthropic"][2:-1]  # Extract from ${VAR}
        click.echo(f'  export {env_var}="your-api-key-here"')

    click.echo("\nSetup complete!")


@main.command("generate-parser")
@click.argument("sample_file", type=click.Path(exists=True))
@click.option("--name", "-n", help="Name for the parser (derived from filename if not provided).")
@click.option("--test/--no-test", default=True, help="Test the generated parser against the sample file.")
@click.pass_context
def generate_parser(ctx: click.Context, sample_file: str, name: str, test: bool) -> None:
    """Generate a parser for an unknown file format using LLM.

    SAMPLE_FILE: Path to a sample file of the format to parse.

    The generated parser will be saved to ~/.argus/custom_parsers/ and
    automatically loaded for future use.
    """
    from argus.parsers.generator import generate_and_save_parser
    from argus.parsers.detector import detect_parser

    file_path = Path(sample_file)

    # Check if we already have a parser for this
    existing = detect_parser(file_path)
    if existing:
        click.echo(f"\nExisting parser found: {existing.name}")
        if not click.confirm("Generate a new custom parser anyway?"):
            return

    if not check_required_api_key("anthropic"):
        raise click.Abort()

    click.echo(f"\nGenerating parser for: {file_path.name}")
    if name:
        click.echo(f"  Parser name: {name}")

    try:
        with click.progressbar(length=3, label="Generating") as bar:
            bar.update(1)  # Analyzing file
            parser_path, parser_class = generate_and_save_parser(
                file_path, name, validate=test
            )
            bar.update(2)  # Generated and validated

        click.echo(click.style("\nParser generated successfully!", fg="green"))
        click.echo(f"  Name: {parser_class.name}")
        click.echo(f"  Description: {parser_class.description}")
        click.echo(f"  Saved to: {parser_path}")

        if test:
            click.echo(click.style("  Validation: PASSED", fg="green"))

    except Exception as e:
        click.echo(click.style(f"\nError generating parser: {e}", fg="red"))
        raise click.Abort()


@main.command("list-parsers")
@click.option("--custom-only", is_flag=True, help="Only show custom parsers.")
@click.option("--builtin-only", is_flag=True, help="Only show built-in parsers.")
@click.pass_context
def list_parsers(ctx: click.Context, custom_only: bool, builtin_only: bool) -> None:
    """List all available parsers.

    Shows both built-in parsers and custom parsers from ~/.argus/custom_parsers/.
    """
    from argus.parsers.detector import get_supported_formats, list_custom_parsers, PARSERS

    if custom_only:
        custom = list_custom_parsers()
        if not custom:
            click.echo("\nNo custom parsers found.")
            click.echo("Use 'argus generate-parser <file>' to create one.")
            return

        click.echo(f"\nCustom parsers ({len(custom)}):")
        click.echo("-" * 50)
        for p in custom:
            click.echo(f"  {p['name']}: {p['description']}")
            click.echo(f"    Extensions: {', '.join(p['extensions'])}")
        return

    if builtin_only:
        click.echo(f"\nBuilt-in parsers ({len(PARSERS)}):")
        click.echo("-" * 50)
        for parser_class in PARSERS:
            click.echo(f"  {parser_class.name}: {parser_class.description}")
        return

    # Show all
    formats = get_supported_formats(include_custom=True)
    custom = list_custom_parsers()
    custom_names = {p["name"] for p in custom}

    click.echo(f"\nAll parsers ({len(formats)} total):")
    click.echo("-" * 50)

    # Built-in parsers
    click.echo("\nBuilt-in:")
    for name, desc in sorted(formats.items()):
        if name not in custom_names:
            click.echo(f"  {name}: {desc}")

    # Custom parsers
    if custom:
        click.echo("\nCustom (auto-generated):")
        for p in custom:
            click.echo(f"  {p['name']}: {p['description']}")


@main.command("delete-parser")
@click.argument("parser_name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def delete_parser(ctx: click.Context, parser_name: str, yes: bool) -> None:
    """Delete a custom parser.

    PARSER_NAME: Name of the custom parser to delete.
    """
    from argus.parsers.generator import CUSTOM_PARSERS_DIR

    # Find the parser file
    parser_file = None
    for f in CUSTOM_PARSERS_DIR.glob("*.py"):
        if f.stem == parser_name or f.stem == parser_name.replace("-", "_"):
            parser_file = f
            break

    if not parser_file or not parser_file.exists():
        click.echo(click.style(f"Custom parser not found: {parser_name}", fg="red"))
        click.echo("Use 'argus list-parsers --custom-only' to see available custom parsers.")
        raise click.Abort()

    if not yes:
        if not click.confirm(f"Delete custom parser '{parser_name}'?"):
            return

    parser_file.unlink()
    click.echo(click.style(f"Deleted: {parser_file}", fg="green"))


if __name__ == "__main__":
    main()
