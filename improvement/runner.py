#!/usr/bin/env python3
"""ARGUS Self-Improvement Runner (Orchestrator).

Main CLI for the automated improvement pipeline.
Commands:
  add-case    Create a new test case directory
  run         Run ARGUS pipeline and compare against answer key
  regression  Run all cases and check for score regressions
  scores      Show score history with trends
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from improvement.comparator import compare, print_summary
from improvement.fix_generator import generate_fix_instructions


# Directories relative to ARGUS project root
IMPROVEMENT_DIR = Path(__file__).parent
CASES_DIR = IMPROVEMENT_DIR / "cases"
RESULTS_DIR = IMPROVEMENT_DIR / "results"
SCORES_FILE = IMPROVEMENT_DIR / "scores" / "score_history.json"
PROJECT_ROOT = IMPROVEMENT_DIR.parent


def discover_argus_command() -> list:
    """Discover the correct ARGUS CLI command.

    Returns:
        Command list for subprocess, e.g., ["python", "-m", "argus.cli"]
    """
    # Try different invocations
    candidates = [
        ["python", "-m", "argus.cli"],
        ["python", "-m", "argus"],
        [str(PROJECT_ROOT / ".venv" / "bin" / "python"), "-m", "argus.cli"],
    ]

    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd + ["--help"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=PROJECT_ROOT
            )
            if result.returncode == 0 and "ARGUS" in result.stdout:
                return cmd
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    # Default fallback
    return ["python", "-m", "argus.cli"]


def add_case(case_name: str) -> bool:
    """Create a new test case directory from template.

    Args:
        case_name: Name for the new case

    Returns:
        True if successful
    """
    case_dir = CASES_DIR / case_name
    evidence_dir = case_dir / "evidence"

    if case_dir.exists():
        print(f"Error: Case '{case_name}' already exists at {case_dir}")
        return False

    # Create directories
    case_dir.mkdir(parents=True)
    evidence_dir.mkdir()

    # Copy template answer key
    template_path = CASES_DIR / "_template" / "answer_key_template.json"
    answer_key_path = case_dir / "answer_key.json"

    if template_path.exists():
        with open(template_path, 'r') as f:
            template = json.load(f)
        template["case_name"] = case_name
        with open(answer_key_path, 'w') as f:
            json.dump(template, f, indent=2)
    else:
        # Create minimal answer key
        with open(answer_key_path, 'w') as f:
            json.dump({
                "case_name": case_name,
                "source": "CyberDefenders",
                "difficulty": "easy",
                "evidence_files": [],
                "expected_findings": [],
                "total_possible_points": 0
            }, f, indent=2)

    print(f"Created case: {case_dir}")
    print(f"  1. Add evidence files to: {evidence_dir}")
    print(f"  2. Edit answer key: {answer_key_path}")
    return True


def run_argus_pipeline(
    case_name: str,
    evidence_dir: Path,
    result_dir: Path,
    extraction_only: bool = False
) -> bool:
    """Run ARGUS pipeline on evidence.

    Args:
        case_name: Name of the case
        evidence_dir: Directory containing evidence files
        result_dir: Where to save output
        extraction_only: If True, only run extraction (no API calls)

    Returns:
        True if pipeline ran (even with errors)
    """
    result_dir.mkdir(parents=True, exist_ok=True)

    argus_cmd = discover_argus_command()

    if extraction_only:
        # Run ForensicExtractor directly (no API costs)
        print("Running extraction-only mode (no API calls)...")
        try:
            # Initialize case
            init_cmd = argus_cmd + [
                "init",
                "-e", str(evidence_dir),
                str(result_dir / "case")
            ]
            subprocess.run(init_cmd, cwd=PROJECT_ROOT, capture_output=True)

            # Run only phase 1 (ingest)
            phase1_cmd = argus_cmd + [
                "run-phase", "1",
                str(result_dir / "case")
            ]
            subprocess.run(phase1_cmd, cwd=PROJECT_ROOT, capture_output=True)

            return True
        except Exception as e:
            print(f"Extraction error: {e}")
            return False
    else:
        # Full pipeline
        print(f"Running full ARGUS pipeline...")

        # Check for evidence files
        evidence_files = list(evidence_dir.glob("*"))
        evidence_files = [f for f in evidence_files if f.is_file()]

        if not evidence_files:
            print(f"Error: No evidence files in {evidence_dir}")
            return False

        try:
            # Initialize case
            case_path = result_dir / "case"
            init_cmd = argus_cmd + [
                "init",
                "-e", str(evidence_dir),
                str(case_path)
            ]
            print(f"  Initializing case...")
            result = subprocess.run(
                init_cmd,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"  Init output: {result.stdout}")
                print(f"  Init errors: {result.stderr}")

            # Run analyze
            analyze_cmd = argus_cmd + ["analyze", str(case_path)]
            print(f"  Running analysis (this may take several minutes)...")
            result = subprocess.run(
                analyze_cmd,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )

            # Save output
            with open(result_dir / "argus_stdout.txt", 'w') as f:
                f.write(result.stdout)
            with open(result_dir / "argus_stderr.txt", 'w') as f:
                f.write(result.stderr)

            return True

        except subprocess.TimeoutExpired:
            print("  Pipeline timed out after 30 minutes")
            return False
        except Exception as e:
            print(f"  Pipeline error: {e}")
            return False


def record_score(case_name: str, gap_analysis: dict) -> None:
    """Append score to history file.

    Args:
        case_name: Name of the case
        gap_analysis: Gap analysis dict from comparator
    """
    # Load existing history
    if SCORES_FILE.exists():
        with open(SCORES_FILE, 'r') as f:
            history = json.load(f)
    else:
        history = []

    # Add new entry
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case": case_name,
        "score_numeric": gap_analysis.get("score_numeric", 0),
        "score": gap_analysis.get("score", "0/0"),
        "gaps": gap_analysis.get("gap_summary", {}),
    }
    history.append(entry)

    # Save
    with open(SCORES_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def run_case(case_name: str, extraction_only: bool = False) -> dict:
    """Run the full improvement cycle for a case.

    Args:
        case_name: Name of the case to run
        extraction_only: If True, skip full pipeline

    Returns:
        Gap analysis dict
    """
    case_dir = CASES_DIR / case_name
    answer_key_path = case_dir / "answer_key.json"
    evidence_dir = case_dir / "evidence"

    if not case_dir.exists():
        print(f"Error: Case not found: {case_dir}")
        return {}

    if not answer_key_path.exists():
        print(f"Error: Answer key not found: {answer_key_path}")
        return {}

    # Create timestamped results directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = RESULTS_DIR / f"{case_name}_{timestamp}"

    print(f"\n{'='*60}")
    print(f"Running case: {case_name}")
    print(f"{'='*60}")

    # Step 1: Run ARGUS
    success = run_argus_pipeline(
        case_name,
        evidence_dir,
        result_dir,
        extraction_only
    )

    if not success:
        print("Pipeline failed - attempting comparison with partial output")

    # Step 2: Find case output directory
    case_output = result_dir / "case"
    if not case_output.exists():
        # Try to find any output
        case_output = result_dir

    # Step 3: Run comparison
    print("\nComparing against answer key...")
    gap_analysis = compare(str(answer_key_path), str(case_output))

    # Save gap analysis
    with open(result_dir / "gap_analysis.json", 'w') as f:
        json.dump(gap_analysis, f, indent=2)

    # Print summary
    print_summary(gap_analysis)

    # Step 4: Record score
    record_score(case_name, gap_analysis)
    print(f"\nScore recorded to: {SCORES_FILE}")

    # Step 5: Generate fix instructions if gaps exist
    total_gaps = sum(
        v for k, v in gap_analysis.get("gap_summary", {}).items()
        if k != "NONE"
    )

    if total_gaps > 0:
        print("\nGenerating fix instructions...")
        fix_path = generate_fix_instructions(
            str(result_dir / "gap_analysis.json"),
            str(PROJECT_ROOT),
            mode="claude-code"
        )
        if fix_path:
            print(f"Fix instructions: {fix_path}")
    else:
        print("\n100% score - no fixes needed!")

    return gap_analysis


def run_regression(extraction_only: bool = False) -> dict:
    """Run all cases and check for regressions.

    Args:
        extraction_only: If True, skip full pipeline

    Returns:
        Summary dict
    """
    print(f"\n{'='*60}")
    print("REGRESSION TEST")
    print(f"{'='*60}")

    # Find all cases with answer keys
    cases = []
    for case_dir in CASES_DIR.iterdir():
        if case_dir.is_dir() and case_dir.name != "_template":
            if (case_dir / "answer_key.json").exists():
                cases.append(case_dir.name)

    if not cases:
        print("No cases found with answer keys")
        return {}

    print(f"Found {len(cases)} cases: {', '.join(cases)}")

    # Load previous scores for regression check
    previous_scores = {}
    if SCORES_FILE.exists():
        with open(SCORES_FILE, 'r') as f:
            history = json.load(f)
        for entry in history:
            case = entry.get("case")
            if case:
                previous_scores[case] = entry.get("score_numeric", 0)

    # Run each case
    results = {}
    regressions = []

    for case_name in cases:
        gap_analysis = run_case(case_name, extraction_only)
        new_score = gap_analysis.get("score_numeric", 0)
        old_score = previous_scores.get(case_name, 0)

        results[case_name] = {
            "score": new_score,
            "previous": old_score,
            "change": new_score - old_score
        }

        if old_score > 0 and new_score < old_score - 1:  # Allow 1% tolerance
            regressions.append(case_name)

    # Print summary
    print(f"\n{'='*60}")
    print("REGRESSION SUMMARY")
    print(f"{'='*60}")

    for case_name, result in results.items():
        if result["change"] > 0:
            trend = f"↑ +{result['change']:.1f}%"
        elif result["change"] < -1:
            trend = f"↓ {result['change']:.1f}% ⚠ REGRESSION"
        else:
            trend = "→ stable"

        print(f"  {case_name}: {result['score']:.1f}% ({trend})")

    if regressions:
        print(f"\n⚠ REGRESSIONS DETECTED: {', '.join(regressions)}")
        return {"status": "regression", "cases": regressions}
    else:
        print(f"\n✓ No regressions detected")
        return {"status": "ok", "cases": cases}


def show_scores() -> None:
    """Show score history with trends."""
    if not SCORES_FILE.exists():
        print("No score history found")
        return

    with open(SCORES_FILE, 'r') as f:
        history = json.load(f)

    if not history:
        print("Score history is empty")
        return

    # Group by case
    by_case = {}
    for entry in history:
        case = entry.get("case", "unknown")
        if case not in by_case:
            by_case[case] = []
        by_case[case].append(entry)

    print(f"\n{'='*60}")
    print("SCORE HISTORY")
    print(f"{'='*60}")

    for case, entries in sorted(by_case.items()):
        print(f"\n{case}:")
        # Show last 5 runs
        recent = entries[-5:]
        for i, entry in enumerate(recent):
            score = entry.get("score_numeric", 0)
            timestamp = entry.get("timestamp", "")[:16]

            # Calculate trend
            if i > 0:
                prev_score = recent[i-1].get("score_numeric", 0)
                if score > prev_score:
                    trend = "↑"
                elif score < prev_score:
                    trend = "↓"
                else:
                    trend = "→"
            else:
                trend = " "

            print(f"  {trend} {timestamp} - {score:.1f}% ({entry.get('score', '')})")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="ARGUS Self-Improvement Runner"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # add-case command
    add_parser = subparsers.add_parser(
        "add-case",
        help="Create a new test case directory"
    )
    add_parser.add_argument("name", help="Case name")

    # run command
    run_parser = subparsers.add_parser(
        "run",
        help="Run ARGUS and compare against answer key"
    )
    run_parser.add_argument("case", help="Case name to run")
    run_parser.add_argument(
        "--extraction-only",
        action="store_true",
        help="Skip full pipeline, only test extraction (no API costs)"
    )

    # regression command
    reg_parser = subparsers.add_parser(
        "regression",
        help="Run all cases and check for regressions"
    )
    reg_parser.add_argument(
        "--extraction-only",
        action="store_true",
        help="Skip full pipeline, only test extraction (no API costs)"
    )

    # scores command
    subparsers.add_parser(
        "scores",
        help="Show score history with trends"
    )

    args = parser.parse_args()

    if args.command == "add-case":
        success = add_case(args.name)
        sys.exit(0 if success else 1)

    elif args.command == "run":
        gap_analysis = run_case(args.case, args.extraction_only)
        score = gap_analysis.get("score_numeric", 0)
        sys.exit(0 if score >= 80 else 1)

    elif args.command == "regression":
        result = run_regression(args.extraction_only)
        sys.exit(0 if result.get("status") == "ok" else 1)

    elif args.command == "scores":
        show_scores()
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
