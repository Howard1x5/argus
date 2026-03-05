#!/usr/bin/env python3
"""ARGUS Self-Improvement Comparator Module.

Compares ARGUS output against answer keys to identify gaps.
Supports three-layer comparison: extraction, agents, report.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
import pyarrow.parquet as pq


def load_parquet_as_text(filepath: Path) -> str:
    """Load a parquet file and convert to searchable text.

    Args:
        filepath: Path to parquet file

    Returns:
        Text representation of parquet contents for searching
    """
    try:
        df = pd.read_parquet(filepath)
        if df.empty:
            return ""

        # Convert all columns to string and concatenate
        text_parts = []
        for _, row in df.iterrows():
            row_text = " ".join(str(v) for v in row.values if pd.notna(v) and str(v) != "")
            text_parts.append(row_text)

        return "\n".join(text_parts)
    except Exception:
        return ""


def load_text_recursive(directory: Path) -> str:
    """Load all text from JSON, MD, TXT, and Parquet files in a directory tree.

    Args:
        directory: Path to search recursively

    Returns:
        Concatenated text from all readable files
    """
    if not directory.exists():
        return ""

    text_parts = []
    text_extensions = {'.json', '.md', '.txt', '.yaml', '.yml'}
    parquet_extensions = {'.parquet', '.pq'}

    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = Path(root) / filename
            suffix = filepath.suffix.lower()

            if suffix in text_extensions:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        text_parts.append(f"\n=== {filepath} ===\n{content}")
                except (IOError, OSError):
                    continue
            elif suffix in parquet_extensions:
                content = load_parquet_as_text(filepath)
                if content:
                    text_parts.append(f"\n=== {filepath} ===\n{content}")

    return "\n".join(text_parts)


def check_finding(finding: dict, text: str) -> bool:
    """Check if a finding's search terms are present in text.

    Args:
        finding: Dict with 'search_terms' and 'search_mode' keys
        text: Text to search in (case-insensitive)

    Returns:
        True if finding criteria are met
    """
    search_terms = finding.get("search_terms", [])
    search_mode = finding.get("search_mode", "ANY").upper()

    if not search_terms:
        return False

    text_lower = text.lower()

    if search_mode == "ALL":
        # Every term must appear
        return all(term.lower() in text_lower for term in search_terms)
    else:
        # ANY: at least one term must appear
        return any(term.lower() in text_lower for term in search_terms)


def classify_gap(in_extraction: bool, in_agents: bool, in_report: bool) -> str:
    """Classify the type of gap based on where finding appears.

    Returns:
        NONE, EXTRACTION_GAP, AGENT_GAP, REPORT_GAP, or ROUTING_GAP
    """
    if in_report:
        return "NONE"  # Found in final output
    elif not in_extraction:
        return "EXTRACTION_GAP"  # Never extracted from evidence
    elif in_extraction and not in_agents:
        return "AGENT_GAP"  # Extracted but agents didn't surface
    elif in_extraction and in_agents and not in_report:
        return "REPORT_GAP"  # Agents found but report omitted
    else:
        return "ROUTING_GAP"  # Somewhere but wrong layer


def compare(answer_key_path: str, results_dir: str) -> dict:
    """Compare ARGUS results against an answer key.

    Args:
        answer_key_path: Path to answer_key.json
        results_dir: Path to ARGUS output directory

    Returns:
        Gap analysis dict with scores and per-finding details
    """
    # Load answer key
    with open(answer_key_path, 'r') as f:
        answer_key = json.load(f)

    results_path = Path(results_dir)

    # Load text from three layers
    # Try structured directories first, fall back to flat search
    extraction_text = ""
    agents_text = ""
    report_text = ""
    all_text = ""

    # Structured: Look for specific directories
    extractions_dir = results_path / "extractions"
    agents_dir = results_path / "analysis" / "agents"
    report_dir = results_path / "report"

    if extractions_dir.exists():
        extraction_text = load_text_recursive(extractions_dir)

    if agents_dir.exists():
        agents_text = load_text_recursive(agents_dir)
    elif (results_path / "analysis").exists():
        # Fall back to analysis directory
        agents_text = load_text_recursive(results_path / "analysis")

    if report_dir.exists():
        report_text = load_text_recursive(report_dir)

    # Also load all text for fallback matching
    all_text = load_text_recursive(results_path)

    # If structured dirs didn't work, use all_text for everything
    if not extraction_text:
        extraction_text = all_text
    if not agents_text:
        agents_text = all_text
    if not report_text:
        report_text = all_text

    # Check each finding
    findings_results = []
    total_points = 0
    earned_points = 0
    gap_counts = {
        "NONE": 0,
        "EXTRACTION_GAP": 0,
        "AGENT_GAP": 0,
        "REPORT_GAP": 0,
        "ROUTING_GAP": 0,
    }

    for finding in answer_key.get("expected_findings", []):
        finding_id = finding.get("id", "?")
        points = finding.get("points", 10)
        total_points += points

        # Check each layer
        in_extraction = check_finding(finding, extraction_text)
        in_agents = check_finding(finding, agents_text)
        in_report = check_finding(finding, report_text)

        # Also check all_text as fallback
        in_any = check_finding(finding, all_text)

        # Classify gap
        gap_type = classify_gap(in_extraction, in_agents, in_report)

        # If not found in structured layers but found somewhere, it's a routing gap
        if gap_type != "NONE" and in_any:
            gap_type = "ROUTING_GAP"

        gap_counts[gap_type] += 1

        if gap_type == "NONE":
            earned_points += points

        findings_results.append({
            "id": finding_id,
            "description": finding.get("description", ""),
            "category": finding.get("category", ""),
            "points": points,
            "in_extraction": in_extraction,
            "in_agents": in_agents,
            "in_report": in_report,
            "gap_type": gap_type,
            "search_terms": finding.get("search_terms", []),
        })

    # Calculate score
    score_pct = (earned_points / total_points * 100) if total_points > 0 else 0

    return {
        "case_name": answer_key.get("case_name", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score_numeric": round(score_pct, 1),
        "score": f"{earned_points}/{total_points} ({score_pct:.1f}%)",
        "earned_points": earned_points,
        "total_points": total_points,
        "gap_summary": gap_counts,
        "findings": findings_results,
        "extraction_gaps": [f for f in findings_results if f["gap_type"] == "EXTRACTION_GAP"],
        "agent_gaps": [f for f in findings_results if f["gap_type"] == "AGENT_GAP"],
        "report_gaps": [f for f in findings_results if f["gap_type"] == "REPORT_GAP"],
        "routing_gaps": [f for f in findings_results if f["gap_type"] == "ROUTING_GAP"],
    }


def print_summary(gap_analysis: dict) -> None:
    """Print human-readable summary of gap analysis."""
    print(f"\n{'='*60}")
    print(f"ARGUS Comparison: {gap_analysis['case_name']}")
    print(f"{'='*60}")
    print(f"\nScore: {gap_analysis['score']}")
    print(f"\nGap Summary:")
    for gap_type, count in gap_analysis['gap_summary'].items():
        marker = "✓" if gap_type == "NONE" else "✗"
        print(f"  {marker} {gap_type}: {count}")

    print(f"\nPer-Finding Results:")
    for f in gap_analysis['findings']:
        marker = "✓" if f['gap_type'] == "NONE" else "✗"
        print(f"  [{marker}] {f['id']}: {f['description'][:50]}...")
        if f['gap_type'] != "NONE":
            print(f"      Gap: {f['gap_type']} | Terms: {f['search_terms']}")

    # Print priority fixes
    if gap_analysis['extraction_gaps']:
        print(f"\n⚠ EXTRACTION GAPS (highest priority):")
        for f in gap_analysis['extraction_gaps']:
            print(f"  - {f['id']}: {f['description']}")

    if gap_analysis['agent_gaps']:
        print(f"\n⚠ AGENT GAPS (agents missed extracted data):")
        for f in gap_analysis['agent_gaps']:
            print(f"  - {f['id']}: {f['description']}")


def main():
    """CLI entry point."""
    if len(sys.argv) < 3:
        print("Usage: python comparator.py <answer_key.json> <results_dir>")
        print("\nCompares ARGUS output against an answer key and reports gaps.")
        sys.exit(1)

    answer_key_path = sys.argv[1]
    results_dir = sys.argv[2]

    if not os.path.exists(answer_key_path):
        print(f"Error: Answer key not found: {answer_key_path}")
        sys.exit(1)

    if not os.path.exists(results_dir):
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)

    # Run comparison
    gap_analysis = compare(answer_key_path, results_dir)

    # Print summary
    print_summary(gap_analysis)

    # Save to results directory
    output_path = Path(results_dir) / "gap_analysis.json"
    with open(output_path, 'w') as f:
        json.dump(gap_analysis, f, indent=2)
    print(f"\nGap analysis saved to: {output_path}")

    # Return exit code based on score
    if gap_analysis['score_numeric'] >= 80:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
