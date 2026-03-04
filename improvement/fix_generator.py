#!/usr/bin/env python3
"""ARGUS Self-Improvement Fix Generator Module.

Generates fix instructions from gap analysis.
Supports two modes:
  - claude-code: Outputs structured fix file for Claude Code to read and implement
  - api: Uses Anthropic API to generate fix instructions (costs ~$0.50)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Key source files that are most likely to need changes
KEY_SOURCE_FILES = [
    "src/argus/extractors/forensic_extractor.py",
    "src/argus/agents/analysis_agents.py",
    "src/argus/phases/phase3_analysis.py",
    "src/argus/phases/phase6_detection.py",
    "src/argus/phases/phase7_report.py",
    "src/argus/agents/base.py",
]


def load_source_files(source_dir: Path, max_chars: int = 8000) -> dict:
    """Load key source files, truncating if necessary.

    Args:
        source_dir: ARGUS source directory
        max_chars: Max chars per file (first 4000 + last 4000 if over)

    Returns:
        Dict mapping filepath -> content
    """
    sources = {}

    for rel_path in KEY_SOURCE_FILES:
        filepath = source_dir / rel_path
        if not filepath.exists():
            continue

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Truncate if too long
            if len(content) > max_chars:
                half = max_chars // 2
                content = (
                    content[:half] +
                    f"\n\n... [TRUNCATED {len(content) - max_chars} chars] ...\n\n" +
                    content[-half:]
                )

            sources[rel_path] = content
        except IOError:
            continue

    return sources


def generate_fix_header(gap_analysis: dict) -> str:
    """Generate metadata header for fix file."""
    gap_summary = gap_analysis.get("gap_summary", {})

    return f"""# Auto-Generated Fix Instructions
# Case: {gap_analysis.get('case_name', 'unknown')}
# Generated: {datetime.now(timezone.utc).isoformat()}
# Score before fix: {gap_analysis.get('score', 'N/A')}
# Gaps to fix: {sum(v for k, v in gap_summary.items() if k != 'NONE')}
# Gap types: extraction={gap_summary.get('EXTRACTION_GAP', 0)}, agent={gap_summary.get('AGENT_GAP', 0)}, report={gap_summary.get('REPORT_GAP', 0)}

---

"""


def generate_fix_instructions_claude_code(gap_analysis: dict, source_dir: Path) -> str:
    """Generate fix instructions for Claude Code to read and implement.

    This mode creates a detailed fix file that Claude Code can read
    and use to make the necessary code changes.
    """
    output = generate_fix_header(gap_analysis)

    output += """## Instructions for Claude Code

Read this file and implement the fixes described below. Each fix includes:
1. What's missing
2. Which file(s) to modify
3. Specific changes to make
4. Verification steps

---

"""

    fix_num = 0

    # Extraction gaps - highest priority
    extraction_gaps = gap_analysis.get("extraction_gaps", [])
    if extraction_gaps:
        output += "## EXTRACTION GAPS (Highest Priority)\n\n"
        output += "These findings were never extracted from the evidence.\n"
        output += "Fix in: `src/argus/extractors/forensic_extractor.py`\n\n"

        for gap in extraction_gaps:
            fix_num += 1
            output += f"""### Fix {fix_num}: Extract {gap['id']} - {gap['description']}

**Problem:** The ForensicExtractor doesn't extract data matching: {gap['search_terms']}

**Category:** {gap['category']}

**Fix approach:**
1. Identify which extraction function should capture this data
2. Add or modify pattern matching to capture these terms
3. Ensure the extracted data is saved to the appropriate extraction category

**Verification:**
```bash
# After fix, run extraction and verify terms appear
python -c "
import json
from pathlib import Path
# Load extraction results and search for terms
"
```

---

"""

    # Agent gaps
    agent_gaps = gap_analysis.get("agent_gaps", [])
    if agent_gaps:
        output += "## AGENT GAPS (Agents missed extracted data)\n\n"
        output += "These findings exist in extraction but agents didn't surface them.\n"
        output += "Fix in: `src/argus/agents/analysis_agents.py` or `src/argus/agents/base.py`\n\n"

        for gap in agent_gaps:
            fix_num += 1
            output += f"""### Fix {fix_num}: Surface {gap['id']} - {gap['description']}

**Problem:** Extraction contains data matching {gap['search_terms']} but no agent surfaced it.

**Category:** {gap['category']}

**Fix approach:**
1. Identify which agent should analyze this data type (based on category: {gap['category']})
2. Check if the agent's `relevant_extraction_keys` includes the right extraction category
3. Update agent prompt to specifically look for this pattern
4. Ensure finding is converted to a claim with proper MITRE mapping

**Verification:**
```bash
# After fix, check agent output for the terms
grep -ri "{gap['search_terms'][0] if gap['search_terms'] else 'TERM'}" analysis/agents/
```

---

"""

    # Report gaps
    report_gaps = gap_analysis.get("report_gaps", [])
    if report_gaps:
        output += "## REPORT GAPS (Agents found but report omitted)\n\n"
        output += "These findings were in agent output but not in final report.\n"
        output += "Fix in: `src/argus/phases/phase7_report.py`\n\n"

        for gap in report_gaps:
            fix_num += 1
            output += f"""### Fix {fix_num}: Include {gap['id']} in report - {gap['description']}

**Problem:** Agent claims contain {gap['search_terms']} but it's not in the final report.

**Fix approach:**
1. Check if claims are being passed to report generator
2. Ensure report template includes all validated claims
3. Verify claim isn't being filtered out during report generation

**Verification:**
```bash
# Check that terms appear in final report
grep -i "{gap['search_terms'][0] if gap['search_terms'] else 'TERM'}" report/incident_report.md
```

---

"""

    # Summary
    output += f"""## Summary

Total fixes needed: {fix_num}

After implementing all fixes:
1. Run the ARGUS pipeline against the same case
2. Run the comparator to verify score improvement
3. Run regression tests against all other cases

```bash
python improvement/runner.py run {gap_analysis.get('case_name', 'CASE')}
python improvement/runner.py regression
```
"""

    return output


def generate_fix_instructions_api(gap_analysis: dict, source_dir: Path) -> str:
    """Generate fix instructions using Anthropic API.

    This mode calls Claude API to generate detailed fix instructions.
    Costs ~$0.50 per call.
    """
    try:
        import anthropic
    except ImportError:
        return "ERROR: anthropic package not installed. Run: pip install anthropic"

    # Load source files for context
    sources = load_source_files(source_dir)

    # Build prompt
    gap_json = json.dumps(gap_analysis, indent=2, default=str)

    source_context = "\n\n".join([
        f"### {path}\n```python\n{content}\n```"
        for path, content in sources.items()
    ])

    prompt = f"""You are an expert Python developer fixing an IR automation tool called ARGUS.

## Gap Analysis (what's missing)
```json
{gap_json}
```

## Relevant Source Code
{source_context}

## Task
Generate specific, atomic fix instructions for each gap. For each fix:
1. Identify the exact file and function to modify
2. Show the specific code changes (before/after or new code to add)
3. Include a verification command to test the fix

Focus on the gaps with type EXTRACTION_GAP, AGENT_GAP, and REPORT_GAP.

Format your response as a markdown document with numbered fixes.
"""

    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )

    output = generate_fix_header(gap_analysis)
    output += response.content[0].text

    return output


def generate_fix_instructions(
    gap_analysis_path: str,
    source_dir: str,
    mode: str = "claude-code"
) -> str:
    """Generate fix instructions from gap analysis.

    Args:
        gap_analysis_path: Path to gap_analysis.json
        source_dir: Path to ARGUS source directory
        mode: 'claude-code' or 'api'

    Returns:
        Path to generated fix file
    """
    # Load gap analysis
    with open(gap_analysis_path, 'r') as f:
        gap_analysis = json.load(f)

    source_path = Path(source_dir)

    # Check if any gaps exist
    gap_counts = gap_analysis.get("gap_summary", {})
    total_gaps = sum(v for k, v in gap_counts.items() if k != "NONE")

    if total_gaps == 0:
        return None  # No fixes needed

    # Generate fix instructions
    if mode == "api":
        content = generate_fix_instructions_api(gap_analysis, source_path)
    else:
        content = generate_fix_instructions_claude_code(gap_analysis, source_path)

    # Save to pending fixes
    case_name = gap_analysis.get("case_name", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"fix_{case_name}_{timestamp}.md"

    # Find the improvement directory
    improvement_dir = source_path / "improvement"
    if not improvement_dir.exists():
        # Try relative to current working directory
        improvement_dir = Path("improvement")

    pending_dir = improvement_dir / "fixes" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)

    output_path = pending_dir / filename
    with open(output_path, 'w') as f:
        f.write(content)

    return str(output_path)


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate fix instructions from ARGUS gap analysis"
    )
    parser.add_argument(
        "gap_analysis",
        help="Path to gap_analysis.json"
    )
    parser.add_argument(
        "--source-dir",
        default=".",
        help="Path to ARGUS source directory (default: current directory)"
    )
    parser.add_argument(
        "--mode",
        choices=["claude-code", "api"],
        default="claude-code",
        help="Generation mode: claude-code (free) or api (costs ~$0.50)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.gap_analysis):
        print(f"Error: Gap analysis not found: {args.gap_analysis}")
        sys.exit(1)

    result = generate_fix_instructions(
        args.gap_analysis,
        args.source_dir,
        args.mode
    )

    if result is None:
        print("No gaps found - no fixes needed!")
        sys.exit(0)
    else:
        print(f"Fix instructions generated: {result}")
        sys.exit(0)


if __name__ == "__main__":
    main()
