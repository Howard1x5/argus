"""LLM Triage Agents for Phase 2b.

Five specialized agents that catch what programmatic scanning misses:
- T1: Pattern Gap Hunter
- T2: Behavioral Anomaly Agent
- T3: Cross-Source Correlation Agent
- T4: Absence & Evasion Agent
- T5: Identity & Privilege Context Agent
"""

import json
from pathlib import Path
from typing import Optional

import click

from argus.agents.base import BaseAgent, AgentResult


TRIAGE_SYSTEM_PROMPT = """You are an expert incident response analyst performing triage on security log data.
Your task is to identify findings that programmatic scanning might miss.

OUTPUT FORMAT:
Return your findings as a JSON object with this structure:
```json
{
    "findings": [
        {
            "description": "Brief description of what you found",
            "severity": "HIGH|MEDIUM|LOW|INFO",
            "evidence": "Specific log entries or patterns that support this finding",
            "source_file": "If applicable, which source file",
            "timestamp_range": "If applicable, time range",
            "recommendation": "What should be investigated further"
        }
    ],
    "summary": "Brief overall summary of triage findings"
}
```

Be specific. Reference actual data from the logs. Don't make up findings.
If you don't find anything significant, return an empty findings array."""


class PatternGapHunterAgent(BaseAgent):
    """Agent T1: Finds what regex patterns missed."""
    
    name = "t1_pattern_gaps"
    description = "Finds obfuscated commands and novel techniques regex missed"
    
    def get_system_prompt(self) -> str:
        return TRIAGE_SYSTEM_PROMPT + """

YOUR SPECIFIC ROLE: Pattern Gap Hunter
Look for what the programmatic regex patterns MISSED:
- Obfuscated PowerShell commands (string concatenation, variable substitution, encoding variations)
- Encoded payloads in unusual fields (not just command lines)
- Living-off-the-land techniques not in the standard pattern list
- Custom tool names that indicate attacker tooling
- Novel attack techniques not matching known patterns
- Command-line obfuscation (caret insertion, environment variable expansion)

Focus on the GAP between what was detected and what exists in the logs."""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events_sample", [])
        scan_results = context.get("scan_results", {})
        
        prompt = f"""## Programmatic Scan Results
The following patterns were already detected:
{json.dumps(scan_results.get("suspicious_findings", [])[:20], indent=2, default=str)}

## Event Sample
Here are events from the evidence (this is a sample, not all events):
{json.dumps(events[:100], indent=2, default=str)}

## Your Task
Analyze these events for suspicious patterns that the regex-based scan MISSED.
Look for obfuscation, encoding tricks, and novel techniques.
Return findings in the specified JSON format."""
        
        return prompt


class BehavioralAnomalyAgent(BaseAgent):
    """Agent T2: Statistical and temporal anomaly detection."""
    
    name = "t2_behavioral"
    description = "Finds statistical anomalies and unusual timing patterns"
    
    def get_system_prompt(self) -> str:
        return TRIAGE_SYSTEM_PROMPT + """

YOUR SPECIFIC ROLE: Behavioral Anomaly Analyst
Look for statistical and temporal anomalies:
- Unusual activity volumes at odd hours (midnight, weekends)
- User accounts active on unexpected systems
- Processes with unusual parent chains
- Timing clusters suggesting automation or scripted attacks
- Suspicious gaps in activity (staging/planning indicators)
- Sudden changes in normal patterns
- Bursts of similar events (brute force, spray attacks)
- Events happening faster than humanly possible (automation)

Focus on BEHAVIOR patterns, not just content patterns."""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events_sample", [])
        scan_results = context.get("scan_results", {})
        
        timeline = scan_results.get("timeline", {})
        entities = scan_results.get("entities", {})
        
        prompt = f"""## Timeline Summary
{json.dumps(timeline, indent=2, default=str)}

## Entity Summary
Users: {len(entities.get("usernames", []))}
Source IPs: {len(entities.get("source_ips", []))}
Hosts: {len(entities.get("hostnames", []))}

## Event Sample (sorted by timestamp)
{json.dumps(events[:100], indent=2, default=str)}

## Your Task
Analyze for behavioral anomalies - unusual timing, volumes, or patterns.
Look for automation indicators, staging behavior, and temporal clustering.
Return findings in the specified JSON format."""
        
        return prompt


class CrossSourceCorrelationAgent(BaseAgent):
    """Agent T3: Correlates findings across evidence sources."""
    
    name = "t3_cross_source"
    description = "Correlates events across different log sources"
    
    def get_system_prompt(self) -> str:
        return TRIAGE_SYSTEM_PROMPT + """

YOUR SPECIFIC ROLE: Cross-Source Correlation Analyst
Look for connections BETWEEN evidence sources that programmatic scan can't make:
- IPs appearing in both web logs AND authentication events
- Filenames matching process names across systems
- Timing relationships between events on different hosts
- Evidence of lateral movement bridging systems
- User accounts active across multiple systems in suspicious patterns
- Network connections correlating with process creation
- Web requests followed by system-level activity

Focus on CONNECTIONS that span multiple log sources."""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events_sample", [])
        scan_results = context.get("scan_results", {})
        
        # Group events by source
        by_source = {}
        for event in events:
            source = event.get("_source_parquet", "unknown")
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(event)
        
        prompt = f"""## Evidence Sources
Sources found: {list(by_source.keys())}

## Entities Across Sources
{json.dumps(scan_results.get("entities", {}), indent=2, default=str)}

## Event Samples by Source
"""
        for source, source_events in by_source.items():
            prompt += f"\n### {source}\n{json.dumps(source_events[:30], indent=2, default=str)}\n"
        
        prompt += """
## Your Task
Analyze for connections ACROSS different log sources.
Look for the same IPs, users, or files appearing in multiple places.
Identify potential lateral movement and attack chains spanning systems.
Return findings in the specified JSON format."""
        
        return prompt


class AbsenceEvasionAgent(BaseAgent):
    """Agent T4: Finds what SHOULD be there but isn't."""
    
    name = "t4_absence"
    description = "Identifies log gaps, missing events, and evasion indicators"
    
    def get_system_prompt(self) -> str:
        return TRIAGE_SYSTEM_PROMPT + """

YOUR SPECIFIC ROLE: Absence & Evasion Analyst
Look for what SHOULD be there but ISN'T:
- Log gaps (periods with no events)
- Missing Event IDs that should exist on a functioning system
- Disabled security tools (no AV events, no EDR events)
- Cleared event logs (Event ID 1102, gaps)
- Suspicious log termination (logs ending abruptly)
- Missing periodic events (heartbeats, scheduled tasks that should run)
- Evidence of timestomping or log manipulation
- Missing authentication for observed network activity

Focus on ABSENCE - gaps and missing data that indicate evasion."""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events_sample", [])
        scan_results = context.get("scan_results", {})
        
        timeline = scan_results.get("timeline", {})
        event_ids = scan_results.get("event_id_distribution", {})
        
        prompt = f"""## Timeline
Earliest: {timeline.get("earliest", "unknown")}
Latest: {timeline.get("latest", "unknown")}
Duration: {timeline.get("duration_hours", 0):.1f} hours
Total events: {timeline.get("event_count", 0)}

## Event ID Distribution
{json.dumps(event_ids.get("counts", {}), indent=2, default=str)}

## Activity Spikes (could indicate gaps around them)
{json.dumps(timeline.get("activity_spikes", []), indent=2, default=str)}

## Event Sample
{json.dumps(events[:80], indent=2, default=str)}

## Your Task
Analyze for MISSING data and evasion indicators.
Look for log gaps, missing expected events, and signs of tampering.
Compare what you see to what a healthy system should produce.
Return findings in the specified JSON format."""
        
        return prompt


class IdentityPrivilegeAgent(BaseAgent):
    """Agent T5: Role-based analysis of users and accounts."""
    
    name = "t5_privilege"
    description = "Analyzes identity and privilege context"
    
    def get_system_prompt(self) -> str:
        return TRIAGE_SYSTEM_PROMPT + """

YOUR SPECIFIC ROLE: Identity & Privilege Context Analyst
Analyze every user, process, and service account for role violations:
- Accounts operating outside expected role (admin doing user things, user doing admin things)
- Service accounts with interactive logons (should never happen)
- Processes spawning children they shouldn't (w3wp.exe -> cmd.exe, services.exe -> powershell.exe)
- SYSTEM-level processes doing user-level things
- Privilege assignments to unexpected accounts
- Logon type mismatches (network logon for interactive activity)
- Multiple accounts from same source (compromised workstation)
- Unusual account naming patterns (random strings, SYSTEM$ accounts)

Focus on WHO is doing WHAT and whether it makes sense."""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events_sample", [])
        scan_results = context.get("scan_results", {})
        
        entities = scan_results.get("entities", {})
        
        # Group events by user
        by_user = {}
        for event in events:
            user = event.get("username", "UNKNOWN")
            if user not in by_user:
                by_user[user] = []
            by_user[user].append(event)
        
        prompt = f"""## Users Found
{json.dumps(entities.get("usernames", [])[:50], indent=2)}

## Processes Found
{json.dumps(entities.get("processes", [])[:50], indent=2)}

## Events by User (sample)
"""
        for user, user_events in list(by_user.items())[:10]:
            prompt += f"\n### {user}\n{json.dumps(user_events[:10], indent=2, default=str)}\n"
        
        prompt += """
## Your Task
Analyze identity and privilege context.
Look for accounts acting outside their expected role.
Identify suspicious process parent-child relationships.
Flag service accounts doing interactive things.
Return findings in the specified JSON format."""
        
        return prompt


# Agent registry
TRIAGE_AGENTS = [
    PatternGapHunterAgent,
    BehavioralAnomalyAgent,
    CrossSourceCorrelationAgent,
    AbsenceEvasionAgent,
    IdentityPrivilegeAgent,
]


def run_triage_agents(
    events: list[dict],
    scan_results: dict,
    output_dir: Path,
) -> dict:
    """Run all triage agents and save results.
    
    Args:
        events: List of parsed events
        scan_results: Results from programmatic scan
        output_dir: Directory to save agent outputs
        
    Returns:
        Dict mapping agent name to results
    """
    results = {}
    
    # Sample events for LLM (respect token limits)
    events_sample = events[:500]  # Take first 500 for now
    
    context = {
        "events_sample": events_sample,
        "scan_results": scan_results,
    }
    
    for agent_class in TRIAGE_AGENTS:
        agent = agent_class()
        click.echo(f"  Running {agent.name}...")
        
        try:
            result = agent.run(context)
            results[agent.name] = result.to_dict()
            
            # Save individual result
            output_path = output_dir / f"agent_{agent.name}.json"
            with open(output_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            
            finding_count = len(result.findings)
            click.echo(f"    Found {finding_count} findings")
            
            if result.errors:
                for error in result.errors:
                    click.echo(click.style(f"    Error: {error}", fg="red"))
            
        except Exception as e:
            click.echo(click.style(f"    Failed: {e}", fg="red"))
            results[agent.name] = {"error": str(e)}
    
    return results
