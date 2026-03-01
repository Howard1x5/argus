"""Deep Analysis Agents for Phase 3.

Nine domain-specific agents plus a master synthesizer:
- Agent 1: Process Tree Forensics
- Agent 2: File Operations
- Agent 3: Registry Forensics
- Agent 4: Network Forensics
- Agent 5: Service Analysis
- Agent 6: Authentication Forensics
- Agent 7: Cross-System Correlation
- Agent 8: PowerShell Deep Dive
- Agent 9: Anomaly Hunter
- Agent 10: Master Synthesizer
"""

import json
from pathlib import Path
from typing import Optional

import click

from argus.agents.base import BaseAgent, AgentResult


# Base system prompt for analysis agents
ANALYSIS_SYSTEM_PROMPT = """You are an expert incident response analyst performing deep forensic analysis.
Your task is to analyze evidence and produce structured claims that can be validated.

CRITICAL: Every claim MUST be traceable to specific evidence. Include:
- Exact timestamps
- Source file and line numbers where possible
- Specific field values from the logs
- The query or filter used to find this evidence

OUTPUT FORMAT - Return claims as JSON:
```json
{
    "claims": [
        {
            "claim_id": "A{agent_num}-{sequence}",
            "summary": "Brief description of the finding",
            "affected_entities": ["hostnames", "users", "IPs", "processes"],
            "timestamp_range": ["start_time", "end_time"],
            "log_sources": ["source files"],
            "event_ids": [list of relevant event IDs],
            "detection_method": "How this was detected",
            "confidence": "HIGH|MEDIUM|LOW",
            "mitre_technique": "T1234.001 if applicable",
            "mitre_tactic": "Tactic name",
            "raw_evidence_refs": [
                {"file": "filename", "filter": "query used", "timestamp": "exact time"}
            ],
            "supporting_evidence": "Detailed evidence description",
            "inferred_vs_direct": "DIRECT|INFERRED"
        }
    ],
    "summary": "Overall analysis summary",
    "gaps": ["Evidence gaps or limitations noted"]
}
```

Be precise. Reference actual data. Don't fabricate evidence."""


class ProcessTreeAgent(BaseAgent):
    """Agent 1: Process Tree Forensics."""
    
    name = "agent_01_process_trees"
    description = "Analyzes process creation and parent-child relationships"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "1") + """

YOUR DOMAIN: Process Tree Forensics
Analyze Sysmon Event ID 1 and Windows Event 4688 for:
- Complete process trees: grandparent → parent → child → grandchild
- Extract: Image, CommandLine, ParentImage, ParentCommandLine, User, ProcessId
- Flag: web server children (w3wp.exe, httpd), services.exe spawns, encoded commands
- Identify LOLBIN abuse (certutil, mshta, regsvr32, rundll32, wmic, bitsadmin)
- Note if Sysmon data is missing (4688 lacks parent command lines)"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        # Filter for process events
        process_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["4688", "process", "sysmon_1", "sysmon 1"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Process Events ({len(process_events)} total, showing sample)
{json.dumps(process_events[:100], indent=2, default=str)}

Analyze process creation patterns. Build process trees. Identify suspicious parent-child relationships."""


class FileOperationsAgent(BaseAgent):
    """Agent 2: File Operations."""
    
    name = "agent_02_file_ops"
    description = "Analyzes file creation, modification, and deletion"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "2") + """

YOUR DOMAIN: File Operations
Analyze Sysmon Event ID 11 (FileCreate), 15 (FileCreateStreamHash), 23 (FileDelete):
- Extract: TargetFilename, CreationTime, ProcessId, Image, Hash
- Flag files in: Temp, Public, Downloads, inetpub, ProgramData
- Flag: executables, scripts (.ps1, .bat, .vbs), renamed extensions
- Cross-reference ProcessId to identify which process created each file
- Look for staging activity and suspicious file placement"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        file_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["file", "sysmon_11", "sysmon_15", "sysmon_23"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## File Events ({len(file_events)} total, showing sample)
{json.dumps(file_events[:100], indent=2, default=str)}

Analyze file operations. Identify suspicious file creation patterns and staging activity."""


class RegistryAgent(BaseAgent):
    """Agent 3: Registry Forensics."""
    
    name = "agent_03_registry"
    description = "Analyzes registry modifications for persistence"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "3") + """

YOUR DOMAIN: Registry Forensics
Analyze Sysmon Event ID 12 (CreateKey), 13 (SetValue), 14 (RenameKey):
- Extract: EventType, TargetObject, Details, ProcessId
- Flag persistence locations: Run keys, Services, COM objects
- Identify: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
- Identify: HKLM\\SYSTEM\\CurrentControlSet\\Services
- Look for encoded values, suspicious paths in registry data"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        reg_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["registry", "sysmon_12", "sysmon_13", "sysmon_14", "reg"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Registry Events ({len(reg_events)} total, showing sample)
{json.dumps(reg_events[:100], indent=2, default=str)}

Analyze registry modifications. Identify persistence mechanisms and suspicious registry changes."""


class NetworkAgent(BaseAgent):
    """Agent 4: Network Forensics."""
    
    name = "agent_04_network"
    description = "Analyzes network connections and DNS queries"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "4") + """

YOUR DOMAIN: Network Forensics
Analyze Sysmon Event ID 3 (NetworkConnect), 22 (DNSQuery), and PCAP data:
- Extract: SourceIp, DestinationIp, DestinationPort, ProcessId, QueryName
- Flag: external connections from internal hosts
- Flag: internal lateral movement (internal-to-internal on suspicious ports)
- Identify C2 patterns: beaconing intervals, known-bad ports (4444, 5555, etc.)
- Look for DNS tunneling or suspicious domain queries"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        net_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["network", "sysmon_3", "sysmon_22", "dns", "connection", "pcap"]) or
            e.get("dest_ip") or e.get("source_ip")]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Network Events ({len(net_events)} total, showing sample)
{json.dumps(net_events[:100], indent=2, default=str)}

Analyze network activity. Identify external connections, lateral movement, and C2 patterns."""


class ServiceAgent(BaseAgent):
    """Agent 5: Service Analysis."""
    
    name = "agent_05_services"
    description = "Analyzes service installation and changes"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "5") + """

YOUR DOMAIN: Service Analysis
Analyze Event ID 7045 (ServiceInstall), 7034 (ServiceCrash), 7036 (ServiceStateChange), 4697:
- Extract: ServiceName, ImagePath, ServiceType, StartType, AccountName
- Flag: random service names (15+ chars, all caps, no spaces)
- Flag: cmd/powershell in ImagePath
- Flag: demand start services (often used for persistence)
- Build service installation timeline"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        svc_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in ["7045", "7034", "7036", "4697", "service"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Service Events ({len(svc_events)} total, showing sample)
{json.dumps(svc_events[:100], indent=2, default=str)}

Analyze service installations. Identify malicious services and persistence mechanisms."""


class AuthenticationAgent(BaseAgent):
    """Agent 6: Authentication Forensics."""
    
    name = "agent_06_auth"
    description = "Analyzes authentication events and credential usage"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "6") + """

YOUR DOMAIN: Authentication Forensics
Analyze authentication events:
- 4624 (LogonSuccess), 4625 (LogonFail), 4648 (ExplicitCredentials)
- 4672 (SpecialPrivileges), 4769 (KerberosTGS), 4771 (KerberosPreAuth), 4776 (CredentialValidation)
- Group by LogonType: 2=interactive, 3=network, 10=RDP
- Identify: brute force, password spraying, Kerberoasting (RC4), pass-the-hash
- Build authentication timeline per user"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        auth_events = [e for e in events if 
            any(x in str(e.get("event_type", "")).lower() for x in 
                ["4624", "4625", "4648", "4672", "4769", "4771", "4776", "logon", "auth", "kerberos"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Authentication Events ({len(auth_events)} total, showing sample)
{json.dumps(auth_events[:100], indent=2, default=str)}

Analyze authentication patterns. Identify credential attacks and suspicious logon activity."""


class CrossSystemAgent(BaseAgent):
    """Agent 7: Cross-System Correlation."""
    
    name = "agent_07_cross_system"
    description = "Correlates activity across multiple systems"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "7") + """

YOUR DOMAIN: Cross-System Correlation
Analyze all evidence sources simultaneously:
- Map attack paths between systems
- Identify which commands on System A led to activity on System B
- Find network connections correlating with process creation
- Establish lateral movement chain with evidence from BOTH sides
- Identify credential reuse across systems
- Build complete timeline spanning all systems"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        # Group by source system
        by_system = {}
        for e in events:
            system = e.get("source_system") or e.get("_source_parquet", "unknown")
            if system not in by_system:
                by_system[system] = []
            by_system[system].append(e)
        
        prompt = f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Systems Found: {list(by_system.keys())}

## Events by System (samples):
"""
        for system, sys_events in list(by_system.items())[:5]:
            prompt += f"\n### {system} ({len(sys_events)} events)\n{json.dumps(sys_events[:20], indent=2, default=str)}\n"
        
        prompt += "\nCorrelate activity across systems. Map the attack path. Identify lateral movement."
        return prompt


class PowerShellAgent(BaseAgent):
    """Agent 8: PowerShell Deep Dive."""
    
    name = "agent_08_powershell"
    description = "Deep analysis of PowerShell activity"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "8") + """

YOUR DOMAIN: PowerShell Deep Dive
Analyze all PowerShell activity:
- Process creation with powershell.exe
- Engine events (400/403/600)
- ScriptBlock logging (4104)
- DECODE ALL encoded commands (-enc, -encodedcommand) - provide full base64 decode
- Identify: bypass flags (-ep bypass, -nop), download commands (IEX, Invoke-WebRequest)
- For web logs: decode URL-encoded PowerShell from query strings
- Identify obfuscation techniques (string concatenation, variable substitution)"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        
        ps_events = [e for e in events if 
            any(x in str(e).lower() for x in ["powershell", "-enc", "invoke-", "iex", "4104", "scriptblock"])]
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## PowerShell-Related Events ({len(ps_events)} total, showing sample)
{json.dumps(ps_events[:100], indent=2, default=str)}

Deep dive into PowerShell. DECODE all encoded commands. Identify malicious scripts."""


class AnomalyHunterAgent(BaseAgent):
    """Agent 9: Anomaly Hunter."""
    
    name = "agent_09_anomalies"
    description = "Finds anything other agents might miss"
    
    def get_system_prompt(self) -> str:
        return ANALYSIS_SYSTEM_PROMPT.replace("{agent_num}", "9") + """

YOUR DOMAIN: Anomaly Hunter (Wildcard)
Find anything other agents might miss:
- Rare Event IDs (not commonly seen)
- Time gaps in logging
- Unusual process names
- Cryptocurrency addresses or wallet references
- Cleanup activity (file deletion, log clearing)
- Log tampering evidence
- Anti-forensics indicators
- Events just before/after log boundaries (first/last events)
- Anything that looks out of place"""
    
    def build_user_prompt(self, context: dict) -> str:
        events = context.get("events", [])
        hypotheses = context.get("hypotheses", [])
        triage_findings = context.get("triage_findings", [])
        
        return f"""## Hypotheses to Investigate
{json.dumps(hypotheses[:5], indent=2, default=str)}

## Triage Findings Already Identified
{json.dumps(triage_findings[:20], indent=2, default=str)}

## All Events (sample - look for anomalies)
{json.dumps(events[:150], indent=2, default=str)}

Hunt for anomalies. Find what other agents missed. Look for rare events and suspicious patterns."""


class SynthesizerAgent(BaseAgent):
    """Agent 10: Master Synthesizer."""
    
    name = "agent_10_synthesizer"
    description = "Synthesizes all agent findings into unified analysis"
    max_tokens = 8192
    
    def get_system_prompt(self) -> str:
        return """You are the Master Synthesizer for an incident response analysis.
You receive findings from 9 specialized forensic agents. Your task is to:
1. Create a unified attack reconstruction
2. Build a second-by-second timeline
3. Identify the complete attack chain narrative (as HYPOTHESIS, not validated fact)
4. Assess confidence per phase of the attack
5. Note unanswered questions and evidence gaps
6. Consolidate IOC list
7. Create consolidated MITRE ATT&CK mapping
8. Identify contradictions between agents

OUTPUT FORMAT:
```json
{
    "attack_timeline": [
        {"timestamp": "ISO timestamp", "event": "What happened", "source": "Evidence source", "confidence": "HIGH|MEDIUM|LOW"}
    ],
    "attack_narrative": "Detailed narrative of the attack chain",
    "attack_phases": [
        {"phase": "Initial Access|Execution|Persistence|etc", "description": "What happened", "confidence": "HIGH|MEDIUM|LOW", "evidence": ["references"]}
    ],
    "ioc_list": [
        {"type": "IP|Domain|Hash|File|etc", "value": "the IOC", "context": "Where/how seen"}
    ],
    "mitre_mapping": [
        {"technique_id": "T1234", "technique_name": "Name", "tactic": "Tactic", "evidence": "How observed"}
    ],
    "contradictions": ["List of conflicting findings between agents"],
    "evidence_gaps": ["Questions that remain unanswered"],
    "confidence_assessment": "Overall confidence in the reconstruction"
}
```"""
    
    def build_user_prompt(self, context: dict) -> str:
        agent_results = context.get("agent_results", {})
        hypotheses = context.get("hypotheses", [])
        
        prompt = f"""## Initial Hypotheses
{json.dumps(hypotheses, indent=2, default=str)}

## Agent Findings:

"""
        for agent_name, results in agent_results.items():
            claims = results.get("claims", [])
            findings = results.get("findings", [])
            prompt += f"### {agent_name}\nClaims: {len(claims)}, Findings: {len(findings)}\n"
            prompt += json.dumps(claims[:10] + findings[:10], indent=2, default=str)[:3000]
            prompt += "\n\n"
        
        prompt += """
Synthesize all findings into a unified attack reconstruction.
Build the timeline. Map to MITRE. Identify gaps and contradictions."""
        
        return prompt


# Agent registry
ANALYSIS_AGENTS = [
    ProcessTreeAgent,
    FileOperationsAgent,
    RegistryAgent,
    NetworkAgent,
    ServiceAgent,
    AuthenticationAgent,
    CrossSystemAgent,
    PowerShellAgent,
    AnomalyHunterAgent,
]

SYNTHESIZER_AGENT = SynthesizerAgent


def run_analysis_agents(
    events: list[dict],
    hypotheses: list[dict],
    triage_findings: list[dict],
    output_dir: Path,
) -> dict:
    """Run all analysis agents and synthesizer.
    
    Args:
        events: Parsed events
        hypotheses: Hypotheses from Phase 2
        triage_findings: Findings from triage
        output_dir: Directory for output files
        
    Returns:
        Dict with all agent results and synthesis
    """
    results = {}
    agents_dir = output_dir / "agents"
    agents_dir.mkdir(exist_ok=True)
    
    context = {
        "events": events,
        "hypotheses": hypotheses,
        "triage_findings": triage_findings,
    }
    
    # Run domain agents
    for agent_class in ANALYSIS_AGENTS:
        agent = agent_class()
        click.echo(f"  Running {agent.name}...")
        
        try:
            result = agent.run(context)
            results[agent.name] = result.to_dict()
            
            # Save result
            output_path = agents_dir / f"{agent.name}.json"
            with open(output_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            
            claim_count = len(result.claims)
            finding_count = len(result.findings)
            click.echo(f"    Claims: {claim_count}, Findings: {finding_count}")
            
            if result.errors:
                for error in result.errors:
                    click.echo(click.style(f"    Error: {error}", fg="red"))
                    
        except Exception as e:
            click.echo(click.style(f"    Failed: {e}", fg="red"))
            results[agent.name] = {"error": str(e)}
    
    # Run synthesizer
    click.echo(f"  Running synthesizer...")
    try:
        synth = SYNTHESIZER_AGENT()
        synth_context = {
            "agent_results": results,
            "hypotheses": hypotheses,
        }
        synth_result = synth.run(synth_context)
        results["synthesis"] = synth_result.to_dict()
        
        # Save synthesis
        synth_path = output_dir / "synthesis.json"
        with open(synth_path, "w") as f:
            json.dump(synth_result.to_dict(), f, indent=2, default=str)
        
        click.echo(f"    Synthesis complete")
        
    except Exception as e:
        click.echo(click.style(f"    Synthesis failed: {e}", fg="red"))
        results["synthesis"] = {"error": str(e)}
    
    return results
