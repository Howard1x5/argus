"""Hypothesis Generation Agent for Phase 2d.

Generates ranked attack hypotheses based on merged triage findings.
Uses rule-based hypothesis generation plus one LLM call for synthesis.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from argus.agents.base import BaseAgent
from argus.config import get_api_key


# Rule-based hypothesis patterns
HYPOTHESIS_RULES = [
    {
        "name": "web_application_compromise",
        "triggers": ["webshell", "cmd=", "exec=", "w3wp.exe", "cmd.exe", "iis"],
        "hypothesis": "Web Application Compromise",
        "description": "Indicators suggest an attacker compromised a web application and achieved code execution on the web server.",
        "investigate": ["IIS logs for webshell requests", "Process creation from w3wp.exe", "File creation in web directories"],
    },
    {
        "name": "credential_theft",
        "triggers": ["lsass", "mimikatz", "sekurlsa", "procdump", "credential"],
        "hypothesis": "Credential Theft",
        "description": "Evidence of credential harvesting from memory or other sources.",
        "investigate": ["LSASS access events", "Process creation for credential tools", "Kerberos ticket requests"],
    },
    {
        "name": "lateral_movement",
        "triggers": ["psexec", "wmi", "winrm", "remote", "4648", "pass-the-hash"],
        "hypothesis": "Lateral Movement",
        "description": "Attacker moved between systems using stolen credentials or remote execution tools.",
        "investigate": ["Network logon events (Type 3)", "Service installations", "Remote process creation"],
    },
    {
        "name": "persistence",
        "triggers": ["schtasks", "service", "7045", "run key", "registry", "startup"],
        "hypothesis": "Persistence Mechanism",
        "description": "Attacker established persistence through scheduled tasks, services, or registry modifications.",
        "investigate": ["Service installation events", "Scheduled task creation", "Registry modifications"],
    },
    {
        "name": "reconnaissance",
        "triggers": ["whoami", "net user", "net group", "systeminfo", "ipconfig", "nltest"],
        "hypothesis": "Internal Reconnaissance",
        "description": "Attacker performed reconnaissance to understand the environment.",
        "investigate": ["Command execution patterns", "Timing between recon commands", "User context of recon"],
    },
    {
        "name": "data_exfiltration",
        "triggers": ["compress", "archive", "zip", "rar", "upload", "transfer", "external"],
        "hypothesis": "Data Exfiltration",
        "description": "Evidence suggests data staging or exfiltration activity.",
        "investigate": ["File compression activity", "Large outbound transfers", "Renamed file extensions"],
    },
    {
        "name": "defense_evasion",
        "triggers": ["clear", "1102", "log", "disable", "tamper", "bypass"],
        "hypothesis": "Defense Evasion",
        "description": "Attacker attempted to evade detection or hide their tracks.",
        "investigate": ["Log clearing events", "Security tool modification", "Timestomping evidence"],
    },
]


def generate_rule_based_hypotheses(findings: list[dict]) -> list[dict]:
    """Generate hypotheses based on pattern rules.
    
    Args:
        findings: Merged findings from triage
        
    Returns:
        List of hypothesis dicts
    """
    hypotheses = []
    findings_text = json.dumps(findings, default=str).lower()
    
    for rule in HYPOTHESIS_RULES:
        # Check if any triggers match
        trigger_matches = [t for t in rule["triggers"] if t.lower() in findings_text]
        
        if trigger_matches:
            hypotheses.append({
                "hypothesis": rule["hypothesis"],
                "description": rule["description"],
                "confidence": "HIGH" if len(trigger_matches) >= 3 else "MEDIUM" if len(trigger_matches) >= 2 else "LOW",
                "supporting_evidence": trigger_matches,
                "investigate": rule["investigate"],
                "source": "rule_based",
            })
    
    return hypotheses


def generate_hypotheses(
    merged_findings: dict,
    events: list[dict],
    api_key: Optional[str] = None,
) -> dict:
    """Generate attack hypotheses from merged findings.
    
    Args:
        merged_findings: Merged findings from Phase 2c
        events: Original events for context
        api_key: Optional API key
        
    Returns:
        Dict with hypotheses and metadata
    """
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hypotheses": [],
        "summary": "",
    }
    
    findings = merged_findings.get("findings", [])
    
    # Step 1: Rule-based hypotheses
    rule_hypotheses = generate_rule_based_hypotheses(findings)
    result["hypotheses"].extend(rule_hypotheses)
    
    # Step 2: LLM synthesis (if API key available)
    api_key = api_key or get_api_key("ANTHROPIC_API_KEY")
    
    if api_key:
        try:
            import anthropic
            
            client = anthropic.Anthropic(api_key=api_key)
            
            system_prompt = """You are an expert incident response analyst.
Based on the triage findings provided, generate attack hypotheses.

OUTPUT FORMAT:
```json
{
    "hypotheses": [
        {
            "hypothesis": "Name of the hypothesis",
            "description": "What you believe happened",
            "confidence": "HIGH|MEDIUM|LOW",
            "supporting_evidence": ["List of supporting findings"],
            "investigate": ["What to investigate to confirm/deny this"],
            "alternative_explanations": ["Other possible explanations"]
        }
    ],
    "attack_narrative": "Brief narrative of the likely attack chain",
    "key_questions": ["Questions that need answers"]
}
```

Focus on the MOST LIKELY attack scenarios. Don't make up evidence."""
            
            user_prompt = f"""## Triage Findings
{json.dumps(findings[:100], indent=2, default=str)}

## Rule-Based Hypotheses Already Generated
{json.dumps(rule_hypotheses, indent=2)}

## Your Task
1. Review the triage findings
2. Generate additional hypotheses the rules might have missed
3. Provide an overall attack narrative hypothesis
4. Rank hypotheses by likelihood
5. Identify key questions that need answers

Return your analysis in the specified JSON format."""
            
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            
            # Parse response
            response_text = response.content[0].text
            
            import re
            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text)
            if json_match:
                llm_result = json.loads(json_match.group(1))
            else:
                json_match = re.search(r'(\{[\s\S]*\})', response_text)
                if json_match:
                    llm_result = json.loads(json_match.group(1))
                else:
                    llm_result = {}
            
            # Add LLM hypotheses
            for hyp in llm_result.get("hypotheses", []):
                hyp["source"] = "llm"
                # Avoid duplicates
                if not any(h["hypothesis"] == hyp["hypothesis"] for h in result["hypotheses"]):
                    result["hypotheses"].append(hyp)
            
            # Add narrative and questions
            result["attack_narrative"] = llm_result.get("attack_narrative", "")
            result["key_questions"] = llm_result.get("key_questions", [])
            
            result["token_usage"] = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
            
        except Exception as e:
            result["llm_error"] = str(e)
    
    # Sort by confidence
    confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    result["hypotheses"].sort(key=lambda h: confidence_order.get(h.get("confidence", "LOW"), 3))
    
    # Generate summary
    if result["hypotheses"]:
        high_conf = [h for h in result["hypotheses"] if h.get("confidence") == "HIGH"]
        result["summary"] = f"Generated {len(result['hypotheses'])} hypotheses ({len(high_conf)} high confidence)"
    else:
        result["summary"] = "No clear attack hypotheses identified"
    
    return result
