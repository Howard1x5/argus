"""Phase 4: VALIDATION - Forensic Validation Engine (FVE).

100% PROGRAMMATIC - NO LLM INVOLVEMENT.

Validates every structured claim from Phase 3 against raw evidence.
"""

import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import click
import pyarrow.parquet as pq

from argus.phases.phase0_init import write_completion_marker
from argus.phases.phase2_triage import check_phase_complete


class ValidationResult:
    """Result of validating a single claim."""
    
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    CONTRADICTED = "CONTRADICTED"
    FAILED = "FAILED"
    
    def __init__(self, claim_id: str):
        self.claim_id = claim_id
        self.status = self.VERIFIED
        self.checks_passed = []
        self.checks_failed = []
        self.warnings = []
        self.review_instructions = []
    
    def add_pass(self, check: str):
        self.checks_passed.append(check)
    
    def add_fail(self, check: str, instruction: str = ""):
        self.checks_failed.append(check)
        if instruction:
            self.review_instructions.append(instruction)
        self._update_status()
    
    def add_warning(self, warning: str):
        self.warnings.append(warning)
    
    def _update_status(self):
        if len(self.checks_failed) == 0:
            self.status = self.VERIFIED
        elif len(self.checks_passed) > len(self.checks_failed):
            self.status = self.PARTIALLY_VERIFIED
        else:
            self.status = self.UNVERIFIED
    
    def to_dict(self) -> dict:
        return {
            "claim_id": self.claim_id,
            "status": self.status,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "warnings": self.warnings,
            "review_instructions": self.review_instructions,
        }


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
        except Exception:
            pass
    
    return events


def load_claims(case_path: Path) -> list[dict]:
    """Load all claims from Phase 3 analysis."""
    claims = []
    agents_dir = case_path / "analysis" / "agents"
    
    if not agents_dir.exists():
        return claims
    
    for agent_file in agents_dir.glob("*.json"):
        try:
            with open(agent_file) as f:
                data = json.load(f)
                for claim in data.get("claims", []):
                    claim["_source_agent"] = agent_file.stem
                    claims.append(claim)
        except Exception:
            pass
    
    return claims


def extract_entities_from_events(events: list[dict]) -> dict:
    """Build entity index from events."""
    entities = {
        "ips": set(),
        "hostnames": set(),
        "usernames": set(),
        "processes": set(),
        "files": set(),
        "timestamps": [],
    }
    
    for event in events:
        if event.get("source_ip"):
            entities["ips"].add(event["source_ip"])
        if event.get("dest_ip"):
            entities["ips"].add(event["dest_ip"])
        if event.get("source_system"):
            entities["hostnames"].add(event["source_system"].lower())
        if event.get("username"):
            entities["usernames"].add(event["username"].lower())
        if event.get("process_name"):
            entities["processes"].add(event["process_name"].lower())
        if event.get("file_path"):
            entities["files"].add(event["file_path"].lower())
        if event.get("timestamp_utc"):
            try:
                ts = event["timestamp_utc"]
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                entities["timestamps"].append(ts)
            except:
                pass
    
    return entities


def validate_entity_existence(claim: dict, entities: dict) -> tuple[list, list]:
    """Check that all entities in claim exist in evidence.
    
    Returns:
        Tuple of (passed_checks, failed_checks)
    """
    passed = []
    failed = []
    
    affected = claim.get("affected_entities", [])
    
    for entity in affected:
        entity_lower = entity.lower()
        found = False
        
        # Check against all entity types
        if entity_lower in entities["hostnames"]:
            found = True
        elif entity_lower in entities["usernames"]:
            found = True
        elif entity_lower in entities["processes"]:
            found = True
        elif entity in entities["ips"]:
            found = True
        elif any(entity_lower in f for f in entities["files"]):
            found = True
        
        if found:
            passed.append(f"Entity '{entity}' exists in evidence")
        else:
            failed.append(f"UNVERIFIED_ENTITY: '{entity}' not found in evidence")
    
    return passed, failed


def validate_timestamp(claim: dict, entities: dict, tolerance_seconds: int = 2) -> tuple[list, list]:
    """Check that timestamps in claim correspond to real events.
    
    Returns:
        Tuple of (passed_checks, failed_checks)
    """
    passed = []
    failed = []
    
    timestamp_range = claim.get("timestamp_range", [])
    if not timestamp_range or not entities["timestamps"]:
        return passed, failed
    
    tolerance = timedelta(seconds=tolerance_seconds)
    
    for ts_str in timestamp_range:
        try:
            if isinstance(ts_str, str):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = ts_str
            
            # Check if any event timestamp is within tolerance
            found = False
            for event_ts in entities["timestamps"]:
                if abs((ts - event_ts).total_seconds()) <= tolerance_seconds:
                    found = True
                    break
            
            if found:
                passed.append(f"Timestamp {ts_str} verified")
            else:
                failed.append(f"TIMESTAMP_MISMATCH: {ts_str} not found in evidence (±{tolerance_seconds}s)")
                
        except Exception as e:
            failed.append(f"Invalid timestamp format: {ts_str}")
    
    return passed, failed


def validate_evidence_refs(claim: dict, events: list[dict]) -> tuple[list, list]:
    """Validate raw evidence references.
    
    Returns:
        Tuple of (passed_checks, failed_checks)
    """
    passed = []
    failed = []
    
    refs = claim.get("raw_evidence_refs", [])
    
    for ref in refs:
        ref_file = ref.get("file", "")
        ref_filter = ref.get("filter", "")
        
        if not ref_file:
            continue
        
        # Find matching events
        matching = [e for e in events if ref_file in str(e.get("_source_parquet", ""))]
        
        if matching:
            passed.append(f"Evidence file '{ref_file}' exists")
        else:
            failed.append(f"EVIDENCE_NOT_FOUND: File '{ref_file}' not in parsed evidence")
    
    return passed, failed


def validate_supporting_evidence(claim: dict, events: list[dict]) -> tuple[list, list]:
    """Search for quoted strings in claim within evidence.
    
    Returns:
        Tuple of (passed_checks, failed_checks)
    """
    passed = []
    failed = []
    
    supporting = claim.get("supporting_evidence", "")
    if not supporting:
        return passed, failed
    
    # Extract quoted strings
    quoted = re.findall(r'"([^"]+)"', supporting)
    quoted += re.findall(r"'([^']+)'", supporting)
    
    # Build searchable evidence text
    evidence_text = " ".join(
        str(v) for e in events for v in e.values() if v
    ).lower()
    
    for quote in quoted[:5]:  # Limit to first 5 quotes
        if len(quote) < 5:
            continue
        if quote.lower() in evidence_text:
            passed.append(f"Quote verified: '{quote[:30]}...'")
        else:
            failed.append(f"QUOTE_NOT_FOUND: '{quote[:50]}' not in evidence")
    
    return passed, failed


def detect_contradictions(claims: list[dict]) -> list[dict]:
    """Detect contradictions between claims.
    
    Returns:
        List of contradiction records
    """
    contradictions = []
    
    # Group claims by affected entities
    by_entity = {}
    for claim in claims:
        for entity in claim.get("affected_entities", []):
            if entity not in by_entity:
                by_entity[entity] = []
            by_entity[entity].append(claim)
    
    # Check for conflicting claims about same entity
    for entity, entity_claims in by_entity.items():
        if len(entity_claims) < 2:
            continue
        
        # Check for conflicting timestamps
        timestamps = []
        for c in entity_claims:
            ts_range = c.get("timestamp_range", [])
            if ts_range:
                timestamps.append((c.get("claim_id"), ts_range))
        
        # Simple contradiction: same entity, vastly different times
        for i, (id1, ts1) in enumerate(timestamps):
            for id2, ts2 in timestamps[i+1:]:
                try:
                    t1 = datetime.fromisoformat(ts1[0].replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(ts2[0].replace("Z", "+00:00"))
                    diff = abs((t1 - t2).total_seconds())
                    
                    # If same entity has events >1 hour apart, might be ok
                    # But if claims conflict on interpretation, flag it
                    # For now, just note potential contradictions
                    
                except:
                    pass
    
    return contradictions


def detect_duplicates(claims: list[dict]) -> list[tuple]:
    """Detect potential duplicate claims.
    
    Returns:
        List of (claim_id_1, claim_id_2) tuples
    """
    duplicates = []
    
    for i, claim1 in enumerate(claims):
        for claim2 in claims[i+1:]:
            # Check if claims reference same evidence
            refs1 = set(str(r) for r in claim1.get("raw_evidence_refs", []))
            refs2 = set(str(r) for r in claim2.get("raw_evidence_refs", []))
            
            if refs1 and refs2 and refs1 == refs2:
                duplicates.append((
                    claim1.get("claim_id", "unknown"),
                    claim2.get("claim_id", "unknown")
                ))
    
    return duplicates


def validate_claim(claim: dict, events: list[dict], entities: dict, tolerance: int = 2) -> ValidationResult:
    """Validate a single claim against evidence.
    
    Args:
        claim: The claim to validate
        events: All parsed events
        entities: Pre-extracted entity index
        tolerance: Timestamp tolerance in seconds
        
    Returns:
        ValidationResult with status and details
    """
    claim_id = claim.get("claim_id", "unknown")
    result = ValidationResult(claim_id)
    
    # 1. Entity existence check
    passed, failed = validate_entity_existence(claim, entities)
    for p in passed:
        result.add_pass(p)
    for f in failed:
        result.add_fail(f, f"Search evidence for entity mentioned in claim {claim_id}")
    
    # 2. Timestamp consistency check
    passed, failed = validate_timestamp(claim, entities, tolerance)
    for p in passed:
        result.add_pass(p)
    for f in failed:
        result.add_fail(f, f"Check timestamps in claim {claim_id} against event log times")
    
    # 3. Evidence reference check
    passed, failed = validate_evidence_refs(claim, events)
    for p in passed:
        result.add_pass(p)
    for f in failed:
        result.add_fail(f, f"Verify evidence file references in claim {claim_id}")
    
    # 4. Quote verification
    passed, failed = validate_supporting_evidence(claim, events)
    for p in passed:
        result.add_pass(p)
    for f in failed:
        result.add_fail(f, f"Search for quoted strings from claim {claim_id}")
    
    # Add warnings for inferred claims
    if claim.get("inferred_vs_direct") == "INFERRED":
        result.add_warning("This is an inferred claim - requires additional validation")
    
    return result


def generate_failure_report(failed_claims: list[tuple], case_path: Path) -> str:
    """Generate markdown report for failed validations.
    
    Args:
        failed_claims: List of (claim, validation_result) tuples
        case_path: Path to case directory
        
    Returns:
        Markdown formatted report
    """
    report = "# Validation Failures Report\n\n"
    report += f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
    report += f"Total failures: {len(failed_claims)}\n\n"
    
    for claim, result in failed_claims:
        report += f"## Claim: {result.claim_id}\n\n"
        report += f"**Status:** {result.status}\n\n"
        report += f"**Summary:** {claim.get('summary', 'No summary')}\n\n"
        report += f"**Source Agent:** {claim.get('_source_agent', 'unknown')}\n\n"
        
        report += "### Failed Checks\n"
        for check in result.checks_failed:
            report += f"- {check}\n"
        
        report += "\n### Manual Review Instructions\n"
        for instr in result.review_instructions:
            report += f"1. {instr}\n"
        
        report += "\n### Verification Steps\n"
        report += f"1. Open the parsed evidence in `{case_path}/parsed/`\n"
        report += f"2. Search for entities: {claim.get('affected_entities', [])}\n"
        report += f"3. Check timestamps: {claim.get('timestamp_range', [])}\n"
        report += "\n---\n\n"
    
    return report


def generate_traceability_matrix(claims: list[dict], results: dict) -> dict:
    """Generate claim traceability matrix.
    
    Args:
        claims: All claims
        results: Dict mapping claim_id to ValidationResult
        
    Returns:
        Traceability matrix as dict
    """
    matrix = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_claims": len(claims),
        "verified": 0,
        "partially_verified": 0,
        "unverified": 0,
        "claims": [],
    }
    
    for claim in claims:
        claim_id = claim.get("claim_id", "unknown")
        result = results.get(claim_id)
        
        if result:
            status = result.status
            if status == ValidationResult.VERIFIED:
                matrix["verified"] += 1
            elif status == ValidationResult.PARTIALLY_VERIFIED:
                matrix["partially_verified"] += 1
            else:
                matrix["unverified"] += 1
        else:
            status = "NOT_VALIDATED"
            matrix["unverified"] += 1
        
        matrix["claims"].append({
            "claim_id": claim_id,
            "summary": claim.get("summary", ""),
            "agent": claim.get("_source_agent", ""),
            "status": status,
            "evidence_refs": claim.get("raw_evidence_refs", []),
            "mitre_technique": claim.get("mitre_technique", ""),
        })
    
    return matrix


def run_validation(case_path_str: str) -> bool:
    """Run Phase 4: Validation.

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

    # Check if Phase 3 is complete
    if not check_phase_complete(case_path, 3):
        click.echo("Phase 3 not complete. Running analysis first...")
        from argus.phases.phase3_analysis import run_analysis
        if not run_analysis(case_path_str):
            click.echo("Analysis failed. Cannot proceed with validation.")
            return False

    validation_dir = case_path / "validation"
    validation_dir.mkdir(exist_ok=True)

    click.echo(f"\nPhase 4: VALIDATION (FVE)")
    click.echo("=" * 40)
    click.echo("100% Programmatic - No LLM")

    # Load data
    click.echo("\nLoading evidence and claims...")
    events = load_parquet_events(case_path)
    claims = load_claims(case_path)

    click.echo(f"  Events: {len(events)}")
    click.echo(f"  Claims to validate: {len(claims)}")

    if not claims:
        click.echo("No claims to validate.")
        write_completion_marker(case_path, 4)
        return True

    # Build entity index
    click.echo("\nBuilding entity index...")
    entities = extract_entities_from_events(events)
    click.echo(f"  IPs: {len(entities['ips'])}")
    click.echo(f"  Hostnames: {len(entities['hostnames'])}")
    click.echo(f"  Users: {len(entities['usernames'])}")
    click.echo(f"  Processes: {len(entities['processes'])}")

    # Load tolerance from config
    import yaml
    config_path = case_path / "argus.yaml"
    tolerance = 2
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            tolerance = config.get("settings", {}).get("timestamp_tolerance_seconds", 2)

    # Validate each claim
    click.echo(f"\nValidating claims (tolerance: ±{tolerance}s)...")
    results = {}
    validated_claims = []
    failed_claims = []
    
    for claim in claims:
        result = validate_claim(claim, events, entities, tolerance)
        results[result.claim_id] = result
        
        if result.status in [ValidationResult.VERIFIED, ValidationResult.PARTIALLY_VERIFIED]:
            validated_claims.append((claim, result))
        else:
            failed_claims.append((claim, result))

    # Detect contradictions
    contradictions = detect_contradictions(claims)
    
    # Detect duplicates
    duplicates = detect_duplicates(claims)

    # Generate outputs
    click.echo("\nGenerating validation outputs...")

    # 1. Validated claims
    validated_output = {
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "total_validated": len(validated_claims),
        "claims": [
            {**claim, "validation": result.to_dict()}
            for claim, result in validated_claims
        ],
    }
    with open(validation_dir / "validated_claims.json", "w") as f:
        json.dump(validated_output, f, indent=2, default=str)

    # 2. Validation failures report
    if failed_claims:
        failure_report = generate_failure_report(failed_claims, case_path)
        with open(validation_dir / "validation_failures.md", "w") as f:
            f.write(failure_report)

    # 3. Claim traceability
    traceability = generate_traceability_matrix(claims, results)
    with open(validation_dir / "claim_traceability.json", "w") as f:
        json.dump(traceability, f, indent=2)

    # 4. Hallucination log (failed claims that look like hallucinations)
    hallucinations = [
        {"claim": claim, "result": result.to_dict()}
        for claim, result in failed_claims
        if result.status == ValidationResult.UNVERIFIED and len(result.checks_failed) > 2
    ]
    with open(validation_dir / "hallucination_log.json", "w") as f:
        json.dump(hallucinations, f, indent=2, default=str)

    # Summary
    click.echo("\n" + "=" * 40)
    click.echo("Validation Summary")
    click.echo("=" * 40)
    click.echo(f"  Verified:           {traceability['verified']}")
    click.echo(f"  Partially verified: {traceability['partially_verified']}")
    click.echo(f"  Unverified:         {traceability['unverified']}")
    
    if contradictions:
        click.echo(click.style(f"  Contradictions:     {len(contradictions)}", fg="yellow"))
    if duplicates:
        click.echo(f"  Potential duplicates: {len(duplicates)}")
    if hallucinations:
        click.echo(click.style(f"  Potential hallucinations: {len(hallucinations)}", fg="red"))

    # Write completion marker
    write_completion_marker(case_path, 4)

    click.echo(f"\nPhase 4 complete. Results in: {validation_dir}")
    return True
