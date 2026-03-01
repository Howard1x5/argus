"""Phase 5: IOC EXTRACTION & ENRICHMENT.

Extracts IOCs from evidence and validated claims,
enriches with threat intelligence if API keys available.
"""

import json
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import ipaddress
import time

import click
import pyarrow.parquet as pq

from argus.config import get_api_key
from argus.phases.phase0_init import write_completion_marker
from argus.phases.phase2_triage import check_phase_complete


# RFC 1918 private IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in PRIVATE_RANGES)
    except ValueError:
        return False


# IOC extraction patterns
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
}

# Domains to exclude (common benign domains and file extensions)
EXCLUDED_DOMAINS = {
    # Major tech domains
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "googleapis.com", "gstatic.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com", "cloudflare-dns.com",
    "localhost", "local",
    # File extensions that match domain pattern
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1",
    ".log", ".txt", ".json", ".xml", ".csv", ".dat", ".tmp",
    ".dmp", ".evtx", ".etl", ".msi", ".cab",
}

# TLDs that are commonly file extensions - need special handling
FILE_EXTENSION_TLDS = {"exe", "dll", "sys", "com", "bat", "cmd", "log", "txt", "dat", "dmp", "msi"}


def extract_iocs(text: str) -> dict:
    """Extract IOCs from text.
    
    Returns:
        Dict mapping IOC type to set of values
    """
    iocs = {ioc_type: set() for ioc_type in IOC_PATTERNS}
    
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            # Filter IPs
            if ioc_type == "ipv4":
                if not is_private_ip(match):
                    iocs[ioc_type].add(match)
            # Filter domains
            elif ioc_type == "domain":
                domain_lower = match.lower()
                # Skip if contains excluded domain
                if any(excl in domain_lower for excl in EXCLUDED_DOMAINS):
                    continue
                # Skip if TLD is a common file extension (e.g., cmd.exe, lsass.exe)
                tld = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
                if tld in FILE_EXTENSION_TLDS:
                    continue
                # Skip if it looks like a filename (single dot, short)
                if domain_lower.count(".") == 1 and len(domain_lower) < 20:
                    parts = domain_lower.split(".")
                    if len(parts[0]) < 12 and len(parts[1]) <= 4:
                        continue
                iocs[ioc_type].add(match)
            else:
                iocs[ioc_type].add(match)
    
    return iocs


def load_all_evidence_text(case_path: Path) -> str:
    """Load all evidence as searchable text."""
    text_parts = []
    
    # Load from Parquet
    parsed_dir = case_path / "parsed"
    for parquet_file in parsed_dir.glob("*.parquet"):
        try:
            table = pq.read_table(parquet_file)
            for row in table.to_pylist():
                text_parts.append(" ".join(str(v) for v in row.values() if v))
        except Exception:
            pass
    
    # Load from validated claims
    validation_dir = case_path / "validation"
    claims_file = validation_dir / "validated_claims.json"
    if claims_file.exists():
        try:
            with open(claims_file) as f:
                data = json.load(f)
                for claim in data.get("claims", []):
                    text_parts.append(json.dumps(claim))
        except Exception:
            pass
    
    return " ".join(text_parts)


def enrich_with_virustotal(ioc: str, ioc_type: str, api_key: str) -> Optional[dict]:
    """Enrich IOC with VirusTotal data."""
    try:
        import requests
        
        base_url = "https://www.virustotal.com/api/v3"
        headers = {"x-apikey": api_key}
        
        if ioc_type == "ipv4":
            url = f"{base_url}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{base_url}/domains/{ioc}"
        elif ioc_type in ["md5", "sha1", "sha256"]:
            url = f"{base_url}/files/{ioc}"
        else:
            return None
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation", 0),
            }
        elif response.status_code == 429:
            time.sleep(60)  # Rate limited, wait
            return None
            
    except Exception:
        pass
    
    return None


def enrich_with_abuseipdb(ip: str, api_key: str) -> Optional[dict]:
    """Enrich IP with AbuseIPDB data."""
    try:
        import requests
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "abuseipdb",
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
            }
            
    except Exception:
        pass
    
    return None


def calculate_risk_score(ioc: str, ioc_type: str, enrichment: list) -> int:
    """Calculate risk score (0-100) based on enrichment data."""
    score = 0
    
    for data in enrichment:
        source = data.get("source", "")
        
        if source == "virustotal":
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            if malicious > 5:
                score += 50
            elif malicious > 0:
                score += 30
            if suspicious > 0:
                score += 10
                
        elif source == "abuseipdb":
            confidence = data.get("abuse_confidence", 0)
            score += min(confidence // 2, 40)
    
    return min(score, 100)


def run_ioc_extraction(case_path_str: str) -> bool:
    """Run Phase 5: IOC Extraction & Enrichment.

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

    # Check if Phase 4 is complete
    if not check_phase_complete(case_path, 4):
        click.echo("Phase 4 not complete. Running validation first...")
        from argus.phases.phase4_validation import run_validation
        if not run_validation(case_path_str):
            click.echo("Validation failed. Cannot proceed with IOC extraction.")
            return False

    iocs_dir = case_path / "iocs"
    iocs_dir.mkdir(exist_ok=True)

    click.echo(f"\nPhase 5: IOC EXTRACTION & ENRICHMENT")
    click.echo("=" * 40)

    # Extract IOCs
    click.echo("\nExtracting IOCs from evidence...")
    evidence_text = load_all_evidence_text(case_path)
    
    extracted = extract_iocs(evidence_text)
    
    total_iocs = sum(len(v) for v in extracted.values())
    click.echo(f"  Total IOCs found: {total_iocs}")
    for ioc_type, iocs in extracted.items():
        if iocs:
            click.echo(f"    {ioc_type}: {len(iocs)}")

    # Build IOC records
    ioc_records = []
    for ioc_type, iocs in extracted.items():
        for ioc in iocs:
            ioc_records.append({
                "type": ioc_type,
                "value": ioc,
                "context": f"Extracted from evidence",
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "enrichment": [],
                "risk_score": 0,
            })

    # Save extracted IOCs
    extracted_output = {
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(ioc_records),
        "by_type": {k: len(v) for k, v in extracted.items()},
        "iocs": ioc_records,
    }
    with open(iocs_dir / "extracted_iocs.json", "w") as f:
        json.dump(extracted_output, f, indent=2)

    # Enrichment
    click.echo("\nChecking for enrichment API keys...")
    
    vt_key = get_api_key("virustotal")
    abuseipdb_key = get_api_key("abuseipdb")
    
    has_enrichment = vt_key or abuseipdb_key
    
    if not has_enrichment:
        click.echo(click.style("  No enrichment keys configured.", fg="yellow"))
        click.echo("  Run 'argus enrich' after adding API keys to enrich IOCs.")
    else:
        click.echo("\nEnriching IOCs...")
        enriched_count = 0
        
        for ioc_record in ioc_records[:50]:  # Limit to first 50 for API limits
            ioc = ioc_record["value"]
            ioc_type = ioc_record["type"]
            
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
            
            # Calculate risk score
            ioc_record["risk_score"] = calculate_risk_score(
                ioc, ioc_type, ioc_record["enrichment"]
            )
        
        click.echo(f"  Enriched: {enriched_count} IOCs")

    # Sort by risk score
    ioc_records.sort(key=lambda x: x["risk_score"], reverse=True)

    # Save enriched IOCs
    enriched_output = {
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(ioc_records),
        "high_risk": len([i for i in ioc_records if i["risk_score"] >= 50]),
        "enrichment_sources": [],
        "iocs": ioc_records,
    }
    
    if vt_key:
        enriched_output["enrichment_sources"].append("virustotal")
    if abuseipdb_key:
        enriched_output["enrichment_sources"].append("abuseipdb")
    
    with open(iocs_dir / "enriched_iocs.json", "w") as f:
        json.dump(enriched_output, f, indent=2)

    # Summary
    click.echo("\n" + "=" * 40)
    click.echo("IOC Summary")
    click.echo("=" * 40)
    click.echo(f"  Total IOCs:      {len(ioc_records)}")
    click.echo(f"  High risk (50+): {enriched_output['high_risk']}")
    if enriched_output["enrichment_sources"]:
        click.echo(f"  Enriched with:   {', '.join(enriched_output['enrichment_sources'])}")

    # Write completion marker
    write_completion_marker(case_path, 5)

    click.echo(f"\nPhase 5 complete. Results in: {iocs_dir}")
    return True
