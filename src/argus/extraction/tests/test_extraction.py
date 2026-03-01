#!/usr/bin/env python3
"""
Test script for ForensicExtractor against Trigonous data.

Validates against the Testing Checklist in FORENSIC_EXTRACTOR_GUIDE.md.
"""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from argus.extraction.orchestrator import ExtractionOrchestrator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_extraction(parquet_dir: Path, output_dir: Path):
    """Run the full extraction pipeline."""
    logger.info(f"Starting extraction from {parquet_dir}")

    orchestrator = ExtractionOrchestrator(parquet_dir, output_dir)
    context = orchestrator.run()

    return context


def validate_trigonous_checklist(context):
    """
    Validate extraction against Trigonous Testing Checklist.

    Returns (passed, failed, total) counts.
    """
    results = {
        'passed': [],
        'failed': [],
    }

    # ===== Process Trees =====
    # 30 w3wp.exe child processes found
    w3wp_children = 0
    for tree in context.process_trees:
        for node in tree.all_nodes:
            if 'w3wp' in node.parent_process_name.lower():
                w3wp_children += 1

    if w3wp_children >= 25:  # Allow some tolerance
        results['passed'].append(f"w3wp children: {w3wp_children}")
    else:
        results['failed'].append(f"w3wp children: {w3wp_children} (expected ~30)")

    # w3wp chains classified as suspicious
    suspicious_w3wp = sum(
        1 for e in context.classified_edges
        if 'w3wp' in e['parent_process'] and e['classification'] in ['SUSPICIOUS', 'HIGHLY_SUSPICIOUS']
    )
    if suspicious_w3wp > 0:
        results['passed'].append(f"Suspicious w3wp edges: {suspicious_w3wp}")
    else:
        results['failed'].append("No suspicious w3wp edges found")

    # ===== Decoded Content =====
    # Base64 decoded (optional - depends on attack techniques in dataset)
    if len(context.decoded_base64) > 0:
        results['passed'].append(f"Decoded base64: {len(context.decoded_base64)}")
    # No failure - base64 encoding is not always present in attacks

    # PowerShell decoded (more common and important)
    ps_decoded = len(context.decoded_powershell)
    if ps_decoded > 0:
        results['passed'].append(f"Decoded PowerShell: {ps_decoded}")
    else:
        results['failed'].append("No PowerShell decoded")

    # Check for Invoke-WMIExec/SMBExec in decoded content
    attack_tools = ['invoke-wmiexec', 'invoke-smbexec', 'invoke-thehash']
    found_tools = set()
    for content in context.decoded_content_index:
        for tool in attack_tools:
            if tool in content.final_text.lower():
                found_tools.add(tool)

    if found_tools:
        results['passed'].append(f"Attack tools found: {found_tools}")
    else:
        results['failed'].append("No Invoke-* attack tools in decoded content")

    # ===== Credential Access =====
    # pd.exe / procdump
    procdump_found = any(
        'procdump' in m['pattern_name'] or 'pd.exe' in m.get('matched_text', '').lower()
        for m in context.pattern_matches
    )
    if procdump_found:
        results['passed'].append("ProcDump pattern found")
    else:
        results['failed'].append("ProcDump pattern not found")

    # ===== Persistence =====
    # Random service names (high entropy)
    random_services = [
        h for h in context.high_entropy_strings
        if 'service' in h.source_column.lower() and h.entropy >= 3.5
    ]
    if len(random_services) >= 5:  # Expecting 6
        results['passed'].append(f"High-entropy services: {len(random_services)}")
    else:
        results['failed'].append(f"High-entropy services: {len(random_services)} (expected 6)")

    # ===== Network =====
    # External IP detected
    external_ips = [
        ioc for ioc in context.iocs
        if ioc['type'] == 'ipv4' and ioc.get('classification') == 'EXTERNAL'
    ]
    if external_ips:
        results['passed'].append(f"External IPs: {len(external_ips)}")
        # Check for specific IPs in decoded attack commands (optional, dataset-specific)
        attack_ips = [ioc for ioc in external_ips if ioc.get('risk_score') in ['HIGH', 'CRITICAL']]
        if attack_ips:
            results['passed'].append(f"High-risk external IPs: {len(attack_ips)}")
    else:
        results['failed'].append("No external IPs found")

    # ===== Cross-System =====
    if len(context.cross_system_correlations) > 0:
        results['passed'].append(f"Cross-system correlations: {len(context.cross_system_correlations)}")
    else:
        results['failed'].append("No cross-system correlations (may be single system)")

    # ===== Hot Clusters =====
    if len(context.hot_clusters) > 0:
        results['passed'].append(f"Hot clusters: {len(context.hot_clusters)}")
    else:
        results['failed'].append("No hot clusters detected")

    # ===== Assembly =====
    if len(context.agent_files) >= 9:
        results['passed'].append(f"Agent files created: {len(context.agent_files)}")
    else:
        results['failed'].append(f"Agent files: {len(context.agent_files)} (expected 9)")

    return results


def print_results(results):
    """Print validation results."""
    print("\n" + "=" * 60)
    print("TRIGONOUS TESTING CHECKLIST RESULTS")
    print("=" * 60)

    print(f"\nPASSED ({len(results['passed'])}):")
    for item in results['passed']:
        print(f"  [✓] {item}")

    print(f"\nFAILED ({len(results['failed'])}):")
    for item in results['failed']:
        print(f"  [✗] {item}")

    total = len(results['passed']) + len(results['failed'])
    pct = (len(results['passed']) / total * 100) if total > 0 else 0
    print(f"\nSCORE: {len(results['passed'])}/{total} ({pct:.1f}%)")
    print("=" * 60)


def main():
    # Default paths
    parquet_dir = Path("/tmp/argus-fresh-run/parsed")
    output_dir = Path("/tmp/extraction-test")

    # Allow override via args
    if len(sys.argv) > 1:
        parquet_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_dir = Path(sys.argv[2])

    output_dir.mkdir(parents=True, exist_ok=True)

    # Run extraction
    context = run_extraction(parquet_dir, output_dir)

    # Print statistics
    print("\n" + "=" * 60)
    print("EXTRACTION STATISTICS")
    print("=" * 60)
    for stage, stats in context.statistics.items():
        print(f"\n{stage}:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    # Validate against checklist
    results = validate_trigonous_checklist(context)
    print_results(results)

    return 0 if len(results['failed']) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
