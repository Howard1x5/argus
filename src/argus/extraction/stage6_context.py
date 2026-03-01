"""
STAGE 6: CONTEXT ENRICHMENT

Goal: Make every finding richer so agents can interpret better.

Steps:
- 6.1: Temporal Context Builder (3 substeps)
- 6.2: Lineage Expander (3 substeps)
- 6.3: Counter-Evidence Finder (2 substeps)

Total: 10 substeps (originally listed as 10, but spec shows 8 in detail)
"""

import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import timedelta

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class EnrichedFinding:
    """A finding with full context for agent interpretation."""
    finding_id: str
    source_stage: str
    source_step: str
    timestamp: Any
    system: str
    summary: str
    severity: str
    confidence: str

    # Temporal context
    before_events: List[Dict] = field(default_factory=list)
    after_events: List[Dict] = field(default_factory=list)
    cross_system_events: List[Dict] = field(default_factory=list)

    # Lineage context
    process_ancestors: List[Dict] = field(default_factory=list)
    process_descendants: List[Dict] = field(default_factory=list)
    file_lifecycle: Optional[Dict] = None
    auth_context: Optional[Dict] = None

    # Counter-evidence
    counter_evidence: List[str] = field(default_factory=list)
    adjusted_confidence: str = ''

    # Raw data
    raw_data: Dict = field(default_factory=dict)


def run(context) -> None:
    """Execute Stage 6: Context Enrichment."""
    logger.info("Stage 6: Context Enrichment starting")

    df = context.unified_df

    # Step 6.1: Temporal Context Builder
    findings = step_6_1_temporal_context_builder(df, context)
    logger.info(f"Step 6.1: Built temporal context for {len(findings)} findings")

    # Step 6.2: Lineage Expander
    step_6_2_lineage_expander(findings, context)
    logger.info("Step 6.2: Expanded lineage for all findings")

    # Step 6.3: Counter-Evidence Finder
    step_6_3_counter_evidence_finder(findings, df, context)
    logger.info("Step 6.3: Checked counter-evidence for all findings")

    context.enriched_findings = findings

    # Update statistics
    context.statistics['stage6'] = {
        'enriched_findings': len(findings),
        'with_counter_evidence': sum(1 for f in findings if f.counter_evidence),
        'confidence_adjustments': sum(1 for f in findings if f.adjusted_confidence != f.confidence),
    }

    logger.info("Stage 6: Context Enrichment completed")


# =============================================================================
# STEP 6.1: TEMPORAL CONTEXT BUILDER
# =============================================================================

def step_6_1_temporal_context_builder(df, context) -> List[EnrichedFinding]:
    """
    Add temporal context to all findings.

    Substeps:
    6.1.1: Collect All Findings
    6.1.2: Pull Surrounding Events
    6.1.3: Pull Cross-System Simultaneous Events
    """

    findings = []
    finding_id = 0

    # Substep 6.1.1: Collect All Findings from Stages 4-5

    # Pattern matches (Stage 4)
    for match in context.pattern_matches:
        findings.append(EnrichedFinding(
            finding_id=f"pattern_{finding_id}",
            source_stage='4',
            source_step='4.1',
            timestamp=match.get('timestamp'),
            system=match.get('source_system', 'unknown'),
            summary=f"{match['pattern_name']}: {match['description']}",
            severity=match['severity'],
            confidence='HIGH',
            raw_data=match,
        ))
        finding_id += 1

    # MITRE detections (Stage 4)
    for detection in context.mitre_detections:
        if detection['status'] in ['CONFIRMED', 'LIKELY']:
            findings.append(EnrichedFinding(
                finding_id=f"mitre_{finding_id}",
                source_stage='4',
                source_step='4.3',
                timestamp=None,
                system='multiple',
                summary=f"MITRE {detection['technique_id']}: {detection['technique_name']}",
                severity='HIGH' if detection['status'] == 'CONFIRMED' else 'MEDIUM',
                confidence=detection['status'],
                raw_data=detection,
            ))
            finding_id += 1

    # Rare values (Stage 5)
    for rare in context.rare_values[:50]:  # Limit to top 50
        findings.append(EnrichedFinding(
            finding_id=f"rare_{finding_id}",
            source_stage='5',
            source_step='5.1',
            timestamp=rare.first_seen,
            system='multiple',
            summary=f"Rare {rare.column}: {rare.value} (seen {rare.count}x, rarity score {rare.rarity_score:.1f})",
            severity='MEDIUM',
            confidence='MEDIUM',
            raw_data={'value': rare.value, 'column': rare.column, 'count': rare.count},
        ))
        finding_id += 1

    # High entropy strings (Stage 5) - limit to top 100 by entropy
    sorted_entropy = sorted(context.high_entropy_strings, key=lambda x: x.entropy, reverse=True)[:100]
    for he in sorted_entropy:
        findings.append(EnrichedFinding(
            finding_id=f"entropy_{finding_id}",
            source_stage='5',
            source_step='5.2',
            timestamp=he.source_timestamp,
            system='unknown',
            summary=f"High-entropy {he.source_column}: {he.value} (entropy {he.entropy:.2f})",
            severity='HIGH' if he.entropy > 4.5 else 'MEDIUM',
            confidence='HIGH',
            raw_data={'value': he.value, 'entropy': he.entropy, 'column': he.source_column},
        ))
        finding_id += 1

    # Suspicious chains (Stage 5)
    for chain in context.suspicious_chains:
        findings.append(EnrichedFinding(
            finding_id=f"chain_{finding_id}",
            source_stage='5',
            source_step='5.5',
            timestamp=chain.get('timestamp'),
            system=chain.get('source_system', 'unknown'),
            summary=f"Suspicious chain: {chain['parent_process']} → {chain['child_process']}",
            severity='CRITICAL' if chain['severity_score'] > 15 else 'HIGH',
            confidence='HIGH',
            raw_data=chain,
        ))
        finding_id += 1

    # Hot clusters (Stage 5)
    for i, cluster in enumerate(context.hot_clusters):
        findings.append(EnrichedFinding(
            finding_id=f"cluster_{finding_id}",
            source_stage='5',
            source_step='5.4',
            timestamp=cluster.start_time,
            system='multiple',
            summary=f"Activity cluster: {cluster.indicator_count} indicators in {cluster.duration_seconds:.0f}s",
            severity='HIGH',
            confidence='HIGH',
            raw_data={
                'start': str(cluster.start_time),
                'end': str(cluster.end_time),
                'indicator_count': cluster.indicator_count,
                'indicator_types': list(cluster.indicator_types),
            },
        ))
        finding_id += 1

    # Substep 6.1.2 & 6.1.3: Pull Surrounding Events
    # Limit temporal context enrichment to top 100 findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings_with_ts = [f for f in findings if f.timestamp is not None]
    findings_with_ts.sort(key=lambda f: severity_order.get(f.severity, 4))

    for finding in findings_with_ts[:100]:  # Only top 100
        _add_temporal_context(finding, df)

    return findings


def _add_temporal_context(finding: EnrichedFinding, df) -> None:
    """Add before/after and cross-system events to a finding."""

    if finding.timestamp is None:
        return

    ts = finding.timestamp
    system = finding.system

    # Substep 6.1.2: Pull Surrounding Events (±30 seconds on same system)
    window_before = ts - timedelta(seconds=30)
    window_after = ts + timedelta(seconds=30)

    same_system = df[df['source_system'] == system] if system != 'multiple' else df

    before = same_system[
        (same_system['timestamp_utc'] >= window_before) &
        (same_system['timestamp_utc'] < ts)
    ].sort_values('timestamp_utc', ascending=False)

    after = same_system[
        (same_system['timestamp_utc'] > ts) &
        (same_system['timestamp_utc'] <= window_after)
    ].sort_values('timestamp_utc')

    # Convert to dicts (limit to 10 events each)
    finding.before_events = _rows_to_event_summaries(before.head(10))
    finding.after_events = _rows_to_event_summaries(after.head(10))

    # Substep 6.1.3: Pull Cross-System Simultaneous Events (±5 seconds)
    if system != 'multiple':
        cross_window_start = ts - timedelta(seconds=5)
        cross_window_end = ts + timedelta(seconds=5)

        other_systems = df[df['source_system'] != system]
        cross_events = other_systems[
            (other_systems['timestamp_utc'] >= cross_window_start) &
            (other_systems['timestamp_utc'] <= cross_window_end)
        ]

        finding.cross_system_events = _rows_to_event_summaries(cross_events.head(10))


def _rows_to_event_summaries(df_subset) -> List[Dict]:
    """Convert DataFrame rows to event summary dicts."""
    summaries = []
    for _, row in df_subset.iterrows():
        summary = {
            'timestamp': str(row.get('timestamp_utc', '')),
            'event_id': row.get('event_id'),
            'process': row.get('process_name'),
            'command': str(row.get('command_line', ''))[:200] if pd.notna(row.get('command_line')) else '',
            'user': row.get('username'),
            'system': row.get('source_system'),
        }
        summaries.append(summary)
    return summaries


# =============================================================================
# STEP 6.2: LINEAGE EXPANDER
# =============================================================================

def step_6_2_lineage_expander(findings: List[EnrichedFinding], context) -> None:
    """
    Expand process, file, and auth lineage for findings.

    Substeps:
    6.2.1: Expand Process Findings
    6.2.2: Expand File Findings
    6.2.3: Expand Authentication Findings
    """

    # Build process tree lookup
    process_lookup = {}
    for tree in context.process_trees:
        for node in tree.all_nodes:
            process_lookup[node.event_index] = {
                'node': node,
                'tree': tree,
            }

    for finding in findings:
        # Substep 6.2.1: Expand Process Findings
        if finding.source_step in ['4.1', '5.5']:
            row_idx = finding.raw_data.get('row_index')
            if row_idx and row_idx in process_lookup:
                info = process_lookup[row_idx]
                node = info['node']
                tree = info['tree']

                # Get ancestors
                finding.process_ancestors = _get_process_ancestors(node, tree)
                # Get descendants
                finding.process_descendants = _get_process_descendants(node)

        # Substep 6.2.2: Expand File Findings
        if 'filename' in finding.summary.lower() or 'file' in finding.summary.lower():
            # Check if this finding relates to any file-process links
            for link in context.file_process_links:
                if link.get('target_filename') and finding.raw_data.get('value'):
                    if finding.raw_data['value'] in str(link.get('target_filename', '')):
                        finding.file_lifecycle = {
                            'created_by': link.get('creating_process'),
                            'creation_time': str(link.get('timestamp')),
                            'executed': link.get('execution_event_index') is not None,
                            'execution_time': str(link.get('execution_timestamp')) if link.get('execution_timestamp') else None,
                        }
                        break

        # Substep 6.2.3: Expand Authentication Findings
        if any(term in finding.summary.lower() for term in ['logon', 'auth', 'credential', 'lateral']):
            # Check cross-system correlations
            for corr in context.cross_system_correlations:
                # Link if timestamps are close
                if finding.timestamp and corr.source_timestamp:
                    try:
                        delta = abs((finding.timestamp - corr.source_timestamp).total_seconds())
                        if delta < 10:
                            finding.auth_context = {
                                'source_system': corr.source_system,
                                'target_system': corr.target_system,
                                'correlation_type': corr.correlation_type,
                                'time_delta': corr.time_delta_seconds,
                            }
                            break
                    except:
                        pass


def _get_process_ancestors(node, tree) -> List[Dict]:
    """Get ancestor process info up the tree."""
    ancestors = []

    # Find parent node in tree
    for other_node in tree.all_nodes:
        if other_node.pid == node.ppid and other_node.timestamp < node.timestamp:
            ancestors.append({
                'process': other_node.process_name,
                'command': other_node.command_line[:200] if other_node.command_line else '',
                'pid': other_node.pid,
                'user': other_node.username,
            })
            # Recurse for grandparents (limit depth)
            if len(ancestors) < 3:
                parent_ancestors = _get_process_ancestors(other_node, tree)
                ancestors.extend(parent_ancestors)
            break

    return ancestors


def _get_process_descendants(node) -> List[Dict]:
    """Get descendant process info down the tree."""
    descendants = []

    for child in node.children:
        descendants.append({
            'process': child.process_name,
            'command': child.command_line[:200] if child.command_line else '',
            'pid': child.pid,
            'user': child.username,
        })
        # Recurse for grandchildren (limit depth)
        if len(descendants) < 10:
            child_descendants = _get_process_descendants(child)
            descendants.extend(child_descendants)

    return descendants[:10]  # Limit total


# =============================================================================
# STEP 6.3: COUNTER-EVIDENCE FINDER
# =============================================================================

def step_6_3_counter_evidence_finder(findings: List[EnrichedFinding], df, context) -> None:
    """
    Find evidence that might reduce suspicion of findings.

    Substeps:
    6.3.1: Check for Benign Explanations
    6.3.2: Compute Adjusted Confidence
    """

    # Get attack window
    attack_window = getattr(context, 'attack_window', {})
    attack_start = attack_window.get('start')
    attack_end = attack_window.get('end')

    for finding in findings:
        # Substep 6.3.1: Check for Benign Explanations

        # Check if entity appeared before attack window (suggests legitimate)
        if finding.timestamp and attack_start:
            entity = finding.raw_data.get('value') or finding.raw_data.get('process_name')
            if entity:
                first_seen = context.first_seen_entities.get(f"process:{entity}", {}).get('first_seen')
                if first_seen and first_seen < attack_start:
                    finding.counter_evidence.append(
                        f"Entity '{entity}' first seen before attack window"
                    )

        # Check if service name matches known legitimate software
        if 'service' in finding.summary.lower():
            value = finding.raw_data.get('value', '')
            # Known legitimate services with unusual names
            legitimate_services = ['googleupdate', 'microsoftedge', 'mozillamaintenance']
            if any(leg in value.lower() for leg in legitimate_services):
                finding.counter_evidence.append(
                    f"Service name matches known legitimate software pattern"
                )

        # Check if IP appears in normal traffic before attack
        if 'ip' in finding.source_step.lower() or 'network' in finding.summary.lower():
            ip = finding.raw_data.get('value')
            if ip and attack_start:
                # Check if IP was seen before attack window
                ip_events = df[df['dest_ip'] == ip]
                if len(ip_events) > 0:
                    earliest = ip_events['timestamp_utc'].min()
                    if earliest and earliest < attack_start:
                        finding.counter_evidence.append(
                            f"IP {ip} seen in normal traffic before attack window"
                        )

        # Substep 6.3.2: Compute Adjusted Confidence
        finding.adjusted_confidence = finding.confidence

        if len(finding.counter_evidence) == 0:
            # No counter-evidence, confidence unchanged
            pass
        elif len(finding.counter_evidence) == 1:
            # Partial counter-evidence, reduce one level
            confidence_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            current_idx = confidence_levels.index(finding.confidence) if finding.confidence in confidence_levels else 1
            new_idx = min(current_idx + 1, len(confidence_levels) - 1)
            finding.adjusted_confidence = confidence_levels[new_idx]
        else:
            # Strong counter-evidence, reduce two levels
            confidence_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            current_idx = confidence_levels.index(finding.confidence) if finding.confidence in confidence_levels else 1
            new_idx = min(current_idx + 2, len(confidence_levels) - 1)
            finding.adjusted_confidence = confidence_levels[new_idx]
