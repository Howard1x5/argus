"""
STAGE 7: ASSEMBLY

Goal: Package all findings into agent-ready files.

Steps:
- 7.1: Domain Packager (3 substeps)
- 7.2: Summary Generator (3 substeps)
- 7.3: Size Checker (3 substeps)

Total: 9 substeps
"""

import logging
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# Token limit (chars / 4 approximation)
DEFAULT_TOKEN_LIMIT = 150000
CHARS_PER_TOKEN = 4


def run(context) -> None:
    """Execute Stage 7: Assembly."""
    logger.info("Stage 7: Assembly starting")

    # Step 7.1: Domain Packager
    agent_files = step_7_1_domain_packager(context)
    context.agent_files = agent_files
    logger.info(f"Step 7.1: Created {len(agent_files)} agent files")

    # Step 7.2: Summary Generator
    summary = step_7_2_summary_generator(context)
    context.extraction_summary = summary
    logger.info("Step 7.2: Generated extraction summary")

    # Step 7.3: Size Checker
    validation = step_7_3_size_checker(context)
    logger.info(f"Step 7.3: Validation complete - {validation['passed']}/{validation['total']} passed")

    # Update statistics
    context.statistics['stage7'] = {
        'agent_files_created': len(agent_files),
        'validation_passed': validation['passed'],
        'validation_total': validation['total'],
        'oversized_files': len(validation.get('oversized', [])),
    }

    logger.info("Stage 7: Assembly completed")


# =============================================================================
# STEP 7.1: DOMAIN PACKAGER
# =============================================================================

def step_7_1_domain_packager(context) -> Dict[str, Path]:
    """
    Create per-agent JSON files.

    Substeps:
    7.1.1: Define Agent-to-Extraction Mapping
    7.1.2: Assemble Per-Agent Files
    7.1.3: Include Decoded Content References
    """

    agent_files = {}
    output_dir = context.output_dir

    # Substep 7.1.1: Define Agent-to-Extraction Mapping
    agent_mapping = {
        'process_trees': {
            'name': 'Agent 1: Process Trees',
            'data_sources': ['process_trees', 'classified_edges'],
            'finding_types': ['chain_', 'pattern_'],
        },
        'file_operations': {
            'name': 'Agent 2: File Operations',
            'data_sources': ['file_process_links'],
            'finding_types': ['file_'],
        },
        'persistence': {
            'name': 'Agent 3: Persistence',
            'data_sources': ['pattern_matches', 'high_entropy_strings'],
            'filter': lambda m: 'service' in str(m.get('pattern_name', '')).lower() or 'persist' in str(m.get('pattern_name', '')).lower(),
        },
        'network': {
            'name': 'Agent 4: Network',
            'data_sources': ['network_profiles', 'iocs'],
            'finding_types': ['network_'],
        },
        'services': {
            'name': 'Agent 5: Services',
            'data_sources': ['pattern_matches', 'high_entropy_strings'],
            'filter': lambda m: 'service' in str(m.get('pattern_name', '')).lower() or 'random_service' in str(m.get('pattern_name', '')).lower(),
        },
        'auth_lateral': {
            'name': 'Agent 6: Auth & Lateral Movement',
            'data_sources': ['cross_system_correlations', 'attack_path'],
            'finding_types': ['mitre_', 'lateral'],
        },
        'cross_system': {
            'name': 'Agent 7: Cross-System',
            'data_sources': ['attack_path', 'sessions'],
            'finding_types': ['cluster_'],
        },
        'powershell': {
            'name': 'Agent 8: PowerShell',
            'data_sources': ['decoded_powershell', 'decoded_content_index'],
            'filter': lambda d: 'powershell' in str(d).lower() or 'ps' in str(getattr(d, 'encoding_chain', [])),
        },
        'anomalies': {
            'name': 'Agent 9: Anomalies',
            'data_sources': ['rare_values', 'high_entropy_strings', 'hot_clusters', 'first_seen_entities'],
            'finding_types': ['rare_', 'entropy_', 'cluster_'],
        },
    }

    # Substep 7.1.2 & 7.1.3: Assemble Per-Agent Files
    for agent_key, config in agent_mapping.items():
        agent_data = {
            'agent_name': config['name'],
            'extraction_data': {},
            'triage_context': _get_triage_context(context, agent_key),
            'statistics': {},
            'key_questions': _get_key_questions(agent_key),
            'decoded_content': [],
        }

        # Collect data from sources
        for source in config.get('data_sources', []):
            source_data = getattr(context, source, None)
            if source_data is not None:
                agent_data['extraction_data'][source] = _serialize_data(source_data, config.get('filter'))

        # Collect relevant findings
        relevant_findings = []
        for finding in context.enriched_findings:
            finding_types = config.get('finding_types', [])
            if any(finding.finding_id.startswith(ft) for ft in finding_types):
                relevant_findings.append(_serialize_finding(finding))

        if relevant_findings:
            agent_data['extraction_data']['findings'] = relevant_findings

        # Include decoded content relevant to this agent
        agent_data['decoded_content'] = _get_relevant_decoded_content(context, agent_key)

        # Compute statistics
        agent_data['statistics'] = _compute_agent_statistics(agent_data)

        # Write to file
        file_path = output_dir / f"{agent_key}.json"
        with open(file_path, 'w') as f:
            json.dump(agent_data, f, indent=2, default=str)

        agent_files[agent_key] = file_path

    return agent_files


def _get_triage_context(context, agent_key: str) -> Dict:
    """Get triage context relevant to this agent."""
    return {
        'attack_window': {
            'start': str(getattr(context, 'attack_window', {}).get('start', '')),
            'end': str(getattr(context, 'attack_window', {}).get('end', '')),
        },
        'systems_analyzed': list(context.unified_df['source_system'].unique()) if context.unified_df is not None else [],
        'total_events': len(context.unified_df) if context.unified_df is not None else 0,
    }


def _get_key_questions(agent_key: str) -> List[str]:
    """Get key investigation questions for this agent."""
    questions = {
        'process_trees': [
            "What process trees show webshell-like behavior (w3wp spawning cmd/powershell)?",
            "Which process chains have the deepest suspicious activity?",
            "Are there any processes running from unusual paths?",
        ],
        'file_operations': [
            "What files were created during the attack window?",
            "Are there any suspicious file moves or renames (potential staging)?",
            "Which files were created and then executed?",
        ],
        'persistence': [
            "What services were installed during the incident?",
            "Are there any scheduled tasks created?",
            "What registry modifications were made to run keys?",
        ],
        'network': [
            "What external IPs were contacted?",
            "Are there any signs of beaconing behavior?",
            "Which processes made unusual network connections?",
        ],
        'services': [
            "Are there services with randomly-generated names?",
            "What commands are embedded in service ImagePaths?",
            "When were the suspicious services created?",
        ],
        'auth_lateral': [
            "What authentication events occurred during the attack?",
            "Is there evidence of lateral movement between systems?",
            "What credentials or accounts were compromised?",
        ],
        'cross_system': [
            "What is the attack path from initial access to objectives?",
            "How did the attacker move between systems?",
            "What is the timeline of cross-system activity?",
        ],
        'powershell': [
            "What encoded PowerShell commands were executed?",
            "Are there any download cradles or remote code execution?",
            "What attack tools (Invoke-*) were used?",
        ],
        'anomalies': [
            "What rare values only appeared during the attack?",
            "Are there high-entropy strings indicating obfuscation?",
            "What entities first appeared during the attack window?",
        ],
    }
    return questions.get(agent_key, ["Investigate this domain for suspicious activity."])


def _serialize_data(data: Any, filter_func=None) -> Any:
    """Serialize data for JSON output."""
    if data is None:
        return None

    if isinstance(data, list):
        result = []
        for item in data:
            # Convert dataclass to dict first for filter compatibility
            if hasattr(item, '__dataclass_fields__'):
                item_dict = _dataclass_to_dict(item)
                if filter_func and not filter_func(item_dict):
                    continue
                result.append(item_dict)
            elif isinstance(item, dict):
                if filter_func and not filter_func(item):
                    continue
                result.append(item)
            else:
                result.append(str(item))
        return result

    if isinstance(data, dict):
        return {k: _serialize_data(v) for k, v in data.items()}

    if hasattr(data, '__dataclass_fields__'):
        return _dataclass_to_dict(data)

    return str(data)


def _dataclass_to_dict(obj) -> Dict:
    """Convert dataclass to dict, handling nested objects."""
    result = {}
    for field_name in obj.__dataclass_fields__:
        value = getattr(obj, field_name)
        if hasattr(value, '__dataclass_fields__'):
            result[field_name] = _dataclass_to_dict(value)
        elif isinstance(value, list):
            result[field_name] = [_dataclass_to_dict(v) if hasattr(v, '__dataclass_fields__') else str(v) for v in value]
        elif isinstance(value, set):
            result[field_name] = list(value)
        else:
            result[field_name] = value
    return result


def _serialize_finding(finding) -> Dict:
    """Serialize an EnrichedFinding for JSON."""
    return {
        'finding_id': finding.finding_id,
        'source_stage': finding.source_stage,
        'timestamp': str(finding.timestamp) if finding.timestamp else None,
        'system': finding.system,
        'summary': finding.summary,
        'severity': finding.severity,
        'confidence': finding.adjusted_confidence or finding.confidence,
        'before_events': finding.before_events[:5],
        'after_events': finding.after_events[:5],
        'process_ancestors': finding.process_ancestors,
        'process_descendants': finding.process_descendants[:5],
        'counter_evidence': finding.counter_evidence,
    }


def _get_relevant_decoded_content(context, agent_key: str) -> List[Dict]:
    """Get decoded content relevant to this agent."""
    decoded = []

    for content in context.decoded_content_index:
        include = False

        if agent_key == 'powershell':
            if 'powershell' in str(content.encoding_chain).lower():
                include = True
            if content.contains_commands:
                include = True

        elif agent_key == 'network':
            if content.contains_urls or content.contains_ips:
                include = True

        elif agent_key == 'auth_lateral':
            if content.contains_credentials:
                include = True
            if any('wmi' in cmd.lower() or 'smb' in cmd.lower() for cmd in content.contains_commands):
                include = True

        elif agent_key in ['process_trees', 'persistence', 'services']:
            # Include all decoded content for these agents
            include = True

        if include:
            decoded.append({
                'decoded_id': content.decoded_id,
                'original': content.original_text[:200] + '...' if len(content.original_text) > 200 else content.original_text,
                'decoded': content.final_text,
                'encoding_chain': content.encoding_chain,
                'contains_urls': content.contains_urls,
                'contains_ips': content.contains_ips,
                'contains_commands': content.contains_commands,
                'source_timestamp': str(content.source_timestamp) if content.source_timestamp else None,
            })

    return decoded[:50]  # Limit per agent


def _compute_agent_statistics(agent_data: Dict) -> Dict:
    """Compute statistics for an agent file."""
    stats = {}

    for key, data in agent_data.get('extraction_data', {}).items():
        if isinstance(data, list):
            stats[f'{key}_count'] = len(data)
        elif isinstance(data, dict):
            stats[f'{key}_keys'] = len(data)

    stats['decoded_content_count'] = len(agent_data.get('decoded_content', []))

    return stats


# =============================================================================
# STEP 7.2: SUMMARY GENERATOR
# =============================================================================

def step_7_2_summary_generator(context) -> Dict:
    """
    Generate global extraction summary.

    Substeps:
    7.2.1: Compute Global Statistics
    7.2.2: Build Extraction Summary
    7.2.3: Build Finding Index
    """

    summary = {}

    # Substep 7.2.1: Compute Global Statistics
    summary['statistics'] = {
        'total_events': len(context.unified_df) if context.unified_df is not None else 0,
        'systems_analyzed': list(context.unified_df['source_system'].unique()) if context.unified_df is not None else [],
        'extraction_stages_completed': 7,
    }

    # Add per-stage stats
    for stage_key, stage_stats in context.statistics.items():
        summary['statistics'][stage_key] = stage_stats

    # Substep 7.2.2: Build Extraction Summary
    # Top 20 findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(
        context.enriched_findings,
        key=lambda f: (severity_order.get(f.severity, 4), str(f.timestamp or ''))
    )

    summary['key_findings'] = [
        {
            'finding_id': f.finding_id,
            'summary': f.summary,
            'severity': f.severity,
            'confidence': f.adjusted_confidence or f.confidence,
            'timestamp': str(f.timestamp) if f.timestamp else None,
        }
        for f in sorted_findings[:20]
    ]

    # Coverage gaps
    summary['coverage_gaps'] = []
    if len(context.process_trees) == 0:
        summary['coverage_gaps'].append('No process trees built (missing Sysmon/Windows process events)')
    if len(context.decoded_content_index) == 0:
        summary['coverage_gaps'].append('No encoded content decoded')
    if len(context.cross_system_correlations) == 0:
        summary['coverage_gaps'].append('No cross-system correlations (single system or missing data)')
    if len(context.network_profiles) == 0:
        summary['coverage_gaps'].append('No network profiles (missing Sysmon EID 3)')

    # Warnings
    summary['warnings'] = context.warnings

    # Attack window
    summary['attack_window'] = {
        'start': str(getattr(context, 'attack_window', {}).get('start', '')),
        'end': str(getattr(context, 'attack_window', {}).get('end', '')),
    }

    # Substep 7.2.3: Build Finding Index
    summary['finding_index'] = [
        {
            'finding_id': f.finding_id,
            'stage': f.source_stage,
            'step': f.source_step,
            'severity': f.severity,
            'summary': f.summary[:100],
            'timestamp': str(f.timestamp) if f.timestamp else None,
            'confidence': f.adjusted_confidence or f.confidence,
        }
        for f in sorted_findings
    ]

    # Write summary to file
    summary_path = context.output_dir / 'extraction_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)

    return summary


# =============================================================================
# STEP 7.3: SIZE CHECKER
# =============================================================================

def step_7_3_size_checker(context) -> Dict:
    """
    Validate agent file sizes and generate summaries if needed.

    Substeps:
    7.3.1: Measure Agent File Sizes
    7.3.2: Generate Summaries for Oversized Files
    7.3.3: Validate Agent-Readiness
    """

    validation = {
        'total': 0,
        'passed': 0,
        'failed': [],
        'oversized': [],
        'summaries_created': [],
    }

    for agent_key, file_path in context.agent_files.items():
        validation['total'] += 1

        # Substep 7.3.1: Measure Agent File Sizes
        file_size = file_path.stat().st_size
        estimated_tokens = file_size / CHARS_PER_TOKEN

        if estimated_tokens > DEFAULT_TOKEN_LIMIT:
            validation['oversized'].append({
                'agent': agent_key,
                'tokens': estimated_tokens,
                'limit': DEFAULT_TOKEN_LIMIT,
            })

            # Substep 7.3.2: Generate Summaries for Oversized Files
            _create_summary_file(file_path, context.output_dir, agent_key)
            validation['summaries_created'].append(agent_key)

        # Substep 7.3.3: Validate Agent-Readiness
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Check required sections
            required_sections = ['extraction_data', 'triage_context', 'statistics', 'key_questions']
            missing = [s for s in required_sections if s not in data]

            if missing:
                validation['failed'].append({
                    'agent': agent_key,
                    'reason': f'Missing sections: {missing}',
                })
            else:
                validation['passed'] += 1

        except Exception as e:
            validation['failed'].append({
                'agent': agent_key,
                'reason': f'Invalid JSON: {e}',
            })

    # Write validation report
    report_path = context.output_dir / 'validation_report.json'
    with open(report_path, 'w') as f:
        json.dump(validation, f, indent=2)

    return validation


def _create_summary_file(original_path: Path, output_dir: Path, agent_key: str) -> Path:
    """Create a summarized version of an oversized agent file."""

    with open(original_path, 'r') as f:
        data = json.load(f)

    # Create summary prioritizing critical/high findings
    summary_data = {
        'agent_name': data.get('agent_name', ''),
        'is_summary': True,
        'note': f"Full extraction contains more items. Summary shows top findings. Full data in {original_path.name}",
        'extraction_data': {},
        'triage_context': data.get('triage_context', {}),
        'statistics': data.get('statistics', {}),
        'key_questions': data.get('key_questions', []),
    }

    # Include only critical/high severity items from extraction_data
    for key, items in data.get('extraction_data', {}).items():
        if isinstance(items, list):
            # Filter to high-priority items
            high_priority = [
                item for item in items
                if item.get('severity') in ['CRITICAL', 'HIGH'] or
                   item.get('classification') in ['HIGHLY_SUSPICIOUS', 'SUSPICIOUS']
            ][:50]  # Limit to 50
            summary_data['extraction_data'][key] = high_priority
        else:
            summary_data['extraction_data'][key] = items

    # Limit decoded content
    summary_data['decoded_content'] = data.get('decoded_content', [])[:20]

    # Write summary
    summary_path = output_dir / f"{agent_key}_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary_data, f, indent=2, default=str)

    return summary_path
