"""
STAGE 5: ANOMALY DETECTION

Goal: Find suspicious activity that doesn't match known signatures.

Steps:
- 5.1: Frequency Analyzer (3 substeps)
- 5.2: Entropy Calculator (4 substeps)
- 5.3: First-Seen Detector (3 substeps)
- 5.4: Temporal Cluster Detector (3 substeps)
- 5.5: Parent-Child Novelty Detector (3 substeps)
- 5.6: Network Behavior Profiler (3 substeps)

Total: 20 substeps
"""

import logging
import math
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import timedelta
from collections import Counter

import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class RareValue:
    """Represents a rare value detected in the data."""
    value: str
    column: str
    count: int
    median: float
    rarity_score: float
    first_seen: Any
    last_seen: Any
    timestamps: List[Any]
    in_attack_window: bool = False


@dataclass
class HighEntropyString:
    """Represents a high-entropy string."""
    value: str
    entropy: float
    normalized_entropy: float
    source_column: str
    source_row: int
    source_timestamp: Any
    is_false_positive: bool = False
    fp_reason: Optional[str] = None


@dataclass
class HotCluster:
    """Represents a temporal cluster of suspicious activity."""
    start_time: Any
    end_time: Any
    duration_seconds: float
    indicator_count: int
    indicator_types: Set[str]
    key_events: List[Dict]
    events_in_window: int


def run(context) -> None:
    """Execute Stage 5: Anomaly Detection."""
    logger.info("Stage 5: Anomaly Detection starting")

    df = context.unified_df

    # Step 5.1: Frequency Analyzer
    rare_values = step_5_1_frequency_analyzer(df)
    context.rare_values = rare_values
    logger.info(f"Step 5.1: Found {len(rare_values)} rare values")

    # Step 5.2: Entropy Calculator
    high_entropy = step_5_2_entropy_calculator(df)
    context.high_entropy_strings = high_entropy
    logger.info(f"Step 5.2: Found {len(high_entropy)} high-entropy strings")

    # Step 5.3: First-Seen Detector
    first_seen, attack_window = step_5_3_first_seen_detector(df, context)
    context.first_seen_entities = first_seen
    context.attack_window = attack_window
    new_during_attack = sum(1 for v in first_seen.values() if v.get('in_attack_window', False))
    logger.info(f"Step 5.3: Found {new_during_attack} entities new during attack window")

    # Step 5.4: Temporal Cluster Detector
    hot_clusters = step_5_4_temporal_cluster_detector(df, context)
    context.hot_clusters = hot_clusters
    logger.info(f"Step 5.4: Found {len(hot_clusters)} hot clusters")

    # Step 5.5: Parent-Child Novelty Detector
    suspicious_chains = step_5_5_parent_child_novelty(context)
    context.suspicious_chains = suspicious_chains
    logger.info(f"Step 5.5: Found {len(suspicious_chains)} suspicious process chains")

    # Step 5.6: Network Behavior Profiler
    network_profiles = step_5_6_network_profiler(df, context)
    context.network_profiles = network_profiles
    abnormal = sum(1 for p in network_profiles if p.get('is_abnormal', False))
    logger.info(f"Step 5.6: Found {abnormal} abnormal network behaviors")

    # Update statistics
    context.statistics['stage5'] = {
        'rare_values': len(rare_values),
        'high_entropy_strings': len(high_entropy),
        'entities_new_during_attack': new_during_attack,
        'hot_clusters': len(hot_clusters),
        'suspicious_chains': len(suspicious_chains),
        'abnormal_network_behaviors': abnormal,
    }

    logger.info("Stage 5: Anomaly Detection completed")


# =============================================================================
# STEP 5.1: FREQUENCY ANALYZER
# =============================================================================

def step_5_1_frequency_analyzer(df) -> List[RareValue]:
    """
    Find rare values that stand out from baseline.

    Substeps:
    5.1.1: Compute Value Frequencies
    5.1.2: Identify Rare Values
    5.1.3: Cross-Reference with Timing
    """

    rare_values = []

    # Columns of interest
    columns_of_interest = [
        'process_name', 'parent_process_name', 'username', 'source_ip', 'dest_ip',
        'service_name', 'target_filename', 'uri',
    ]

    columns_to_check = [c for c in columns_of_interest if c in df.columns]

    for col in columns_to_check:
        # Substep 5.1.1: Compute Value Frequencies
        value_counts = df[col].value_counts()

        if len(value_counts) == 0:
            continue

        mean_count = value_counts.mean()
        median_count = value_counts.median()
        std_count = value_counts.std()

        # Substep 5.1.2: Identify Rare Values
        # Flag values appearing ≤3 times when median is >50
        threshold = 3
        if median_count > 50:
            for value, count in value_counts.items():
                if count <= threshold:
                    rarity_score = median_count / count if count > 0 else median_count

                    # Substep 5.1.3: Cross-Reference with Timing
                    value_rows = df[df[col] == value]
                    timestamps = value_rows['timestamp_utc'].dropna().tolist()

                    rare_val = RareValue(
                        value=str(value),
                        column=col,
                        count=count,
                        median=median_count,
                        rarity_score=rarity_score,
                        first_seen=min(timestamps) if timestamps else None,
                        last_seen=max(timestamps) if timestamps else None,
                        timestamps=timestamps[:20],  # Limit for size
                    )
                    rare_values.append(rare_val)

    # Sort by rarity score
    rare_values.sort(key=lambda x: x.rarity_score, reverse=True)

    return rare_values


# =============================================================================
# STEP 5.2: ENTROPY CALCULATOR
# =============================================================================

def step_5_2_entropy_calculator(df) -> List[HighEntropyString]:
    """
    Find high-entropy strings (potentially random/obfuscated).

    Substeps:
    5.2.1: Select Target Strings
    5.2.2: Calculate Shannon Entropy
    5.2.3: Flag High-Entropy Strings
    5.2.4: Check Against Known Patterns
    """

    high_entropy = []

    # Substep 5.2.1: Select Target Strings
    target_columns = ['service_name', 'process_name', 'target_filename']
    target_columns = [c for c in target_columns if c in df.columns]

    for col in target_columns:
        for idx, val in df[col].items():
            if pd.isna(val):
                continue

            val_str = str(val)

            # Skip very short strings
            if len(val_str) < 6:
                continue

            # Extract just the filename/name part
            if '\\' in val_str:
                val_str = val_str.split('\\')[-1]
            if '/' in val_str:
                val_str = val_str.split('/')[-1]

            # Remove extension for entropy calculation
            if '.' in val_str:
                name_part = val_str.rsplit('.', 1)[0]
            else:
                name_part = val_str

            if len(name_part) < 4:
                continue

            # Substep 5.2.2: Calculate Shannon Entropy
            entropy = _calculate_entropy(name_part)
            normalized = entropy / math.log2(len(set(name_part))) if len(set(name_part)) > 1 else 0

            # Substep 5.2.3: Flag High-Entropy Strings
            # Threshold: >3.5 for service names (detect random service persistence)
            # >3.0 for short strings, >3.5 for longer strings
            if col == 'service_name':
                threshold = 3.5  # Random service names are strong indicators
            else:
                threshold = 3.0 if len(name_part) < 10 else 3.5

            if entropy >= threshold:
                row = df.iloc[idx] if idx < len(df) else {}

                entry = HighEntropyString(
                    value=val_str,
                    entropy=entropy,
                    normalized_entropy=normalized,
                    source_column=col,
                    source_row=idx,
                    source_timestamp=row.get('timestamp_utc') if isinstance(row, dict) or hasattr(row, 'get') else None,
                )

                # Substep 5.2.4: Check Against Known Patterns
                _check_entropy_false_positives(entry)

                if not entry.is_false_positive:
                    high_entropy.append(entry)

    # Sort by entropy
    high_entropy.sort(key=lambda x: x.entropy, reverse=True)

    return high_entropy


def _calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0

    freq = Counter(s)
    length = len(s)
    entropy = 0.0

    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def _check_entropy_false_positives(entry: HighEntropyString) -> None:
    """Check if high-entropy string is a known false positive."""
    value = entry.value.lower()

    # GUIDs
    if len(value) == 36 and value.count('-') == 4:
        entry.is_false_positive = True
        entry.fp_reason = 'GUID format'
        return

    # Base64 that's part of normal encoding
    if value.endswith('==') or value.endswith('='):
        # Already decoded in Stage 2, so this might be legitimate
        pass

    # Known legitimate high-entropy names
    legitimate_patterns = [
        'microsoftedgeupdate',
        'mozillamaintenance',
        'googleupdate',
    ]

    for pattern in legitimate_patterns:
        if pattern in value:
            entry.is_false_positive = True
            entry.fp_reason = f'Known legitimate pattern: {pattern}'
            return


# =============================================================================
# STEP 5.3: FIRST-SEEN DETECTOR
# =============================================================================

def step_5_3_first_seen_detector(df, context) -> Tuple[Dict, Dict]:
    """
    Find entities that appeared for the first time during attack window.

    Substeps:
    5.3.1: Build Entity First-Seen Timeline
    5.3.2: Identify Attack Window
    5.3.3: Flag New-During-Attack Entities
    """

    first_seen = {}
    attack_window = {'start': None, 'end': None}

    # Substep 5.3.1: Build Entity First-Seen Timeline
    entity_columns = {
        'process_name': 'process',
        'username': 'user',
        'source_ip': 'ip',
        'dest_ip': 'ip',
    }

    for col, entity_type in entity_columns.items():
        if col not in df.columns:
            continue

        grouped = df.groupby(col)['timestamp_utc'].min()

        for entity, first_ts in grouped.items():
            if pd.isna(entity) or pd.isna(first_ts):
                continue

            key = f"{entity_type}:{entity}"
            if key not in first_seen or first_ts < first_seen[key]['first_seen']:
                first_seen[key] = {
                    'entity': str(entity),
                    'type': entity_type,
                    'first_seen': first_ts,
                    'in_attack_window': False,
                }

    # Substep 5.3.2: Identify Attack Window
    # Use pattern matches and suspicious edges to define attack window
    attack_timestamps = []

    # From pattern matches
    for match in context.pattern_matches:
        ts = match.get('timestamp')
        if ts is not None:
            attack_timestamps.append(ts)

    # From suspicious edges
    for edge in context.classified_edges:
        if edge['classification'] in ['SUSPICIOUS', 'HIGHLY_SUSPICIOUS']:
            ts = edge.get('timestamp')
            if ts is not None:
                attack_timestamps.append(ts)

    if attack_timestamps:
        attack_window['start'] = min(attack_timestamps)
        attack_window['end'] = max(attack_timestamps)

        # Expand window slightly (30 minutes before first indicator)
        attack_window['start'] = attack_window['start'] - timedelta(minutes=30)

    # Substep 5.3.3: Flag New-During-Attack Entities
    if attack_window['start'] and attack_window['end']:
        for key, info in first_seen.items():
            fs = info['first_seen']
            if fs and attack_window['start'] <= fs <= attack_window['end']:
                info['in_attack_window'] = True

    return first_seen, attack_window


# =============================================================================
# STEP 5.4: TEMPORAL CLUSTER DETECTOR
# =============================================================================

def step_5_4_temporal_cluster_detector(df, context) -> List[HotCluster]:
    """
    Find temporal clusters of suspicious activity.

    Substeps:
    5.4.1: Create Sliding Windows
    5.4.2: Count Indicators Per Window
    5.4.3: Identify Hot Clusters

    Optimized: Only examine windows around indicator events, not all time.
    """

    hot_clusters = []

    if 'timestamp_utc' not in df.columns:
        return hot_clusters

    # Sort by timestamp
    df_sorted = df.dropna(subset=['timestamp_utc']).sort_values('timestamp_utc')

    if len(df_sorted) == 0:
        return hot_clusters

    # Window size for clustering
    window_size = timedelta(seconds=60)

    # Build indicator set for quick lookup
    indicator_rows = set()
    indicator_types_by_row = {}
    indicator_timestamps = []

    # Add pattern match rows
    for match in context.pattern_matches:
        row_idx = match.get('row_index')
        if row_idx is not None and row_idx in df_sorted.index:
            indicator_rows.add(row_idx)
            if row_idx not in indicator_types_by_row:
                indicator_types_by_row[row_idx] = set()
            indicator_types_by_row[row_idx].add(f"pattern:{match['pattern_name']}")
            ts = df_sorted.loc[row_idx, 'timestamp_utc'] if row_idx in df_sorted.index else None
            if ts is not None:
                indicator_timestamps.append(ts)

    # Add high entropy rows (limit to top 500 by entropy to avoid slowdown)
    sorted_entropy = sorted(context.high_entropy_strings, key=lambda x: x.entropy, reverse=True)[:500]
    for he in sorted_entropy:
        row_idx = he.source_row
        if row_idx in df_sorted.index:
            indicator_rows.add(row_idx)
            if row_idx not in indicator_types_by_row:
                indicator_types_by_row[row_idx] = set()
            indicator_types_by_row[row_idx].add(f"entropy:{he.source_column}")
            ts = df_sorted.loc[row_idx, 'timestamp_utc'] if row_idx in df_sorted.index else None
            if ts is not None:
                indicator_timestamps.append(ts)

    if not indicator_timestamps:
        return hot_clusters

    # Sort unique timestamps and deduplicate to find cluster centers
    indicator_timestamps = sorted(set(indicator_timestamps))

    # Group timestamps that are close together (within 60s) into cluster candidates
    cluster_centers = []
    current_cluster_start = indicator_timestamps[0]
    current_cluster_count = 1

    for ts in indicator_timestamps[1:]:
        if (ts - current_cluster_start).total_seconds() <= 60:
            current_cluster_count += 1
        else:
            if current_cluster_count >= 3:  # Only clusters with 3+ indicators
                cluster_centers.append(current_cluster_start)
            current_cluster_start = ts
            current_cluster_count = 1

    # Don't forget last cluster
    if current_cluster_count >= 3:
        cluster_centers.append(current_cluster_start)

    # Limit to top 50 cluster centers to avoid excessive processing
    cluster_centers = cluster_centers[:50]

    # For each cluster center, examine the window
    window_results = []
    for center_ts in cluster_centers:
        window_start = center_ts - timedelta(seconds=30)
        window_end = center_ts + timedelta(seconds=90)

        # Get events in this window
        window_events = df_sorted[
            (df_sorted['timestamp_utc'] >= window_start) &
            (df_sorted['timestamp_utc'] < window_end)
        ]

        # Count indicators in window
        indicators_in_window = []
        indicator_types = set()

        for idx in window_events.index:
            if idx in indicator_rows:
                indicators_in_window.append(idx)
                indicator_types.update(indicator_types_by_row.get(idx, set()))

        if len(indicators_in_window) >= 3:
            window_results.append({
                'start': window_start,
                'end': window_end,
                'indicator_count': len(indicators_in_window),
                'indicator_types': indicator_types,
                'event_count': len(window_events),
                'indicator_indices': indicators_in_window,
            })

    # Merge overlapping hot windows
    if window_results:
        # Sort by start time
        window_results.sort(key=lambda x: x['start'])

        merged = [window_results[0]]
        for window in window_results[1:]:
            last = merged[-1]
            if window['start'] <= last['end']:
                # Merge
                last['end'] = max(last['end'], window['end'])
                last['indicator_count'] = max(last['indicator_count'], window['indicator_count'])
                last['indicator_types'].update(window['indicator_types'])
                last['event_count'] = max(last['event_count'], window['event_count'])
                last['indicator_indices'] = list(set(last['indicator_indices'] + window['indicator_indices']))
            else:
                merged.append(window)

        # Convert to HotCluster objects
        for w in merged:
            cluster = HotCluster(
                start_time=w['start'],
                end_time=w['end'],
                duration_seconds=(w['end'] - w['start']).total_seconds(),
                indicator_count=w['indicator_count'],
                indicator_types=w['indicator_types'],
                key_events=[],  # Would need to fill with actual event data
                events_in_window=w['event_count'],
            )
            hot_clusters.append(cluster)

    # Sort by indicator count
    hot_clusters.sort(key=lambda x: x.indicator_count, reverse=True)

    return hot_clusters


# =============================================================================
# STEP 5.5: PARENT-CHILD NOVELTY DETECTOR
# =============================================================================

def step_5_5_parent_child_novelty(context) -> List[Dict]:
    """
    Analyze suspicious process chains for evasion and severity.

    Substeps:
    5.5.1: Extract Suspicious Chains
    5.5.2: Score Chain Severity
    5.5.3: Check for Evasion Patterns
    """

    suspicious_chains = []

    # Substep 5.5.1: Extract Suspicious Chains
    suspicious_edges = [
        e for e in context.classified_edges
        if e['classification'] in ['SUSPICIOUS', 'HIGHLY_SUSPICIOUS']
    ]

    for edge in suspicious_edges:
        chain = {
            'parent_process': edge['parent_process'],
            'child_process': edge['child_process'],
            'parent_command': edge.get('parent_command', ''),
            'child_command': edge.get('child_command', ''),
            'classification': edge['classification'],
            'timestamp': edge.get('timestamp'),
            'source_system': edge.get('source_system'),
            'severity_score': 0,
            'evasion_indicators': [],
        }

        # Substep 5.5.2: Score Chain Severity
        score = 0

        if edge['classification'] == 'HIGHLY_SUSPICIOUS':
            score += 10

        # Check if chain involves decoded content
        cmd = chain['child_command'].lower()
        if any(term in cmd for term in ['invoke-', 'downloadstring', 'iex', '-enc']):
            score += 5

        # Check for network activity in command
        if any(term in cmd for term in ['http:', 'https:', 'ftp:', '//']):
            score += 3

        # Check for known attack tools
        if any(tool in cmd for tool in ['mimikatz', 'procdump', 'psexec', 'wmiexec', 'smbexec']):
            score += 10

        chain['severity_score'] = score

        # Substep 5.5.3: Check for Evasion Patterns
        # Process name mimicking system process from wrong path
        child_proc = chain['child_process'].lower()
        child_cmd = chain['child_command'].lower()

        system_procs = ['svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe']
        for sys_proc in system_procs:
            if sys_proc in child_proc:
                # Check if it's from expected path
                if 'system32' not in child_cmd and 'syswow64' not in child_cmd:
                    chain['evasion_indicators'].append(f'Process mimicking {sys_proc} from non-standard path')

        # Very short process name (potential obfuscation)
        if len(child_proc) <= 4 and child_proc not in ['cmd', 'sc', 'at']:
            chain['evasion_indicators'].append('Very short process name')

        suspicious_chains.append(chain)

    # Sort by severity
    suspicious_chains.sort(key=lambda x: x['severity_score'], reverse=True)

    return suspicious_chains


# =============================================================================
# STEP 5.6: NETWORK BEHAVIOR PROFILER
# =============================================================================

def step_5_6_network_profiler(df, context) -> List[Dict]:
    """
    Profile network behavior and detect anomalies.

    Substeps:
    5.6.1: Build Per-Process Network Profile
    5.6.2: Flag Abnormal Processes
    5.6.3: Detect Beaconing
    """

    profiles = []

    # Get network connection events (Sysmon EID 3)
    network_events = df[df['event_id'] == 3].copy() if 'event_id' in df.columns else pd.DataFrame()

    if len(network_events) == 0:
        logger.debug("No network events (Sysmon EID 3) found")
        return profiles

    # Substep 5.6.1: Build Per-Process Network Profile
    process_col = 'process_name' if 'process_name' in network_events.columns else None
    if process_col is None:
        return profiles

    grouped = network_events.groupby(process_col)

    for process, group in grouped:
        if pd.isna(process):
            continue

        dest_ips = set(group['dest_ip'].dropna().unique()) if 'dest_ip' in group.columns else set()
        dest_ports = set(group['dest_port'].dropna().unique()) if 'dest_port' in group.columns else set()
        timestamps = group['timestamp_utc'].dropna().sort_values().tolist()

        profile = {
            'process_name': str(process),
            'unique_dest_ips': list(dest_ips)[:20],
            'unique_dest_ports': list(dest_ports)[:20],
            'connection_count': len(group),
            'first_connection': min(timestamps) if timestamps else None,
            'last_connection': max(timestamps) if timestamps else None,
            'is_abnormal': False,
            'abnormal_reasons': [],
            'beaconing_detected': False,
            'beaconing_interval': None,
        }

        # Substep 5.6.2: Flag Abnormal Processes
        process_lower = str(process).lower()
        process_class = context.process_classifications.get(process_lower, 'UNKNOWN')

        # Check for EXTERNAL connections
        external_ips = [ip for ip in dest_ips if context.ip_classifications.get(str(ip)) == 'EXTERNAL']

        if external_ips:
            # System processes shouldn't talk externally
            if process_class == 'SYSTEM_PROCESS' or process_lower in ['lsass.exe', 'csrss.exe']:
                profile['is_abnormal'] = True
                profile['abnormal_reasons'].append(f'System process with external connections to: {external_ips[:5]}')

            # Unknown processes with external connections
            if process_class == 'UNKNOWN_PROCESS':
                profile['is_abnormal'] = True
                profile['abnormal_reasons'].append(f'Unknown process with external connections')

        # Web servers connecting to internal systems on non-web ports
        if process_class == 'WEB_SERVER':
            non_web_ports = [p for p in dest_ports if p not in [80, 443, 8080, 8443]]
            internal_ips = [ip for ip in dest_ips if context.ip_classifications.get(str(ip)) == 'INTERNAL']
            if non_web_ports and internal_ips:
                profile['is_abnormal'] = True
                profile['abnormal_reasons'].append(f'Web server connecting internally on non-web ports: {non_web_ports}')

        # Substep 5.6.3: Detect Beaconing
        if len(timestamps) >= 5:
            intervals = []
            for i in range(1, len(timestamps)):
                try:
                    delta = (timestamps[i] - timestamps[i-1]).total_seconds()
                    if delta > 0:
                        intervals.append(delta)
                except:
                    pass

            if intervals:
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals)

                # Coefficient of variation < 0.3 suggests regular intervals
                if mean_interval > 0:
                    cv = std_interval / mean_interval
                    if cv < 0.3 and mean_interval < 300:  # Regular intervals under 5 minutes
                        profile['beaconing_detected'] = True
                        profile['beaconing_interval'] = mean_interval
                        profile['is_abnormal'] = True
                        profile['abnormal_reasons'].append(f'Potential beaconing with ~{mean_interval:.1f}s interval')

        profiles.append(profile)

    # Sort by abnormal status
    profiles.sort(key=lambda x: (not x['is_abnormal'], -x['connection_count']))

    return profiles
