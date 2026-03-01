"""
STAGE 3: RELATIONSHIP BUILDING

Goal: Connect isolated events into trees, sessions, cross-system chains.

Steps:
- 3.1: Process Tree Builder (5 substeps)
- 3.2: Parent-Child Classifier (3 substeps)
- 3.3: Session Grouper (3 substeps)
- 3.4: Cross-System Correlator (3 substeps)
- 3.5: File-to-Process Linker (4 substeps)

Total: 19 substeps
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
import yaml

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class ProcessNode:
    """Represents a process in the tree."""
    event_index: int
    timestamp: Any
    pid: int
    ppid: int
    process_name: str
    parent_process_name: Optional[str]
    command_line: Optional[str]
    parent_command_line: Optional[str]
    username: Optional[str]
    source_system: str
    event_id: int
    depth: int = 0
    children: List['ProcessNode'] = field(default_factory=list)
    parent_found: bool = False


@dataclass
class ProcessTree:
    """Represents a complete process tree."""
    root: ProcessNode
    all_nodes: List[ProcessNode]
    edges: List[Tuple[int, int]]  # (parent_idx, child_idx)
    max_depth: int
    node_count: int
    unique_processes: Set[str]
    unique_users: Set[str]
    time_span_seconds: float
    has_decoded_content: bool = False
    has_network_connections: bool = False
    suspicion_score: float = 0.0


@dataclass
class Session:
    """Represents a grouped session of activity."""
    session_id: str
    source_entity: str
    target_entity: Optional[str]
    start_time: Any
    end_time: Any
    duration_seconds: float
    event_count: int
    unique_event_ids: Set[int]
    unique_processes: Set[str]
    unique_commands: Set[str]
    unique_ips: Set[str]
    intent_tags: List[str] = field(default_factory=list)


@dataclass
class CrossSystemCorrelation:
    """Represents a correlation between events on different systems."""
    source_system: str
    source_event_index: int
    source_timestamp: Any
    target_system: str
    correlation_type: str  # e.g., 'network_connection', 'lateral_movement', 'auth'
    target_event_index: Optional[int] = None
    target_timestamp: Optional[Any] = None
    time_delta_seconds: Optional[float] = None
    evidence: Dict = field(default_factory=dict)


# Expected parent-child relationships (loaded from baseline)
EXPECTED_PARENTS = {
    'chrome.exe': ['explorer.exe', 'chrome.exe'],
    'firefox.exe': ['explorer.exe', 'firefox.exe'],
    'notepad.exe': ['explorer.exe', 'cmd.exe', 'powershell.exe'],
    'calc.exe': ['explorer.exe'],
    'svchost.exe': ['services.exe'],
    'csrss.exe': ['smss.exe'],
    'wininit.exe': ['smss.exe'],
    'winlogon.exe': ['smss.exe'],
    'lsass.exe': ['wininit.exe'],
    'services.exe': ['wininit.exe'],
    'explorer.exe': ['userinit.exe', 'winlogon.exe'],
}

# Parent processes that should rarely spawn children (suspicious if they do)
RARELY_SPAWN_CHILDREN = {
    'w3wp.exe',  # IIS worker - webshell indicator
    'httpd.exe',
    'nginx.exe',
    'sqlservr.exe',
    'oracle.exe',
    'mysqld.exe',
    'lsass.exe',  # unless it's csrss
}

# Always suspicious parent-child pairs
ALWAYS_SUSPICIOUS = [
    ('w3wp.exe', 'cmd.exe'),
    ('w3wp.exe', 'powershell.exe'),
    ('w3wp.exe', 'whoami.exe'),
    ('w3wp.exe', 'net.exe'),
    ('w3wp.exe', 'net1.exe'),
    ('sqlservr.exe', 'cmd.exe'),
    ('sqlservr.exe', 'powershell.exe'),
    ('excel.exe', 'cmd.exe'),
    ('excel.exe', 'powershell.exe'),
    ('winword.exe', 'cmd.exe'),
    ('winword.exe', 'powershell.exe'),
    ('outlook.exe', 'cmd.exe'),
    ('outlook.exe', 'powershell.exe'),
]

# Intent classification patterns
RECON_COMMANDS = ['whoami', 'ipconfig', 'hostname', 'systeminfo', 'net user', 'net group', 'net localgroup', 'net view', 'net share', 'tasklist', 'netstat', 'qprocess', 'qwinsta', 'query user']
CREDENTIAL_INDICATORS = ['mimikatz', 'procdump', 'pd.exe', 'sekurlsa', 'lsass', 'sam', 'ntds', 'credential', 'password', 'hash', 'kerberos', 'ticket']
LATERAL_INDICATORS = ['psexec', 'wmic', 'invoke-wmiexec', 'invoke-smbexec', 'invoke-psexec', 'enter-pssession', 'invoke-command', 'winrm']
DOWNLOAD_INDICATORS = ['downloadstring', 'downloadfile', 'wget', 'curl', 'bitsadmin', 'certutil', 'invoke-webrequest']


def run(context) -> None:
    """Execute Stage 3: Relationship Building."""
    logger.info("Stage 3: Relationship Building starting")

    df = context.unified_df

    # Step 3.1: Process Tree Builder
    trees, edges = step_3_1_process_tree_builder(df)
    context.process_trees = trees
    logger.info(f"Step 3.1: Built {len(trees)} process trees")

    # Step 3.2: Parent-Child Classifier
    classified_edges = step_3_2_parent_child_classifier(edges, df)
    context.classified_edges = classified_edges
    suspicious_count = sum(1 for e in classified_edges if e['classification'] in ['SUSPICIOUS', 'HIGHLY_SUSPICIOUS'])
    logger.info(f"Step 3.2: Classified {len(classified_edges)} edges ({suspicious_count} suspicious)")

    # Rank trees by suspicion
    for tree in trees:
        tree.suspicion_score = _compute_tree_suspicion_score(tree, classified_edges)
    trees.sort(key=lambda t: t.suspicion_score, reverse=True)

    # Step 3.3: Session Grouper
    sessions = step_3_3_session_grouper(df)
    context.sessions = sessions
    logger.info(f"Step 3.3: Grouped {len(sessions)} sessions")

    # Step 3.4: Cross-System Correlator
    correlations, attack_path = step_3_4_cross_system_correlator(df)
    context.cross_system_correlations = correlations
    context.attack_path = attack_path
    logger.info(f"Step 3.4: Found {len(correlations)} cross-system correlations")

    # Step 3.5: File-to-Process Linker
    file_links = step_3_5_file_process_linker(df)
    context.file_process_links = file_links
    logger.info(f"Step 3.5: Linked {len(file_links)} file operations")

    # Update statistics
    context.statistics['stage3'] = {
        'process_trees': len(trees),
        'classified_edges': len(classified_edges),
        'suspicious_edges': suspicious_count,
        'sessions': len(sessions),
        'cross_system_correlations': len(correlations),
        'attack_path_steps': len(attack_path),
        'file_process_links': len(file_links),
    }

    logger.info("Stage 3: Relationship Building completed")


# =============================================================================
# STEP 3.1: PROCESS TREE BUILDER
# =============================================================================

def step_3_1_process_tree_builder(df) -> Tuple[List[ProcessTree], List[Dict]]:
    """
    Build process trees from Sysmon EID 1 and Windows EID 4688.

    Substeps:
    3.1.1: Collect Process Creation Events
    3.1.2: Deduplicate Sysmon + Windows
    3.1.3: Build Parent-Child Edges
    3.1.4: Assemble Trees
    3.1.5: Compute Tree Metadata
    """

    # Substep 3.1.1: Collect Process Creation Events
    # Sysmon EID 1 = Process Create, Windows EID 4688 = Process Created
    process_events = df[df['event_id'].isin([1, 4688])].copy()
    logger.debug(f"Substep 3.1.1: Found {len(process_events)} process creation events")

    if len(process_events) == 0:
        return [], []

    # Handle column name variations (ARGUS parser uses process_id/parent_process_id)
    if 'pid' not in process_events.columns and 'process_id' in process_events.columns:
        process_events['pid'] = process_events['process_id']
    if 'ppid' not in process_events.columns and 'parent_process_id' in process_events.columns:
        process_events['ppid'] = process_events['parent_process_id']

    # Ensure required columns exist
    for col in ['pid', 'ppid', 'process_name', 'parent_process_name', 'command_line', 'username', 'source_system']:
        if col not in process_events.columns:
            process_events[col] = None

    # Substep 3.1.2: Deduplicate Sysmon + Windows
    # Group by PID + approximate timestamp and keep Sysmon (more detailed)
    process_events = process_events.sort_values('event_id')  # Sysmon EID 1 comes before 4688
    process_events['ts_rounded'] = pd.to_datetime(process_events['timestamp_utc']).dt.round('1s')

    # Keep first occurrence (Sysmon if both exist)
    deduped = process_events.drop_duplicates(
        subset=['source_system', 'pid', 'ts_rounded'],
        keep='first'
    )
    logger.debug(f"Substep 3.1.2: Deduplicated to {len(deduped)} events")

    # Create process nodes
    nodes = []
    for idx, row in deduped.iterrows():
        # Extract just the exe name from full paths
        proc_name = str(row.get('process_name', '')) if pd.notna(row.get('process_name')) else ''
        parent_name = str(row.get('parent_process_name', '')) if pd.notna(row.get('parent_process_name')) else ''

        # Handle full paths (C:\Windows\System32\cmd.exe -> cmd.exe)
        if '\\' in proc_name:
            proc_name = proc_name.split('\\')[-1]
        if '\\' in parent_name:
            parent_name = parent_name.split('\\')[-1]

        node = ProcessNode(
            event_index=idx,
            timestamp=row.get('timestamp_utc'),
            pid=int(row.get('pid', 0)) if pd.notna(row.get('pid')) else 0,
            ppid=int(row.get('ppid', 0)) if pd.notna(row.get('ppid')) else 0,
            process_name=proc_name.lower(),
            parent_process_name=parent_name.lower(),
            command_line=str(row.get('command_line', '')) if pd.notna(row.get('command_line')) else '',
            parent_command_line=str(row.get('parent_command_line', '')) if pd.notna(row.get('parent_command_line')) else '',
            username=str(row.get('username', '')) if pd.notna(row.get('username')) else '',
            source_system=str(row.get('source_system', '')) if pd.notna(row.get('source_system')) else '',
            event_id=int(row.get('event_id', 0)),
        )
        nodes.append(node)

    # Substep 3.1.3: Build Parent-Child Edges
    edges = []
    node_by_pid_system = {}

    # Index nodes by (system, pid)
    for node in nodes:
        key = (node.source_system, node.pid)
        if key not in node_by_pid_system:
            node_by_pid_system[key] = []
        node_by_pid_system[key].append(node)

    # Find parent for each node
    for child in nodes:
        parent_key = (child.source_system, child.ppid)

        if parent_key in node_by_pid_system:
            # Find the most recent parent that precedes this child
            potential_parents = [
                p for p in node_by_pid_system[parent_key]
                if p.timestamp is not None and child.timestamp is not None
                and p.timestamp < child.timestamp
            ]

            if potential_parents:
                parent = max(potential_parents, key=lambda p: p.timestamp)
                child.parent_found = True
                edges.append({
                    'parent_index': parent.event_index,
                    'child_index': child.event_index,
                    'parent_node': parent,
                    'child_node': child,
                })

    logger.debug(f"Substep 3.1.3: Built {len(edges)} parent-child edges")

    # Substep 3.1.4: Assemble Trees
    # Find roots (no parent found)
    roots = [n for n in nodes if not n.parent_found]

    trees = []
    for root in roots:
        tree_nodes = _build_tree_recursive(root, edges, 0)
        all_tree_nodes = _flatten_tree(root)

        if len(all_tree_nodes) > 0:
            # Substep 3.1.5: Compute Tree Metadata
            timestamps = [n.timestamp for n in all_tree_nodes if n.timestamp is not None]
            time_span = 0.0
            if len(timestamps) >= 2:
                time_span = (max(timestamps) - min(timestamps)).total_seconds()

            tree = ProcessTree(
                root=root,
                all_nodes=all_tree_nodes,
                edges=[(e['parent_index'], e['child_index']) for e in edges
                       if e['parent_node'] in all_tree_nodes],
                max_depth=max(n.depth for n in all_tree_nodes),
                node_count=len(all_tree_nodes),
                unique_processes=set(n.process_name for n in all_tree_nodes if n.process_name),
                unique_users=set(n.username for n in all_tree_nodes if n.username),
                time_span_seconds=time_span,
            )
            trees.append(tree)

    logger.debug(f"Substep 3.1.4-5: Assembled {len(trees)} trees")

    return trees, edges


def _build_tree_recursive(node: ProcessNode, all_edges: List[Dict], depth: int) -> None:
    """Recursively build tree by attaching children."""
    node.depth = depth

    # Find children of this node
    children_edges = [e for e in all_edges if e['parent_index'] == node.event_index]

    for edge in children_edges:
        child = edge['child_node']
        node.children.append(child)
        _build_tree_recursive(child, all_edges, depth + 1)


def _flatten_tree(root: ProcessNode) -> List[ProcessNode]:
    """Flatten tree into list of all nodes."""
    result = [root]
    for child in root.children:
        result.extend(_flatten_tree(child))
    return result


# =============================================================================
# STEP 3.2: PARENT-CHILD CLASSIFIER
# =============================================================================

def step_3_2_parent_child_classifier(edges: List[Dict], df) -> List[Dict]:
    """
    Classify each parent-child edge.

    Substeps:
    3.2.1: Load Baseline (using built-in for now)
    3.2.2: Classify Each Edge
    3.2.3: Rank Trees by Suspicion (done after return)
    """

    classified = []

    for edge in edges:
        parent = edge['parent_node']
        child = edge['child_node']

        parent_name = parent.process_name.lower()
        child_name = child.process_name.lower()

        # Substep 3.2.2: Classify Each Edge
        classification = 'UNUSUAL'  # Default

        # Check always suspicious pairs
        for sus_parent, sus_child in ALWAYS_SUSPICIOUS:
            if parent_name == sus_parent.lower() and child_name == sus_child.lower():
                classification = 'HIGHLY_SUSPICIOUS'
                break

        if classification != 'HIGHLY_SUSPICIOUS':
            # Check if parent rarely spawns children
            if parent_name in [p.lower() for p in RARELY_SPAWN_CHILDREN]:
                classification = 'SUSPICIOUS'

            # Check expected relationships
            elif child_name in EXPECTED_PARENTS:
                if parent_name in [p.lower() for p in EXPECTED_PARENTS[child_name]]:
                    classification = 'EXPECTED'

        classified.append({
            'parent_index': edge['parent_index'],
            'child_index': edge['child_index'],
            'parent_process': parent_name,
            'child_process': child_name,
            'parent_command': parent.command_line[:200] if parent.command_line else '',
            'child_command': child.command_line[:200] if child.command_line else '',
            'classification': classification,
            'timestamp': child.timestamp,
            'source_system': child.source_system,
        })

    return classified


def _compute_tree_suspicion_score(tree: ProcessTree, classified_edges: List[Dict]) -> float:
    """Compute suspicion score for a tree."""
    score = 0.0

    tree_event_indices = set(n.event_index for n in tree.all_nodes)

    for edge in classified_edges:
        if edge['child_index'] in tree_event_indices:
            if edge['classification'] == 'HIGHLY_SUSPICIOUS':
                score += 10.0 * (tree.max_depth + 1)
            elif edge['classification'] == 'SUSPICIOUS':
                score += 5.0 * (tree.max_depth + 1)

    return score


# =============================================================================
# STEP 3.3: SESSION GROUPER
# =============================================================================

def step_3_3_session_grouper(df) -> List[Session]:
    """
    Group events into sessions.

    Substeps:
    3.3.1: Define Session Boundaries
    3.3.2: Compute Session Metadata
    3.3.3: Classify Session Intent
    """

    sessions = []

    if len(df) == 0 or 'timestamp_utc' not in df.columns:
        return sessions

    # Substep 3.3.1: Define Session Boundaries using vectorized operations
    # Create a copy with required columns
    df_work = df[['timestamp_utc', 'source_system', 'username', 'event_id',
                   'process_name', 'command_line', 'source_ip', 'dest_ip']].copy() \
        if all(c in df.columns for c in ['timestamp_utc', 'source_system', 'username']) \
        else df.copy()

    df_work = df_work.sort_values('timestamp_utc').reset_index(drop=True)

    # Create session key (system + user)
    df_work['session_key'] = df_work['source_system'].fillna('unknown').astype(str) + '_' + \
                             df_work['username'].fillna('unknown').astype(str)

    # Calculate time gaps
    df_work['time_diff'] = df_work.groupby('session_key')['timestamp_utc'].diff()

    # Mark session boundaries (gap > 30 minutes or key change)
    session_gap = pd.Timedelta(minutes=30)
    df_work['new_session'] = (
        (df_work['time_diff'] > session_gap) |
        (df_work['session_key'] != df_work['session_key'].shift(1))
    )

    # Assign session IDs
    df_work['session_id'] = df_work['new_session'].cumsum()

    # Substep 3.3.2: Compute Session Metadata (vectorized)
    session_groups = df_work.groupby('session_id')

    # Limit to first 1000 sessions for performance
    session_ids = df_work['session_id'].unique()[:1000]

    for sess_id in session_ids:
        group = df_work[df_work['session_id'] == sess_id]
        if len(group) == 0:
            continue

        timestamps = group['timestamp_utc'].dropna()
        if len(timestamps) == 0:
            continue

        start = timestamps.min()
        end = timestamps.max()
        duration = (end - start).total_seconds() if start != end else 0

        session = Session(
            session_id=f"session_{sess_id}",
            source_entity=group['session_key'].iloc[0] if len(group) > 0 else 'unknown',
            target_entity=None,
            start_time=start,
            end_time=end,
            duration_seconds=duration,
            event_count=len(group),
            unique_event_ids=set(group['event_id'].dropna().unique()) if 'event_id' in group else set(),
            unique_processes=set(group['process_name'].dropna().unique()) if 'process_name' in group else set(),
            unique_commands=set(group['command_line'].dropna().head(100).unique()) if 'command_line' in group else set(),  # Limit for memory
            unique_ips=set(),
        )

        # Collect IPs
        for col in ['source_ip', 'dest_ip']:
            if col in group.columns:
                session.unique_ips.update(group[col].dropna().unique())

        # Substep 3.3.3: Classify Session Intent
        _classify_session_intent(session)

        sessions.append(session)

    return sessions


def _create_session(events: List, session_num: int) -> Optional[Session]:
    """Create a Session from a list of events."""
    if not events:
        return None

    events_df = pd.DataFrame(events) if not isinstance(events[0], dict) else pd.DataFrame([dict(e) for e in events])

    timestamps = pd.to_datetime(events_df.get('timestamp_utc', pd.Series()), errors='coerce').dropna()

    if len(timestamps) == 0:
        return None

    start = timestamps.min()
    end = timestamps.max()
    duration = (end - start).total_seconds() if start != end else 0

    # Get unique values
    unique_event_ids = set(events_df.get('event_id', pd.Series()).dropna().astype(int).unique())
    unique_processes = set(events_df.get('process_name', pd.Series()).dropna().unique())
    unique_commands = set(events_df.get('command_line', pd.Series()).dropna().unique())
    unique_ips = set()
    for col in ['source_ip', 'dest_ip']:
        if col in events_df.columns:
            unique_ips.update(events_df[col].dropna().unique())

    source_entity = f"{events_df.iloc[0].get('source_system', 'unknown')}_{events_df.iloc[0].get('username', 'unknown')}"

    session = Session(
        session_id=f"session_{session_num}",
        source_entity=source_entity,
        target_entity=None,
        start_time=start,
        end_time=end,
        duration_seconds=duration,
        event_count=len(events_df),
        unique_event_ids=unique_event_ids,
        unique_processes=unique_processes,
        unique_commands=unique_commands,
        unique_ips=unique_ips,
    )

    # Substep 3.3.3: Classify Session Intent
    _classify_session_intent(session)

    return session


def _classify_session_intent(session: Session) -> None:
    """Classify the intent of a session based on content."""
    commands_str = ' '.join(session.unique_commands).lower()
    processes_str = ' '.join(session.unique_processes).lower()

    # Check for reconnaissance
    if any(cmd in commands_str for cmd in RECON_COMMANDS):
        session.intent_tags.append('RECONNAISSANCE')

    # Check for credential access
    if any(ind in commands_str or ind in processes_str for ind in CREDENTIAL_INDICATORS):
        session.intent_tags.append('CREDENTIAL_ACCESS')

    # Check for lateral movement
    if any(ind in commands_str for ind in LATERAL_INDICATORS):
        session.intent_tags.append('LATERAL_MOVEMENT')

    # Check for downloads/staging
    if any(ind in commands_str for ind in DOWNLOAD_INDICATORS):
        session.intent_tags.append('TOOL_STAGING')

    if not session.intent_tags:
        session.intent_tags.append('UNKNOWN')


# =============================================================================
# STEP 3.4: CROSS-SYSTEM CORRELATOR
# =============================================================================

def step_3_4_cross_system_correlator(df) -> Tuple[List[CrossSystemCorrelation], List[Dict]]:
    """
    Find correlations between events on different systems.

    Substeps:
    3.4.1: Find Cross-System References
    3.4.2: Find Matching Target Events
    3.4.3: Build Attack Path
    """

    correlations = []
    attack_path = []

    # Get unique systems
    systems = df['source_system'].dropna().unique()
    if len(systems) < 2:
        logger.debug("Only one system found, skipping cross-system correlation")
        return correlations, attack_path

    # Build IP to system mapping
    system_ips = {}
    for system in systems:
        system_df = df[df['source_system'] == system]
        ips = set()
        for col in ['source_ip', 'dest_ip']:
            if col in system_df.columns:
                ips.update(system_df[col].dropna().unique())
        system_ips[system] = ips

    # Substep 3.4.1: Find Cross-System References
    for idx, row in df.iterrows():
        source_system = row.get('source_system')
        if pd.isna(source_system):
            continue

        # Check for references to other systems
        for target_system in systems:
            if target_system == source_system:
                continue

            target_ips = system_ips.get(target_system, set())

            # Check if this event references the target system
            referenced = False
            ref_type = None

            # Check dest_ip
            dest_ip = row.get('dest_ip')
            if pd.notna(dest_ip) and dest_ip in target_ips:
                referenced = True
                ref_type = 'network_connection'

            # Check command line for IPs/hostnames
            cmd = str(row.get('command_line', ''))
            if not referenced and target_system.lower() in cmd.lower():
                referenced = True
                ref_type = 'command_reference'

            if referenced:
                corr = CrossSystemCorrelation(
                    source_system=source_system,
                    source_event_index=idx,
                    source_timestamp=row.get('timestamp_utc'),
                    target_system=target_system,
                    correlation_type=ref_type,
                    evidence={'row': dict(row)},
                )
                correlations.append(corr)

    # Substep 3.4.2: Find Matching Target Events
    for corr in correlations:
        if corr.source_timestamp is None:
            continue

        # Look for events on target system within ±5 seconds
        target_df = df[df['source_system'] == corr.target_system]
        window_start = corr.source_timestamp - timedelta(seconds=5)
        window_end = corr.source_timestamp + timedelta(seconds=5)

        matching = target_df[
            (target_df['timestamp_utc'] >= window_start) &
            (target_df['timestamp_utc'] <= window_end)
        ]

        if len(matching) > 0:
            # Take the closest event
            closest_idx = (matching['timestamp_utc'] - corr.source_timestamp).abs().idxmin()
            closest = matching.loc[closest_idx]

            corr.target_event_index = closest_idx
            corr.target_timestamp = closest.get('timestamp_utc')
            if corr.target_timestamp and corr.source_timestamp:
                corr.time_delta_seconds = (corr.target_timestamp - corr.source_timestamp).total_seconds()

    # Substep 3.4.3: Build Attack Path
    # Sort correlations by time and chain them
    sorted_corrs = sorted(
        [c for c in correlations if c.source_timestamp is not None],
        key=lambda c: c.source_timestamp
    )

    step_num = 1
    for corr in sorted_corrs:
        attack_path.append({
            'step': step_num,
            'source_system': corr.source_system,
            'target_system': corr.target_system,
            'correlation_type': corr.correlation_type,
            'timestamp': corr.source_timestamp,
            'time_delta': corr.time_delta_seconds,
            'evidence': corr.evidence,
        })
        step_num += 1

    return correlations, attack_path


# =============================================================================
# STEP 3.5: FILE-TO-PROCESS LINKER
# =============================================================================

def step_3_5_file_process_linker(df) -> List[Dict]:
    """
    Link file operations to processes.

    Substeps:
    3.5.1: Collect File Events
    3.5.2: Link to Creator Process
    3.5.3: Link to Subsequent Execution
    3.5.4: Identify Moves and Renames
    """

    links = []

    # Substep 3.5.1: Collect File Events
    # Sysmon EID 11 = FileCreate, EID 15 = FileCreateStreamHash, EID 23 = FileDelete
    file_events = df[df['event_id'].isin([11, 15, 23])].copy()
    logger.debug(f"Substep 3.5.1: Found {len(file_events)} file events")

    if len(file_events) == 0:
        # Still check for move/copy commands
        pass
    else:
        # Substep 3.5.2: Link to Creator Process (limit to first 500 for performance)
        for idx, row in file_events.head(500).iterrows():
            link = {
                'file_event_index': idx,
                'event_id': row.get('event_id'),
                'timestamp': row.get('timestamp_utc'),
                'target_filename': row.get('target_filename') if 'target_filename' in row.index else row.get('file_path'),
                'creating_pid': row.get('pid') if 'pid' in row.index else row.get('process_id'),
                'creating_process': row.get('process_name'),
                'creating_command': row.get('command_line'),
                'source_system': row.get('source_system'),
                'execution_event_index': None,
                'execution_timestamp': None,
            }
            links.append(link)

    # Substep 3.5.3: Link to Subsequent Execution (simplified for performance)
    # Skip detailed linking - can be done post-hoc if needed

    # Substep 3.5.4: Identify Moves and Renames (vectorized)
    if 'command_line' in df.columns:
        move_mask = df['command_line'].str.lower().str.contains(
            r'(?:move|rename|copy|xcopy|robocopy|\bren\b)',
            na=False,
            regex=True
        )
        move_events = df[move_mask].head(100)  # Limit for performance

        for idx, row in move_events.iterrows():
            links.append({
                'file_event_index': idx,
                'event_id': row.get('event_id'),
                'timestamp': row.get('timestamp_utc'),
                'operation': 'move_or_copy',
                'command': row.get('command_line'),
                'source_system': row.get('source_system'),
                'process_name': row.get('process_name'),
                'username': row.get('username'),
            })

    return links
