"""
STAGE 1: FIELD EXTRACTION

Goal: Raw Parquet → fully queryable data with every field as a first-class column.

Steps:
- 1.1: Column Normalizer (4 substeps)
- 1.2: Payload Unpacker (6 substeps)
- 1.3: Timestamp Normalizer (5 substeps)
- 1.4: Entity Tagger (7 substeps)

Total: 17 substeps
"""

import logging
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
import ipaddress

import pandas as pd
import pyarrow.parquet as pq

logger = logging.getLogger(__name__)

# Unified schema mapping for different log sources
COLUMN_MAPPING = {
    # EvtxECmd standard columns
    'TimeCreated': 'timestamp_utc',
    'EventId': 'event_id',
    'Computer': 'source_system',
    'UserName': 'username',
    'ExecutableInfo': 'command_line',
    'Payload': 'raw_payload',
    'Provider': 'provider',
    'Channel': 'channel',
    'Level': 'level',
    'MapDescription': 'map_description',

    # IIS columns
    'c-ip': 'source_ip',
    'cs-uri-stem': 'uri',
    'cs-method': 'http_method',
    'sc-status': 'status_code',
    'cs(User-Agent)': 'user_agent',
    'cs-uri-query': 'query_string',
    's-ip': 'dest_ip',
    's-port': 'dest_port',
    'time-taken': 'time_taken',

    # Common variations
    'SourceIp': 'source_ip',
    'DestinationIp': 'dest_ip',
    'ProcessName': 'process_name',
    'ParentProcessName': 'parent_process_name',
    'CommandLine': 'command_line',
    'ParentCommandLine': 'parent_command_line',
    'TargetFilename': 'target_filename',
    'Image': 'image_path',
    'ParentImage': 'parent_image_path',
    'ProcessId': 'pid',
    'ParentProcessId': 'ppid',
    'ServiceName': 'service_name',
    'ImagePath': 'service_image_path',
    'LogonType': 'logon_type',

    # ARGUS parser output columns (already in unified format - map to canonical)
    'process_id': 'pid',
    'parent_process_id': 'ppid',
    'file_path': 'target_filename',
    'service_path': 'service_image_path',
}

# Columns that are already in unified schema format (don't rename)
UNIFIED_SCHEMA_COLUMNS = {
    'timestamp_utc', 'event_id', 'source_system', 'username', 'command_line',
    'process_name', 'parent_process_name', 'parent_command_line',
    'source_ip', 'dest_ip', 'source_port', 'dest_port',
    'uri', 'http_method', 'status_code', 'user_agent', 'query_string',
    'service_name', 'raw_payload', 'logon_type', 'domain',
    'event_type', 'severity', 'file_hash', 'referrer',
    'registry_key', 'registry_value', 'description',
    'source_file', 'source_line', 'parser_name', 'parse_warnings',
}

# IP classification ranges (RFC 1918 private ranges)
INTERNAL_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),  # NOSEC
    ipaddress.ip_network('172.16.0.0/12'),  # NOSEC
    ipaddress.ip_network('192.168.0.0/16'),  # NOSEC
]
LOOPBACK_RANGE = ipaddress.ip_network('127.0.0.0/8')
LINK_LOCAL_RANGE = ipaddress.ip_network('169.254.0.0/16')

# System accounts
SYSTEM_ACCOUNTS = {
    'system', 'local service', 'network service', 'nt authority\\system',
    'nt authority\\local service', 'nt authority\\network service',
}

# Known process categories
SYSTEM_PROCESSES = {
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe', 'smss.exe',
    'services.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe', 'spoolsv.exe',
    'lsaiso.exe', 'fontdrvhost.exe', 'sihost.exe', 'taskhostw.exe',
}

WINDOWS_TOOLS = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'net.exe', 'net1.exe',
    'whoami.exe', 'ipconfig.exe', 'ping.exe', 'nslookup.exe', 'tracert.exe',
    'netstat.exe', 'systeminfo.exe', 'hostname.exe', 'tasklist.exe',
    'taskkill.exe', 'sc.exe', 'reg.exe', 'wmic.exe', 'mshta.exe',
    'cscript.exe', 'wscript.exe', 'certutil.exe', 'bitsadmin.exe',
    'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'curl.exe', 'wget.exe',
}

KNOWN_ATTACK_TOOLS = {
    'mimikatz.exe', 'procdump.exe', 'pd.exe', 'procdump64.exe',
    'psexec.exe', 'psexec64.exe', 'wce.exe', 'gsecdump.exe',
    'lazagne.exe', 'bloodhound.exe', 'sharphound.exe', 'rubeus.exe',
    'kekeo.exe', 'safetykatz.exe', 'logonpasswords.exe',
    'secretsdump.exe', 'crackmapexec.exe', 'covenant.exe',
    'cobalt', 'beacon', 'meterpreter',
}

WEB_SERVERS = {
    'w3wp.exe', 'httpd.exe', 'nginx.exe', 'apache.exe', 'tomcat.exe',
    'java.exe', 'node.exe', 'iisexpress.exe', 'webengine4.exe',
}


def run(context) -> None:
    """Execute Stage 1: Field Extraction."""
    logger.info("Stage 1: Field Extraction starting")

    # Load all parquet files
    parquet_files = list(context.parquet_dir.glob("*.parquet"))
    if not parquet_files:
        raise FileNotFoundError(f"No parquet files found in {context.parquet_dir}")

    logger.info(f"Found {len(parquet_files)} parquet files")

    all_dfs = []
    for pq_file in parquet_files:
        logger.info(f"Processing {pq_file.name}")

        # Step 1.1: Column Normalizer
        df, inventory = step_1_1_column_normalizer(pq_file)
        context.column_inventory[pq_file.name] = inventory

        # Step 1.2: Payload Unpacker
        df = step_1_2_payload_unpacker(df)

        # Step 1.3: Timestamp Normalizer
        df = step_1_3_timestamp_normalizer(df)

        # Add source file reference
        df['source_file'] = pq_file.name

        all_dfs.append(df)

    # Combine all dataframes
    context.unified_df = pd.concat(all_dfs, ignore_index=True)
    logger.info(f"Combined {len(context.unified_df)} total events")

    # Step 1.4: Entity Tagger (operates on combined data)
    step_1_4_entity_tagger(context)

    # Update statistics
    context.statistics['stage1'] = {
        'total_events': len(context.unified_df),
        'parquet_files': len(parquet_files),
        'unique_ips': len(context.ip_classifications),
        'unique_usernames': len(context.username_classifications),
        'unique_processes': len(context.process_classifications),
    }

    logger.info("Stage 1: Field Extraction completed")


# =============================================================================
# STEP 1.1: COLUMN NORMALIZER
# =============================================================================

def step_1_1_column_normalizer(parquet_path: Path) -> Tuple[pd.DataFrame, Dict]:
    """
    Normalize column names and types to unified schema.

    Substeps:
    1.1.1: Inventory Source Columns
    1.1.2: Map to Unified Schema
    1.1.3: Apply Renames and Cast Types
    1.1.4: Fill Missing Schema Columns
    """

    # Substep 1.1.1: Inventory Source Columns
    df = pd.read_parquet(parquet_path)
    inventory = {col: str(df[col].dtype) for col in df.columns}
    logger.debug(f"Substep 1.1.1: Found {len(inventory)} columns in {parquet_path.name}")

    # Substep 1.1.2: Map to Unified Schema
    rename_mapping = {}
    for col in df.columns:
        if col in COLUMN_MAPPING:
            # Column needs to be renamed to unified schema
            rename_mapping[col] = COLUMN_MAPPING[col]
        elif col in UNIFIED_SCHEMA_COLUMNS:
            # Column is already in unified schema format, keep as-is
            pass
        elif col.startswith('PayloadData'):
            # Keep PayloadData columns as-is for unpacking in 1.2
            pass
        else:
            # Prefix unmapped columns with raw_ only if not already there
            if not col.startswith('raw_') and col not in rename_mapping.values():
                rename_mapping[col] = f'raw_{col}'

    logger.debug(f"Substep 1.1.2: Mapped {len(rename_mapping)} columns")

    # Substep 1.1.3: Apply Renames and Cast Types
    df = df.rename(columns=rename_mapping)

    # Cast event_id to int if present
    if 'event_id' in df.columns:
        df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(0).astype(int)

    logger.debug("Substep 1.1.3: Applied renames and type casts")

    # Substep 1.1.4: Fill Missing Schema Columns
    required_columns = [
        'timestamp_utc', 'event_id', 'source_system', 'username',
        'command_line', 'process_name', 'parent_process_name',
        'source_ip', 'dest_ip', 'pid', 'ppid'
    ]

    for col in required_columns:
        if col not in df.columns:
            df[col] = None

    logger.debug("Substep 1.1.4: Filled missing schema columns")

    return df, inventory


# =============================================================================
# STEP 1.2: PAYLOAD UNPACKER
# =============================================================================

def step_1_2_payload_unpacker(df: pd.DataFrame) -> pd.DataFrame:
    """
    Unpack structured payloads into named columns.

    Substeps:
    1.2.1: Identify Payload Columns
    1.2.2: Detect Format Per Row
    1.2.3: Parse JSON Payloads
    1.2.4: Parse Key-Value Payloads
    1.2.5: Parse PayloadData1-6
    1.2.6: Consolidate to Canonical Fields
    """

    # Substep 1.2.1: Identify Payload Columns
    payload_cols = [col for col in df.columns
                    if 'payload' in col.lower() or col.startswith('PayloadData')]
    logger.debug(f"Substep 1.2.1: Found {len(payload_cols)} payload columns")

    # Process each payload column
    extracted_data = []
    for idx, row in df.iterrows():
        row_extracts = {}

        for col in payload_cols:
            val = row.get(col)
            if pd.isna(val) or val == '':
                continue

            val_str = str(val)

            # Substep 1.2.2: Detect Format Per Row
            fmt = _detect_payload_format(val_str)

            # Substep 1.2.3: Parse JSON Payloads
            if fmt == 'json':
                parsed = _parse_json_payload(val_str)
                for k, v in parsed.items():
                    row_extracts[f'payload_{k}'] = v

            # Substep 1.2.4: Parse Key-Value Payloads
            elif fmt in ('kv_newline', 'kv_pipe'):
                parsed = _parse_kv_payload(val_str, fmt)
                for k, v in parsed.items():
                    row_extracts[f'payload_{k}'] = v

            # Substep 1.2.5: Parse PayloadData1-6 (EvtxECmd pre-parsed fields)
            elif col.startswith('PayloadData'):
                # These are often already parsed key-value pairs
                parsed = _parse_evtxecmd_payload(val_str, col)
                row_extracts.update(parsed)

        extracted_data.append(row_extracts)

    # Create dataframe from extracted data
    if extracted_data:
        extract_df = pd.DataFrame(extracted_data)
        for col in extract_df.columns:
            df[col] = extract_df[col]

    # Substep 1.2.6: Consolidate to Canonical Fields
    df = _consolidate_canonical_fields(df)

    logger.debug("Substep 1.2.6: Consolidated to canonical fields")

    return df


def _detect_payload_format(val: str) -> str:
    """Substep 1.2.2: Detect payload format."""
    val = val.strip()

    if val.startswith('{') or val.startswith('['):
        return 'json'
    elif '\n' in val and ':' in val:
        return 'kv_newline'
    elif '|' in val and '=' in val:
        return 'kv_pipe'
    else:
        return 'raw'


def _parse_json_payload(val: str) -> Dict[str, Any]:
    """Substep 1.2.3: Parse JSON payloads with flattening."""
    try:
        data = json.loads(val)
        return _flatten_dict(data)
    except json.JSONDecodeError:
        return {}


def _flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dict with dot notation."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list):
            items.append((new_key, ';'.join(str(x) for x in v)))
        else:
            items.append((new_key, v))
    return dict(items)


def _parse_kv_payload(val: str, fmt: str) -> Dict[str, str]:
    """Substep 1.2.4: Parse key-value payloads."""
    result = {}

    if fmt == 'kv_newline':
        for line in val.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.strip()] = value.strip()
    elif fmt == 'kv_pipe':
        for pair in val.split('|'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                result[key.strip()] = value.strip()

    return result


def _parse_evtxecmd_payload(val: str, col_name: str) -> Dict[str, Any]:
    """Substep 1.2.5: Parse PayloadData fields from EvtxECmd."""
    result = {}

    # PayloadData fields often contain structured data
    # Common formats:
    # PayloadData1 often = ProcessId, LogonType
    # PayloadData3 often = Image path
    # PayloadData4 often = ParentImage, TargetFilename

    # Try to detect what kind of data this is
    val = str(val)

    # Check for path-like values (Image, TargetFilename)
    if '\\' in val or '/' in val:
        if col_name == 'PayloadData3':
            result['image_path'] = val
        elif col_name == 'PayloadData4':
            result['parent_image_path'] = val
        else:
            result[f'{col_name}_path'] = val

    # Check for numeric values (ProcessId, LogonType)
    elif val.isdigit():
        if col_name == 'PayloadData1':
            result['pid'] = int(val)
        elif col_name == 'PayloadData2':
            result['ppid'] = int(val)
        else:
            result[f'{col_name}_num'] = int(val)

    # Check for key=value format
    elif '=' in val:
        parsed = _parse_kv_payload(val, 'kv_pipe')
        result.update(parsed)

    return result


def _consolidate_canonical_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Substep 1.2.6: Consolidate to canonical field names."""

    # Command line: prefer ExecutableInfo > payload_CommandLine
    if 'command_line' not in df.columns or df['command_line'].isna().all():
        for alt in ['payload_CommandLine', 'payload_commandline', 'raw_CommandLine']:
            if alt in df.columns:
                df['command_line'] = df[alt].combine_first(df.get('command_line', pd.Series()))
                break

    # Process name: extract from image_path if not present
    if 'process_name' not in df.columns or df['process_name'].isna().all():
        if 'image_path' in df.columns:
            df['process_name'] = df['image_path'].apply(_extract_exe_name)

    # Parent process name
    if 'parent_process_name' not in df.columns or df['parent_process_name'].isna().all():
        if 'parent_image_path' in df.columns:
            df['parent_process_name'] = df['parent_image_path'].apply(_extract_exe_name)

    # PID/PPID
    for field in ['pid', 'ppid']:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce')

    return df


def _extract_exe_name(path: Any) -> Optional[str]:
    """Extract executable name from full path."""
    if pd.isna(path):
        return None

    path_str = str(path)
    # Handle both Windows and Unix paths
    if '\\' in path_str:
        return path_str.split('\\')[-1].lower()
    elif '/' in path_str:
        return path_str.split('/')[-1].lower()
    return path_str.lower()


# =============================================================================
# STEP 1.3: TIMESTAMP NORMALIZER
# =============================================================================

def step_1_3_timestamp_normalizer(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize all timestamps to UTC datetime.

    Substeps:
    1.3.1: Identify Timestamp Columns
    1.3.2: Parse Formats
    1.3.3: Detect Timezone
    1.3.4: Convert All to UTC
    1.3.5: Detect Cross-Source Clock Skew (handled at orchestrator level)
    """

    # Substep 1.3.1: Identify Timestamp Columns
    timestamp_cols = [col for col in df.columns
                      if 'time' in col.lower() or 'date' in col.lower()]

    if 'timestamp_utc' not in timestamp_cols:
        timestamp_cols.append('timestamp_utc')

    logger.debug(f"Substep 1.3.1: Found {len(timestamp_cols)} timestamp columns")

    # Substep 1.3.2 & 1.3.3 & 1.3.4: Parse and convert
    df['timezone_uncertain'] = False

    for col in timestamp_cols:
        if col not in df.columns:
            continue

        df[col], uncertain_mask = _parse_and_normalize_timestamps(df[col])

        if col == 'timestamp_utc':
            df.loc[uncertain_mask, 'timezone_uncertain'] = True

    logger.debug("Substep 1.3.4: Converted all timestamps to UTC")

    return df


def _parse_and_normalize_timestamps(series: pd.Series) -> Tuple[pd.Series, pd.Series]:
    """Parse various timestamp formats and convert to UTC."""

    def parse_single(val):
        if pd.isna(val):
            return None, False

        val_str = str(val)
        uncertain = False

        # Already a datetime object
        if isinstance(val, datetime):
            if val.tzinfo is None:
                uncertain = True
                return val.replace(tzinfo=timezone.utc), uncertain
            return val.astimezone(timezone.utc), uncertain

        # Try pandas parsing first (handles ISO 8601 well)
        try:
            parsed = pd.to_datetime(val_str)
            if parsed.tzinfo is None:
                uncertain = True
                parsed = parsed.tz_localize('UTC')
            else:
                parsed = parsed.tz_convert('UTC')
            return parsed, uncertain
        except:
            pass

        # Try common formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%m/%d/%Y %H:%M:%S',  # US format
            '%d/%m/%Y %H:%M:%S',  # EU format
        ]

        for fmt in formats:
            try:
                parsed = datetime.strptime(val_str.rstrip('Z'), fmt.rstrip('Z'))
                if 'Z' in val_str or fmt.endswith('Z'):
                    parsed = parsed.replace(tzinfo=timezone.utc)
                else:
                    uncertain = True
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed, uncertain
            except ValueError:
                continue

        # Windows FileTime (100-nanosecond intervals since 1601-01-01)
        if val_str.isdigit() and len(val_str) > 15:
            try:
                filetime = int(val_str)
                # Convert to Unix timestamp
                unix_ts = (filetime - 116444736000000000) / 10000000
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc), False
            except:
                pass

        # Unix timestamp
        if val_str.replace('.', '').isdigit():
            try:
                ts = float(val_str)
                if ts > 1e12:  # Milliseconds
                    ts = ts / 1000
                return datetime.fromtimestamp(ts, tz=timezone.utc), False
            except:
                pass

        return None, False

    results = series.apply(parse_single)
    timestamps = results.apply(lambda x: x[0] if x else None)
    uncertain = results.apply(lambda x: x[1] if x else False)

    return pd.to_datetime(timestamps, utc=True, errors='coerce'), uncertain


# =============================================================================
# STEP 1.4: ENTITY TAGGER
# =============================================================================

def step_1_4_entity_tagger(context) -> None:
    """
    Tag entities with classifications for quick filtering.

    Substeps:
    1.4.1: Extract Unique IPs
    1.4.2: Classify IPs
    1.4.3: Extract Unique Usernames
    1.4.4: Classify Usernames
    1.4.5: Extract Unique Process Names
    1.4.6: Classify Processes
    1.4.7: Apply All Classifications to DataFrame
    """

    df = context.unified_df

    # Substeps 1.4.1 & 1.4.2: Extract and classify IPs
    ip_cols = ['source_ip', 'dest_ip']
    all_ips = set()
    for col in ip_cols:
        if col in df.columns:
            # Filter out NaN and empty strings
            valid_ips = df[col].dropna()
            valid_ips = valid_ips[valid_ips != '']
            all_ips.update(valid_ips.unique())

    for ip in all_ips:
        context.ip_classifications[str(ip)] = _classify_ip(str(ip))

    logger.debug(f"Substep 1.4.2: Classified {len(context.ip_classifications)} IPs")

    # Substeps 1.4.3 & 1.4.4: Extract and classify usernames
    username_cols = ['username', 'payload_TargetUserName', 'payload_SubjectUserName']
    all_usernames = set()
    for col in username_cols:
        if col in df.columns:
            all_usernames.update(df[col].dropna().unique())

    for username in all_usernames:
        context.username_classifications[str(username)] = _classify_username(str(username))

    logger.debug(f"Substep 1.4.4: Classified {len(context.username_classifications)} usernames")

    # Substeps 1.4.5 & 1.4.6: Extract and classify processes
    process_cols = ['process_name', 'parent_process_name']
    all_processes = set()
    for col in process_cols:
        if col in df.columns:
            for proc in df[col].dropna().unique():
                # Extract just exe name from full path
                exe_name = _extract_exe_name(proc)
                if exe_name:
                    all_processes.add(exe_name)
                # Also add the full path for lookup
                all_processes.add(str(proc).lower())

    for proc in all_processes:
        context.process_classifications[str(proc)] = _classify_process(str(proc))

    logger.debug(f"Substep 1.4.6: Classified {len(context.process_classifications)} processes")

    # Substep 1.4.7: Apply Classifications to DataFrame
    _apply_classifications(df, context)

    logger.debug("Substep 1.4.7: Applied classifications to DataFrame")


def _classify_ip(ip_str: str) -> str:
    """Substep 1.4.2: Classify IP address."""
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback:
            return 'LOOPBACK'
        if ip.is_link_local:
            return 'LINK_LOCAL'
        if ip.is_unspecified:
            return 'UNSPECIFIED'

        for net in INTERNAL_RANGES:
            if ip in net:
                return 'INTERNAL'

        return 'EXTERNAL'

    except ValueError:
        # Invalid IP format (might be hostname)
        return 'UNKNOWN'


def _classify_username(username: str) -> str:
    """Substep 1.4.4: Classify username."""
    username_lower = username.lower().strip()

    # Remove domain prefix for comparison
    if '\\' in username_lower:
        username_lower = username_lower.split('\\')[-1]

    if username_lower in SYSTEM_ACCOUNTS:
        return 'SYSTEM_ACCOUNT'
    if username_lower.endswith('$'):
        return 'MACHINE_ACCOUNT'
    if username_lower.startswith('svc_') or username_lower.startswith('service_'):
        return 'SERVICE_ACCOUNT'
    if 'admin' in username_lower:
        return 'ADMIN_ACCOUNT'

    return 'USER_ACCOUNT'


def _classify_process(process_name: str) -> str:
    """Substep 1.4.6: Classify process name."""
    proc_lower = process_name.lower().strip()

    # Extract just the exe name if full path
    if '\\' in proc_lower:
        proc_lower = proc_lower.split('\\')[-1]
    if '/' in proc_lower:
        proc_lower = proc_lower.split('/')[-1]

    if proc_lower in SYSTEM_PROCESSES:
        return 'SYSTEM_PROCESS'
    if proc_lower in WINDOWS_TOOLS:
        return 'WINDOWS_TOOL'
    if proc_lower in KNOWN_ATTACK_TOOLS:
        return 'KNOWN_ATTACK_TOOL'
    if proc_lower in WEB_SERVERS:
        return 'WEB_SERVER'

    return 'UNKNOWN_PROCESS'


def _apply_classifications(df: pd.DataFrame, context) -> None:
    """Substep 1.4.7: Apply classification columns to DataFrame."""

    # Source IP classification
    if 'source_ip' in df.columns:
        df['source_ip_class'] = df['source_ip'].apply(
            lambda x: context.ip_classifications.get(str(x), 'UNKNOWN') if pd.notna(x) else 'UNKNOWN'
        )

    # Dest IP classification
    if 'dest_ip' in df.columns:
        df['dest_ip_class'] = df['dest_ip'].apply(
            lambda x: context.ip_classifications.get(str(x), 'UNKNOWN') if pd.notna(x) else 'UNKNOWN'
        )

    # Username classification
    if 'username' in df.columns:
        df['username_class'] = df['username'].apply(
            lambda x: context.username_classifications.get(str(x), 'UNKNOWN') if pd.notna(x) else 'UNKNOWN'
        )

    # Process classification
    if 'process_name' in df.columns:
        df['process_class'] = df['process_name'].apply(
            lambda x: context.process_classifications.get(str(x), 'UNKNOWN') if pd.notna(x) else 'UNKNOWN'
        )

    # Parent process classification
    if 'parent_process_name' in df.columns:
        df['parent_process_class'] = df['parent_process_name'].apply(
            lambda x: context.process_classifications.get(str(x), 'UNKNOWN') if pd.notna(x) else 'UNKNOWN'
        )
