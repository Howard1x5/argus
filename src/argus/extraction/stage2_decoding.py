"""
STAGE 2: DECODING

Goal: Every encoded/obfuscated string decoded to plaintext.

Steps:
- 2.1: Base64 Finder (4 substeps)
- 2.2: Base64 Decoder (5 substeps)
- 2.3: URL Decoder (4 substeps)
- 2.4: PowerShell Decoder (5 substeps)
- 2.5: Nested Encoding Resolver (3 substeps)

Total: 23 substeps
"""

import logging
import re
import base64
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class DecodedContent:
    """Represents a decoded piece of content with full context."""
    decoded_id: str
    original_text: str
    final_text: str
    encoding_chain: List[str]  # e.g., ["URL", "Base64", "UTF-16LE"]
    source_file: str
    source_row: int
    source_column: str
    source_timestamp: Any
    source_event_type: Optional[str]
    source_process_name: Optional[str]
    confidence: str  # HIGH, MEDIUM, LOW
    contains_urls: List[str] = field(default_factory=list)
    contains_ips: List[str] = field(default_factory=list)
    contains_credentials: bool = False
    contains_commands: List[str] = field(default_factory=list)


# Regex patterns
# Note: Lower threshold for finding base64 - webshell commands can be short (e.g., "whoami" = "d2hvYW1p")
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')
BASE64_PATTERN_LONG = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
URL_ENCODED_PATTERN = re.compile(r'%[0-9A-Fa-f]{2}')
HEX_PATTERNS = {
    'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
}
SID_PATTERN = re.compile(r'^S-\d+-\d+(-\d+)+$')
GUID_PATTERN = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')

# PowerShell patterns
PS_INVOCATION_PATTERN = re.compile(
    r'(?:powershell|pwsh)(?:\.exe)?.*?(?:-enc(?:odedcommand)?|-e\s|-ec\s)',
    re.IGNORECASE
)
PS_COMMAND_PATTERN = re.compile(
    r'(?:powershell|pwsh)(?:\.exe)?.*?(?:-c(?:ommand)?)',
    re.IGNORECASE
)
IEX_PATTERN = re.compile(
    r'(?:Invoke-Expression|IEX)\s*[\(\{]',
    re.IGNORECASE
)

# Attack indicator patterns for parsed content
URL_EXTRACT_PATTERN = re.compile(r'https?://[^\s\'"<>]+')
IP_EXTRACT_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CREDENTIAL_PATTERNS = [
    re.compile(r'password\s*[=:]\s*[\'"]?[\w\S]+', re.IGNORECASE),
    re.compile(r'\$cred', re.IGNORECASE),
    re.compile(r'Get-Credential', re.IGNORECASE),
    re.compile(r'ConvertTo-SecureString', re.IGNORECASE),
    re.compile(r'-Credential', re.IGNORECASE),
]
ATTACK_COMMANDS = [
    'Invoke-Mimikatz', 'Invoke-WMIExec', 'Invoke-SMBExec', 'Invoke-TheHash',
    'Invoke-ReflectivePEInjection', 'Invoke-Shellcode', 'Invoke-TokenManipulation',
    'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-ClipboardContents',
    'DownloadString', 'DownloadFile', 'Net.WebClient', 'Invoke-WebRequest',
    'Start-Process', 'New-Object', 'IEX', 'Invoke-Expression',
]


def run(context) -> None:
    """Execute Stage 2: Decoding."""
    logger.info("Stage 2: Decoding starting")

    df = context.unified_df

    # Step 2.1: Base64 Finder
    base64_candidates = step_2_1_base64_finder(df)
    logger.info(f"Step 2.1: Found {len(base64_candidates)} base64 candidates")

    # Step 2.2: Base64 Decoder
    decoded_base64 = step_2_2_base64_decoder(base64_candidates)
    context.decoded_base64 = decoded_base64
    logger.info(f"Step 2.2: Decoded {len(decoded_base64)} base64 strings")

    # Step 2.3: URL Decoder
    decoded_urls = step_2_3_url_decoder(df)
    context.decoded_urls = decoded_urls
    logger.info(f"Step 2.3: Decoded {len(decoded_urls)} URL-encoded strings")

    # Step 2.4: PowerShell Decoder
    decoded_ps = step_2_4_powershell_decoder(df, decoded_base64, decoded_urls)
    context.decoded_powershell = decoded_ps
    logger.info(f"Step 2.4: Parsed {len(decoded_ps)} PowerShell invocations")

    # Step 2.5: Nested Encoding Resolver & Master Index
    all_decoded = decoded_base64 + decoded_urls + decoded_ps
    final_decoded = step_2_5_nested_resolver(all_decoded)
    context.decoded_content_index = final_decoded
    logger.info(f"Step 2.5: Final decoded content index: {len(final_decoded)} items")

    # Update statistics
    context.statistics['stage2'] = {
        'base64_candidates': len(base64_candidates),
        'decoded_base64': len(decoded_base64),
        'decoded_urls': len(decoded_urls),
        'decoded_powershell': len(decoded_ps),
        'total_decoded': len(final_decoded),
    }

    logger.info("Stage 2: Decoding completed")


# =============================================================================
# STEP 2.1: BASE64 FINDER
# =============================================================================

def step_2_1_base64_finder(df) -> List[Dict]:
    """
    Find all base64 candidates in text fields.

    Substeps:
    2.1.1: Define Search Columns
    2.1.2: Scan for Base64 Patterns
    2.1.3: Filter False Positives
    2.1.4: Record Context
    """

    # Substep 2.1.1: Define Search Columns
    search_cols = []
    for col in df.columns:
        if any(x in col.lower() for x in ['command', 'payload', 'query', 'line', 'data', 'uri']):
            if df[col].dtype == 'object':
                search_cols.append(col)

    logger.debug(f"Substep 2.1.1: Searching {len(search_cols)} columns")

    # Substep 2.1.2: Scan for Base64 Patterns
    candidates = []
    for col in search_cols:
        for idx, val in df[col].items():
            if pd.isna(val):
                continue

            val_str = str(val)
            for match in BASE64_PATTERN.finditer(val_str):
                matched = match.group()
                candidates.append({
                    'row_index': idx,
                    'column': col,
                    'matched_string': matched,
                    'position': match.start(),
                    'full_value': val_str,
                    'row_data': df.iloc[idx].to_dict() if idx < len(df) else {},
                })

    logger.debug(f"Substep 2.1.2: Found {len(candidates)} raw candidates")

    # Substep 2.1.3: Filter False Positives
    filtered = []
    for cand in candidates:
        matched = cand['matched_string']
        col = cand['column']

        # Skip if matches hash patterns
        if HEX_PATTERNS['md5'].match(matched):
            continue
        if HEX_PATTERNS['sha1'].match(matched):
            continue
        if HEX_PATTERNS['sha256'].match(matched):
            continue

        # Skip SIDs and GUIDs
        if SID_PATTERN.match(matched):
            continue
        if GUID_PATTERN.match(matched):
            continue

        # For non-query columns, skip short strings (likely false positives)
        # For query_string columns, keep shorter base64 (webshell commands are often short)
        if len(matched) < 16 and 'query' not in col.lower():
            continue

        # Try to decode to determine confidence
        confidence = 'MEDIUM'
        try:
            decoded = base64.b64decode(matched)

            # Check if it's valid text
            try:
                text = decoded.decode('utf-8')
                if all(c.isprintable() or c in '\n\r\t ' for c in text):
                    confidence = 'HIGH'
            except UnicodeDecodeError:
                # Try UTF-16LE (PowerShell)
                if len(decoded) % 2 == 0:
                    try:
                        text = decoded.decode('utf-16-le')
                        if all(c.isprintable() or c in '\n\r\t ' for c in text):
                            confidence = 'HIGH'
                    except:
                        confidence = 'BINARY'
                else:
                    confidence = 'BINARY'
        except:
            continue  # Invalid base64, skip

        cand['confidence'] = confidence
        filtered.append(cand)

    logger.debug(f"Substep 2.1.3: Filtered to {len(filtered)} candidates")

    # Substep 2.1.4: Record Context (already done via row_data)
    return filtered


# =============================================================================
# STEP 2.2: BASE64 DECODER
# =============================================================================

def step_2_2_base64_decoder(candidates: List[Dict]) -> List[DecodedContent]:
    """
    Decode all base64 candidates.

    Substeps:
    2.2.1: Decode as UTF-8
    2.2.2: Decode as UTF-16LE
    2.2.3: Decode as ASCII/Latin-1
    2.2.4: Fix Padding Issues
    2.2.5: Compile Results
    """

    results = []

    for cand in candidates:
        encoded = cand['matched_string']
        row_data = cand.get('row_data', {})

        decoded_text = None
        encoding_used = None

        # Substep 2.2.1: Decode as UTF-8 (try first - most common for webshell commands)
        try:
            decoded_bytes = base64.b64decode(encoded)
            text = decoded_bytes.decode('utf-8')
            if all(c.isprintable() or c in '\n\r\t ' for c in text):
                decoded_text = text
                encoding_used = 'UTF-8'
        except:
            pass

        # Substep 2.2.2: Decode as UTF-16LE (PowerShell -EncodedCommand)
        if decoded_text is None:
            try:
                decoded_bytes = base64.b64decode(encoded)
                if len(decoded_bytes) % 2 == 0:
                    text = decoded_bytes.decode('utf-16-le')
                    if all(c.isprintable() or c in '\n\r\t ' for c in text):
                        decoded_text = text
                        encoding_used = 'UTF-16LE'
            except:
                pass

        # Substep 2.2.3: Decode as ASCII/Latin-1
        if decoded_text is None:
            try:
                decoded_bytes = base64.b64decode(encoded)
                for enc in ['ascii', 'latin-1']:
                    try:
                        text = decoded_bytes.decode(enc)
                        if sum(c.isprintable() or c in '\n\r\t ' for c in text) / len(text) > 0.8:
                            decoded_text = text
                            encoding_used = enc.upper()
                            break
                    except:
                        continue
            except:
                pass

        # Substep 2.2.4: Fix Padding Issues
        if decoded_text is None:
            padded = encoded
            while len(padded) % 4 != 0:
                padded += '='

            try:
                decoded_bytes = base64.b64decode(padded)
                for enc in ['utf-8', 'utf-16-le', 'ascii', 'latin-1']:
                    try:
                        text = decoded_bytes.decode(enc)
                        if sum(c.isprintable() or c in '\n\r\t ' for c in text) / max(len(text), 1) > 0.8:
                            decoded_text = text
                            encoding_used = f'{enc.upper()} (padding fixed)'
                            break
                    except:
                        continue
            except:
                pass

        # Substep 2.2.5: Compile Results
        if decoded_text:
            decoded_id = hashlib.md5(encoded.encode()).hexdigest()[:12]

            content = DecodedContent(
                decoded_id=decoded_id,
                original_text=encoded,
                final_text=decoded_text.strip(),
                encoding_chain=['Base64', encoding_used],
                source_file=row_data.get('source_file', 'unknown'),
                source_row=cand['row_index'],
                source_column=cand['column'],
                source_timestamp=row_data.get('timestamp_utc'),
                source_event_type=str(row_data.get('event_id', '')),
                source_process_name=row_data.get('process_name'),
                confidence=cand.get('confidence', 'MEDIUM'),
            )

            # Extract indicators from decoded content
            _extract_indicators(content)
            results.append(content)

    return results


# =============================================================================
# STEP 2.3: URL DECODER
# =============================================================================

def step_2_3_url_decoder(df) -> List[DecodedContent]:
    """
    Decode URL-encoded content.

    Substeps:
    2.3.1: Find URL-Encoded Content
    2.3.2: First-Pass Decode
    2.3.3: Check Double Encoding
    2.3.4: Handle Plus-Encoding
    """

    results = []

    # Substep 2.3.1: Find URL-Encoded Content
    url_cols = ['query_string', 'uri', 'raw_cs-uri-query']
    search_cols = [c for c in df.columns if any(x in c.lower() for x in url_cols)]

    # Also search any column that might have URL encoding
    for col in df.columns:
        if df[col].dtype == 'object':
            sample = df[col].dropna().head(100).astype(str)
            if any(URL_ENCODED_PATTERN.search(str(v)) for v in sample):
                if col not in search_cols:
                    search_cols.append(col)

    for col in search_cols:
        for idx, val in df[col].items():
            if pd.isna(val):
                continue

            val_str = str(val)
            if not URL_ENCODED_PATTERN.search(val_str):
                continue

            row_data = df.iloc[idx].to_dict() if idx < len(df) else {}

            # Substep 2.3.4: Handle Plus-Encoding first (for query strings)
            working = val_str
            if col in ['query_string', 'raw_cs-uri-query'] or 'query' in col.lower():
                working = working.replace('+', ' ')

            # Substep 2.3.2: First-Pass Decode
            decoded = urllib.parse.unquote(working)

            # Substep 2.3.3: Check Double Encoding (max 3 passes)
            depth = 1
            while URL_ENCODED_PATTERN.search(decoded) and depth < 3:
                decoded = urllib.parse.unquote(decoded)
                depth += 1

            # Only record if decoding changed something meaningful
            if decoded != val_str and len(decoded) > 10:
                decoded_id = hashlib.md5(val_str.encode()).hexdigest()[:12]

                content = DecodedContent(
                    decoded_id=decoded_id,
                    original_text=val_str,
                    final_text=decoded.strip(),
                    encoding_chain=['URL'] * depth,
                    source_file=row_data.get('source_file', 'unknown'),
                    source_row=idx,
                    source_column=col,
                    source_timestamp=row_data.get('timestamp_utc'),
                    source_event_type=str(row_data.get('event_id', '')),
                    source_process_name=row_data.get('process_name'),
                    confidence='HIGH' if depth == 1 else 'MEDIUM',
                )

                _extract_indicators(content)
                results.append(content)

    return results


# =============================================================================
# STEP 2.4: POWERSHELL DECODER
# =============================================================================

def step_2_4_powershell_decoder(df, decoded_base64: List, decoded_urls: List) -> List[DecodedContent]:
    """
    Parse PowerShell invocations and extract meaningful content.

    Substeps:
    2.4.1: Find All PowerShell Invocations
    2.4.2: Extract Encoded Portions
    2.4.3: Decode PS Encoded Commands
    2.4.4: Parse Decoded PS Scripts
    2.4.5: Parse Direct PS Commands
    """

    results = []

    # Substep 2.4.1: Find All PowerShell Invocations
    ps_invocations = []

    for col in ['command_line', 'parent_command_line', 'raw_payload']:
        if col not in df.columns:
            continue

        for idx, val in df[col].items():
            if pd.isna(val):
                continue

            val_str = str(val).lower()
            if 'powershell' in val_str or 'pwsh' in val_str:
                ps_invocations.append({
                    'row_index': idx,
                    'column': col,
                    'full_text': str(df.iloc[idx][col]) if idx < len(df) else str(val),
                    'row_data': df.iloc[idx].to_dict() if idx < len(df) else {},
                })

    # Also check decoded content for PS
    for decoded in decoded_base64 + decoded_urls:
        if 'powershell' in decoded.final_text.lower() or 'pwsh' in decoded.final_text.lower():
            ps_invocations.append({
                'row_index': decoded.source_row,
                'column': f'decoded_{decoded.decoded_id}',
                'full_text': decoded.final_text,
                'row_data': {},
                'from_decoded': True,
            })

    logger.debug(f"Substep 2.4.1: Found {len(ps_invocations)} PowerShell invocations")

    for inv in ps_invocations:
        full_text = inv['full_text']
        row_data = inv.get('row_data', {})

        # Substep 2.4.2: Extract Encoded Portions
        enc_match = re.search(
            r'(?:-enc(?:odedcommand)?|-e\s|-ec\s)\s*["\']?([A-Za-z0-9+/=]+)',
            full_text,
            re.IGNORECASE
        )

        if enc_match:
            encoded_portion = enc_match.group(1)

            # Substep 2.4.3: Decode PS Encoded Commands (ALWAYS UTF-16LE for -enc)
            try:
                decoded_bytes = base64.b64decode(encoded_portion)
                decoded_script = decoded_bytes.decode('utf-16-le')

                decoded_id = hashlib.md5(encoded_portion.encode()).hexdigest()[:12]

                content = DecodedContent(
                    decoded_id=decoded_id,
                    original_text=encoded_portion,
                    final_text=decoded_script.strip(),
                    encoding_chain=['PowerShell -EncodedCommand', 'Base64', 'UTF-16LE'],
                    source_file=row_data.get('source_file', 'unknown'),
                    source_row=inv['row_index'],
                    source_column=inv['column'],
                    source_timestamp=row_data.get('timestamp_utc'),
                    source_event_type=str(row_data.get('event_id', '')),
                    source_process_name=row_data.get('process_name'),
                    confidence='HIGH',
                )

                # Substep 2.4.4: Parse Decoded PS Scripts
                _parse_powershell_script(content)
                _extract_indicators(content)
                results.append(content)

            except Exception as e:
                logger.debug(f"Failed to decode PS encoded command: {e}")

        # Substep 2.4.5: Parse Direct PS Commands
        cmd_match = re.search(
            r'(?:-c(?:ommand)?)\s+["\']?(.+?)(?:["\']?\s*$|["\']?\s+-)',
            full_text,
            re.IGNORECASE
        )

        if cmd_match and not enc_match:
            command_text = cmd_match.group(1)
            decoded_id = hashlib.md5(command_text.encode()).hexdigest()[:12]

            content = DecodedContent(
                decoded_id=decoded_id,
                original_text=full_text,
                final_text=command_text.strip(),
                encoding_chain=['PowerShell -Command', 'Direct'],
                source_file=row_data.get('source_file', 'unknown'),
                source_row=inv['row_index'],
                source_column=inv['column'],
                source_timestamp=row_data.get('timestamp_utc'),
                source_event_type=str(row_data.get('event_id', '')),
                source_process_name=row_data.get('process_name'),
                confidence='HIGH',
            )

            _parse_powershell_script(content)
            _extract_indicators(content)
            results.append(content)

    return results


def _parse_powershell_script(content: DecodedContent) -> None:
    """Parse PowerShell script content for attack indicators."""
    script = content.final_text

    # Extract URLs (IWR, wget, curl, DownloadString, DownloadFile, Net.WebClient)
    urls = URL_EXTRACT_PATTERN.findall(script)
    content.contains_urls.extend(urls)

    # Extract IPs
    ips = IP_EXTRACT_PATTERN.findall(script)
    content.contains_ips.extend(ips)

    # Check for credential indicators
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(script):
            content.contains_credentials = True
            break

    # Check for attack commands
    for cmd in ATTACK_COMMANDS:
        if cmd.lower() in script.lower():
            content.contains_commands.append(cmd)


# =============================================================================
# STEP 2.5: NESTED ENCODING RESOLVER
# =============================================================================

def step_2_5_nested_resolver(all_decoded: List[DecodedContent]) -> List[DecodedContent]:
    """
    Resolve nested encoding and build master index.

    Substeps:
    2.5.1: Check for Further Encoding
    2.5.2: Recursive Decode
    2.5.3: Build Master Decoded Index
    """

    final_results = []

    for content in all_decoded:
        current_text = content.final_text
        encoding_chain = content.encoding_chain.copy()
        iterations = 0
        max_iterations = 5

        # Substep 2.5.1 & 2.5.2: Check and recursively decode
        while iterations < max_iterations:
            changed = False
            iterations += 1

            # Check for more base64
            b64_match = BASE64_PATTERN.search(current_text)
            if b64_match:
                try:
                    inner_encoded = b64_match.group()
                    decoded_bytes = base64.b64decode(inner_encoded)

                    # Try UTF-8 first, then UTF-16LE
                    for enc in ['utf-8', 'utf-16-le']:
                        try:
                            decoded = decoded_bytes.decode(enc)
                            if all(c.isprintable() or c in '\n\r\t ' for c in decoded):
                                current_text = current_text.replace(inner_encoded, decoded)
                                encoding_chain.append(f'Nested Base64 → {enc.upper()}')
                                changed = True
                                break
                        except:
                            continue
                except:
                    pass

            # Check for more URL encoding
            if URL_ENCODED_PATTERN.search(current_text):
                decoded = urllib.parse.unquote(current_text)
                if decoded != current_text:
                    current_text = decoded
                    encoding_chain.append('Nested URL')
                    changed = True

            if not changed:
                break

        # Update content with final decoded text
        content.final_text = current_text.strip()
        content.encoding_chain = encoding_chain

        # Re-extract indicators after full decoding
        content.contains_urls = []
        content.contains_ips = []
        content.contains_commands = []
        content.contains_credentials = False
        _extract_indicators(content)

        final_results.append(content)

    # Substep 2.5.3: Build Master Decoded Index (list of DecodedContent)
    # Deduplicate by decoded_id
    seen_ids = set()
    unique_results = []
    for content in final_results:
        if content.decoded_id not in seen_ids:
            seen_ids.add(content.decoded_id)
            unique_results.append(content)

    return unique_results


def _extract_indicators(content: DecodedContent) -> None:
    """Extract attack indicators from decoded content."""
    text = content.final_text

    # URLs
    urls = URL_EXTRACT_PATTERN.findall(text)
    content.contains_urls.extend([u for u in urls if u not in content.contains_urls])

    # IPs
    ips = IP_EXTRACT_PATTERN.findall(text)
    content.contains_ips.extend([ip for ip in ips if ip not in content.contains_ips])

    # Credentials
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(text):
            content.contains_credentials = True
            break

    # Commands
    for cmd in ATTACK_COMMANDS:
        if cmd.lower() in text.lower() and cmd not in content.contains_commands:
            content.contains_commands.append(cmd)


# Import pandas for type checking
import pandas as pd
