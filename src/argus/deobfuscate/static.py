"""ARGUS Static Deobfuscation Module.

Layer 1: Fast pattern-based deobfuscation for common techniques.

This module handles simple, well-known obfuscation patterns that can
be decoded without execution or emulation. It's safe to run anywhere.

Supported techniques:
- Base64 encoding (forward and reversed)
- PowerShell -EncodedCommand
- Hex encoding
- URL encoding
- XOR with single-byte key
- String concatenation patterns
- Escape sequence decoding
"""

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ObfuscationType(Enum):
    """Types of obfuscation detected."""
    BASE64 = "base64"
    BASE64_REVERSED = "base64_reversed"
    POWERSHELL_ENCODED = "powershell_encoded"
    HEX_ENCODED = "hex"
    URL_ENCODED = "url"
    XOR_SINGLE_BYTE = "xor"
    STRING_CONCAT = "string_concat"
    CHAR_CODE = "char_code"
    BATCH_VAR_INDEX = "batch_var_index"
    ESCAPE_SEQUENCES = "escape"
    UNKNOWN = "unknown"


@dataclass
class DeobfuscationResult:
    """Result of a deobfuscation attempt."""

    success: bool
    obfuscation_type: ObfuscationType
    original: str
    decoded: Optional[str] = None
    confidence: float = 0.0  # 0.0 to 1.0
    layer: str = "static"  # Which layer performed the deobfuscation
    iocs_found: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    child_results: list["DeobfuscationResult"] = field(default_factory=list)

    def all_decoded_content(self) -> str:
        """Get all decoded content including nested results."""
        parts = []
        if self.decoded:
            parts.append(self.decoded)
        for child in self.child_results:
            parts.append(child.all_decoded_content())
        return "\n".join(parts)


# Common IOC patterns for extraction
IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    "url": re.compile(r'https?://[^\s<>"\']+'),
    "filepath_windows": re.compile(r'[A-Za-z]:\\[^\s<>"\'|*?]+'),
    "filepath_unc": re.compile(r'\\\\[^\s<>"\'|*?]+'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "registry": re.compile(r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s<>"\']+'),
}

# Suspicious command patterns
SUSPICIOUS_COMMANDS = [
    "powershell", "cmd", "wscript", "cscript", "mshta",
    "bitsadmin", "certutil", "regsvr32", "rundll32",
    "schtasks", "at ", "net user", "net localgroup",
    "whoami", "systeminfo", "ipconfig", "netstat",
    "tasklist", "wmic", "invoke-expression", "invoke-webrequest",
    "downloadstring", "downloadfile", "iex", "iwr",
    "start-process", "new-object", "system.net.webclient",
]


def extract_iocs(text: str) -> list[str]:
    """Extract IOCs from decoded text.

    Args:
        text: Decoded content to search

    Returns:
        List of found IOCs with type prefixes
    """
    iocs = []
    text_lower = text.lower()

    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group()
            # Filter out common false positives
            if ioc_type == "ipv4":
                # Skip localhost and common non-IOC IPs
                if value.startswith(("127.", "0.", "255.")):
                    continue
            iocs.append(f"{ioc_type}:{value}")

    # Check for suspicious commands
    for cmd in SUSPICIOUS_COMMANDS:
        if cmd in text_lower:
            iocs.append(f"command:{cmd}")

    return list(set(iocs))  # Deduplicate


def decode_base64(content: str, reversed_input: bool = False) -> DeobfuscationResult:
    """Decode Base64 encoded content.

    Args:
        content: The Base64 string to decode
        reversed_input: If True, reverse the string before decoding

    Returns:
        DeobfuscationResult with decoded content
    """
    obf_type = ObfuscationType.BASE64_REVERSED if reversed_input else ObfuscationType.BASE64

    try:
        # Clean up the input
        cleaned = content.strip()
        if reversed_input:
            cleaned = cleaned[::-1]

        # Try to decode
        decoded_bytes = base64.b64decode(cleaned)

        # Try UTF-8 first, then UTF-16 (common in PowerShell)
        try:
            decoded = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                decoded = decoded_bytes.decode('utf-16-le')
            except UnicodeDecodeError:
                decoded = decoded_bytes.decode('latin-1')

        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=obf_type,
            original=content,
            decoded=decoded,
            confidence=0.9,
            iocs_found=iocs,
        )

    except Exception as e:
        return DeobfuscationResult(
            success=False,
            obfuscation_type=obf_type,
            original=content,
            warnings=[f"Base64 decode failed: {str(e)}"],
            confidence=0.0,
        )


def decode_powershell_encoded(content: str) -> DeobfuscationResult:
    """Decode PowerShell -EncodedCommand content.

    PowerShell uses UTF-16LE Base64 for -EncodedCommand.

    Args:
        content: The encoded command string

    Returns:
        DeobfuscationResult with decoded content
    """
    # Extract the encoded portion if full command line
    pattern = r'-(?:e(?:nc(?:oded)?)?(?:command)?)\s+([A-Za-z0-9+/=]+)'
    match = re.search(pattern, content, re.IGNORECASE)

    encoded = match.group(1) if match else content.strip()

    try:
        decoded_bytes = base64.b64decode(encoded)
        decoded = decoded_bytes.decode('utf-16-le')
        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.POWERSHELL_ENCODED,
            original=content,
            decoded=decoded,
            confidence=0.95,
            iocs_found=iocs,
        )

    except Exception as e:
        return DeobfuscationResult(
            success=False,
            obfuscation_type=ObfuscationType.POWERSHELL_ENCODED,
            original=content,
            warnings=[f"PowerShell decode failed: {str(e)}"],
            confidence=0.0,
        )


def decode_hex(content: str) -> DeobfuscationResult:
    """Decode hex-encoded content.

    Args:
        content: Hex string (with or without 0x prefix, spaces)

    Returns:
        DeobfuscationResult with decoded content
    """
    try:
        # Remove common prefixes and separators
        cleaned = re.sub(r'[0x\s\\x,]', '', content)

        decoded_bytes = binascii.unhexlify(cleaned)

        try:
            decoded = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            decoded = decoded_bytes.decode('latin-1')

        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.HEX_ENCODED,
            original=content,
            decoded=decoded,
            confidence=0.85,
            iocs_found=iocs,
        )

    except Exception as e:
        return DeobfuscationResult(
            success=False,
            obfuscation_type=ObfuscationType.HEX_ENCODED,
            original=content,
            warnings=[f"Hex decode failed: {str(e)}"],
            confidence=0.0,
        )


def extract_and_decode_embedded_base64(content: str) -> DeobfuscationResult:
    """Extract and decode Base64 strings embedded in scripts.

    Handles patterns like:
    - $variable = "base64string"
    - var x = "base64string"
    - Also tries reversed base64 (common in malware)

    Args:
        content: Script content that may contain embedded base64

    Returns:
        DeobfuscationResult with decoded content
    """
    # Patterns for base64 strings in various languages
    patterns = [
        # PowerShell: $var = "base64"
        r'\$\w+\s*=\s*["\']([A-Za-z0-9+/]{50,}={0,2})["\']',
        # JavaScript: var x = "base64"
        r'(?:var|let|const)\s+\w+\s*=\s*["\']([A-Za-z0-9+/]{50,}={0,2})["\']',
        # Generic quoted base64
        r'["\']([A-Za-z0-9+/]{100,}={0,2})["\']',
    ]

    all_decoded = []
    all_iocs = []

    for pattern in patterns:
        for match in re.finditer(pattern, content):
            b64_string = match.group(1)

            def is_valid_decoded(text: str) -> bool:
                """Check if decoded text looks like valid script/text content."""
                if not text or len(text) < 10:
                    return False
                # Count ASCII printable (excluding replacement char)
                ascii_printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')
                ratio = ascii_printable / len(text)
                # Also check for common script keywords
                has_keywords = any(kw in text.lower() for kw in ['$', 'function', 'var', 'http', 'invoke', '='])
                return ratio > 0.85 or (ratio > 0.7 and has_keywords)

            best_decoded = None
            best_score = 0

            # Try reversed base64 first (common malware trick)
            try:
                reversed_b64 = b64_string[::-1]
                decoded_bytes = base64.b64decode(reversed_b64)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if is_valid_decoded(decoded):
                    score = sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded)
                    if score > best_score:
                        best_decoded = decoded
                        best_score = score
            except Exception:
                pass

            # Try direct decode
            try:
                decoded_bytes = base64.b64decode(b64_string)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if is_valid_decoded(decoded):
                    score = sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded)
                    if score > best_score:
                        best_decoded = decoded
                        best_score = score
            except Exception:
                pass

            # Try UTF-16LE decode (PowerShell EncodedCommand)
            try:
                decoded_bytes = base64.b64decode(b64_string)
                decoded = decoded_bytes.decode('utf-16-le', errors='ignore')
                if is_valid_decoded(decoded):
                    score = sum(1 for c in decoded if 32 <= ord(c) <= 126) / len(decoded)
                    if score > best_score:
                        best_decoded = decoded
                        best_score = score
            except Exception:
                pass

            if best_decoded:
                all_decoded.append(best_decoded)
                all_iocs.extend(extract_iocs(best_decoded))

    if all_decoded:
        combined = "\n\n---\n\n".join(all_decoded)
        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.BASE64,
            original=content,
            decoded=combined,
            confidence=0.85,
            iocs_found=list(set(all_iocs)),
        )

    return DeobfuscationResult(
        success=False,
        obfuscation_type=ObfuscationType.BASE64,
        original=content,
        warnings=["No embedded base64 strings found"],
        confidence=0.0,
    )


def decode_url(content: str) -> DeobfuscationResult:
    """Decode URL-encoded content.

    Args:
        content: URL-encoded string

    Returns:
        DeobfuscationResult with decoded content
    """
    try:
        decoded = urllib.parse.unquote(content)

        # Check if anything was actually decoded
        if decoded == content:
            return DeobfuscationResult(
                success=False,
                obfuscation_type=ObfuscationType.URL_ENCODED,
                original=content,
                warnings=["No URL encoding detected"],
                confidence=0.0,
            )

        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.URL_ENCODED,
            original=content,
            decoded=decoded,
            confidence=0.9,
            iocs_found=iocs,
        )

    except Exception as e:
        return DeobfuscationResult(
            success=False,
            obfuscation_type=ObfuscationType.URL_ENCODED,
            original=content,
            warnings=[f"URL decode failed: {str(e)}"],
            confidence=0.0,
        )


def decode_xor_single_byte(content: bytes, key: Optional[int] = None) -> DeobfuscationResult:
    """Decode single-byte XOR encoded content.

    If no key provided, attempts to brute force common keys.

    Args:
        content: Bytes to decode
        key: Optional XOR key (0-255)

    Returns:
        DeobfuscationResult with decoded content
    """
    def xor_decode(data: bytes, k: int) -> bytes:
        return bytes(b ^ k for b in data)

    def score_text(text: str) -> float:
        """Score how likely text is to be valid decoded content."""
        printable = sum(1 for c in text if c.isprintable() or c.isspace())
        return printable / len(text) if text else 0

    best_result = None
    best_score = 0

    keys_to_try = [key] if key is not None else range(256)

    for k in keys_to_try:
        try:
            decoded_bytes = xor_decode(content, k)
            decoded = decoded_bytes.decode('latin-1')
            score = score_text(decoded)

            if score > best_score:
                best_score = score
                best_result = (k, decoded)

        except Exception:
            continue

    if best_result and best_score > 0.7:
        key_used, decoded = best_result
        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.XOR_SINGLE_BYTE,
            original=content.hex(),
            decoded=decoded,
            confidence=best_score,
            iocs_found=iocs,
            warnings=[f"XOR key: 0x{key_used:02x}"],
        )

    return DeobfuscationResult(
        success=False,
        obfuscation_type=ObfuscationType.XOR_SINGLE_BYTE,
        original=content.hex() if isinstance(content, bytes) else str(content),
        warnings=["Could not find valid XOR key"],
        confidence=0.0,
    )


def decode_char_codes(content: str) -> DeobfuscationResult:
    """Decode character code obfuscation.

    Handles patterns like:
    - chr(72)+chr(101)+chr(108)+chr(108)+chr(111) (Python/PowerShell)
    - String.fromCharCode(72,101,108,108,111) (JavaScript)
    - [char]72+[char]101 (PowerShell)

    Args:
        content: String containing char code expressions

    Returns:
        DeobfuscationResult with decoded content
    """
    decoded_chars = []

    # Pattern: chr(N) or [char]N
    chr_pattern = r'(?:chr\(|[char])(\d+)\)?'
    # Pattern: fromCharCode(N,N,N)
    fromchar_pattern = r'String\.fromCharCode\(([\d,\s]+)\)'

    # Try chr() pattern
    chr_matches = re.findall(chr_pattern, content, re.IGNORECASE)
    if chr_matches:
        decoded_chars = [chr(int(c)) for c in chr_matches]

    # Try fromCharCode pattern
    fromchar_match = re.search(fromchar_pattern, content, re.IGNORECASE)
    if fromchar_match:
        codes = [int(c.strip()) for c in fromchar_match.group(1).split(',')]
        decoded_chars = [chr(c) for c in codes]

    if decoded_chars:
        decoded = ''.join(decoded_chars)
        iocs = extract_iocs(decoded)

        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.CHAR_CODE,
            original=content,
            decoded=decoded,
            confidence=0.9,
            iocs_found=iocs,
        )

    return DeobfuscationResult(
        success=False,
        obfuscation_type=ObfuscationType.CHAR_CODE,
        original=content,
        warnings=["No char code patterns found"],
        confidence=0.0,
    )


def decode_string_concat(content: str) -> DeobfuscationResult:
    """Decode string concatenation obfuscation.

    Handles patterns like:
    - "pow" + "ersh" + "ell"
    - 'c'+'m'+'d'
    - $a="pow";$b="ershell";$a+$b

    Args:
        content: String containing concatenation

    Returns:
        DeobfuscationResult with decoded content
    """
    # Remove string concatenation operators and quotes
    # Pattern matches quoted strings and concatenation operators
    pattern = r'["\']([^"\']*)["\']'
    matches = re.findall(pattern, content)

    if matches:
        decoded = ''.join(matches)
        iocs = extract_iocs(decoded)

        # Only report success if we found something substantial
        if len(decoded) > 3:
            return DeobfuscationResult(
                success=True,
                obfuscation_type=ObfuscationType.STRING_CONCAT,
                original=content,
                decoded=decoded,
                confidence=0.75,
                iocs_found=iocs,
            )

    return DeobfuscationResult(
        success=False,
        obfuscation_type=ObfuscationType.STRING_CONCAT,
        original=content,
        warnings=["No string concatenation patterns found"],
        confidence=0.0,
    )


def decode_batch_var_index(content: str) -> DeobfuscationResult:
    """Decode batch file variable indexing obfuscation.

    This handles the pattern where a batch file:
    1. Sets a variable with a scrambled alphabet
    2. Uses %VAR:~N,1% to extract single characters
    3. Chains variables to build commands

    Args:
        content: Batch file content

    Returns:
        DeobfuscationResult with decoded commands
    """
    # Extract ASCII content if there's encoding issues
    ascii_content = ''.join(c for c in content if ord(c) < 128 or c in '\n\r\t')

    # Find all SET commands: set "VAR=value" or set VAR=value
    variables = {}
    set_pattern = r'set\s+"?([^"=\s]+)=([^"\n\r]+)"?'

    # First pass: find initial variable assignments
    for match in re.finditer(set_pattern, ascii_content, re.IGNORECASE):
        var_name = match.group(1).strip()
        var_value = match.group(2).strip().rstrip('"')
        if var_name and var_value:
            variables[var_name] = var_value

    def expand_var_refs(text: str, vars_dict: dict, depth: int = 0) -> str:
        """Expand %VAR:~N,L% patterns recursively."""
        if depth > 20:  # Prevent infinite recursion
            return text

        result = []
        i = 0
        while i < len(text):
            if text[i] == '%':
                # Find closing %
                end = text.find('%', i + 1)
                if end > i:
                    ref = text[i + 1:end]
                    # Check for :~N,L pattern
                    colon_pos = ref.find(':~')
                    if colon_pos >= 0:
                        var_name = ref[:colon_pos]
                        index_match = re.match(r'(\d+),(\d+)', ref[colon_pos + 2:])
                        if index_match:
                            start_idx = int(index_match.group(1))
                            length = int(index_match.group(2))
                            # Find variable (case-insensitive partial match)
                            var_val = None
                            for vn, vv in vars_dict.items():
                                if var_name.lower() in vn.lower() or vn.lower() in var_name.lower():
                                    var_val = vv
                                    break
                            if var_val and start_idx < len(var_val):
                                result.append(var_val[start_idx:start_idx + length])
                                i = end + 1
                                continue
                    # Simple variable reference
                    elif ref in vars_dict:
                        result.append(vars_dict[ref])
                        i = end + 1
                        continue
            result.append(text[i])
            i += 1

        expanded = ''.join(result)

        # Check for new SET commands and recurse
        for match in re.finditer(set_pattern, expanded, re.IGNORECASE):
            var_name = match.group(1).strip()
            var_value = match.group(2).strip().rstrip('"')
            if var_name and var_value:
                vars_dict[var_name] = var_value

        # Recurse if there are still unexpanded patterns
        if '%' in expanded and ':~' in expanded:
            return expand_var_refs(expanded, vars_dict, depth + 1)

        return expanded

    # Process line by line
    decoded_lines = []
    all_commands = []

    for line in ascii_content.split('\n'):
        line = line.strip()
        if not line:
            continue

        expanded = expand_var_refs(line, variables)
        decoded_lines.append(expanded)

        # Extract non-SET commands
        if expanded.strip() and 'set' not in expanded.lower()[:10]:
            # Clean up the command
            cmd = expanded.strip()
            if cmd and not cmd.startswith('@') and not cmd.startswith('::'):
                all_commands.append(cmd)

    decoded_content = '\n'.join(decoded_lines)

    # Extract IOCs from decoded content
    iocs = []
    # IPs
    for ip_match in re.finditer(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decoded_content):
        iocs.append(('ip', ip_match.group()))
    # URLs
    for url_match in re.finditer(r'https?://[^\s"\'<>]+', decoded_content):
        iocs.append(('url', url_match.group()))
    # Domains
    for domain_match in re.finditer(r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}', decoded_content):
        iocs.append(('domain', domain_match.group()))

    # Convert to flat IOC list
    iocs_flat = [ioc[1] for ioc in iocs]

    if decoded_content != ascii_content or all_commands or iocs:
        return DeobfuscationResult(
            success=True,
            obfuscation_type=ObfuscationType.BATCH_VAR_INDEX,
            original=content,
            decoded=decoded_content,
            iocs_found=iocs_flat,
            confidence=0.7 if iocs else 0.5,
        )

    return DeobfuscationResult(
        success=False,
        obfuscation_type=ObfuscationType.BATCH_VAR_INDEX,
        original=content,
        warnings=["Could not decode batch variable indexing"],
        confidence=0.0,
    )


def detect_obfuscation_type(content: str) -> list[ObfuscationType]:
    """Detect what types of obfuscation are present in content.

    Args:
        content: Content to analyze

    Returns:
        List of detected obfuscation types
    """
    detected = []
    content_lower = content.lower()

    # Base64 patterns
    base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
    if re.match(base64_pattern, content.strip()):
        detected.append(ObfuscationType.BASE64)

    # Reversed base64 (check if reversed version looks like base64)
    reversed_content = content.strip()[::-1]
    if re.match(base64_pattern, reversed_content):
        detected.append(ObfuscationType.BASE64_REVERSED)

    # PowerShell encoded command
    if re.search(r'-e(?:nc(?:oded)?)?(?:command)?\s+[A-Za-z0-9+/=]{20,}', content_lower):
        detected.append(ObfuscationType.POWERSHELL_ENCODED)

    # Hex encoding
    if re.match(r'^(?:0x)?[0-9a-fA-F]{10,}$', content.strip().replace(' ', '')):
        detected.append(ObfuscationType.HEX_ENCODED)

    # URL encoding
    if '%' in content and re.search(r'%[0-9a-fA-F]{2}', content):
        detected.append(ObfuscationType.URL_ENCODED)

    # Char code patterns
    if re.search(r'chr\(\d+\)|fromCharCode|\[char\]\d+', content_lower):
        detected.append(ObfuscationType.CHAR_CODE)

    # String concatenation
    if re.search(r'["\'][^"\']{1,20}["\']\s*\+\s*["\']', content):
        detected.append(ObfuscationType.STRING_CONCAT)

    # Batch variable indexing
    if re.search(r'%[^%]+:~\d+,\d+%', content):
        detected.append(ObfuscationType.BATCH_VAR_INDEX)

    return detected if detected else [ObfuscationType.UNKNOWN]


def deobfuscate_static(content: str) -> DeobfuscationResult:
    """Attempt to deobfuscate content using all static methods.

    Args:
        content: Content to deobfuscate

    Returns:
        DeobfuscationResult with best decoded content
    """
    detected_types = detect_obfuscation_type(content)

    results = []

    # Always try embedded base64 extraction for script-like content
    if len(content) > 100:  # Only for longer content
        embedded_result = extract_and_decode_embedded_base64(content)
        if embedded_result.success:
            results.append(embedded_result)

    for obf_type in detected_types:
        if obf_type == ObfuscationType.BASE64:
            results.append(decode_base64(content))

        elif obf_type == ObfuscationType.BASE64_REVERSED:
            results.append(decode_base64(content, reversed_input=True))

        elif obf_type == ObfuscationType.POWERSHELL_ENCODED:
            results.append(decode_powershell_encoded(content))

        elif obf_type == ObfuscationType.HEX_ENCODED:
            results.append(decode_hex(content))

        elif obf_type == ObfuscationType.URL_ENCODED:
            results.append(decode_url(content))

        elif obf_type == ObfuscationType.CHAR_CODE:
            results.append(decode_char_codes(content))

        elif obf_type == ObfuscationType.STRING_CONCAT:
            results.append(decode_string_concat(content))

        elif obf_type == ObfuscationType.BATCH_VAR_INDEX:
            results.append(decode_batch_var_index(content))

    # Return best result or aggregate
    successful = [r for r in results if r.success]

    if not successful:
        return DeobfuscationResult(
            success=False,
            obfuscation_type=ObfuscationType.UNKNOWN,
            original=content,
            warnings=["No static deobfuscation method succeeded"],
            confidence=0.0,
            child_results=results,
        )

    # Return highest confidence result
    best = max(successful, key=lambda r: r.confidence)

    # Check if decoded content needs further deobfuscation
    if best.decoded:
        nested_types = detect_obfuscation_type(best.decoded)
        if nested_types != [ObfuscationType.UNKNOWN]:
            nested_result = deobfuscate_static(best.decoded)
            best.child_results.append(nested_result)
            # Merge IOCs
            best.iocs_found.extend(nested_result.iocs_found)
            best.iocs_found = list(set(best.iocs_found))

    return best
