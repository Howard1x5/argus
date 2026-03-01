"""File type auto-detection for ARGUS.

Automatically detects evidence file types and selects appropriate parsers.
Supports custom parsers from ~/.argus/custom_parsers/ and LLM-powered
auto-generation for unknown formats.
"""

from pathlib import Path
from typing import Optional, Type

from argus.parsers.base import BaseParser, ParseResult


# Import all parsers
from argus.parsers.excel import ExcelParser
from argus.parsers.evtx import EvtxParser
from argus.parsers.iis import IISParser
from argus.parsers.csv_parser import CSVParser
from argus.parsers.weblog import ApacheParser, NginxParser
from argus.parsers.zeek import ZeekParser
from argus.parsers.pcap import PCAPParser
from argus.parsers.cloud.cloudtrail import CloudTrailParser
from argus.parsers.cloud.azure_ad import AzureADParser
from argus.parsers.cloud.gcp import GCPAuditParser

# New parsers
from argus.parsers.registry import RegistryParser
from argus.parsers.prefetch import PrefetchParser
from argus.parsers.memory import MemoryParser
from argus.parsers.syslog import SyslogParser
from argus.parsers.jsonl import JSONLinesParser
from argus.parsers.suricata import SuricataParser
from argus.parsers.firewall import WindowsFirewallParser

# Additional parsers
from argus.parsers.proxy import SquidParser
from argus.parsers.paloalto import PaloAltoParser
from argus.parsers.cisco import CiscoASAParser
from argus.parsers.defender import DefenderParser
from argus.parsers.o365 import O365Parser
from argus.parsers.vpcflow import VPCFlowParser
from argus.parsers.shimcache import ShimcacheParser
from argus.parsers.browser import BrowserHistoryParser
from argus.parsers.haproxy import HAProxyParser
from argus.parsers.okta import OktaParser


# Ordered list of parsers to try (more specific parsers first)
PARSERS: list[Type[BaseParser]] = [
    # Binary formats (check magic bytes first)
    EvtxParser,
    PCAPParser,
    RegistryParser,
    PrefetchParser,
    MemoryParser,
    BrowserHistoryParser,  # SQLite browser databases

    # Excel (specific extension and format)
    ExcelParser,

    # Windows forensic artifacts
    ShimcacheParser,
    DefenderParser,

    # IDS/IPS logs (before generic JSON)
    SuricataParser,

    # Firewall logs
    PaloAltoParser,
    CiscoASAParser,
    WindowsFirewallParser,

    # Web server and proxy logs
    IISParser,
    ApacheParser,
    NginxParser,
    HAProxyParser,
    SquidParser,
    ZeekParser,

    # Syslog (before generic text)
    SyslogParser,

    # Cloud/Identity logs (JSON with specific structure)
    CloudTrailParser,
    AzureADParser,
    GCPAuditParser,
    O365Parser,
    OktaParser,
    VPCFlowParser,

    # JSON Lines (after specific JSON formats)
    JSONLinesParser,

    # Generic CSV (fallback for CSV files)
    CSVParser,
]


def _get_all_parsers() -> list[Type[BaseParser]]:
    """Get all parsers including custom ones.

    Returns:
        List of all parser classes (built-in + custom)
    """
    from argus.parsers.generator import load_all_custom_parsers

    all_parsers = list(PARSERS)

    # Load custom parsers and prepend them (they get priority)
    try:
        custom = load_all_custom_parsers()
        all_parsers = custom + all_parsers
    except Exception:
        pass

    return all_parsers


def detect_parser(
    file_path: Path,
    include_custom: bool = True,
) -> Optional[Type[BaseParser]]:
    """Detect the appropriate parser for a file.

    Args:
        file_path: Path to the evidence file
        include_custom: Whether to include custom parsers from ~/.argus/custom_parsers/

    Returns:
        Parser class that can handle the file, or None if no parser matches
    """
    parsers = _get_all_parsers() if include_custom else PARSERS

    for parser_class in parsers:
        try:
            if parser_class.can_parse(file_path):
                return parser_class
        except Exception:
            # Parser check failed, try next
            continue
    return None


def parse_file(
    file_path: Path,
    auto_generate: bool = False,
    format_name: Optional[str] = None,
) -> ParseResult:
    """Parse an evidence file using auto-detected parser.

    Args:
        file_path: Path to the evidence file
        auto_generate: If True, generate a parser using LLM when none matches
        format_name: Name for auto-generated parser (derived from filename if not provided)

    Returns:
        ParseResult with events or errors
    """
    parser_class = detect_parser(file_path)

    if parser_class is None:
        if auto_generate:
            # Try to generate a parser
            try:
                from argus.parsers.generator import generate_and_save_parser

                parser_path, parser_class = generate_and_save_parser(
                    file_path, format_name
                )
                result = ParseResult(file_path)
                result.metadata["auto_generated_parser"] = str(parser_path)
            except Exception as e:
                result = ParseResult(file_path)
                result.add_error(f"Failed to auto-generate parser: {e}")
                result.metadata["detected_parser"] = None
                return result
        else:
            # Return error result for unknown format
            result = ParseResult(file_path)
            result.add_error(f"Unknown file format: {file_path.suffix}")
            result.metadata["detected_parser"] = None
            return result

    parser = parser_class()
    result = parser.parse(file_path)
    result.metadata["detected_parser"] = parser_class.name

    return result


def get_supported_formats(include_custom: bool = True) -> dict[str, str]:
    """Get dictionary of supported file formats and their descriptions.

    Args:
        include_custom: Whether to include custom parsers

    Returns:
        Dict mapping format name to description
    """
    parsers = _get_all_parsers() if include_custom else PARSERS
    formats = {}
    for parser_class in parsers:
        formats[parser_class.name] = parser_class.description
    return formats


def get_parser_for_extension(
    extension: str,
    include_custom: bool = True,
) -> list[Type[BaseParser]]:
    """Get parsers that support a given file extension.

    Args:
        extension: File extension (e.g., '.log', '.xlsx')
        include_custom: Whether to include custom parsers

    Returns:
        List of parser classes that might handle files with this extension
    """
    parsers = _get_all_parsers() if include_custom else PARSERS
    ext = extension.lower()
    if not ext.startswith("."):
        ext = f".{ext}"

    matching = []
    for parser_class in parsers:
        if ext in parser_class.supported_extensions:
            matching.append(parser_class)
    return matching


def list_custom_parsers() -> list[dict]:
    """List all custom parsers.

    Returns:
        List of dicts with parser info (name, description, path)
    """
    from argus.parsers.generator import CUSTOM_PARSERS_DIR, load_all_custom_parsers

    result = []
    if not CUSTOM_PARSERS_DIR.exists():
        return result

    for parser_class in load_all_custom_parsers():
        result.append({
            "name": parser_class.name,
            "description": parser_class.description,
            "extensions": parser_class.supported_extensions,
        })

    return result
