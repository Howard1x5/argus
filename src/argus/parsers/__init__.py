"""Evidence parsers for ARGUS.

Each parser normalizes evidence files to the unified event schema.
"""

from argus.parsers.base import (
    BaseParser,
    ParseResult,
    UnifiedEvent,
    EventSeverity,
    PARQUET_SCHEMA,
)

from argus.parsers.detector import (
    detect_parser,
    parse_file,
    get_supported_formats,
    get_parser_for_extension,
    list_custom_parsers,
    PARSERS,
)
from argus.parsers.generator import (
    generate_parser_code,
    generate_and_save_parser,
    load_custom_parser,
    load_all_custom_parsers,
    CUSTOM_PARSERS_DIR,
)

# Import all parser classes
from argus.parsers.excel import ExcelParser
from argus.parsers.evtx import EvtxParser
from argus.parsers.iis import IISParser
from argus.parsers.csv_parser import CSVParser
from argus.parsers.weblog import ApacheParser, NginxParser
from argus.parsers.zeek import ZeekParser
from argus.parsers.pcap import PCAPParser
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

# Cloud parsers
from argus.parsers.cloud.cloudtrail import CloudTrailParser
from argus.parsers.cloud.azure_ad import AzureADParser
from argus.parsers.cloud.gcp import GCPAuditParser

__all__ = [
    # Base classes
    "BaseParser",
    "ParseResult",
    "UnifiedEvent",
    "EventSeverity",
    "PARQUET_SCHEMA",
    # Detection
    "detect_parser",
    "parse_file",
    "get_supported_formats",
    "get_parser_for_extension",
    "list_custom_parsers",
    "PARSERS",
    # Generator
    "generate_parser_code",
    "generate_and_save_parser",
    "load_custom_parser",
    "load_all_custom_parsers",
    "CUSTOM_PARSERS_DIR",
    # Parsers
    "ExcelParser",
    "EvtxParser",
    "IISParser",
    "CSVParser",
    "ApacheParser",
    "NginxParser",
    "ZeekParser",
    "PCAPParser",
    "RegistryParser",
    "PrefetchParser",
    "MemoryParser",
    "SyslogParser",
    "JSONLinesParser",
    "SuricataParser",
    "WindowsFirewallParser",
    # Additional parsers
    "SquidParser",
    "PaloAltoParser",
    "CiscoASAParser",
    "DefenderParser",
    "O365Parser",
    "VPCFlowParser",
    "ShimcacheParser",
    "BrowserHistoryParser",
    "HAProxyParser",
    "OktaParser",
    # Cloud parsers
    "CloudTrailParser",
    "AzureADParser",
    "GCPAuditParser",
]
