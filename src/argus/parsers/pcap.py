"""PCAP network capture parser for ARGUS.

Parses PCAP/PCAPNG files using tshark subprocess.
"""

import json
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.parsers.base import BaseParser, ParseResult, UnifiedEvent, EventSeverity


class PCAPParser(BaseParser):
    """Parser for PCAP/PCAPNG files using tshark."""

    name = "pcap"
    description = "Network packet captures (PCAP/PCAPNG)"
    supported_extensions = [".pcap", ".pcapng", ".cap"]

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this is a PCAP file and tshark is available."""
        if file_path.suffix.lower() not in cls.supported_extensions:
            return False

        # Check magic bytes
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                # PCAP magic: d4 c3 b2 a1 or a1 b2 c3 d4
                # PCAPNG magic: 0a 0d 0d 0a
                pcap_magic = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
                pcapng_magic = magic == b"\x0a\x0d\x0d\x0a"
                return pcap_magic or pcapng_magic
        except Exception:
            return False

    @classmethod
    def is_tshark_available(cls) -> bool:
        """Check if tshark is installed."""
        return shutil.which("tshark") is not None

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a PCAP file using tshark."""
        result = self._create_result(file_path)

        if not self.is_tshark_available():
            result.add_error("tshark not found. Install Wireshark/tshark to parse PCAP files.")
            return result

        try:
            # Run tshark to extract packet info as JSON
            cmd = [
                "tshark",
                "-r", str(file_path),
                "-T", "ek",  # Elasticsearch/JSON format
                "-e", "frame.time_epoch",
                "-e", "frame.number",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "frame.protocols",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "http.host",
                "-e", "http.user_agent",
                "-e", "dns.qry.name",
                "-e", "dns.a",
                "-e", "tls.handshake.extensions_server_name",
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if proc.returncode != 0:
                result.add_error(f"tshark failed: {proc.stderr}")
                return result

            # Parse JSON lines output
            line_num = 0
            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue

                line_num += 1
                try:
                    data = json.loads(line)
                    # Skip index lines (tshark EK format)
                    if "index" in data:
                        continue

                    event = self._parse_packet(data, line_num, file_path.name)
                    if event:
                        result.add_event(event)
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    result.add_warning(f"Packet {line_num}: {str(e)}")

            result.metadata["packet_count"] = len(result.events)

        except subprocess.TimeoutExpired:
            result.add_error("tshark timed out processing PCAP file")
        except Exception as e:
            result.add_error(f"Failed to parse PCAP: {str(e)}")

        return result

    def _parse_packet(
        self, data: dict, line_num: int, source_file: str
    ) -> Optional[UnifiedEvent]:
        """Parse a single packet from tshark output."""
        layers = data.get("layers", {})

        # Get timestamp
        timestamp = self._parse_timestamp(layers.get("frame_time_epoch", [None])[0])
        if not timestamp:
            return None

        # Get protocol info
        protocols = layers.get("frame_protocols", [""])[0]
        event_type = self._determine_event_type(protocols)

        event = UnifiedEvent(
            timestamp_utc=timestamp,
            source_file=source_file,
            source_line=line_num,
            event_type=f"PCAP_{event_type}",
            severity=EventSeverity.INFO,
            parser_name=self.name,
        )

        # Network fields
        src_ip = layers.get("ip_src", [None])[0]
        dst_ip = layers.get("ip_dst", [None])[0]
        event.source_ip = src_ip
        event.dest_ip = dst_ip

        # Ports (TCP or UDP)
        src_port = layers.get("tcp_srcport", [None])[0] or layers.get("udp_srcport", [None])[0]
        dst_port = layers.get("tcp_dstport", [None])[0] or layers.get("udp_dstport", [None])[0]

        if src_port:
            try:
                event.source_port = int(src_port)
            except (ValueError, TypeError):
                pass

        if dst_port:
            try:
                event.dest_port = int(dst_port)
            except (ValueError, TypeError):
                pass

        # HTTP fields
        event.http_method = layers.get("http_request_method", [None])[0]
        event.uri = layers.get("http_request_uri", [None])[0]
        event.user_agent = layers.get("http_user_agent", [None])[0]

        # HTTP host (for URL construction)
        http_host = layers.get("http_host", [None])[0]
        if http_host and event.uri:
            event.uri = f"http://{http_host}{event.uri}"

        # DNS query
        dns_query = layers.get("dns_qry_name", [None])[0]
        if dns_query:
            event.uri = dns_query
            event.event_type = "PCAP_DNS"

        # TLS SNI
        tls_sni = layers.get("tls_handshake_extensions_server_name", [None])[0]
        if tls_sni:
            event.uri = tls_sni
            event.event_type = "PCAP_TLS"

        # Store protocols string
        event.raw_payload = protocols

        return event

    def _parse_timestamp(self, epoch_str: Optional[str]) -> Optional[datetime]:
        """Parse Unix epoch timestamp."""
        if not epoch_str:
            return None

        try:
            epoch = float(epoch_str)
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (ValueError, TypeError):
            return None

    def _determine_event_type(self, protocols: str) -> str:
        """Determine event type from protocol string."""
        protocols_lower = protocols.lower()

        if "http" in protocols_lower:
            return "HTTP"
        elif "dns" in protocols_lower:
            return "DNS"
        elif "tls" in protocols_lower or "ssl" in protocols_lower:
            return "TLS"
        elif "tcp" in protocols_lower:
            return "TCP"
        elif "udp" in protocols_lower:
            return "UDP"
        elif "icmp" in protocols_lower:
            return "ICMP"
        elif "arp" in protocols_lower:
            return "ARP"
        return "OTHER"
