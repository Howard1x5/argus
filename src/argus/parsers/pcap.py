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
                # HTTP request fields
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "http.host",
                "-e", "http.user_agent",
                # HTTP response fields (S2.1)
                "-e", "http.response.code",
                "-e", "http.content_type",
                "-e", "http.content_length",
                # DNS fields (S2.3)
                "-e", "dns.qry.name",
                "-e", "dns.qry.type",
                "-e", "dns.flags.rcode",
                "-e", "dns.resp.ttl",
                "-e", "dns.a",
                "-e", "dns.aaaa",
                "-e", "dns.txt",
                "-e", "dns.cname",
                "-e", "dns.mx.mail_exchange",
                # TLS fields (S2.5)
                "-e", "tls.handshake.extensions_server_name",
                "-e", "tls.handshake.ja3",
                "-e", "tls.handshake.ja3s",
                "-e", "tls.handshake.ja3_full",
                # Kerberos fields (S2.4)
                "-e", "kerberos.msg_type",
                "-e", "kerberos.CNameString",
                "-e", "kerberos.SNameString",
                "-e", "kerberos.etype",
                "-e", "kerberos.realm",
                # SMB2 fields for file transfer and share enumeration
                "-e", "smb2.tree",
                "-e", "smb2.filename",
                "-e", "smb2.write_length",
                "-e", "smb2.cmd",
                "-e", "smb2.flags",
                # SMB1 fields for backwards compatibility
                "-e", "smb.path",
                "-e", "smb.file",
                "-e", "smb.cmd",
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

        # HTTP request fields
        event.http_method = layers.get("http_request_method", [None])[0]
        event.uri = layers.get("http_request_uri", [None])[0]
        event.user_agent = layers.get("http_user_agent", [None])[0]

        # HTTP response fields (S2.1)
        http_response_code = layers.get("http_response_code", [None])[0]
        http_content_type = layers.get("http_content_type", [None])[0]
        http_content_length = layers.get("http_content_length", [None])[0]

        # HTTP host (for URL construction)
        http_host = layers.get("http_host", [None])[0]
        if http_host and event.uri:
            event.uri = f"http://{http_host}{event.uri}"

        # Store HTTP response data in raw_payload as JSON if present
        if http_response_code or http_content_type:
            http_data = {
                "response_code": http_response_code,
                "content_type": http_content_type,
                "content_length": http_content_length,
            }
            http_data = {k: v for k, v in http_data.items() if v is not None}
            if http_data:
                event.raw_payload = json.dumps(http_data)

        # DNS extended fields (S2.3)
        dns_query = layers.get("dns_qry_name", [None])[0]
        dns_query_type = layers.get("dns_qry_type", [None])[0]
        dns_rcode = layers.get("dns_flags_rcode", [None])[0]
        dns_ttl = layers.get("dns_resp_ttl", [None])[0]
        dns_a = layers.get("dns_a", [None])[0]
        dns_aaaa = layers.get("dns_aaaa", [None])[0]
        dns_txt = layers.get("dns_txt", [None])[0]
        dns_cname = layers.get("dns_cname", [None])[0]
        dns_mx = layers.get("dns_mx_mail_exchange", [None])[0]

        if dns_query:
            event.uri = dns_query
            event.event_type = "PCAP_DNS"
            dns_data = {
                "query_name": dns_query,
                "query_type": dns_query_type,
                "rcode": dns_rcode,
                "ttl": dns_ttl,
                "a_record": dns_a,
                "aaaa_record": dns_aaaa,
                "txt_record": dns_txt,
                "cname": dns_cname,
                "mx_record": dns_mx,
            }
            dns_data = {k: v for k, v in dns_data.items() if v is not None}
            if dns_data:
                event.raw_payload = json.dumps(dns_data)

        # TLS fields with JA3/JA3S (S2.5)
        tls_sni = layers.get("tls_handshake_extensions_server_name", [None])[0]
        ja3 = layers.get("tls_handshake_ja3", [None])[0]
        ja3s = layers.get("tls_handshake_ja3s", [None])[0]
        ja3_full = layers.get("tls_handshake_ja3_full", [None])[0]

        if tls_sni or ja3 or ja3s:
            event.event_type = "PCAP_TLS"
            if tls_sni:
                event.uri = tls_sni
            tls_data = {
                "sni": tls_sni,
                "ja3": ja3,
                "ja3s": ja3s,
                "ja3_full": ja3_full,
            }
            tls_data = {k: v for k, v in tls_data.items() if v is not None}
            if tls_data:
                event.raw_payload = json.dumps(tls_data)

        # Kerberos fields (S2.4)
        krb_msg_type = layers.get("kerberos_msg_type", [None])[0]
        krb_cname = layers.get("kerberos_CNameString", [None])[0]
        krb_sname = layers.get("kerberos_SNameString", [None])[0]
        krb_etype = layers.get("kerberos_etype", [None])[0]
        krb_realm = layers.get("kerberos_realm", [None])[0]

        if krb_msg_type or krb_cname or krb_sname:
            event.event_type = "PCAP_KERBEROS"
            krb_data = {
                "msg_type": krb_msg_type,
                "cname": krb_cname,
                "sname": krb_sname,
                "etype": krb_etype,
                "realm": krb_realm,
            }
            krb_data = {k: v for k, v in krb_data.items() if v is not None}
            if krb_data:
                event.raw_payload = json.dumps(krb_data)

        # SMB2 fields
        smb2_tree = layers.get("smb2_tree", [None])[0]
        smb2_filename = layers.get("smb2_filename", [None])[0]
        smb2_write_length = layers.get("smb2_write_length", [None])[0]
        smb2_cmd = layers.get("smb2_cmd", [None])[0]

        # SMB1 fields (fallback)
        smb_path = layers.get("smb_path", [None])[0]
        smb_file = layers.get("smb_file", [None])[0]
        smb_cmd = layers.get("smb_cmd", [None])[0]

        # Use SMB2 first, fallback to SMB1
        smb_tree_path = smb2_tree or smb_path
        smb_filename = smb2_filename or smb_file

        if smb_tree_path or smb_filename:
            event.event_type = "PCAP_SMB"
            # Store SMB-specific data in raw_payload as JSON
            smb_data = {
                "tree_path": smb_tree_path,
                "filename": smb_filename,
                "write_length": smb2_write_length,
                "smb_cmd": smb2_cmd or smb_cmd,
            }
            # Filter out None values
            smb_data = {k: v for k, v in smb_data.items() if v is not None}
            if smb_data:
                event.raw_payload = json.dumps(smb_data)
                # Also store in URI for easier access
                if smb_filename:
                    event.uri = smb_filename
                elif smb_tree_path:
                    event.uri = smb_tree_path
        else:
            # Store protocols string for non-SMB packets
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

        if "smb" in protocols_lower or "smb2" in protocols_lower:
            return "SMB"
        elif "http" in protocols_lower:
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
