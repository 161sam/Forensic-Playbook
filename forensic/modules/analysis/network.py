#!/usr/bin/env python3
"""Network analysis module with optional PCAP extra.

This module expands the network analysis capabilities by extracting
flow, DNS and HTTP information from a PCAP file. The heavy lifting is
performed by optional dependencies which are exposed through the
``pcap`` extra (``pip install forensic-playbook[pcap]``). When the
extra is not installed the module emits a warning and exits
successfully without doing any intensive processing, satisfying the
"optional extra" requirement.
"""

from __future__ import annotations

import json
import math
import re
import struct
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable as IterableABC
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ...core.evidence import Evidence
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat, utc_slug

try:  # pragma: no cover - optional dependency
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    pyshark = None  # type: ignore

try:  # pragma: no cover - optional dependency
    from scapy.all import (  # type: ignore
        DNS,
        IP,
        TCP,
        UDP,
        IPv6,
        rdpcap,
    )
except ImportError:  # pragma: no cover - optional dependency
    DNS = IP = IPv6 = TCP = UDP = rdpcap = None  # type: ignore

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "TRACE",
    "CONNECT",
}

SUSPICIOUS_USER_AGENTS = {
    "curl",
    "python-requests",
    "wget",
    "powershell",
}

ENCODED_URI_PATTERN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class FlowAccumulator:
    packets: int = 0
    bytes: int = 0
    start_ts: float = field(default_factory=lambda: float("inf"))
    end_ts: float = field(default_factory=lambda: float("-inf"))

    def update(self, timestamp: float, packet_len: int) -> None:
        self.packets += 1
        self.bytes += packet_len
        if timestamp < self.start_ts:
            self.start_ts = timestamp
        if timestamp > self.end_ts:
            self.end_ts = timestamp


class NetworkAnalysisModule(AnalysisModule):
    """Perform flow, DNS and HTTP analysis on PCAP captures."""

    @property
    def name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Extract network flows, DNS queries and HTTP metadata from PCAP files."

    @property
    def requires_root(self) -> bool:
        return False

    def _config_defaults(self) -> Dict[str, Any]:
        return self._module_config("network")

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()

        for key in ("pcap", "pcap_json"):
            if params.get(key):
                continue
            default_value = defaults.get(key)
            if default_value:
                params[key] = default_value

        has_pcap = "pcap" in params and params["pcap"]
        has_pcap_json = "pcap_json" in params and params["pcap_json"]

        if not has_pcap and not has_pcap_json:
            self.logger.error("Missing required parameter: pcap or pcap_json")
            return False

        if has_pcap:
            pcap_path = Path(params["pcap"])
            if not pcap_path.exists():
                self.logger.error(f"PCAP file does not exist: {pcap_path}")
                return False

        if has_pcap_json:
            json_source = params["pcap_json"]
            if json_source != "-":
                json_path = Path(json_source)
                if not json_path.exists():
                    self.logger.error(
                        f"PCAP JSON file does not exist: {json_path}"
                    )
                    return False

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        slug = utc_slug()

        pcap_path = params.get("pcap")
        pcap_file = Path(pcap_path) if pcap_path else None
        pcap_json_source = params.get("pcap_json")

        output_root = self.output_dir / slug
        metadata: Dict[str, Any] = {"generated_at": timestamp}

        if pcap_file is not None:
            metadata["pcap_file"] = str(pcap_file)
            try:
                metadata["pcap_size"] = pcap_file.stat().st_size
            except FileNotFoundError:
                metadata["pcap_size"] = None
        else:
            metadata["pcap_file"] = None
            metadata["pcap_size"] = None

        fallback_used = False
        has_extra = rdpcap is not None or pyshark is not None
        metadata["pcap_extra_available"] = has_extra

        if pcap_json_source:
            try:
                (
                    json_flows,
                    json_dns,
                    json_http,
                    json_origin,
                ) = self._load_pcap_json_input(pcap_json_source)
            except ValueError as exc:
                message = f"Failed to load PCAP JSON input: {exc}"
                metadata["pcap_json_error"] = str(exc)
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    metadata=metadata,
                    errors=[message],
                )

            metadata["pcap_json_source"] = json_origin
            metadata["pcap_json_mode"] = True

            flows_list = self._sort_flow_records(json_flows)
            dns_summary = self._summarise_dns(json_dns)
            http_summary = self._summarise_http(json_http)
        else:
            if pcap_file is None:
                message = "PCAP file is required when no PCAP JSON is provided"
                metadata["pcap_error"] = message
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    metadata=metadata,
                    errors=[message],
                )

            flows: Dict[
                Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
            ] = defaultdict(FlowAccumulator)
            dns_queries: List[Dict[str, Any]] = []
            http_requests: List[Dict[str, Any]] = []

            if rdpcap is not None:
                packets = rdpcap(str(pcap_file))
                self._process_scapy_packets(
                    packets, flows, dns_queries, http_requests
                )
            elif pyshark is not None:
                self._process_pyshark_capture(
                    str(pcap_file), flows, dns_queries, http_requests
                )
            else:
                fallback_used = True
                metadata["fallback_parser"] = "builtin"
                try:
                    self._process_builtin_packets(
                        pcap_file, flows, dns_queries, http_requests
                    )
                except Exception as exc:  # pragma: no cover - defensive path
                    message = (
                        "Failed to analyse PCAP without optional dependencies:"
                        f" {exc}"
                    )
                    metadata["fallback_error"] = str(exc)
                    return ModuleResult(
                        result_id=result_id,
                        module_name=self.name,
                        status="failed",
                        timestamp=timestamp,
                        metadata=metadata,
                        errors=[message],
                    )

            flows_list = self._serialise_flows(flows)
            dns_summary = self._summarise_dns(dns_queries)
            http_summary = self._summarise_http(http_requests)

        output_root.mkdir(parents=True, exist_ok=True)
        output_file = output_root / "network.json"
        payload = {
            "metadata": metadata,
            "flows": flows_list,
            "dns": dns_summary,
            "http": http_summary,
        }

        with output_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

        findings = [
            {
                "type": "network_analysis",
                "description": "Extracted flows, DNS queries and HTTP metadata",
                "flow_count": len(flows_list),
                "dns_query_count": len(dns_summary["queries"]),
                "http_request_count": len(http_summary["requests"]),
                "output_file": str(output_file),
            }
        ]

        if fallback_used:
            findings.append(
                {
                    "type": "info",
                    "severity": "info",
                    "description": "Parsed PCAP using built-in lightweight parser",
                }
            )

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status="success",
            timestamp=timestamp,
            output_path=output_file,
            findings=findings,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # JSON/utility helpers
    # ------------------------------------------------------------------
    def _load_pcap_json_input(
        self, source: str
    ) -> Tuple[
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        str,
    ]:
        if source == "-":
            raw = sys.stdin.read()
            origin = "stdin"
        else:
            json_path = Path(source)
            raw = json_path.read_text(encoding="utf-8")
            origin = str(json_path)

        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive path
            raise ValueError(f"invalid JSON input: {exc}") from exc

        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")

        flows_raw = payload.get("flows", [])
        dns_raw = payload.get("dns", [])
        http_raw = payload.get("http", [])

        if isinstance(dns_raw, dict):
            dns_raw = dns_raw.get("queries", [])
        if isinstance(http_raw, dict):
            http_raw = http_raw.get("requests", [])

        flows = self._ensure_dict_list(flows_raw)
        dns = self._ensure_dict_list(dns_raw)
        http = self._ensure_dict_list(http_raw)

        return flows, dns, http, origin

    def _ensure_dict_list(self, value: Any) -> List[Dict[str, Any]]:
        if value is None:
            return []
        if isinstance(value, dict):
            return [dict(value)]
        if isinstance(value, str | bytes):
            return []
        if not isinstance(value, IterableABC):
            return []

        result: List[Dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                result.append(dict(item))
        return result

    def _normalise_int(self, value: Any) -> int:
        if value is None:
            return -1
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        try:
            return int(str(value), 10)
        except (TypeError, ValueError):
            return -1

    def _sort_flow_records(
        self, flows: Iterable[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return sorted(
            flows,
            key=lambda item: (
                item.get("start_ts") or "",
                item.get("end_ts") or "",
                item.get("src") or "",
                item.get("dst") or "",
                self._normalise_int(item.get("src_port")),
                self._normalise_int(item.get("dst_port")),
                item.get("protocol") or "",
            ),
        )

    def _sort_dns_queries(
        self, queries: Iterable[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return sorted(
            queries,
            key=lambda item: (
                item.get("timestamp") or "",
                item.get("query") or "",
                self._normalise_int(item.get("query_type")),
                item.get("src") or "",
                item.get("dst") or "",
                self._normalise_int(item.get("src_port")),
                self._normalise_int(item.get("dst_port")),
            ),
        )

    def _sort_http_requests(
        self, requests: Iterable[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return sorted(
            requests,
            key=lambda item: (
                item.get("timestamp") or "",
                item.get("method") or "",
                item.get("host") or "",
                item.get("uri") or "",
                item.get("src") or "",
                item.get("dst") or "",
                self._normalise_int(item.get("src_port")),
                self._normalise_int(item.get("dst_port")),
            ),
        )

    # ------------------------------------------------------------------
    # Packet processing helpers
    # ------------------------------------------------------------------
    def _process_scapy_packets(
        self,
        packets: Iterable[object],
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
        dns_queries: List[Dict[str, object]],
        http_requests: List[Dict[str, object]],
    ) -> None:
        for packet in packets:
            timestamp = float(getattr(packet, "time", 0.0))
            packet_len = int(len(packet)) if hasattr(packet, "__len__") else 0
            flow_key = self._extract_flow_key_scapy(packet)
            if flow_key:
                flows[flow_key].update(timestamp, packet_len)

            if DNS is not None and packet.haslayer(DNS):  # type: ignore[union-attr]
                dns_layer = packet[DNS]
                if getattr(dns_layer, "qr", 1) == 0 and hasattr(dns_layer, "qd"):
                    query = dns_layer.qd
                    query_name = (
                        getattr(query, "qname", b"")
                        .rstrip(b".")
                        .decode("utf-8", "ignore")
                    )
                    dns_queries.append(
                        self._build_dns_record(
                            query_name,
                            getattr(query, "qtype", 0),
                            timestamp,
                            flow_key,
                        )
                    )

            if TCP is not None and packet.haslayer(TCP):  # type: ignore[union-attr]
                tcp_layer = packet[TCP]
                payload = bytes(getattr(tcp_layer, "payload", b""))
                if payload:
                    http_record = self._parse_http_payload(payload, timestamp, flow_key)
                    if http_record:
                        http_requests.append(http_record)

    def _process_pyshark_capture(
        self,
        pcap_path: str,
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
        dns_queries: List[Dict[str, object]],
        http_requests: List[Dict[str, object]],
    ) -> None:
        assert pyshark is not None  # for type checking
        capture = pyshark.FileCapture(pcap_path, keep_packets=False)
        try:
            for packet in capture:
                timestamp = float(getattr(packet, "sniff_timestamp", 0.0))
                length = int(getattr(packet, "length", 0))
                flow_key = self._extract_flow_key_pyshark(packet)
                if flow_key:
                    flows[flow_key].update(timestamp, length)

                if hasattr(packet, "dns") and getattr(packet.dns, "qry_name", None):
                    query_name = packet.dns.qry_name.rstrip(".")
                    qtype = int(getattr(packet.dns, "qry_type", 0))
                    dns_queries.append(
                        self._build_dns_record(query_name, qtype, timestamp, flow_key)
                    )

                if hasattr(packet, "http") and getattr(
                    packet.http, "request_method", None
                ):
                    http_requests.append(
                        self._build_http_record_pyshark(
                            packet.http, timestamp, flow_key
                        )
                    )
        finally:
            capture.close()

    def _process_builtin_packets(
        self,
        pcap_file: Path,
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
        dns_queries: List[Dict[str, object]],
        http_requests: List[Dict[str, object]],
    ) -> None:
        """Parse packets using a minimal PCAP reader implemented in pure Python."""

        for timestamp, length, frame in self._iter_pcap_packets(pcap_file):
            if len(frame) < 14:
                continue

            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                self._parse_ipv4_frame(
                    timestamp, length, frame[14:], flows, dns_queries, http_requests
                )
            elif eth_type == 0x86DD:  # IPv6
                self._parse_ipv6_frame(
                    timestamp, length, frame[14:], flows, dns_queries, http_requests
                )

    def _iter_pcap_packets(self, pcap_file: Path) -> Iterable[Tuple[float, int, bytes]]:
        """Yield ``(timestamp, length, frame)`` tuples from ``pcap_file``."""

        with pcap_file.open("rb") as handle:
            header = handle.read(24)
            if len(header) < 24:
                raise ValueError("Incomplete PCAP global header")

            magic_le = int.from_bytes(header[:4], "little")
            magic_be = int.from_bytes(header[:4], "big")

            if magic_le == 0xA1B2C3D4:
                endian = "<"
                ts_divisor = 1_000_000
            elif magic_le == 0xA1B23C4D:
                endian = "<"
                ts_divisor = 1_000_000_000
            elif magic_be == 0xA1B2C3D4:
                endian = ">"
                ts_divisor = 1_000_000
            elif magic_be == 0xA1B23C4D:
                endian = ">"
                ts_divisor = 1_000_000_000
            else:
                raise ValueError(f"Unsupported PCAP magic value: {header[:4].hex()}")

            while True:
                packet_header = handle.read(16)
                if not packet_header:
                    break
                if len(packet_header) < 16:
                    raise ValueError("Incomplete PCAP packet header")

                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                    f"{endian}IIII", packet_header
                )

                frame = handle.read(incl_len)
                if len(frame) < incl_len:
                    raise ValueError("Truncated PCAP packet data")

                timestamp = ts_sec + (ts_frac / ts_divisor)
                yield timestamp, orig_len, frame

    def _parse_ipv4_frame(
        self,
        timestamp: float,
        packet_len: int,
        payload: bytes,
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
        dns_queries: List[Dict[str, object]],
        http_requests: List[Dict[str, object]],
    ) -> None:
        if len(payload) < 20:
            return

        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return

        protocol = payload[9]
        src_ip = ".".join(str(b) for b in payload[12:16])
        dst_ip = ".".join(str(b) for b in payload[16:20])

        transport_payload = payload[ihl:]
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        if protocol in (6, 17) and len(transport_payload) >= 4:
            src_port, dst_port = struct.unpack("!HH", transport_payload[:4])

        key = (src_ip, dst_ip, src_port, dst_port, self._protocol_name(protocol))
        flows[key].update(timestamp, packet_len)

        if protocol == 17:
            self._maybe_record_dns(
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_payload,
                dns_queries,
            )
        elif protocol == 6:
            self._maybe_record_http(
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_payload,
                http_requests,
            )

    def _parse_ipv6_frame(
        self,
        timestamp: float,
        packet_len: int,
        payload: bytes,
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
        dns_queries: List[Dict[str, object]],
        http_requests: List[Dict[str, object]],
    ) -> None:
        if len(payload) < 40:
            return

        next_header = payload[6]
        src_ip = ":".join(
            f"{int.from_bytes(payload[i:i+2], 'big'):x}" for i in range(8, 24, 2)
        )
        dst_ip = ":".join(
            f"{int.from_bytes(payload[i:i+2], 'big'):x}" for i in range(24, 40, 2)
        )

        transport_payload = payload[40:]
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        if next_header in (6, 17) and len(transport_payload) >= 4:
            src_port, dst_port = struct.unpack("!HH", transport_payload[:4])

        key = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            self._protocol_name(next_header),
        )
        flows[key].update(timestamp, packet_len)

        if next_header == 17:
            self._maybe_record_dns(
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_payload,
                dns_queries,
            )
        elif next_header == 6:
            self._maybe_record_http(
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_payload,
                http_requests,
            )

    def _maybe_record_dns(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        payload: bytes,
        dns_queries: List[Dict[str, object]],
    ) -> None:
        if src_port is None or dst_port is None:
            return
        if 53 not in (src_port, dst_port):
            return
        if len(payload) < 8:
            return

        dns_payload = payload[8:]
        queries = list(self._decode_dns_queries(dns_payload))
        if not queries:
            return

        ts = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        client = src_ip if dst_port == 53 else dst_ip
        server = dst_ip if dst_port == 53 else src_ip

        for query in queries:
            dns_queries.append(
                {
                    "timestamp": ts,
                    "query": query.get("name"),
                    "qtype": query.get("type"),
                    "client": client,
                    "server": server,
                }
            )

    def _decode_dns_queries(self, payload: bytes) -> Iterable[Dict[str, object]]:
        if len(payload) < 12:
            return []

        try:
            header = struct.unpack("!HHHHHH", payload[:12])
        except struct.error:
            return []

        qdcount = header[2]
        offset = 12
        queries = []

        for _ in range(qdcount):
            labels = []
            while offset < len(payload):
                length = payload[offset]
                offset += 1
                if length == 0:
                    break
                if offset + length > len(payload):
                    return queries
                label_bytes = payload[offset : offset + length]
                try:
                    labels.append(label_bytes.decode("ascii"))
                except UnicodeDecodeError:
                    labels.append(label_bytes.decode("ascii", "ignore"))
                offset += length

            if offset + 4 > len(payload):
                break

            qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4

            queries.append(
                {"name": ".".join(filter(None, labels)), "type": qtype, "class": qclass}
            )

        return queries

    def _maybe_record_http(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        payload: bytes,
        http_requests: List[Dict[str, object]],
    ) -> None:
        if src_port is None or dst_port is None:
            return
        if len(payload) < 20:
            return

        data_offset = (payload[12] >> 4) * 4
        if len(payload) <= data_offset:
            return

        body = payload[data_offset:]
        if not body:
            return

        try:
            text = body.decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - defensive
            return

        lines = text.splitlines()
        if not lines:
            return

        request_line = lines[0]
        parts = request_line.split()
        if not parts:
            return

        method = parts[0].upper()
        if method not in HTTP_METHODS:
            return

        path = parts[1] if len(parts) > 1 else "/"
        host = None
        for line in lines[1:10]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        ts = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        http_requests.append(
            {
                "timestamp": ts,
                "method": method,
                "path": path,
                "host": host,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            }
        )

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------
    def _serialise_flows(
        self,
        flows: Dict[
            Tuple[str, str, Optional[int], Optional[int], str], FlowAccumulator
        ],
    ) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for (src, dst, sport, dport, proto), accumulator in flows.items():
            if accumulator.packets == 0:
                continue
            start_ts = self._format_timestamp(accumulator.start_ts)
            end_ts = self._format_timestamp(accumulator.end_ts)
            result.append(
                {
                    "src": src,
                    "dst": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": proto,
                    "packets": accumulator.packets,
                    "bytes": accumulator.bytes,
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                }
            )
        return self._sort_flow_records(result)

    def _summarise_dns(self, queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        sorted_queries = self._sort_dns_queries(queries)
        suspicious = [
            query
            for query in sorted_queries
            if query.get("heuristics", {}).get("long_domain")
            or query.get("heuristics", {}).get("high_entropy")
        ]
        return {
            "queries": sorted_queries,
            "suspicious": suspicious,
        }

    def _summarise_http(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        sorted_requests = self._sort_http_requests(requests)
        suspicious_agents = sorted(
            {
                req["user_agent"].lower()
                for req in sorted_requests
                if req.get("user_agent")
                and req.get("indicators", {}).get("suspicious_user_agent")
            }
        )
        encoded_uris = [
            req["uri"]
            for req in sorted_requests
            if req.get("uri") and req.get("indicators", {}).get("encoded_uri")
        ]
        return {
            "requests": sorted_requests,
            "indicators": {
                "suspicious_user_agents": suspicious_agents,
                "encoded_uris": encoded_uris,
            },
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _extract_flow_key_scapy(
        self, packet: object
    ) -> Optional[Tuple[str, str, Optional[int], Optional[int], str]]:
        if IP is not None and packet.haslayer(IP):  # type: ignore[union-attr]
            layer = packet[IP]
            src = getattr(layer, "src", None)
            dst = getattr(layer, "dst", None)
            proto_number = getattr(layer, "proto", None)
        elif IPv6 is not None and packet.haslayer(IPv6):  # type: ignore[union-attr]
            layer = packet[IPv6]
            src = getattr(layer, "src", None)
            dst = getattr(layer, "dst", None)
            proto_number = getattr(layer, "nh", None)
        else:
            return None

        protocol = self._protocol_name(proto_number)
        sport: Optional[int] = None
        dport: Optional[int] = None
        if TCP is not None and packet.haslayer(TCP):  # type: ignore[union-attr]
            tcp_layer = packet[TCP]
            raw_sport = getattr(tcp_layer, "sport", None)
            raw_dport = getattr(tcp_layer, "dport", None)
            sport = int(raw_sport) if raw_sport is not None else None
            dport = int(raw_dport) if raw_dport is not None else None
            protocol = "TCP"
        elif UDP is not None and packet.haslayer(UDP):  # type: ignore[union-attr]
            udp_layer = packet[UDP]
            raw_sport = getattr(udp_layer, "sport", None)
            raw_dport = getattr(udp_layer, "dport", None)
            sport = int(raw_sport) if raw_sport is not None else None
            dport = int(raw_dport) if raw_dport is not None else None
            protocol = "UDP"
        return (src, dst, sport, dport, protocol)

    def _extract_flow_key_pyshark(
        self, packet: object
    ) -> Optional[Tuple[str, str, Optional[int], Optional[int], str]]:
        src = dst = None
        sport = dport = None
        protocol = getattr(
            packet.highest_layer, "lower", lambda: packet.highest_layer
        )()

        if hasattr(packet, "ip"):
            src = getattr(packet.ip, "src", None)
            dst = getattr(packet.ip, "dst", None)
            proto_number = int(getattr(packet.ip, "proto", 0))
            protocol = self._protocol_name(proto_number)
        elif hasattr(packet, "ipv6"):
            src = getattr(packet.ipv6, "src", None)
            dst = getattr(packet.ipv6, "dst", None)
            proto_number = int(getattr(packet.ipv6, "nxt", 0))
            protocol = self._protocol_name(proto_number)
        else:
            return None

        if hasattr(packet, "tcp"):
            raw_sport = getattr(packet.tcp, "srcport", None)
            raw_dport = getattr(packet.tcp, "dstport", None)
            sport = int(raw_sport) if raw_sport is not None else None
            dport = int(raw_dport) if raw_dport is not None else None
            protocol = "TCP"
        elif hasattr(packet, "udp"):
            raw_sport = getattr(packet.udp, "srcport", None)
            raw_dport = getattr(packet.udp, "dstport", None)
            sport = int(raw_sport) if raw_sport is not None else None
            dport = int(raw_dport) if raw_dport is not None else None
            protocol = "UDP"

        return (src, dst, sport, dport, protocol)

    def _build_dns_record(
        self,
        query: str,
        qtype: int,
        timestamp: float,
        flow_key: Optional[Tuple[str, str, Optional[int], Optional[int], str]],
    ) -> Dict[str, object]:
        heuristics = self._dns_heuristics(query)
        record = {
            "query": query,
            "query_type": qtype,
            "timestamp": self._format_timestamp(timestamp),
            "heuristics": heuristics,
        }
        if flow_key:
            src, dst, sport, dport, protocol = flow_key
            record.update(
                {
                    "src": src,
                    "dst": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": protocol,
                }
            )
        return record

    def _build_http_record_pyshark(
        self,
        http_layer: object,
        timestamp: float,
        flow_key: Optional[Tuple[str, str, Optional[int], Optional[int], str]],
    ) -> Dict[str, object]:
        method = getattr(http_layer, "request_method", "").upper()
        host = getattr(http_layer, "host", None)
        uri = getattr(http_layer, "request_uri", None)
        user_agent = getattr(http_layer, "user_agent", None)
        indicators = self._http_indicators(method, uri, user_agent)
        record = {
            "timestamp": self._format_timestamp(timestamp),
            "method": method or None,
            "host": host,
            "uri": uri,
            "user_agent": user_agent,
            "indicators": indicators,
        }
        if flow_key:
            src, dst, sport, dport, protocol = flow_key
            record.update(
                {
                    "src": src,
                    "dst": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": protocol,
                }
            )
        return record

    def _parse_http_payload(
        self,
        payload: bytes,
        timestamp: float,
        flow_key: Optional[Tuple[str, str, Optional[int], Optional[int], str]],
    ) -> Optional[Dict[str, object]]:
        try:
            text = payload.decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - safeguard
            return None

        request_line, _, header_blob = text.partition("\r\n")
        parts = request_line.split()
        if len(parts) < 2:
            return None

        method = parts[0].upper()
        if method not in HTTP_METHODS:
            return None

        uri = parts[1]
        headers = self._parse_headers(header_blob)
        host = headers.get("host")
        user_agent = headers.get("user-agent")
        indicators = self._http_indicators(method, uri, user_agent)

        record: Dict[str, object] = {
            "timestamp": self._format_timestamp(timestamp),
            "method": method,
            "host": host,
            "uri": uri,
            "user_agent": user_agent,
            "indicators": indicators,
        }
        if flow_key:
            src, dst, sport, dport, protocol = flow_key
            record.update(
                {
                    "src": src,
                    "dst": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": protocol,
                }
            )
        return record

    def _parse_headers(self, header_blob: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in header_blob.split("\r\n"):
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        return headers

    def _dns_heuristics(self, query: str) -> Dict[str, bool]:
        return {
            "long_domain": len(query) > 50,
            "high_entropy": self._shannon_entropy(query) > 4.0 if query else False,
        }

    def _http_indicators(
        self, method: str, uri: Optional[str], user_agent: Optional[str]
    ) -> Dict[str, bool]:
        ua_lower = (user_agent or "").lower()
        encoded_uri = bool(uri and self._looks_encoded(uri))
        suspicious_agent = any(agent in ua_lower for agent in SUSPICIOUS_USER_AGENTS)
        suspicious_method = method not in {"GET", "POST", "HEAD"}
        return {
            "suspicious_user_agent": suspicious_agent,
            "encoded_uri": encoded_uri,
            "uncommon_method": suspicious_method,
        }

    def _looks_encoded(self, uri: str) -> bool:
        if "%" in uri:
            return True
        return bool(ENCODED_URI_PATTERN.search(uri))

    def _protocol_name(self, proto_number: Optional[int]) -> str:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return proto_map.get(
            proto_number, str(proto_number) if proto_number is not None else "unknown"
        )

    def _format_timestamp(self, timestamp: float) -> str:
        if timestamp in (float("inf"), float("-inf")):
            return "unknown"
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        total = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy
