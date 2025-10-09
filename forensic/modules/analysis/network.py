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
from ...core.time_utils import ZoneInfo, isoformat_with_timezone, utc_slug

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

DEFAULT_HTTP_METHODS = {
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

DEFAULT_SUSPICIOUS_USER_AGENTS = {
    "curl",
    "python-requests",
    "wget",
    "powershell",
}

DEFAULT_ENCODED_URI_PATTERN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


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

    def __init__(self, case_dir: Path, config: Dict):
        super().__init__(case_dir=case_dir, config=config)

        defaults = self._config_defaults()

        self._http_methods = self._normalise_http_methods(
            defaults.get("http_methods")
        )
        suspicious_agents = self._normalise_string_list(
            defaults.get("suspicious_user_agents")
        )
        if suspicious_agents:
            self._suspicious_user_agents = {agent.lower() for agent in suspicious_agents}
        else:
            self._suspicious_user_agents = {
                agent.lower() for agent in DEFAULT_SUSPICIOUS_USER_AGENTS
            }

        encoded_pattern = defaults.get(
            "encoded_uri_regex", DEFAULT_ENCODED_URI_PATTERN.pattern
        )
        self._encoded_uri_pattern = self._compile_encoded_pattern(encoded_pattern)

        output_filename = str(defaults.get("output_filename", "network.json")).strip()
        self._output_filename = output_filename or "network.json"

        timezone_override = defaults.get("timezone") or self.timezone
        self._timezone_name = str(timezone_override)
        self._tzinfo = self._build_timezone(self._timezone_name)

        self._enable_builtin_parser = bool(defaults.get("enable_builtin_parser", True))
        self._param_sources: Dict[str, str] = {}
        self._dry_run_missing_inputs: List[str] = []

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
        return self._module_config("network_analysis", "network")

    def validate_params(self, params: Dict) -> bool:
        defaults = self._config_defaults()
        original = dict(params)
        self._param_sources = {}
        self._dry_run_missing_inputs = []

        def _resolve(
            key: str,
            *,
            allow_stdin: bool = False,
            default_value: Any = None,
        ) -> Optional[str]:
            if key in original:
                value = self._normalise_scalar(original[key], allow_stdin=allow_stdin)
                if value is not None:
                    params[key] = value
                    self._param_sources[key] = "cli"
                    return value
                params.pop(key, None)

            for candidate in (key, f"default_{key}"):
                if candidate in defaults:
                    value = self._normalise_scalar(
                        defaults[candidate], allow_stdin=allow_stdin
                    )
                    if value is not None:
                        params[key] = value
                        self._param_sources[key] = "config"
                        return value

            if default_value is not None:
                params[key] = default_value
                self._param_sources[key] = "default"
                return default_value

            params.pop(key, None)
            return None

        pcap_value = _resolve("pcap")
        pcap_json_value = _resolve("pcap_json", allow_stdin=True)

        dry_run_raw = original.get("dry_run")
        if "dry_run" in original:
            self._param_sources["dry_run"] = "cli"
        elif "dry_run" in defaults:
            dry_run_raw = defaults.get("dry_run")
            self._param_sources["dry_run"] = "config"
        else:
            dry_run_raw = False
            self._param_sources["dry_run"] = "default"

        dry_run = self._to_bool(dry_run_raw, default=False)
        params["dry_run"] = dry_run

        has_pcap = bool(pcap_value)
        has_pcap_json = bool(pcap_json_value)

        if not has_pcap and not has_pcap_json:
            self.logger.error("Missing required parameter: pcap or pcap_json")
            return False

        if has_pcap:
            pcap_path = Path(str(pcap_value))
            if not pcap_path.exists() or not pcap_path.is_file():
                if dry_run:
                    self._dry_run_missing_inputs.append(str(pcap_path))
                else:
                    self.logger.error(f"PCAP file does not exist: {pcap_path}")
                    return False

        if has_pcap_json and pcap_json_value != "-":
            json_path = Path(str(pcap_json_value))
            if not json_path.exists() or not json_path.is_file():
                if dry_run:
                    self._dry_run_missing_inputs.append(str(json_path))
                else:
                    self.logger.error(
                        f"PCAP JSON file does not exist: {json_path}"
                    )
                    return False

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        del evidence  # Analysis operates on supplied artefacts only.

        result_id = self._generate_result_id()
        timestamp = isoformat_with_timezone(self._timezone_name)
        slug = utc_slug()

        dry_run = bool(params.get("dry_run", False))
        pcap_value = params.get("pcap")
        pcap_file = Path(str(pcap_value)) if pcap_value else None
        pcap_json_source = params.get("pcap_json")
        extras_available = self._extras_available()

        metadata: Dict[str, Any] = {
            "generated_at": timestamp,
            "timezone": self._timezone_name,
            "pcap_extra_available": extras_available,
            "pcap_json_mode": bool(pcap_json_source),
            "dry_run": dry_run,
            "parameter_sources": dict(sorted(self._param_sources.items())),
        }

        metadata["pcap_file"] = str(pcap_file) if pcap_file else None
        metadata["pcap_json_source"] = (
            None
            if not pcap_json_source
            else ("stdin" if pcap_json_source == "-" else str(pcap_json_source))
        )

        if pcap_file and pcap_file.exists():
            try:
                metadata["pcap_size"] = pcap_file.stat().st_size
            except OSError:
                metadata["pcap_size"] = None
        else:
            metadata["pcap_size"] = None

        if dry_run and self._dry_run_missing_inputs:
            metadata["missing_inputs"] = sorted(set(self._dry_run_missing_inputs))

        output_root = self.output_dir / slug
        planned_output = output_root / self._output_filename

        if dry_run:
            planned_steps = self._planned_steps(pcap_file, pcap_json_source, extras_available)
            metadata.update(self.dry_run_notice(planned_steps))
            metadata["planned_output_file"] = str(planned_output)

            findings: List[Dict[str, Any]] = [
                {
                    "type": "dry_run",
                    "description": "Dry-run only logged planned network analysis steps.",
                    "planned_output": str(planned_output),
                }
            ]

            if not extras_available:
                findings.append(
                    {
                        "type": "guard",
                        "severity": "info",
                        "description": (
                            "Optional PCAP extras are not installed. Install the "
                            "'pcap' extra for enhanced protocol decoding."
                        ),
                        "hints": [
                            "pip install forensic-playbook[pcap]",
                        ],
                    }
                )

            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="success",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
            )

        fallback_used = False
        parser_used: Optional[str] = None
        parser_errors: Dict[str, str] = {}

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
            if json_origin not in {None, "stdin"}:
                json_path = Path(json_origin)
                if json_path.exists():
                    try:
                        metadata["pcap_json_sha256"] = self._compute_hash(json_path)
                    except Exception:  # pragma: no cover - defensive hashing failure
                        pass

            flows_list = self._sort_flow_records(json_flows)
            dns_summary = self._summarise_dns(json_dns)
            http_summary = self._summarise_http(json_http)
            metadata["parser_used"] = "pcap_json"
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

            if pcap_file.exists():
                try:
                    metadata["pcap_sha256"] = self._compute_hash(pcap_file)
                except Exception:  # pragma: no cover - defensive hashing failure
                    pass

            if rdpcap is not None:
                try:
                    packets = rdpcap(str(pcap_file))
                    self._process_scapy_packets(packets, flows, dns_queries, http_requests)
                    parser_used = "scapy"
                except Exception as exc:  # pragma: no cover - optional dependency failure
                    parser_errors["scapy"] = str(exc)

            if parser_used is None and pyshark is not None:
                try:
                    self._process_pyshark_capture(
                        str(pcap_file), flows, dns_queries, http_requests
                    )
                    parser_used = "pyshark"
                except Exception as exc:  # pragma: no cover - optional dependency failure
                    parser_errors["pyshark"] = str(exc)

            if parser_used is None:
                if not self._enable_builtin_parser:
                    metadata["parser_errors"] = dict(sorted(parser_errors.items()))
                    return self.guard_result(
                        "Optional PCAP parsers unavailable and builtin parser disabled.",
                        hints=[
                            "Install the 'pcap' extra via `pip install forensic-playbook[pcap]`.",
                            "Enable the builtin parser via configuration if desired.",
                        ],
                        status="skipped",
                        metadata=metadata,
                        result_id=result_id,
                        timestamp=timestamp,
                    )

                fallback_used = True
                metadata["fallback_parser"] = "builtin"
                if parser_errors:
                    metadata["parser_errors"] = dict(sorted(parser_errors.items()))
                try:
                    self._process_builtin_packets(
                        pcap_file, flows, dns_queries, http_requests
                    )
                    metadata["parser_used"] = "builtin"
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
            else:
                metadata["parser_used"] = parser_used

            flows_list = self._serialise_flows(flows)
            dns_summary = self._summarise_dns(dns_queries)
            http_summary = self._summarise_http(http_requests)

        output_root.mkdir(parents=True, exist_ok=True)
        output_file = output_root / self._output_filename
        payload = {
            "metadata": metadata,
            "flows": flows_list,
            "dns": dns_summary,
            "http": http_summary,
        }

        with output_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

        findings: List[Dict[str, Any]] = [
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

        if not extras_available:
            findings.append(
                {
                    "type": "guard",
                    "severity": "info",
                    "description": (
                        "Optional PCAP extras are not installed. Install the 'pcap' "
                        "extra for enhanced protocol decoding."
                    ),
                    "hints": ["pip install forensic-playbook[pcap]"],
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
    def _load_pcap_json_input(self, source: str) -> Tuple[
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

        ts = self._format_timestamp(timestamp)
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
        if method not in self._http_methods:
            return

        path = parts[1] if len(parts) > 1 else "/"
        host = None
        for line in lines[1:10]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        ts = self._format_timestamp(timestamp)
        http_requests.append(
            {
                "timestamp": ts,
                "method": method,
                "uri": path,
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
        encoded_uris = sorted(
            {
                str(req.get("uri"))
                for req in sorted_requests
                if req.get("uri")
                and req.get("indicators", {}).get("encoded_uri")
            }
        )
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
    def _planned_steps(
        self,
        pcap_file: Optional[Path],
        pcap_json_source: Optional[str],
        extras_available: bool,
    ) -> List[str]:
        steps: List[str] = []
        if pcap_json_source:
            origin = "stdin" if pcap_json_source == "-" else str(pcap_json_source)
            steps.append(f"Load PCAP JSON input from {origin}")
        elif pcap_file:
            steps.append(f"Parse PCAP capture from {pcap_file}")
            if extras_available:
                steps.append("Prefer scapy/pyshark parsers when available")
            if self._enable_builtin_parser:
                steps.append("Fallback to builtin parser for flow/DNS/HTTP extraction")
        else:
            steps.append("Awaiting PCAP or PCAP JSON input for analysis")

        steps.append("Aggregate flows, DNS queries and HTTP metadata")
        steps.append(f"Write deterministic output to {self._output_filename}")
        return steps

    def _normalise_string_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            items = list(value)
        elif isinstance(value, str):
            items = re.split(r"[,;]", value)
        else:
            return []

        result: List[str] = []
        for item in items:
            if isinstance(item, str):
                trimmed = item.strip()
                if trimmed:
                    result.append(trimmed)
            elif item is not None:
                result.append(str(item))
        return result

    def _normalise_http_methods(self, value: Any) -> set[str]:
        methods = {method.upper() for method in self._normalise_string_list(value)}
        if not methods:
            methods = set(DEFAULT_HTTP_METHODS)
        return methods

    def _compile_encoded_pattern(self, value: Any) -> re.Pattern[str]:
        if isinstance(value, re.Pattern):
            return value

        pattern = str(value).strip() if value is not None else ""
        if not pattern:
            return DEFAULT_ENCODED_URI_PATTERN

        try:
            return re.compile(pattern)
        except re.error:
            self.logger.warning(
                "Invalid encoded URI regex configured for network analysis: %s",
                pattern,
            )
            return DEFAULT_ENCODED_URI_PATTERN

    def _build_timezone(self, name: Optional[str]) -> timezone:
        if name and name.upper() in {"UTC", "Z"}:
            return timezone.utc

        if name and ZoneInfo is not None:
            try:
                return ZoneInfo(str(name))  # type: ignore[arg-type]
            except Exception:
                self.logger.warning(
                    "Falling back to UTC due to invalid timezone configuration: %s",
                    name,
                )

        return timezone.utc

    def _extras_available(self) -> bool:
        return any(extra is not None for extra in (rdpcap, pyshark))

    def _normalise_scalar(
        self, value: Any, *, allow_stdin: bool = False
    ) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            trimmed = value.strip()
            if allow_stdin and trimmed == "-":
                return "-"
            return trimmed or None
        return str(value)

    def _to_bool(self, value: Any, *, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        return bool(value)

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
        if method not in self._http_methods:
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
        suspicious_agent = any(
            agent in ua_lower for agent in self._suspicious_user_agents
        )
        suspicious_method = method not in {"GET", "POST", "HEAD"}
        return {
            "suspicious_user_agent": suspicious_agent,
            "encoded_uri": encoded_uri,
            "uncommon_method": suspicious_method,
        }

    def _looks_encoded(self, uri: str) -> bool:
        if "%" in uri:
            return True
        return bool(self._encoded_uri_pattern.search(uri))

    def _protocol_name(self, proto_number: Optional[int]) -> str:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return proto_map.get(
            proto_number, str(proto_number) if proto_number is not None else "unknown"
        )

    def _format_timestamp(self, timestamp: float) -> str:
        if timestamp in (float("inf"), float("-inf")):
            return "unknown"

        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        tzinfo = self._tzinfo
        if tzinfo and tzinfo != timezone.utc:
            return dt.astimezone(tzinfo).isoformat()
        return dt.isoformat().replace("+00:00", "Z")

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
