"""Helpers to generate minimal PCAP fixtures at runtime.

This module attempts to use :mod:`scapy` to build a couple of representative
packets that exercise DNS and HTTP/TCP parsing logic. When Scapy is not
available, the module falls back to emitting a JSON representation of the
intended traffic shape so that callers still receive structured fixture data.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

try:
    from scapy.all import (  # type: ignore
        DNS,
        DNSQR,
        IP,
        TCP,
        UDP,
        Ether,
        Raw,
        wrpcap,
    )

    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when scapy is absent in env
    DNS = DNSQR = Ether = IP = Raw = TCP = UDP = wrpcap = None  # type: ignore
    SCAPY_AVAILABLE = False


MINIMAL_PCAP_NAME = "minimal.pcap"


def _build_packets() -> list[Ether]:
    """Construct a minimal sequence of packets for the generated PCAP."""

    if not SCAPY_AVAILABLE or Ether is None:  # Defensive, should not happen here
        raise RuntimeError("Scapy is required to build packets")

    dns_query = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )

    tcp_syn = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:03")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=44500, dport=80, flags="S", seq=1000)
    )

    http_get = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:03")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=44500, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

    return [dns_query, tcp_syn, http_get]


def _write_pcap(out_dir: Path) -> Path:
    """Persist the generated packets to ``out_dir`` and return the file path."""

    if not SCAPY_AVAILABLE or wrpcap is None:
        raise RuntimeError("Scapy is required to write PCAP fixtures")

    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / MINIMAL_PCAP_NAME
    packets: Iterable[Ether] = _build_packets()
    wrpcap(str(output_path), list(packets))
    return output_path


def _fallback_payload() -> str:
    """Return a structured JSON payload describing the intended packets."""

    payload = {
        "flows": [
            {
                "protocol": "tcp",
                "src": "192.0.2.10:44500",
                "dst": "198.51.100.20:80",
                "flags": ["S"],
            }
        ],
        "dns": [
            {
                "query": "example.com",
                "type": "A",
                "src": "192.0.2.10",
                "dst": "192.0.2.53",
            }
        ],
        "http": [
            {
                "method": "GET",
                "host": "example.com",
                "path": "/",
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthesize a minimal PCAP file")
    parser.add_argument(
        "--out",
        dest="out",
        type=Path,
        required=True,
        help="Directory where the generated PCAP should be stored",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    if not SCAPY_AVAILABLE:
        print(_fallback_payload())
        return 0

    try:
        output_path = _write_pcap(args.out)
    except Exception as exc:  # pragma: no cover - aids CLI diagnostics
        parser.error(str(exc))
        return 2

    print(output_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
