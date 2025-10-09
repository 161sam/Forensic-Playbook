import io
import json
import sys
from pathlib import Path

from forensic.modules.analysis.network import NetworkAnalysisModule


def _prepare_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "analysis").mkdir()
    (case_dir / "evidence").mkdir()
    (case_dir / "reports").mkdir()
    return case_dir


def test_validate_accepts_pcap_json_only(tmp_path):
    case_dir = _prepare_case_dir(tmp_path)
    module = NetworkAnalysisModule(case_dir=case_dir, config={})
    assert module.validate_params({"pcap_json": "-"})


def test_run_with_pcap_json_stdin(monkeypatch, tmp_path):
    case_dir = _prepare_case_dir(tmp_path)
    module = NetworkAnalysisModule(case_dir=case_dir, config={})

    debug_payload = {
        "flows": [
            {
                "src": "10.0.0.5",
                "dst": "10.0.0.2",
                "src_port": 12345,
                "dst_port": 8080,
                "protocol": "TCP",
                "packets": 10,
                "bytes": 5120,
                "start_ts": "2024-01-02T00:00:05+00:00",
                "end_ts": "2024-01-02T00:00:10+00:00",
            },
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.3",
                "src_port": 443,
                "dst_port": 55555,
                "protocol": "TCP",
                "packets": 2,
                "bytes": 1024,
                "start_ts": "2024-01-01T00:00:01+00:00",
                "end_ts": "2024-01-01T00:00:02+00:00",
            },
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "src_port": 80,
                "dst_port": 50000,
                "protocol": "TCP",
                "packets": 5,
                "bytes": 2048,
                "start_ts": "2024-01-01T00:00:01+00:00",
                "end_ts": "2024-01-01T00:00:05+00:00",
            },
        ],
        "dns": [
            {
                "timestamp": "2024-01-02T00:00:00+00:00",
                "query": "example.org",
                "query_type": 1,
            },
            {
                "timestamp": "2024-01-01T00:00:00+00:00",
                "query": "long" + "a" * 60 + ".evil",
                "query_type": 1,
                "heuristics": {"long_domain": True},
            },
        ],
        "http": [
            {
                "timestamp": "2024-01-02T00:00:00+00:00",
                "method": "GET",
                "host": "b.example.org",
                "uri": "/ok",
                "user_agent": "Mozilla/5.0",
                "indicators": {
                    "suspicious_user_agent": False,
                    "encoded_uri": False,
                },
            },
            {
                "timestamp": "2024-01-01T00:00:00+00:00",
                "method": "POST",
                "host": "a.example.org",
                "uri": "/encoded%2fvalue",
                "user_agent": "curl/7.88.1",
                "indicators": {
                    "suspicious_user_agent": True,
                    "encoded_uri": True,
                },
            },
        ],
    }

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(debug_payload)))

    result = module.run(None, {"pcap_json": "-"})

    assert result.status == "success"
    assert result.metadata.get("pcap_json_mode") is True
    assert result.metadata.get("pcap_json_source") == "stdin"

    output_path = Path(result.output_path)
    with output_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    flows = payload["flows"]
    assert [flow["src"] for flow in flows] == [
        "10.0.0.1",
        "10.0.0.1",
        "10.0.0.5",
    ]

    dns_queries = payload["dns"]["queries"]
    assert [query["query"] for query in dns_queries] == [
        "long" + "a" * 60 + ".evil",
        "example.org",
    ]
    assert payload["dns"]["suspicious"][0]["query"].endswith(".evil")

    http_requests = payload["http"]["requests"]
    assert [req["method"] for req in http_requests] == ["POST", "GET"]
    assert payload["http"]["indicators"]["suspicious_user_agents"] == ["curl/7.88.1"]
    assert payload["http"]["indicators"]["encoded_uris"] == ["/encoded%2fvalue"]
