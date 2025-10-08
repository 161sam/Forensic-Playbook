import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic.modules.acquisition.memory_dump import MemoryDumpModule
from forensic.modules.acquisition.network_capture import NetworkCaptureModule


@pytest.fixture
def workspace_case(tmp_path):
    workspace = tmp_path / "workspace"
    case_dir = workspace / "cases" / "CASE123"
    case_dir.mkdir(parents=True)
    return workspace, case_dir


def _fake_completed(stdout="", stderr="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_memory_dump_success_creates_artifacts_and_coc(monkeypatch, workspace_case):
    workspace, case_dir = workspace_case
    module = MemoryDumpModule(
        case_dir=case_dir, config={"enable_coc": True, "coc_actor": "UnitTest"}
    )

    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.platform.system", lambda: "Linux"
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.socket.gethostname",
        lambda: "test-host",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.utc_slug", lambda: "20230101T000000Z"
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.utc_isoformat",
        lambda: "2023-01-01T00:00:00Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.shutil.which",
        lambda tool: "/usr/bin/avml" if tool == "avml" else None,
    )

    def fake_run(cmd, capture_output, text, timeout, check):
        output_file = Path(cmd[1])
        output_file.write_bytes(b"memory data")
        return _fake_completed(stdout="captured", stderr="", returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)

    result = module.run(None, {"enable_live_capture": True})

    assert result.status == "success"
    assert result.metadata["command"] == ["/usr/bin/avml", str(result.output_path)]

    output_path = result.output_path
    assert output_path is not None
    assert output_path.exists()

    meta_path = Path(result.metadata["metadata_file"])
    assert meta_path.exists()

    metadata = json.loads(meta_path.read_text())
    assert metadata["command"] == ["/usr/bin/avml", str(output_path)]
    assert metadata["sha256"] == result.metadata["sha256"]
    assert metadata["size_bytes"] == output_path.stat().st_size

    conn = sqlite3.connect(workspace / "chain_of_custody.db")
    row = conn.execute("SELECT event_type, metadata FROM coc_events").fetchone()
    conn.close()
    assert row is not None
    event_type, metadata_json = row
    assert event_type == "EVIDENCE_COLLECTED"
    coc_metadata = json.loads(metadata_json)
    assert coc_metadata["path"] == str(output_path)
    assert coc_metadata["metadata_file"] == str(meta_path)
    assert coc_metadata["hash_sha256"] == metadata["sha256"]


def test_memory_dump_dry_run_creates_no_files(monkeypatch, workspace_case):
    _, case_dir = workspace_case
    module = MemoryDumpModule(case_dir=case_dir, config={})

    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.platform.system", lambda: "Linux"
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.socket.gethostname",
        lambda: "dry-run-host",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.utc_slug", lambda: "20230101T000000Z"
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.utc_isoformat",
        lambda: "2023-01-01T00:00:00Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.memory_dump.shutil.which",
        lambda tool: "/usr/bin/avml",
    )

    result = module.run(None, {"dry_run": True, "enable_live_capture": True})

    assert result.status == "success"
    output_hint = Path(result.metadata["output"])
    assert not output_hint.exists()
    assert not output_hint.with_name(f"{output_hint.stem}.meta.json").exists()


def test_network_capture_success_creates_artifacts_and_coc(monkeypatch, workspace_case):
    workspace, case_dir = workspace_case
    module = NetworkCaptureModule(
        case_dir=case_dir, config={"enable_coc": True, "coc_actor": "NetTester"}
    )

    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.utc_slug",
        lambda: "20230101T000000Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.utc_isoformat",
        lambda: "2023-01-01T00:00:00Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.socket.gethostname",
        lambda: "net-host",
    )

    def fake_which(tool):
        return {
            "dumpcap": "/usr/bin/dumpcap",
            "tcpdump": "/usr/sbin/tcpdump",
        }.get(tool)

    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.shutil.which", fake_which
    )

    def fake_execute(self, command, tool_name, duration):
        if "-w" in command:
            output_index = command.index("-w") + 1
        else:
            output_index = len(command) - 1
        output_file = Path(command[output_index])
        output_file.write_bytes(b"pcap data")
        return "capture", "", 0

    monkeypatch.setattr(NetworkCaptureModule, "_execute_capture", fake_execute)

    params = {
        "enable_live_capture": True,
        "tool": "dumpcap",
        "duration": 120,
        "count": 50,
        "interface": "eth0",
        "bpf": "port 80",
    }

    result = module.run(None, params)

    assert result.status == "success"
    command = result.metadata["command"]
    assert command[:2] == ["/usr/bin/dumpcap", "-i"]
    assert "-w" in command and str(result.output_path) in command

    output_path = result.output_path
    assert output_path is not None and output_path.exists()

    meta_path = Path(result.metadata["metadata_file"])
    assert meta_path.exists()

    metadata = json.loads(meta_path.read_text())
    assert metadata["tool"] == "dumpcap"
    assert metadata["sha256"] == result.metadata["sha256"]
    assert metadata["size_bytes"] == output_path.stat().st_size

    conn = sqlite3.connect(workspace / "chain_of_custody.db")
    row = conn.execute("SELECT event_type, metadata FROM coc_events").fetchone()
    conn.close()
    assert row is not None
    event_type, metadata_json = row
    assert event_type == "EVIDENCE_COLLECTED"
    coc_metadata = json.loads(metadata_json)
    assert coc_metadata["path"] == str(output_path)
    assert coc_metadata["metadata_file"] == str(meta_path)
    assert coc_metadata["tool"] == "dumpcap"


def test_network_capture_dry_run_creates_no_artifacts(monkeypatch, workspace_case):
    _, case_dir = workspace_case
    module = NetworkCaptureModule(case_dir=case_dir, config={})

    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.utc_slug",
        lambda: "20230101T000000Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.utc_isoformat",
        lambda: "2023-01-01T00:00:00Z",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.socket.gethostname",
        lambda: "net-host",
    )
    monkeypatch.setattr(
        "forensic.modules.acquisition.network_capture.shutil.which",
        lambda tool: "/usr/bin/dumpcap",
    )

    params = {
        "dry_run": True,
        "tool": "dumpcap",
        "duration": 60,
        "interface": "eth0",
        "bpf": "port 443",
    }

    result = module.run(None, params)

    assert result.status == "success"
    output_hint = Path(result.metadata["output"])
    assert not output_hint.exists()
    assert not output_hint.with_name(f"{output_hint.stem}.meta.json").exists()
    assert any(finding["type"] == "dry_run" for finding in result.findings)
