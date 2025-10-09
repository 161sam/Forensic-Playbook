#!/usr/bin/env python3
"""
Test Suite for Forensic Framework Core
Unit and integration tests for core framework components
"""

import json
import tempfile
from pathlib import Path

import pytest

from forensic.core.chain_of_custody import ChainOfCustody
from forensic.core.evidence import Evidence, EvidenceState, EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.core.module import ForensicModule, ModuleResult
from forensic.core.time_utils import utc_isoformat
from forensic.utils.hashing import compute_hash

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_workspace():
    """Create temporary workspace"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def framework(temp_workspace):
    """Create framework instance"""
    return ForensicFramework(workspace=temp_workspace)


@pytest.fixture
def sample_case(framework):
    """Create sample case"""
    return framework.create_case(
        name="Test Case",
        description="Test case for unit tests",
        investigator="Test Investigator",
    )


@pytest.fixture
def sample_evidence(temp_workspace):
    """Create sample evidence file"""
    evidence_file = temp_workspace / "evidence.txt"
    evidence_file.write_text("Sample evidence content")

    evidence = Evidence(
        evidence_type=EvidenceType.FILE,
        source_path=evidence_file,
        description="Test evidence",
        collected_by="Tester",
    )
    evidence.compute_hashes(["sha256"])

    return evidence


# ============================================================================
# Core Framework Tests
# ============================================================================


class TestForensicFramework:
    """Test ForensicFramework class"""

    def test_framework_initialization(self, temp_workspace):
        """Test framework initialization"""
        framework = ForensicFramework(workspace=temp_workspace)

        assert framework.workspace.exists()
        assert (framework.workspace / "cases.db").exists()
        assert (framework.workspace / "chain_of_custody.db").exists()

    def test_create_case(self, framework):
        """Test case creation"""
        case = framework.create_case(
            name="Test Case", description="Test description", investigator="John Doe"
        )

        assert case.case_id.startswith("CASE_")
        assert case.name == "Test Case"
        assert case.investigator == "John Doe"
        assert case.case_dir.exists()
        assert (case.case_dir / "evidence").exists()
        assert (case.case_dir / "analysis").exists()
        assert (case.case_dir / "reports").exists()

    def test_load_case(self, framework, sample_case):
        """Test loading existing case"""
        case_id = sample_case.case_id

        # Create new framework instance
        framework2 = ForensicFramework(workspace=framework.workspace)
        loaded_case = framework2.load_case(case_id)

        assert loaded_case.case_id == case_id
        assert loaded_case.name == sample_case.name

    def test_add_evidence(self, framework, sample_case, sample_evidence):
        """Test adding evidence to case"""
        evidence = framework.add_evidence(
            evidence_type=sample_evidence.evidence_type,
            source_path=sample_evidence.source_path,
            description=sample_evidence.description,
        )

        assert evidence.evidence_id.startswith("EVD_")
        assert evidence.hash_sha256 is not None
        assert len(framework.current_case.evidence) == 1

    def test_list_cases(self, framework, sample_case):
        """Test listing all cases"""
        cases = framework.list_cases()

        assert len(cases) >= 1
        assert any(c["case_id"] == sample_case.case_id for c in cases)

    def test_module_registration(self, framework):
        """Test module registration"""
        from forensic.modules.triage.quick_triage import QuickTriageModule

        framework.register_module("quick_triage", QuickTriageModule)

        modules = framework.list_modules()
        assert "quick_triage" in modules


# ============================================================================
# Evidence Tests
# ============================================================================


class TestEvidence:
    """Test Evidence class"""

    def test_evidence_creation(self, sample_evidence):
        """Test evidence object creation"""
        assert sample_evidence.evidence_id.startswith("EVD_")
        assert sample_evidence.evidence_type == EvidenceType.FILE
        assert sample_evidence.state == EvidenceState.COLLECTED

    def test_hash_computation(self, temp_workspace):
        """Test hash computation"""
        test_file = temp_workspace / "test.txt"
        test_file.write_text("Test content")

        evidence = Evidence(
            evidence_type=EvidenceType.FILE, source_path=test_file, description="Test"
        )

        evidence.compute_hashes(["sha256", "md5"])

        assert evidence.hash_sha256 is not None
        assert evidence.hash_md5 is not None
        assert len(evidence.hash_sha256) == 64  # SHA256 hex length
        assert len(evidence.hash_md5) == 32  # MD5 hex length

    def test_integrity_verification(self, sample_evidence):
        """Test integrity verification"""
        # Should match
        assert sample_evidence.verify_integrity("sha256")

        # Modify file
        sample_evidence.source_path.write_text("Modified content")

        # Should not match
        assert not sample_evidence.verify_integrity("sha256")

    def test_evidence_tagging(self, sample_evidence):
        """Test evidence tagging"""
        sample_evidence.add_tag("malware")
        sample_evidence.add_tag("critical")

        assert "malware" in sample_evidence.tags
        assert "critical" in sample_evidence.tags
        assert len(sample_evidence.tags) == 2

    def test_evidence_linking(self, sample_evidence):
        """Test evidence linking"""
        sample_evidence.link_evidence("EVD_OTHER_001")

        assert "EVD_OTHER_001" in sample_evidence.related_evidence

    def test_evidence_serialization(self, sample_evidence):
        """Test to_dict and from_dict"""
        data = sample_evidence.to_dict()

        assert data["evidence_id"] == sample_evidence.evidence_id
        assert data["evidence_type"] == sample_evidence.evidence_type.value

        # Recreate from dict
        evidence2 = Evidence.from_dict(data)
        assert evidence2.evidence_id == sample_evidence.evidence_id


# ============================================================================
# Chain of Custody Tests
# ============================================================================


class TestChainOfCustody:
    """Test ChainOfCustody class"""

    def test_coc_initialization(self, temp_workspace):
        """Test CoC initialization"""
        coc_db = temp_workspace / "coc_test.db"
        ChainOfCustody(coc_db)

        assert coc_db.exists()

    def test_log_event(self, temp_workspace):
        """Test event logging"""
        coc_db = temp_workspace / "coc_test.db"
        coc = ChainOfCustody(coc_db)

        event_id = coc.log_event(
            event_type="TEST_EVENT",
            case_id="CASE_TEST",
            evidence_id="EVD_TEST",
            actor="Test User",
            description="Test event",
            metadata={"key": "value"},
        )

        assert event_id > 0

    def test_get_evidence_chain(self, temp_workspace):
        """Test retrieving evidence chain"""
        coc_db = temp_workspace / "coc_test.db"
        coc = ChainOfCustody(coc_db)

        # Log multiple events
        for i in range(3):
            coc.log_event(
                event_type=f"EVENT_{i}",
                evidence_id="EVD_TEST",
                actor="Tester",
                description=f"Event {i}",
            )

        chain = coc.get_evidence_chain("EVD_TEST")

        assert len(chain) == 3
        assert chain[0]["event_type"] == "EVENT_0"
        assert chain[2]["event_type"] == "EVENT_2"

    def test_verify_chain_integrity(self, temp_workspace):
        """Test chain integrity verification"""
        coc_db = temp_workspace / "coc_test.db"
        coc = ChainOfCustody(coc_db)

        # Create valid chain
        for i in range(3):
            coc.log_event(
                event_type=f"EVENT_{i}", evidence_id="EVD_TEST", actor="Tester"
            )

        is_valid, issues = coc.verify_chain_integrity("EVD_TEST")

        assert is_valid
        assert len(issues) == 0

    def test_coc_statistics(self, temp_workspace):
        """Test CoC statistics"""
        coc_db = temp_workspace / "coc_test.db"
        coc = ChainOfCustody(coc_db)

        # Log events
        coc.log_event(
            event_type="COLLECTED",
            case_id="CASE_TEST",
            evidence_id="EVD_001",
            actor="User1",
        )
        coc.log_event(
            event_type="ANALYZED",
            case_id="CASE_TEST",
            evidence_id="EVD_001",
            actor="User2",
        )

        stats = coc.get_statistics(case_id="CASE_TEST")

        assert stats["total_events"] == 2
        assert stats["unique_actors"] >= 2
        assert stats["unique_evidence"] >= 1


# ============================================================================
# Module Tests
# ============================================================================


class DummyModule(ForensicModule):
    """Dummy module for testing"""

    @property
    def name(self) -> str:
        return "dummy_module"

    @property
    def description(self) -> str:
        return "Dummy module for testing"

    def validate_params(self, params):
        return "required_param" in params

    def run(self, evidence, params):
        output_file = self.output_dir / "dummy_output.txt"
        output_file.write_text("dummy output")
        return ModuleResult(
            result_id=self._generate_result_id(),
            module_name=self.name,
            status="success",
            timestamp=utc_isoformat(),
            output_path=output_file,
            findings=[
                {
                    "type": "test",
                    "description": "Test finding",
                    "output_file": str(output_file),
                }
            ],
            metadata={"artifacts": [str(output_file)]},
        )


class TestForensicModule:
    """Test ForensicModule base class"""

    def test_module_creation(self, temp_workspace):
        """Test module instantiation"""
        module = DummyModule(case_dir=temp_workspace, config={})

        assert module.name == "dummy_module"
        assert module.output_dir.exists()

    def test_parameter_validation(self, temp_workspace):
        """Test parameter validation"""
        module = DummyModule(case_dir=temp_workspace, config={})

        # Valid params
        assert module.validate_params({"required_param": "value"})

        # Invalid params
        assert not module.validate_params({})

    def test_module_execution(self, temp_workspace):
        """Test module execution"""
        module = DummyModule(case_dir=temp_workspace, config={})

        result = module.execute(evidence=None, params={"required_param": "value"})

        assert result.status == "success"
        assert result.module_name == "dummy_module"
        assert len(result.findings) == 1


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    """Integration tests"""

    def test_full_workflow(self, framework, temp_workspace):
        """Test complete investigation workflow"""
        # Create case
        case = framework.create_case(
            name="Integration Test",
            description="Full workflow test",
            investigator="Tester",
        )

        assert case.case_id is not None

        # Create and add evidence
        evidence_file = temp_workspace / "evidence.txt"
        evidence_file.write_text("Evidence content")

        evidence = framework.add_evidence(
            evidence_type=EvidenceType.FILE,
            source_path=evidence_file,
            description="Test evidence",
        )

        assert evidence.evidence_id is not None

        # Register and execute module
        framework.register_module("dummy", DummyModule)

        result = framework.execute_module(
            "dummy", evidence=evidence, params={"required_param": "value"}
        )

        assert result.status == "success"

        # Verify CoC events logged
        coc_events = framework.coc.get_case_chain(case.case_id)
        assert len(coc_events) > 0
        completion_events = [
            event
            for event in coc_events
            if event["event_type"] == "MODULE_EXECUTION_COMPLETE"
        ]
        assert completion_events
        artifacts = completion_events[-1]["metadata"].get("artifacts", [])
        assert artifacts
        artifact_entry = artifacts[0]
        artifact_path = Path(artifact_entry["path"])
        assert artifact_path.exists()
        assert artifact_entry["sha256"] == compute_hash(artifact_path)

        # Check case can be listed
        cases = framework.list_cases()
        assert any(c["case_id"] == case.case_id for c in cases)

    def test_provenance_logging_no_duplicates(self, framework, temp_workspace):
        """Ensure provenance records are created once per execution."""

        case = framework.create_case(
            name="Provenance Case",
            description="Test provenance handling",
            investigator="Tester",
        )

        evidence_file = temp_workspace / "evidence.txt"
        evidence_file.write_text("Evidence content")

        evidence = framework.add_evidence(
            evidence_type=EvidenceType.FILE,
            source_path=evidence_file,
            description="Test evidence",
        )

        framework.register_module("dummy", DummyModule)

        for _ in range(2):
            framework.execute_module(
                "dummy", evidence=evidence, params={"required_param": "value"}
            )

        provenance_file = case.case_dir / "meta" / "provenance.jsonl"
        assert provenance_file.exists()

        records = [
            json.loads(line)
            for line in provenance_file.read_text().splitlines()
            if line
        ]
        assert len(records) == 2
        assert len({record["result_id"] for record in records}) == len(records)

        for record in records:
            assert record["module"] == "dummy"
            assert record["outputs"], "Expected output paths in provenance record"
            assert record["sha256"], "Expected SHA entries in provenance record"
            for entry in record["sha256"]:
                hash_path = Path(entry["path"])
                assert hash_path.exists()
                assert entry["sha256"] == compute_hash(hash_path)


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
