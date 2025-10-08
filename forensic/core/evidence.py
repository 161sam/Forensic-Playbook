#!/usr/bin/env python3
"""
Evidence Management
Handles evidence objects and metadata
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from forensic.core.time_utils import utc_isoformat, utc_slug


class EvidenceType(Enum):
    """Evidence types"""

    DISK = "disk"
    MEMORY = "memory"
    NETWORK = "network"
    FILE = "file"
    LOG = "log"
    REGISTRY = "registry"
    MOBILE = "mobile"
    CLOUD = "cloud"
    OTHER = "other"


class EvidenceState(Enum):
    """Evidence processing state"""

    COLLECTED = "collected"
    PROCESSING = "processing"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"


@dataclass
class Evidence:
    """
    Evidence object

    Represents a piece of digital evidence with complete metadata
    and chain of custody tracking.
    """

    evidence_type: EvidenceType
    source_path: Path
    description: str
    evidence_id: str = field(default_factory=lambda: f"EVD_{utc_slug()}")
    collected_at: str = field(default_factory=utc_isoformat)
    collected_by: Optional[str] = None
    state: EvidenceState = EvidenceState.COLLECTED

    # Hashes
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None

    # File properties
    size_bytes: Optional[int] = None
    mime_type: Optional[str] = None

    # Device/Source information
    device_model: Optional[str] = None
    device_serial: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Tags for categorization
    tags: list = field(default_factory=list)

    # Related evidence
    related_evidence: list = field(default_factory=list)

    def __post_init__(self):
        """Post-initialization processing"""
        # Convert string path to Path object
        if isinstance(self.source_path, str):
            self.source_path = Path(self.source_path)

        # Auto-detect some properties
        if self.source_path.exists() and self.source_path.is_file():
            self.size_bytes = self.source_path.stat().st_size
            self._detect_mime_type()

    def compute_hashes(self, algorithms: list = None):
        """
        Compute file hashes

        Args:
            algorithms: List of algorithms (md5, sha1, sha256)
                       Default: ['sha256']
        """
        if algorithms is None:
            algorithms = ["sha256"]

        if not self.source_path.exists() or not self.source_path.is_file():
            raise ValueError(f"Cannot hash: {self.source_path}")

        hashers = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }

        # Only initialize requested algorithms
        active_hashers = {k: v for k, v in hashers.items() if k in algorithms}

        # Read file and update all hashers
        with open(self.source_path, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64KB chunks
                if not chunk:
                    break
                for hasher in active_hashers.values():
                    hasher.update(chunk)

        # Store results
        if "md5" in active_hashers:
            self.hash_md5 = active_hashers["md5"].hexdigest()
        if "sha1" in active_hashers:
            self.hash_sha1 = active_hashers["sha1"].hexdigest()
        if "sha256" in active_hashers:
            self.hash_sha256 = active_hashers["sha256"].hexdigest()

    def verify_integrity(self, algorithm: str = "sha256") -> bool:
        """
        Verify evidence integrity

        Args:
            algorithm: Hash algorithm to verify

        Returns:
            True if hash matches, False otherwise
        """
        if algorithm == "sha256" and not self.hash_sha256:
            raise ValueError("No SHA256 hash stored")
        elif algorithm == "sha1" and not self.hash_sha1:
            raise ValueError("No SHA1 hash stored")
        elif algorithm == "md5" and not self.hash_md5:
            raise ValueError("No MD5 hash stored")

        # Compute current hash
        h = getattr(hashlib, algorithm)()
        with open(self.source_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)

        current_hash = h.hexdigest()
        stored_hash = getattr(self, f"hash_{algorithm}")

        return current_hash == stored_hash

    def _detect_mime_type(self):
        """Detect MIME type of file"""
        try:
            import magic

            self.mime_type = magic.from_file(str(self.source_path), mime=True)
        except ImportError:
            # Fallback to basic detection
            import mimetypes

            self.mime_type = mimetypes.guess_type(str(self.source_path))[0]
        except Exception:
            self.mime_type = "application/octet-stream"

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "source_path": str(self.source_path),
            "description": self.description,
            "collected_at": self.collected_at,
            "collected_by": self.collected_by,
            "state": self.state.value,
            "hash_md5": self.hash_md5,
            "hash_sha1": self.hash_sha1,
            "hash_sha256": self.hash_sha256,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
            "device_model": self.device_model,
            "device_serial": self.device_serial,
            "metadata": self.metadata,
            "tags": self.tags,
            "related_evidence": self.related_evidence,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Evidence":
        """Create from dictionary"""
        evidence_type = EvidenceType(data["evidence_type"])
        state = EvidenceState(data.get("state", "collected"))

        return cls(
            evidence_type=evidence_type,
            source_path=Path(data["source_path"]),
            description=data["description"],
            evidence_id=data["evidence_id"],
            collected_at=data["collected_at"],
            collected_by=data.get("collected_by"),
            state=state,
            hash_md5=data.get("hash_md5"),
            hash_sha1=data.get("hash_sha1"),
            hash_sha256=data.get("hash_sha256"),
            size_bytes=data.get("size_bytes"),
            mime_type=data.get("mime_type"),
            device_model=data.get("device_model"),
            device_serial=data.get("device_serial"),
            metadata=data.get("metadata", {}),
            tags=data.get("tags", []),
            related_evidence=data.get("related_evidence", []),
        )

    def add_tag(self, tag: str):
        """Add tag to evidence"""
        if tag not in self.tags:
            self.tags.append(tag)

    def link_evidence(self, evidence_id: str):
        """Link related evidence"""
        if evidence_id not in self.related_evidence:
            self.related_evidence.append(evidence_id)

    def update_state(self, new_state: EvidenceState):
        """Update evidence state"""
        self.state = new_state

    def __repr__(self) -> str:
        return f"Evidence(id={self.evidence_id}, type={self.evidence_type.value}, path={self.source_path})"
