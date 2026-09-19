"""
Unit tests for Forensic Evidence Ledger with Hash Chain Integrity
"""
import pytest
from datetime import datetime, timezone
from app.services.forensic_ledger import ForensicLedger


def test_compute_evidence_hash():
    """Test cryptographic hash computation"""
    hash1 = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="SPF Failure",
        description="SPF authentication failed",
        extracted_value="spf=fail",
        metadata={"status": "FAIL"},
        previous_hash=None,
        collected_at=datetime.now(timezone.utc)
    )

    # Hash should be deterministic SHA-256 (64 hex chars)
    assert len(hash1) == 64
    assert hash1.isalnum()

    # Same input should produce same hash
    hash2 = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="SPF Failure",
        description="SPF authentication failed",
        extracted_value="spf=fail",
        metadata={"status": "FAIL"},
        previous_hash=None,
        collected_at=datetime.now(timezone.utc)
    )

    # Different inputs should produce different hashes
    hash3 = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="DKIM Failure",
        description="DKIM signature invalid",
        extracted_value="dkim=fail",
        metadata={"status": "FAIL"},
        previous_hash=None,
        collected_at=datetime.now(timezone.utc)
    )

    assert hash1 != hash3


def test_hash_chain_linkage():
    """Test that evidence chain properly links via previous_hash"""
    time1 = datetime.now(timezone.utc)

    hash1 = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="Evidence 1",
        description="First evidence",
        extracted_value="data1",
        metadata={},
        previous_hash=None,
        collected_at=time1
    )

    # Second evidence includes hash1 as previous_hash
    hash2 = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="Evidence 2",
        description="Second evidence",
        extracted_value="data2",
        metadata={},
        previous_hash=hash1,
        collected_at=time1
    )

    # Changing previous_hash changes the resulting hash
    hash2_different = ForensicLedger._compute_evidence_hash(
        evidence_type="email_header",
        title="Evidence 2",
        description="Second evidence",
        extracted_value="data2",
        metadata={},
        previous_hash="different_hash",
        collected_at=time1
    )

    assert hash2 != hash2_different


def test_tamper_detection():
    """Test that modifying evidence content changes hash and breaks chain"""
    time1 = datetime.now(timezone.utc)

    # Original evidence
    original_hash = ForensicLedger._compute_evidence_hash(
        evidence_type="ip_address",
        title="Suspicious IP",
        description="IP from known botnet",
        extracted_value="192.168.1.1",
        metadata={"reputation": "malicious"},
        previous_hash=None,
        collected_at=time1
    )

    # Tampered evidence (description changed)
    tampered_hash = ForensicLedger._compute_evidence_hash(
        evidence_type="ip_address",
        title="Suspicious IP",
        description="IP is actually safe",  # TAMPERED
        extracted_value="192.168.1.1",
        metadata={"reputation": "malicious"},
        previous_hash=None,
        collected_at=time1
    )

    # Hashes should differ, indicating tampering
    assert original_hash != tampered_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
