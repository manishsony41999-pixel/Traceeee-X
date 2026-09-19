"""
Forensic Evidence Ledger with Hash-Chain Integrity Verification
Implements tamper-evident evidence chain using cryptographic hashing.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.evidence import Evidence, EvidenceType
from app.schemas import EvidenceCreate, EvidenceResponse, LedgerVerificationResult
import uuid


class ForensicLedger:
    """
    Forensic evidence ledger with hash-chain integrity.
    Each evidence record contains:
    - Hash of its own content
    - Hash of the previous evidence record
    This creates a tamper-evident chain where any modification breaks integrity.
    """

    @staticmethod
    def _compute_evidence_hash(
        evidence_type: str,
        title: str,
        description: Optional[str],
        extracted_value: Optional[str],
        metadata: Optional[Dict[str, Any]],
        previous_hash: Optional[str],
        collected_at: datetime
    ) -> str:
        """
        Compute SHA-256 hash of evidence content.
        Including previous_hash creates the chain linkage.
        """
        content = {
            "evidence_type": evidence_type,
            "title": title,
            "description": description or "",
            "extracted_value": extracted_value or "",
            "metadata": metadata or {},
            "previous_hash": previous_hash or "",
            "collected_at": collected_at.isoformat(),
        }

        # Deterministic JSON serialization
        json_str = json.dumps(content, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    @classmethod
    async def add_evidence(
        cls,
        db: AsyncSession,
        evidence_data: EvidenceCreate
    ) -> Evidence:
        """
        Add new evidence to the ledger with hash-chain integrity.
        Automatically links to previous evidence in the same case.
        """
        # Get the last evidence in this case to maintain chain
        stmt = select(Evidence).where(
            Evidence.case_id == evidence_data.case_id
        ).order_by(Evidence.chain_index.desc()).limit(1)
        result = await db.execute(stmt)
        last_evidence = result.scalar_one_or_none()

        # Determine chain index and previous hash
        if last_evidence:
            chain_index = last_evidence.chain_index + 1
            previous_hash = last_evidence.evidence_hash
        else:
            chain_index = 0
            previous_hash = None

        # Generate evidence ID
        evidence_id = str(uuid.uuid4())
        collected_at = datetime.now(timezone.utc)

        # Compute hash
        evidence_hash = cls._compute_evidence_hash(
            evidence_type=evidence_data.evidence_type.value,
            title=evidence_data.title,
            description=evidence_data.description,
            extracted_value=evidence_data.extracted_value,
            metadata=evidence_data.metadata,
            previous_hash=previous_hash,
            collected_at=collected_at
        )

        # Create evidence record
        evidence = Evidence(
            evidence_id=evidence_id,
            case_id=evidence_data.case_id,
            email_id=evidence_data.email_id,
            evidence_type=evidence_data.evidence_type,
            title=evidence_data.title,
            description=evidence_data.description,
            extracted_value=evidence_data.extracted_value,
            evidence_metadata=evidence_data.metadata,
            source=evidence_data.source,
            collection_method=evidence_data.collection_method,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            chain_index=chain_index,
            integrity_verified=True,
            verified_at=collected_at,
            collected_at=collected_at
        )

        db.add(evidence)
        await db.flush()
        await db.refresh(evidence)

        return evidence

    @classmethod
    async def verify_chain_integrity(
        cls,
        db: AsyncSession,
        case_id: int
    ) -> LedgerVerificationResult:
        """
        Verify the integrity of the entire evidence chain for a case.
        Recalculates hashes and checks chain linkage.
        Returns True if all hashes match and chain is intact.
        """
        # Get all evidence for this case, ordered by chain index
        stmt = select(Evidence).where(
            Evidence.case_id == case_id
        ).order_by(Evidence.chain_index)
        result = await db.execute(stmt)
        evidence_chain = result.scalars().all()

        if not evidence_chain:
            return LedgerVerificationResult(
                case_id=str(case_id),
                total_records=0,
                is_valid=True,
                message="No evidence records found for this case."
            )

        previous_hash = None
        for idx, evidence in enumerate(evidence_chain):
            # Verify chain linkage
            if evidence.previous_hash != previous_hash:
                return LedgerVerificationResult(
                    case_id=str(case_id),
                    total_records=len(evidence_chain),
                    is_valid=False,
                    compromised_index=idx,
                    message=f"Chain integrity broken at index {idx}: previous_hash mismatch."
                )

            # Recalculate hash
            expected_hash = cls._compute_evidence_hash(
                evidence_type=evidence.evidence_type.value,
                title=evidence.title,
                description=evidence.description,
                extracted_value=evidence.extracted_value,
                metadata=evidence.evidence_metadata,
                previous_hash=evidence.previous_hash,
                collected_at=evidence.collected_at
            )

            # Verify hash matches
            if evidence.evidence_hash != expected_hash:
                return LedgerVerificationResult(
                    case_id=str(case_id),
                    total_records=len(evidence_chain),
                    is_valid=False,
                    compromised_index=idx,
                    message=f"Evidence hash mismatch at index {idx}: content has been tampered with."
                )

            # Update for next iteration
            previous_hash = evidence.evidence_hash

        # All checks passed
        return LedgerVerificationResult(
            case_id=str(case_id),
            total_records=len(evidence_chain),
            is_valid=True,
            message=f"Chain integrity verified: All {len(evidence_chain)} evidence records are intact."
        )

    @classmethod
    async def get_evidence_by_case(
        cls,
        db: AsyncSession,
        case_id: int
    ) -> List[Evidence]:
        """Get all evidence for a case, ordered by chain index"""
        stmt = select(Evidence).where(
            Evidence.case_id == case_id
        ).order_by(Evidence.chain_index)
        result = await db.execute(stmt)
        return result.scalars().all()
