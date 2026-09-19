"""
Evidence Ledger API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.schemas import EvidenceCreate, EvidenceResponse, LedgerVerificationResult
from app.services.forensic_ledger import ForensicLedger

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


@router.post("/", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def add_evidence(
    evidence_data: EvidenceCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Add new evidence to the tamper-evident forensic ledger.
    Automatically links to the previous evidence in the case hash chain.
    """
    # Verify case exists
    stmt = select(Case).where(Case.id == evidence_data.case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {evidence_data.case_id} not found"
        )

    evidence = await ForensicLedger.add_evidence(db, evidence_data)
    await db.commit()
    await db.refresh(evidence)

    return evidence


@router.get("/case/{case_id}", response_model=List[EvidenceResponse])
async def get_case_evidence(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all evidence for a specific case, ordered by hash chain index"""
    # Find case by string ID
    stmt = select(Case).where(Case.case_id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found"
        )

    evidence_list = await ForensicLedger.get_evidence_by_case(db, case.id)
    return evidence_list


@router.post("/verify/{case_id}", response_model=LedgerVerificationResult)
async def verify_case_evidence_integrity(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Forensically verify the cryptographic hash-chain integrity of all evidence for a case.
    Recalculates every SHA-256 hash and checks the previous-hash linkages.
    Reports whether the ledger is INTEGRITY VERIFIED or INTEGRITY COMPROMISED.
    """
    stmt = select(Case).where(Case.case_id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found"
        )

    verification = await ForensicLedger.verify_chain_integrity(db, case.id)
    return verification
