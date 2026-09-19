"""
Case Management API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from typing import List

from app.database import get_db
from app.models.case import Case
from app.models.email import Email
from app.models.evidence import Evidence
from app.models.alert import Alert
from app.schemas import CaseCreate, CaseUpdate, CaseSummary, CaseDetail

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.post("/", response_model=CaseSummary, status_code=status.HTTP_201_CREATED)
async def create_case(
    case_data: CaseCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new investigation case"""
    import uuid
    from datetime import datetime, timezone

    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    case = Case(
        case_id=case_id,
        title=case_data.title,
        description=case_data.description,
        severity=case_data.severity,
        analyst_id=case_data.analyst_id
    )

    db.add(case)
    await db.commit()
    await db.refresh(case)

    # Get counts
    stmt_emails = select(func.count(Email.id)).where(Email.case_id == case.id)
    emails_count = (await db.execute(stmt_emails)).scalar() or 0

    stmt_evidence = select(func.count(Evidence.id)).where(Evidence.case_id == case.id)
    evidence_count = (await db.execute(stmt_evidence)).scalar() or 0

    stmt_alerts = select(func.count(Alert.id)).where(Alert.case_id == case.id)
    alerts_count = (await db.execute(stmt_alerts)).scalar() or 0

    return CaseSummary(
        id=case.id,
        case_id=case.case_id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        emails_count=emails_count,
        evidence_count=evidence_count,
        alerts_count=alerts_count,
        created_at=case.created_at,
        updated_at=case.updated_at
    )


@router.get("/", response_model=List[CaseSummary])
async def list_cases(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List all investigation cases"""
    stmt = select(Case).order_by(desc(Case.created_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    cases = result.scalars().all()

    summaries = []
    for case in cases:
        stmt_emails = select(func.count(Email.id)).where(Email.case_id == case.id)
        emails_count = (await db.execute(stmt_emails)).scalar() or 0

        stmt_evidence = select(func.count(Evidence.id)).where(Evidence.case_id == case.id)
        evidence_count = (await db.execute(stmt_evidence)).scalar() or 0

        stmt_alerts = select(func.count(Alert.id)).where(Alert.case_id == case.id)
        alerts_count = (await db.execute(stmt_alerts)).scalar() or 0

        summaries.append(CaseSummary(
            id=case.id,
            case_id=case.case_id,
            title=case.title,
            description=case.description,
            status=case.status,
            severity=case.severity,
            emails_count=emails_count,
            evidence_count=evidence_count,
            alerts_count=alerts_count,
            created_at=case.created_at,
            updated_at=case.updated_at
        ))

    return summaries


@router.get("/{case_id}")
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get detailed case information"""
    stmt = select(Case).where(Case.case_id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found"
        )

    # TODO: Build full CaseDetail response
    return {"case_id": case.case_id, "title": case.title, "status": case.status}


@router.patch("/{case_id}", response_model=CaseSummary)
async def update_case(
    case_id: str,
    case_update: CaseUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update case information"""
    stmt = select(Case).where(Case.case_id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found"
        )

    # Update fields if provided
    if case_update.title is not None:
        case.title = case_update.title
    if case_update.description is not None:
        case.description = case_update.description
    if case_update.status is not None:
        case.status = case_update.status
    if case_update.severity is not None:
        case.severity = case_update.severity
    if case_update.analyst_id is not None:
        case.analyst_id = case_update.analyst_id

    await db.commit()
    await db.refresh(case)

    return CaseSummary(
        id=case.id,
        case_id=case.case_id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        emails_count=0,
        evidence_count=0,
        alerts_count=0,
        created_at=case.created_at,
        updated_at=case.updated_at
    )


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a case and all associated data"""
    stmt = select(Case).where(Case.case_id == case_id)
    result = await db.execute(stmt)
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found"
        )

    await db.delete(case)
    await db.commit()
    return None
