"""
Email Analysis API Endpoints
"""
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List

from app.database import get_db
from app.models.email import Email
from app.schemas import EmailAnalysisResponse, RawEmailInput, EmailListItem
from app.services.email_analysis_orchestrator import EmailAnalysisOrchestrator

router = APIRouter(prefix="/api/v1/emails", tags=["emails"])


@router.post("/analyze", response_model=EmailAnalysisResponse, status_code=status.HTTP_201_CREATED)
async def analyze_email_raw(
    email_input: RawEmailInput,
    db: AsyncSession = Depends(get_db)
):
    """
    Analyze raw email content (paste or API submission).
    Performs complete threat analysis pipeline.
    """
    try:
        result = await EmailAnalysisOrchestrator.analyze_email(
            db=db,
            raw_email_content=email_input.raw_content,
            source=email_input.source or "api"
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )


@router.post("/upload", response_model=EmailAnalysisResponse, status_code=status.HTTP_201_CREATED)
async def upload_email_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload .eml or .msg file for analysis.
    """
    # Validate file extension
    if not file.filename or not any(file.filename.endswith(ext) for ext in [".eml", ".msg", ".txt"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only .eml, .msg, and .txt files are supported."
        )

    # Read file content
    try:
        content = await file.read()

        # Decode content
        try:
            raw_content = content.decode('utf-8')
        except UnicodeDecodeError:
            raw_content = content.decode('latin-1')

        result = await EmailAnalysisOrchestrator.analyze_email(
            db=db,
            raw_email_content=raw_content,
            source="file_upload"
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File upload failed: {str(e)}"
        )


@router.get("/", response_model=List[EmailListItem])
async def list_emails(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """
    List analyzed emails with pagination.
    """
    stmt = select(Email).order_by(desc(Email.created_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    emails = result.scalars().all()
    return emails


@router.get("/{email_id}", response_model=EmailAnalysisResponse)
async def get_email_analysis(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed analysis for a specific email.
    """
    stmt = select(Email).where(Email.email_id == email_id)
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID {email_id} not found"
        )

    # TODO: Build full EmailAnalysisResponse from stored data
    # For now, return simplified response
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Full email retrieval not yet implemented"
    )


@router.delete("/{email_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_email(
    email_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an email and all associated analysis data.
    """
    stmt = select(Email).where(Email.email_id == email_id)
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with ID {email_id} not found"
        )

    await db.delete(email)
    await db.commit()
    return None
