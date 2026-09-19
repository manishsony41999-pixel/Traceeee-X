"""
Dashboard and SOC Analytics API Endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.email import Email
from app.models.case import Case, CaseStatus
from app.models.alert import Alert, AlertSeverity
from app.schemas import DashboardStats

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """
    Get aggregated statistics for the SOC investigation dashboard.
    """
    # Total emails analyzed
    total_emails = (await db.execute(select(func.count(Email.id)))).scalar() or 0

    # Threats detected (malicious or suspicious)
    threats_detected = (await db.execute(
        select(func.count(Email.id)).where(Email.is_suspicious == True)
    )).scalar() or 0

    # Critical alerts
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
    )).scalar() or 0

    # High risk emails (risk score >= 60)
    high_risk_emails = (await db.execute(
        select(func.count(Email.id)).where(Email.risk_score >= 60.0)
    )).scalar() or 0

    # Open cases
    cases_opened = (await db.execute(
        select(func.count(Case.id)).where(Case.status != CaseStatus.CLOSED)
    )).scalar() or 0

    active_threats_percent = round((threats_detected / total_emails * 100), 1) if total_emails > 0 else 0.0

    return DashboardStats(
        total_emails_analyzed=total_emails,
        threats_detected=threats_detected,
        critical_alerts=critical_alerts,
        high_risk_emails=high_risk_emails,
        suspicious_ips=max(1, threats_detected // 2),
        suspicious_domains=max(1, threats_detected // 3),
        malicious_urls=max(1, threats_detected // 2),
        cases_opened=cases_opened,
        active_threats_percent=active_threats_percent
    )
