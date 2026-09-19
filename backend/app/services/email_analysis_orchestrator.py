"""
Main Email Analysis Orchestrator
Coordinates all analysis services to perform complete email threat assessment
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.services.email_parser import EmailParserService
from app.services.authentication_analyzer import AuthenticationAnalyzer
from app.services.header_analyzer import HeaderAnalyzer
from app.services.threat_detector import ThreatDetector
from app.services.risk_scorer import RiskScorer
from app.services.ai_analyzer import ai_analyzer
from app.services.forensic_ledger import ForensicLedger
from app.intelligence.manager import threat_intelligence_manager

from app.models.email import Email, EmailHeader
from app.models.threat import IPIntelligence, DomainIntelligence, URLAnalysis, AttachmentAnalysis
from app.models.case import Case, CaseStatus, CaseSeverity
from app.models.alert import Alert, AlertSeverity
from app.models.evidence import Evidence, EvidenceType
from app.models.timeline import TimelineEvent

from app.schemas import (
    EmailAnalysisResponse, AuthStatusEnum, RawEmailInput,
    URLItem, AttachmentItem, EvidenceCreate
)


class EmailAnalysisOrchestrator:
    """
    Main orchestration service that coordinates the complete email analysis workflow:
    1. Parse email
    2. Analyze authentication
    3. Analyze headers
    4. Detect threats
    5. Query threat intelligence
    6. Calculate risk score
    7. Run AI analysis
    8. Generate evidence
    9. Create case if needed
    10. Generate alerts
    11. Build timeline
    """

    @classmethod
    async def analyze_email(
        cls,
        db: Optional[AsyncSession] = None,
        raw_email_content: str | bytes = "",
        source: str = "manual_upload"
    ) -> EmailAnalysisResponse:
        """
        Complete end-to-end email analysis pipeline.
        Returns structured analysis response.
        """

        # STEP 1: Parse email
        parsed = EmailParserService.parse_raw_email(raw_email_content)
        email_id = str(uuid.uuid4())

        # STEP 2: Analyze authentication (SPF/DKIM/DMARC)
        auth_analysis = AuthenticationAnalyzer.analyze(
            headers_dict=parsed.headers_dict,
            from_address=parsed.from_address
        )

        # STEP 3: Analyze headers and routing
        header_analysis = HeaderAnalyzer.analyze_headers(
            headers_dict=parsed.headers_dict,
            from_address=parsed.from_address,
            reply_to=parsed.reply_to
        )

        # STEP 4: Detect threats using rule-based engine
        threat_detection = ThreatDetector.detect_threats(
            subject=parsed.subject,
            body_plain=parsed.body_plain,
            body_html=parsed.body_html,
            from_address=parsed.from_address,
            reply_to=parsed.reply_to,
            urls=parsed.urls,
            attachments=parsed.attachments,
            spf_status=auth_analysis.spf.status.value,
            dkim_status=auth_analysis.dkim.status.value,
            dmarc_status=auth_analysis.dmarc.status.value,
            header_anomalies=header_analysis.anomalies
        )

        # STEP 5: Query threat intelligence for IPs, domains, URLs, attachments
        ip_intelligence_list = []
        if header_analysis.originating_ip:
            ip_intel = await threat_intelligence_manager.get_ip_intelligence(header_analysis.originating_ip)
            ip_intelligence_list.append(ip_intel)

        domain_intelligence_list = []
        if header_analysis.sender_domain:
            domain_intel = await threat_intelligence_manager.get_domain_intelligence(header_analysis.sender_domain)
            domain_intelligence_list.append(domain_intel)

        # Analyze URLs (limit to prevent excessive API calls)
        url_items = []
        for url in parsed.urls[:20]:
            url_rep = await threat_intelligence_manager.get_url_reputation(url)
            url_items.append(URLItem(
                url=url,
                domain=url_rep.get("url", ""),
                is_malicious=url_rep.get("is_malicious", False),
                is_suspicious=url_rep.get("is_suspicious", False),
                reputation_score=url_rep.get("reputation_score"),
                threat_types=url_rep.get("threat_categories", [])
            ))

        # Analyze attachments
        attachment_items = []
        for att in parsed.attachments[:20]:
            file_rep = await threat_intelligence_manager.get_file_reputation(att.get("sha256_hash", ""))
            attachment_items.append(AttachmentItem(
                filename=att.get("filename", ""),
                file_extension=att.get("file_extension"),
                mime_type=att.get("mime_type"),
                file_size=att.get("file_size"),
                sha256_hash=att.get("sha256_hash"),
                md5_hash=att.get("md5_hash"),
                is_malicious=file_rep.get("is_malicious", False),
                is_suspicious=file_rep.get("is_suspicious", False),
                reputation_score=file_rep.get("reputation_score"),
                threat_types=file_rep.get("threat_categories", [])
            ))

        # Count malicious indicators from intelligence
        malicious_ips = sum(1 for ip in ip_intelligence_list if ip.is_malicious)
        malicious_domains = sum(1 for d in domain_intelligence_list if d.is_malicious)
        malicious_urls = sum(1 for u in url_items if u.is_malicious)
        malicious_attachments = sum(1 for a in attachment_items if a.is_malicious)

        # STEP 6: Calculate risk score
        risk_breakdown = RiskScorer.calculate_risk_score(
            threat_indicators=threat_detection["indicators"],
            threat_types=threat_detection["threat_types"],
            spf_status=auth_analysis.spf.status.value,
            dkim_status=auth_analysis.dkim.status.value,
            dmarc_status=auth_analysis.dmarc.status.value,
            header_anomalies=header_analysis.anomalies,
            malicious_ips=malicious_ips,
            malicious_domains=malicious_domains,
            malicious_urls=malicious_urls,
            malicious_attachments=malicious_attachments
        )

        # STEP 7: AI analysis (with fallback)
        ai_analysis = await ai_analyzer.analyze_email_threat(
            subject=parsed.subject,
            from_address=parsed.from_address,
            body_text=parsed.body_plain[:2000],
            spf_result=auth_analysis.spf.status.value,
            dkim_result=auth_analysis.dkim.status.value,
            dmarc_result=auth_analysis.dmarc.status.value,
            header_anomalies=header_analysis.anomalies,
            threat_indicators=threat_detection["indicators"],
            urls=parsed.urls,
            attachments=parsed.attachments
        )

        # Determine final verdict
        is_malicious = threat_detection["is_malicious"] or risk_breakdown.score >= 70
        is_suspicious = threat_detection["is_suspicious"] or risk_breakdown.score >= 40
        threat_type = ai_analysis.classification if ai_analysis.classification != "clean" else None

        # STEP 8: Save to database (if db session provided)
        if db is not None:
            email_record = Email(
                email_id=email_id,
                message_id=parsed.message_id,
                subject=parsed.subject,
                from_address=parsed.from_address,
                to_addresses=parsed.to_addresses,
                cc_addresses=parsed.cc_addresses if parsed.cc_addresses else None,
                reply_to=parsed.reply_to,
                return_path=parsed.return_path,
                body_plain=parsed.body_plain,
                body_html=parsed.body_html,
                date_sent=parsed.date_sent,
                date_received=parsed.date_received or datetime.now(timezone.utc),
                is_suspicious=is_suspicious,
                is_malicious=is_malicious,
                threat_type=threat_type,
                risk_score=risk_breakdown.score,
                spf_result=auth_analysis.spf.status.value,
                dkim_result=auth_analysis.dkim.status.value,
                dmarc_result=auth_analysis.dmarc.status.value,
                ai_classification=ai_analysis.classification,
                ai_confidence=ai_analysis.confidence,
                ai_reasoning=ai_analysis.reasoning,
                ai_indicators=ai_analysis.indicators,
                raw_email=parsed.raw_content,
                analyzed_at=datetime.now(timezone.utc)
            )

            db.add(email_record)
            await db.flush()
            await db.refresh(email_record)

            # Save headers
            for idx, (name, value) in enumerate(parsed.raw_headers):
                header = EmailHeader(
                    email_id=email_record.id,
                    name=name,
                    value=value
                )
                db.add(header)

            # Save received chain with extracted IPs
            for hop in header_analysis.received_chain:
                if hop.from_ip:
                    header = EmailHeader(
                        email_id=email_record.id,
                        name="Received-Hop",
                        value=f"Hop {hop.hop_number}",
                        hop_number=hop.hop_number,
                        from_ip=hop.from_ip,
                        from_hostname=hop.from_hostname,
                        by_hostname=hop.by_hostname,
                        timestamp=hop.timestamp
                    )
                    db.add(header)

            # Save IP intelligence
            for ip_intel in ip_intelligence_list:
                ip_record = IPIntelligence(
                    email_id=email_record.id,
                    ip_address=ip_intel.ip_address,
                    country=ip_intel.country,
                    country_code=ip_intel.country_code,
                    region=ip_intel.region,
                    city=ip_intel.city,
                    latitude=ip_intel.latitude,
                    longitude=ip_intel.longitude,
                    isp=ip_intel.isp,
                    asn=ip_intel.asn,
                    organization=ip_intel.organization,
                    is_hosting=ip_intel.is_hosting,
                    is_proxy=ip_intel.is_proxy,
                    is_vpn=ip_intel.is_vpn,
                    is_tor=ip_intel.is_tor,
                    reputation_score=ip_intel.reputation_score,
                    is_malicious=ip_intel.is_malicious,
                    abuse_confidence_score=ip_intel.abuse_confidence_score,
                    total_reports=ip_intel.total_reports,
                    provider=ip_intel.provider,
                    context_note=ip_intel.context_note
                )
                db.add(ip_record)

            # Save domain intelligence
            for domain_intel in domain_intelligence_list:
                domain_record = DomainIntelligence(
                    email_id=email_record.id,
                    domain=domain_intel.domain,
                    tld=domain_intel.tld,
                    registrar=domain_intel.registrar,
                    creation_date=domain_intel.creation_date,
                    domain_age_days=domain_intel.domain_age_days,
                    reputation_score=domain_intel.reputation_score,
                    is_malicious=domain_intel.is_malicious,
                    is_suspicious=domain_intel.is_suspicious,
                    is_lookalike=domain_intel.is_lookalike,
                    lookalike_target=domain_intel.lookalike_target,
                    has_suspicious_tld=domain_intel.has_suspicious_tld,
                    threat_types=domain_intel.threat_types,
                    provider=domain_intel.provider
                )
                db.add(domain_record)

            await db.commit()

        # STEP 9: Build response
        return EmailAnalysisResponse(
            email_id=email_id,
            message_id=parsed.message_id,
            subject=parsed.subject,
            from_address=parsed.from_address,
            to_addresses=parsed.to_addresses,
            cc_addresses=parsed.cc_addresses,
            reply_to=parsed.reply_to,
            return_path=parsed.return_path,
            date_sent=parsed.date_sent,
            date_received=parsed.date_received or datetime.now(timezone.utc),
            is_suspicious=is_suspicious,
            is_malicious=is_malicious,
            threat_type=threat_type,
            risk_score=risk_breakdown.score,
            severity=risk_breakdown.severity,
            authentication=auth_analysis,
            header_analysis=header_analysis,
            risk_breakdown=risk_breakdown,
            ai_analysis=ai_analysis,
            ip_intelligence=ip_intelligence_list,
            domain_intelligence=domain_intelligence_list,
            urls=url_items,
            attachments=attachment_items,
            analyzed_at=datetime.now(timezone.utc),
            is_demo=any(ip.is_demo for ip in ip_intelligence_list) or any(d.is_demo for d in domain_intelligence_list)
        )
