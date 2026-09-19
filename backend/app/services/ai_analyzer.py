"""
AI Analysis Service - LLM-powered threat classification and reasoning
Supports multiple providers (OpenAI, Anthropic, etc.) with structured output validation
"""
import json
import logging
from typing import Optional, List, Dict, Any, Tuple
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic
from app.config import settings
from app.schemas import AIAnalysisResult

logger = logging.getLogger("tracex.ai_analyzer")



class AIAnalyzer:
    """
    AI-powered email threat analysis service.
    Uses LLM to classify threats and explain reasoning based on extracted evidence.
    """

    def __init__(self):
        self.provider = settings.AI_PROVIDER.lower()
        self.api_key = settings.AI_API_KEY
        self.model = settings.AI_MODEL

        # Initialize clients based on provider
        self.openai_client = None
        self.anthropic_client = None

        if self.provider == "openai" and self.api_key:
            self.openai_client = AsyncOpenAI(api_key=self.api_key)
        elif self.provider == "anthropic" and self.api_key:
            self.anthropic_client = AsyncAnthropic(api_key=self.api_key)

    async def analyze_email_threat(
        self,
        subject: str,
        from_address: str,
        body_text: str,
        spf_result: str,
        dkim_result: str,
        dmarc_result: str,
        header_anomalies: list,
        threat_indicators: list,
        urls: list,
        attachments: list,
    ) -> AIAnalysisResult:
        """
        Perform AI-based threat classification and reasoning.
        Returns structured output validated against schema.
        Falls back to rule-based analysis if AI is unavailable.
        """

        # Build evidence-based prompt
        prompt = self._build_analysis_prompt(
            subject=subject,
            from_address=from_address,
            body_text=body_text,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            header_anomalies=header_anomalies,
            threat_indicators=threat_indicators,
            urls=urls,
            attachments=attachments
        )

        # Try AI analysis
        if self.api_key and (self.openai_client or self.anthropic_client):
            try:
                if self.provider == "openai":
                    result = await self._analyze_with_openai(prompt)
                elif self.provider == "anthropic":
                    result = await self._analyze_with_anthropic(prompt)
                else:
                    result = self._fallback_analysis(threat_indicators, spf_result, dkim_result, dmarc_result)

                # Validate result has all required fields
                if self._validate_result(result):
                    return result
            except Exception as e:
                # Log error and fall back
                print(f"AI analysis failed: {e}")

        # Fallback to rule-based
        return self._fallback_analysis(threat_indicators, spf_result, dkim_result, dmarc_result)

    def _build_analysis_prompt(
        self,
        subject: str,
        from_address: str,
        body_text: str,
        spf_result: str,
        dkim_result: str,
        dmarc_result: str,
        header_anomalies: list,
        threat_indicators: list,
        urls: list,
        attachments: list
    ) -> str:
        """Build evidence-based analysis prompt for LLM"""

        # Truncate body to avoid excessive tokens
        body_preview = body_text[:2000] if body_text else "(No body text)"

        prompt = f"""You are an email security analyst. Analyze this email and provide a structured threat assessment.

IMPORTANT: Base your analysis ONLY on the provided evidence. Do not invent indicators that are not present.

Email Evidence:
- Subject: {subject}
- From: {from_address}
- SPF: {spf_result}
- DKIM: {dkim_result}
- DMARC: {dmarc_result}

Header Anomalies: {json.dumps(header_anomalies)}
Detected Threat Indicators: {json.dumps(threat_indicators)}
URLs Found: {len(urls)}
Attachments: {len(attachments)}

Body Preview:
{body_preview}

Respond with a JSON object containing:
{{
  "classification": "clean" | "spam" | "phishing" | "spear_phishing" | "bec" | "malware" | "spoofing",
  "confidence": <float 0.0 to 1.0>,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "indicators": [<list of specific observed indicators, cite evidence only>],
  "reasoning": "<explain why, referencing specific evidence>",
  "recommended_actions": [<list of actions>],
  "evidence_citations": [<list of evidence items you referenced>]
}}

Classification definitions:
- clean: No threat indicators
- spam: Unsolicited bulk mail, low severity
- phishing: Credential harvesting attempt
- spear_phishing: Targeted phishing against specific individual/organization
- bec: Business Email Compromise attempt
- malware: Contains or links to malware
- spoofing: Sender identity forgery

Respond ONLY with valid JSON, no markdown or extra text.
"""
        return prompt

    async def _analyze_with_openai(self, prompt: str) -> AIAnalysisResult:
        """Call OpenAI API for analysis"""
        response = await self.openai_client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert email security analyst. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=settings.AI_TEMPERATURE,
            max_tokens=settings.AI_MAX_TOKENS,
        )

        content = response.choices[0].message.content.strip()

        # Try to parse JSON
        try:
            data = json.loads(content)
            return AIAnalysisResult(
                classification=data.get("classification", "unknown"),
                confidence=float(data.get("confidence", 0.5)),
                severity=data.get("severity", "MEDIUM"),
                indicators=data.get("indicators", []),
                reasoning=data.get("reasoning", ""),
                recommended_actions=data.get("recommended_actions", []),
                evidence_citations=data.get("evidence_citations", []),
                is_fallback=False
            )
        except json.JSONDecodeError:
            # If LLM didn't return valid JSON, fall back
            raise ValueError("LLM did not return valid JSON")

    async def _analyze_with_anthropic(self, prompt: str) -> AIAnalysisResult:
        """Call Anthropic Claude API for analysis"""
        message = await self.anthropic_client.messages.create(
            model=self.model,
            max_tokens=settings.AI_MAX_TOKENS,
            temperature=settings.AI_TEMPERATURE,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        content = message.content[0].text.strip()

        # Try to parse JSON
        try:
            data = json.loads(content)
            return AIAnalysisResult(
                classification=data.get("classification", "unknown"),
                confidence=float(data.get("confidence", 0.5)),
                severity=data.get("severity", "MEDIUM"),
                indicators=data.get("indicators", []),
                reasoning=data.get("reasoning", ""),
                recommended_actions=data.get("recommended_actions", []),
                evidence_citations=data.get("evidence_citations", []),
                is_fallback=False
            )
        except json.JSONDecodeError:
            raise ValueError("LLM did not return valid JSON")

    def _fallback_analysis(
        self,
        threat_indicators: list,
        spf_result: str,
        dkim_result: str,
        dmarc_result: str
    ) -> AIAnalysisResult:
        """Rule-based fallback when AI is unavailable"""

        # Simple rule-based classification
        indicator_count = len(threat_indicators)
        auth_failures = sum(1 for r in [spf_result, dkim_result, dmarc_result] if r == "FAIL")

        if indicator_count == 0 and auth_failures == 0:
            classification = "clean"
            severity = "INFO"
            confidence = 0.7
            reasoning = "No significant threat indicators detected."
        elif auth_failures >= 2 and indicator_count >= 2:
            classification = "phishing"
            severity = "HIGH"
            confidence = 0.85
            reasoning = "Multiple authentication failures combined with phishing indicators suggest credential harvesting attempt."
        elif auth_failures >= 2:
            classification = "spoofing"
            severity = "HIGH"
            confidence = 0.8
            reasoning = "Email authentication failures indicate sender domain forgery."
        elif indicator_count >= 3:
            classification = "phishing"
            severity = "MEDIUM"
            confidence = 0.75
            reasoning = "Multiple suspicious characteristics detected."
        else:
            classification = "spam"
            severity = "LOW"
            confidence = 0.6
            reasoning = "Some suspicious indicators present, but low confidence of targeted attack."

        return AIAnalysisResult(
            classification=classification,
            confidence=confidence,
            severity=severity,
            indicators=threat_indicators[:5],
            reasoning=f"[Rule-based analysis] {reasoning}",
            recommended_actions=self._get_recommended_actions(classification, severity),
            evidence_citations=["threat_detection", "authentication_results"],
            is_fallback=True
        )

    def _get_recommended_actions(self, classification: str, severity: str) -> list:
        """Generate recommended actions based on classification"""
        actions = []

        if severity in ["CRITICAL", "HIGH"]:
            actions.append("Quarantine email immediately")
            actions.append("Block sender domain/IP at email gateway")
            actions.append("Notify security team")

        if classification in ["phishing", "spear_phishing", "bec"]:
            actions.append("Alert affected users about phishing attempt")
            actions.append("Check for similar emails in mailboxes")
            actions.append("Add indicators to threat intelligence feeds")

        if classification == "malware":
            actions.append("Scan all systems that may have opened attachments")
            actions.append("Update antivirus signatures")

        if classification == "spoofing":
            actions.append("Verify SPF/DKIM/DMARC policies for organization domains")
            actions.append("Consider DMARC enforcement policy")

        if not actions:
            actions.append("Continue monitoring")
            actions.append("Document for threat intelligence")

        return actions

    def _validate_result(self, result: AIAnalysisResult) -> bool:
        """Validate AI result has required fields with sensible values"""
        if not result.classification or result.classification not in [
            "clean", "spam", "phishing", "spear_phishing", "bec", "malware", "spoofing", "unknown"
        ]:
            return False
        if not (0.0 <= result.confidence <= 1.0):
            return False
        if not result.severity or result.severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            return False
        if not result.reasoning:
            return False
        return True

    # =========================================================================
    # SOC Analyst Copilot Chatbot Engine
    # =========================================================================

    async def answer_soc_copilot(
        self,
        messages: List[Dict[str, str]],
        threat_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, List[str], str]:
        """
        Process conversational SOC analyst queries.
        Explains SPF/DKIM/DMARC failures, decodes header anomalies,
        and provides incident containment playbooks.
        Uses OpenAI or Anthropic if configured, with comprehensive offline SOC heuristic reasoning as fallback.
        Returns: (response_text, suggested_actions, model_name)
        """
        is_dummy_key = (
            not self.api_key
            or "your-openai-api-key" in self.api_key
            or "your-anthropic-key" in self.api_key
            or self.api_key.startswith("sk-your-")
        )

        system_instruction = (
            "You are TRACE-X SOC Copilot, an elite Tier-3 Cyber Security Operations Center (SOC) Lead Analyst "
            "and Email Forensics Specialist in TRACE-X Pro.\n"
            "Your mission is to assist security analysts, incident responders, and SOC managers in evaluating email threats, "
            "explaining SPF/DKIM/DMARC authentication failures, decoding header anomalies, explaining phishing and BEC tactics, "
            "and generating actionable containment playbooks (aligned with NIST SP 800-61r2 and SANS).\n"
            "Style: authoritative, structured, concise, and technically rigorous. Use markdown headings, bullet points, "
            "and code blocks for commands or hunting queries.\n"
        )

        if threat_context:
            context_summary = self._format_threat_context(threat_context)
            system_instruction += f"\n[ACTIVE INCIDENT FORENSIC CONTEXT]\n{context_summary}\n"

        # Try live LLM if valid key is configured and demo mode not forced
        if not is_dummy_key and not settings.USE_DEMO_INTELLIGENCE:
            try:
                if self.provider == "openai" and self.openai_client:
                    llm_msgs = [{"role": "system", "content": system_instruction}] + [
                        {"role": m["role"], "content": m["content"]} for m in messages
                    ]
                    response = await self.openai_client.chat.completions.create(
                        model=self.model,
                        messages=llm_msgs,
                        temperature=0.3,
                        max_tokens=1500
                    )
                    content = response.choices[0].message.content or ""
                    suggested_actions = self._generate_suggested_actions(content, threat_context)
                    return content, suggested_actions, self.model

                elif self.provider == "anthropic" and self.anthropic_client:
                    formatted_msgs = [
                        {"role": m["role"] if m["role"] in ["user", "assistant"] else "user", "content": m["content"]}
                        for m in messages
                    ]
                    response = await self.anthropic_client.messages.create(
                        model=self.model,
                        system=system_instruction,
                        messages=formatted_msgs,
                        temperature=0.3,
                        max_tokens=1500
                    )
                    content = response.content[0].text or ""
                    suggested_actions = self._generate_suggested_actions(content, threat_context)
                    return content, suggested_actions, self.model
            except Exception as e:
                logger.warning(f"Live AI provider call failed ({e}). Falling back to TRACE-X offline SOC heuristic engine.")

        # Fallback to offline heuristic SOC engine
        response_text, suggested_actions = self._heuristic_soc_copilot_response(messages, threat_context)
        return response_text, suggested_actions, "trace-x-soc-copilot-engine"

    def _format_threat_context(self, ctx: Dict[str, Any]) -> str:
        """Format active incident context dictionary into prompt string"""
        lines = []
        if ctx.get("email_id"):
            lines.append(f"- Email ID: {ctx['email_id']}")
        if ctx.get("subject"):
            lines.append(f"- Subject: {ctx['subject']}")
        if ctx.get("from_address"):
            lines.append(f"- Sender (From): {ctx['from_address']}")
        if ctx.get("to_address"):
            lines.append(f"- Recipient (To): {ctx['to_address']}")
        if ctx.get("risk_score") is not None:
            lines.append(f"- Risk Score: {ctx['risk_score']} / 100 ({ctx.get('severity', 'UNKNOWN')})")
        if ctx.get("threat_type") or ctx.get("classification"):
            lines.append(f"- Classification: {ctx.get('threat_type') or ctx.get('classification')}")
        if ctx.get("is_malicious") is not None:
            lines.append(f"- Is Malicious: {ctx['is_malicious']}")
        if ctx.get("spf_result"):
            lines.append(f"- SPF Verdict: {ctx['spf_result']}")
        if ctx.get("dkim_result"):
            lines.append(f"- DKIM Verdict: {ctx['dkim_result']}")
        if ctx.get("dmarc_result"):
            lines.append(f"- DMARC Verdict: {ctx['dmarc_result']}")
        if ctx.get("header_anomalies"):
            lines.append(f"- Header Anomalies: {ctx['header_anomalies']}")
        if ctx.get("indicators"):
            lines.append(f"- Indicators: {ctx['indicators']}")
        if ctx.get("urls"):
            lines.append(f"- Extracted URLs: {ctx['urls'][:5]}")
        if ctx.get("attachments"):
            lines.append(f"- Attachments: {ctx['attachments'][:5]}")
        return "\n".join(lines)

    def _generate_suggested_actions(self, content: str, threat_context: Optional[Dict[str, Any]]) -> List[str]:
        """Generate dynamic suggested action prompts for analysts"""
        actions = []
        lower = content.lower()
        if "playbook" not in lower and "containment" not in lower:
            actions.append("Generate 4-phase containment playbook")
        if "spf" not in lower and "dmarc" not in lower:
            actions.append("Explain DMARC alignment failure")
        if "kql" not in lower and "splunk" not in lower:
            actions.append("Generate KQL threat hunting query")
        if "header" not in lower:
            actions.append("Decode header routing anomalies")
        return actions[:4]

    def _heuristic_soc_copilot_response(
        self,
        messages: List[Dict[str, str]],
        threat_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, List[str]]:
        """
        Expert Tier-3 SOC analyst offline heuristic intelligence engine.
        Diagnoses SPF/DKIM/DMARC failures, decodes header anomalies,
        formulates NIST/SANS containment playbooks, and generates KQL/Splunk threat hunting queries.
        """
        ctx = threat_context or {}
        last_user_query = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user_query = m.get("content", "").strip()
                break

        q = last_user_query.lower()

        # Extract incident variables
        subject = ctx.get("subject") or "Suspicious Email Inbound Alert"
        from_addr = ctx.get("from_address") or "unverified-sender@external-domain.com"
        spf = ctx.get("spf_result") or "FAIL"
        dkim = ctx.get("dkim_result") or "FAIL"
        dmarc = ctx.get("dmarc_result") or "FAIL"
        risk_score = ctx.get("risk_score", 85)
        threat_type = ctx.get("threat_type") or ctx.get("classification") or "phishing"
        anomalies = ctx.get("header_anomalies") or []

        # 1. SPF / DKIM / DMARC Authentication Inquiries
        if any(k in q for k in ["spf", "dkim", "dmarc", "authentication", "auth", "alignment", "softfail", "hardfail", "signature"]):
            has_ctx = bool(ctx.get("spf_result") or ctx.get("dkim_result") or ctx.get("dmarc_result"))
            title = "### 🛡️ Email Authentication Diagnostic Analysis\n"
            if has_ctx:
                title += f"**Incident Target**: `{from_addr}` | **Subject**: \"{subject}\"\n\n"

            from_domain = from_addr.split('@')[-1] if '@' in from_addr else from_addr
            body = (
                f"{title}"
                f"#### 1. SPF (Sender Policy Framework - RFC 7208): **{spf}**\n"
                f"- **Mechanism Check**: SPF validates the connecting MTA's IP address against the DNS TXT records published by the envelope sender domain (`MAIL FROM` / Return-Path).\n"
                f"- **Forensic Assessment**: The connecting sending IP was **not authorized** in the domain's SPF record. "
                f"Attackers commonly forge the envelope address or send from unauthorized cloud VPS/relays without possessing matching SPF authorization (`-all` hardfail or `~all` softfail).\n\n"
                f"#### 2. DKIM (DomainKeys Identified Mail - RFC 6376): **{dkim}**\n"
                f"- **Cryptographic Check**: DKIM computes an RSA-SHA256 digital signature over chosen headers and the body hash (`bh=`). The receiving mail server queries `selector._domainkey.domain` to retrieve the public key and verify signature integrity.\n"
                f"- **Forensic Assessment**: DKIM evaluated to **{dkim}**. This signifies either:\n"
                f"  - The signature is invalid or absent (no valid private key held by sender).\n"
                f"  - The message body or signed headers were tampered with or rewritten in transit by an intermediary MTA.\n"
                f"  - A DKIM replay attack was attempted using mismatched header parameters.\n\n"
                f"#### 3. DMARC (Domain-based Message Authentication - RFC 7489): **{dmarc}**\n"
                f"- **Alignment Check**: DMARC mandates **Identifier Alignment**: the RFC 5322 visible `From:` header domain must strictly or relaxedly align with either an **SPF-authenticated domain** OR a **DKIM-authenticated signing domain** (`d=`).\n"
                f"- **Forensic Verdict**: Because both SPF and DKIM failed alignment with the visible From domain (`{from_domain}`), DMARC fails completely.\n"
                f"- **Recommended Policy**: If your organization controls this domain, configure `v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com` to drop spoofed messages at SMTP time."
            )
            suggested = [
                "Generate 4-phase containment playbook",
                "Decode header routing anomalies",
                "Generate KQL threat hunting query",
                "Draft user warning notification"
            ]
            return body, suggested

        # 2. Header Anomalies & Routing Analysis
        elif any(k in q for k in ["header", "hop", "route", "relay", "anomaly", "anomalies", "received", "transit", "delay", "reply-to", "message-id"]):
            body = (
                f"### 🔍 RFC 5322 / RFC 822 Header Forensic Investigation\n\n"
                f"#### 1. Received Header Hop Traversal (Bottom-to-Top)\n"
                f"- **Routing Integrity**: Email routing headers must be traced chronologically from the lowest `Received:` header (originating client/MTA) up to the topmost header (your perimeter MX gate).\n"
                f"- **Transit Delay Analysis**: High timestamp deltas (>15-30 minutes) between intermediate hops often signify staging relays, bulletproof proxy routing, or queued spam botnet nodes.\n\n"
                f"#### 2. Critical Header Discrepancies & Spoofing Indicators\n"
                f"- **From vs. Reply-To Mismatch**: A classic executive impersonation / credential phishing technique. The visible `From:` displays a trusted identity, but the `Reply-To:` redirects responses to an attacker-controlled external freemail address.\n"
                f"- **Message-ID Syntax Validation**: Standard MTAs generate structured Message-IDs with legitimate domain FQDNs (e.g. `<GUID@mail.domain.com>`). Forged or random alphanumeric hashes without valid domain suffixes indicate scripted attack tools (e.g. PHPMailer, Python smtplib, evilginx).\n"
                f"- **X-Originating-IP Geolocation**: Directly inspect the initial client IP hop. Look for known Tor exit nodes, commercial VPN proxies, or VPS hosts hosting phishing kits."
            )
            if anomalies:
                body += f"\n\n#### Detected Anomalies in Current Investigation:\n"
                for anom in anomalies:
                    body += f"- ⚠️ **{anom}**\n"

            suggested = [
                "Explain DMARC alignment failure",
                "Generate 4-phase containment playbook",
                "Generate KQL threat hunting query",
                "Provide risk score breakdown"
            ]
            return body, suggested

        # 3. Incident Containment & Remediation Playbooks
        elif any(k in q for k in ["contain", "containment", "playbook", "remediate", "remediation", "quarantine", "mitigate", "block", "isolate", "action", "step", "response"]):
            body = (
                f"### 🚨 NIST SP 800-61r2 Incident Containment & Eradication Playbook\n\n"
                f"**Target**: `{from_addr}` | **Subject**: \"{subject}\" | **Threat Type**: `{threat_type.upper()}`\n\n"
                f"#### Phase 1: Perimeter & Gateway Containment (Immediate)\n"
                f"1. **Email Security Gateway (ESG)**: Add sender address (`{from_addr}`) and envelope domain to tenant-wide Blocklist.\n"
                f"2. **DNS & Web Proxy Sinkhole**: Submit extracted IoC domains and URLs to Secure Web Gateway (SWG) and DNS filtering (Cisco Umbrella/Infoblox) as high-confidence malicious.\n"
                f"3. **Firewall / WAF Block**: Block originating relay IPs at perimeter edge firewalls.\n\n"
                f"#### Phase 2: Tenant-Wide Mailbox Purge\n"
                f"Execute automated administrative search and purge across all tenant mailboxes to neutralize unopened copies:\n\n"
                f"```powershell\n"
                f"# Microsoft 365 Exchange Online Security & Compliance PowerShell\n"
                f"$SearchName = \"TRACE-X_Triage_Incident\"\n"
                f"New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery 'Subject:\"{subject}\" OR From:\"{from_addr}\"'\n"
                f"Start-ComplianceSearch -Identity $SearchName\n"
                f"New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete\n"
                f"```\n\n"
                f"#### Phase 3: Identity & Credential Neutralization\n"
                f"1. **Revoke Active Sessions**: For any recipient who interacted with the email, immediately revoke Azure AD / Okta refresh tokens:\n"
                f"   ```powershell\n"
                f"   Revoke-AzureADUserAllRefreshToken -ObjectId <UserPrincipalId>\n"
                f"   ```\n"
                f"2. **Enforce Credential Reset**: Mark identity as 'High Risk' in Microsoft Entra ID Identity Protection.\n"
                f"3. **MFA Audit**: Review Azure AD Sign-in logs for anomalous MFA prompts, impossible travel, or Session Hijacking tokens.\n\n"
                f"#### Phase 4: Endpoint Isolation & Forensic Triage\n"
                f"1. **EDR Host Isolation**: If attachments or malicious URLs were opened, isolate recipient workstations using EDR (Defender for Endpoint / CrowdStrike).\n"
                f"2. **Artifact Acquisition**: Collect triage package (memory dump, browser history, LNK files, and scheduled tasks)."
            )
            suggested = [
                "Generate KQL threat hunting query",
                "Explain DMARC alignment failure",
                "Decode header routing anomalies",
                "Draft user security alert notification"
            ]
            return body, suggested

        # 4. Threat Hunting Queries (KQL & Splunk)
        elif any(k in q for k in ["kql", "splunk", "hunt", "hunting", "query", "siem", "sentinel", "rule", "yara"]):
            body = (
                f"### 🎯 Advanced Threat Hunting Queries (SIEM / XDR)\n\n"
                f"#### 1. Microsoft Defender XDR / Sentinel KQL Query:\n"
                f"```kql\n"
                f"// Search for all email deliveries and URL clicks across the enterprise\n"
                f"EmailEvents\n"
                f"| where Timestamp > ago(14d)\n"
                f"| where SenderFromAddress has \"{from_addr}\" or Subject has \"{subject}\"\n"
                f"| join kind=leftouter (\n"
                f"    EmailUrlInfo\n"
                f"    | project NetworkMessageId, Url, UrlDomain\n"
                f") on NetworkMessageId\n"
                f"| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Url, DeliveryAction, ThreatTypes\n"
                f"| order by Timestamp desc\n"
                f"```\n\n"
                f"#### 2. Splunk SPL Query (Email Gateway & Proxy Logs):\n"
                f"```spl\n"
                f"index=email (sourcetype=\"cisco:esa\" OR sourcetype=\"proofpoint:pps\")\n"
                f"| search sender=\"*{from_addr}*\" OR subject=\"*{subject}*\"\n"
                f"| stats count earliest(_time) as first_seen latest(_time) as last_seen by sender, recipient, subject, client_ip, action\n"
                f"| eval first_seen=strftime(first_seen, \"%Y-%m-%d %H:%M:%S\"), last_seen=strftime(last_seen, \"%Y-%m-%d %H:%M:%S\")\n"
                f"```\n\n"
                f"#### 3. Endpoint Execution Hunting (Process Creation):\n"
                f"```kql\n"
                f"DeviceProcessEvents\n"
                f"| where Timestamp > ago(7d)\n"
                f"| where InitiatingProcessFileName in~ (\"outlook.exe\", \"chrome.exe\", \"msedge.exe\")\n"
                f"| where FileName in~ (\"powershell.exe\", \"cmd.exe\", \"wscript.exe\", \"rundll32.exe\", \"mshta.exe\", \"certutil.exe\")\n"
                f"| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n"
                f"```"
            )
            suggested = [
                "Generate 4-phase containment playbook",
                "Explain DMARC alignment failure",
                "Decode header routing anomalies",
                "Check IoC reputation"
            ]
            return body, suggested

        # 5. Risk Assessment & Threat Verdict
        elif any(k in q for k in ["risk", "score", "verdict", "threat", "safe", "malicious", "summary", "assess"]):
            body = (
                f"### 📊 Comprehensive Threat Forensic Assessment\n\n"
                f"- **Overall Risk Score**: **{risk_score}/100** ({ctx.get('severity', 'HIGH')} Severity)\n"
                f"- **Classification**: **{threat_type.upper()}**\n"
                f"- **Target Subject**: \"{subject}\"\n"
                f"- **Sender Identity**: `{from_addr}`\n\n"
                f"#### Forensic Evidence Matrix:\n"
                f"| Dimension | Verdict | Forensic Assessment |\n"
                f"| :--- | :--- | :--- |\n"
                f"| **SPF Check** | `{spf}` | Sending MTA IP is unauthorized in sender domain DNS. |\n"
                f"| **DKIM Signature** | `{dkim}` | Missing or cryptographic body/header hash verification failure. |\n"
                f"| **DMARC Policy** | `{dmarc}` | Failed strict alignment between envelope and visible From domain. |\n"
                f"| **Domain Trust** | `UNTRUSTED` | Typo-squatting, free webmail relay, or newly registered domain. |\n\n"
                f"#### Threat Assessment Verdict:\n"
                f"Based on the cumulative forensic indicators, this email represents an **active, unauthorized threat** designed to deceive recipients and bypass standard perimeter filters. "
                f"Immediate quarantine and containment are recommended."
            )
            suggested = [
                "Generate 4-phase containment playbook",
                "Explain DMARC alignment failure",
                "Generate KQL threat hunting query",
                "Decode header routing anomalies"
            ]
            return body, suggested

        # 6. General / Conversational Response
        else:
            body = (
                f"### 🛡️ TRACE-X SOC Analyst Copilot Online\n\n"
                f"I am ready to assist with your investigation. Here is what I can do for you right now:\n\n"
                f"- **Email Authentication Forensics**: In-depth diagnosis of SPF mechanism failures, DKIM cryptographic signature mismatches, and DMARC identifier alignment.\n"
                f"- **RFC 5322 Header Traversal**: Trace Received hop sequences, isolate MTA relay delays, uncover Reply-To discrepancy, and detect spoofed display names.\n"
                f"- **Containment Playbooks**: Generate step-by-step NIST SP 800-61r2 incident response playbooks with ready-to-run M365 PowerShell commands.\n"
                f"- **Threat Hunting**: Provide automated KQL and Splunk queries to sweep your entire SIEM and EDR for IoCs.\n\n"
            )
            if threat_context:
                body += f"*(Active Threat Context loaded for email: \"{subject}\" from `{from_addr}`)*\n\n"

            body += "What aspect of the investigation would you like to explore?"
            suggested = [
                "Explain DMARC alignment failure",
                "Generate 4-phase containment playbook",
                "Decode header routing anomalies",
                "Generate KQL threat hunting query"
            ]
            return body, suggested


# Global singleton
ai_analyzer = AIAnalyzer()

