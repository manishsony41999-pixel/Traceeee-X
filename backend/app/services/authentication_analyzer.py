"""
Email Authentication Analyzer (SPF, DKIM, DMARC, ARC)
Extracts and forensically explains authentication results from email headers.
"""
import re
from typing import Dict, List, Optional
from app.schemas import AuthResult, AuthStatusEnum, EmailAuthenticationAnalysis


class AuthenticationAnalyzer:
    """Analyzes email authentication protocols (SPF, DKIM, DMARC, ARC)"""

    @classmethod
    def analyze(cls, headers_dict: Dict[str, List[str]], from_address: str) -> EmailAuthenticationAnalysis:
        """
        Analyze authentication headers and determine protocol states and implications.
        """
        spf_result = cls._analyze_spf(headers_dict, from_address)
        dkim_result = cls._analyze_dkim(headers_dict)
        dmarc_result = cls._analyze_dmarc(headers_dict, from_address, spf_result.status, dkim_result.status)
        arc_result = cls._analyze_arc(headers_dict)

        # Build summary
        passed_count = sum(1 for r in [spf_result, dkim_result, dmarc_result] if r.status == AuthStatusEnum.PASS)
        failed_count = sum(1 for r in [spf_result, dkim_result, dmarc_result] if r.status == AuthStatusEnum.FAIL)

        if failed_count > 0:
            summary = f"Authentication issues detected: {failed_count} protocol(s) failed validation."
        elif passed_count == 3:
            summary = "All major email authentication mechanisms (SPF, DKIM, DMARC) passed."
        elif passed_count > 0:
            summary = f"Partial authentication pass ({passed_count}/3 passed, none explicitly failed)."
        else:
            summary = "No verifiable authentication records were present in the email headers."

        return EmailAuthenticationAnalysis(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            arc=arc_result,
            summary=summary
        )

    @classmethod
    def _analyze_spf(cls, headers: Dict[str, List[str]], from_addr: str) -> AuthResult:
        """Extract and interpret SPF results from Received-SPF or Authentication-Results headers"""
        # 1. Check Received-SPF
        recv_spf = headers.get("received-spf", [])
        auth_results = headers.get("authentication-results", [])

        raw_spf = None
        status = AuthStatusEnum.NONE
        details = None

        if recv_spf:
            raw_spf = recv_spf[0]
            norm_lower = raw_spf.lower()
            if norm_lower.startswith("pass") or " spf=pass" in norm_lower:
                status = AuthStatusEnum.PASS
                details = "Sender IP matches SPF policy authorized IPs for the sending domain."
            elif norm_lower.startswith("fail") or " spf=fail" in norm_lower or "hardfail" in norm_lower:
                status = AuthStatusEnum.FAIL
                details = "Sender IP is NOT authorized to send mail on behalf of the domain (Hard Fail)."
            elif "softfail" in norm_lower:
                status = AuthStatusEnum.FAIL
                details = "Sender IP is probably not authorized (Soft Fail ~all policy)."
            elif "neutral" in norm_lower:
                status = AuthStatusEnum.NEUTRAL
                details = "Domain SPF record explicitly does not state whether IP is authorized (?all)."
            elif "none" in norm_lower:
                status = AuthStatusEnum.NONE
                details = "No SPF record published for sending domain."
        elif auth_results:
            for ar in auth_results:
                match = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', ar, re.IGNORECASE)
                if match:
                    raw_spf = match.group(0)
                    spf_val = match.group(1).lower()
                    if spf_val == "pass":
                        status = AuthStatusEnum.PASS
                        details = "Authentication-Results header indicates SPF PASS."
                    elif spf_val in ["fail", "softfail", "hardfail"]:
                        status = AuthStatusEnum.FAIL
                        details = f"Authentication-Results header indicates SPF {spf_val.upper()}."
                    elif spf_val == "neutral":
                        status = AuthStatusEnum.NEUTRAL
                        details = "Authentication-Results header indicates SPF NEUTRAL."
                    elif spf_val == "none":
                        status = AuthStatusEnum.NONE
                        details = "No SPF record found in Authentication-Results."
                    break

        if status == AuthStatusEnum.PASS:
            explanation = "SPF validation succeeded. The originating mail server was explicitly authorized by the domain owner's DNS records."
        elif status == AuthStatusEnum.FAIL:
            explanation = "SPF validation failed. The mail server sending this message is not listed in the DNS TXT SPF record for this domain, strongly suggesting spoofing or unauthorized relay."
        elif status == AuthStatusEnum.NEUTRAL:
            explanation = "SPF returned Neutral. The domain owner chose not to declare an explicit policy on sending servers."
        elif status == AuthStatusEnum.NONE:
            explanation = "No SPF record was found for the sender domain. This leaves the domain vulnerable to sender forgery."
        else:
            explanation = "SPF status could not be conclusively determined from available headers."

        return AuthResult(
            status=status,
            details=details,
            raw_header=raw_spf,
            explanation=explanation
        )

    @classmethod
    def _analyze_dkim(cls, headers: Dict[str, List[str]]) -> AuthResult:
        """Extract and interpret DKIM results from DKIM-Signature and Authentication-Results headers"""
        has_dkim_sig = bool(headers.get("dkim-signature"))
        auth_results = headers.get("authentication-results", [])

        raw_dkim = None
        status = AuthStatusEnum.NONE
        details = None

        if auth_results:
            for ar in auth_results:
                match = re.search(r'dkim=(\w+)(?:\s+\(([^)]+)\))?', ar, re.IGNORECASE)
                if match:
                    raw_dkim = match.group(0)
                    val = match.group(1).lower()
                    if val == "pass":
                        status = AuthStatusEnum.PASS
                        details = "Cryptographic signature verified against the sender domain's public key."
                    elif val in ["fail", "badsignature", "perm_error"]:
                        status = AuthStatusEnum.FAIL
                        details = f"DKIM verification failed ({val}). The email body or critical headers may have been modified in transit or signed with invalid keys."
                    elif val == "none":
                        status = AuthStatusEnum.NONE
                        details = "No DKIM signature found for evaluation."
                    break

        if status == AuthStatusEnum.NONE and has_dkim_sig:
            status = AuthStatusEnum.UNKNOWN
            details = "DKIM-Signature header present, but verification result was not recorded in receiver headers."

        if status == AuthStatusEnum.PASS:
            explanation = "DKIM signature is valid. Guarantees message integrity and confirms it was signed by an authorized key from the signing domain."
        elif status == AuthStatusEnum.FAIL:
            explanation = "DKIM signature is invalid. This indicates the message was either tampered with after signing, or sent with a forged/corrupted signature."
        elif status == AuthStatusEnum.NONE:
            explanation = "No DKIM signature present on the email. The message has no cryptographic proof of origin or content integrity."
        else:
            explanation = "DKIM signature exists but could not be verified locally without external DNS lookup."

        return AuthResult(
            status=status,
            details=details,
            raw_header=raw_dkim or (headers.get("dkim-signature", [""])[0] if has_dkim_sig else None),
            explanation=explanation
        )

    @classmethod
    def _analyze_dmarc(
        cls,
        headers: Dict[str, List[str]],
        from_addr: str,
        spf_status: AuthStatusEnum,
        dkim_status: AuthStatusEnum
    ) -> AuthResult:
        """Extract and interpret DMARC policy compliance"""
        auth_results = headers.get("authentication-results", [])
        raw_dmarc = None
        status = AuthStatusEnum.NONE
        details = None

        if auth_results:
            for ar in auth_results:
                match = re.search(r'dmarc=(\w+)(?:\s+\(([^)]+)\))?', ar, re.IGNORECASE)
                if match:
                    raw_dmarc = match.group(0)
                    val = match.group(1).lower()
                    if val == "pass":
                        status = AuthStatusEnum.PASS
                        details = "DMARC alignment verified (either SPF alignment or DKIM alignment succeeded)."
                    elif val in ["fail", "reject", "quarantine"]:
                        status = AuthStatusEnum.FAIL
                        details = f"DMARC check failed ({val}). Neither SPF nor DKIM aligned with the visible From domain."
                    elif val == "none":
                        status = AuthStatusEnum.NONE
                        details = "Domain has no DMARC policy published."
                    break

        # If DMARC header not explicitly listed, deduce from SPF + DKIM failure
        if status == AuthStatusEnum.NONE:
            if spf_status == AuthStatusEnum.FAIL and dkim_status in [AuthStatusEnum.FAIL, AuthStatusEnum.NONE]:
                status = AuthStatusEnum.FAIL
                details = "Inferred DMARC failure: Both SPF and DKIM failed or are absent."

        if status == AuthStatusEnum.PASS:
            explanation = "DMARC passed. The sender domain policy matches authenticated identifiers, preventing domain impersonation."
        elif status == AuthStatusEnum.FAIL:
            explanation = "DMARC failed. The email fails both SPF and DKIM domain alignment, indicating high likelihood of email spoofing."
        elif status == AuthStatusEnum.NONE:
            explanation = "No DMARC policy reported. Receivers cannot enforce strict domain anti-spoofing policies for this sender."
        else:
            explanation = "DMARC status could not be verified from available headers."

        return AuthResult(
            status=status,
            details=details,
            raw_header=raw_dmarc,
            explanation=explanation
        )

    @classmethod
    def _analyze_arc(cls, headers: Dict[str, List[str]]) -> Optional[AuthResult]:
        """Extract ARC (Authenticated Received Chain) if present for forwarded emails"""
        arc_results = headers.get("arc-authentication-results", [])
        if not arc_results:
            return None

        raw_arc = arc_results[0]
        status = AuthStatusEnum.UNKNOWN
        if "arc=pass" in raw_arc.lower() or "arc-seal=pass" in raw_arc.lower():
            status = AuthStatusEnum.PASS
            details = "ARC chain valid: Intermediate forwarding intermediaries preserved authentication."
        elif "arc=fail" in raw_arc.lower():
            status = AuthStatusEnum.FAIL
            details = "ARC chain invalid or broken during intermediate relay."
        else:
            details = "ARC headers present but status is indeterminate."

        return AuthResult(
            status=status,
            details=details,
            raw_header=raw_arc,
            explanation="ARC preserves original authentication results across email forwarding services."
        )
