"""
Email Header Forensics - Parse and analyze email routing chain
Extracts Received headers, IP addresses, hostnames, routing anomalies, and mail path
"""
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional
from app.schemas import HeaderAnalysisResult, EmailHop


class HeaderAnalyzer:
    """Service for analyzing email headers and routing path"""

    @classmethod
    def analyze_headers(cls, headers_dict: Dict[str, List[str]], from_address: str, reply_to: Optional[str]) -> HeaderAnalysisResult:
        """
        Perform forensic analysis on email headers:
        - Parse Received chain
        - Extract originating IP
        - Detect routing anomalies
        - Compare sender domains
        """
        received_headers = headers_dict.get("received", [])
        hops = cls._parse_received_chain(received_headers)

        originating_ip = hops[-1].from_ip if hops else None

        # Extract domains
        sender_domain = cls._extract_domain(from_address)
        reply_to_domain = cls._extract_domain(reply_to) if reply_to else None

        # Detect anomalies
        anomalies = cls._detect_anomalies(headers_dict, from_address, reply_to, hops)

        # Check for timezone inconsistencies
        tz_issues = cls._check_timezone_consistency(hops, headers_dict)

        # Validate Message-ID
        message_id = headers_dict.get("message-id", [""])[0]
        message_id_valid = cls._validate_message_id(message_id, sender_domain)

        return HeaderAnalysisResult(
            originating_ip=originating_ip,
            received_chain=hops,
            sender_domain=sender_domain,
            reply_to_domain=reply_to_domain,
            message_id_valid=message_id_valid,
            anomalies=anomalies,
            timezone_inconsistencies=tz_issues
        )

    @classmethod
    def _parse_received_chain(cls, received_headers: List[str]) -> List[EmailHop]:
        """
        Parse Received headers to construct email routing path.
        Received headers are in reverse chronological order (newest first).
        """
        hops = []

        for idx, header in enumerate(reversed(received_headers)):
            hop = EmailHop(hop_number=idx + 1)

            # Extract "from" hostname/IP
            from_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
            if from_match:
                hop.from_hostname = from_match.group(1).strip("[]")

            # Extract IP address in brackets or parentheses
            ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', header)
            if ip_match:
                hop.from_ip = ip_match.group(1)

            # Extract "by" hostname
            by_match = re.search(r'by\s+([^\s]+)', header, re.IGNORECASE)
            if by_match:
                hop.by_hostname = by_match.group(1).strip()

            # Extract timestamp
            semicolon_parts = header.split(";")
            if len(semicolon_parts) > 1:
                date_str = semicolon_parts[-1].strip()
                try:
                    hop.timestamp = parsedate_to_datetime(date_str)
                except Exception:
                    pass

            # Calculate delay from previous hop
            if idx > 0 and hop.timestamp and hops[-1].timestamp:
                try:
                    delay = (hop.timestamp - hops[-1].timestamp).total_seconds()
                    hop.delay_seconds = int(delay)

                    # Flag unusual delays
                    if delay > 3600:  # More than 1 hour
                        hop.anomalies.append(f"Unusual delay: {int(delay/60)} minutes from previous hop")
                    elif delay < 0:
                        hop.anomalies.append("Timestamp earlier than previous hop (clock skew)")
                except Exception:
                    pass

            hops.append(hop)

        return hops

    @classmethod
    def _detect_anomalies(
        cls,
        headers: Dict[str, List[str]],
        from_address: str,
        reply_to: Optional[str],
        hops: List[EmailHop]
    ) -> List[str]:
        """Detect header-level anomalies and suspicious patterns"""
        anomalies = []

        # 1. From vs Reply-To domain mismatch
        if reply_to and reply_to.lower() != from_address.lower():
            from_domain = cls._extract_domain(from_address)
            reply_domain = cls._extract_domain(reply_to)
            if from_domain != reply_domain:
                anomalies.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")

        # 2. Return-Path mismatch
        return_path = headers.get("return-path", [""])[0].strip("<>")
        if return_path:
            return_domain = cls._extract_domain(return_path)
            from_domain = cls._extract_domain(from_address)
            if return_domain and from_domain and return_domain != from_domain:
                anomalies.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})")

        # 3. Check for missing or minimal Received chain
        if len(hops) == 0:
            anomalies.append("No Received headers found - possible direct submission or header stripping")
        elif len(hops) == 1:
            anomalies.append("Only one Received header - unusually short routing path")

        # 4. Suspicious received chain hostnames
        for hop in hops:
            if hop.from_hostname:
                hostname_lower = hop.from_hostname.lower()
                if any(susp in hostname_lower for susp in ["unknown", "localhost", "dynamic", "dhcp"]):
                    anomalies.append(f"Suspicious hostname in mail path: {hop.from_hostname}")

        # 5. Check for X-Mailer inconsistencies
        x_mailer = headers.get("x-mailer", [""])[0]
        if x_mailer:
            # Just log it - could compare against known patterns
            pass

        # 6. Duplicate Message-ID (not detectable from single email but flag if malformed)
        message_id = headers.get("message-id", [""])[0]
        if message_id and not re.match(r'^<[^@]+@[^@>]+>$', message_id):
            anomalies.append(f"Malformed Message-ID: {message_id}")

        return anomalies

    @classmethod
    def _check_timezone_consistency(cls, hops: List[EmailHop], headers: Dict[str, List[str]]) -> List[str]:
        """Check for timezone inconsistencies between Date header and Received timestamps"""
        issues = []

        date_header = headers.get("date", [""])[0]
        if not date_header:
            return issues

        try:
            claimed_date = parsedate_to_datetime(date_header)

            # Compare with first received timestamp (oldest)
            if hops and hops[0].timestamp:
                delta = abs((claimed_date - hops[0].timestamp).total_seconds())
                if delta > 7200:  # More than 2 hours difference
                    issues.append(f"Date header differs from oldest Received timestamp by {int(delta/60)} minutes")
        except Exception:
            pass

        return issues

    @classmethod
    def _validate_message_id(cls, message_id: str, sender_domain: Optional[str]) -> bool:
        """
        Validate Message-ID format and domain alignment.
        Valid format: <unique-string@domain.com>
        """
        if not message_id:
            return False

        # Check basic structure
        match = re.match(r'^<([^@]+)@([^@>]+)>$', message_id)
        if not match:
            return False

        # If we have sender domain, check if Message-ID domain is related
        if sender_domain:
            msg_id_domain = match.group(2).lower()
            # Allow if domains match or Message-ID is from mail provider subdomain
            if msg_id_domain != sender_domain.lower() and not msg_id_domain.endswith(f".{sender_domain.lower()}"):
                # This is actually common with mail providers, so don't fail, just note
                return True

        return True

    @staticmethod
    def _extract_domain(email_address: str) -> Optional[str]:
        """Extract domain from email address"""
        if not email_address or "@" not in email_address:
            return None
        return email_address.split("@")[-1].lower().strip()
