"""
RFC 822 and MIME email parsing engine
Safely parses raw email content, extracts headers, body parts, URLs, and attachments.
"""
import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, parsedate_to_datetime
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import chardet


class ParsedEmailData:
    """Structured container for parsed email components"""
    def __init__(self):
        self.message_id: Optional[str] = None
        self.subject: str = ""
        self.from_address: str = ""
        self.from_name: str = ""
        self.to_addresses: List[str] = []
        self.cc_addresses: List[str] = []
        self.reply_to: Optional[str] = None
        self.return_path: Optional[str] = None
        self.date_sent: Optional[datetime] = None
        self.date_received: Optional[datetime] = None

        self.body_plain: str = ""
        self.body_html: str = ""

        self.raw_headers: List[Tuple[str, str]] = []
        self.headers_dict: Dict[str, List[str]] = {}

        self.urls: List[str] = []
        self.attachments: List[Dict[str, Any]] = []
        self.raw_content: str = ""


class EmailParserService:
    """Service for parsing raw email files or strings into structured forensic data"""

    @classmethod
    def parse_raw_email(cls, raw_content: str | bytes) -> ParsedEmailData:
        """
        Parse raw RFC 822 email string or bytes.
        Handles various encodings and malformed MIME gracefully.
        """
        result = ParsedEmailData()

        if isinstance(raw_content, str):
            result.raw_content = raw_content
            # Parse string
            msg = Parser(policy=policy.default).parsestr(raw_content)
        else:
            # Detect encoding if bytes
            try:
                result.raw_content = raw_content.decode('utf-8')
            except UnicodeDecodeError:
                detected = chardet.detect(raw_content)
                enc = detected.get('encoding') or 'latin-1'
                result.raw_content = raw_content.decode(enc, errors='replace')
            msg = BytesParser(policy=policy.default).parsebytes(raw_content)

        # Extract headers
        cls._extract_headers(msg, result)

        # Extract metadata
        cls._extract_metadata(msg, result)

        # Extract bodies & attachments
        cls._extract_body_and_attachments(msg, result)

        # Extract URLs from plain text and HTML bodies
        cls._extract_urls(result)

        return result

    @classmethod
    def _extract_headers(cls, msg: email.message.EmailMessage, result: ParsedEmailData) -> None:
        """Extract all header pairs and build header mapping"""
        for header_name, header_val in msg.items():
            str_val = str(header_val)
            result.raw_headers.append((header_name, str_val))

            norm_name = header_name.lower()
            if norm_name not in result.headers_dict:
                result.headers_dict[norm_name] = []
            result.headers_dict[norm_name].append(str_val)

    @classmethod
    def _extract_metadata(cls, msg: email.message.EmailMessage, result: ParsedEmailData) -> None:
        """Extract sender, recipients, dates, and identification headers"""
        result.message_id = msg.get("Message-ID", "").strip("<> \r\n\t") or None
        result.subject = msg.get("Subject", "(No Subject)")

        # From header
        from_hdr = msg.get("From", "")
        from_name, from_email = parseaddr(from_hdr)
        result.from_name = from_name
        result.from_address = from_email or from_hdr

        # To headers
        to_hdr = msg.get_all("To", [])
        for to_val in to_hdr:
            for addr in to_val.split(","):
                _, clean_addr = parseaddr(addr.strip())
                if clean_addr:
                    result.to_addresses.append(clean_addr)

        # CC headers
        cc_hdr = msg.get_all("Cc", [])
        for cc_val in cc_hdr:
            for addr in cc_val.split(","):
                _, clean_addr = parseaddr(addr.strip())
                if clean_addr:
                    result.cc_addresses.append(clean_addr)

        # Reply-To & Return-Path
        reply_to_hdr = msg.get("Reply-To")
        if reply_to_hdr:
            _, clean_reply_to = parseaddr(reply_to_hdr)
            result.reply_to = clean_reply_to or reply_to_hdr

        return_path_hdr = msg.get("Return-Path")
        if return_path_hdr:
            _, clean_ret_path = parseaddr(return_path_hdr)
            result.return_path = clean_ret_path or return_path_hdr

        # Dates
        date_hdr = msg.get("Date")
        if date_hdr:
            try:
                result.date_sent = parsedate_to_datetime(date_hdr)
            except Exception:
                result.date_sent = None

        # Received date from outermost received header if present
        received_hdrs = msg.get_all("Received", [])
        if received_hdrs:
            try:
                # The first Received header is usually the newest
                date_part = received_hdrs[0].split(";")[-1].strip()
                result.date_received = parsedate_to_datetime(date_part)
            except Exception:
                result.date_received = datetime.now(timezone.utc)
        else:
            result.date_received = datetime.now(timezone.utc)

    @classmethod
    def _extract_body_and_attachments(cls, msg: email.message.EmailMessage, result: ParsedEmailData) -> None:
        """Walk MIME structure to separate text/plain, text/html, and file attachments"""
        if not msg.is_multipart():
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if content_type == "text/html":
                        result.body_html = content
                    else:
                        result.body_plain = content
                elif isinstance(content, bytes):
                    # Single-part binary payload
                    cls._process_attachment_part(msg, content, result)
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    try:
                        decoded = payload.decode('utf-8', errors='replace')
                        if content_type == "text/html":
                            result.body_html = decoded
                        else:
                            result.body_plain = decoded
                    except Exception:
                        pass
            return

        # Multipart traversal
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            content_type = part.get_content_type()
            filename = part.get_filename()

            # If it has a filename or disposition is attachment, treat as attachment
            is_attachment = bool(filename) or "attachment" in content_disposition.lower()

            if is_attachment:
                try:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        cls._process_attachment_part(part, payload, result)
                except Exception:
                    pass
            elif content_type == "text/plain" and not result.body_plain:
                try:
                    text_content = part.get_content()
                    if isinstance(text_content, str):
                        result.body_plain = text_content
                    else:
                        payload = part.get_payload(decode=True)
                        if payload:
                            result.body_plain = payload.decode('utf-8', errors='replace')
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_plain = payload.decode('utf-8', errors='replace')
            elif content_type == "text/html" and not result.body_html:
                try:
                    html_content = part.get_content()
                    if isinstance(html_content, str):
                        result.body_html = html_content
                    else:
                        payload = part.get_payload(decode=True)
                        if payload:
                            result.body_html = payload.decode('utf-8', errors='replace')
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_html = payload.decode('utf-8', errors='replace')

    @classmethod
    def _process_attachment_part(cls, part: email.message.EmailMessage, payload: bytes, result: ParsedEmailData) -> None:
        """Extract metadata, calculate SHA-256 and MD5 hashes safely without writing file to disk"""
        filename = part.get_filename() or "unnamed_attachment"
        # Sanitize filename (strip directory traversal characters)
        clean_filename = filename.replace("\\", "/").split("/")[-1].strip() or "attachment"

        sha256 = hashlib.sha256(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        file_size = len(payload)
        mime_type = part.get_content_type() or "application/octet-stream"

        # Determine file extension
        ext = ""
        if "." in clean_filename:
            ext = "." + clean_filename.rsplit(".", 1)[-1].lower()

        result.attachments.append({
            "filename": clean_filename,
            "file_extension": ext,
            "mime_type": mime_type,
            "file_size": file_size,
            "sha256_hash": sha256,
            "md5_hash": md5,
            # Payload is held strictly in memory for analysis; never executed
        })

    @classmethod
    def _extract_urls(cls, result: ParsedEmailData) -> None:
        """Extract all unique URLs from plain text and HTML bodies"""
        found_urls = set()

        url_regex = re.compile(
            r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            re.IGNORECASE
        )

        # 1. Plain text extraction
        if result.body_plain:
            for match in url_regex.finditer(result.body_plain):
                found_urls.add(match.group(0))

        # 2. HTML body extraction (both text and href/src attributes)
        if result.body_html:
            try:
                soup = BeautifulSoup(result.body_html, 'html.parser')
                for tag in soup.find_all(['a', 'link', 'form', 'img', 'iframe']):
                    for attr in ['href', 'src', 'action']:
                        val = tag.get(attr)
                        if val and isinstance(val, str) and (val.startswith('http://') or val.startswith('https://')):
                            found_urls.add(val.strip())

                # Also regex over full HTML for non-tagged links
                for match in url_regex.finditer(result.body_html):
                    found_urls.add(match.group(0))
            except Exception:
                for match in url_regex.finditer(result.body_html):
                    found_urls.add(match.group(0))

        result.urls = list(found_urls)
