from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

import re
from urllib.parse import urlparse
from email.utils import parseaddr





def is_public_host(hostname: str) -> bool:
    """
    Prevent requests to localhost, private networks, link-local addresses,
    and other non-public IP ranges.
    """

    if not hostname:
        return False

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False

    for address in addresses:
        ip_text = address[4][0]
        ip = ipaddress.ip_address(ip_text)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True

def analyze_webpage_html(html: str) -> dict:
    if not html:
        return {
            "title": "",
            "forms": 0,
            "password_fields": 0,
            "suspicious_page_indicators": [],
        }

    soup = BeautifulSoup(html, "html.parser")

    title = ""

    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    forms = soup.find_all("form")

    password_fields = soup.find_all(
        "input",
        {"type": "password"},
    )

    text = soup.get_text(" ", strip=True).lower()

    indicators = []

    suspicious_terms = [
        "verify your account",
        "confirm your identity",
        "account suspended",
        "session expired",
        "sign in to continue",
        "update payment",
        "enter your password",
        "security verification",
    ]

    for term in suspicious_terms:
        if term in text:
            indicators.append(
                f"Page contains suspicious phrase: {term}"
            )

    if password_fields:
        indicators.append(
            f"Page contains {len(password_fields)} password field(s)."
        )

    if forms and password_fields:
        indicators.append(
            "Page contains a form requesting authentication details."
        )

    return {
        "title": title,
        "forms": len(forms),
        "password_fields": len(password_fields),
        "suspicious_page_indicators": indicators,
    }
def inspect_url(url: str, max_redirects: int = 5) -> dict:
    """
    Inspect a URL without executing JavaScript.

    Returns:
    - redirect chain
    - final URL
    - HTTP status
    - page title
    - phishing-related page indicators
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return {
            "error": "Only HTTP and HTTPS URLs are supported."
        }

    if not is_public_host(parsed.hostname or ""):
        return {
            "error": "URL points to a blocked or non-public address."
        }

    redirect_chain = []
    current_url = url

    headers = {
        "User-Agent": (
            "Mozilla/5.0 PhishingAnalyzer/1.0"
        )
    }

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=False,
            headers=headers,
        ) as client:

            for _ in range(max_redirects + 1):
                current_parsed = urlparse(current_url)

                if not is_public_host(current_parsed.hostname or ""):
                    return {
                        "error": (
                            "Redirect attempted to reach a blocked "
                            "or non-public address."
                        ),
                        "redirect_chain": redirect_chain,
                    }

                response = client.get(current_url)

                redirect_chain.append(
                    {
                        "url": current_url,
                        "status_code": response.status_code,
                    }
                )

                if response.status_code in {
                    301,
                    302,
                    303,
                    307,
                    308,
                }:
                    location = response.headers.get("location")

                    if not location:
                        break

                    current_url = urljoin(current_url, location)
                    continue

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                html = ""

                if "text/html" in content_type:
                    html = response.text[:500_000]

                page_analysis = analyze_webpage_html(html)

                return {
                    "original_url": url,
                    "final_url": str(response.url),
                    "status_code": response.status_code,
                    "redirect_chain": redirect_chain,
                    "content_type": content_type,
                    "page_analysis": page_analysis,
                }

        return {
            "original_url": url,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "error": "Maximum redirect limit reached.",
        }

    except httpx.TimeoutException:
        return {
            "original_url": url,
            "redirect_chain": redirect_chain,
            "error": "Request timed out.",
        }

    except httpx.HTTPError as error:
        return {
            "original_url": url,
            "redirect_chain": redirect_chain,
            "error": str(error),
        }  

def analyze_html_links(html_body: str) -> dict:
    links = []
    misleading_links = []

    if not html_body:
        return {
            "html_links": links,
            "misleading_links": misleading_links,
        }

    soup = BeautifulSoup(html_body, "html.parser")

    for anchor in soup.find_all("a", href=True):
        actual_url = anchor.get("href", "").strip()
        visible_text = anchor.get_text(" ", strip=True)

        link_data = {
            "visible_text": visible_text,
            "actual_url": actual_url,
        }

        links.append(link_data)

        # Only compare when visible text itself looks like a URL
        if visible_text.startswith(("http://", "https://")):
            visible_domain = urlparse(visible_text).netloc.lower()
            actual_domain = urlparse(actual_url).netloc.lower()

            if (
                visible_domain
                and actual_domain
                and visible_domain != actual_domain
            ):
                misleading_links.append(
                    {
                        "visible_text": visible_text,
                        "actual_url": actual_url,
                        "reason": (
                            f"Displayed domain '{visible_domain}' "
                            f"does not match destination domain "
                            f"'{actual_domain}'."
                        ),
                    }
                )

    return {
        "html_links": links,
        "misleading_links": misleading_links,
    }


def extract_domain(email_address: str) -> str:
    """Extract domain from an email address."""

    _, address = parseaddr(email_address or "")

    if "@" not in address:
        return ""

    return address.split("@", 1)[1].lower()


def analyze_email(email_data: dict, email_text: str) -> dict:
    suspicious_words = [
        "urgent",
        "verify your account",
        "click immediately",
        "password expired",
        "account suspended",
        "limited time",
        "confirm your identity",
        "bank details",
        "login now",
        "you have won",
    ]

    email_lower = email_text.lower()

    urls = re.findall(r'https?://[^\s"\'<>]+', email_text)
    url_inspection_results = []

    for url in urls[:3]:
        result = inspect_url(url)
    url_inspection_results.append(result)
    suspicious_phrases = [
        phrase
        for phrase in suspicious_words
        if phrase in email_lower
    ]

    suspicious_urls = []

    for url in urls:
        domain = urlparse(url).netloc.lower()

        if (
            domain.count("-") >= 2
            or domain.replace(".", "").isdigit()
            or "login" in domain
            or "verify" in domain
        ):
            suspicious_urls.append(url)

    from_domain = extract_domain(email_data.get("from", ""))
    reply_to_domain = extract_domain(email_data.get("reply_to", ""))
    return_path_domain = extract_domain(
        email_data.get("return_path", "")
    )

    header_issues = []

    if (
        reply_to_domain
        and from_domain
        and reply_to_domain != from_domain
    ):
        header_issues.append(
            f"From domain '{from_domain}' does not match "
            f"Reply-To domain '{reply_to_domain}'."
        )

    if (
        return_path_domain
        and from_domain
        and return_path_domain != from_domain
    ):
        header_issues.append(
            f"From domain '{from_domain}' does not match "
            f"Return-Path domain '{return_path_domain}'."
        )

    authentication_results = (
        email_data.get("authentication_results") or ""
    ).lower()

    received_spf = (
        email_data.get("received_spf") or ""
    ).lower()

    authentication_issues = []

    if "spf=fail" in authentication_results or "fail" in received_spf:
        authentication_issues.append("SPF authentication failed.")

    if "dkim=fail" in authentication_results:
        authentication_issues.append("DKIM authentication failed.")

    if "dmarc=fail" in authentication_results:
        authentication_issues.append("DMARC authentication failed.")

    attachment_issues = analyze_attachments(email_data)
    html_link_result = analyze_html_links(
    email_data.get("html_body", "")
)

    html_links = html_link_result["html_links"]
    misleading_links = html_link_result["misleading_links"]

    score = 0
    score += len(suspicious_phrases) * 10
    score += len(suspicious_urls) * 25
    score += len(header_issues) * 20
    score += len(authentication_issues) * 25
    score += len(attachment_issues) * 30
    score += len(urls) * 3
    score += len(misleading_links) * 35
    for result in url_inspection_results:
        page_analysis = result.get("page_analysis", {})

        indicators = page_analysis.get(
            "suspicious_page_indicators",
            [],
        )

        score += len(indicators) * 15

        if len(result.get("redirect_chain", [])) > 2:
            score += 10

    score = min(score, 100)

    if score >= 70:
        risk_level = "High"
    elif score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "urls_found": urls,
        "suspicious_urls": suspicious_urls,
        "suspicious_phrases": suspicious_phrases,
        "header_issues": header_issues,
        "authentication_issues": authentication_issues,
        "attachment_issues": attachment_issues,
        "attachments": email_data.get("attachments", []),
        "html_links": html_links,
        "misleading_links": misleading_links,
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
        "url_inspection_results": url_inspection_results,
    }

def analyze_attachments(email_data: dict) -> list[str]:
    risky_extensions = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".ps1",
        ".msi",
        ".jar",
        ".iso",
        ".img",
        ".lnk",
        ".zip",
        ".rar",
        ".7z",
    }

    issues = []

    for attachment in email_data.get("attachments", []):
        filename = attachment.get("filename", "").lower()

        for extension in risky_extensions:
            if filename.endswith(extension):
                issues.append(
                    f"Potentially risky attachment: {filename}"
                )
                break

    return issues

if __name__ == "__main__":
    sample_email = """
    URGENT: Your account has been suspended.

    Verify your account immediately:
    https://login-verify-bank-security.com
    """

    result = analyze_email(sample_email)
    print(result)


def save_phishing_report(email_text: str, analysis: str) -> str:
    """Save the phishing analysis as a PDF report."""

    reports_folder = Path("phishing_reports")
    reports_folder.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = reports_folder / f"phishing_report_{timestamp}.pdf"

    document = SimpleDocTemplate(
        str(file_path),
        pagesize=A4,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )

    styles = getSampleStyleSheet()
    content = []

    content.append(
        Paragraph("Phishing Email Analysis Report", styles["Title"])
    )
    content.append(Spacer(1, 20))

    content.append(
        Paragraph(f"<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M:%S}",
                  styles["BodyText"])
    )
    content.append(Spacer(1, 20))

    content.append(Paragraph("Original Email", styles["Heading2"]))
    content.append(Spacer(1, 8))

    # Convert line breaks so they display correctly in the PDF
    safe_email = email_text.replace("&", "&amp;")
    safe_email = safe_email.replace("<", "&lt;").replace(">", "&gt;")
    safe_email = safe_email.replace("\n", "<br/>")

    content.append(Paragraph(safe_email, styles["BodyText"]))

    content.append(PageBreak())

    content.append(Paragraph("Analysis", styles["Heading2"]))
    content.append(Spacer(1, 8))

    safe_analysis = analysis.replace("&", "&amp;")
    safe_analysis = safe_analysis.replace("<", "&lt;").replace(">", "&gt;")
    safe_analysis = safe_analysis.replace("\n", "<br/>")

    content.append(Paragraph(safe_analysis, styles["BodyText"]))

    document.build(content)

    return str(file_path)