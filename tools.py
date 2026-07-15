from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlparse

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

import re
from urllib.parse import urlparse
from email.utils import parseaddr


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

    urls = re.findall(r"https?://[^\s\"'<>]+", email_text)

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

    score = 0
    score += len(suspicious_phrases) * 10
    score += len(suspicious_urls) * 25
    score += len(header_issues) * 20
    score += len(authentication_issues) * 25
    score += len(urls) * 3

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
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
    }



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