from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)


def analyze_email(email_text: str) -> dict:

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

    # Extract URLs
    urls = re.findall(r"https?://[^\s]+", email_text)

    # Find suspicious phrases
    found_words = [
        word for word in suspicious_words
        if word in email_lower
    ]

    # Check URLs
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

    # Simple risk score
    score = 0
    score += len(found_words) * 10
    score += len(suspicious_urls) * 25
    score += len(urls) * 5

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
        "suspicious_phrases": found_words,
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