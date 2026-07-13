import re
from urllib.parse import urlparse


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