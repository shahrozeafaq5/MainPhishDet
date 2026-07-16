from datetime import datetime
from email.utils import parseaddr
from html import escape
from pathlib import Path
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse
from url_reputation import (
    calculate_reputation_score,
    lookup_virustotal_url,
)
import httpx
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


SUSPICIOUS_WORDS = [
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
    "open it quickly",
    "security verification",
    "sign in to continue",
    "update payment",
]

RISKY_ATTACHMENT_EXTENSIONS = {
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
    ".docm",
    ".xlsm",
    ".pptm",
}

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "click",
    "work",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
}


def extract_email_domain(email_address: str) -> str:
    """Extract a lowercase domain from an email header."""

    _, address = parseaddr(email_address or "")

    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[1].lower().strip()


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname for comparisons."""

    return (hostname or "").lower().strip().rstrip(".")


def get_registered_domain_approximation(hostname: str) -> str:

    hostname = normalize_hostname(hostname)
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


def analyze_domain(hostname: str) -> list[str]:

    hostname = normalize_hostname(hostname)
    issues = []

    if not hostname:
        return issues

    try:
        ipaddress.ip_address(hostname)
        issues.append("URL uses a raw IP address instead of a domain name.")
        return issues
    except ValueError:
        pass

    if "xn--" in hostname:
        issues.append(
            "Domain contains Punycode, which may be used for lookalike characters."
        )

    labels = hostname.split(".")

    if len(labels) > 4:
        issues.append("Domain contains an unusually deep subdomain structure.")

    if hostname.count("-") >= 3:
        issues.append("Domain contains several hyphens.")

    if len(hostname) > 60:
        issues.append("Domain name is unusually long.")

    tld = labels[-1] if labels else ""

    if tld in SUSPICIOUS_TLDS:
        issues.append(f"Domain uses a higher-risk TLD: .{tld}")

    suspicious_tokens = {
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "authentication",
        "signin",
        "wallet",
        "payment",
    }

    token_matches = [
        token
        for token in suspicious_tokens
        if token in hostname
    ]

    if len(token_matches) >= 2:
        issues.append(
            "Domain contains multiple security or account-related words: "
            + ", ".join(sorted(token_matches))
        )

    if hostname in URL_SHORTENERS:
        issues.append("URL uses a link-shortening service.")

    return issues


def is_public_host(hostname: str) -> bool:


    hostname = normalize_hostname(hostname)

    if not hostname:
        return False

    if hostname in {"localhost", "localhost.localdomain"}:
        return False

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False

    if not addresses:
        return False

    for address in addresses:
        ip_text = address[4][0]

        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return False

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


def analyze_attachments(email_data: dict) -> list[str]:
    """Inspect attachment names for risky extensions."""

    issues = []

    for attachment in email_data.get("attachments", []):
        filename = (
            attachment.get("filename")
            or "unnamed_attachment"
        ).lower()

        suffixes = Path(filename).suffixes

        if any(
            suffix in RISKY_ATTACHMENT_EXTENSIONS
            for suffix in suffixes
        ):
            issues.append(
                f"Potentially risky attachment type: {filename}"
            )

        if len(suffixes) >= 2:
            final_suffix = suffixes[-1]

            if final_suffix in RISKY_ATTACHMENT_EXTENSIONS:
                issues.append(
                    f"Attachment uses multiple extensions: {filename}"
                )

    return list(dict.fromkeys(issues))


def analyze_html_links(html_body: str) -> dict:
    """Extract links and detect displayed-URL mismatches."""

    html_links = []
    misleading_links = []

    if not html_body:
        return {
            "html_links": html_links,
            "misleading_links": misleading_links,
        }

    soup = BeautifulSoup(html_body, "html.parser")

    for anchor in soup.find_all("a", href=True):
        actual_url = anchor.get("href", "").strip()
        visible_text = anchor.get_text(" ", strip=True)

        html_links.append(
            {
                "visible_text": visible_text,
                "actual_url": actual_url,
            }
        )

        if visible_text.startswith(("http://", "https://")):
            visible_domain = normalize_hostname(
                urlparse(visible_text).hostname or ""
            )
            actual_domain = normalize_hostname(
                urlparse(actual_url).hostname or ""
            )

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
                            f"Displayed domain '{visible_domain}' does not "
                            f"match destination domain '{actual_domain}'."
                        ),
                    }
                )

    return {
        "html_links": html_links,
        "misleading_links": misleading_links,
    }


def analyze_webpage_html(
    html: str,
    page_url: str,
) -> dict:
    """Analyze a downloaded page without running JavaScript."""

    empty_result = {
        "title": "",
        "forms": [],
        "password_fields": 0,
        "sensitive_fields": [],
        "suspicious_page_indicators": [],
    }

    if not html:
        return empty_result

    soup = BeautifulSoup(html, "html.parser")

    title = ""

    if soup.title:
        title = soup.title.get_text(" ", strip=True)

    page_hostname = normalize_hostname(
        urlparse(page_url).hostname or ""
    )
    page_base_domain = get_registered_domain_approximation(
        page_hostname
    )

    forms_analysis = []
    suspicious_indicators = []
    sensitive_fields = []

    page_text = soup.get_text(" ", strip=True).lower()

    for phrase in SUSPICIOUS_WORDS:
        if phrase in page_text:
            suspicious_indicators.append(
                f"Page contains suspicious phrase: {phrase}"
            )

    password_inputs = soup.find_all(
        "input",
        attrs={"type": re.compile("^password$", re.I)},
    )

    if password_inputs:
        sensitive_fields.append("password")

    for field_type in ["email", "tel"]:
        if soup.find("input", attrs={"type": field_type}):
            sensitive_fields.append(field_type)

    sensitive_name_patterns = re.compile(
        r"card|credit|cvv|cvc|otp|pin|ssn|passport|password|passcode",
        re.I,
    )

    for field in soup.find_all(["input", "textarea"]):
        field_name = " ".join(
            [
                field.get("name", ""),
                field.get("id", ""),
                field.get("placeholder", ""),
            ]
        )

        if sensitive_name_patterns.search(field_name):
            sensitive_fields.append(field_name.strip())

    for index, form in enumerate(soup.find_all("form"), start=1):
        method = form.get("method", "get").lower()
        raw_action = form.get("action", "").strip()

        destination = (
            urljoin(page_url, raw_action)
            if raw_action
            else page_url
        )

        destination_hostname = normalize_hostname(
            urlparse(destination).hostname or ""
        )
        destination_base_domain = (
            get_registered_domain_approximation(
                destination_hostname
            )
        )

        form_issues = []

        if (
            destination_hostname
            and page_base_domain
            and destination_base_domain != page_base_domain
        ):
            form_issues.append(
                "Form submits data to a different base domain."
            )

        form_password_fields = form.find_all(
            "input",
            attrs={"type": re.compile("^password$", re.I)},
        )

        if form_password_fields:
            form_issues.append(
                "Form requests a password."
            )

        if (
            form_password_fields
            and destination_base_domain != page_base_domain
        ):
            form_issues.append(
                "Password form submits to an external domain."
            )

        if method == "get" and form_password_fields:
            form_issues.append(
                "Password form uses GET, which can expose values in the URL."
            )

        forms_analysis.append(
            {
                "index": index,
                "method": method,
                "action": raw_action,
                "resolved_destination": destination,
                "destination_domain": destination_hostname,
                "issues": form_issues,
            }
        )

        suspicious_indicators.extend(form_issues)

    if password_inputs:
        suspicious_indicators.append(
            f"Page contains {len(password_inputs)} password field(s)."
        )

    return {
        "title": title,
        "forms": forms_analysis,
        "password_fields": len(password_inputs),
        "sensitive_fields": list(dict.fromkeys(sensitive_fields)),
        "suspicious_page_indicators": list(
            dict.fromkeys(suspicious_indicators)
        ),
    }


def inspect_url(
    url: str,
    max_redirects: int = 5,
) -> dict:


    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return {
            "original_url": url,
            "error": "Only HTTP and HTTPS URLs are supported.",
        }

    hostname = normalize_hostname(parsed.hostname or "")

    if not is_public_host(hostname):
        return {
            "original_url": url,
            "error": "URL points to a blocked or non-public address.",
        }

    redirect_chain = []
    redirect_issues = []
    current_url = url

    original_hostname = hostname
    original_base_domain = get_registered_domain_approximation(
        original_hostname
    )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(compatible; PhishingAnalyzer/1.0; SecurityResearch)"
        )
    }

    try:
        with httpx.Client(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            headers=headers,
            verify=True,
            trust_env=False,
        ) as client:
            for _ in range(max_redirects + 1):
                current_parsed = urlparse(current_url)
                current_hostname = normalize_hostname(
                    current_parsed.hostname or ""
                )

                if not is_public_host(current_hostname):
                    return {
                        "original_url": url,
                        "redirect_chain": redirect_chain,
                        "redirect_issues": redirect_issues,
                        "error": (
                            "A redirect attempted to reach a blocked "
                            "or non-public address."
                        ),
                    }

                response = client.get(current_url)

                redirect_chain.append(
                    {
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "domain": current_hostname,
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

                    next_url = urljoin(current_url, location)

                    next_hostname = normalize_hostname(
                        urlparse(next_url).hostname or ""
                    )
                    next_base_domain = (
                        get_registered_domain_approximation(
                            next_hostname
                        )
                    )

                    if (
                        original_base_domain
                        and next_base_domain
                        and next_base_domain != original_base_domain
                    ):
                        redirect_issues.append(
                            "Redirect leaves the original base domain: "
                            f"{original_hostname} -> {next_hostname}"
                        )

                    current_url = next_url
                    continue

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                html = ""

                if "text/html" in content_type:
                    html = response.text[:500_000]

                final_url = str(response.url)
                final_hostname = normalize_hostname(
                    response.url.host or ""
                )

                return {
                    "original_url": url,
                    "final_url": final_url,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "redirect_chain": redirect_chain,
                    "redirect_issues": list(
                        dict.fromkeys(redirect_issues)
                    ),
                    "original_domain_issues": analyze_domain(
                        original_hostname
                    ),
                    "final_domain_issues": analyze_domain(
                        final_hostname
                    ),
                    "page_analysis": analyze_webpage_html(
                        html=html,
                        page_url=final_url,
                    ),
                }

        return {
            "original_url": url,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "redirect_issues": redirect_issues,
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


def analyze_email(
    email_data: dict,
    email_text: str,
) -> dict:
    """Run deterministic phishing checks."""

    email_lower = email_text.lower()

    text_urls = re.findall(
        r'https?://[^\s"\'<>]+',
        email_text,
    )

    html_link_result = analyze_html_links(
        email_data.get("html_body", "")
    )

    html_urls = [
        item["actual_url"]
        for item in html_link_result["html_links"]
        if item["actual_url"].startswith(("http://", "https://"))
    ]

    urls = list(dict.fromkeys(text_urls + html_urls))

    suspicious_phrases = [
        phrase
        for phrase in SUSPICIOUS_WORDS
        if phrase in email_lower
    ]

    suspicious_urls = []
    url_domain_issues = {}

    for url in urls:
        hostname = normalize_hostname(
            urlparse(url).hostname or ""
        )

        issues = analyze_domain(hostname)

        if issues:
            suspicious_urls.append(url)
            url_domain_issues[url] = issues

    from_domain = extract_email_domain(
        email_data.get("from", "")
    )
    reply_to_domain = extract_email_domain(
        email_data.get("reply_to", "")
    )
    return_path_domain = extract_email_domain(
        email_data.get("return_path", "")
    )

    header_issues = []

    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    ):
        header_issues.append(
            f"From domain '{from_domain}' does not match "
            f"Reply-To domain '{reply_to_domain}'."
        )

    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
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

    if (
        "spf=fail" in authentication_results
        or re.search(r"\bfail\b", received_spf)
    ):
        authentication_issues.append(
            "SPF authentication failed."
        )

    if "dkim=fail" in authentication_results:
        authentication_issues.append(
            "DKIM authentication failed."
        )

    if "dmarc=fail" in authentication_results:
        authentication_issues.append(
            "DMARC authentication failed."
        )

    attachment_issues = analyze_attachments(email_data)


url_reputation_results = []

# Limit remote checks to prevent excessive requests
for url in urls[:3]:
    inspection_result = inspect_url(url)
    reputation_result = lookup_virustotal_url(url)

    url_inspection_results.append(
        inspection_result
    )

    url_reputation_results.append(
        reputation_result
    )

    redirect_issue_count = 0
    page_indicator_count = 0
    external_password_form_count = 0

    for result in url_inspection_results:
        redirect_issue_count += len(
            result.get("redirect_issues", [])
        )

        page_analysis = result.get(
            "page_analysis",
            {},
        )

        page_indicator_count += len(
            page_analysis.get(
                "suspicious_page_indicators",
                [],
            )
        )

        for form in page_analysis.get("forms", []):
            if (
                "Password form submits to an external domain."
                in form.get("issues", [])
            ):
                external_password_form_count += 1
    reputation_score = 0
reputation_issues = []

for result in url_reputation_results:
    result_score = calculate_reputation_score(result)
    reputation_score += result_score

    if result.get("found"):
        malicious_count = result.get(
            "malicious",
            0,
        )

        suspicious_count = result.get(
            "suspicious",
            0,
        )

        if malicious_count > 0:
            reputation_issues.append(
                (
                    f"VirusTotal reports "
                    f"{malicious_count} malicious detection(s) "
                    f"for {result.get('url')}."
                )
            )

        if suspicious_count > 0:
            reputation_issues.append(
                (
                    f"VirusTotal reports "
                    f"{suspicious_count} suspicious detection(s) "
                    f"for {result.get('url')}."
                )
            )
    score = 0
    score += len(suspicious_phrases) * 8
    score += len(suspicious_urls) * 15
    score += len(header_issues) * 20
    score += len(authentication_issues) * 25
    score += len(attachment_issues) * 25
    score += len(
        html_link_result["misleading_links"]
    ) * 35
    score += redirect_issue_count * 15
    score += page_indicator_count * 8
    score += external_password_form_count * 30
    score += min(reputation_score, 50)
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
    "url_domain_issues": url_domain_issues,
    "suspicious_phrases": suspicious_phrases,
    "header_issues": header_issues,
    "authentication_issues": authentication_issues,
    "attachment_issues": attachment_issues,
    "attachments": email_data.get(
        "attachments",
        [],
    ),
    "html_links": html_link_result[
        "html_links"
    ],
    "misleading_links": html_link_result[
        "misleading_links"
    ],
    "url_inspection_results": (
        url_inspection_results
    ),
    "url_reputation_results": (
        url_reputation_results
    ),
    "reputation_issues": reputation_issues,
    "domains": {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": (
            return_path_domain
        ),
    },
}


def save_phishing_report(
    email_text: str,
    analysis: str,
) -> str:
    """Save the email and analysis in a PDF report."""

    reports_folder = Path("phishing_reports")
    reports_folder.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    file_path = (
        reports_folder
        / f"phishing_report_{timestamp}.pdf"
    )

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
        Paragraph(
            "Phishing Email Analysis Report",
            styles["Title"],
        )
    )
    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            (
                "<b>Generated:</b> "
                f"{datetime.now():%Y-%m-%d %H:%M:%S}"
            ),
            styles["BodyText"],
        )
    )
    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Original Email",
            styles["Heading2"],
        )
    )
    content.append(Spacer(1, 8))

    safe_email = escape(email_text).replace(
        "\n",
        "<br/>",
    )

    content.append(
        Paragraph(
            safe_email,
            styles["BodyText"],
        )
    )

    content.append(PageBreak())

    content.append(
        Paragraph(
            "Analysis",
            styles["Heading2"],
        )
    )
    content.append(Spacer(1, 8))

    safe_analysis = escape(analysis).replace(
        "\n",
        "<br/>",
    )

    content.append(
        Paragraph(
            safe_analysis,
            styles["BodyText"],
        )
    )

    document.build(content)

    return str(file_path)