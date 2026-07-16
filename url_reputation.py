import base64
import os
from typing import Any

import httpx
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def create_virustotal_url_id(url: str) -> str:

    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def lookup_virustotal_url(url: str) -> dict[str, Any]:

    if not VT_API_KEY:
        return {
            "provider": "VirusTotal",
            "url": url,
            "available": False,
            "error": "VT_API_KEY was not found in .env",
        }

    url_id = create_virustotal_url_id(url)

    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
    }

    try:
        with httpx.Client(
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            response = client.get(
                endpoint,
                headers=headers,
            )

        if response.status_code == 404:
            return {
                "provider": "VirusTotal",
                "url": url,
                "available": True,
                "found": False,
                "message": (
                    "No existing VirusTotal report was found."
                ),
            }

        if response.status_code == 401:
            return {
                "provider": "VirusTotal",
                "url": url,
                "available": False,
                "error": "VirusTotal rejected the API key.",
            }

        if response.status_code == 403:
            return {
                "provider": "VirusTotal",
                "url": url,
                "available": False,
                "error": (
                    "VirusTotal denied access or the API quota "
                    "does not permit this request."
                ),
            }

        if response.status_code == 429:
            return {
                "provider": "VirusTotal",
                "url": url,
                "available": False,
                "error": "VirusTotal API rate limit reached.",
            }

        response.raise_for_status()

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        statistics = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = int(statistics.get("malicious", 0))
        suspicious = int(statistics.get("suspicious", 0))
        harmless = int(statistics.get("harmless", 0))
        undetected = int(statistics.get("undetected", 0))
        timeout = int(statistics.get("timeout", 0))

        total_engines = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )

        reputation = attributes.get("reputation", 0)

        categories = attributes.get("categories", {})

        return {
            "provider": "VirusTotal",
            "url": url,
            "available": True,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total_engines": total_engines,
            "reputation": reputation,
            "categories": categories,
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
            "last_final_url": attributes.get(
                "last_final_url",
                url,
            ),
            "times_submitted": attributes.get(
                "times_submitted",
                0,
            ),
        }

    except httpx.TimeoutException:
        return {
            "provider": "VirusTotal",
            "url": url,
            "available": False,
            "error": "VirusTotal request timed out.",
        }

    except httpx.HTTPStatusError as error:
        return {
            "provider": "VirusTotal",
            "url": url,
            "available": False,
            "error": (
                "VirusTotal returned HTTP status "
                f"{error.response.status_code}."
            ),
        }

    except httpx.HTTPError as error:
        return {
            "provider": "VirusTotal",
            "url": url,
            "available": False,
            "error": str(error),
        }

    except ValueError:
        return {
            "provider": "VirusTotal",
            "url": url,
            "available": False,
            "error": "VirusTotal returned invalid JSON.",
        }


def calculate_reputation_score(
    reputation_result: dict,
) -> int:
    """
    Convert VirusTotal findings into a local risk score.

    This is our application's heuristic, not VirusTotal's score.
    """

    if not reputation_result.get("found"):
        return 0

    malicious = reputation_result.get("malicious", 0)
    suspicious = reputation_result.get("suspicious", 0)
    reputation = reputation_result.get("reputation", 0)

    score = 0

    score += malicious * 20
    score += suspicious * 10

    if reputation < 0:
        score += min(abs(reputation), 20)

    return min(score, 100)


if __name__ == "__main__":
    import json

    test_url = input(
        "Enter a URL for VirusTotal lookup: "
    ).strip()

    result = lookup_virustotal_url(test_url)

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )