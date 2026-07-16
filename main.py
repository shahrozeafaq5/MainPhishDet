import json
import os

from dotenv import load_dotenv
from huggingface_hub import InferenceClient

from email_parser import parse_eml_file
from tools import analyze_email, save_phishing_report


# 1. Load environment variables
load_dotenv()

hf_token = os.getenv("HF_TOKEN")

if not hf_token:
    raise ValueError("HF_TOKEN was not found in .env")


# 2. Create Hugging Face client
client = InferenceClient(api_key=hf_token)

MODEL = "google/gemma-3-27b-it"


# 3. Send messages to Gemma
def ask_gemma(messages: list[dict]) -> str:
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=700,
        temperature=0.1,
    )

    content = response.choices[0].message.content

    if not content:
        raise ValueError("Gemma returned an empty response.")

    return content


# 4. Remove Markdown code fences
def clean_json_response(text: str) -> str:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]

    return cleaned.strip()


# 5. Convert parsed email dictionary into readable text
def build_email_text(email_data: dict) -> str:
    return f"""
From: {email_data.get("from") or "Not available"}
To: {email_data.get("to") or "Not available"}
Reply-To: {email_data.get("reply_to") or "Not available"}
Return-Path: {email_data.get("return_path") or "Not available"}
Subject: {email_data.get("subject") or "Not available"}
Date: {email_data.get("date") or "Not available"}
Authentication Results: {
    email_data.get("authentication_results") or "Not available"
}
Received SPF: {email_data.get("received_spf") or "Not available"}

Plain-text body:
{email_data.get("plain_text_body") or "Not available"}

HTML body:
{email_data.get("html_body") or "Not available"}
""".strip()

def analyze_phishing_email(
    email_data: dict,
    email_text: str,
) -> dict:

    tool_result = analyze_email(
    email_data=email_data,
    email_text=email_text,
)

    messages = [
        {
            "role": "system",
            "content": """
You are a cybersecurity analyst specializing in phishing emails.

Return exactly one valid JSON object using this structure:

{
  "risk_level": "Low",
  "risk_score": 0,
  "suspicious_indicators": [],
  "reasons": [],
  "recommended_action": ""
}

Rules:
- Return JSON only.
- Do not use Markdown.
- Do not use code fences.
- The outermost value must be a JSON object, not a string.
- risk_level must be Low, Medium, or High.
- risk_score must be an integer from 0 to 100.
- suspicious_indicators must be a list of strings.
- reasons must be a list of strings.
- Do not claim an email is definitely safe.
- Do not treat warning emojis, self-addressed automated emails,
  or unfamiliar software names as phishing by themselves.
- Base suspicious findings on evidence such as suspicious URLs,
  sender mismatch, Reply-To mismatch, credential requests,
  payment requests, impersonation, failed authentication,
  dangerous attachments, or urgent external actions.
-Consider risky attachment types such as executables, scripts,
archives, disk images, and shortcut files.
- Treat VirusTotal detections as supporting evidence.
- Clearly mention how many engines marked a URL as malicious or suspicious.
- Do not treat a missing VirusTotal report as proof that a URL is safe.
- Do not override strong local indicators merely because VirusTotal has no detection.
""",
        },
        {
            "role": "user",
            "content": f"""
Analyze the following email.

EMAIL CONTENT:
{email_text}

PYTHON TOOL RESULT:
{json.dumps(tool_result, indent=2, ensure_ascii=False)}
""",
        },
    ]

    response = ask_gemma(messages)
    cleaned_response = clean_json_response(response)

    try:
        analysis = json.loads(cleaned_response)
    except json.JSONDecodeError as error:
        raise ValueError(
            "Gemma returned invalid JSON.\n"
            f"Raw response:\n{response}"
        ) from error

    if not isinstance(analysis, dict):
        raise ValueError(
            "Gemma returned a JSON string or list instead of a JSON object."
        )

    required_fields = {
        "risk_level",
        "risk_score",
        "suspicious_indicators",
        "reasons",
        "recommended_action",
    }

    missing_fields = required_fields - analysis.keys()

    if missing_fields:
        raise ValueError(
            f"Gemma response is missing fields: {sorted(missing_fields)}"
        )

    return analysis


def main() -> None:
    print("\n=== Phishing Email Analyzer ===")

    file_path = input(
        "Enter the path of the .eml file: "
    ).strip().strip('"')

    if not file_path:
        print("No file path provided.")
        return

    try:
        # Step 1: Parse the .eml file
        email_data = parse_eml_file(file_path)

        print("\nEmail parsed successfully.")


        email_text = build_email_text(email_data)

        print("\n=== Parsed Email ===\n")
        print(email_text)

        # Step 3: Run Python scanner and Gemma analysis
        print("\nAnalyzing email...\n")

        analysis = analyze_phishing_email(
            email_data=email_data,
            email_text=email_text,
        )

        print("=== Phishing Analysis ===\n")
        print(
            json.dumps(
                analysis,
                indent=2,
                ensure_ascii=False,
            )
        )

        # Step 4: Convert dictionary to text for the PDF function
        analysis_text = json.dumps(
            analysis,
            indent=2,
            ensure_ascii=False,
        )

        # Step 5: Generate PDF report
        report_path = save_phishing_report(
            email_text=email_text,
            analysis=analysis_text,
        )

        print(f"\nPDF report saved at: {report_path}")

    except FileNotFoundError as error:
        print(f"\nFile error: {error}")

    except ValueError as error:
        print(f"\nInvalid data: {error}")

    except Exception as error:
        print(f"\nUnexpected error: {error}")


if __name__ == "__main__":
    main()