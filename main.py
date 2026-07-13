import json
import os
from  urllib.parse import   urlparse
from dotenv import load_dotenv
from huggingface_hub import InferenceClient
from tools import analyze_email, save_phishing_report
import json

from email_parser import parse_eml_file

# 1. Load API token
load_dotenv()

hf_token = os.getenv("HF_TOKEN")

if not hf_token:
    raise ValueError("HF_TOKEN was not found in .env")


# 2. Create model client
client = InferenceClient(api_key=hf_token)

MODEL = "google/gemma-3-27b-it"


# 3. Call Gemma
def ask_gemma(messages: list[dict]) -> str:
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=300,
        temperature=0.1,
    )

    return response.choices[0].message.content

def clean_json_response(text: str) -> str:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.replace("**", "")
    cleaned = cleaned.replace("*", "")

    return cleaned.strip()



def analyze_phishing_email(email_text: str) -> str:
    # 1. Python tool analyzes the email
    tool_result = analyze_email(email_text)


    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst. "
                "Explain phishing findings clearly and briefly. "
                "Do not claim an email is definitely safe."
            ),
        },
        {
            "role": "user",
            "content": f"""
Analyze this phishing detection result.

Email:
{email_text}

Tool result:
{json.dumps(tool_result, indent=2)}

Give:
1. Risk level
2. Suspicious indicators
3. Why they are suspicious
4. Recommended action
""",
        },
    ]

    return ask_gemma(messages)


def main() -> None:
    print("\n=== Phishing Email Analyzer ===")

    file_path = input("Enter the path of the .eml file: ").strip()

    if not file_path:
        print("No file path provided.")
        return

    try:
        email_data = parse_eml_file(file_path)

        print("\n=== Parsed Email ===\n")
        print(json.dumps(email_data, indent=2, ensure_ascii=False))

    except FileNotFoundError as error:
        print(f"\nError: {error}")

    except ValueError as error:
        print(f"\nError: {error}")

    except Exception as error:
        print(f"\nUnexpected error: {error}")


if __name__ == "__main__":
    main()