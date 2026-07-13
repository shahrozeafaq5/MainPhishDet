import json
import os

from dotenv import load_dotenv
from huggingface_hub import InferenceClient
from tools import analyze_email

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
    print("Paste the email below.")
    print("Type END on a new line when finished.\n")

    email_lines = []

    while True:
        line = input()

        if line.strip().upper() == "END":
            break

        email_lines.append(line)

    email_text = "\n".join(email_lines).strip()

    if not email_text:
        print("No email text was provided.")
        return

    try:
        answer = analyze_phishing_email(email_text)

        print("\n=== Analysis Result ===\n")
        print(answer)

    except Exception as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()