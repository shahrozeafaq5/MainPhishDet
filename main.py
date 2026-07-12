import json
import os

from dotenv import load_dotenv
from huggingface_hub import InferenceClient
from tools import get_current_time, add_numbers, save_text


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


# 4. Remove ```json blocks
def clean_json_response(text: str) -> str:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]

    return cleaned.strip()


# 5. Ask Gemma which action is needed
def choose_action(question: str) -> dict:
    messages = [
        {
            "role": "system",
            "content": """
Choose exactly one action based on the user's question.

Available actions:

1. get_current_time
Use when the user asks for the current date or time.

Return exactly:
{"action": "get_current_time"}

2. add_numbers
Use when the user asks to add two numbers.

Extract both numbers from the user's question.

Return exactly:
{
  "action": "add_numbers",
  "number1": 10,
  "number2": 20
}

3. normal_answer
Use for every other question.

Return exactly:
{"action": "normal_answer"}
4. save_text
Use when the user asks to save some text into a file.

Return exactly:

{
  "action": "save_text",
  "filename": "notes",
  "content": "Text to save"
}
Rules:
- Respond with valid JSON only.
- Do not use markdown code blocks.
- For add_numbers, always include number1 and number2.
-For save_text, always include filename and content.
""",
        },
        {
            "role": "user",
            "content": question,
        },
    ]

    response = ask_gemma(messages)
    cleaned_response = clean_json_response(response)

    print("Model decision:", cleaned_response)

    return json.loads(cleaned_response)

# 6. Main agent flow
def run_agent(question: str) -> str:
    decision = choose_action(question)

    action = decision.get("action")

    if action == "get_current_time":
        tool_result = get_current_time()

        messages = [
            {
                "role": "system",
                "content": "Answer briefly using the provided tool result.",
            },
            {
                "role": "user",
                "content": (
                    f"Question: {question}\n"
                    f"Current date and time: {tool_result}"
                ),
            },
        ]

        return ask_gemma(messages)

    if action == "normal_answer":
        messages = [
            {
                "role": "system",
                "content": "Give a short and clear answer.",
            },
            {
                "role": "user",
                "content": question,
            },
        ]

        return ask_gemma(messages)
    
    if action == "save_text":
        filename = decision.get("filename")
        content = decision.get("content")

        if not filename or not content:
            return "The model did not provide a filename or content."

        file_path = save_text(filename, content)

        return f"File saved successfully at: {file_path}"

    if action == "add_numbers":
        number1 = decision.get("number1")
        number2 = decision.get("number2")

        if number1 is None or number2 is None:
            return "The model did not provide both numbers."

        tool_result = add_numbers(number1, number2)

        messages = [
            {
                "role": "system",
                "content": "Answer briefly using the calculation result.",
            },
            {
                "role": "user",
                "content": (
                    f"Question: {question}\n"
                    f"Calculation result: {tool_result}"
                ),
            },
        ]

        return ask_gemma(messages)

    return f"Unknown action selected: {action}"


def main() -> None:
    question = input("You: ").strip()

    if not question:
        print("Please enter a question.")
        return

    try:
        answer = run_agent(question)
        print(f"\nGemma: {answer}")

    except json.JSONDecodeError as error:
        print(f"\nGemma returned invalid JSON: {error}")

    except Exception as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()