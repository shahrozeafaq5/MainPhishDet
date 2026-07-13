from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def parse_eml_file(file_path: str) -> dict[str, Any]:
    """Parse an .eml file and extract headers, body, and attachments."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    with path.open("rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    plain_text_body = ""
    html_body = ""
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":
                attachments.append(
                    {
                        "filename": part.get_filename() or "unknown",
                        "content_type": content_type,
                        "size": len(part.get_payload(decode=True) or b""),
                    }
                )

            elif content_type == "text/plain" and disposition != "attachment":
                plain_text_body += part.get_content()

            elif content_type == "text/html" and disposition != "attachment":
                html_body += part.get_content()

    else:
        content_type = message.get_content_type()

        if content_type == "text/plain":
            plain_text_body = message.get_content()

        elif content_type == "text/html":
            html_body = message.get_content()

    return {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "message_id": message.get("Message-ID", ""),
        "authentication_results": message.get("Authentication-Results", ""),
        "received_spf": message.get("Received-SPF", ""),
        "plain_text_body": plain_text_body.strip(),
        "html_body": html_body.strip(),
        "attachments": attachments,
    }