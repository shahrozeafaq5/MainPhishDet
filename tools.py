from datetime import datetime
from pathlib import Path


def get_current_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add_numbers(number1: float, number2: float) -> float:
    return number1 + number2


def save_text(filename: str, content: str) -> str:
    folder = Path("saved_files")
    folder.mkdir(exist_ok=True)

    safe_filename = filename.replace(" ", "_")

    if not safe_filename.endswith(".txt"):
        safe_filename += ".txt"

    file_path = folder / safe_filename
    file_path.write_text(content, encoding="utf-8")

    return str(file_path)