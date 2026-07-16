import json
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from email_parser import parse_eml_file
from main import (
    analyze_phishing_email,
    build_email_text,
)


app = FastAPI(title="Phishing Email Analyzer")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(exist_ok=True)

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
    )


@app.post("/analyze")
async def analyze_uploaded_email(
    file: UploadFile = File(...),
):
    original_name = file.filename or ""

    if not original_name.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    temporary_name = f"{uuid4().hex}.eml"
    temporary_path = UPLOAD_DIR / temporary_name

    try:
        with temporary_path.open("wb") as destination:
            shutil.copyfileobj(
                file.file,
                destination,
            )

        email_data = parse_eml_file(
            str(temporary_path)
        )

        email_text = build_email_text(email_data)

        analysis = analyze_phishing_email(
            email_data=email_data,
            email_text=email_text,
        )

        return {
            "success": True,
            "filename": original_name,
            "email": {
                "from": email_data.get("from", ""),
                "to": email_data.get("to", ""),
                "subject": email_data.get("subject", ""),
                "date": email_data.get("date", ""),
                "attachments": email_data.get(
                    "attachments",
                    [],
                ),
            },
            "analysis": analysis,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {error}",
        ) from error

    finally:
        await file.close()

        if temporary_path.exists():
            temporary_path.unlink()