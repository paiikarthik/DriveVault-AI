"""
Main FastAPI Server for DriveVault AI.

Exposes endpoints for:
- Local file encryption & decryption (.vault packaging)
- Google Drive OAuth 2.0 & Cloud Vault Management
- Gemma AI Assistant Natural Language Interface
- Web UI frontend static files & templates
"""

import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import settings
from app.crypto_vault import CryptoVault, VaultDecryptionError
from app.drive_service import GoogleDriveService
from app.gemma_assistant import GemmaVaultAssistant

app = FastAPI(
    title="DriveVault AI",
    description="Secure Encrypted Google Drive File Vault powered by AES-256-GCM, Argon2id & Gemma AI",
    version="1.0.0"
)

# Setup Templates & Static Assets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
templates_dir = os.path.join(BASE_DIR, "templates")

os.makedirs(static_dir, exist_ok=True)
os.makedirs(templates_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Global Drive Service Instance & Assistant Instance
gemma_assistant = GemmaVaultAssistant()

def get_drive_service(request: Request) -> GoogleDriveService:
    """Helper to retrieve GoogleDriveService initialized from session cookie if present."""
    token_str = request.cookies.get("drivevault_token")
    token_dict = None
    if token_str:
        try:
            import json
            token_dict = json.loads(token_str)
        except Exception:
            pass
    return GoogleDriveService(token_dict=token_dict)


class ChatRequest(BaseModel):
    message: str


@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Renders the main web user interface."""
    drive_service = get_drive_service(request)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "is_connected": drive_service.is_connected,
            "gemma_enabled": bool(settings.GEMMA_API_KEY)
        }
    )


@app.post("/api/vault/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...),
    upload_to_drive: bool = Form(False),
    request: Request = None
):
    """
    Encrypts an uploaded file using AES-256-GCM + Argon2id.
    Produces a .vault package. Option to upload directly to Google Drive.
    """
    if not password or len(password) < 1:
        raise HTTPException(status_code=400, detail="Password is required for encryption.")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        vault_payload, vault_filename = CryptoVault.pack_vault(
            file_bytes=file_bytes,
            filename=file.filename or "file",
            password=password,
            mime_type=file.content_type or "application/octet-stream"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")

    # Upload to Drive if requested
    drive_result = None
    if upload_to_drive:
        drive_service = get_drive_service(request)
        drive_result = drive_service.upload_vault_file(vault_filename, vault_payload)

    return JSONResponse({
        "success": True,
        "message": f"Successfully encrypted '{file.filename}' into '{vault_filename}'.",
        "vault_filename": vault_filename,
        "file_size": len(vault_payload),
        "drive_result": drive_result
    })


@app.post("/api/vault/download-encrypted")
async def download_encrypted_file(
    file: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Encrypts a file and returns the .vault file directly for download.
    """
    if not password:
        raise HTTPException(status_code=400, detail="Password is required.")

    file_bytes = await file.read()
    vault_payload, vault_filename = CryptoVault.pack_vault(
        file_bytes=file_bytes,
        filename=file.filename or "file",
        password=password,
        mime_type=file.content_type or "application/octet-stream"
    )

    return StreamingResponse(
        io.BytesIO(vault_payload),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{vault_filename}"'}
    )


@app.post("/api/vault/decrypt")
async def decrypt_file(
    file: Optional[UploadFile] = File(None),
    file_id: Optional[str] = Form(None),
    password: str = Form(...),
    request: Request = None
):
    """
    Decrypts a .vault package provided via upload or Google Drive file_id.
    Fails safely if password is wrong or package is modified.
    """
    if not password:
        raise HTTPException(status_code=400, detail="Password is required for decryption.")

    vault_bytes = None

    if file:
        vault_bytes = await file.read()
    elif file_id:
        drive_service = get_drive_service(request)
        try:
            vault_bytes = drive_service.download_vault_file(file_id)
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"File not found in vault: {str(e)}")

    if not vault_bytes:
        raise HTTPException(status_code=400, detail="No vault file or file ID provided.")

    try:
        plaintext, original_filename, metadata = CryptoVault.unpack_vault(vault_bytes, password)
    except VaultDecryptionError as e:
        # Standard strict security failure message
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail="Decryption failed. The password may be incorrect or the file may have been modified."
        )

    import io
    mime_type = metadata.get("mime_type", "application/octet-stream")
    
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{original_filename}"',
            "X-Original-Filename": original_filename
        }
    )


@app.get("/api/drive/auth-url")
async def get_google_auth_url(response: Response):
    """Generates Google OAuth 2.0 Login URL."""
    auth_url, code_verifier = GoogleDriveService.get_auth_url()
    if not auth_url:
        return JSONResponse({
            "configured": False,
            "auth_url": "",
            "message": "Google OAuth credentials are not set in environment. Running in Local Vault mode."
        })
    resp = JSONResponse({"configured": True, "auth_url": auth_url})
    if code_verifier:
        resp.set_cookie(
            key="drivevault_code_verifier",
            value=code_verifier,
            httponly=True,
            samesite="lax"
        )
    return resp


@app.get("/api/drive/callback")
async def google_auth_callback(code: str, request: Request):
    """Handles Google OAuth authorization code redirect."""
    try:
        code_verifier = request.cookies.get("drivevault_code_verifier")
        token_dict = GoogleDriveService.exchange_code_for_tokens(code, code_verifier=code_verifier)
        import json
        resp = RedirectResponse(url="/")
        resp.set_cookie(
            key="drivevault_token",
            value=json.dumps(token_dict),
            httponly=True,
            samesite="lax"
        )
        resp.delete_cookie("drivevault_code_verifier")
        return resp
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth authentication failed: {str(e)}")


@app.get("/api/drive/status")
async def drive_status(request: Request):
    """Returns Google Drive connection status."""
    drive_service = get_drive_service(request)
    return JSONResponse({
        "connected": drive_service.is_connected,
        "mode": "Google Drive" if drive_service.is_connected else "Local Vault (Offline)"
    })


@app.get("/api/drive/files")
async def list_vault_files(request: Request):
    """Lists encrypted .vault files."""
    drive_service = get_drive_service(request)
    files = drive_service.list_vault_files()
    return JSONResponse({
        "success": True,
        "files": files,
        "mode": "Google Drive" if drive_service.is_connected else "Local Vault (Offline)"
    })


@app.delete("/api/drive/files/{file_id}")
async def delete_vault_file(file_id: str, request: Request):
    """Deletes an encrypted .vault file."""
    drive_service = get_drive_service(request)
    success = drive_service.delete_vault_file(file_id)
    if not success:
        raise HTTPException(status_code=404, detail="Failed to delete file or file not found.")
    return JSONResponse({"success": True, "message": f"File '{file_id}' deleted successfully."})


@app.post("/api/ai/chat")
async def chat_with_gemma(chat_req: ChatRequest):
    """Interacts with Gemma AI Assistant for natural language vault management."""
    result = gemma_assistant.process_message(chat_req.message)
    return JSONResponse(result)
