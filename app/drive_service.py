"""
Google Drive OAuth 2.0 & API Service for DriveVault AI.

Uses minimum required permission scope:
`https://www.googleapis.com/auth/drive.file` (only files created/opened by DriveVault AI).

Also provides an automatic local vault fallback storage mode when OAuth credentials are absent
or when running in offline development mode.
"""

import io
import json
import os
from typing import List, Dict, Any, Optional, Tuple

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

from app.config import settings

SCOPES = ["https://www.googleapis.com/auth/drive.file"]

class GoogleDriveService:
    """Manages Google Drive OAuth 2.0 authentication and file operations."""

    def __init__(self, token_dict: Optional[Dict[str, Any]] = None):
        self.credentials: Optional[Credentials] = None
        self.service = None
        self.is_connected = False
        self.vault_folder_id: Optional[str] = None
        
        if token_dict:
            try:
                self.credentials = Credentials.from_authorized_user_info(token_dict, SCOPES)
                if self.credentials:
                    if self.credentials.expired and self.credentials.refresh_token:
                        from google.auth.transport.requests import Request
                        self.credentials.refresh(Request())
                    if self.credentials.valid:
                        self.service = build("drive", "v3", credentials=self.credentials)
                        self.is_connected = True
                        self.ensure_vault_folder()
            except Exception as e:
                print(f"[DriveService] Failed to initialize Google Drive service: {e}")

    @staticmethod
    def get_auth_url() -> Tuple[str, Optional[str]]:
        """Generates Google OAuth 2.0 authorization URL and PKCE code_verifier."""
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            return "", None

        client_config = {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI]
            }
        }

        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=settings.GOOGLE_REDIRECT_URI
        )
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        return auth_url, flow.code_verifier

    @staticmethod
    def exchange_code_for_tokens(code: str, code_verifier: Optional[str] = None) -> Dict[str, Any]:
        """Exchanges OAuth authorization code for credentials token dictionary."""
        client_config = {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [settings.GOOGLE_REDIRECT_URI]
            }
        }

        kwargs = {
            "client_config": client_config,
            "scopes": SCOPES,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI
        }
        if code_verifier:
            kwargs["code_verifier"] = code_verifier

        flow = Flow.from_client_config(**kwargs)
        if not code_verifier:
            flow.autogenerate_code_verifier = False

        flow.fetch_token(code=code)
        creds = flow.credentials
        return json.loads(creds.to_json())

    def ensure_vault_folder(self) -> str:
        """Finds or creates the dedicated DriveVault folder in Google Drive."""
        if not self.is_connected or not self.service:
            # Fallback local directory
            return settings.LOCAL_STORAGE_DIR

        try:
            folder_name = settings.DRIVE_VAULT_FOLDER_NAME
            query = f"mimeType = 'application/vnd.google-apps.folder' and name = '{folder_name}' and trashed = false"
            results = self.service.files().list(q=query, fields="files(id, name)").execute()
            files = results.get("files", [])

            if files:
                self.vault_folder_id = files[0]["id"]
            else:
                folder_metadata = {
                    "name": folder_name,
                    "mimeType": "application/vnd.google-apps.folder"
                }
                folder = self.service.files().create(body=folder_metadata, fields="id").execute()
                self.vault_folder_id = folder.get("id")

            return self.vault_folder_id
        except Exception as e:
            print(f"[DriveService] Error resolving DriveVault folder: {e}")
            return settings.LOCAL_STORAGE_DIR

    def upload_vault_file(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Uploads encrypted .vault payload to Google Drive (or local storage fallback)."""
        if self.is_connected and self.service:
            try:
                folder_id = self.ensure_vault_folder()
                file_metadata = {
                    "name": filename,
                    "parents": [folder_id] if folder_id else []
                }
                media = MediaIoBaseUpload(
                    io.BytesIO(content),
                    mimetype="application/octet-stream",
                    resumable=True
                )
                uploaded_file = self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields="id, name, createdTime, size"
                ).execute()

                return {
                    "id": uploaded_file.get("id"),
                    "name": uploaded_file.get("name"),
                    "created_at": uploaded_file.get("createdTime"),
                    "size": int(uploaded_file.get("size", len(content))),
                    "storage": "Google Drive"
                }
            except Exception as e:
                print(f"[DriveService] Google Drive upload failed, falling back to local: {e}")

        # Local storage fallback
        file_path = os.path.join(settings.LOCAL_STORAGE_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(content)

        return {
            "id": filename,
            "name": filename,
            "created_at": os.path.getctime(file_path),
            "size": len(content),
            "storage": "Local Vault (Offline)"
        }

    def list_vault_files(self) -> List[Dict[str, Any]]:
        """Lists encrypted .vault files in Google Drive (or local storage fallback)."""
        file_list = []

        if self.is_connected and self.service:
            try:
                folder_id = self.ensure_vault_folder()
                query = f"'{folder_id}' in parents and name contains '.vault' and trashed = false"
                results = self.service.files().list(
                    q=query,
                    fields="files(id, name, createdTime, size)"
                ).execute()
                drive_files = results.get("files", [])

                for item in drive_files:
                    file_list.append({
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "created_at": item.get("createdTime"),
                        "size": int(item.get("size", 0)),
                        "storage": "Google Drive"
                    })
                return file_list
            except Exception as e:
                print(f"[DriveService] Error listing Google Drive files: {e}")

        # Local fallback listing
        if os.path.exists(settings.LOCAL_STORAGE_DIR):
            for f in os.listdir(settings.LOCAL_STORAGE_DIR):
                if f.endswith(".vault"):
                    p = os.path.join(settings.LOCAL_STORAGE_DIR, f)
                    stat = os.stat(p)
                    file_list.append({
                        "id": f,
                        "name": f,
                        "created_at": stat.st_ctime,
                        "size": stat.st_size,
                        "storage": "Local Vault (Offline)"
                    })

        return file_list

    def download_vault_file(self, file_id: str) -> bytes:
        """Downloads .vault payload from Google Drive (or local storage fallback)."""
        if self.is_connected and self.service:
            try:
                request = self.service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                return fh.getvalue()
            except Exception as e:
                print(f"[DriveService] Error downloading from Google Drive ({file_id}): {e}")

        # Local storage fallback download
        local_path = os.path.join(settings.LOCAL_STORAGE_DIR, file_id)
        if os.path.exists(local_path):
            with open(local_path, "rb") as f:
                return f.read()

        raise FileNotFoundError(f"Vault file with ID '{file_id}' not found.")

    def delete_vault_file(self, file_id: str) -> bool:
        """Deletes .vault file from Google Drive (or local storage fallback)."""
        if self.is_connected and self.service:
            try:
                self.service.files().delete(fileId=file_id).execute()
                return True
            except Exception as e:
                print(f"[DriveService] Error deleting file from Google Drive ({file_id}): {e}")

        # Local fallback delete
        local_path = os.path.join(settings.LOCAL_STORAGE_DIR, file_id)
        if os.path.exists(local_path):
            os.remove(local_path)
            return True

        return False
