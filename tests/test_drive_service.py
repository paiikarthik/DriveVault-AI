"""
Automated Drive Service Test Suite for DriveVault AI.

Tests folder management, uploading .vault files, listing, downloading, and deleting files.
"""

import os
import pytest
from app.drive_service import GoogleDriveService
from app.config import settings

def test_drive_service_local_fallback_operations(tmp_path):
    """Test storage upload, list, download, and delete in fallback local mode."""
    # Override settings local storage dir to isolated tmp_path
    settings.LOCAL_STORAGE_DIR = str(tmp_path)
    drive_service = GoogleDriveService()

    vault_filename = "test_doc.pdf.vault"
    vault_content = b"DRIVEVAULT_MOCK_PAYLOAD_BYTES_12345"

    # 1. Upload file
    upload_res = drive_service.upload_vault_file(vault_filename, vault_content)
    assert upload_res["name"] == vault_filename
    assert upload_res["size"] == len(vault_content)

    # 2. List files
    file_list = drive_service.list_vault_files()
    assert len(file_list) == 1
    assert file_list[0]["name"] == vault_filename

    # 3. Download file
    downloaded_bytes = drive_service.download_vault_file(vault_filename)
    assert downloaded_bytes == vault_content

    # 4. Delete file
    delete_res = drive_service.delete_vault_file(vault_filename)
    assert delete_res is True

    # 5. Confirm deletion
    file_list_after = drive_service.list_vault_files()
    assert len(file_list_after) == 0

def test_get_auth_url_unconfigured():
    """Test get_auth_url when OAuth client credentials are missing."""
    settings.GOOGLE_CLIENT_ID = ""
    settings.GOOGLE_CLIENT_SECRET = ""
    auth_url, code_verifier = GoogleDriveService.get_auth_url()
    assert auth_url == ""
    assert code_verifier is None

def test_get_auth_url_configured():
    """Test get_auth_url when OAuth credentials are present returns URL and PKCE code_verifier."""
    settings.GOOGLE_CLIENT_ID = "mock_client_id.apps.googleusercontent.com"
    settings.GOOGLE_CLIENT_SECRET = "mock_client_secret"
    auth_url, code_verifier = GoogleDriveService.get_auth_url()
    assert "https://accounts.google.com" in auth_url
    assert code_verifier is not None
    assert len(code_verifier) > 10


