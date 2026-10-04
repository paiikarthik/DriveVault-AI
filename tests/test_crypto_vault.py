"""
Automated Cryptographic Test Suite for DriveVault AI.

Tests AES-256-GCM authenticated encryption, Argon2id key derivation,
vault packaging, byte-exact file reconstruction, tamper detection, and fail-safe safety.
"""

import os
import pytest
from app.crypto_vault import CryptoVault, VaultDecryptionError

def test_crypto_vault_roundtrip_text():
    """Test encrypting and decrypting a text file produces exact byte-for-byte match."""
    original_data = b"Confidential Financial Report 2026 - Top Secret Data"
    filename = "financial_report.txt"
    password = "CorrectHorseBatteryStaple123!"

    # 1. Encrypt and pack into .vault format
    vault_payload, vault_filename = CryptoVault.pack_vault(
        file_bytes=original_data,
        filename=filename,
        password=password,
        mime_type="text/plain"
    )

    assert vault_filename == "financial_report.txt.vault"
    assert len(vault_payload) > len(original_data)
    # Plaintext must NOT appear unencrypted in vault payload
    assert original_data not in vault_payload

    # 2. Decrypt with correct password
    restored_bytes, restored_filename, metadata = CryptoVault.unpack_vault(vault_payload, password)

    assert restored_bytes == original_data
    assert restored_filename == "financial_report.txt"
    assert metadata["original_filename"] == "financial_report.txt"
    assert metadata["cipher"] == "AES-256-GCM"
    assert metadata["kdf"] == "Argon2id"


def test_crypto_vault_binary_file():
    """Test roundtrip encryption for arbitrary binary data (simulating PDF / JPEG)."""
    binary_data = os.urandom(1024 * 50)  # 50 KB random binary blob
    filename = "family_photo.jpg"
    password = "MySecureVaultPassword99$"

    vault_payload, vault_filename = CryptoVault.pack_vault(
        file_bytes=binary_data,
        filename=filename,
        password=password,
        mime_type="image/jpeg"
    )

    restored_bytes, restored_filename, metadata = CryptoVault.unpack_vault(vault_payload, password)

    assert restored_bytes == binary_data
    assert restored_filename == "family_photo.jpg"


def test_crypto_vault_wrong_password_rejection():
    """Test that an incorrect password raises VaultDecryptionError safely without returning data."""
    original_data = b"Top Secret Payload"
    filename = "secret.pdf"
    correct_password = "RightPassword123"
    wrong_password = "WrongPassword456"

    vault_payload, _ = CryptoVault.pack_vault(
        file_bytes=original_data,
        filename=filename,
        password=correct_password
    )

    with pytest.raises(VaultDecryptionError) as exc_info:
        CryptoVault.unpack_vault(vault_payload, wrong_password)

    assert "Decryption failed" in str(exc_info.value)


def test_crypto_vault_tampered_ciphertext_detection():
    """Test that modifying even a single byte in ciphertext causes GCM tag validation to fail."""
    original_data = b"Unmodified Authentic Data"
    filename = "document.docx"
    password = "StrongPassword!88"

    vault_payload, _ = CryptoVault.pack_vault(
        file_bytes=original_data,
        filename=filename,
        password=password
    )

    # Flip a single bit in the ciphertext payload near the end
    tampered_bytes = bytearray(vault_payload)
    tampered_bytes[-1] ^= 0xFF

    with pytest.raises(VaultDecryptionError) as exc_info:
        CryptoVault.unpack_vault(bytes(tampered_bytes), password)

    assert "Decryption failed" in str(exc_info.value)


def test_crypto_vault_tampered_header_detection():
    """Test that modifying header metadata (AAD) is caught by AES-GCM tag verification."""
    original_data = b"Important Document"
    filename = "original_name.pdf"
    password = "PassWord123!"

    vault_payload, _ = CryptoVault.pack_vault(
        file_bytes=original_data,
        filename=filename,
        password=password
    )

    # Modify header string inside vault bytes (e.g. attempt to tamper filename in header)
    tampered_bytes = vault_payload.replace(b"original_name.pdf", b"hacked_name.pdf")

    with pytest.raises(VaultDecryptionError) as exc_info:
        CryptoVault.unpack_vault(tampered_bytes, password)

    assert "Decryption failed" in str(exc_info.value)


def test_crypto_vault_unique_salt_and_nonce():
    """Test that encrypting the same file twice produces unique salts, nonces, and different vault payloads."""
    data = b"Identical Data Payload"
    password = "SamePassword123"

    payload1, _ = CryptoVault.pack_vault(data, "test.pdf", password)
    payload2, _ = CryptoVault.pack_vault(data, "test.pdf", password)

    assert payload1 != payload2
