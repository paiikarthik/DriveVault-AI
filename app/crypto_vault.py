"""
Cryptographic Vault Engine for DriveVault AI.

Implements privacy-first authenticated file encryption and decryption using:
- AES-256-GCM for authenticated symmetric encryption
- Argon2id for key derivation from user password
- Cryptographically secure random salts and nonces per file
- Authenticated header metadata (AAD) to prevent tamper attacks
- Safe fail-state handling without producing partial/corrupted files
"""

import base64
import datetime
import json
import os
import struct
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.config import settings

class VaultDecryptionError(Exception):
    """Raised when vault decryption fails due to invalid password or tampered payload."""
    pass

class CryptoVault:
    """Core cryptographic engine for DriveVault AI."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit key from a plaintext password and salt using Argon2id.
        The plaintext password is NEVER stored or logged.
        """
        if not password:
            raise ValueError("Password cannot be empty.")
        if len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes.")

        kdf = Argon2id(
            salt=salt,
            length=settings.AES_KEY_SIZE,
            iterations=settings.ARGON2_TIME_COST,
            memory_cost=settings.ARGON2_MEMORY_COST,
            lanes=settings.ARGON2_PARALLELISM,
        )
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def pack_vault(
        cls,
        file_bytes: bytes,
        filename: str,
        password: str,
        mime_type: str = "application/octet-stream"
    ) -> Tuple[bytes, str]:
        """
        Encrypts plaintext file_bytes and builds a versioned .vault package.
        
        Returns:
            Tuple[bytes, str]: (vault_binary_payload, vault_filename)
        """
        if not file_bytes:
            raise ValueError("File content cannot be empty.")
        
        # Extract filename and extension
        original_name = os.path.basename(filename)
        base, ext = os.path.splitext(original_name)

        # Generate cryptographically secure random salt and nonce
        salt = os.urandom(settings.ARGON2_SALT_SIZE)
        nonce = os.urandom(settings.AES_NONCE_SIZE)

        # Derive key using Argon2id
        derived_key = cls.derive_key(password, salt)

        # Construct Vault Header Metadata
        header_data: Dict[str, Any] = {
            "version": settings.VAULT_FORMAT_VERSION,
            "original_filename": original_name,
            "base_name": base,
            "extension": ext,
            "mime_type": mime_type,
            "cipher": "AES-256-GCM",
            "kdf": "Argon2id",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "file_size": len(file_bytes),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        header_json_bytes = json.dumps(header_data, sort_keys=True).encode("utf-8")
        header_length = len(header_json_bytes)

        # Build Authenticated Additional Data (AAD)
        # Magic (10) + Version (1) + HeaderLength (4) + HeaderBytes
        magic = settings.VAULT_MAGIC_HEADER
        version_byte = struct.pack("!B", settings.VAULT_FORMAT_VERSION)
        length_bytes = struct.pack("!I", header_length)
        aad = magic + version_byte + length_bytes + header_json_bytes

        # Encrypt file bytes with AES-256-GCM
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, file_bytes, aad)

        # Assemble final .vault binary payload
        vault_payload = magic + version_byte + length_bytes + header_json_bytes + ciphertext
        vault_filename = f"{original_name}.vault"

        return vault_payload, vault_filename

    @classmethod
    def unpack_vault(
        cls,
        vault_bytes: bytes,
        password: str
    ) -> Tuple[bytes, str, Dict[str, Any]]:
        """
        Decrypts a .vault package using the provided password.
        
        Validates authentication tag and header integrity (AAD).
        If the password is wrong or content/metadata is modified, fails safely without returning output.
        
        Returns:
            Tuple[bytes, str, Dict[str, Any]]: (original_file_bytes, original_filename, metadata)
        """
        magic = settings.VAULT_MAGIC_HEADER
        if len(vault_bytes) < len(magic) + 5:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        # Check Magic Bytes
        if not vault_bytes.startswith(magic):
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        offset = len(magic)
        version = struct.unpack("!B", vault_bytes[offset:offset + 1])[0]
        offset += 1

        if version != settings.VAULT_FORMAT_VERSION:
            raise VaultDecryptionError(f"Unsupported vault format version: {version}")

        header_length = struct.unpack("!I", vault_bytes[offset:offset + 4])[0]
        offset += 4

        if len(vault_bytes) < offset + header_length:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        header_json_bytes = vault_bytes[offset:offset + header_length]
        offset += header_length

        try:
            header_data = json.loads(header_json_bytes.decode("utf-8"))
        except Exception:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        salt = base64.b64decode(header_data["salt_b64"])
        nonce = base64.b64decode(header_data["nonce_b64"])
        ciphertext = vault_bytes[offset:]

        # Derive key from password and stored salt
        try:
            derived_key = cls.derive_key(password, salt)
        except Exception:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        # Construct AAD for verification
        version_byte = struct.pack("!B", version)
        length_bytes = struct.pack("!I", header_length)
        aad = magic + version_byte + length_bytes + header_json_bytes

        # Decrypt payload using AES-256-GCM
        aesgcm = AESGCM(derived_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")
        except Exception:
            raise VaultDecryptionError("Decryption failed. The password may be incorrect or the file may have been modified.")

        original_filename = header_data.get("original_filename", "restored_file")
        return plaintext, original_filename, header_data
