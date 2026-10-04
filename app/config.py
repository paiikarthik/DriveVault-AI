"""
Application Configuration for DriveVault AI.
Loads configuration from environment variables with safe defaults.
"""
import os
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv()

# Allow HTTP redirect URIs for local OAuth testing
if os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/drive/callback").startswith("http://"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

class Settings:
    # Security Configuration
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536  # 64 MB
    ARGON2_PARALLELISM: int = 4
    ARGON2_SALT_SIZE: int = 16  # 128-bit salt
    
    AES_KEY_SIZE: int = 32  # 256 bits
    AES_NONCE_SIZE: int = 12  # 96-bit nonce for GCM
    
    VAULT_MAGIC_HEADER: bytes = b"DRIVEVAULT"
    VAULT_FORMAT_VERSION: int = 1

    # Google Drive OAuth Configuration
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/drive/callback")
    DRIVE_VAULT_FOLDER_NAME: str = "DriveVault"

    # Gemma AI Assistant Configuration
    GEMMA_API_KEY: str = os.getenv("GEMMA_API_KEY", "")
    GEMMA_MODEL_NAME: str = os.getenv("GEMMA_MODEL_NAME", "gemma-2-9b-it")

    # Storage Paths
    LOCAL_STORAGE_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local_vault")

settings = Settings()

os.makedirs(settings.LOCAL_STORAGE_DIR, exist_ok=True)

