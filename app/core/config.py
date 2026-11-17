"""
app/core/config.py
CryptAudio Web — Centralized Application Configuration
"""

from __future__ import annotations

from pathlib import Path


class Settings:
    """Application settings with sensible defaults for local development."""

    # --- Application Identity ---
    APP_NAME: str = "CryptAudio"
    APP_TITLE: str = "CryptAudio Web"
    APP_DESCRIPTION: str = (
        "Cryptographic Audio Steganography Application.\n\n"
        "Encrypt secret text messages with AES-256-GCM and hide them inside "
        "PCM WAV audio files using LSB steganography — entirely on your local machine."
    )
    APP_VERSION: str = "1.0.0"

    # --- Server Binding ---
    HOST: str = "127.0.0.1"   # Localhost only — never expose publicly
    PORT: int = 8000

    # --- Runtime ---
    DEBUG: bool = False

    # --- Upload Limits ---
    MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024           # 50 MB per single WAV file
    MAX_COMBINED_UPLOAD_BYTES: int = 100 * 1024 * 1024  # 100 MB combined limit for analysis

    # --- Temporary File Storage ---
    TEMP_DIR: Path = Path(__file__).resolve().parent.parent.parent / "temporary"


# Module-level singleton
settings = Settings()
# Ensure temporary directory exists
settings.TEMP_DIR.mkdir(parents=True, exist_ok=True)
