"""
app/core/config.py
CryptAudio Web — Centralized Application Configuration
"""

from __future__ import annotations

import os
from pathlib import Path


class Settings:
    """Application settings with sensible defaults for local development and cloud deployment."""

    # --- Application Identity ---
    APP_NAME: str = "CryptAudio"
    APP_TITLE: str = "CryptAudio Web"
    APP_DESCRIPTION: str = (
        "Cryptographic Audio Steganography Application.\n\n"
        "Encrypt secret text messages with AES-256-GCM and hide them inside "
        "PCM WAV audio files using LSB, DWT-DCT-QIM, or Echo Hiding steganography."
    )
    APP_VERSION: str = "1.0.0"

    # --- Server Binding ---
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # --- Runtime ---
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # --- Upload Limits ---
    MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024           # 50 MB per single WAV file
    MAX_COMBINED_UPLOAD_BYTES: int = 100 * 1024 * 1024  # 100 MB combined limit for analysis

    # --- Temporary File Storage ---
    TEMP_DIR: Path = Path(__file__).resolve().parent.parent.parent / "temporary"


# Module-level singleton
settings = Settings()
# Ensure temporary directory exists
settings.TEMP_DIR.mkdir(parents=True, exist_ok=True)
