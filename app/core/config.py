"""
app/core/config.py
CryptAudio Web — Centralized Application Configuration
"""

from __future__ import annotations


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

    # --- Server ---
    HOST: str = "127.0.0.1"   # Localhost only — never expose publicly
    PORT: int = 8000

    # --- Runtime ---
    DEBUG: bool = False        # Set True during active development if needed

    # --- Upload limits (enforced in future phases) ---
    MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB ceiling for WAV files


# Module-level singleton — import this everywhere
settings = Settings()
