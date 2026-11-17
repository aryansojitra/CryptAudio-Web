"""
app/crypto package initialization.
Exposes public encryption/decryption routines and custom exception classes.
"""

from app.crypto.aes_crypto import (
    CryptoError,
    DecryptionError,
    InvalidMessageError,
    InvalidPasswordError,
    InvalidPayloadError,
    decrypt_message,
    encrypt_message,
)

__all__ = [
    "encrypt_message",
    "decrypt_message",
    "CryptoError",
    "InvalidMessageError",
    "InvalidPasswordError",
    "InvalidPayloadError",
    "DecryptionError",
]
