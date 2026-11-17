"""
app/crypto/aes_crypto.py
CryptAudio Web — Cryptographic Engine (AES-256-GCM & PBKDF2-HMAC-SHA256)

This module provides authenticated symmetric encryption and decryption of
Unicode text messages using AES-256-GCM and key derivation via PBKDF2-HMAC-SHA256.

Binary Payload Specification:
=============================
Offset   Size (bytes)   Field             Description
---------------------------------------------------------------------------------
0        4              Magic Identifier  b"CAUD" (CryptAudio)
4        1              Format Version    0x01 (Version 1)
5        16             Salt              Random 128-bit salt for PBKDF2
21       12             Nonce / IV        Random 96-bit nonce for AES-GCM
33       N >= 16        Ciphertext + Tag  AES-256-GCM ciphertext with 128-bit tag
---------------------------------------------------------------------------------
Total Header Size: 33 bytes.
Minimum Payload Size: 33 (header) + 16 (GCM tag for empty/minimal data) = 49 bytes.

Authenticated Associated Data (AAD):
The entire 33-byte header (Magic + Version + Salt + Nonce) is passed as AAD
during AES-GCM encryption and decryption. This cryptographically binds the header
parameters to the ciphertext, preventing header manipulation attacks.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Cryptographic Constants
# ---------------------------------------------------------------------------

MAGIC_IDENTIFIER: Final[bytes] = b"CAUD"
CURRENT_VERSION: Final[int] = 1

SALT_SIZE_BYTES: Final[int] = 16       # 128-bit salt
NONCE_SIZE_BYTES: Final[int] = 12      # 96-bit standard GCM nonce
KEY_SIZE_BYTES: Final[int] = 32        # 256-bit AES key
TAG_SIZE_BYTES: Final[int] = 16        # 128-bit authentication tag
PBKDF2_ITERATIONS: Final[int] = 600_000

HEADER_SIZE_BYTES: Final[int] = (
    len(MAGIC_IDENTIFIER) + 1 + SALT_SIZE_BYTES + NONCE_SIZE_BYTES
)  # 4 + 1 + 16 + 12 = 33 bytes

MIN_PAYLOAD_SIZE_BYTES: Final[int] = HEADER_SIZE_BYTES + TAG_SIZE_BYTES  # 49 bytes


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Base exception for all cryptographic operations."""


class InvalidMessageError(CryptoError):
    """Raised when the provided message is invalid, empty, or wrong type."""


class InvalidPasswordError(CryptoError):
    """Raised when the provided password is empty or wrong type."""


class InvalidPayloadError(CryptoError):
    """Raised when the binary payload header is corrupt, unsupported, or malformed."""


class DecryptionError(CryptoError):
    """Raised when decryption or cryptographic authentication fails."""


# ---------------------------------------------------------------------------
# Key Derivation Helper
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.

    Parameters:
        password: Plaintext password string.
        salt: 16-byte random salt.

    Returns:
        32-byte derived key suitable for AES-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_message(message: str, password: str) -> bytes:
    """
    Encrypt and authenticate a Unicode text message using AES-256-GCM.

    Generates a cryptographically secure random salt and nonce, derives an
    AES-256 key via PBKDF2-HMAC-SHA256 (600,000 iterations), and returns
    a binary payload containing the formatted header and ciphertext with tag.

    Parameters:
        message: The plaintext string to encrypt (supports arbitrary Unicode).
        password: The secret passphrase used to derive the encryption key.

    Returns:
        bytes: Binary payload (Header + Ciphertext + GCM Tag).

    Raises:
        InvalidMessageError: If message is not a non-empty string.
        InvalidPasswordError: If password is not a non-empty string.
    """
    if not isinstance(message, str):
        raise InvalidMessageError("Message must be a string.")
    if len(message) == 0:
        raise InvalidMessageError("Message cannot be empty.")

    if not isinstance(password, str):
        raise InvalidPasswordError("Password must be a string.")
    if len(password) == 0:
        raise InvalidPasswordError("Password cannot be empty.")

    # Generate fresh cryptographically secure random values
    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)

    # Derive 256-bit AES key
    key = _derive_key(password, salt)

    # Construct the 33-byte immutable header
    version_byte = bytes([CURRENT_VERSION])
    header = MAGIC_IDENTIFIER + version_byte + salt + nonce

    # Encrypt plaintext with AES-256-GCM, binding the header as AAD
    plaintext_bytes = message.encode("utf-8")
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=header)

    return header + ciphertext_and_tag


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Authenticate and decrypt a binary payload into the original Unicode text message.

    Validates the binary header structure, extracts salt and nonce, derives the
    AES key via PBKDF2-HMAC-SHA256, and authenticates/decrypts the ciphertext.

    Parameters:
        payload: The binary payload produced by encrypt_message().
        password: The secret passphrase required for key derivation.

    Returns:
        str: Decrypted plaintext Unicode string.

    Raises:
        InvalidPayloadError: If payload is malformed, truncated, or has invalid header.
        InvalidPasswordError: If password is not a non-empty string.
        DecryptionError: If authentication fails (wrong password or tampered data).
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise InvalidPayloadError("Payload must be bytes.")
    if len(payload) < MIN_PAYLOAD_SIZE_BYTES:
        raise InvalidPayloadError(
            f"Payload is truncated. Expected at least {MIN_PAYLOAD_SIZE_BYTES} bytes, got {len(payload)}."
        )

    if not isinstance(password, str):
        raise InvalidPasswordError("Password must be a string.")
    if len(password) == 0:
        raise InvalidPasswordError("Password cannot be empty.")

    payload_bytes = bytes(payload)

    # Validate Magic Identifier
    magic = payload_bytes[:4]
    if magic != MAGIC_IDENTIFIER:
        raise InvalidPayloadError("Invalid payload format: magic identifier mismatch.")

    # Validate Format Version
    version = payload_bytes[4]
    if version != CURRENT_VERSION:
        raise InvalidPayloadError(
            f"Unsupported payload version: {version}. Expected version {CURRENT_VERSION}."
        )

    # Extract Header Components
    salt = payload_bytes[5:21]   # 16 bytes
    nonce = payload_bytes[21:33] # 12 bytes
    header = payload_bytes[:HEADER_SIZE_BYTES]
    ciphertext_and_tag = payload_bytes[HEADER_SIZE_BYTES:]

    # Derive AES Key from password and embedded salt
    key = _derive_key(password, salt)

    # Authenticate and Decrypt with AES-256-GCM using header as AAD
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(
            nonce,
            ciphertext_and_tag,
            associated_data=header,
        )
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: authentication tag verification failed. "
            "Invalid password or tampered payload."
        ) from exc

    # Decode UTF-8 plaintext
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError("Decryption failed: plaintext is not valid UTF-8.") from exc
