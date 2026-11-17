"""
tests/test_crypto.py
CryptAudio Web — Cryptographic Engine Test Suite (Phase 3)

Tests AES-256-GCM encryption/decryption, PBKDF2 key derivation, header validation,
tamper detection, and Unicode support.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_crypto.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.crypto.aes_crypto import (
    HEADER_SIZE_BYTES,
    MAGIC_IDENTIFIER,
    MIN_PAYLOAD_SIZE_BYTES,
    DecryptionError,
    InvalidMessageError,
    InvalidPasswordError,
    InvalidPayloadError,
    decrypt_message,
    encrypt_message,
)


# ---------------------------------------------------------------------------
# 1-5. Encryption & Decryption with Various Character Sets
# ---------------------------------------------------------------------------

def test_ascii_encryption_decryption() -> None:
    """1. ASCII message encryption and round-trip decryption."""
    original = "This is a confidential secret message for CryptAudio."
    password = "SuperSecretPassword123!"
    payload = encrypt_message(original, password)
    decrypted = decrypt_message(payload, password)
    assert decrypted == original


def test_unicode_encryption_decryption() -> None:
    """2. General Unicode message encryption and round-trip decryption."""
    original = "Café au lait, señorita! M&A transactions: €500M or ¥70B. Über-cool!"
    password = "UnicodePassphrase_2026"
    payload = encrypt_message(original, password)
    decrypted = decrypt_message(payload, password)
    assert decrypted == original


def test_gujarati_encryption_decryption() -> None:
    """3. Gujarati script encryption and decryption."""
    original = "નમસ્તે દુનિયા! ક્રિપ્ટોગ્રાફી ઓડિયો સ્ટેગનોગ્રાફી પ્રોજેક્ટ."
    password = "પાસવર્ડ_ગુજરાતી_૧૨૩"
    payload = encrypt_message(original, password)
    decrypted = decrypt_message(payload, password)
    assert decrypted == original


def test_hindi_encryption_decryption() -> None:
    """4. Hindi (Devanagari) script encryption and decryption."""
    original = "नमस्ते भारत! गुप्त संदेश ऑडियो फ़ाइल में छिपाया जाएगा।"
    password = "सुरक्षित_पासवर्ड_२०२६"
    payload = encrypt_message(original, password)
    decrypted = decrypt_message(payload, password)
    assert decrypted == original


def test_emoji_encryption_decryption() -> None:
    """5. Emoji and mixed symbols encryption and decryption."""
    original = "🔐 Secret audio steganography 🎵🎧! Top secret 🤫🚀✨ — 100% secure."
    password = "EmojiPass🗝️🛡️"
    payload = encrypt_message(original, password)
    decrypted = decrypt_message(payload, password)
    assert decrypted == original


# ---------------------------------------------------------------------------
# 6-8. Authentication & Tamper Detection
# ---------------------------------------------------------------------------

def test_wrong_password_rejected() -> None:
    """6. Decryption fails with DecryptionError when an incorrect password is used."""
    message = "Secret message payload"
    password = "CorrectPassword123"
    wrong_password = "IncorrectPassword999"

    payload = encrypt_message(message, password)

    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_message(payload, wrong_password)


def test_ciphertext_tampering_detected() -> None:
    """7. Tampering with any byte in the ciphertext portion triggers DecryptionError."""
    message = "Data integrity is paramount."
    password = "SecurityKey#456"
    payload = bytearray(encrypt_message(message, password))

    # Flip bits in the ciphertext portion (after header)
    payload[HEADER_SIZE_BYTES + 2] ^= 0xFF

    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_message(bytes(payload), password)


def test_header_tampering_detected() -> None:
    """8. Tampering with header fields triggers DecryptionError or InvalidPayloadError."""
    message = "Authenticated header test"
    password = "MyPassword789"
    payload = bytearray(encrypt_message(message, password))

    # Alter salt (offset 5-20)
    salt_tampered = bytearray(payload)
    salt_tampered[10] ^= 0x01
    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_message(bytes(salt_tampered), password)

    # Alter nonce (offset 21-32)
    nonce_tampered = bytearray(payload)
    nonce_tampered[25] ^= 0x01
    with pytest.raises(DecryptionError, match="Decryption failed"):
        decrypt_message(bytes(nonce_tampered), password)


# ---------------------------------------------------------------------------
# 9-11. Payload Format & Header Validation
# ---------------------------------------------------------------------------

def test_invalid_magic_identifier_rejected() -> None:
    """9. Rejects payloads with corrupted magic identifier."""
    message = "Valid message"
    password = "ValidPassword"
    payload = bytearray(encrypt_message(message, password))

    # Corrupt magic bytes b"CAUD" -> b"BAUD"
    payload[0] = ord(b"B")

    with pytest.raises(InvalidPayloadError, match="magic identifier mismatch"):
        decrypt_message(bytes(payload), password)


def test_unsupported_version_rejected() -> None:
    """10. Rejects payloads with unrecognized format version."""
    message = "Valid message"
    password = "ValidPassword"
    payload = bytearray(encrypt_message(message, password))

    # Set version byte to 99
    payload[4] = 99

    with pytest.raises(InvalidPayloadError, match="Unsupported payload version"):
        decrypt_message(bytes(payload), password)


def test_truncated_payload_rejected() -> None:
    """11. Rejects payloads smaller than the minimum payload size."""
    password = "ValidPassword"

    # Less than header size
    short_payload = MAGIC_IDENTIFIER + b"\x01" + b"\x00" * 10
    with pytest.raises(InvalidPayloadError, match="truncated"):
        decrypt_message(short_payload, password)

    # Zero bytes
    with pytest.raises(InvalidPayloadError, match="truncated"):
        decrypt_message(b"", password)

    # Exactly header size (missing ciphertext and tag)
    header_only = MAGIC_IDENTIFIER + b"\x01" + b"\x00" * 28
    assert len(header_only) == HEADER_SIZE_BYTES
    assert len(header_only) < MIN_PAYLOAD_SIZE_BYTES
    with pytest.raises(InvalidPayloadError, match="truncated"):
        decrypt_message(header_only, password)


# ---------------------------------------------------------------------------
# 12-14. Input Validation & Type Safety
# ---------------------------------------------------------------------------

def test_empty_message_validation() -> None:
    """12. Rejects empty messages."""
    with pytest.raises(InvalidMessageError, match="empty"):
        encrypt_message("", "ValidPassword123")


def test_empty_password_validation() -> None:
    """13. Rejects empty passwords in both encrypt and decrypt."""
    with pytest.raises(InvalidPasswordError, match="empty"):
        encrypt_message("Valid Message", "")

    dummy_payload = b"X" * MIN_PAYLOAD_SIZE_BYTES
    with pytest.raises(InvalidPasswordError, match="empty"):
        decrypt_message(dummy_payload, "")


def test_invalid_input_types() -> None:
    """14. Rejects invalid input types (None, int, dict, bytes message)."""
    # Invalid message types
    with pytest.raises(InvalidMessageError, match="must be a string"):
        encrypt_message(None, "ValidPassword")  # type: ignore

    with pytest.raises(InvalidMessageError, match="must be a string"):
        encrypt_message(12345, "ValidPassword")  # type: ignore

    with pytest.raises(InvalidMessageError, match="must be a string"):
        encrypt_message(b"bytes instead of str", "ValidPassword")  # type: ignore

    # Invalid password types
    with pytest.raises(InvalidPasswordError, match="must be a string"):
        encrypt_message("Valid Message", None)  # type: ignore

    with pytest.raises(InvalidPasswordError, match="must be a string"):
        encrypt_message("Valid Message", ["list"])  # type: ignore

    # Invalid payload types in decrypt
    with pytest.raises(InvalidPayloadError, match="must be bytes"):
        decrypt_message("string_instead_of_bytes", "ValidPassword")  # type: ignore

    with pytest.raises(InvalidPayloadError, match="must be bytes"):
        decrypt_message(None, "ValidPassword")  # type: ignore


# ---------------------------------------------------------------------------
# 15-18. Cryptographic Properties & Freshness
# ---------------------------------------------------------------------------

def test_output_is_bytes() -> None:
    """15. Confirms the encryption output type is bytes."""
    payload = encrypt_message("Check output type", "Pass1234")
    assert isinstance(payload, bytes)
    assert len(payload) >= MIN_PAYLOAD_SIZE_BYTES


def test_different_ciphertexts_for_same_message_and_password() -> None:
    """16. Two encryptions of the same input produce different payloads."""
    message = "Identical message content"
    password = "SamePassword123"

    payload1 = encrypt_message(message, password)
    payload2 = encrypt_message(message, password)

    assert payload1 != payload2


def test_fresh_salt_and_nonce_generated() -> None:
    """17. Fresh random salt and nonce are generated for each encryption."""
    message = "Testing randomness"
    password = "TestPassword"

    payload1 = encrypt_message(message, password)
    payload2 = encrypt_message(message, password)

    # Salt is at bytes [5:21]
    salt1 = payload1[5:21]
    salt2 = payload2[5:21]
    assert salt1 != salt2

    # Nonce is at bytes [21:33]
    nonce1 = payload1[21:33]
    nonce2 = payload2[21:33]
    assert nonce1 != nonce2


def test_exact_original_message_returned() -> None:
    """18. Decryption returns strictly byte-for-byte identical Unicode string."""
    large_message = (
        "Multi-line secret message:\n"
        "Line 1: 🔐 High security audio steganography.\n"
        "Line 2: ગુજરાતી લખાણ અને હિન્દી લખાણ સાથે.\n"
        "Line 3: Special characters: !@#$%^&*()_+{}[]:;\"'<>,.?/~`|\\\n"
        "Line 4: Spaces and tabs: \t\t   end."
    )
    password = "ComplexPassword_!@#$"

    payload = encrypt_message(large_message, password)
    recovered = decrypt_message(payload, password)

    assert recovered == large_message
    assert len(recovered) == len(large_message)
