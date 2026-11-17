"""
app/services/cryptaudio_service.py
CryptAudio Web — Centralized Service Layer

Coordinates the Cryptographic Engine, Audio Processing Engine, and
LSB Steganography Engine to provide end-to-end workflows:
1. Encrypting a secret text message and concealing it in a PCM WAV audio file.
2. Extracting and decrypting a concealed message from a stego WAV audio file.
3. Estimating carrier audio capacity for given secret messages.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.audio.wav_handler import (
    AudioError,
    AudioReadError,
    AudioWriteError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    inspect_wav,
    read_wav,
    validate_wav,
)
from app.crypto.aes_crypto import (
    CryptoError,
    DecryptionError,
    InvalidMessageError,
    InvalidPasswordError,
    InvalidPayloadError as CryptoPayloadError,
    decrypt_message,
    encrypt_message,
)
from app.steganography.lsb_engine import (
    HEADER_SIZE_BYTES,
    InsufficientCapacityError,
    InvalidPayloadError as StegoPayloadError,
    InvalidStegoFileError,
    PayloadCorruptionError,
    SteganographyError,
    UnsupportedVersionError,
    embed_payload,
    extract_payload,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Service Exceptions
# ---------------------------------------------------------------------------

class ServiceError(Exception):
    """Base exception for all service layer operations."""


class MessageEmbeddingError(ServiceError):
    """Raised when encrypting and embedding a secret message fails."""


class MessageExtractionError(ServiceError):
    """Raised when extracting and decrypting a secret message fails."""


class InsufficientAudioCapacityError(MessageEmbeddingError):
    """Raised when carrier audio lacks sufficient capacity for the encrypted payload."""


# ---------------------------------------------------------------------------
# Result Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmbedMessageResult:
    """Structured result of a successful embed_message operation."""

    success: bool
    message: str
    output_path: str
    original_audio_duration: float
    payload_size_bytes: int
    framed_size_bytes: int
    required_capacity_bits: int
    available_capacity_bits: int
    utilization_percent: float

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class CapacityEstimate:
    """Detailed capacity comparison between a message and a carrier audio file."""

    can_fit: bool
    message_utf8_bytes: int
    estimated_crypto_bytes: int
    framed_payload_bytes: int
    required_bits: int
    available_bits: int
    utilization_percent: float

    def to_dict(self) -> dict[str, Any]:
        """Convert estimate to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Capacity Estimation Helper
# ---------------------------------------------------------------------------

def estimate_capacity(input_wav: str | Path, message: str) -> CapacityEstimate:
    """
    Estimate whether a carrier audio file has enough capacity to hold an encrypted message.

    Cryptographic overhead breakdown:
        - 33 bytes fixed header (Magic 4B + Version 1B + Salt 16B + Nonce 12B)
        - N bytes ciphertext (UTF-8 byte length of message)
        - 16 bytes AES-GCM authentication tag
        Total Crypto Payload = len(message.encode("utf-8")) + 49 bytes.

    Steganography overhead breakdown:
        - 13 bytes framing header (Magic 4B + Version 1B + Length 4B + CRC32 4B)
        Total Framed Bytes = Total Crypto Payload + 13 bytes.
        Total Required Bits = Total Framed Bytes * 8.

    Parameters:
        input_wav: Path to carrier WAV file.
        message: Secret message string.

    Returns:
        CapacityEstimate: Comparison of required bits versus available samples.

    Raises:
        AudioError: If carrier WAV file is invalid or missing.
        MessageEmbeddingError: If message is invalid.
    """
    if not isinstance(message, str) or len(message) == 0:
        raise MessageEmbeddingError("Message must be a non-empty string.")

    wav_data = validate_wav(input_wav)
    total_samples = wav_data.frame_count * wav_data.channels
    available_bits = total_samples

    msg_utf8_len = len(message.encode("utf-8"))
    # AES-GCM payload = 33B header + msg_utf8_len + 16B tag = msg_utf8_len + 49
    crypto_bytes = msg_utf8_len + 49
    framed_bytes = crypto_bytes + HEADER_SIZE_BYTES
    required_bits = framed_bytes * 8

    can_fit = required_bits <= available_bits
    utilization = round((required_bits / available_bits) * 100, 4) if available_bits > 0 else 0.0

    return CapacityEstimate(
        can_fit=can_fit,
        message_utf8_bytes=msg_utf8_len,
        estimated_crypto_bytes=crypto_bytes,
        framed_payload_bytes=framed_bytes,
        required_bits=required_bits,
        available_bits=available_bits,
        utilization_percent=utilization,
    )


# ---------------------------------------------------------------------------
# Core Workflow 1: Embed Message
# ---------------------------------------------------------------------------

def embed_message(
    input_wav: str | Path,
    output_wav: str | Path,
    message: str,
    password: str,
) -> EmbedMessageResult:
    """
    Encrypt a secret Unicode message and embed it into a PCM WAV file.

    Execution Flow:
    1. Validate input parameters and paths.
    2. Validate carrier WAV audio using Phase 4.
    3. Encrypt message with AES-256-GCM and PBKDF2 using Phase 3.
    4. Verify carrier audio has sufficient capacity.
    5. Embed framed binary payload into sample LSBs using Phase 5.
    6. Verify that the output WAV file is valid and readable.
    7. Return structured result metadata.

    Parameters:
        input_wav: Path to the input carrier WAV file.
        output_wav: Path where the resulting stego WAV file will be written.
        message: Plaintext secret message (supports arbitrary Unicode).
        password: Secret passphrase for encryption key derivation.

    Returns:
        EmbedMessageResult: Structured metadata detailing the operation.

    Raises:
        MessageEmbeddingError: If validation, encryption, or embedding fails.
        InsufficientAudioCapacityError: If the carrier WAV is too small.
    """
    in_path = Path(input_wav).resolve()
    out_path = Path(output_wav).resolve()

    # Step 1: Input validation
    if in_path == out_path:
        raise MessageEmbeddingError(
            f"Input and output paths cannot be identical ({in_path}). "
            "Never overwrite the original carrier audio."
        )

    if not isinstance(message, str) or len(message) == 0:
        raise MessageEmbeddingError("Message must be a non-empty string.")

    if not isinstance(password, str) or len(password) == 0:
        raise MessageEmbeddingError("Password must be a non-empty string.")

    # Step 2: Validate carrier WAV audio
    try:
        wav_data = read_wav(in_path)
    except AudioError as exc:
        raise MessageEmbeddingError(f"Invalid carrier WAV audio: {exc}") from exc

    # Step 3: Encrypt the secret message
    try:
        encrypted_payload = encrypt_message(message, password)
    except (InvalidMessageError, InvalidPasswordError, CryptoError) as exc:
        raise MessageEmbeddingError(f"Encryption failed: {exc}") from exc

    # Step 4: Pre-check capacity before file operations
    total_samples = wav_data.frame_count * wav_data.channels
    available_bits = total_samples
    framed_payload_bytes = len(encrypted_payload) + HEADER_SIZE_BYTES
    required_bits = framed_payload_bytes * 8

    if required_bits > available_bits:
        raise InsufficientAudioCapacityError(
            f"Carrier audio has insufficient capacity: requires {required_bits} bits "
            f"({framed_payload_bytes} bytes), but carrier provides only {available_bits} samples/bits."
        )

    # Step 5: Embed the encrypted payload into carrier audio
    try:
        embed_result = embed_payload(
            input_wav=in_path,
            output_wav=out_path,
            payload=encrypted_payload,
        )
    except InsufficientCapacityError as exc:
        raise InsufficientAudioCapacityError(str(exc)) from exc
    except (SteganographyError, AudioError) as exc:
        # Clean up partial output file if created
        if out_path.is_file():
            try:
                out_path.unlink()
            except OSError:
                pass
        raise MessageEmbeddingError(f"Steganography embedding failed: {exc}") from exc

    # Step 6: Verify output file integrity
    try:
        stego_info = inspect_wav(out_path)
    except AudioError as exc:
        if out_path.is_file():
            try:
                out_path.unlink()
            except OSError:
                pass
        raise MessageEmbeddingError(f"Generated stego WAV failed validation: {exc}") from exc

    duration = round(wav_data.frame_count / wav_data.sample_rate, 4)

    return EmbedMessageResult(
        success=True,
        message="Message successfully encrypted and embedded into audio.",
        output_path=str(out_path),
        original_audio_duration=duration,
        payload_size_bytes=len(encrypted_payload),
        framed_size_bytes=framed_payload_bytes,
        required_capacity_bits=required_bits,
        available_capacity_bits=available_bits,
        utilization_percent=embed_result.utilization_percent,
    )


# ---------------------------------------------------------------------------
# Core Workflow 2: Extract Message
# ---------------------------------------------------------------------------

def extract_message(
    stego_wav: str | Path,
    password: str,
) -> str:
    """
    Extract and decrypt a secret message from a stego PCM WAV file.

    Execution Flow:
    1. Validate password and stego audio file.
    2. Extract the encrypted binary payload using Phase 5.
    3. Authenticate and decrypt the payload using Phase 3.
    4. Return the original plaintext Unicode message.

    Parameters:
        stego_wav: Path to the stego WAV file.
        password: Secret passphrase for key derivation and authentication.

    Returns:
        str: Exact original plaintext Unicode message.

    Raises:
        MessageExtractionError: If extraction, authentication, or decryption fails.
    """
    # Step 1: Input validation
    if not isinstance(password, str) or len(password) == 0:
        raise MessageExtractionError("Password must be a non-empty string.")

    stego_path = Path(stego_wav).resolve()
    if not stego_path.is_file():
        raise MessageExtractionError(f"Stego audio file does not exist: {stego_path}")

    # Validate WAV structure
    try:
        validate_wav(stego_path)
    except AudioError as exc:
        raise MessageExtractionError(f"Invalid stego audio file: {exc}") from exc

    # Step 2: Extract embedded payload
    try:
        encrypted_payload = extract_payload(stego_path)
    except InvalidStegoFileError as exc:
        raise MessageExtractionError(
            f"No valid hidden payload found in audio: {exc}"
        ) from exc
    except PayloadCorruptionError as exc:
        raise MessageExtractionError(
            f"Extracted payload is corrupted (CRC32 mismatch): {exc}"
        ) from exc
    except (UnsupportedVersionError, SteganographyError, AudioError) as exc:
        raise MessageExtractionError(f"Payload extraction failed: {exc}") from exc

    # Step 3: Decrypt and authenticate payload
    try:
        plaintext = decrypt_message(encrypted_payload, password)
    except DecryptionError as exc:
        raise MessageExtractionError(
            "Authentication or decryption failed: incorrect password or tampered data."
        ) from exc
    except (CryptoPayloadError, InvalidPasswordError, CryptoError) as exc:
        raise MessageExtractionError(f"Decryption error: {exc}") from exc

    return plaintext
