"""
app/services/cryptaudio_service.py
CryptAudio Web — Centralized Multi-Algorithm Service Layer (Phase M5)

Coordinates the Cryptographic Engine, Audio Processing Engine, and
Steganography Algorithms via BaseStegoAlgorithm and StegoRegistry:
1. Encrypting a secret text message and concealing it into carrier WAV audio
   using a selectable algorithm (LSB, DWT-DCT-QIM, or Echo Hiding).
2. Extracting and decrypting a concealed message from a stego WAV audio file
   with explicit or automatic algorithm resolution.
3. Estimating algorithm-specific carrier audio capacity for given secret messages.
4. Non-destructively inspecting carrier audio for steganographic signatures.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.audio.wav_handler import (
    AudioError,
    AudioReadError,
    AudioWriteError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    WavData,
    inspect_wav,
    read_wav,
    validate_wav,
    write_wav,
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
from app.steganography.base import (
    AlgorithmRegistryError,
    AudioFormatIncompatibleError,
    BaseStegoAlgorithm,
    CapacityExceededError,
    CapacityProfile,
    CorruptedPayloadError,
    ExtractedPayload,
    HeaderNotFoundError,
    StegoAlgorithmError,
    StegoInspection,
    StegoResult,
    SynchronizationError,
    UnsupportedParameterError,
)
from app.steganography.envelope import (
    ALGO_ID_ECHO,
    ALGO_ID_LSB,
    ALGO_ID_DWT_DCT_QIM,
    ALGO_ID_TO_NAME,
    ALGO_NAME_TO_ID,
    CSMA_HEADER_SIZE_BYTES,
)
from app.steganography.lsb_engine import (
    HEADER_SIZE_BYTES,
    InsufficientCapacityError,
    InvalidStegoFileError,
    PayloadCorruptionError,
    SteganographyError,
    UnsupportedVersionError,
)
from app.steganography.registry import StegoRegistry, get_registry

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
    algorithm_id: str = "lsb"
    algorithm_parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class ExtractMessageResult:
    """Structured result of an extract_message_detailed operation."""

    success: bool
    message: str
    algorithm_id: str
    payload_size_bytes: int
    framing_checksum_verified: bool
    algorithm_parameters: dict[str, Any] = field(default_factory=dict)

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
    algorithm_id: str = "lsb"
    bits_per_sample: float = 1.0
    recommended_min_duration_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert estimate to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Helper: Registry Resolution
# ---------------------------------------------------------------------------

def _resolve_algorithm(
    algorithm: str | int | None,
    registry: StegoRegistry | None = None,
) -> BaseStegoAlgorithm:
    """
    Resolve a steganography algorithm by canonical name or integer ID from the registry.

    Parameters:
        algorithm: Algorithm identifier (e.g., 'lsb', 'dwt_dct_qim', 'echo', 1, 2, 3).
                   Defaults to 'lsb' if None.
        registry: Optional custom StegoRegistry instance; defaults to global singleton.

    Returns:
        BaseStegoAlgorithm: The resolved algorithm instance.

    Raises:
        AlgorithmRegistryError: If the algorithm is unknown or unregistered.
    """
    reg = registry if registry is not None else get_registry(include_echo=True)
    target_id = "lsb" if algorithm is None else algorithm
    return reg.get(target_id)


# ---------------------------------------------------------------------------
# Capacity Estimation Helper
# ---------------------------------------------------------------------------

def estimate_capacity(
    input_wav: str | Path,
    message: str,
    algorithm: str | int = "lsb",
    registry: StegoRegistry | None = None,
    **options: Any,
) -> CapacityEstimate:
    """
    Estimate whether a carrier audio file has enough capacity to hold an encrypted message
    for the specified steganography algorithm.

    Cryptographic overhead breakdown (AES-256-GCM):
        - 33 bytes fixed header (Magic 4B + Version 1B + Salt 16B + Nonce 12B)
        - N bytes ciphertext (UTF-8 byte length of message)
        - 16 bytes AES-GCM authentication tag
        Total Crypto Payload = len(message.encode("utf-8")) + 49 bytes.

    Steganography overhead breakdown (CSMA v1 Envelope):
        - 18 bytes universal framing header (Sync 2B + Magic 4B + Algo 1B + Ver 1B + Flags 2B + Len 4B + CRC32 4B)
        Total Framed Bytes = Total Crypto Payload + 18 bytes.

    Parameters:
        input_wav: Path to carrier WAV file.
        message: Secret message string.
        algorithm: Steganography algorithm to evaluate ('lsb', 'dwt_dct_qim', 'echo').
        registry: Optional custom registry.
        options: Algorithm-specific parameters (e.g., segment_size for Echo).

    Returns:
        CapacityEstimate: Comparison of required bits versus available capacity.

    Raises:
        AudioError: If carrier WAV file is invalid or missing.
        MessageEmbeddingError: If message is invalid or algorithm is unknown.
    """
    if not isinstance(message, str) or len(message) == 0:
        raise MessageEmbeddingError("Message must be a non-empty string.")

    call_options = dict(options)
    if isinstance(algorithm, str) and algorithm.strip().lower() == "legacy_cslb":
        call_options.setdefault("framing", "legacy_cslb")

    try:
        algo_instance = _resolve_algorithm(algorithm, registry)
    except AlgorithmRegistryError as exc:
        raise MessageEmbeddingError(f"Unsupported steganography algorithm '{algorithm}': {exc}") from exc

    in_path = Path(input_wav).resolve()
    try:
        wav_data = read_wav(in_path)
    except AudioError as exc:
        raise MessageEmbeddingError(f"Invalid carrier WAV audio: {exc}") from exc

    # 1. Calculate cryptographic payload size
    msg_utf8_len = len(message.encode("utf-8"))
    crypto_bytes = msg_utf8_len + 49  # 33B header + ciphertext + 16B GHASH tag

    # 2. Query algorithm-specific capacity profile
    try:
        profile = algo_instance.estimate_capacity(wav_data, **call_options)
    except StegoAlgorithmError as exc:
        raise MessageEmbeddingError(f"Capacity estimation failed for '{algo_instance.algorithm_id}': {exc}") from exc

    envelope_bytes = profile.envelope_overhead_bits // 8
    framed_bytes = crypto_bytes + envelope_bytes
    # Required bits equals the complete framed envelope in bits.
    # The 16-bit synchronization word is already included in the 18-byte (144-bit) CSMA header.
    required_bits = int((crypto_bytes * 8) + profile.envelope_overhead_bits)
    can_fit = crypto_bytes <= profile.max_payload_bytes
    available_bits = profile.available_bits
    utilization = round((required_bits / available_bits) * 100, 4) if available_bits > 0 else 0.0

    return CapacityEstimate(
        can_fit=can_fit,
        message_utf8_bytes=msg_utf8_len,
        estimated_crypto_bytes=crypto_bytes,
        framed_payload_bytes=framed_bytes,
        required_bits=required_bits,
        available_bits=available_bits,
        utilization_percent=utilization,
        algorithm_id=algo_instance.algorithm_id,
        bits_per_sample=profile.bits_per_sample,
        recommended_min_duration_sec=profile.recommended_min_duration_sec,
    )


# ---------------------------------------------------------------------------
# Metadata Inspection Helper
# ---------------------------------------------------------------------------

def inspect_stego_metadata(
    input_wav: str | Path,
    algorithm: str | int | None = None,
    registry: StegoRegistry | None = None,
    **options: Any,
) -> dict[str, Any]:
    """
    Non-destructively inspect carrier audio for steganographic headers and signatures.

    Parameters:
        input_wav: Path to carrier WAV file.
        algorithm: Optional algorithm identifier ('lsb', 'dwt_dct_qim', 'echo').
                   If None or 'auto', inspects across all registered algorithms.
        registry: Optional custom registry.
        options: Algorithm-specific inspection options.

    Returns:
        dict: Inspection summary detailing detected signature, algorithm, and header validity.
    """
    in_path = Path(input_wav).resolve()
    wav_data = read_wav(in_path)
    reg = registry if registry is not None else get_registry(include_echo=True)

    if algorithm is not None and str(algorithm).strip().lower() != "auto":
        algo_instance = _resolve_algorithm(algorithm, reg)
        inspection = algo_instance.inspect_metadata(wav_data, **options)
        return inspection.to_dict()

    # Automatic inspection across all available algorithms
    inspections: dict[str, dict[str, Any]] = {}
    detected_algo_id: str | None = None
    detected_inspection: StegoInspection | None = None

    for descriptor in reg.list_available():
        algo = reg.get(descriptor.algorithm_id)
        insp = algo.inspect_metadata(wav_data, **options)
        inspections[descriptor.algorithm_id] = insp.to_dict()
        if insp.has_stego_signature and detected_algo_id is None:
            detected_algo_id = descriptor.algorithm_id
            detected_inspection = insp

    if detected_inspection is not None and detected_algo_id is not None:
        return {
            "has_stego_signature": True,
            "detected_algorithm": detected_algo_id,
            "envelope_version": detected_inspection.envelope_version,
            "payload_length_bytes": detected_inspection.payload_length_bytes,
            "confidence_score": detected_inspection.confidence_score,
            "header_valid": detected_inspection.header_valid,
            "crc32_verified": detected_inspection.crc32_verified,
            "candidate_inspections": inspections,
        }

    return {
        "has_stego_signature": False,
        "detected_algorithm": None,
        "envelope_version": None,
        "payload_length_bytes": None,
        "confidence_score": 0.0,
        "header_valid": False,
        "crc32_verified": False,
        "candidate_inspections": inspections,
    }


# ---------------------------------------------------------------------------
# Core Workflow 1: Embed Message
# ---------------------------------------------------------------------------

def embed_message(
    input_wav: str | Path,
    output_wav: str | Path,
    message: str,
    password: str,
    algorithm: str | int = "lsb",
    registry: StegoRegistry | None = None,
    **options: Any,
) -> EmbedMessageResult:
    """
    Encrypt a secret Unicode message with AES-256-GCM and embed it into a PCM WAV file
    using the specified steganography algorithm.

    Execution Flow:
    1. Validate input parameters and ensure input != output.
    2. Resolve target steganography algorithm from the registry.
    3. Validate and load carrier WAV audio into memory.
    4. Encrypt message with AES-256-GCM and PBKDF2 (600,000 iterations).
    5. Verify carrier audio has sufficient capacity for the algorithm.
    6. Embed encrypted binary payload into carrier audio via BaseStegoAlgorithm.embed().
    7. Write modified audio frames to the output WAV path.
    8. Verify that the output WAV file is structurally valid.
    9. Return structured result metadata.

    Parameters:
        input_wav: Path to the input carrier WAV file.
        output_wav: Path where the resulting stego WAV file will be written.
        message: Plaintext secret message (supports arbitrary Unicode).
        password: Secret passphrase for encryption key derivation.
        algorithm: Machine identifier or numeric ID ('lsb', 'dwt_dct_qim', 'echo').
        registry: Optional custom StegoRegistry instance.
        options: Algorithm-specific parameters (e.g. delta for DWT, alpha for Echo).

    Returns:
        EmbedMessageResult: Structured metadata detailing the operation.

    Raises:
        MessageEmbeddingError: If validation, encryption, or embedding fails.
        InsufficientAudioCapacityError: If the carrier WAV lacks sufficient capacity.
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

    # Step 2: Resolve algorithm from registry
    call_options = dict(options)
    if isinstance(algorithm, str) and algorithm.strip().lower() == "legacy_cslb":
        call_options.setdefault("framing", "legacy_cslb")

    try:
        algo_instance = _resolve_algorithm(algorithm, registry)
    except AlgorithmRegistryError as exc:
        raise MessageEmbeddingError(f"Unsupported steganography algorithm '{algorithm}': {exc}") from exc

    # Step 3: Validate and read carrier WAV audio
    try:
        wav_data = read_wav(in_path)
    except AudioError as exc:
        raise MessageEmbeddingError(f"Invalid carrier WAV audio: {exc}") from exc

    # Step 4: Encrypt the secret message with AES-256-GCM
    try:
        encrypted_payload = encrypt_message(message, password)
    except (InvalidMessageError, InvalidPasswordError, CryptoError) as exc:
        raise MessageEmbeddingError(f"Encryption failed: {exc}") from exc

    # Step 5: Pre-check capacity using algorithm-specific profile
    try:
        profile = algo_instance.estimate_capacity(wav_data, **call_options)
        if len(encrypted_payload) > profile.max_payload_bytes:
            envelope_bytes = profile.envelope_overhead_bits // 8
            framed_bytes = len(encrypted_payload) + envelope_bytes
            required_bits = (len(encrypted_payload) * 8) + profile.envelope_overhead_bits
            raise InsufficientAudioCapacityError(
                f"Carrier audio has insufficient capacity: requires {required_bits} bits "
                f"({framed_bytes} bytes), but carrier provides only {profile.available_bits} samples/bits."
            )
    except CapacityExceededError as exc:
        raise InsufficientAudioCapacityError(str(exc)) from exc
    except InsufficientAudioCapacityError:
        raise
    except StegoAlgorithmError as exc:
        raise MessageEmbeddingError(f"Capacity pre-check failed: {exc}") from exc

    # Step 6: Embed the encrypted payload into carrier audio
    try:
        stego_result = algo_instance.embed(wav_data, encrypted_payload, **call_options)
    except CapacityExceededError as exc:
        raise InsufficientAudioCapacityError(str(exc)) from exc
    except InsufficientCapacityError as exc:
        raise InsufficientAudioCapacityError(str(exc)) from exc
    except (StegoAlgorithmError, SteganographyError, AudioError) as exc:
        _cleanup_file_safely(out_path)
        raise MessageEmbeddingError(f"Steganography embedding failed: {exc}") from exc

    # Step 7: Write modified audio frames to the output file
    try:
        write_wav(
            output_path=out_path,
            frames=stego_result.modified_wav.frames,
            channels=stego_result.modified_wav.channels,
            sample_width=stego_result.modified_wav.sample_width,
            sample_rate=stego_result.modified_wav.sample_rate,
        )
    except AudioError as exc:
        _cleanup_file_safely(out_path)
        raise MessageEmbeddingError(f"Failed to write output stego WAV: {exc}") from exc

    # Step 8: Verify output file integrity
    try:
        inspect_wav(out_path)
    except AudioError as exc:
        _cleanup_file_safely(out_path)
        raise MessageEmbeddingError(f"Generated stego WAV failed validation: {exc}") from exc

    duration = round(wav_data.frame_count / wav_data.sample_rate, 4)

    return EmbedMessageResult(
        success=True,
        message="Message successfully encrypted and embedded into audio.",
        output_path=str(out_path),
        original_audio_duration=duration,
        payload_size_bytes=stego_result.payload_size_bytes,
        framed_size_bytes=stego_result.framed_size_bytes,
        required_capacity_bits=stego_result.required_bits,
        available_capacity_bits=stego_result.available_bits,
        utilization_percent=stego_result.utilization_percent,
        algorithm_id=algo_instance.algorithm_id,
        algorithm_parameters=stego_result.algorithm_parameters,
    )


# ---------------------------------------------------------------------------
# Core Workflow 2: Extract Message
# ---------------------------------------------------------------------------

def extract_message_detailed(
    stego_wav: str | Path,
    password: str,
    algorithm: str | int | None = None,
    registry: StegoRegistry | None = None,
    **options: Any,
) -> ExtractMessageResult:
    """
    Extract and decrypt a secret message from a stego PCM WAV file with structured metadata.

    Execution Flow:
    1. Validate input parameters and audio file existence.
    2. Read and validate WAV container structure.
    3. Determine the target steganography algorithm:
       - If explicitly specified, resolve through the registry.
       - If None or 'auto', detect algorithm signature via registry.detect_algorithm().
       - If no supported signature is detected, raise MessageExtractionError.
    4. Extract the encrypted binary payload via BaseStegoAlgorithm.extract().
    5. Authenticate and decrypt the payload with AES-256-GCM and PBKDF2.
    6. Return structured result containing plaintext and extraction metadata.

    Parameters:
        stego_wav: Path to the stego WAV file.
        password: Secret passphrase for key derivation and authentication.
        algorithm: Optional explicit algorithm identifier ('lsb', 'dwt_dct_qim', 'echo').
        registry: Optional custom StegoRegistry instance.
        options: Algorithm-specific extraction options.

    Returns:
        ExtractMessageResult: Structured metadata and decrypted plaintext.

    Raises:
        MessageExtractionError: If extraction, authentication, or decryption fails.
    """
    # Step 1: Input validation
    if not isinstance(password, str) or len(password) == 0:
        raise MessageExtractionError("Password must be a non-empty string.")

    stego_path = Path(stego_wav).resolve()
    if not stego_path.is_file():
        raise MessageExtractionError(f"Stego audio file does not exist: {stego_path}")

    # Step 2: Validate and load WAV data
    try:
        wav_data = read_wav(stego_path)
    except AudioError as exc:
        raise MessageExtractionError(f"Invalid stego audio file: {exc}") from exc

    # Step 3: Determine algorithm
    call_options = dict(options)
    reg = registry if registry is not None else get_registry(include_echo=True)
    if algorithm is not None and str(algorithm).strip().lower() != "auto":
        clean_algo = str(algorithm).strip().lower()
        if clean_algo == "legacy_cslb":
            algo_instance = reg.get("lsb")
            call_options.setdefault("framing", "legacy_cslb")
        else:
            try:
                algo_instance = _resolve_algorithm(clean_algo, reg)
            except AlgorithmRegistryError as exc:
                raise MessageExtractionError(f"Unsupported steganography algorithm '{algorithm}': {exc}") from exc
    else:
        # Automatic algorithm detection across registered engines
        detected = reg.detect_algorithm(wav_data)
        if detected is not None:
            algo_instance = detected
        else:
            raise MessageExtractionError(
                "No valid hidden payload found in audio: no supported steganography algorithm signature detected."
            )

    # Step 4: Extract embedded payload
    try:
        extracted = algo_instance.extract(wav_data, **call_options)
    except HeaderNotFoundError as exc:
        raise MessageExtractionError(f"No valid hidden payload found in audio: {exc}") from exc
    except InvalidStegoFileError as exc:
        raise MessageExtractionError(f"No valid hidden payload found in audio: {exc}") from exc
    except SynchronizationError as exc:
        raise MessageExtractionError(f"No valid hidden payload found in audio (synchronization failed): {exc}") from exc
    except CorruptedPayloadError as exc:
        raise MessageExtractionError(f"Extracted payload is corrupted (CRC32 mismatch): {exc}") from exc
    except PayloadCorruptionError as exc:
        raise MessageExtractionError(f"Extracted payload is corrupted (CRC32 mismatch): {exc}") from exc
    except (UnsupportedVersionError, StegoAlgorithmError, SteganographyError, AudioError) as exc:
        raise MessageExtractionError(f"Payload extraction failed: {exc}") from exc

    # Step 5: Decrypt and authenticate payload using AES-256-GCM
    try:
        plaintext = decrypt_message(extracted.payload, password)
    except DecryptionError as exc:
        raise MessageExtractionError(
            "Authentication or decryption failed: incorrect password or tampered data."
        ) from exc
    except (CryptoPayloadError, InvalidPasswordError, CryptoError) as exc:
        raise MessageExtractionError(f"Decryption error: {exc}") from exc

    return ExtractMessageResult(
        success=True,
        message=plaintext,
        algorithm_id=algo_instance.algorithm_id,
        payload_size_bytes=len(extracted.payload),
        framing_checksum_verified=extracted.framing_checksum_verified,
        algorithm_parameters=extracted.algorithm_parameters,
    )


def extract_message(
    stego_wav: str | Path,
    password: str,
    algorithm: str | int | None = None,
    registry: StegoRegistry | None = None,
    **options: Any,
) -> str:
    """
    Extract and decrypt a secret message from a stego PCM WAV file.
    Maintains 100% backward compatibility by returning the plaintext string.

    Parameters:
        stego_wav: Path to the stego WAV file.
        password: Secret passphrase for key derivation and authentication.
        algorithm: Optional explicit algorithm identifier.
        registry: Optional custom StegoRegistry instance.
        options: Algorithm-specific extraction options.

    Returns:
        str: Exact original plaintext Unicode message.

    Raises:
        MessageExtractionError: If extraction, authentication, or decryption fails.
    """
    result = extract_message_detailed(
        stego_wav=stego_wav,
        password=password,
        algorithm=algorithm,
        registry=registry,
        **options,
    )
    return result.message


# ---------------------------------------------------------------------------
# Internal Helper
# ---------------------------------------------------------------------------

def _cleanup_file_safely(file_path: Path) -> None:
    """Safely remove a file without raising exceptions."""
    if file_path.is_file():
        try:
            file_path.unlink()
        except OSError:
            pass

