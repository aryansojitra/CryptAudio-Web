"""
app/steganography package initialization.

Exposes:
1. Multi-Algorithm Steganography Core Architecture (Phase M2):
   - BaseStegoAlgorithm, DomainType, RobustnessEvaluationStatus
   - Data models: CapacityProfile, StegoResult, ExtractedPayload, StegoInspection
   - Standardized exception hierarchy: StegoAlgorithmError, CapacityExceededError, etc.
   - StegoRegistry and AlgorithmDescriptor
   - UniversalEnvelope (CSMA v1) utilities and constants
   - LSBAdapter
2. Legacy LSB Steganography Engine (Phase 1-12 baseline):
   - embed_payload, extract_payload, create_framed_payload
   - bytes_to_bits, bits_to_bytes
   - EmbeddingResult, SteganographyError, etc.
"""

# Base abstractions, enums, dataclasses, and exceptions
from app.steganography.base import (
    AlgorithmRegistryError,
    AudioFormatIncompatibleError,
    BaseStegoAlgorithm,
    CapacityExceededError,
    CapacityProfile,
    CorruptedPayloadError,
    DomainType,
    ExtractedPayload,
    HeaderNotFoundError,
    RobustnessEvaluationStatus,
    StegoAlgorithmError,
    StegoInspection,
    StegoResult,
    SynchronizationError,
    UnsupportedParameterError,
)

# Universal Envelope (CSMA v1)
from app.steganography.envelope import (
    ALGO_ID_DWT_DCT_QIM,
    ALGO_ID_ECHO,
    ALGO_ID_LSB,
    CSMA_HEADER_SIZE_BITS,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_DWT_DCT_QIM,
    SYNC_WORD_ECHO,
    SYNC_WORD_LSB,
    CSMAEnvelope,
    create_csma_envelope,
    parse_csma_envelope,
    resolve_algorithm_id,
)

# Algorithm Registry
from app.steganography.registry import (
    AlgorithmDescriptor,
    StegoRegistry,
    get_registry,
    reset_registry,
)

# LSB Strategy Adapter
from app.steganography.lsb_adapter import LSBAdapter

# DWT-DCT-QIM Strategy (Phase M3)
from app.steganography.dwt_dct_qim import DWTDCTQIMAlgorithm

# Echo Hiding Strategy (Phase M4)
from app.steganography.echo_hiding import EchoHidingAlgorithm

# Legacy LSB Engine (preserved for 100% backward compatibility)
from app.steganography.lsb_engine import (
    HEADER_SIZE_BITS,
    HEADER_SIZE_BYTES,
    STEGO_MAGIC,
    STEGO_VERSION,
    EmbeddingResult,
    InsufficientCapacityError,
    InvalidPayloadError,
    InvalidStegoFileError,
    PayloadCorruptionError,
    SteganographyError,
    UnsupportedVersionError,
    bits_to_bytes,
    bytes_to_bits,
    create_framed_payload,
    embed_payload,
    extract_payload,
)

__all__ = [
    # Multi-Algorithm Core
    "BaseStegoAlgorithm",
    "DomainType",
    "RobustnessEvaluationStatus",
    "CapacityProfile",
    "StegoResult",
    "ExtractedPayload",
    "StegoInspection",
    "StegoAlgorithmError",
    "CapacityExceededError",
    "HeaderNotFoundError",
    "SynchronizationError",
    "CorruptedPayloadError",
    "AudioFormatIncompatibleError",
    "UnsupportedParameterError",
    "AlgorithmRegistryError",
    # Universal Envelope
    "create_csma_envelope",
    "parse_csma_envelope",
    "resolve_algorithm_id",
    "CSMAEnvelope",
    "CSMA_MAGIC",
    "CSMA_VERSION",
    "CSMA_HEADER_SIZE_BYTES",
    "CSMA_HEADER_SIZE_BITS",
    "MAX_PAYLOAD_SIZE_BYTES",
    "ALGO_ID_LSB",
    "ALGO_ID_DWT_DCT_QIM",
    "ALGO_ID_ECHO",
    "SYNC_WORD_LSB",
    "SYNC_WORD_DWT_DCT_QIM",
    "SYNC_WORD_ECHO",
    # Registry
    "StegoRegistry",
    "AlgorithmDescriptor",
    "get_registry",
    "reset_registry",
    # Adapter
    "LSBAdapter",
    "DWTDCTQIMAlgorithm",
    "EchoHidingAlgorithm",
    # Legacy LSB Engine
    "embed_payload",
    "extract_payload",
    "bytes_to_bits",
    "bits_to_bytes",
    "create_framed_payload",
    "EmbeddingResult",
    "SteganographyError",
    "InsufficientCapacityError",
    "InvalidPayloadError",
    "InvalidStegoFileError",
    "PayloadCorruptionError",
    "UnsupportedVersionError",
    "STEGO_MAGIC",
    "STEGO_VERSION",
    "HEADER_SIZE_BYTES",
    "HEADER_SIZE_BITS",
]
