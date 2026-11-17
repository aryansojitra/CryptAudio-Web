"""
app/steganography package initialization.
Exposes public LSB embedding, extraction, bit conversion routines, and custom exception classes.
"""

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
