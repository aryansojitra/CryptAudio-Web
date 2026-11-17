"""
app/steganography/lsb_engine.py
CryptAudio Web — LSB Steganography Engine

Provides a standalone, robust Least Significant Bit (LSB) replacement engine
for embedding arbitrary binary payloads into uncompressed integer PCM WAV audio
and extracting them cleanly.

Operates purely on bytes without handling passwords or cryptographic keys.

Framing Protocol:
=================
Offset   Size (bytes)   Field             Description
-------------------------------------------------------------------------
0        4              Magic Identifier  b"CSLB" (CryptAudio Stego LSB)
4        1              Format Version    0x01 (Version 1)
5        4              Payload Length    Big-endian uint32 payload byte count
9        4              CRC32 Checksum    Big-endian uint32 payload CRC32
13       Variable       Payload Data      Raw payload bytes
-------------------------------------------------------------------------
Header Size: 13 bytes (104 bits).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from app.audio.wav_handler import read_wav, write_wav

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STEGO_MAGIC: Final[bytes] = b"CSLB"
STEGO_VERSION: Final[int] = 1
HEADER_SIZE_BYTES: Final[int] = 13
HEADER_SIZE_BITS: Final[int] = HEADER_SIZE_BYTES * 8  # 104 bits


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class SteganographyError(Exception):
    """Base exception for all steganography engine operations."""


class InsufficientCapacityError(SteganographyError):
    """Raised when host audio has insufficient samples to store the framed payload."""


class InvalidPayloadError(SteganographyError):
    """Raised when the payload is invalid, empty, or wrong type."""


class InvalidStegoFileError(SteganographyError):
    """Raised when the audio does not contain a valid stego header or is truncated."""


class PayloadCorruptionError(SteganographyError):
    """Raised when extracted payload fails CRC32 checksum verification."""


class UnsupportedVersionError(SteganographyError):
    """Raised when the stego format version is not supported."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmbeddingResult:
    """Metadata detailing the result of an LSB embedding operation."""

    success: bool
    payload_size_bytes: int
    framed_size_bytes: int
    required_bits: int
    available_bits: int
    utilization_percent: float
    output_path: str

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Bit Conversion Utilities (MSB-first)
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> list[int]:
    """
    Convert a sequence of bytes into a list of bits using Most Significant Bit (MSB) first order.

    Each byte produces exactly 8 bits, ordered from bit 7 (MSB) down to bit 0 (LSB).

    Example:
        b"\\x81" (10000001) -> [1, 0, 0, 0, 0, 0, 0, 1]

    Parameters:
        data: Input bytes.

    Returns:
        list[int]: Sequence of 0s and 1s.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Input data must be bytes or bytearray.")

    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """
    Convert a list of bits into bytes using Most Significant Bit (MSB) first order.

    Parameters:
        bits: Sequence of integer bit values (must all be 0 or 1).

    Returns:
        bytes: Assembled byte sequence.

    Raises:
        ValueError: If any bit value is not 0 or 1, or if bit count is not a multiple of 8.
    """
    if not isinstance(bits, list):
        raise TypeError("Bits must be a list of integers.")

    if len(bits) % 8 != 0:
        raise ValueError(
            f"Bit count ({len(bits)}) is not a multiple of 8. Cannot assemble complete bytes."
        )

    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        for bit_idx in range(8):
            bit = bits[i + bit_idx]
            if bit not in (0, 1):
                raise ValueError(f"Invalid bit value: {bit}. Expected 0 or 1.")
            byte_val = (byte_val << 1) | bit
        byte_array.append(byte_val)

    return bytes(byte_array)


# ---------------------------------------------------------------------------
# Payload Framing Helpers
# ---------------------------------------------------------------------------

def create_framed_payload(payload: bytes) -> bytes:
    """
    Wrap an arbitrary binary payload inside the CryptAudio stego framing protocol.

    Structure:
        Magic (4B) + Version (1B) + Length (4B, big-endian) + CRC32 (4B, big-endian) + Payload (NB)

    Parameters:
        payload: Binary payload bytes.

    Returns:
        bytes: Framed binary structure (13 + len(payload) bytes).
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise InvalidPayloadError("Payload must be bytes or bytearray.")
    if len(payload) == 0:
        raise InvalidPayloadError("Payload cannot be empty.")

    payload_bytes = bytes(payload)
    crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF

    header = (
        STEGO_MAGIC
        + struct.pack(">B", STEGO_VERSION)
        + struct.pack(">I", len(payload_bytes))
        + struct.pack(">I", crc)
    )
    return header + payload_bytes


# ---------------------------------------------------------------------------
# Embedding Functionality
# ---------------------------------------------------------------------------

def embed_payload(
    input_wav: str | Path,
    output_wav: str | Path,
    payload: bytes,
) -> EmbeddingResult:
    """
    Embed an arbitrary binary payload into the least significant bits of an audio file.

    Parameters:
        input_wav: Path to the source carrier PCM WAV file.
        output_wav: Path to save the resulting stego WAV file.
        payload: Binary payload bytes to conceal.

    Returns:
        EmbeddingResult: Metadata about the embedding operation.

    Raises:
        InvalidPayloadError: If the payload is empty or not bytes.
        ValueError: If input and output paths refer to the same file.
        InsufficientCapacityError: If host audio samples < required bits.
        AudioError: If input audio fails validation or output cannot be written.
    """
    in_path = Path(input_wav).resolve()
    out_path = Path(output_wav).resolve()

    if in_path == out_path:
        raise ValueError(
            f"Input and output paths cannot be identical ({in_path}). "
            f"Never overwrite the original carrier audio."
        )

    if not isinstance(payload, (bytes, bytearray)):
        raise InvalidPayloadError("Payload must be bytes or bytearray.")
    if len(payload) == 0:
        raise InvalidPayloadError("Payload cannot be empty.")

    # 1. Read and validate carrier audio
    wav_data = read_wav(in_path)

    # 2. Frame the payload and convert to bits
    framed_payload = create_framed_payload(bytes(payload))
    bits = bytes_to_bits(framed_payload)
    required_bits = len(bits)

    # 3. Capacity check
    total_samples = wav_data.frame_count * wav_data.channels
    available_bits = total_samples

    if required_bits > available_bits:
        raise InsufficientCapacityError(
            f"Insufficient capacity in carrier audio: requires {required_bits} bits "
            f"({len(framed_payload)} bytes), but audio provides {available_bits} samples/bits."
        )

    # 4. Perform sample-level LSB replacement
    # In uncompressed PCM (little-endian for multi-byte), the least significant bit
    # of each sample is located at bit 0 of the first byte of that sample.
    sample_width = wav_data.sample_width
    frame_bytes = bytearray(wav_data.frames)

    for i, bit in enumerate(bits):
        offset = i * sample_width
        frame_bytes[offset] = (frame_bytes[offset] & 0xFE) | bit

    # 5. Write the modified PCM frames
    write_wav(
        output_path=out_path,
        frames=bytes(frame_bytes),
        channels=wav_data.channels,
        sample_width=wav_data.sample_width,
        sample_rate=wav_data.sample_rate,
    )

    utilization = round((required_bits / available_bits) * 100, 4)

    return EmbeddingResult(
        success=True,
        payload_size_bytes=len(payload),
        framed_size_bytes=len(framed_payload),
        required_bits=required_bits,
        available_bits=available_bits,
        utilization_percent=utilization,
        output_path=str(out_path),
    )


# ---------------------------------------------------------------------------
# Extraction Functionality
# ---------------------------------------------------------------------------

def extract_payload(stego_wav: str | Path) -> bytes:
    """
    Extract and verify an embedded binary payload from a stego PCM WAV file.

    Reads sample LSBs, extracts and parses the 13-byte framing header, extracts
    the declared payload, validates the CRC32 checksum, and returns the original bytes.

    Parameters:
        stego_wav: Path to the stego WAV file.

    Returns:
        bytes: Extracted original payload bytes.

    Raises:
        InvalidStegoFileError: If file lacks a valid stego header or is truncated.
        UnsupportedVersionError: If format version is unsupported.
        PayloadCorruptionError: If CRC32 checksum verification fails.
        AudioError: If WAV file fails validation.
    """
    wav_data = read_wav(stego_wav)
    total_samples = wav_data.frame_count * wav_data.channels
    sample_width = wav_data.sample_width
    frame_bytes = wav_data.frames

    # Check that audio has at least enough samples for the 13-byte header
    if total_samples < HEADER_SIZE_BITS:
        raise InvalidStegoFileError(
            f"Audio file has only {total_samples} samples; at least {HEADER_SIZE_BITS} "
            f"samples are required to contain a steganography header."
        )

    # 1. Extract the 104 header bits from the first 104 samples
    header_bits = [
        frame_bytes[i * sample_width] & 1
        for i in range(HEADER_SIZE_BITS)
    ]
    header_bytes = bits_to_bytes(header_bits)

    # 2. Parse and validate header
    magic = header_bytes[:4]
    if magic != STEGO_MAGIC:
        raise InvalidStegoFileError(
            f"Invalid magic identifier: expected {STEGO_MAGIC!r}, found {magic!r}. "
            f"This file does not appear to contain an embedded payload."
        )

    version = header_bytes[4]
    if version != STEGO_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported stego format version: {version}. Expected version {STEGO_VERSION}."
        )

    payload_length = struct.unpack(">I", header_bytes[5:9])[0]
    expected_crc = struct.unpack(">I", header_bytes[9:13])[0]

    # 3. Check that audio has enough samples for declared payload
    required_total_bits = HEADER_SIZE_BITS + (payload_length * 8)
    if required_total_bits > total_samples:
        raise InvalidStegoFileError(
            f"Declared payload length ({payload_length} bytes) requires {required_total_bits} bits, "
            f"but audio contains only {total_samples} samples. Stego payload is truncated or invalid."
        )

    # 4. Extract payload bits
    payload_bits = [
        frame_bytes[i * sample_width] & 1
        for i in range(HEADER_SIZE_BITS, required_total_bits)
    ]
    payload_bytes = bits_to_bytes(payload_bits)

    # 5. Verify CRC32 checksum
    actual_crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise PayloadCorruptionError(
            f"Payload CRC32 checksum mismatch: expected {expected_crc:#010x}, "
            f"computed {actual_crc:#010x}. The embedded payload is corrupted."
        )

    return payload_bytes
