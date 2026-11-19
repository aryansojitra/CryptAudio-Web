"""
app/steganography/envelope.py
CryptAudio Web — Universal Steganography Payload Envelope (CSMA v1)

Implements packing, parsing, validation, and serialization for the universal
multi-algorithm steganography framing protocol (CSMA v1).

Format Specification:
=====================
Offset   Size (bytes)   Field             Format / Value
-----------------------------------------------------------------------------------
0        2              Sync Word         Big-endian uint16 (0xF9A9 / 0x596A)
2        4              Magic Identifier  b"CSMA" (CryptAudio Stego Multi-Algorithm)
6        1              Algorithm ID      0x01 = LSB, 0x02 = DWT_DCT_QIM, 0x03 = ECHO
7        1              Format Version    0x01 (Version 1)
8        2              Algorithm Flags   Big-endian uint16 packed parameters
10       4              Payload Length    Big-endian uint32 payload byte count (N)
14       4              CRC32 Checksum    Big-endian uint32 CRC32 (framing checksum for accidental corruption detection)
18       N              Payload Data      Raw binary cryptographic payload (CAUD...)
-----------------------------------------------------------------------------------
Total Header Overhead: 18 bytes (144 bits).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Final

from app.steganography.base import (
    CorruptedPayloadError,
    HeaderNotFoundError,
    SynchronizationError,
    UnsupportedParameterError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CSMA_MAGIC: Final[bytes] = b"CSMA"
CSMA_VERSION: Final[int] = 1
CSMA_HEADER_SIZE_BYTES: Final[int] = 18
CSMA_HEADER_SIZE_BITS: Final[int] = CSMA_HEADER_SIZE_BYTES * 8  # 144 bits

# Struct format string: big-endian uint16, 4 bytes, uint8, uint8, uint16, uint32, uint32
CSMA_HEADER_STRUCT: Final[str] = ">H4sBBHII"

# Canonical Algorithm IDs
ALGO_ID_LSB: Final[int] = 1
ALGO_ID_DWT_DCT_QIM: Final[int] = 2
ALGO_ID_ECHO: Final[int] = 3

SUPPORTED_ALGORITHM_IDS: Final[frozenset[int]] = frozenset({
    ALGO_ID_LSB,
    ALGO_ID_DWT_DCT_QIM,
    ALGO_ID_ECHO,
})

ALGO_NAME_TO_ID: Final[dict[str, int]] = {
    "lsb": ALGO_ID_LSB,
    "dwt_dct_qim": ALGO_ID_DWT_DCT_QIM,
    "echo": ALGO_ID_ECHO,
}

ALGO_ID_TO_NAME: Final[dict[int, str]] = {
    ALGO_ID_LSB: "lsb",
    ALGO_ID_DWT_DCT_QIM: "dwt_dct_qim",
    ALGO_ID_ECHO: "echo",
}

# Standard Synchronization Words
SYNC_WORD_LSB: Final[int] = 0xF9A9
SYNC_WORD_DWT_DCT_QIM: Final[int] = 0xF9A9
SYNC_WORD_ECHO: Final[int] = 0x596A

ALGO_DEFAULT_SYNC_WORDS: Final[dict[int, int]] = {
    ALGO_ID_LSB: SYNC_WORD_LSB,
    ALGO_ID_DWT_DCT_QIM: SYNC_WORD_DWT_DCT_QIM,
    ALGO_ID_ECHO: SYNC_WORD_ECHO,
}

# Application-Level Maximum Payload Size Ceiling: 16 MiB (16,777,216 bytes).
# Rationale:
# 1. CryptAudio-Web enforces a 50 MB maximum audio container upload limit.
# 2. In uncompressed PCM, 50 MB corresponds to ~12.5M samples (16-bit stereo)
#    providing ~1.56 MB of Channel 0 LSB capacity, or ~12.5M samples in 32-bit mono.
# 3. Setting a 16 MiB ceiling ensures that any realistic payload fitting inside
#    the 50 MB carrier is supported, while strictly preventing untrusted 32-bit
#    uint32 length fields from triggering unbounded memory allocations or denial-
#    of-service (OOM) attacks during envelope parsing.
MAX_PAYLOAD_SIZE_BYTES: Final[int] = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Envelope Data Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CSMAEnvelope:
    """Parsed representation of a CSMA v1 envelope header and payload."""

    sync_word: int
    magic: bytes
    algorithm_id: int
    algorithm_name: str
    version: int
    flags: int
    payload_length: int
    expected_crc: int
    actual_crc: int
    payload: bytes


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def resolve_algorithm_id(algo: Any) -> int:
    """
    Resolve an integer or string algorithm identifier to canonical integer ID.

    Rejects:
    - Boolean values (bool is a subclass of int in Python; True must not resolve to 1)
    - None
    - Unsupported numeric IDs
    - Unsupported string identifiers
    - Unsupported types (floats, lists, dicts)

    Raises:
        UnsupportedParameterError: For all invalid, unsupported, or incompatible values.
    """
    if isinstance(algo, bool) or algo is None:
        raise UnsupportedParameterError(
            f"Algorithm identifier cannot be {type(algo).__name__} (value: {algo!r})."
        )
    if isinstance(algo, int):
        if algo not in SUPPORTED_ALGORITHM_IDS:
            raise UnsupportedParameterError(
                f"Unsupported numeric algorithm ID: {algo}. "
                f"Supported IDs: {sorted(SUPPORTED_ALGORITHM_IDS)}."
            )
        return algo
    if isinstance(algo, str):
        normalized = algo.strip().lower()
        if normalized not in ALGO_NAME_TO_ID:
            raise UnsupportedParameterError(
                f"Unsupported algorithm name: '{algo}'. "
                f"Supported names: {sorted(ALGO_NAME_TO_ID.keys())}."
            )
        return ALGO_NAME_TO_ID[normalized]
    raise UnsupportedParameterError(
        f"Algorithm identifier must be int or str, got {type(algo).__name__}."
    )


def create_csma_envelope(
    payload: bytes,
    algorithm: int | str,
    flags: int = 0,
    sync_word: int | None = None,
) -> bytes:
    """
    Serialize an arbitrary binary payload into a 18-byte CSMA v1 envelope.

    Parameters:
        payload: Binary payload bytes to encapsulate.
        algorithm: Algorithm identifier (int or machine name like 'lsb').
        flags: 16-bit packed flags field (default 0).
        sync_word: Optional custom 16-bit sync word (defaults to algorithm canonical value).

    Returns:
        bytes: 18-byte header concatenated with payload bytes.

    Raises:
        UnsupportedParameterError: If algorithm, flags, or sync_word are invalid.
        SynchronizationError: If explicit sync_word does not match algorithm canonical value.
        TypeError: If payload is not bytes or bytearray.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes or bytearray.")

    algo_id = resolve_algorithm_id(algorithm)
    canonical_sync = ALGO_DEFAULT_SYNC_WORDS[algo_id]

    # Validate sync_word: None selects canonical sync word; explicit values must be int in 0..65535
    if sync_word is None:
        sync_word = canonical_sync
    else:
        if isinstance(sync_word, bool) or not isinstance(sync_word, int):
            raise UnsupportedParameterError(
                f"Synchronization word must be an integer, got {type(sync_word).__name__} (value: {sync_word!r})."
            )
        if not (0 <= sync_word <= 0xFFFF):
            raise UnsupportedParameterError(
                f"Synchronization word must be an unsigned 16-bit integer (0..65535), got {sync_word}."
            )
        if sync_word != canonical_sync:
            raise SynchronizationError(
                f"Synchronization word mismatch: supplied {sync_word:#06x} does not match canonical "
                f"synchronization word {canonical_sync:#06x} for algorithm {algo_id} ({ALGO_ID_TO_NAME[algo_id]})."
            )

    # Validate flags: must be integer, strictly non-boolean, in range 0..65535
    if flags is None or isinstance(flags, bool) or not isinstance(flags, int):
        raise UnsupportedParameterError(
            f"Flags must be an integer, got {type(flags).__name__} (value: {flags!r})."
        )
    if not (0 <= flags <= 0xFFFF):
        raise UnsupportedParameterError(
            f"Flags must be an unsigned 16-bit integer (0..65535), got {flags}."
        )

    if len(payload) > MAX_PAYLOAD_SIZE_BYTES:
        raise UnsupportedParameterError(
            f"Payload length ({len(payload)} bytes) exceeds maximum allowable limit "
            f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
        )

    payload_bytes = bytes(payload)
    payload_len = len(payload_bytes)
    crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF

    header = struct.pack(
        CSMA_HEADER_STRUCT,
        sync_word,
        CSMA_MAGIC,
        algo_id,
        CSMA_VERSION,
        flags,
        payload_len,
        crc,
    )

    return header + payload_bytes


def parse_csma_envelope(
    buffer: bytes,
    expected_algorithm: int | str | None = None,
    enforce_sync_word: bool = True,
) -> CSMAEnvelope:
    """
    Parse and validate a CSMA v1 envelope from raw bytes.

    Parameters:
        buffer: Byte sequence containing at least the 18-byte header and declared payload.
        expected_algorithm: Optional algorithm identifier to strictly match.
        enforce_sync_word: Whether to enforce that the sync word matches the algorithm.

    Returns:
        CSMAEnvelope: Parsed and CRC-verified envelope structure.

    Raises:
        HeaderNotFoundError: If buffer is smaller than 18 bytes or magic != b"CSMA".
        SynchronizationError: If synchronization word mismatches expected algorithm sequence.
        UnsupportedParameterError: If version or algorithm ID is invalid/unsupported.
        CorruptedPayloadError: If buffer is truncated or CRC32 checksum verification fails.
    """
    if not isinstance(buffer, (bytes, bytearray)):
        raise TypeError(f"Buffer must be bytes or bytearray, got {type(buffer).__name__}.")

    if len(buffer) < CSMA_HEADER_SIZE_BYTES:
        raise HeaderNotFoundError(
            f"Buffer too short for CSMA header: {len(buffer)} bytes supplied; "
            f"at least {CSMA_HEADER_SIZE_BYTES} bytes required."
        )

    # 1. Unpack header fields
    header_bytes = buffer[:CSMA_HEADER_SIZE_BYTES]
    sync_word, magic, algo_id, version, flags, payload_len, expected_crc = struct.unpack(
        CSMA_HEADER_STRUCT, header_bytes
    )

    # 2. Validate magic identifier
    if magic != CSMA_MAGIC:
        raise HeaderNotFoundError(
            f"Invalid stego magic: expected {CSMA_MAGIC!r}, found {magic!r}. "
            f"Data does not start with a CSMA v1 envelope."
        )

    # 3. Validate format version
    if version != CSMA_VERSION:
        raise UnsupportedParameterError(
            f"Unsupported CSMA format version: {version}. Expected version {CSMA_VERSION}."
        )

    # 4. Validate algorithm ID
    if algo_id not in SUPPORTED_ALGORITHM_IDS:
        raise UnsupportedParameterError(
            f"Unsupported algorithm ID in CSMA header: {algo_id}. "
            f"Supported IDs: {sorted(SUPPORTED_ALGORITHM_IDS)}."
        )
    algo_name = ALGO_ID_TO_NAME[algo_id]

    # 5. Check expected algorithm match if requested
    if expected_algorithm is not None:
        expected_id = resolve_algorithm_id(expected_algorithm)
        if algo_id != expected_id:
            raise UnsupportedParameterError(
                f"Algorithm mismatch: CSMA header declares algorithm {algo_id} ({algo_name}), "
                f"but caller expected {expected_id} ({ALGO_ID_TO_NAME[expected_id]})."
            )

    # 6. Validate synchronization word
    if enforce_sync_word:
        expected_sync = ALGO_DEFAULT_SYNC_WORDS[algo_id]
        if sync_word != expected_sync:
            raise SynchronizationError(
                f"Synchronization word mismatch: expected {expected_sync:#06x} for {algo_name}, "
                f"found {sync_word:#06x}."
            )

    # 7. Safe payload length and boundary validation (avoid memory allocation attacks)
    if payload_len > MAX_PAYLOAD_SIZE_BYTES:
        raise CorruptedPayloadError(
            f"Declared CSMA payload length ({payload_len} bytes) exceeds maximum allowable limit "
            f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
        )

    required_total_bytes = CSMA_HEADER_SIZE_BYTES + payload_len
    if len(buffer) < required_total_bytes:
        raise CorruptedPayloadError(
            f"Truncated CSMA payload: declared payload length is {payload_len} bytes "
            f"(requires {required_total_bytes} bytes total), but buffer contains only "
            f"{len(buffer)} bytes."
        )

    # 8. Extract payload slice without reallocation
    payload = bytes(buffer[CSMA_HEADER_SIZE_BYTES:required_total_bytes])

    # 9. Verify CRC32 checksum
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise CorruptedPayloadError(
            f"Payload CRC32 checksum mismatch: expected {expected_crc:#010x}, "
            f"computed {actual_crc:#010x}. Framing checksum failed (accidental corruption or payload alteration detected)."
        )

    return CSMAEnvelope(
        sync_word=sync_word,
        magic=magic,
        algorithm_id=algo_id,
        algorithm_name=algo_name,
        version=version,
        flags=flags,
        payload_length=payload_len,
        expected_crc=expected_crc,
        actual_crc=actual_crc,
        payload=payload,
    )
