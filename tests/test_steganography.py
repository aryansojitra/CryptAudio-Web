"""
tests/test_steganography.py
CryptAudio Web — LSB Steganography Engine Test Suite (Phase 5)

Tests bit conversion, payload framing, LSB embedding across 8/16/24/32-bit PCM
and mono/stereo channels, extraction, error detection, and audio preservation.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_steganography.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import read_wav, write_wav
from app.steganography.lsb_engine import (
    HEADER_SIZE_BITS,
    HEADER_SIZE_BYTES,
    STEGO_MAGIC,
    EmbeddingResult,
    InsufficientCapacityError,
    InvalidPayloadError,
    InvalidStegoFileError,
    PayloadCorruptionError,
    UnsupportedVersionError,
    bits_to_bytes,
    bytes_to_bits,
    create_framed_payload,
    embed_payload,
    extract_payload,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def create_carrier_wav(
    file_path: Path,
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 2000,
) -> Path:
    """Helper to create a standard valid carrier PCM WAV file."""
    frame_size = channels * sample_width
    frames = bytes((i * 3 + 7) % 256 for i in range(num_frames * frame_size))
    write_wav(
        output_path=file_path,
        frames=frames,
        channels=channels,
        sample_width=sample_width,
        sample_rate=sample_rate,
    )
    return file_path


# ---------------------------------------------------------------------------
# 1-6. Bit Conversion Tests
# ---------------------------------------------------------------------------

def test_bytes_to_bits() -> None:
    """1. Converts bytes to bits accurately."""
    data = b"\x05"  # 00000101
    bits = bytes_to_bits(data)
    assert bits == [0, 0, 0, 0, 0, 1, 0, 1]


def test_bits_to_bytes() -> None:
    """2. Converts bits to bytes accurately."""
    bits = [0, 0, 0, 0, 0, 1, 0, 1]
    assert bits_to_bytes(bits) == b"\x05"


def test_msb_first_ordering() -> None:
    """3. Verifies strictly Most Significant Bit (MSB) first ordering."""
    # 0x80 = 10000000; 0x01 = 00000001
    bits = bytes_to_bits(b"\x80\x01")
    assert bits[:8] == [1, 0, 0, 0, 0, 0, 0, 0]
    assert bits[8:] == [0, 0, 0, 0, 0, 0, 0, 1]
    assert bits_to_bytes(bits) == b"\x80\x01"


def test_empty_byte_input() -> None:
    """4. Handles empty byte input safely."""
    assert bytes_to_bits(b"") == []
    assert bits_to_bytes([]) == b""


def test_invalid_bit_values() -> None:
    """5. Rejects bit lists containing values other than 0 or 1."""
    with pytest.raises(ValueError, match="Invalid bit value"):
        bits_to_bytes([0, 1, 2, 0, 1, 0, 1, 0])

    with pytest.raises(ValueError, match="Invalid bit value"):
        bits_to_bytes([0, 1, -1, 0, 1, 0, 1, 0])


def test_incomplete_byte_rejection() -> None:
    """6. Rejects bit lists whose length is not a multiple of 8."""
    with pytest.raises(ValueError, match="not a multiple of 8"):
        bits_to_bytes([1, 0, 1])  # 3 bits


# ---------------------------------------------------------------------------
# 7-20. Embedding Tests
# ---------------------------------------------------------------------------

def test_embed_small_payload(tmp_path: Path) -> None:
    """7. Embed a small binary payload and verify metadata."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "stego.wav"
    payload = b"Secret123"

    result = embed_payload(carrier, stego, payload)
    assert isinstance(result, EmbeddingResult)
    assert result.success is True
    assert result.payload_size_bytes == len(payload)
    assert result.framed_size_bytes == HEADER_SIZE_BYTES + len(payload)
    assert result.required_bits == (HEADER_SIZE_BYTES + len(payload)) * 8
    assert result.available_bits == 1000
    assert result.utilization_percent > 0
    assert Path(result.output_path).is_file()


def test_embed_large_payload(tmp_path: Path) -> None:
    """8. Embed a large binary payload requiring substantial capacity."""
    # 5,000 frames mono = 5,000 bits capacity
    # 500 bytes payload + 13 bytes header = 513 bytes = 4,104 bits (< 5,000 bits)
    carrier = create_carrier_wav(tmp_path / "large_carrier.wav", num_frames=5000)
    stego = tmp_path / "large_stego.wav"
    payload = os.urandom(500)

    result = embed_payload(carrier, stego, payload)
    assert result.success is True
    extracted = extract_payload(stego)
    assert extracted == payload


def test_embed_payload_containing_zeros(tmp_path: Path) -> None:
    """9. Embed payload consisting entirely of null bytes (\\x00)."""
    carrier = create_carrier_wav(tmp_path / "zero_carrier.wav", num_frames=1000)
    stego = tmp_path / "zero_stego.wav"
    payload = b"\x00" * 32

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_all_possible_byte_values(tmp_path: Path) -> None:
    """10. Embed a payload containing all 256 byte values (0x00 to 0xFF)."""
    carrier = create_carrier_wav(tmp_path / "all_bytes_carrier.wav", num_frames=3000)
    stego = tmp_path / "all_bytes_stego.wav"
    payload = bytes(range(256))

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_mono_audio(tmp_path: Path) -> None:
    """11. Embed payload in mono audio."""
    carrier = create_carrier_wav(tmp_path / "mono.wav", channels=1, num_frames=1000)
    stego = tmp_path / "mono_stego.wav"
    payload = b"MonoPayload"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_stereo_audio(tmp_path: Path) -> None:
    """12. Embed payload in stereo audio across interleaved channels."""
    carrier = create_carrier_wav(tmp_path / "stereo.wav", channels=2, num_frames=1000)
    stego = tmp_path / "stereo_stego.wav"
    payload = b"StereoPayloadAcrossChannels"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_8bit_pcm(tmp_path: Path) -> None:
    """13. Embed payload in 8-bit unsigned PCM audio."""
    carrier = create_carrier_wav(tmp_path / "8bit.wav", sample_width=1, num_frames=1000)
    stego = tmp_path / "8bit_stego.wav"
    payload = b"8BitPCMData"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_16bit_pcm(tmp_path: Path) -> None:
    """14. Embed payload in 16-bit signed PCM audio."""
    carrier = create_carrier_wav(tmp_path / "16bit.wav", sample_width=2, num_frames=1000)
    stego = tmp_path / "16bit_stego.wav"
    payload = b"16BitPCMData"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_24bit_pcm(tmp_path: Path) -> None:
    """15. Embed payload in 24-bit PCM audio (3 bytes per sample)."""
    carrier = create_carrier_wav(tmp_path / "24bit.wav", sample_width=3, num_frames=1000)
    stego = tmp_path / "24bit_stego.wav"
    payload = b"24BitPCMDataHighRes"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_embed_32bit_pcm(tmp_path: Path) -> None:
    """16. Embed payload in 32-bit integer PCM audio (4 bytes per sample)."""
    carrier = create_carrier_wav(tmp_path / "32bit.wav", sample_width=4, num_frames=1000)
    stego = tmp_path / "32bit_stego.wav"
    payload = b"32BitIntegerPCMData"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_reject_insufficient_capacity(tmp_path: Path) -> None:
    """17. Rejects embedding when carrier audio has insufficient samples."""
    # Carrier with only 100 samples (header alone requires 104 samples)
    tiny_carrier = create_carrier_wav(tmp_path / "tiny.wav", num_frames=100)
    stego = tmp_path / "fail.wav"

    with pytest.raises(InsufficientCapacityError, match="Insufficient capacity"):
        embed_payload(tiny_carrier, stego, b"Short")


def test_reject_invalid_input_wav(tmp_path: Path) -> None:
    """18. Rejects non-WAV input file."""
    fake_wav = tmp_path / "fake.wav"
    fake_wav.write_bytes(b"NOT A WAV FILE")
    stego = tmp_path / "stego.wav"

    with pytest.raises(Exception):
        embed_payload(fake_wav, stego, b"Payload")


def test_reject_empty_or_invalid_payload(tmp_path: Path) -> None:
    """19. Rejects empty payload or non-bytes payload."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "stego.wav"

    with pytest.raises(InvalidPayloadError, match="cannot be empty"):
        embed_payload(carrier, stego, b"")

    with pytest.raises(InvalidPayloadError, match="must be bytes"):
        embed_payload(carrier, stego, "string_instead_of_bytes")  # type: ignore


def test_reject_identical_input_and_output_paths(tmp_path: Path) -> None:
    """20. Rejects input and output paths that resolve to the same file."""
    carrier = create_carrier_wav(tmp_path / "same.wav", num_frames=1000)

    with pytest.raises(ValueError, match="Input and output paths cannot be identical"):
        embed_payload(carrier, carrier, b"Payload")


# ---------------------------------------------------------------------------
# 21-31. Extraction & Tamper / Corruption Tests
# ---------------------------------------------------------------------------

def test_extract_valid_payload(tmp_path: Path) -> None:
    """21. Extract a valid payload and verify byte-for-byte exact match."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "stego.wav"
    payload = b"ExactPayloadBytes_12345"

    embed_payload(carrier, stego, payload)
    extracted = extract_payload(stego)
    assert extracted == payload


def test_extract_8bit_wav(tmp_path: Path) -> None:
    """22. Extract payload correctly from 8-bit audio."""
    carrier = create_carrier_wav(tmp_path / "c8.wav", sample_width=1, num_frames=1000)
    stego = tmp_path / "s8.wav"
    payload = b"EightBitPayload"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_extract_16bit_wav(tmp_path: Path) -> None:
    """23. Extract payload correctly from 16-bit audio."""
    carrier = create_carrier_wav(tmp_path / "c16.wav", sample_width=2, num_frames=1000)
    stego = tmp_path / "s16.wav"
    payload = b"SixteenBitPayload"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_extract_24bit_wav(tmp_path: Path) -> None:
    """24. Extract payload correctly from 24-bit audio."""
    carrier = create_carrier_wav(tmp_path / "c24.wav", sample_width=3, num_frames=1000)
    stego = tmp_path / "s24.wav"
    payload = b"TwentyFourBitPayload"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_extract_32bit_wav(tmp_path: Path) -> None:
    """25. Extract payload correctly from 32-bit audio."""
    carrier = create_carrier_wav(tmp_path / "c32.wav", sample_width=4, num_frames=1000)
    stego = tmp_path / "s32.wav"
    payload = b"ThirtyTwoBitPayload"

    embed_payload(carrier, stego, payload)
    assert extract_payload(stego) == payload


def test_detect_invalid_magic_identifier(tmp_path: Path) -> None:
    """26. Rejects audio file without valid stego magic header."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "corrupted_magic.wav"
    embed_payload(carrier, stego, b"SecretData")

    # Corrupt one bit in the magic header area (first 32 bits = samples 0..31)
    data = read_wav(stego)
    corrupted_frames = bytearray(data.frames)
    corrupted_frames[0] ^= 1  # flip LSB of sample 0
    write_wav(stego, bytes(corrupted_frames), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(InvalidStegoFileError, match="Invalid magic identifier"):
        extract_payload(stego)


def test_detect_unsupported_version(tmp_path: Path) -> None:
    """27. Rejects payload with unsupported format version."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "bad_ver.wav"
    embed_payload(carrier, stego, b"SecretData")

    # The version byte is at header offset 4 -> bits 32..39 -> samples 32..39
    # Version 1 is 00000001; flip sample 38 (second to last bit of version byte) to make it 3
    data = read_wav(stego)
    corrupted = bytearray(data.frames)
    corrupted[38 * data.sample_width] ^= 1
    write_wav(stego, bytes(corrupted), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(UnsupportedVersionError, match="Unsupported stego format version"):
        extract_payload(stego)


def test_detect_truncated_header(tmp_path: Path) -> None:
    """28. Rejects audio shorter than the 104-bit header."""
    # Create audio with only 50 frames
    short_audio = create_carrier_wav(tmp_path / "short.wav", num_frames=50)

    with pytest.raises(InvalidStegoFileError, match="at least 104 samples are required"):
        extract_payload(short_audio)


def test_detect_truncated_payload(tmp_path: Path) -> None:
    """29. Rejects audio where declared payload length exceeds available samples."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=500)
    stego = tmp_path / "truncated_stego.wav"
    embed_payload(carrier, stego, b"ValidData")

    # Tamper with length field in header (bytes 5..8 -> bits 40..71 -> samples 40..71)
    # Set sample 40 (MSB of length) to 1 -> declares an enormous length
    data = read_wav(stego)
    corrupted = bytearray(data.frames)
    corrupted[40 * data.sample_width] |= 1  # sets bit 31 of length to 1 (huge number)
    write_wav(stego, bytes(corrupted), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(InvalidStegoFileError, match="Declared payload length"):
        extract_payload(stego)


def test_detect_crc32_mismatch(tmp_path: Path) -> None:
    """30. Detects bit flips in the payload body via CRC32 verification."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", num_frames=1000)
    stego = tmp_path / "corrupted_payload.wav"
    embed_payload(carrier, stego, b"SensitiveIntegrityData")

    # Flip one payload bit (sample index >= 104)
    data = read_wav(stego)
    corrupted = bytearray(data.frames)
    corrupted[110 * data.sample_width] ^= 1  # flip LSB of sample 110 (payload bit)
    write_wav(stego, bytes(corrupted), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(PayloadCorruptionError, match="CRC32 checksum mismatch"):
        extract_payload(stego)


def test_reject_wav_without_embedded_payload(tmp_path: Path) -> None:
    """31. Attempting to extract from plain carrier WAV raises InvalidStegoFileError."""
    plain_carrier = create_carrier_wav(tmp_path / "plain.wav", num_frames=1000)

    with pytest.raises(InvalidStegoFileError, match="Invalid magic identifier"):
        extract_payload(plain_carrier)


# ---------------------------------------------------------------------------
# 32-38. Audio Preservation Tests
# ---------------------------------------------------------------------------

def test_audio_properties_unchanged(tmp_path: Path) -> None:
    """32-35. Sample rate, channels, sample width, and frame count are identical after embedding."""
    carrier = create_carrier_wav(
        tmp_path / "orig.wav", channels=2, sample_width=3, sample_rate=48000, num_frames=1500
    )
    stego = tmp_path / "stego.wav"

    orig_data = read_wav(carrier)
    embed_payload(carrier, stego, b"CheckPreservation")
    stego_data = read_wav(stego)

    assert stego_data.sample_rate == orig_data.sample_rate       # 32
    assert stego_data.channels == orig_data.channels             # 33
    assert stego_data.sample_width == orig_data.sample_width     # 34
    assert stego_data.frame_count == orig_data.frame_count       # 35


def test_only_sample_lsbs_are_modified(tmp_path: Path) -> None:
    """36-37. Verifies that only bit 0 of each sample can change; all higher bits are identical."""
    carrier = create_carrier_wav(
        tmp_path / "orig_bits.wav", channels=2, sample_width=2, sample_rate=44100, num_frames=1000
    )
    stego = tmp_path / "stego_bits.wav"
    payload = b"PreserveHighBits"

    orig_data = read_wav(carrier)
    embed_payload(carrier, stego, payload)
    stego_data = read_wav(stego)

    orig_frames = orig_data.frames
    stego_frames = stego_data.frames
    sample_width = orig_data.sample_width
    total_samples = orig_data.frame_count * orig_data.channels

    required_bits = (HEADER_SIZE_BYTES + len(payload)) * 8

    # For each sample in the modified region:
    for i in range(required_bits):
        offset = i * sample_width
        orig_byte = orig_frames[offset]
        stego_byte = stego_frames[offset]

        # 36. Only LSB can differ: higher 7 bits must be identical
        assert (orig_byte & 0xFE) == (stego_byte & 0xFE)

        # 37. Higher bytes of multi-byte samples (bytes 1..sample_width-1) must be byte-for-byte identical
        for b_idx in range(1, sample_width):
            assert orig_frames[offset + b_idx] == stego_frames[offset + b_idx]

    # For any samples beyond the embedded region: 100% byte-for-byte identical
    for i in range(required_bits, total_samples):
        offset = i * sample_width
        for b_idx in range(sample_width):
            assert orig_frames[offset + b_idx] == stego_frames[offset + b_idx]


def test_original_input_file_remains_unchanged(tmp_path: Path) -> None:
    """38. Embedding operation never modifies the input carrier file."""
    carrier = create_carrier_wav(tmp_path / "readonly_carrier.wav", num_frames=1000)
    stego = tmp_path / "out.wav"
    orig_bytes = carrier.read_bytes()
    orig_mtime = carrier.stat().st_mtime_ns

    embed_payload(carrier, stego, b"CarrierSafetyTest")

    assert carrier.read_bytes() == orig_bytes
    assert carrier.stat().st_mtime_ns == orig_mtime
