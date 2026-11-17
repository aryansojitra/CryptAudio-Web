"""
tests/test_audio.py
CryptAudio Web — Audio Processing Engine Test Suite (Phase 4)

Tests reading, inspecting, validating, capacity calculation, and writing
of uncompressed integer PCM WAV files (8-bit, 16-bit, 24-bit, 32-bit; mono, stereo).

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_audio.py -v
"""

from __future__ import annotations

import os
import struct
import sys
import wave
from pathlib import Path

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import (
    AudioReadError,
    AudioWriteError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    calculate_capacity,
    inspect_wav,
    read_wav,
    validate_wav,
    write_wav,
)


# ---------------------------------------------------------------------------
# Test Helpers / Fixtures
# ---------------------------------------------------------------------------

def create_pcm_wav(
    file_path: Path,
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 1000,
    seed_pattern: bytes | None = None,
) -> bytes:
    """Helper to generate a valid PCM WAV file and return raw frame bytes."""
    frame_size = channels * sample_width
    if seed_pattern:
        frames = seed_pattern * (num_frames * frame_size // len(seed_pattern))
    else:
        # Create a deterministic byte pattern
        frames = bytes((i % 256) for i in range(num_frames * frame_size))

    with wave.open(str(file_path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(frames)

    return frames


# ---------------------------------------------------------------------------
# 1-4. Sample Width Tests (8-bit, 16-bit, 24-bit, 32-bit)
# ---------------------------------------------------------------------------

def test_read_valid_8bit_pcm(tmp_path: Path) -> None:
    """1. Read valid 8-bit unsigned integer PCM WAV file."""
    wav_path = tmp_path / "test_8bit.wav"
    raw_frames = create_pcm_wav(wav_path, channels=1, sample_width=1, sample_rate=22050, num_frames=500)

    data = read_wav(wav_path)
    assert data.sample_width == 1
    assert data.channels == 1
    assert data.sample_rate == 22050
    assert data.frame_count == 500
    assert data.frames == raw_frames


def test_read_valid_16bit_pcm(tmp_path: Path) -> None:
    """2. Read valid 16-bit signed integer PCM WAV file."""
    wav_path = tmp_path / "test_16bit.wav"
    raw_frames = create_pcm_wav(wav_path, channels=2, sample_width=2, sample_rate=44100, num_frames=1000)

    data = read_wav(wav_path)
    assert data.sample_width == 2
    assert data.channels == 2
    assert data.sample_rate == 44100
    assert data.frame_count == 1000
    assert data.frames == raw_frames


def test_read_valid_24bit_pcm(tmp_path: Path) -> None:
    """3. Read valid 24-bit integer PCM WAV file (3 bytes per sample)."""
    wav_path = tmp_path / "test_24bit.wav"
    raw_frames = create_pcm_wav(wav_path, channels=1, sample_width=3, sample_rate=48000, num_frames=600)

    data = read_wav(wav_path)
    assert data.sample_width == 3
    assert data.channels == 1
    assert data.sample_rate == 48000
    assert data.frame_count == 600
    assert data.frames == raw_frames
    assert len(data.frames) == 600 * 1 * 3


def test_read_valid_32bit_integer_pcm(tmp_path: Path) -> None:
    """4. Read valid 32-bit integer PCM WAV file (4 bytes per sample)."""
    wav_path = tmp_path / "test_32bit.wav"
    raw_frames = create_pcm_wav(wav_path, channels=2, sample_width=4, sample_rate=96000, num_frames=400)

    data = read_wav(wav_path)
    assert data.sample_width == 4
    assert data.channels == 2
    assert data.sample_rate == 96000
    assert data.frame_count == 400
    assert data.frames == raw_frames
    assert len(data.frames) == 400 * 2 * 4


# ---------------------------------------------------------------------------
# 5-6. Channel Configuration Tests (Mono, Stereo)
# ---------------------------------------------------------------------------

def test_read_mono_wav(tmp_path: Path) -> None:
    """5. Read single-channel mono WAV."""
    wav_path = tmp_path / "mono.wav"
    create_pcm_wav(wav_path, channels=1, sample_width=2, sample_rate=44100, num_frames=800)

    data = read_wav(wav_path)
    assert data.channels == 1
    assert len(data.frames) == 800 * 1 * 2


def test_read_stereo_wav(tmp_path: Path) -> None:
    """6. Read dual-channel stereo WAV."""
    wav_path = tmp_path / "stereo.wav"
    create_pcm_wav(wav_path, channels=2, sample_width=2, sample_rate=44100, num_frames=800)

    data = read_wav(wav_path)
    assert data.channels == 2
    assert len(data.frames) == 800 * 2 * 2


# ---------------------------------------------------------------------------
# 7-11. Metadata Inspection & Calculations
# ---------------------------------------------------------------------------

def test_inspect_wav_metadata(tmp_path: Path) -> None:
    """7. Inspect WAV metadata returns structured, complete object."""
    wav_path = tmp_path / "inspect.wav"
    create_pcm_wav(wav_path, channels=2, sample_width=2, sample_rate=44100, num_frames=44100)

    info = inspect_wav(wav_path)
    assert info.filename == "inspect.wav"
    assert info.file_size_bytes > 0
    assert info.channels == 2
    assert info.sample_rate == 44100
    assert info.audio_format == "PCM"
    assert "NONE" in info.compression_info


def test_calculate_duration_correctly(tmp_path: Path) -> None:
    """8. Confirm duration calculation (frames / sample_rate)."""
    wav_path = tmp_path / "duration.wav"
    # 88,200 frames at 44,100 Hz = exactly 2.0 seconds
    create_pcm_wav(wav_path, channels=1, sample_width=2, sample_rate=44100, num_frames=88200)

    info = inspect_wav(wav_path)
    assert info.duration_seconds == 2.0


def test_calculate_bit_depth_correctly(tmp_path: Path) -> None:
    """9. Confirm bit depth calculation (sample_width * 8)."""
    widths_to_bits = {1: 8, 2: 16, 3: 24, 4: 32}
    for width, expected_bits in widths_to_bits.items():
        wav_path = tmp_path / f"bits_{width}.wav"
        create_pcm_wav(wav_path, channels=1, sample_width=width, sample_rate=44100, num_frames=100)
        info = inspect_wav(wav_path)
        assert info.bit_depth == expected_bits


def test_calculate_frame_count_correctly(tmp_path: Path) -> None:
    """10. Confirm frame count corresponds exactly to audio frames."""
    wav_path = tmp_path / "frames.wav"
    create_pcm_wav(wav_path, channels=2, sample_width=3, sample_rate=48000, num_frames=12345)

    data = read_wav(wav_path)
    assert data.frame_count == 12345
    info = inspect_wav(wav_path)
    assert info.frame_count == 12345


def test_calculate_capacity_mono(tmp_path: Path) -> None:
    """11. Calculate raw LSB capacity for mono audio."""
    wav_path = tmp_path / "cap_mono.wav"
    # 8000 frames * 1 channel = 8000 samples = 8000 bits = 1000 bytes
    create_pcm_wav(wav_path, channels=1, sample_width=2, sample_rate=44100, num_frames=8000)

    cap = calculate_capacity(wav_path)
    assert cap.total_frames == 8000
    assert cap.channels == 1
    assert cap.total_samples == 8000
    assert cap.raw_capacity_bits == 8000
    assert cap.raw_capacity_bytes == 1000


# ---------------------------------------------------------------------------
# 12-14. Writing & Readback Round-trip
# ---------------------------------------------------------------------------

def test_write_valid_wav(tmp_path: Path) -> None:
    """12. Write a valid WAV file to disk."""
    out_path = tmp_path / "output.wav"
    frames = b"\x00\x10\x20\x30" * 200  # 800 bytes
    write_wav(out_path, frames=frames, channels=2, sample_width=2, sample_rate=44100)
    assert out_path.is_file()
    assert out_path.stat().st_size > len(frames)  # Contains WAV header


def test_read_back_written_wav(tmp_path: Path) -> None:
    """13. Read back a written WAV file and verify metadata."""
    out_path = tmp_path / "roundtrip.wav"
    frames = b"\xaa\xbb\xcc\xdd" * 500  # 2000 bytes
    write_wav(out_path, frames=frames, channels=1, sample_width=2, sample_rate=48000)

    read_data = read_wav(out_path)
    assert read_data.channels == 1
    assert read_data.sample_width == 2
    assert read_data.sample_rate == 48000
    assert read_data.frame_count == 1000


def test_pcm_frame_bytes_preserved_exactly(tmp_path: Path) -> None:
    """14. Ensure written PCM frame bytes match the original input byte-for-byte."""
    original_frames = bytes([i % 256 for i in range(4800)])  # 4800 arbitrary bytes
    out_path = tmp_path / "exact_bytes.wav"
    write_wav(out_path, frames=original_frames, channels=2, sample_width=3, sample_rate=48000)

    read_data = read_wav(out_path)
    assert read_data.frames == original_frames


# ---------------------------------------------------------------------------
# 15-21. Validation & Error Handling
# ---------------------------------------------------------------------------

def test_reject_missing_file(tmp_path: Path) -> None:
    """15. Rejects non-existent file path with AudioReadError."""
    missing = tmp_path / "does_not_exist.wav"
    with pytest.raises(AudioReadError, match="does not exist"):
        validate_wav(missing)


def test_reject_invalid_wav_content(tmp_path: Path) -> None:
    """16. Rejects corrupt or non-WAV files (e.g. text file or random bytes) with InvalidWavError."""
    corrupt = tmp_path / "corrupt.wav"
    corrupt.write_bytes(b"NOT_A_WAV_FILE_HEADER_TEXT_123456789")

    with pytest.raises(InvalidWavError, match="valid RIFF/WAVE"):
        validate_wav(corrupt)


def test_reject_unsupported_channel_counts(tmp_path: Path) -> None:
    """17. Rejects unsupported channels (e.g. 3, 5.1, or 0 channels)."""
    # Test writing invalid channel count
    with pytest.raises(AudioWriteError, match="Unsupported channel count"):
        write_wav(tmp_path / "bad_ch.wav", frames=b"\x00" * 12, channels=3, sample_width=2, sample_rate=44100)


def test_reject_unsupported_sample_widths(tmp_path: Path) -> None:
    """18. Rejects unsupported sample widths (e.g. 5 bytes or 0 bytes)."""
    with pytest.raises(AudioWriteError, match="Unsupported sample width"):
        write_wav(tmp_path / "bad_width.wav", frames=b"\x00" * 10, channels=1, sample_width=5, sample_rate=44100)


def test_reject_empty_or_malformed_frame_data(tmp_path: Path) -> None:
    """19. Rejects empty frame bytes and misaligned frame lengths."""
    # Empty frames
    with pytest.raises(AudioWriteError, match="empty audio frames"):
        write_wav(tmp_path / "empty.wav", frames=b"", channels=1, sample_width=2, sample_rate=44100)

    # Frame length not a multiple of frame size (2 channels * 2 bytes = 4 bytes/frame; passing 7 bytes)
    with pytest.raises(AudioWriteError, match="not an exact multiple"):
        write_wav(tmp_path / "misaligned.wav", frames=b"\x00" * 7, channels=2, sample_width=2, sample_rate=44100)


def test_reject_invalid_sample_rates(tmp_path: Path) -> None:
    """20. Rejects invalid sample rates (e.g. 0 Hz or excessively high frequencies)."""
    with pytest.raises(AudioWriteError, match="Invalid sample rate"):
        write_wav(tmp_path / "bad_rate.wav", frames=b"\x00" * 4, channels=1, sample_width=2, sample_rate=0)

    with pytest.raises(AudioWriteError, match="Invalid sample rate"):
        write_wav(tmp_path / "bad_rate2.wav", frames=b"\x00" * 4, channels=1, sample_width=2, sample_rate=500_000)


def test_handle_output_path_errors() -> None:
    """21. Gracefully handles uncreatable or invalid target paths."""
    # Attempting to write to an invalid path on Windows (e.g., using reserved characters)
    invalid_path = "Z:\\invalid_nonexistent_drive\\path\\output.wav"
    with pytest.raises(AudioWriteError, match="Cannot create destination directory|Failed to write WAV file"):
        write_wav(invalid_path, frames=b"\x00" * 4, channels=1, sample_width=2, sample_rate=44100)


# ---------------------------------------------------------------------------
# 22-24. Edge Cases & Specific Requirements
# ---------------------------------------------------------------------------

def test_original_input_file_not_modified(tmp_path: Path) -> None:
    """22. Verifies reading and inspecting never modifies the input file."""
    wav_path = tmp_path / "read_only.wav"
    raw_frames = create_pcm_wav(wav_path, channels=1, sample_width=2, sample_rate=44100, num_frames=500)
    original_mtime = wav_path.stat().st_mtime_ns
    original_size = wav_path.stat().st_size

    # Perform multiple read and inspect operations
    _ = read_wav(wav_path)
    _ = inspect_wav(wav_path)
    _ = calculate_capacity(wav_path)
    _ = validate_wav(wav_path)

    assert wav_path.stat().st_size == original_size
    assert wav_path.stat().st_mtime_ns == original_mtime
    # Re-verify byte-for-byte file content
    with wave.open(str(wav_path), "rb") as w:
        assert w.readframes(500) == raw_frames


def test_stereo_capacity_accounts_for_both_channels(tmp_path: Path) -> None:
    """23. Confirms stereo capacity doubles the capacity of mono with identical frames."""
    mono_path = tmp_path / "mono_cap.wav"
    stereo_path = tmp_path / "stereo_cap.wav"
    frames_count = 1000

    create_pcm_wav(mono_path, channels=1, sample_width=2, sample_rate=44100, num_frames=frames_count)
    create_pcm_wav(stereo_path, channels=2, sample_width=2, sample_rate=44100, num_frames=frames_count)

    mono_cap = calculate_capacity(mono_path)
    stereo_cap = calculate_capacity(stereo_path)

    assert stereo_cap.total_samples == mono_cap.total_samples * 2
    assert stereo_cap.raw_capacity_bits == mono_cap.raw_capacity_bits * 2
    assert stereo_cap.raw_capacity_bytes == mono_cap.raw_capacity_bytes * 2


def test_24bit_audio_handled_as_three_bytes_per_sample(tmp_path: Path) -> None:
    """24. Confirms 24-bit audio strictly allocates 3 bytes per sample."""
    wav_path = tmp_path / "audio_24bit.wav"
    num_frames = 200
    channels = 2
    sample_width = 3

    # Total frames = 200, channels = 2 -> 400 samples -> 1200 bytes
    create_pcm_wav(wav_path, channels=channels, sample_width=sample_width, sample_rate=48000, num_frames=num_frames)

    data = read_wav(wav_path)
    assert data.sample_width == 3
    assert len(data.frames) == num_frames * channels * 3
    assert len(data.frames) == 1200


def test_reject_floating_point_wav(tmp_path: Path) -> None:
    """Rejects IEEE 32-bit floating point WAV format."""
    float_wav = tmp_path / "float.wav"
    fmt_chunk = struct.pack("<4sIHHIIHH", b"fmt ", 16, 3, 1, 44100, 44100 * 4, 4, 32)
    data = b"\x00\x00\x00\x00" * 10
    data_chunk = struct.pack("<4sI", b"data", len(data)) + data
    riff = struct.pack("<4sI4s", b"RIFF", 4 + len(fmt_chunk) + len(data_chunk), b"WAVE") + fmt_chunk + data_chunk
    float_wav.write_bytes(riff)

    with pytest.raises(UnsupportedAudioFormatError, match="Unsupported WAV audio format"):
        validate_wav(float_wav)


def test_reject_empty_wav_file(tmp_path: Path) -> None:
    """Rejects 0-byte WAV files."""
    empty_file = tmp_path / "empty_file.wav"
    empty_file.write_bytes(b"")

    with pytest.raises(InvalidWavError, match="Audio file is empty"):
        validate_wav(empty_file)
