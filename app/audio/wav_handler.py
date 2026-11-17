"""
app/audio/wav_handler.py
CryptAudio Web — Audio Processing Engine

Provides modular, secure, and robust handling of PCM WAV files:
- Inspecting audio metadata (bit depth, duration, sample rate, channels, file size)
- Validating WAV container format and uncompressed PCM parameters
- Reading raw audio frames preserving exact sample bytes (8-bit, 16-bit, 24-bit, 32-bit)
- Writing pristine PCM WAV files without resampling or modification
- Calculating theoretical raw LSB steganographic capacity
"""

from __future__ import annotations

import os
import wave
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

# ---------------------------------------------------------------------------
# Supported Format Constants
# ---------------------------------------------------------------------------

SUPPORTED_CHANNELS: Final[frozenset[int]] = frozenset({1, 2})  # Mono (1), Stereo (2)
SUPPORTED_SAMPLE_WIDTHS: Final[frozenset[int]] = frozenset({1, 2, 3, 4})  # 8, 16, 24, 32-bit
MIN_SAMPLE_RATE: Final[int] = 8_000
MAX_SAMPLE_RATE: Final[int] = 384_000


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class AudioError(Exception):
    """Base exception for all audio engine operations."""


class InvalidWavError(AudioError):
    """Raised when a file is not a valid WAV container or is structurally malformed."""


class UnsupportedAudioFormatError(AudioError):
    """Raised when an audio format is valid WAV but not supported (e.g. float, multi-channel, compression)."""


class AudioReadError(AudioError):
    """Raised when reading or accessing an audio file fails due to I/O or permission errors."""


class AudioWriteError(AudioError):
    """Raised when writing an audio file fails due to validation or filesystem errors."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WavData:
    """Raw audio frames and metadata read from a PCM WAV file."""

    channels: int
    sample_rate: int
    sample_width: int
    frame_count: int
    compression_type: str
    compression_name: str
    frames: bytes

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class WavInspection:
    """Human-readable and API-ready inspection metadata for an audio file."""

    filename: str
    file_size_bytes: int
    duration_seconds: float
    sample_rate: int
    channels: int
    sample_width: int
    bit_depth: int
    frame_count: int
    audio_format: str
    compression_info: str

    def to_dict(self) -> dict[str, Any]:
        """Convert inspection info to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class WavCapacity:
    """Theoretical raw LSB steganographic embedding capacity."""

    total_frames: int
    channels: int
    total_samples: int
    raw_capacity_bits: int
    raw_capacity_bytes: int

    def to_dict(self) -> dict[str, Any]:
        """Convert capacity info to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Validation Logic
# ---------------------------------------------------------------------------

def validate_wav(file_path: str | Path) -> WavData:
    """
    Validate that an audio file is a readable, uncompressed PCM WAV file
    with supported channels, sample rate, and sample width.

    Checks:
    1. File exists.
    2. File is readable.
    3. File is not empty.
    4. File has valid RIFF/WAVE header and structure.
    5. Audio is uncompressed PCM (NONE / not compressed).
    6. Channel count is supported (mono or stereo).
    7. Sample width is supported (1, 2, 3, or 4 bytes).
    8. Sample rate is within valid range.
    9. Audio frame data is non-empty.
    10. Metadata matches actual frame bytes length.

    Parameters:
        file_path: Path to the WAV file.

    Returns:
        WavData: Validated audio data and raw frames.

    Raises:
        AudioReadError: If the file is missing or unreadable.
        InvalidWavError: If the file is empty or not a valid WAV file.
        UnsupportedAudioFormatError: If the audio format, channels, or sample width are unsupported.
    """
    path = Path(file_path).resolve()

    # 1. File exists
    if not path.is_file():
        raise AudioReadError(f"Audio file does not exist: {path}")

    # 2. File is readable & not empty
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        raise AudioReadError(f"Cannot access audio file: {path}") from exc

    if file_size == 0:
        raise InvalidWavError(f"Audio file is empty (0 bytes): {path.name}")

    # Preliminary RIFF header sanity check (first 12 bytes: RIFF....WAVE)
    try:
        with path.open("rb") as f:
            header = f.read(12)
    except OSError as exc:
        raise AudioReadError(f"Cannot read audio file: {path}") from exc

    if len(header) < 12 or not header.startswith(b"RIFF") or header[8:12] != b"WAVE":
        raise InvalidWavError(f"File is not a valid RIFF/WAVE audio file: {path.name}")

    # Open with wave module
    try:
        with wave.open(str(path), "rb") as wav_file:
            channels = wav_file.getnchannels()
            sample_rate = wav_file.getframerate()
            sample_width = wav_file.getsampwidth()
            frame_count = wav_file.getnframes()
            comptype = wav_file.getcomptype()
            compname = wav_file.getcompname()
            frames = wav_file.readframes(frame_count)
    except wave.Error as exc:
        err_msg = str(exc).lower()
        if "unknown format" in err_msg or "format" in err_msg:
            raise UnsupportedAudioFormatError(
                f"Unsupported WAV audio format ({exc}): {path.name}. Only uncompressed integer PCM is supported."
            ) from exc
        raise InvalidWavError(f"Malformed or corrupted WAV file: {exc}") from exc
    except OSError as exc:
        raise AudioReadError(f"Error reading WAV file: {exc}") from exc

    # 4. Audio is uncompressed PCM
    if comptype != "NONE":
        raise UnsupportedAudioFormatError(
            f"Unsupported compression type '{comptype}' ({compname}). Only uncompressed PCM audio is supported."
        )

    # 5. Channel count is supported
    if channels not in SUPPORTED_CHANNELS:
        raise UnsupportedAudioFormatError(
            f"Unsupported channel count: {channels}. Supported channels: {sorted(SUPPORTED_CHANNELS)} (mono/stereo)."
        )

    # 6. Sample width is supported (8, 16, 24, 32-bit)
    if sample_width not in SUPPORTED_SAMPLE_WIDTHS:
        raise UnsupportedAudioFormatError(
            f"Unsupported sample width: {sample_width} bytes ({sample_width * 8}-bit). "
            f"Supported widths: 1 (8-bit), 2 (16-bit), 3 (24-bit), 4 (32-bit)."
        )

    # 7. Sample rate is valid
    if sample_rate < MIN_SAMPLE_RATE or sample_rate > MAX_SAMPLE_RATE:
        raise UnsupportedAudioFormatError(
            f"Invalid or unsupported sample rate: {sample_rate} Hz. Supported range: {MIN_SAMPLE_RATE} - {MAX_SAMPLE_RATE} Hz."
        )

    # 8. Frame count is positive and frames exist
    if frame_count <= 0 or len(frames) == 0:
        raise InvalidWavError(f"Audio file contains no audio frames: {path.name}")

    # 9. Consistency check: len(frames) == frame_count * channels * sample_width
    expected_bytes = frame_count * channels * sample_width
    if len(frames) != expected_bytes:
        raise InvalidWavError(
            f"WAV metadata mismatch: expected {expected_bytes} frame bytes for {frame_count} frames, "
            f"found {len(frames)} bytes."
        )

    return WavData(
        channels=channels,
        sample_rate=sample_rate,
        sample_width=sample_width,
        frame_count=frame_count,
        compression_type=comptype,
        compression_name=compname,
        frames=frames,
    )


# ---------------------------------------------------------------------------
# Reading Functionality
# ---------------------------------------------------------------------------

def read_wav(file_path: str | Path) -> WavData:
    """
    Read an uncompressed PCM WAV file, validate its structure, and return
    its metadata and raw frame bytes.

    Parameters:
        file_path: Path to the WAV file.

    Returns:
        WavData: Encapsulates channel count, sample rate, sample width,
                 frame count, compression details, and raw PCM frame bytes.
    """
    return validate_wav(file_path)


# ---------------------------------------------------------------------------
# Inspection Functionality
# ---------------------------------------------------------------------------

def inspect_wav(file_path: str | Path) -> WavInspection:
    """
    Inspect an audio file and return human-readable and structured metadata.

    Parameters:
        file_path: Path to the WAV file.

    Returns:
        WavInspection: Detailed metadata including filename, size, duration,
                       sample rate, channels, bit depth, and compression info.
    """
    path = Path(file_path).resolve()
    wav_data = validate_wav(path)
    file_size = path.stat().st_size
    duration = round(wav_data.frame_count / wav_data.sample_rate, 4)

    return WavInspection(
        filename=path.name,
        file_size_bytes=file_size,
        duration_seconds=duration,
        sample_rate=wav_data.sample_rate,
        channels=wav_data.channels,
        sample_width=wav_data.sample_width,
        bit_depth=wav_data.sample_width * 8,
        frame_count=wav_data.frame_count,
        audio_format="PCM",
        compression_info=f"{wav_data.compression_type} ({wav_data.compression_name})",
    )


# ---------------------------------------------------------------------------
# Writing Functionality
# ---------------------------------------------------------------------------

def write_wav(
    output_path: str | Path,
    frames: bytes,
    channels: int,
    sample_width: int,
    sample_rate: int,
) -> None:
    """
    Write raw PCM audio frames to a valid WAV file.

    Validates audio parameters and ensures raw frame bytes are preserved exactly
    without unintended resampling, normalization, or sample modification.

    Parameters:
        output_path: Target destination path.
        frames: Raw PCM frame bytes.
        channels: Channel count (1 for mono, 2 for stereo).
        sample_width: Bytes per sample (1 for 8-bit, 2 for 16-bit, 3 for 24-bit, 4 for 32-bit).
        sample_rate: Sampling frequency in Hz.

    Raises:
        AudioWriteError: If any parameter is invalid or if writing fails.
    """
    if not isinstance(frames, (bytes, bytearray)):
        raise AudioWriteError("Audio frames must be bytes or bytearray.")
    if len(frames) == 0:
        raise AudioWriteError("Cannot write empty audio frames.")

    if channels not in SUPPORTED_CHANNELS:
        raise AudioWriteError(
            f"Unsupported channel count: {channels}. Supported: {sorted(SUPPORTED_CHANNELS)} (mono/stereo)."
        )

    if sample_width not in SUPPORTED_SAMPLE_WIDTHS:
        raise AudioWriteError(
            f"Unsupported sample width: {sample_width} bytes ({sample_width * 8}-bit). "
            f"Supported: 1 (8-bit), 2 (16-bit), 3 (24-bit), 4 (32-bit)."
        )

    if sample_rate < MIN_SAMPLE_RATE or sample_rate > MAX_SAMPLE_RATE:
        raise AudioWriteError(
            f"Invalid sample rate: {sample_rate} Hz. Supported range: {MIN_SAMPLE_RATE} - {MAX_SAMPLE_RATE} Hz."
        )

    frame_size = channels * sample_width
    if len(frames) % frame_size != 0:
        raise AudioWriteError(
            f"Frame data length ({len(frames)} bytes) is not an exact multiple of "
            f"frame size ({frame_size} bytes = {channels} channels * {sample_width} bytes/sample)."
        )

    out_file = Path(output_path).resolve()

    # Check parent directory existence and writability
    try:
        out_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AudioWriteError(f"Cannot create destination directory {out_file.parent}: {exc}") from exc

    try:
        with wave.open(str(out_file), "wb") as wav_out:
            wav_out.setnchannels(channels)
            wav_out.setsampwidth(sample_width)
            wav_out.setframerate(sample_rate)
            wav_out.writeframes(bytes(frames))
    except (wave.Error, OSError) as exc:
        raise AudioWriteError(f"Failed to write WAV file to {out_file}: {exc}") from exc

    # Verification: Ensure the written file can be reopened and validated
    try:
        validate_wav(out_file)
    except AudioError as exc:
        raise AudioWriteError(f"Verification of written WAV file failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Capacity Calculation
# ---------------------------------------------------------------------------

def calculate_capacity(file_path: str | Path) -> WavCapacity:
    """
    Calculate the theoretical raw LSB steganographic embedding capacity of a WAV file.

    Assumes 1 payload bit can be embedded into the least significant bit (LSB)
    of each individual audio sample across all channels.

    Calculation:
        Total samples = Frame count * Channel count
        Raw capacity in bits = Total samples
        Raw capacity in bytes = Total samples // 8

    NOTE: This represents theoretical maximum raw LSB capacity. Practical message
    capacity will be lower due to framing overhead, magic identifiers, and crypto payloads.

    Parameters:
        file_path: Path to the WAV file.

    Returns:
        WavCapacity: Struct containing total_frames, channels, total_samples,
                    raw_capacity_bits, and raw_capacity_bytes.
    """
    wav_data = validate_wav(file_path)
    total_samples = wav_data.frame_count * wav_data.channels
    raw_bits = total_samples
    raw_bytes = total_samples // 8

    return WavCapacity(
        total_frames=wav_data.frame_count,
        channels=wav_data.channels,
        total_samples=total_samples,
        raw_capacity_bits=raw_bits,
        raw_capacity_bytes=raw_bytes,
    )
