"""
app/evaluation/audio_quality.py
CryptAudio Web — Audio Quality Evaluation Engine

Provides numerical distortion analysis between original carrier WAV audio
and stego WAV audio using NumPy:
- Sample decoding for 8-bit, 16-bit, 24-bit, and 32-bit integer PCM
- Mean Squared Error (MSE)
- Signal-to-Noise Ratio (SNR) in dB
- Peak Signal-to-Noise Ratio (PSNR) in dB
- Pearson Correlation Coefficient
- Distortion classification and sample difference statistics
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np

from app.audio.wav_handler import AudioError, read_wav

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum absolute representable amplitude for each PCM sample width (bytes):
# - 8-bit unsigned centered around zero: 128.0 (range [-128, 127])
# - 16-bit signed integer: 32768.0 (range [-32768, 32767])
# - 24-bit signed integer: 8388608.0 (2^23, range [-8388608, 8388607])
# - 32-bit signed integer: 2147483648.0 (2^31, range [-2147483648, 2147483647])
PEAK_AMPLITUDES: Final[dict[int, float]] = {
    1: 128.0,
    2: 32768.0,
    3: 8388608.0,
    4: 2147483648.0,
}


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------

class AudioEvaluationError(Exception):
    """Base exception for all audio evaluation operations."""


class IncompatibleAudioError(AudioEvaluationError):
    """Raised when the two audio files cannot be compared due to mismatched parameters."""


class UnsupportedEvaluationFormatError(AudioEvaluationError):
    """Raised when an audio sample width or format is not supported for numerical evaluation."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AudioComparisonReport:
    """Comprehensive numerical distortion and quality analysis report."""

    mse: float
    snr_db: float
    psnr_db: float
    correlation: float | None
    quality_assessment: str
    sample_rate: int
    channels: int
    bit_depth: int
    total_samples: int
    modified_samples: int
    max_absolute_difference: float
    average_absolute_difference: float

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Audio Sample Decoding
# ---------------------------------------------------------------------------

def decode_pcm_samples(raw_bytes: bytes, sample_width: int) -> np.ndarray:
    """
    Decode raw PCM audio frame bytes into a 1D float64 NumPy array of samples.

    Correctly handles:
    - 8-bit: Unsigned integer centered around zero by subtracting 128.0.
    - 16-bit: Signed little-endian 16-bit integers.
    - 24-bit: Signed 3-byte little-endian integers with proper sign extension.
    - 32-bit: Signed little-endian 32-bit integers.

    Parameters:
        raw_bytes: Raw PCM bytes from audio frames.
        sample_width: Bytes per sample (1, 2, 3, or 4).

    Returns:
        np.ndarray: 1D array of float64 sample amplitudes.

    Raises:
        UnsupportedEvaluationFormatError: If sample width is not in {1, 2, 3, 4}.
    """
    if sample_width == 1:
        # 8-bit unsigned PCM -> center around zero [-128, 127]
        samples_u8 = np.frombuffer(raw_bytes, dtype=np.uint8)
        return samples_u8.astype(np.float64) - 128.0

    elif sample_width == 2:
        # 16-bit signed PCM (little-endian)
        samples_i16 = np.frombuffer(raw_bytes, dtype="<i2")
        return samples_i16.astype(np.float64)

    elif sample_width == 3:
        # 24-bit signed PCM (3 bytes little-endian per sample)
        # Vectorized sign extension:
        # Reinterpret raw bytes as (N, 3) uint8 array:
        raw = np.frombuffer(raw_bytes, dtype=np.uint8).reshape(-1, 3)
        b0 = raw[:, 0].astype(np.int32)
        b1 = raw[:, 1].astype(np.int32)
        b2 = raw[:, 2].astype(np.int32)
        val = b0 | (b1 << 8) | (b2 << 16)
        # Sign extension: if bit 23 is set (val >= 0x800000 / 8388608), subtract 0x1000000 (16777216)
        val = np.where(val >= 0x800000, val - 0x1000000, val)
        return val.astype(np.float64)

    elif sample_width == 4:
        # 32-bit signed integer PCM (little-endian)
        samples_i32 = np.frombuffer(raw_bytes, dtype="<i4")
        return samples_i32.astype(np.float64)

    else:
        raise UnsupportedEvaluationFormatError(
            f"Unsupported sample width: {sample_width} bytes ({sample_width * 8}-bit). "
            "Supported widths: 1 (8-bit), 2 (16-bit), 3 (24-bit), 4 (32-bit)."
        )


# ---------------------------------------------------------------------------
# Numerical Distortion Metrics
# ---------------------------------------------------------------------------

def calculate_mse(original: np.ndarray, stego: np.ndarray) -> float:
    """
    Calculate the Mean Squared Error (MSE) between original and stego signals.

    Formula:
        MSE = (1 / N) * sum((x[i] - y[i])^2)

    Parameters:
        original: 1D float64 array of original audio samples.
        stego: 1D float64 array of stego audio samples.

    Returns:
        float: Non-negative MSE value. Exactly 0.0 for identical signals.
    """
    diff = original.astype(np.float64) - stego.astype(np.float64)
    mse = float(np.mean(diff ** 2))
    return max(0.0, mse)


def calculate_snr(original: np.ndarray, stego: np.ndarray) -> float:
    """
    Calculate the Signal-to-Noise Ratio (SNR) in decibels (dB).

    Formula:
        SNR = 10 * log10(Signal Power / Noise Power)
        Signal Power = sum(x[i]^2)
        Noise Power  = sum((x[i] - y[i])^2)

    Edge cases:
        - If Noise Power is 0.0: returns +inf (zero distortion).
        - If Signal Power is 0.0 and Noise Power > 0.0: returns -inf.
        - If both Signal Power and Noise Power are 0.0: returns +inf.

    Parameters:
        original: 1D float64 array of original audio samples.
        stego: 1D float64 array of stego audio samples.

    Returns:
        float: SNR in dB (or +inf / -inf).
    """
    x = original.astype(np.float64)
    y = stego.astype(np.float64)

    signal_power = float(np.sum(x ** 2))
    noise_power = float(np.sum((x - y) ** 2))

    if noise_power == 0.0:
        return float("inf")

    if signal_power == 0.0:
        return float("-inf")

    ratio = signal_power / noise_power
    if ratio <= 0.0:
        return float("-inf")

    return float(10.0 * math.log10(ratio))


def calculate_psnr(original: np.ndarray, stego: np.ndarray, peak_value: float) -> float:
    """
    Calculate Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).

    Formula:
        PSNR = 10 * log10(peak_value^2 / MSE)

    Edge cases:
        - If MSE is 0.0: returns +inf (zero distortion).

    Parameters:
        original: 1D float64 array of original audio samples.
        stego: 1D float64 array of stego audio samples.
        peak_value: Maximum absolute representable amplitude for the bit depth.

    Returns:
        float: PSNR in dB (or +inf).
    """
    mse = calculate_mse(original, stego)
    if mse == 0.0:
        return float("inf")

    return float(10.0 * math.log10((peak_value ** 2) / mse))


def calculate_correlation(original: np.ndarray, stego: np.ndarray) -> float | None:
    """
    Calculate the Pearson correlation coefficient between original and stego signals.

    Formula:
        r = sum((x - mean_x) * (y - mean_y)) / (sqrt(sum((x - mean_x)^2)) * sqrt(sum((y - mean_y)^2)))

    Special cases:
        - If both signals are constant and identical: returns 1.0.
        - If one or both signals have zero variance and are not identical: returns None (mathematically undefined).
        - Clamped to the valid range [-1.0, 1.0] to prevent floating-point anomalies.

    Parameters:
        original: 1D float64 array of original audio samples.
        stego: 1D float64 array of stego audio samples.

    Returns:
        float | None: Pearson r in [-1.0, 1.0], or None if variance is zero.
    """
    x = original.astype(np.float64)
    y = stego.astype(np.float64)

    x_diff = x - np.mean(x)
    y_diff = y - np.mean(y)

    ss_x = float(np.sum(x_diff ** 2))
    ss_y = float(np.sum(y_diff ** 2))

    # Check for zero-variance (constant signals)
    if ss_x == 0.0 and ss_y == 0.0:
        if np.array_equal(x, y):
            return 1.0
        return None

    if ss_x == 0.0 or ss_y == 0.0:
        return None

    covariance = float(np.sum(x_diff * y_diff))
    denominator = math.sqrt(ss_x * ss_y)

    if denominator == 0.0:
        return None

    r = covariance / denominator
    # Clamp to valid [-1.0, 1.0] range
    return float(max(-1.0, min(1.0, r)))


def classify_quality(psnr_db: float) -> str:
    """
    Classify audio quality based on PSNR (dB) project evaluation thresholds.

    Thresholds:
        - PSNR == inf: "Excellent (Zero Distortion)"
        - PSNR >= 50 dB: "Excellent"
        - 40 dB <= PSNR < 50 dB: "Very Good"
        - 30 dB <= PSNR < 40 dB: "Good"
        - 20 dB <= PSNR < 30 dB: "Moderate"
        - PSNR < 20 dB: "Poor"

    Parameters:
        psnr_db: Calculated PSNR in decibels.

    Returns:
        str: Descriptive quality assessment category.
    """
    if math.isinf(psnr_db) and psnr_db > 0:
        return "Excellent (Zero Distortion)"
    elif psnr_db >= 50.0:
        return "Excellent"
    elif psnr_db >= 40.0:
        return "Very Good"
    elif psnr_db >= 30.0:
        return "Good"
    elif psnr_db >= 20.0:
        return "Moderate"
    else:
        return "Poor"


# ---------------------------------------------------------------------------
# Main Audio Comparison Function
# ---------------------------------------------------------------------------

def compare_audio(
    original_wav: str | Path,
    stego_wav: str | Path,
) -> AudioComparisonReport:
    """
    Perform a complete numerical audio-quality evaluation comparing
    the original carrier WAV audio with the stego WAV audio.

    Execution Flow:
    1. Read and validate both WAV files using Phase 4 audio engine.
    2. Enforce strict compatibility (sample rate, channels, width, frame count).
    3. Decode raw PCM frame bytes into float64 sample arrays.
    4. Compute MSE, SNR, PSNR, and Pearson Correlation.
    5. Perform sample difference analysis (modified count, max diff, avg diff).
    6. Classify perceived distortion quality based on PSNR.
    7. Return AudioComparisonReport.

    Parameters:
        original_wav: Path to original carrier WAV file.
        stego_wav: Path to stego WAV file.

    Returns:
        AudioComparisonReport: Comprehensive evaluation metrics and quality assessment.

    Raises:
        AudioEvaluationError: If reading, validating, or compatibility checks fail.
    """
    orig_path = Path(original_wav).resolve()
    stego_path = Path(stego_wav).resolve()

    if not orig_path.is_file():
        raise AudioEvaluationError(f"Original audio file does not exist: {orig_path}")
    if not stego_path.is_file():
        raise AudioEvaluationError(f"Stego audio file does not exist: {stego_path}")

    # Step 1: Read and validate WAV containers
    try:
        orig_data = read_wav(orig_path)
    except AudioError as exc:
        raise AudioEvaluationError(f"Failed to read original audio: {exc}") from exc

    try:
        stego_data = read_wav(stego_path)
    except AudioError as exc:
        raise AudioEvaluationError(f"Failed to read stego audio: {exc}") from exc

    # Step 2: Compatibility verification
    if orig_data.sample_rate != stego_data.sample_rate:
        raise IncompatibleAudioError(
            f"Sample rate mismatch: original={orig_data.sample_rate} Hz, stego={stego_data.sample_rate} Hz."
        )

    if orig_data.channels != stego_data.channels:
        raise IncompatibleAudioError(
            f"Channel count mismatch: original={orig_data.channels}, stego={stego_data.channels}."
        )

    if orig_data.sample_width != stego_data.sample_width:
        raise IncompatibleAudioError(
            f"Sample width mismatch: original={orig_data.sample_width} bytes, "
            f"stego={stego_data.sample_width} bytes."
        )

    if orig_data.frame_count != stego_data.frame_count:
        raise IncompatibleAudioError(
            f"Frame count mismatch: original={orig_data.frame_count}, stego={stego_data.frame_count}."
        )

    # Step 3: Decode raw PCM samples
    x = decode_pcm_samples(orig_data.frames, orig_data.sample_width)
    y = decode_pcm_samples(stego_data.frames, stego_data.sample_width)

    if len(x) != len(y):
        raise IncompatibleAudioError(
            f"Decoded sample count mismatch: original has {len(x)} samples, stego has {len(y)} samples."
        )

    # Step 4: Calculate numerical metrics
    peak_value = PEAK_AMPLITUDES[orig_data.sample_width]

    mse = calculate_mse(x, y)
    snr_db = calculate_snr(x, y)
    psnr_db = calculate_psnr(x, y, peak_value)
    correlation = calculate_correlation(x, y)
    assessment = classify_quality(psnr_db)

    # Step 5: Sample difference analysis
    diff = np.abs(x - y)
    modified_mask = diff > 0.0
    modified_samples = int(np.sum(modified_mask))
    max_diff = float(np.max(diff)) if len(diff) > 0 else 0.0
    avg_diff = float(np.mean(diff)) if len(diff) > 0 else 0.0

    return AudioComparisonReport(
        mse=mse,
        snr_db=snr_db,
        psnr_db=psnr_db,
        correlation=correlation,
        quality_assessment=assessment,
        sample_rate=orig_data.sample_rate,
        channels=orig_data.channels,
        bit_depth=orig_data.sample_width * 8,
        total_samples=len(x),
        modified_samples=modified_samples,
        max_absolute_difference=max_diff,
        average_absolute_difference=avg_diff,
    )
