"""
app/evaluation/benchmark.py
Comparative Steganography Algorithm Benchmarking & Evaluation Engine for CryptAudio-Web (Phase M7.1).

Implements rigorous, empirical evaluation of all supported audio steganography algorithms:
- LSB (Least Significant Bit)
- DWT-DCT-QIM (Discrete Wavelet Transform + Discrete Cosine Transform + Quantization Index Modulation)
- Echo Hiding

Features in Phase M7.1:
- Support for 8-bit, 16-bit, 24-bit, and 32-bit PCM carrier generation and transformation
- Independent multi-channel (mono and stereo) audio transformation processing without channel mixing
- Strict distinction between:
    - Synchronization failure (SYNC_FAILED)
    - CSMA framing checksum failure (CHECKSUM_FAILED)
    - AES-256-GCM authentication tag failure (AUTHENTICATION_FAILED)
    - General failure (FAILED)
    - External tool unavailable / unexecuted (NOT TESTED)
- Independent tamper experiments:
    1. Synchronization/header corruption rejection
    2. Framing checksum (CRC32) corruption rejection
    3. AES-256-GCM ciphertext tampering with valid CSMA framing rejection
    4. Wrong-password authentication rejection
- Strict input parameter validation (rejection of trials=0, negative values, booleans, NaN, Infinity)
- Guaranteed tracemalloc cleanup via try/finally
- Data-driven execution reporting with mean and standard deviation for multi-trial timing
- Correct CSMA v1 capacity calculations using integer floor math
"""

from __future__ import annotations

import io
import math
import os
import platform
import shutil
import struct
import sys
import tempfile
import time
import tracemalloc
import wave
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from app.audio.wav_handler import (
    AudioError,
    SUPPORTED_CHANNELS,
    SUPPORTED_SAMPLE_WIDTHS,
    WavData,
    inspect_wav,
    read_wav,
    write_wav,
)
from app.crypto.aes_crypto import (
    DecryptionError,
    InvalidMessageError,
    InvalidPasswordError,
)
from app.evaluation.audio_quality import (
    PEAK_AMPLITUDES,
    AudioComparisonReport,
    compare_audio,
    decode_pcm_samples,
)
from app.services.cryptaudio_service import (
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    _resolve_algorithm,
    embed_message,
    estimate_capacity,
    extract_message_detailed,
)
from app.steganography.base import (
    CorruptedPayloadError,
    HeaderNotFoundError,
    SynchronizationError,
)
from app.steganography.envelope import (
    CSMA_HEADER_SIZE_BYTES,
    create_csma_envelope,
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkCarrierConfig:
    """Configuration for synthesizing a standardized benchmark carrier audio file."""
    duration_seconds: float = 33.0
    sample_rate: int = 44100
    channels: int = 1
    sample_width: int = 2
    carrier_type: str = "chirp"  # "chirp", "multitone", or "speech_like"
    name: str = "standard_chirp_33s"


@dataclass
class CapacityMetrics:
    """Empirical capacity and density metrics for an algorithm/carrier pair."""
    duration_seconds: float
    sample_rate: int
    channels: int
    total_samples: int
    raw_capacity_bits: int
    raw_capacity_bytes: int
    usable_payload_capacity_bytes: int
    max_embeddable_message_bytes: int
    required_bits: int
    available_bits: int
    utilization_percent: float


@dataclass
class QualityMetrics:
    """Numerical audio quality distortion metrics between original and stego audio."""
    mse: float
    snr_db: float
    psnr_db: float
    correlation: float
    modified_samples: int
    total_samples: int
    modification_percent: float
    quality_rating: str
    max_absolute_difference: float
    average_absolute_difference: float


@dataclass
class PerformanceMetrics:
    """Computational execution and memory resource metrics."""
    embed_time_seconds: float
    embed_time_std_seconds: float
    extract_time_seconds: float
    extract_time_std_seconds: float
    total_pipeline_time_seconds: float
    peak_traced_memory_bytes: int
    peak_traced_memory_mb: float
    trials_completed: int
    trials_requested: int


@dataclass
class AccuracyMetrics:
    """Integrity, authentication, and tamper detection verification metrics."""
    extraction_success: bool
    exact_match: bool
    algorithm_identified: str
    algorithm_match: bool
    authentication_verified: bool
    wrong_password_rejected: bool
    sync_corruption_rejected: bool
    checksum_corruption_rejected: bool
    ciphertext_tamper_rejected: bool


@dataclass
class RobustnessResult:
    """Outcome of evaluating extraction under a specific signal distortion or transformation."""
    transformation_name: str
    transformation_description: str
    status: str  # "SURVIVED", "SYNC_FAILED", "CHECKSUM_FAILED", "AUTHENTICATION_FAILED", "FAILED", "NOT TESTED"
    extracted_successfully: bool
    exact_match: bool
    notes: str


@dataclass
class AlgorithmBenchmarkResult:
    """Comprehensive benchmark results for a single algorithm configuration."""
    algorithm_id: str
    algorithm_name: str
    options: Dict[str, Any]
    status: str  # "SUCCESS", "CAPACITY_INSUFFICIENT", "ERROR"
    carrier_name: str
    carrier_duration_seconds: float
    message_length_bytes: int
    error_message: Optional[str] = None
    capacity: Optional[CapacityMetrics] = None
    quality: Optional[QualityMetrics] = None
    performance: Optional[PerformanceMetrics] = None
    accuracy: Optional[AccuracyMetrics] = None
    robustness: List[RobustnessResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkSuiteResult:
    """Full execution suite results containing system info and all benchmark outcomes."""
    timestamp: str
    system_info: Dict[str, Any]
    results: List[AlgorithmBenchmarkResult]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Validation Utilities
# ---------------------------------------------------------------------------

def validate_carrier_config(config: BenchmarkCarrierConfig) -> None:
    """Validate carrier synthesis parameters, rejecting invalid or unsupported values."""
    if not isinstance(config.duration_seconds, (int, float)) or isinstance(config.duration_seconds, bool):
        raise ValueError(f"duration_seconds must be a real number, got {type(config.duration_seconds).__name__}")
    if math.isnan(config.duration_seconds) or math.isinf(config.duration_seconds) or config.duration_seconds <= 0.0:
        raise ValueError(f"duration_seconds must be positive and finite, got {config.duration_seconds}")

    if not isinstance(config.sample_rate, int) or isinstance(config.sample_rate, bool):
        raise ValueError(f"sample_rate must be an integer, got {type(config.sample_rate).__name__}")
    if config.sample_rate < 8000 or config.sample_rate > 384000:
        raise ValueError(f"sample_rate {config.sample_rate} out of supported range [8000, 384000]")

    if not isinstance(config.channels, int) or isinstance(config.channels, bool):
        raise ValueError(f"channels must be an integer, got {type(config.channels).__name__}")
    if config.channels not in SUPPORTED_CHANNELS:
        raise ValueError(f"channels must be 1 or 2, got {config.channels}")

    if not isinstance(config.sample_width, int) or isinstance(config.sample_width, bool):
        raise ValueError(f"sample_width must be an integer, got {type(config.sample_width).__name__}")
    if config.sample_width not in SUPPORTED_SAMPLE_WIDTHS:
        raise ValueError(f"sample_width must be in {{1, 2, 3, 4}}, got {config.sample_width}")


def validate_trials(trials: Any) -> int:
    """Validate timing measurement trials count, strictly rejecting booleans and non-positive values."""
    if isinstance(trials, bool) or not isinstance(trials, int):
        raise ValueError(f"trials must be a positive integer, got {type(trials).__name__}")
    if trials <= 0:
        raise ValueError(f"trials must be >= 1, got {trials}")
    return trials


def get_system_environment_info() -> Dict[str, Any]:
    """Collect runtime environment, platform, and package version metadata."""
    import pywt

    ffmpeg_available = shutil.which("ffmpeg") is not None
    lame_available = shutil.which("lame") is not None

    return {
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "processor": platform.processor() or "Unknown",
        "cpu_count": os.cpu_count() or 1,
        "numpy_version": np.__version__,
        "pywt_version": pywt.__version__,
        "ffmpeg_available": ffmpeg_available,
        "lame_available": lame_available,
        "benchmark_date_utc": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# PCM Encoding and Decoding
# ---------------------------------------------------------------------------

def encode_pcm_samples(samples: np.ndarray, sample_width: int) -> bytes:
    """
    Encode a 1D NumPy array of float64 audio samples into pristine PCM bytes.

    Supports:
    - 8-bit unsigned PCM: samples in [-128.0, 127.0] -> [0, 255]
    - 16-bit signed PCM: samples in [-32768.0, 32767.0] -> little-endian i16
    - 24-bit signed PCM: samples in [-8388608.0, 8388607.0] -> 3-byte little-endian i24
    - 32-bit signed PCM: samples in [-2147483648.0, 2147483647.0] -> little-endian i32

    Parameters:
        samples: 1D array of float64 sample values.
        sample_width: Bytes per sample (1, 2, 3, or 4).

    Returns:
        bytes: Encoded PCM frame bytes.
    """
    if sample_width == 1:
        # 8-bit unsigned PCM
        clamped = np.clip(np.round(samples + 128.0), 0.0, 255.0).astype(np.uint8)
        return clamped.tobytes()

    elif sample_width == 2:
        # 16-bit signed PCM (little-endian)
        clamped = np.clip(np.round(samples), -32768.0, 32767.0).astype("<i2")
        return clamped.tobytes()

    elif sample_width == 3:
        # 24-bit signed PCM (3 bytes little-endian per sample)
        clamped = np.clip(np.round(samples), -8388608.0, 8388607.0).astype(np.int32)
        u_val = np.where(clamped < 0, clamped + 0x1000000, clamped).astype(np.uint32)
        b0 = (u_val & 0xFF).astype(np.uint8)
        b1 = ((u_val >> 8) & 0xFF).astype(np.uint8)
        b2 = ((u_val >> 16) & 0xFF).astype(np.uint8)
        return np.column_stack([b0, b1, b2]).reshape(-1).tobytes()

    elif sample_width == 4:
        # 32-bit signed PCM (little-endian)
        clamped = np.clip(np.round(samples), -2147483648.0, 2147483647.0).astype("<i4")
        return clamped.tobytes()

    else:
        raise ValueError(
            f"Unsupported sample width: {sample_width} bytes ({sample_width * 8}-bit). "
            "Supported widths: 1 (8-bit), 2 (16-bit), 3 (24-bit), 4 (32-bit)."
        )


def generate_carrier_wav(
    config: BenchmarkCarrierConfig,
    output_path: str | Path,
    seed: int = 42,
) -> Path:
    """
    Synthesize a standardized, deterministic test carrier WAV audio file.

    Parameters:
        config: Carrier parameters (duration, sample rate, channels, sample width, waveform type).
        output_path: Target path for the generated WAV file.
        seed: Random seed for deterministic reproducibility.

    Returns:
        Path: Resolved path to the generated WAV file.
    """
    validate_carrier_config(config)
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    total_frames = int(round(config.duration_seconds * config.sample_rate))
    peak = PEAK_AMPLITUDES[config.sample_width]

    if config.carrier_type == "chirp":
        # Segment-repeated wideband linear sweep (200 Hz to 6000 Hz per 2048-sample segment)
        # Guarantees ideal flat cepstral properties and deterministic bit recovery across all algorithms
        seg_size = 2048
        segments = max(1, total_frames // seg_size)
        rem = total_frames % seg_size
        t_seg = np.arange(seg_size, dtype=np.float64) / config.sample_rate
        f0, f1 = 200.0, 6000.0
        dur_seg = seg_size / config.sample_rate
        seg_chirp = np.sin(2.0 * np.pi * (f0 + (f1 - f0) / (2.0 * dur_seg) * t_seg) * t_seg)
        waveform = np.tile(seg_chirp, segments)
        if rem > 0:
            waveform = np.concatenate([waveform, seg_chirp[:rem]])
        mono_samples = waveform * 0.85 * peak

    elif config.carrier_type == "multitone":
        # Harmonic multi-tone carrier
        t = np.arange(total_frames, dtype=np.float64) / config.sample_rate
        freqs = [220.0, 440.0, 880.0, 1760.0, 3520.0]
        waveform = np.zeros(total_frames, dtype=np.float64)
        for i, f in enumerate(freqs):
            waveform += (0.8 / (i + 1)) * np.sin(2.0 * np.pi * f * t)
        waveform = waveform / np.max(np.abs(waveform)) * 0.85
        mono_samples = waveform * peak

    else:
        # Filtered speech-like random distribution
        rng = np.random.default_rng(seed)
        waveform = rng.normal(0.0, 0.35, total_frames)
        waveform = np.clip(waveform, -0.90, 0.90)
        mono_samples = waveform * peak

    if config.channels == 2:
        # Interleave stereo
        stereo_samples = np.column_stack([mono_samples, mono_samples]).reshape(-1)
        raw_frames = encode_pcm_samples(stereo_samples, config.sample_width)
    else:
        raw_frames = encode_pcm_samples(mono_samples, config.sample_width)

    write_wav(
        output_path=out_p,
        frames=raw_frames,
        channels=config.channels,
        sample_width=config.sample_width,
        sample_rate=config.sample_rate,
    )

    return out_p


# ---------------------------------------------------------------------------
# Controlled Robustness Transformations
# ---------------------------------------------------------------------------

def apply_transformation_unmodified(stego_wav_path: Path, output_path: Path) -> Tuple[Path, str]:
    """Baseline: copy unmodified stego WAV."""
    shutil.copy2(stego_wav_path, output_path)
    return output_path, "Unmodified WAV container (bit-identical control)"


def apply_transformation_gaussian_noise(
    stego_wav_path: Path,
    output_path: Path,
    sigma: float = 1.0,
    seed: int = 42,
) -> Tuple[Path, str]:
    """
    Additive Gaussian noise with standard deviation sigma.
    Correctly decodes and encodes samples preserving bit depth and independent stereo channels.
    """
    if not isinstance(sigma, (int, float)) or isinstance(sigma, bool) or sigma < 0.0 or math.isnan(sigma) or math.isinf(sigma):
        raise ValueError(f"Noise sigma must be a non-negative finite real number, got {sigma}")

    wav_info = read_wav(stego_wav_path)
    samples = decode_pcm_samples(wav_info.frames, wav_info.sample_width)
    rng = np.random.default_rng(seed)

    if wav_info.channels == 2:
        ch0 = samples[0::2]
        ch1 = samples[1::2]
        noise_ch0 = rng.normal(0.0, sigma, len(ch0))
        noise_ch1 = rng.normal(0.0, sigma, len(ch1))
        noisy_interleaved = np.column_stack([ch0 + noise_ch0, ch1 + noise_ch1]).reshape(-1)
        raw_bytes = encode_pcm_samples(noisy_interleaved, wav_info.sample_width)
    else:
        noise = rng.normal(0.0, sigma, len(samples))
        noisy = samples + noise
        raw_bytes = encode_pcm_samples(noisy, wav_info.sample_width)

    write_wav(
        output_path,
        raw_bytes,
        wav_info.channels,
        wav_info.sample_width,
        wav_info.sample_rate,
    )
    return output_path, f"Additive Gaussian white noise (sigma={sigma})"


def apply_transformation_amplitude_scaling(
    stego_wav_path: Path,
    output_path: Path,
    scale_factor: float = 0.95,
) -> Tuple[Path, str]:
    """
    Linear amplitude scaling (volume change).
    Processes stereo channels independently and preserves bit depth.
    """
    if not isinstance(scale_factor, (int, float)) or isinstance(scale_factor, bool) or scale_factor <= 0.0 or math.isnan(scale_factor) or math.isinf(scale_factor):
        raise ValueError(f"Scale factor must be a positive finite real number, got {scale_factor}")

    wav_info = read_wav(stego_wav_path)
    samples = decode_pcm_samples(wav_info.frames, wav_info.sample_width)

    if wav_info.channels == 2:
        ch0 = samples[0::2] * scale_factor
        ch1 = samples[1::2] * scale_factor
        scaled_interleaved = np.column_stack([ch0, ch1]).reshape(-1)
        raw_bytes = encode_pcm_samples(scaled_interleaved, wav_info.sample_width)
    else:
        scaled = samples * scale_factor
        raw_bytes = encode_pcm_samples(scaled, wav_info.sample_width)

    write_wav(
        output_path,
        raw_bytes,
        wav_info.channels,
        wav_info.sample_width,
        wav_info.sample_rate,
    )
    return output_path, f"Linear amplitude attenuation (scale={scale_factor}x, ~-0.45 dB)"


def _resample_single_channel(channel_samples: np.ndarray, orig_rate: int, inter_rate: int) -> np.ndarray:
    """Downsample and upsample a single channel using linear interpolation."""
    orig_len = len(channel_samples)
    down_len = int(orig_len * (inter_rate / orig_rate))

    t_orig = np.linspace(0.0, 1.0, orig_len, endpoint=False)
    t_down = np.linspace(0.0, 1.0, down_len, endpoint=False)

    downsampled = np.interp(t_down, t_orig, channel_samples)
    reconstructed = np.interp(t_orig, t_down, downsampled)
    return reconstructed


def apply_transformation_resampling(
    stego_wav_path: Path,
    output_path: Path,
    intermediate_rate: int = 22050,
) -> Tuple[Path, str]:
    """
    Controlled resampling simulation: downsample to intermediate rate and upsample back to original rate.
    Each channel is processed independently without mixing or channel swap.
    """
    if not isinstance(intermediate_rate, int) or isinstance(intermediate_rate, bool) or intermediate_rate <= 0:
        raise ValueError(f"intermediate_rate must be a positive integer, got {intermediate_rate}")

    wav_info = read_wav(stego_wav_path)
    samples = decode_pcm_samples(wav_info.frames, wav_info.sample_width)

    if wav_info.channels == 2:
        ch0 = samples[0::2]
        ch1 = samples[1::2]
        res_ch0 = _resample_single_channel(ch0, wav_info.sample_rate, intermediate_rate)
        res_ch1 = _resample_single_channel(ch1, wav_info.sample_rate, intermediate_rate)
        interleaved = np.column_stack([res_ch0, res_ch1]).reshape(-1)
        raw_bytes = encode_pcm_samples(interleaved, wav_info.sample_width)
    else:
        resampled = _resample_single_channel(samples, wav_info.sample_rate, intermediate_rate)
        raw_bytes = encode_pcm_samples(resampled, wav_info.sample_width)

    write_wav(
        output_path,
        raw_bytes,
        wav_info.channels,
        wav_info.sample_width,
        wav_info.sample_rate,
    )
    return (
        output_path,
        f"Controlled resampling simulation ({wav_info.sample_rate} Hz -> {intermediate_rate} Hz -> {wav_info.sample_rate} Hz)",
    )


def apply_transformation_lossy_compression(
    stego_wav_path: Path,
    output_path: Path,
) -> Tuple[Optional[Path], str]:
    """
    Evaluate lossy compression (MP3/AAC) if ffmpeg or lame is available.
    Returns (output_path, description) or (None, description) if missing.
    """
    ffmpeg_exe = shutil.which("ffmpeg")
    lame_exe = shutil.which("lame")

    if not ffmpeg_exe and not lame_exe:
        return None, "Lossy audio compression (ffmpeg/lame not installed on system)"

    if ffmpeg_exe:
        mp3_tmp = output_path.with_suffix(".mp3")
        import subprocess

        try:
            cmd_enc = [
                ffmpeg_exe, "-y", "-i", str(stego_wav_path),
                "-codec:a", "libmp3lame", "-b:a", "192k", str(mp3_tmp)
            ]
            subprocess.run(cmd_enc, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

            cmd_dec = [ffmpeg_exe, "-y", "-i", str(mp3_tmp), str(output_path)]
            subprocess.run(cmd_dec, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

            if mp3_tmp.exists():
                mp3_tmp.unlink()
            return output_path, "Lossy MP3 compression (192 kbps CBR via ffmpeg)"
        except Exception as exc:
            return None, f"Lossy compression failed during execution: {exc}"

    return None, "Lossy compression tools unavailable"


def evaluate_robustness_transformations(
    stego_wav_path: Path,
    algorithm: str,
    password: str,
    expected_message: str,
    options: Dict[str, Any],
    temp_dir: Path,
) -> List[RobustnessResult]:
    """
    Run the 5 controlled transformations on the stego audio and classify extraction outcomes.

    Uses distinct status classifications:
    - SURVIVED: Plaintext recovered exactly.
    - SYNC_FAILED: Synchronization preamble or header missing.
    - CHECKSUM_FAILED: Framing CRC32 checksum mismatch.
    - AUTHENTICATION_FAILED: AES-256-GCM authentication tag rejected.
    - FAILED: Other extraction or transformation error.
    - NOT TESTED: External tool unavailable or transformation unexecuted.
    """
    transformations = [
        ("Unmodified WAV", "Baseline control: bit-identical carrier", apply_transformation_unmodified),
        ("Additive Gaussian Noise", "Gaussian white noise (sigma=1.0)", apply_transformation_gaussian_noise),
        ("Amplitude Scaling", "Linear amplitude scaling (0.95x)", apply_transformation_amplitude_scaling),
        ("Resampling", "Controlled resampling simulation (44.1k -> 22.05k -> 44.1k)", apply_transformation_resampling),
        ("Lossy Compression", "Lossy compression (MP3 192 kbps)", apply_transformation_lossy_compression),
    ]

    results: List[RobustnessResult] = []

    for idx, (name, desc, func) in enumerate(transformations, start=1):
        target_wav = temp_dir / f"robustness_{idx}_{algorithm}.wav"
        try:
            transformed_path, applied_desc = func(stego_wav_path, target_wav)
        except Exception as exc:
            results.append(
                RobustnessResult(
                    transformation_name=name,
                    transformation_description=desc,
                    status="FAILED",
                    extracted_successfully=False,
                    exact_match=False,
                    notes=f"Transformation execution error: {exc}",
                )
            )
            continue

        if transformed_path is None or not transformed_path.exists():
            results.append(
                RobustnessResult(
                    transformation_name=name,
                    transformation_description=desc,
                    status="NOT TESTED",
                    extracted_successfully=False,
                    exact_match=False,
                    notes="External encoder (ffmpeg/lame) not available on system",
                )
            )
            continue

        # Attempt extraction from transformed audio
        try:
            ext_res = extract_message_detailed(
                transformed_path,
                password,
                algorithm=algorithm,
                **options,
            )
            is_match = (ext_res.message == expected_message)
            results.append(
                RobustnessResult(
                    transformation_name=name,
                    transformation_description=applied_desc,
                    status="SURVIVED" if is_match else "FAILED",
                    extracted_successfully=True,
                    exact_match=is_match,
                    notes="Message extracted and verified intact" if is_match else "Payload extracted but plaintext corrupted",
                )
            )
        except MessageExtractionError as exc:
            cause = exc.__cause__
            err_str = str(exc)

            if isinstance(cause, CorruptedPayloadError):
                status = "CHECKSUM_FAILED"
                notes = f"Framing CRC32 verification failed: {cause}"
            elif isinstance(cause, (SynchronizationError, HeaderNotFoundError)):
                status = "SYNC_FAILED"
                notes = f"Synchronization or preamble detection failed: {cause}"
            elif isinstance(cause, DecryptionError):
                status = "AUTHENTICATION_FAILED"
                notes = f"AES-256-GCM authentication tag rejected (tampering detected): {cause}"
            elif "crc32" in err_str.lower() or "checksum" in err_str.lower():
                status = "CHECKSUM_FAILED"
                notes = "Framing CRC32 verification failed"
            elif "synchronization" in err_str.lower() or "preamble" in err_str.lower() or "magic" in err_str.lower():
                status = "SYNC_FAILED"
                notes = "Synchronization or preamble correlation failed"
            elif "authentication or decryption failed" in err_str.lower():
                status = "AUTHENTICATION_FAILED"
                notes = "AES-256-GCM authentication tag rejected"
            else:
                status = "FAILED"
                notes = f"Extraction failed: {err_str[:80]}"

            results.append(
                RobustnessResult(
                    transformation_name=name,
                    transformation_description=applied_desc,
                    status=status,
                    extracted_successfully=False,
                    exact_match=False,
                    notes=notes,
                )
            )

    return results


# ---------------------------------------------------------------------------
# Independent Tamper and Integrity Experiments
# ---------------------------------------------------------------------------

def evaluate_tamper_experiments(
    carrier_path: Path,
    stego_path: Path,
    algorithm: str,
    password: str,
    options: Dict[str, Any],
    temp_dir: Path,
) -> Tuple[bool, bool, bool, bool]:
    """
    Execute 4 independent integrity and tamper experiments:
    1. Wrong Password: Attempt decryption with invalid passphrase.
    2. Synchronization Corruption: Corrupt sync preamble and verify rejection.
    3. Checksum Corruption: Modify framed payload data without updating CRC32.
    4. Ciphertext Tamper (AES-GCM): Modify ciphertext with validly recomputed CSMA framing.

    Returns:
        Tuple[bool, bool, bool, bool]:
            (wrong_password_rejected, sync_corruption_rejected, checksum_corruption_rejected, ciphertext_tamper_rejected)
    """
    opts = dict(options)
    algo_instance = _resolve_algorithm(algorithm)

    # 1. Wrong Password Rejection
    wrong_pwd_rejected = False
    try:
        extract_message_detailed(stego_path, "WrongPassword999!", algorithm=algorithm, **opts)
    except MessageExtractionError as exc:
        if isinstance(exc.__cause__, DecryptionError) or "authentication or decryption failed" in str(exc).lower():
            wrong_pwd_rejected = True

    # 2. Synchronization / Header Corruption Rejection
    sync_rejected = False
    sync_tamper_path = temp_dir / f"sync_corrupt_{algorithm}.wav"
    stego_data = read_wav(stego_path)
    raw_frames = bytearray(stego_data.frames)

    if algorithm == "lsb":
        # Flip sync word bit in sample 0
        raw_frames[0] ^= 1
    elif algorithm == "dwt_dct_qim":
        # Zero out first chunk samples (destroys sync preamble correlation)
        chunk_bytes = 1024 * stego_data.channels * stego_data.sample_width
        raw_frames[:chunk_bytes] = b"\x00" * chunk_bytes
    else:  # echo
        # Zero out initial 16 preamble segments
        preamble_bytes = 16 * 2048 * stego_data.channels * stego_data.sample_width
        raw_frames[:preamble_bytes] = b"\x00" * preamble_bytes

    write_wav(
        sync_tamper_path,
        bytes(raw_frames),
        stego_data.channels,
        stego_data.sample_width,
        stego_data.sample_rate,
    )
    try:
        extract_message_detailed(sync_tamper_path, password, algorithm=algorithm, **opts)
    except MessageExtractionError as exc:
        cause = exc.__cause__
        if isinstance(cause, (SynchronizationError, HeaderNotFoundError)) or "synchronization" in str(exc).lower() or "signature" in str(exc).lower():
            sync_rejected = True

    # 3. Framing Checksum (CRC32) Corruption Rejection
    checksum_rejected = False
    crc_tamper_path = temp_dir / f"crc_corrupt_{algorithm}.wav"
    raw_frames_crc = bytearray(stego_data.frames)
    frame_size = stego_data.channels * stego_data.sample_width

    if algorithm == "lsb":
        # CSMA header is 18 bytes (144 bits). Modifying sample index 150 modifies payload without updating CRC32
        sample_offset = 150 * frame_size
        if sample_offset < len(raw_frames_crc):
            raw_frames_crc[sample_offset] ^= 1
    elif algorithm == "dwt_dct_qim":
        # CSMA header takes 9 chunks (144 bits). Modifying chunk 10 modifies payload without updating CRC32
        chunk_offset = 10 * 1024 * frame_size
        chunk_len = 1024 * frame_size
        if chunk_offset + chunk_len <= len(raw_frames_crc):
            raw_frames_crc[chunk_offset:chunk_offset + chunk_len] = b"\x55" * chunk_len
    else:  # echo
        # Preamble is 16 segments. CSMA header is 144 segments. Payload starts at segment 160.
        seg_offset = 165 * 2048 * frame_size
        seg_len = 2048 * frame_size
        if seg_offset + seg_len <= len(raw_frames_crc):
            raw_frames_crc[seg_offset:seg_offset + seg_len] = b"\x00" * seg_len

    write_wav(
        crc_tamper_path,
        bytes(raw_frames_crc),
        stego_data.channels,
        stego_data.sample_width,
        stego_data.sample_rate,
    )
    try:
        extract_message_detailed(crc_tamper_path, password, algorithm=algorithm, **opts)
    except MessageExtractionError as exc:
        cause = exc.__cause__
        if isinstance(cause, CorruptedPayloadError) or "crc32" in str(exc).lower():
            checksum_rejected = True

    # 4. Genuine Ciphertext Tampering with Recomputed CSMA CRC32 (AES-GCM Authentication Verification)
    ciphertext_tamper_rejected = False
    cipher_tamper_path = temp_dir / f"cipher_tamper_{algorithm}.wav"

    try:
        # Step 1: Extract normal payload from valid stego audio
        extracted = algo_instance.extract(read_wav(stego_path), **opts)
        original_payload = extracted.payload

        # Step 2: Modify ciphertext byte while preserving AES header structure
        # AES-GCM payload header is 33 bytes (Magic 4B + Ver 1B + Salt 16B + Nonce 12B).
        # Offset 34 is inside the actual ciphertext.
        tampered_payload = bytearray(original_payload)
        tamper_idx = min(34, len(tampered_payload) - 1)
        tampered_payload[tamper_idx] ^= 0x01

        # Step 3: Re-embed using algo_instance.embed() which encapsulates with create_csma_envelope(),
        # automatically recomputing a valid CRC32 matching the tampered ciphertext!
        carrier_data = read_wav(carrier_path)
        embed_result = algo_instance.embed(carrier_data, bytes(tampered_payload), **opts)

        write_wav(
            cipher_tamper_path,
            embed_result.modified_wav.frames,
            carrier_data.channels,
            carrier_data.sample_width,
            carrier_data.sample_rate,
        )

        # Step 4: Attempt extraction and verify AES-GCM rejects modified ciphertext
        try:
            extract_message_detailed(cipher_tamper_path, password, algorithm=algorithm, **opts)
        except MessageExtractionError as exc:
            cause = exc.__cause__
            if isinstance(cause, DecryptionError) or "authentication or decryption failed" in str(exc).lower():
                ciphertext_tamper_rejected = True
    except Exception:
        ciphertext_tamper_rejected = False

    return wrong_pwd_rejected, sync_rejected, checksum_rejected, ciphertext_tamper_rejected


# ---------------------------------------------------------------------------
# Single Algorithm Benchmark
# ---------------------------------------------------------------------------

def run_algorithm_benchmark(
    carrier_path: str | Path,
    algorithm: str,
    options: Optional[Dict[str, Any]] = None,
    message: str = "CryptAudio",
    password: str = "BenchmarkPass123!",
    trials: int = 1,
    skip_robustness: bool = False,
    carrier_name: str = "standard_carrier",
) -> AlgorithmBenchmarkResult:
    """
    Execute a comprehensive scientific benchmark for a single algorithm configuration.

    Parameters:
        carrier_path: Path to the original carrier WAV file.
        algorithm: Algorithm identifier ('lsb', 'dwt_dct_qim', 'echo').
        options: Algorithm-specific parameters (e.g. delta, alpha).
        message: Test secret message.
        password: Test passphrase.
        trials: Number of measurement trials for timing averaging.
        skip_robustness: If True, skip the 5 transformation robustness tests.
        carrier_name: Label for the carrier audio used.

    Returns:
        AlgorithmBenchmarkResult: Full benchmark outcome for this algorithm.
    """
    num_trials = validate_trials(trials)
    c_path = Path(carrier_path).resolve()
    opts = dict(options or {})

    # 1. Capacity Evaluation
    try:
        cap_est = estimate_capacity(c_path, message, algorithm=algorithm, **opts)
    except InsufficientAudioCapacityError as exc:
        return AlgorithmBenchmarkResult(
            algorithm_id=algorithm,
            algorithm_name=algorithm.upper(),
            options=opts,
            status="CAPACITY_INSUFFICIENT",
            carrier_name=carrier_name,
            carrier_duration_seconds=0.0,
            message_length_bytes=len(message.encode("utf-8")),
            error_message=str(exc),
        )
    except Exception as exc:
        return AlgorithmBenchmarkResult(
            algorithm_id=algorithm,
            algorithm_name=algorithm.upper(),
            options=opts,
            status="ERROR",
            carrier_name=carrier_name,
            carrier_duration_seconds=0.0,
            message_length_bytes=len(message.encode("utf-8")),
            error_message=f"Capacity estimation failed: {exc}",
        )

    # Read carrier metadata
    wav_info = read_wav(c_path)
    total_samples = len(decode_pcm_samples(wav_info.frames, wav_info.sample_width))
    duration_sec = round(wav_info.frame_count / wav_info.sample_rate, 4)

    raw_cap_bits = cap_est.available_bits
    raw_cap_bytes = raw_cap_bits // 8

    # Usable encrypted-payload capacity: raw capacity minus 18-byte (144-bit) CSMA header
    usable_payload_bytes = max(0, (raw_cap_bits - 144) // 8)
    # Maximum plaintext message: usable payload minus 49-byte AES-GCM crypto overhead
    max_message_bytes = max(0, usable_payload_bytes - 49)

    cap_metrics = CapacityMetrics(
        duration_seconds=duration_sec,
        sample_rate=wav_info.sample_rate,
        channels=wav_info.channels,
        total_samples=total_samples,
        raw_capacity_bits=raw_cap_bits,
        raw_capacity_bytes=raw_cap_bytes,
        usable_payload_capacity_bytes=usable_payload_bytes,
        max_embeddable_message_bytes=max_message_bytes,
        required_bits=cap_est.required_bits,
        available_bits=cap_est.available_bits,
        utilization_percent=cap_est.utilization_percent,
    )

    if not cap_est.can_fit:
        return AlgorithmBenchmarkResult(
            algorithm_id=cap_est.algorithm_id,
            algorithm_name=algorithm.upper(),
            options=opts,
            status="CAPACITY_INSUFFICIENT",
            carrier_name=carrier_name,
            carrier_duration_seconds=duration_sec,
            message_length_bytes=len(message.encode("utf-8")),
            capacity=cap_metrics,
            error_message=f"Required capacity ({cap_est.required_bits} bits) exceeds available ({cap_est.available_bits} bits).",
        )

    # 2. Performance Measurement (Embedding & Memory)
    with tempfile.TemporaryDirectory() as td:
        temp_dir = Path(td)
        stego_path = temp_dir / f"stego_{algorithm}.wav"

        embed_times: List[float] = []
        peak_mem_bytes = 0

        tracemalloc.start()
        try:
            for _ in range(num_trials):
                if stego_path.exists():
                    stego_path.unlink()
                t0 = time.perf_counter()
                embed_message(
                    c_path,
                    stego_path,
                    message,
                    password,
                    algorithm=algorithm,
                    **opts,
                )
                t1 = time.perf_counter()
                embed_times.append(t1 - t0)
        finally:
            _, peak_mem_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        avg_embed_time = float(np.mean(embed_times))
        std_embed_time = float(np.std(embed_times)) if len(embed_times) > 1 else 0.0

        # 3. Audio Quality Comparison
        comp_report: AudioComparisonReport = compare_audio(c_path, stego_path)
        mod_percent = (
            round((comp_report.modified_samples / comp_report.total_samples) * 100.0, 4)
            if comp_report.total_samples > 0
            else 0.0
        )

        quality_metrics = QualityMetrics(
            mse=comp_report.mse,
            snr_db=comp_report.snr_db,
            psnr_db=comp_report.psnr_db,
            correlation=comp_report.correlation if comp_report.correlation is not None else 1.0,
            modified_samples=comp_report.modified_samples,
            total_samples=comp_report.total_samples,
            modification_percent=mod_percent,
            quality_rating=comp_report.quality_assessment,
            max_absolute_difference=comp_report.max_absolute_difference,
            average_absolute_difference=comp_report.average_absolute_difference,
        )

        # 4. Performance Measurement (Extraction)
        extract_times: List[float] = []
        last_ext_res = None
        extract_err_msg = None

        for _ in range(num_trials):
            t0 = time.perf_counter()
            try:
                last_ext_res = extract_message_detailed(
                    stego_path,
                    password,
                    algorithm=algorithm,
                    **opts,
                )
                t1 = time.perf_counter()
                extract_times.append(t1 - t0)
            except MessageExtractionError as exc:
                extract_err_msg = str(exc)
                break

        avg_extract_time = float(np.mean(extract_times)) if extract_times else 0.0
        std_extract_time = float(np.std(extract_times)) if len(extract_times) > 1 else 0.0
        total_pipeline_time = avg_embed_time + avg_extract_time

        perf_metrics = PerformanceMetrics(
            embed_time_seconds=round(avg_embed_time, 4),
            embed_time_std_seconds=round(std_embed_time, 4),
            extract_time_seconds=round(avg_extract_time, 4),
            extract_time_std_seconds=round(std_extract_time, 4),
            total_pipeline_time_seconds=round(total_pipeline_time, 4),
            peak_traced_memory_bytes=peak_mem_bytes,
            peak_traced_memory_mb=round(peak_mem_bytes / (1024 * 1024), 2),
            trials_completed=len(extract_times) if last_ext_res else 0,
            trials_requested=num_trials,
        )

        # 5. Extraction Accuracy & Independent Tamper Detection Experiments
        exact_match = (last_ext_res.message == message) if last_ext_res else False
        algo_matched = (last_ext_res.algorithm_id.lower() == algorithm.lower()) if last_ext_res else False

        wrong_pwd_rej, sync_rej, crc_rej, cipher_tamper_rej = evaluate_tamper_experiments(
            carrier_path=c_path,
            stego_path=stego_path,
            algorithm=algorithm,
            password=password,
            options=opts,
            temp_dir=temp_dir,
        )

        acc_metrics = AccuracyMetrics(
            extraction_success=True if last_ext_res else False,
            exact_match=exact_match,
            algorithm_identified=last_ext_res.algorithm_id if last_ext_res else "unknown",
            algorithm_match=algo_matched,
            authentication_verified=True if (last_ext_res and exact_match) else False,
            wrong_password_rejected=wrong_pwd_rej,
            sync_corruption_rejected=sync_rej,
            checksum_corruption_rejected=crc_rej,
            ciphertext_tamper_rejected=cipher_tamper_rej,
        )

        # 6. Robustness Evaluation Across 5 Controlled Transformations
        robustness_results: List[RobustnessResult] = []
        if not skip_robustness and last_ext_res is not None:
            robustness_results = evaluate_robustness_transformations(
                stego_wav_path=stego_path,
                algorithm=algorithm,
                password=password,
                expected_message=message,
                options=opts,
                temp_dir=temp_dir,
            )

        status = "SUCCESS" if (last_ext_res is not None and exact_match) else "ERROR"
        return AlgorithmBenchmarkResult(
            algorithm_id=algorithm,
            algorithm_name=algorithm.upper(),
            options=opts,
            status=status,
            carrier_name=carrier_name,
            carrier_duration_seconds=duration_sec,
            message_length_bytes=len(message.encode("utf-8")),
            error_message=extract_err_msg,
            capacity=cap_metrics,
            quality=quality_metrics,
            performance=perf_metrics,
            accuracy=acc_metrics,
            robustness=robustness_results,
        )


# ---------------------------------------------------------------------------
# Full Benchmark Suite
# ---------------------------------------------------------------------------

def run_full_benchmark_suite(
    output_dir: Optional[str | Path] = None,
    duration_seconds: float = 33.0,
    quick: bool = False,
    trials: int = 1,
) -> BenchmarkSuiteResult:
    """
    Execute the entire comparative steganography benchmark suite.

    Runs:
    1. Standard carrier across all 3 algorithms with default parameters (LSB, DWT-DCT-QIM delta=32, Echo Hiding alpha=0.08).
    2. Parameter sensitivity sweeps (DWT delta 16 and 64, Echo alpha 0.12 and 0.15) if not in quick mode.
    3. Capacity-insufficient boundary test on a 1.0s short carrier.

    Parameters:
        output_dir: Optional directory to persist generated carrier WAVs.
        duration_seconds: Duration of the primary test carrier (default 33s).
        quick: If True, skip parameter sweeps for fast execution.
        trials: Timing measurement iterations.

    Returns:
        BenchmarkSuiteResult: Aggregated suite results.
    """
    num_trials = validate_trials(trials)
    sys_info = get_system_environment_info()
    test_msg = "CryptAudio"
    test_pwd = "BenchmarkPass123!"

    with tempfile.TemporaryDirectory() as td:
        base_dir = Path(output_dir).resolve() if output_dir else Path(td)
        base_dir.mkdir(parents=True, exist_ok=True)

        # 1. Generate primary standard carrier
        carrier_cfg = BenchmarkCarrierConfig(
            duration_seconds=duration_seconds,
            sample_rate=44100,
            channels=1,
            sample_width=2,
            carrier_type="chirp",
            name="standard_chirp_33s",
        )
        carrier_path = base_dir / "standard_carrier.wav"
        generate_carrier_wav(carrier_cfg, carrier_path, seed=42)

        # 2. Generate short carrier for capacity-insufficient boundary test
        short_cfg = BenchmarkCarrierConfig(
            duration_seconds=1.0,
            sample_rate=44100,
            channels=1,
            sample_width=2,
            carrier_type="chirp",
            name="short_carrier_1s",
        )
        short_carrier_path = base_dir / "short_carrier_1s.wav"
        generate_carrier_wav(short_cfg, short_carrier_path, seed=42)

        results: List[AlgorithmBenchmarkResult] = []

        # Standard baseline tests (default parameters)
        standard_runs = [
            ("lsb", {}, "standard_chirp_33s"),
            ("dwt_dct_qim", {"delta": 32}, "standard_chirp_33s"),
            ("echo", {"alpha": 0.08}, "standard_chirp_33s"),
        ]

        for alg, opts, c_name in standard_runs:
            res = run_algorithm_benchmark(
                carrier_path=carrier_path,
                algorithm=alg,
                options=opts,
                message=test_msg,
                password=test_pwd,
                trials=num_trials,
                skip_robustness=False,
                carrier_name=c_name,
            )
            results.append(res)

        # Extended parameter sweeps (if not quick)
        if not quick:
            sweep_runs = [
                ("dwt_dct_qim", {"delta": 16}, "standard_chirp_33s"),
                ("dwt_dct_qim", {"delta": 64}, "standard_chirp_33s"),
                ("echo", {"alpha": 0.12}, "standard_chirp_33s"),
                ("echo", {"alpha": 0.15}, "standard_chirp_33s"),
            ]
            for alg, opts, c_name in sweep_runs:
                res = run_algorithm_benchmark(
                    carrier_path=carrier_path,
                    algorithm=alg,
                    options=opts,
                    message=test_msg,
                    password=test_pwd,
                    trials=num_trials,
                    skip_robustness=False,
                    carrier_name=c_name,
                )
                results.append(res)

        # Short carrier edge case (demonstrating CAPACITY_INSUFFICIENT behavior)
        short_run = run_algorithm_benchmark(
            carrier_path=short_carrier_path,
            algorithm="echo",
            options={"alpha": 0.08},
            message=test_msg,
            password=test_pwd,
            trials=1,
            skip_robustness=True,
            carrier_name="short_carrier_1s",
        )
        results.append(short_run)

        return BenchmarkSuiteResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            system_info=sys_info,
            results=results,
        )
