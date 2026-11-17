"""
tests/test_evaluation.py
CryptAudio Web — Audio Quality Evaluation Test Suite (Phase 7)

Tests PCM sample decoding (8/16/24/32-bit), MSE, SNR, PSNR, Pearson correlation,
compatibility validation, and end-to-end WAV comparison reports.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_evaluation.py -v
"""

from __future__ import annotations

import math
import os
import struct
import sys
from pathlib import Path

import numpy as np
import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import write_wav
from app.evaluation.audio_quality import (
    PEAK_AMPLITUDES,
    AudioComparisonReport,
    AudioEvaluationError,
    IncompatibleAudioError,
    UnsupportedEvaluationFormatError,
    calculate_correlation,
    calculate_mse,
    calculate_psnr,
    calculate_snr,
    classify_quality,
    compare_audio,
    decode_pcm_samples,
)
from app.services.cryptaudio_service import embed_message


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def create_carrier_wav(
    file_path: Path,
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 2000,
    constant_val: int | None = None,
) -> Path:
    """Helper to create a deterministic PCM WAV file."""
    frame_size = channels * sample_width
    if constant_val is not None:
        if sample_width == 1:
            frame_sample = bytes([constant_val % 256])
        elif sample_width == 2:
            frame_sample = struct.pack("<h", constant_val)
        elif sample_width == 3:
            val = constant_val & 0xFFFFFF
            frame_sample = bytes([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF])
        elif sample_width == 4:
            frame_sample = struct.pack("<i", constant_val)
        else:
            raise ValueError("Unsupported width")
        frames = (frame_sample * channels) * num_frames
    else:
        # Non-constant deterministic waveform
        frames = bytes((i * 11 + 5) % 256 for i in range(num_frames * frame_size))

    write_wav(
        output_path=file_path,
        frames=frames,
        channels=channels,
        sample_width=sample_width,
        sample_rate=sample_rate,
    )
    return file_path


create_pcm_wav = create_carrier_wav


# ---------------------------------------------------------------------------
# 1-7. Sample Decoding Tests
# ---------------------------------------------------------------------------

def test_decode_8bit_pcm_correctly() -> None:
    """1. Decodes 8-bit unsigned PCM into centered float64 samples."""
    raw = bytes([0, 128, 255])
    decoded = decode_pcm_samples(raw, sample_width=1)
    # 0 - 128 = -128.0; 128 - 128 = 0.0; 255 - 128 = 127.0
    expected = np.array([-128.0, 0.0, 127.0], dtype=np.float64)
    assert np.allclose(decoded, expected)


def test_decode_16bit_pcm_correctly() -> None:
    """2. Decodes 16-bit signed PCM little-endian integers."""
    raw = struct.pack("<hhh", -32768, 0, 32767)
    decoded = decode_pcm_samples(raw, sample_width=2)
    expected = np.array([-32768.0, 0.0, 32767.0], dtype=np.float64)
    assert np.allclose(decoded, expected)


def test_decode_24bit_pcm_correctly() -> None:
    """3. Decodes 24-bit signed 3-byte PCM little-endian integers."""
    # Positive 24-bit: 1, 1000, 8388607 (0x7FFFFF)
    # 8388607 = b'\xff\xff\x7f'
    raw = bytes([1, 0, 0]) + bytes([0xe8, 0x03, 0x00]) + bytes([0xff, 0xff, 0x7f])
    decoded = decode_pcm_samples(raw, sample_width=3)
    expected = np.array([1.0, 1000.0, 8388607.0], dtype=np.float64)
    assert np.allclose(decoded, expected)


def test_decode_32bit_pcm_correctly() -> None:
    """4. Decodes 32-bit signed integer PCM little-endian integers."""
    raw = struct.pack("<iii", -2147483648, 0, 2147483647)
    decoded = decode_pcm_samples(raw, sample_width=4)
    expected = np.array([-2147483648.0, 0.0, 2147483647.0], dtype=np.float64)
    assert np.allclose(decoded, expected)


def test_decode_negative_24bit_values() -> None:
    """5. Decodes negative 24-bit samples with sign extension (-1 and -8388608)."""
    # -1 in 24-bit: 0xFFFFFF = b'\xff\xff\xff'
    # -8388608 in 24-bit: 0x800000 = b'\x00\x00\x80'
    # -100 in 24-bit: 0xFFFF9C = b'\x9c\xff\xff'
    raw = bytes([0xff, 0xff, 0xff]) + bytes([0x00, 0x00, 0x80]) + bytes([0x9c, 0xff, 0xff])
    decoded = decode_pcm_samples(raw, sample_width=3)
    expected = np.array([-1.0, -8388608.0, -100.0], dtype=np.float64)
    assert np.allclose(decoded, expected)


def test_decode_positive_and_negative_samples() -> None:
    """6. Decodes mixed polarity samples without bias or clipping."""
    raw = struct.pack("<hhhh", -15000, -1, 0, 15000)
    decoded = decode_pcm_samples(raw, sample_width=2)
    assert decoded[0] == -15000.0
    assert decoded[1] == -1.0
    assert decoded[2] == 0.0
    assert decoded[3] == 15000.0


def test_8bit_centering_around_zero() -> None:
    """7. Verifies 8-bit unsigned PCM sample value 128 maps to exact zero."""
    raw = bytes([128] * 10)
    decoded = decode_pcm_samples(raw, sample_width=1)
    assert np.all(decoded == 0.0)


# ---------------------------------------------------------------------------
# 8-10. MSE Tests
# ---------------------------------------------------------------------------

def test_identical_signals_produce_zero_mse() -> None:
    """8. Identical signals produce exactly 0.0 MSE."""
    sig = np.array([10.0, -50.0, 100.0, 0.0], dtype=np.float64)
    assert calculate_mse(sig, sig) == 0.0


def test_known_differences_produce_expected_mse() -> None:
    """9. Known differences produce analytically verified MSE."""
    x = np.array([10.0, 20.0, 30.0, 40.0], dtype=np.float64)
    # Add difference [1, 2, 3, 4] -> diff squared = [1, 4, 9, 16] -> mean = 30 / 4 = 7.5
    y = np.array([11.0, 22.0, 33.0, 44.0], dtype=np.float64)
    assert math.isclose(calculate_mse(x, y), 7.5)


def test_mse_is_non_negative() -> None:
    """10. MSE is strictly non-negative."""
    x = np.random.uniform(-1000, 1000, size=100)
    y = np.random.uniform(-1000, 1000, size=100)
    assert calculate_mse(x, y) >= 0.0


# ---------------------------------------------------------------------------
# 11-14. SNR Tests
# ---------------------------------------------------------------------------

def test_identical_signals_produce_infinite_snr() -> None:
    """11. Identical signals produce positive infinity SNR."""
    sig = np.array([100.0, -200.0, 300.0], dtype=np.float64)
    snr = calculate_snr(sig, sig)
    assert math.isinf(snr) and snr > 0


def test_known_signal_noise_produces_expected_snr() -> None:
    """12. Known signal and noise powers produce expected SNR (dB)."""
    # Signal power = 100^2 + 100^2 = 20000
    # Noise = 1^2 + 1^2 = 2
    # Ratio = 20000 / 2 = 10000 -> 10 * log10(10000) = 40.0 dB
    x = np.array([100.0, 100.0], dtype=np.float64)
    y = np.array([101.0, 101.0], dtype=np.float64)
    snr = calculate_snr(x, y)
    assert math.isclose(snr, 40.0, rel_tol=1e-5)


def test_zero_signal_with_nonzero_noise_handled() -> None:
    """13. Zero signal with noise returns negative infinity."""
    x = np.zeros(10, dtype=np.float64)
    y = np.ones(10, dtype=np.float64)
    snr = calculate_snr(x, y)
    assert math.isinf(snr) and snr < 0


def test_no_division_by_zero_in_snr() -> None:
    """14. SNR avoids division by zero on silent/identical signals."""
    silent = np.zeros(100, dtype=np.float64)
    snr = calculate_snr(silent, silent)
    assert math.isinf(snr) and snr > 0


# ---------------------------------------------------------------------------
# 15-17. PSNR Tests
# ---------------------------------------------------------------------------

def test_identical_signals_produce_infinite_psnr() -> None:
    """15. Identical signals produce positive infinity PSNR."""
    sig = np.array([500.0, -500.0], dtype=np.float64)
    psnr = calculate_psnr(sig, sig, peak_value=32768.0)
    assert math.isinf(psnr) and psnr > 0


def test_known_differences_produce_expected_psnr() -> None:
    """16. Known differences produce analytically verified PSNR."""
    # Peak = 100.0, MSE = 1.0 -> 10 * log10(10000 / 1) = 40.0 dB
    x = np.array([0.0, 0.0], dtype=np.float64)
    y = np.array([1.0, 1.0], dtype=np.float64)
    psnr = calculate_psnr(x, y, peak_value=100.0)
    assert math.isclose(psnr, 40.0, rel_tol=1e-5)


def test_peak_values_correct_for_all_bit_depths() -> None:
    """17. Verifies peak amplitude conventions for 8, 16, 24, and 32-bit audio."""
    assert PEAK_AMPLITUDES[1] == 128.0
    assert PEAK_AMPLITUDES[2] == 32768.0
    assert PEAK_AMPLITUDES[3] == 8388608.0
    assert PEAK_AMPLITUDES[4] == 2147483648.0


# ---------------------------------------------------------------------------
# 18-21. Pearson Correlation Tests
# ---------------------------------------------------------------------------

def test_identical_non_constant_signals_produce_correlation_one() -> None:
    """18. Non-constant identical signals produce correlation of exactly 1.0."""
    sig = np.array([10.0, 20.0, 30.0, 40.0, 50.0], dtype=np.float64)
    r = calculate_correlation(sig, sig)
    assert r is not None
    assert math.isclose(r, 1.0, rel_tol=1e-6)


def test_negatively_correlated_signals() -> None:
    """19. Inverted signals produce correlation of -1.0."""
    x = np.array([1.0, 2.0, 3.0, 4.0, 5.0], dtype=np.float64)
    y = np.array([5.0, 4.0, 3.0, 2.0, 1.0], dtype=np.float64)
    r = calculate_correlation(x, y)
    assert r is not None
    assert math.isclose(r, -1.0, rel_tol=1e-6)


def test_constant_signals_handled_safely() -> None:
    """20. Identical constant signals return 1.0; differing constant signals return None."""
    const1 = np.full(50, 100.0, dtype=np.float64)
    assert calculate_correlation(const1, const1) == 1.0

    const2 = np.full(50, 200.0, dtype=np.float64)
    assert calculate_correlation(const1, const2) is None


def test_no_nan_in_reports(tmp_path: Path) -> None:
    """21. Confirms comparison reports do not contain NaN values."""
    f1 = create_carrier_wav(tmp_path / "c1.wav", constant_val=0)
    f2 = create_carrier_wav(tmp_path / "c2.wav", constant_val=0)

    report = compare_audio(f1, f2)
    assert not math.isnan(report.mse)
    assert not math.isnan(report.snr_db)
    assert not math.isnan(report.psnr_db)
    if report.correlation is not None:
        assert not math.isnan(report.correlation)


# ---------------------------------------------------------------------------
# 22-30. Audio Comparison Function & Validation Tests
# ---------------------------------------------------------------------------

def test_compare_identical_wav_files(tmp_path: Path) -> None:
    """22. Comparing identical WAV files reports zero MSE and infinite SNR/PSNR."""
    wav = create_carrier_wav(tmp_path / "carrier.wav")
    report = compare_audio(wav, wav)

    assert isinstance(report, AudioComparisonReport)
    assert report.mse == 0.0
    assert math.isinf(report.snr_db) and report.snr_db > 0
    assert math.isinf(report.psnr_db) and report.psnr_db > 0
    assert report.correlation == 1.0
    assert "Zero Distortion" in report.quality_assessment
    assert report.modified_samples == 0


def test_compare_original_and_stego_wav_files(tmp_path: Path) -> None:
    """23. Compares carrier and LSB-embedded stego WAV, verifying high fidelity."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav", channels=2, sample_width=2, num_frames=3000)
    stego = tmp_path / "stego.wav"
    embed_message(carrier, stego, "Confidential Steganography Payload", "Pass#2026")

    report = compare_audio(carrier, stego)
    assert report.mse > 0.0
    # For LSB modification, PSNR is typically > 80 dB for 16-bit audio
    assert report.psnr_db > 50.0
    assert report.quality_assessment == "Excellent"
    assert report.correlation is not None
    assert report.correlation > 0.999
    assert report.modified_samples > 0
    assert report.max_absolute_difference <= 1.0  # LSB changes at most 1 unit


def test_reject_mismatched_sample_rates(tmp_path: Path) -> None:
    """24. Rejects comparison when sample rates differ."""
    f1 = create_carrier_wav(tmp_path / "w1.wav", sample_rate=44100)
    f2 = create_carrier_wav(tmp_path / "w2.wav", sample_rate=48000)

    with pytest.raises(IncompatibleAudioError, match="Sample rate mismatch"):
        compare_audio(f1, f2)


def test_reject_mismatched_channel_counts(tmp_path: Path) -> None:
    """25. Rejects comparison when channel counts differ."""
    f1 = create_carrier_wav(tmp_path / "mono.wav", channels=1)
    f2 = create_carrier_wav(tmp_path / "stereo.wav", channels=2)

    with pytest.raises(IncompatibleAudioError, match="Channel count mismatch"):
        compare_audio(f1, f2)


def test_reject_mismatched_sample_widths(tmp_path: Path) -> None:
    """26. Rejects comparison when bit depths / sample widths differ."""
    f1 = create_carrier_wav(tmp_path / "w16.wav", sample_width=2)
    f2 = create_carrier_wav(tmp_path / "w24.wav", sample_width=3)

    with pytest.raises(IncompatibleAudioError, match="Sample width mismatch"):
        compare_audio(f1, f2)


def test_reject_mismatched_frame_counts(tmp_path: Path) -> None:
    """27. Rejects comparison when frame counts / durations differ."""
    f1 = create_carrier_wav(tmp_path / "short.wav", num_frames=1000)
    f2 = create_carrier_wav(tmp_path / "long.wav", num_frames=2000)

    with pytest.raises(IncompatibleAudioError, match="Frame count mismatch"):
        compare_audio(f1, f2)


def test_reject_invalid_wav_files(tmp_path: Path) -> None:
    """28. Rejects invalid WAV files with AudioEvaluationError."""
    fake = tmp_path / "not_audio.wav"
    fake.write_bytes(b"NON_WAV_BYTES")
    good = create_carrier_wav(tmp_path / "good.wav")

    with pytest.raises(AudioEvaluationError):
        compare_audio(good, fake)


def test_both_input_files_remain_unchanged(tmp_path: Path) -> None:
    """29. Comparison operation is read-only and never modifies either input file."""
    f1 = create_carrier_wav(tmp_path / "f1.wav")
    f2 = create_carrier_wav(tmp_path / "f2.wav")
    b1_before, m1_before = f1.read_bytes(), f1.stat().st_mtime_ns
    b2_before, m2_before = f2.read_bytes(), f2.stat().st_mtime_ns

    compare_audio(f1, f2)

    assert f1.read_bytes() == b1_before
    assert f1.stat().st_mtime_ns == m1_before
    assert f2.read_bytes() == b2_before
    assert f2.stat().st_mtime_ns == m2_before


def test_verify_result_metadata(tmp_path: Path) -> None:
    """30. Complete metadata fields are populated in report dictionary."""
    f1 = create_carrier_wav(tmp_path / "f1.wav", channels=2, sample_width=2, sample_rate=44100, num_frames=1000)
    report = compare_audio(f1, f1)

    r_dict = report.to_dict()
    assert "mse" in r_dict
    assert "snr_db" in r_dict
    assert "psnr_db" in r_dict
    assert "correlation" in r_dict
    assert "quality_assessment" in r_dict
    assert r_dict["sample_rate"] == 44100
    assert r_dict["channels"] == 2
    assert r_dict["bit_depth"] == 16
    assert r_dict["total_samples"] == 2000
