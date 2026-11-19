"""
tests/test_benchmark.py
Comprehensive test suite for CryptAudio-Web Phase M7.1 Comparative Steganography Benchmarking.

Covers:
1. PCM generation for each supported sample width (8-bit, 16-bit, 24-bit, 32-bit).
2. Mono and stereo carrier generation.
3. Correct PCM encoding and decoding round trips across all bit depths.
4. Noise transformation preserving bit depth and stereo channels.
5. Amplitude scaling preserving bit depth and stereo channels.
6. Stereo resampling without channel mixing.
7. Invalid benchmark configuration rejection (duration, sample rate, channels, width).
8. Validation of trials (rejection of trials=0, negative trials, boolean trials, NaN, Infinity).
9. Guaranteed tracemalloc cleanup after exceptions.
10. CRC32 framing failure classification (CHECKSUM_FAILED).
11. AES-GCM authentication failure classification (AUTHENTICATION_FAILED).
12. Synchronization failure classification (SYNC_FAILED).
13. Wrong-password rejection independently verified.
14. Genuine ciphertext tampering with recomputed CSMA CRC32.
15. Exact capacity boundaries for LSB, DWT-DCT-QIM, and Echo Hiding.
16. JSON and CSV consistency.
17. Markdown values matching JSON values.
18. Markdown report not claiming unexecuted parameter configurations.
19. Lossy compression unavailable -> NOT TESTED.
20. CLI quick mode and full mode execution.
"""

import csv
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
from pathlib import Path
from typing import Any, Generator, Optional

import numpy as np
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.audio.wav_handler import read_wav, write_wav
from app.crypto.aes_crypto import DecryptionError
from app.evaluation.audio_quality import PEAK_AMPLITUDES, decode_pcm_samples
from app.evaluation.benchmark import (
    AccuracyMetrics,
    AlgorithmBenchmarkResult,
    BenchmarkCarrierConfig,
    BenchmarkSuiteResult,
    CapacityMetrics,
    PerformanceMetrics,
    QualityMetrics,
    RobustnessResult,
    apply_transformation_amplitude_scaling,
    apply_transformation_gaussian_noise,
    apply_transformation_lossy_compression,
    apply_transformation_resampling,
    apply_transformation_unmodified,
    encode_pcm_samples,
    evaluate_tamper_experiments,
    generate_carrier_wav,
    get_system_environment_info,
    run_algorithm_benchmark,
    run_full_benchmark_suite,
    validate_carrier_config,
    validate_trials,
)
from app.evaluation.benchmark_report import (
    generate_markdown_report,
    save_csv_report,
    save_json_report,
)
from app.services.cryptaudio_service import (
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


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create and clean up a temporary working directory."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def standard_carrier(temp_dir: Path) -> Path:
    """Generate a standard 33.0-second benchmark carrier WAV (16-bit PCM Mono)."""
    cfg = BenchmarkCarrierConfig(
        duration_seconds=33.0,
        sample_rate=44100,
        channels=1,
        sample_width=2,
        carrier_type="chirp",
        name="fixture_chirp_33s",
    )
    carrier_path = temp_dir / "carrier_33s.wav"
    generate_carrier_wav(cfg, carrier_path, seed=42)
    return carrier_path


@pytest.fixture
def short_carrier(temp_dir: Path) -> Path:
    """Generate a 1.0-second carrier WAV for capacity-insufficient boundary testing."""
    cfg = BenchmarkCarrierConfig(
        duration_seconds=1.0,
        sample_rate=44100,
        channels=1,
        sample_width=2,
        carrier_type="chirp",
        name="fixture_short_1s",
    )
    carrier_path = temp_dir / "carrier_1s.wav"
    generate_carrier_wav(cfg, carrier_path, seed=42)
    return carrier_path


# ---------------------------------------------------------------------------
# Test 1, 2, 3: PCM Synthesis, Widths, Channels, and Round-Trip Encoding
# ---------------------------------------------------------------------------

class TestPcmCarrierSynthesisAndEncoding:
    """Tests 1, 2, 3: Verifies multi-width PCM synthesis, stereo handling, and encoding round trips."""

    @pytest.mark.parametrize("sample_width", [1, 2, 3, 4])
    def test_pcm_generation_all_supported_widths(self, temp_dir: Path, sample_width: int) -> None:
        """Test 1: Verify PCM carrier generation for 8-bit, 16-bit, 24-bit, and 32-bit PCM."""
        cfg = BenchmarkCarrierConfig(
            duration_seconds=1.0,
            sample_rate=44100,
            channels=1,
            sample_width=sample_width,
            carrier_type="chirp",
        )
        wav_path = temp_dir / f"carrier_{sample_width * 8}bit.wav"
        generate_carrier_wav(cfg, wav_path)

        assert wav_path.is_file()
        info = read_wav(wav_path)
        assert info.channels == 1
        assert info.sample_width == sample_width
        assert info.sample_rate == 44100
        assert info.frame_count == 44100
        assert len(info.frames) == 44100 * sample_width

    @pytest.mark.parametrize("channels", [1, 2])
    def test_mono_and_stereo_carrier_generation(self, temp_dir: Path, channels: int) -> None:
        """Test 2: Verify mono and stereo carrier generation."""
        cfg = BenchmarkCarrierConfig(
            duration_seconds=1.0,
            sample_rate=44100,
            channels=channels,
            sample_width=2,
            carrier_type="chirp",
        )
        wav_path = temp_dir / f"carrier_{'stereo' if channels == 2 else 'mono'}.wav"
        generate_carrier_wav(cfg, wav_path)

        assert wav_path.is_file()
        info = read_wav(wav_path)
        assert info.channels == channels
        assert info.frame_count == 44100
        assert len(info.frames) == 44100 * channels * 2

    @pytest.mark.parametrize("sample_width", [1, 2, 3, 4])
    def test_pcm_encoding_decoding_round_trip(self, sample_width: int) -> None:
        """Test 3: Verify bit-exact round trip encoding and decoding across all widths."""
        if sample_width == 1:
            test_samples = np.array([-128.0, -64.0, 0.0, 64.0, 127.0], dtype=np.float64)
        elif sample_width == 2:
            test_samples = np.array([-32768.0, -16384.0, 0.0, 16384.0, 32767.0], dtype=np.float64)
        elif sample_width == 3:
            test_samples = np.array([-8388608.0, -4194304.0, 0.0, 4194304.0, 8388607.0], dtype=np.float64)
        elif sample_width == 4:
            test_samples = np.array([-2147483648.0, -1073741824.0, 0.0, 1073741824.0, 2147483647.0], dtype=np.float64)

        encoded_bytes = encode_pcm_samples(test_samples, sample_width)
        decoded_samples = decode_pcm_samples(encoded_bytes, sample_width)

        np.testing.assert_allclose(decoded_samples, test_samples, atol=0.5)


# ---------------------------------------------------------------------------
# Test 4, 5, 6: Robustness Transformations with Multi-Width and Stereo
# ---------------------------------------------------------------------------

class TestRobustnessTransformations:
    """Tests 4, 5, 6: Verifies transformation fidelity across bit depths and stereo channels."""

    @pytest.mark.parametrize("sample_width", [1, 2, 3, 4])
    def test_noise_transformation_preserves_pcm_width(self, temp_dir: Path, sample_width: int) -> None:
        """Test 4: Verify Gaussian noise transformation preserves sample width and structure."""
        cfg = BenchmarkCarrierConfig(duration_seconds=0.5, sample_rate=44100, sample_width=sample_width)
        in_wav = temp_dir / f"in_noise_{sample_width}.wav"
        out_wav = temp_dir / f"out_noise_{sample_width}.wav"
        generate_carrier_wav(cfg, in_wav)

        apply_transformation_gaussian_noise(in_wav, out_wav, sigma=1.0)
        out_info = read_wav(out_wav)

        assert out_info.sample_width == sample_width
        assert out_info.frame_count == 22050

    @pytest.mark.parametrize("sample_width", [1, 2, 3, 4])
    def test_amplitude_scaling_preserves_pcm_width(self, temp_dir: Path, sample_width: int) -> None:
        """Test 5: Verify amplitude scaling preserves sample width and structure."""
        cfg = BenchmarkCarrierConfig(duration_seconds=0.5, sample_rate=44100, sample_width=sample_width)
        in_wav = temp_dir / f"in_scale_{sample_width}.wav"
        out_wav = temp_dir / f"out_scale_{sample_width}.wav"
        generate_carrier_wav(cfg, in_wav)

        apply_transformation_amplitude_scaling(in_wav, out_wav, scale_factor=0.90)
        out_info = read_wav(out_wav)

        assert out_info.sample_width == sample_width
        assert out_info.frame_count == 22050

    def test_stereo_resampling_without_channel_mixing(self, temp_dir: Path) -> None:
        """Test 6: Verify stereo resampling processes each channel independently without mixing."""
        sr = 44100
        n_frames = 44100
        t = np.linspace(0, 1, n_frames, endpoint=False)
        # Distinct frequencies in left and right channels
        ch0 = np.sin(2 * np.pi * 300 * t) * 15000.0
        ch1 = np.sin(2 * np.pi * 1200 * t) * 20000.0
        stereo_samples = np.column_stack([ch0, ch1]).reshape(-1)
        raw_bytes = encode_pcm_samples(stereo_samples, 2)

        in_wav = temp_dir / "stereo_orig.wav"
        out_wav = temp_dir / "stereo_resampled.wav"
        write_wav(in_wav, raw_bytes, 2, 2, sr)

        apply_transformation_resampling(in_wav, out_wav, intermediate_rate=22050)

        out_info = read_wav(out_wav)
        assert out_info.channels == 2
        assert out_info.frame_count == n_frames

        out_samples = decode_pcm_samples(out_info.frames, 2)
        out_ch0 = out_samples[0::2]
        out_ch1 = out_samples[1::2]

        corr0 = np.corrcoef(ch0, out_ch0)[0, 1]
        corr1 = np.corrcoef(ch1, out_ch1)[0, 1]
        cross_corr = np.corrcoef(ch0, out_ch1)[0, 1]

        assert corr0 > 0.999, f"Channel 0 correlation degraded: {corr0}"
        assert corr1 > 0.999, f"Channel 1 correlation degraded: {corr1}"
        assert abs(cross_corr) < 0.05, f"Channel cross-talk detected: {cross_corr}"


# ---------------------------------------------------------------------------
# Test 7, 8, 9: Validation, Trial Handling, and Tracemalloc Cleanup
# ---------------------------------------------------------------------------

class TestValidationAndResourceManagement:
    """Tests 7, 8, 9: Parameter validation and deterministic resource cleanup."""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"duration_seconds": -5.0},
            {"duration_seconds": 0.0},
            {"duration_seconds": float("nan")},
            {"duration_seconds": float("inf")},
            {"duration_seconds": True},
            {"sample_rate": 4000},
            {"sample_rate": 500000},
            {"channels": 3},
            {"channels": 0},
            {"sample_width": 5},
            {"sample_width": 0},
        ],
    )
    def test_invalid_benchmark_configuration_rejection(self, kwargs: dict) -> None:
        """Test 7: Verify rejection of invalid BenchmarkCarrierConfig parameters."""
        cfg = BenchmarkCarrierConfig(**kwargs)
        with pytest.raises(ValueError):
            validate_carrier_config(cfg)

    @pytest.mark.parametrize("invalid_trials", [0, -1, -10, True, False, "1", float("nan"), float("inf")])
    def test_invalid_trials_rejection(self, invalid_trials: Any) -> None:
        """Test 8: Verify rejection of trials=0, negative trials, boolean trials, NaN, and Infinity."""
        with pytest.raises(ValueError):
            validate_trials(invalid_trials)

    def test_tracemalloc_cleanup_after_exceptions(self, temp_dir: Path) -> None:
        """Test 9: Verify tracemalloc is stopped safely even if an embedding error occurs."""
        bad_carrier = temp_dir / "bad.wav"
        bad_carrier.write_bytes(b"NOT A REAL WAV CONTAINER")

        # Prior state: tracemalloc should not be running
        if tracemalloc.is_tracing():
            tracemalloc.stop()

        res = run_algorithm_benchmark(
            carrier_path=bad_carrier,
            algorithm="lsb",
            options={},
            message="Test",
            trials=1,
        )

        assert res.status == "ERROR"
        assert not tracemalloc.is_tracing(), "tracemalloc was left running after exception!"


# ---------------------------------------------------------------------------
# Test 10, 11, 12, 13, 14: Tamper Rejection and Failure Classifications
# ---------------------------------------------------------------------------

class TestTamperExperimentsAndFailureClassifications:
    """Tests 10, 11, 12, 13, 14: Verification of distinct integrity failure classifications."""

    def test_crc32_failure_classification(self, standard_carrier: Path, temp_dir: Path) -> None:
        """Test 10: Verify framing CRC32 corruption is classified as CHECKSUM_FAILED."""
        stego_path = temp_dir / "stego_lsb.wav"
        embed_message(standard_carrier, stego_path, "CryptAudio", "Pass123!", "lsb")

        stego_data = read_wav(stego_path)
        raw = bytearray(stego_data.frames)
        # CSMA header is 18 bytes (144 bits). Flip sample index 150 (in payload).
        raw[150 * 2] ^= 1
        tamper_wav = temp_dir / "crc_tamper.wav"
        write_wav(tamper_wav, bytes(raw), stego_data.channels, stego_data.sample_width, stego_data.sample_rate)

        # Extraction must fail with CRC32 mismatch
        with pytest.raises(Exception) as exc_info:
            extract_message_detailed(tamper_wav, "Pass123!", "lsb")

        err = exc_info.value
        assert isinstance(err.__cause__, CorruptedPayloadError) or "crc32" in str(err).lower()

    def test_aes_gcm_authentication_failure_classification(self, standard_carrier: Path, temp_dir: Path) -> None:
        """Test 11 & 14: Verify genuine ciphertext tampering with recomputed CRC32 fails at AES-GCM."""
        stego_path = temp_dir / "stego_lsb.wav"
        embed_message(standard_carrier, stego_path, "CryptAudio", "Pass123!", "lsb")

        algo_instance = _resolve_algorithm("lsb")
        extracted = algo_instance.extract(read_wav(stego_path))
        tampered_payload = bytearray(extracted.payload)
        tampered_payload[34] ^= 0x01  # Flip 1 bit in ciphertext

        # Re-embed with algo_instance.embed() to construct valid CSMA framing matching tampered payload
        c_data = read_wav(standard_carrier)
        re_embedded = algo_instance.embed(c_data, bytes(tampered_payload))
        cipher_tamper_wav = temp_dir / "cipher_tamper.wav"
        write_wav(
            cipher_tamper_wav,
            re_embedded.modified_wav.frames,
            c_data.channels,
            c_data.sample_width,
            c_data.sample_rate,
        )

        with pytest.raises(Exception) as exc_info:
            extract_message_detailed(cipher_tamper_wav, "Pass123!", "lsb")

        err = exc_info.value
        assert isinstance(err.__cause__, DecryptionError) or "authentication or decryption failed" in str(err).lower()

    def test_synchronization_failure_classification(self, standard_carrier: Path, temp_dir: Path) -> None:
        """Test 12: Verify sync corruption is classified as SYNC_FAILED."""
        stego_path = temp_dir / "stego_lsb.wav"
        embed_message(standard_carrier, stego_path, "CryptAudio", "Pass123!", "lsb")

        stego_data = read_wav(stego_path)
        raw = bytearray(stego_data.frames)
        raw[0] ^= 1  # Flip sample 0 (sync bit)
        sync_tamper_wav = temp_dir / "sync_tamper.wav"
        write_wav(sync_tamper_wav, bytes(raw), stego_data.channels, stego_data.sample_width, stego_data.sample_rate)

        with pytest.raises(Exception) as exc_info:
            extract_message_detailed(sync_tamper_wav, "Pass123!", "lsb")

        err = exc_info.value
        assert isinstance(err.__cause__, (SynchronizationError, HeaderNotFoundError)) or "synchronization" in str(err).lower()

    def test_wrong_password_rejection(self, standard_carrier: Path, temp_dir: Path) -> None:
        """Test 13: Verify wrong password rejection independently from corruption."""
        stego_path = temp_dir / "stego_lsb.wav"
        embed_message(standard_carrier, stego_path, "CryptAudio", "Pass123!", "lsb")

        with pytest.raises(Exception) as exc_info:
            extract_message_detailed(stego_path, "WrongPassword999!", "lsb")

        err = exc_info.value
        assert isinstance(err.__cause__, DecryptionError) or "authentication or decryption failed" in str(err).lower()

    def test_evaluate_tamper_experiments_four_outcomes(self, standard_carrier: Path, temp_dir: Path) -> None:
        """Test 14: Verify evaluate_tamper_experiments returns all 4 distinct rejection booleans."""
        stego_path = temp_dir / "stego_dwt.wav"
        embed_message(standard_carrier, stego_path, "CryptAudio", "Pass123!", "dwt_dct_qim", delta=32)

        wrong_pwd, sync_rej, crc_rej, cipher_rej = evaluate_tamper_experiments(
            carrier_path=standard_carrier,
            stego_path=stego_path,
            algorithm="dwt_dct_qim",
            password="Pass123!",
            options={"delta": 32},
            temp_dir=temp_dir,
        )

        assert wrong_pwd is True, "Wrong password was not rejected!"
        assert sync_rej is True, "Synchronization corruption was not rejected!"
        assert crc_rej is True, "CRC32 checksum corruption was not rejected!"
        assert cipher_rej is True, "Ciphertext tampering with valid framing was not rejected!"


# ---------------------------------------------------------------------------
# Test 15: Exact Capacity Boundaries
# ---------------------------------------------------------------------------

class TestExactCapacityBoundaries:
    """Test 15: Exact mathematical capacity boundaries for all 3 algorithms."""

    def test_exact_capacity_boundaries(self, standard_carrier: Path) -> None:
        """
        Verify exact available bits, raw capacity, usable payload, and max message sizes:
        - Carrier: 33.0s, 44100 Hz, 1 channel -> 1,455,300 samples.
        - CSMA framing header: 18 bytes (144 bits).
        - Minimum AES-GCM crypto overhead: 49 bytes.
        """
        msg = "CryptAudio"  # 10 bytes

        # LSB
        lsb_cap = estimate_capacity(standard_carrier, msg, "lsb")
        assert lsb_cap.available_bits == 1455300
        assert lsb_cap.required_bits == (10 + 49) * 8 + 144  # 616 bits
        assert lsb_cap.can_fit is True

        # DWT-DCT-QIM
        # 1,455,300 // 1024 = 1,421 chunks * 16 bits = 22,736 bits
        dwt_cap = estimate_capacity(standard_carrier, msg, "dwt_dct_qim", delta=32)
        assert dwt_cap.available_bits == 22736
        assert dwt_cap.required_bits == 616
        assert dwt_cap.can_fit is True

        # Echo Hiding
        # 1,455,300 // 2048 = 710 segments * 1 bit = 710 bits
        echo_cap = estimate_capacity(standard_carrier, msg, "echo", alpha=0.08)
        assert echo_cap.available_bits == 710
        assert echo_cap.required_bits == 616
        assert echo_cap.can_fit is True


# ---------------------------------------------------------------------------
# Test 16 - 28: Reporting, Consistency, Data-Driven Verification & Tool Handling (Phase M7.2)
# ---------------------------------------------------------------------------

def _make_synthetic_result(
    algorithm_id: str,
    options: dict,
    status: str = "SUCCESS",
    carrier_duration: float = 33.0,
    total_samples: int = 1455300,
    sample_rate: int = 44100,
    channels: int = 1,
    raw_capacity_bits: int = 22736,
    raw_capacity_bytes: int = 2842,
    psnr_db: Optional[float] = 104.5,
    snr_db: Optional[float] = 100.2,
    mse: Optional[float] = 0.0001,
    modification_percent: Optional[float] = 0.05,
    correlation: Optional[float] = 0.999999,
    pipeline_time: float = 0.28,
    noise_status: str = "SURVIVED",
    scale_status: str = "SYNC_FAILED",
    resample_status: str = "SYNC_FAILED",
    lossy_status: str = "NOT TESTED",
    missing_metrics: bool = False,
    include_accuracy: bool = True,
    include_robustness: bool = True,
    custom_robustness: Optional[list] = None,
) -> AlgorithmBenchmarkResult:
    if missing_metrics:
        return AlgorithmBenchmarkResult(
            algorithm_id=algorithm_id,
            algorithm_name=algorithm_id.upper(),
            options=options,
            status=status,
            carrier_name="synthetic.wav",
            carrier_duration_seconds=carrier_duration,
            message_length_bytes=10,
            error_message="Insufficient capacity" if status != "SUCCESS" else None,
            capacity=None,
            quality=None,
            performance=None,
            accuracy=None,
            robustness=[],
        )

    cap = CapacityMetrics(
        duration_seconds=carrier_duration,
        sample_rate=sample_rate,
        channels=channels,
        total_samples=total_samples,
        raw_capacity_bits=raw_capacity_bits,
        raw_capacity_bytes=raw_capacity_bytes,
        usable_payload_capacity_bytes=raw_capacity_bytes - 18,
        max_embeddable_message_bytes=raw_capacity_bytes - 67,
        required_bits=616,
        available_bits=raw_capacity_bits,
        utilization_percent=round((616 / raw_capacity_bits) * 100, 3) if raw_capacity_bits else 0.0,
    )
    qual = QualityMetrics(
        mse=mse if mse is not None else 0.0,
        snr_db=snr_db if snr_db is not None else 0.0,
        psnr_db=psnr_db if psnr_db is not None else 0.0,
        correlation=correlation if correlation is not None else 1.0,
        modified_samples=100 if modification_percent is not None else 0,
        total_samples=total_samples,
        modification_percent=modification_percent if modification_percent is not None else 0.0,
        max_absolute_difference=1.0,
        average_absolute_difference=0.01,
        quality_rating="Excellent",
    )
    # Allow overriding fields to None for edge case testing
    if psnr_db is None:
        qual.psnr_db = None  # type: ignore[assignment]
    if snr_db is None:
        qual.snr_db = None  # type: ignore[assignment]
    if mse is None:
        qual.mse = None  # type: ignore[assignment]
    if modification_percent is None:
        qual.modification_percent = None  # type: ignore[assignment]
    if correlation is None:
        qual.correlation = None  # type: ignore[assignment]

    perf = PerformanceMetrics(
        embed_time_seconds=pipeline_time * 0.6,
        embed_time_std_seconds=0.002,
        extract_time_seconds=pipeline_time * 0.4,
        extract_time_std_seconds=0.002,
        total_pipeline_time_seconds=pipeline_time,
        peak_traced_memory_bytes=2500000,
        peak_traced_memory_mb=2.5,
        trials_completed=1,
        trials_requested=1,
    )
    acc = AccuracyMetrics(
        extraction_success=True,
        exact_match=True,
        algorithm_identified=algorithm_id,
        algorithm_match=True,
        authentication_verified=True,
        wrong_password_rejected=True,
        sync_corruption_rejected=True,
        checksum_corruption_rejected=True,
        ciphertext_tamper_rejected=True,
    ) if include_accuracy else None

    if custom_robustness is not None:
        rob = custom_robustness
    elif include_robustness:
        rob = [
            RobustnessResult(transformation_name="Unmodified WAV", transformation_description="Baseline", status="SURVIVED", extracted_successfully=True, exact_match=True, notes="100% exact match"),
            RobustnessResult(transformation_name="Additive Gaussian Noise", transformation_description="Noise", status=noise_status, extracted_successfully=(noise_status == "SURVIVED"), exact_match=(noise_status == "SURVIVED"), notes="Noise test"),
            RobustnessResult(transformation_name="Amplitude Scaling", transformation_description="Scale", status=scale_status, extracted_successfully=(scale_status == "SURVIVED"), exact_match=(scale_status == "SURVIVED"), notes="Scale test"),
            RobustnessResult(transformation_name="Resampling", transformation_description="Resample", status=resample_status, extracted_successfully=(resample_status == "SURVIVED"), exact_match=(resample_status == "SURVIVED"), notes="Resample test"),
            RobustnessResult(transformation_name="Lossy Compression", transformation_description="Lossy", status=lossy_status, extracted_successfully=False, exact_match=False, notes="Lossy test"),
        ]
    else:
        rob = []

    return AlgorithmBenchmarkResult(
        algorithm_id=algorithm_id,
        algorithm_name=algorithm_id.upper(),
        options=options,
        status=status,
        carrier_name="synthetic.wav",
        carrier_duration_seconds=carrier_duration,
        message_length_bytes=10,
        error_message=None if status == "SUCCESS" else "Error",
        capacity=cap,
        quality=qual,
        performance=perf,
        accuracy=acc,
        robustness=rob,
    )


def _make_synthetic_suite(
    carrier_duration: float = 33.0,
    total_samples: int = 1455300,
    dwt_delta16_noise_status: str = "SURVIVED",
    include_missing_metrics: bool = False,
) -> BenchmarkSuiteResult:
    results = [
        _make_synthetic_result(
            algorithm_id="lsb",
            options={},
            raw_capacity_bits=total_samples,
            raw_capacity_bytes=total_samples // 8,
            psnr_db=127.1,
            snr_db=122.7,
            mse=0.000001,
            pipeline_time=0.24,
            noise_status="SYNC_FAILED",
            scale_status="SYNC_FAILED",
            resample_status="SYNC_FAILED",
            carrier_duration=carrier_duration,
            total_samples=total_samples,
        ),
        _make_synthetic_result(
            algorithm_id="dwt_dct_qim",
            options={"delta": 16},
            raw_capacity_bits=(total_samples // 1024) * 16,
            raw_capacity_bytes=((total_samples // 1024) * 16) // 8,
            psnr_db=110.2,
            snr_db=105.7,
            mse=0.00005,
            pipeline_time=0.29,
            noise_status=dwt_delta16_noise_status,
            scale_status="SYNC_FAILED",
            resample_status="SYNC_FAILED",
            carrier_duration=carrier_duration,
            total_samples=total_samples,
        ),
        _make_synthetic_result(
            algorithm_id="dwt_dct_qim",
            options={"delta": 32},
            raw_capacity_bits=(total_samples // 1024) * 16,
            raw_capacity_bytes=((total_samples // 1024) * 16) // 8,
            psnr_db=104.6,
            snr_db=100.2,
            mse=0.0001,
            pipeline_time=0.28,
            noise_status="SURVIVED",
            scale_status="SYNC_FAILED",
            resample_status="SYNC_FAILED",
            carrier_duration=carrier_duration,
            total_samples=total_samples,
        ),
        _make_synthetic_result(
            algorithm_id="echo",
            options={"alpha": 0.08},
            raw_capacity_bits=total_samples // 2048,
            raw_capacity_bytes=(total_samples // 2048) // 8,
            psnr_db=27.0,
            snr_db=22.6,
            mse=0.005,
            pipeline_time=0.38,
            noise_status="SURVIVED",
            scale_status="SURVIVED",
            resample_status="SYNC_FAILED",
            carrier_duration=carrier_duration,
            total_samples=total_samples,
        ),
    ]

    if include_missing_metrics:
        results.append(
            _make_synthetic_result(
                algorithm_id="echo",
                options={"alpha": 0.08},
                status="CAPACITY_INSUFFICIENT",
                carrier_duration=1.0,
                total_samples=44100,
                missing_metrics=True,
            )
        )

    sys_info = get_system_environment_info()
    return BenchmarkSuiteResult(
        timestamp="2026-11-18T21:00:00Z",
        system_info=sys_info,
        results=results,
    )


class TestReportConsistencyAndAccuracy:
    """M7.2 Required report consistency and accuracy tests (Items 1-12 + Regression)."""

    def test_json_and_csv_algorithm_identifiers_match(self, temp_dir: Path) -> None:
        """Requirement 1: JSON and CSV algorithm identifiers match."""
        suite = _make_synthetic_suite(include_missing_metrics=True)
        json_path = temp_dir / "report.json"
        csv_path = temp_dir / "report.csv"
        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)

        with open(json_path, encoding="utf-8") as f:
            j_data = json.load(f)
        with open(csv_path, encoding="utf-8") as f:
            c_rows = list(csv.DictReader(f))

        assert len(j_data["results"]) == len(c_rows)
        for j_res, c_row in zip(j_data["results"], c_rows):
            assert j_res["algorithm_id"] == c_row["Algorithm"]

    def test_json_and_csv_statuses_match(self, temp_dir: Path) -> None:
        """Requirement 2: JSON and CSV statuses match."""
        suite = _make_synthetic_suite(include_missing_metrics=True)
        json_path = temp_dir / "report.json"
        csv_path = temp_dir / "report.csv"
        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)

        with open(json_path, encoding="utf-8") as f:
            j_data = json.load(f)
        with open(csv_path, encoding="utf-8") as f:
            c_rows = list(csv.DictReader(f))

        for j_res, c_row in zip(j_data["results"], c_rows):
            assert j_res["status"] == c_row["Status"]

    def test_json_and_csv_capacity_values_match(self, temp_dir: Path) -> None:
        """Requirement 3: JSON and CSV capacity values match."""
        suite = _make_synthetic_suite(include_missing_metrics=True)
        json_path = temp_dir / "report.json"
        csv_path = temp_dir / "report.csv"
        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)

        with open(json_path, encoding="utf-8") as f:
            j_data = json.load(f)
        with open(csv_path, encoding="utf-8") as f:
            c_rows = list(csv.DictReader(f))

        for j_res, c_row in zip(j_data["results"], c_rows):
            if j_res["capacity"]:
                assert str(j_res["capacity"]["raw_capacity_bits"]) == c_row["Raw Capacity (bits)"]
                assert str(j_res["capacity"]["raw_capacity_bytes"]) == c_row["Raw Capacity (bytes)"]
                assert str(j_res["capacity"]["usable_payload_capacity_bytes"]) == c_row["Usable Payload (bytes)"]
                assert str(j_res["capacity"]["max_embeddable_message_bytes"]) == c_row["Max Plaintext Message (bytes)"]
            else:
                assert c_row["Raw Capacity (bits)"] == "N/A"
                assert c_row["Raw Capacity (bytes)"] == "N/A"

    def test_json_and_csv_quality_values_match(self, temp_dir: Path) -> None:
        """Requirement 4: JSON and CSV quality values match."""
        suite = _make_synthetic_suite(include_missing_metrics=True)
        json_path = temp_dir / "report.json"
        csv_path = temp_dir / "report.csv"
        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)

        with open(json_path, encoding="utf-8") as f:
            j_data = json.load(f)
        with open(csv_path, encoding="utf-8") as f:
            c_rows = list(csv.DictReader(f))

        for j_res, c_row in zip(j_data["results"], c_rows):
            if j_res["quality"]:
                assert float(c_row["SNR (dB)"]) == pytest.approx(j_res["quality"]["snr_db"], abs=0.01)
                assert float(c_row["PSNR (dB)"]) == pytest.approx(j_res["quality"]["psnr_db"], abs=0.01)
                assert float(c_row["MSE"]) == pytest.approx(j_res["quality"]["mse"], abs=0.000001)
                assert j_res["quality"]["quality_rating"] == c_row["Quality Rating"]
            else:
                assert c_row["PSNR (dB)"] == "N/A"
                assert c_row["SNR (dB)"] == "N/A"

    def test_markdown_capacity_values_match_source_results(self, temp_dir: Path) -> None:
        """Requirement 5: Markdown capacity values match the source result objects."""
        suite = _make_synthetic_suite()
        md_path = temp_dir / "report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        for r in suite.results:
            if r.capacity:
                assert f"{r.capacity.raw_capacity_bits:,} bits" in content
                assert f"{r.capacity.raw_capacity_bytes:,} B" in content
                assert f"{r.capacity.usable_payload_capacity_bytes:,} B" in content
                assert f"{r.capacity.max_embeddable_message_bytes:,} B" in content

    def test_markdown_psnr_and_snr_values_match_source_results(self, temp_dir: Path) -> None:
        """Requirement 6: Markdown PSNR and SNR values match the source result objects."""
        suite = _make_synthetic_suite()
        md_path = temp_dir / "report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        for r in suite.results:
            if r.quality:
                assert f"{r.quality.psnr_db:.2f} dB" in content
                assert f"{r.quality.snr_db:.2f} dB" in content

    def test_markdown_reports_actual_robustness_status_for_each_configuration(self, temp_dir: Path) -> None:
        """Requirement 7: Markdown reports the actual robustness status for each configuration."""
        suite = _make_synthetic_suite()
        md_path = temp_dir / "report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        # Parse Section 9 markdown table rows and verify status per configuration and transformation
        assert "## 9. Robustness Evaluation Across Controlled Channel Transformations" in content
        section9_text = content.split("## 9. Robustness Evaluation Across Controlled Channel Transformations")[1].split("## 10.")[0]
        table_rows = [line.strip() for line in section9_text.splitlines() if line.strip().startswith("| `")]
        trans_order = [
            "Unmodified WAV",
            "Additive Gaussian Noise",
            "Amplitude Scaling",
            "Resampling",
            "Lossy Compression",
        ]
        for r in suite.results:
            p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
            prefix = f"| `{r.algorithm_id}` | `{p_str}` |"
            matching_rows = [row for row in table_rows if row.startswith(prefix)]
            assert len(matching_rows) == 1, f"Expected 1 matching table row for {prefix}, found {len(matching_rows)}"
            row_cols = [c.strip() for c in matching_rows[0].split("|")[1:-1]]
            rob_map = {rob.transformation_name: rob.status for rob in r.robustness}
            for col_idx, trans_name in enumerate(trans_order, start=2):
                expected_status = rob_map.get(trans_name, "N/A")
                cell_val = row_cols[col_idx]
                assert cell_val == f"`{expected_status}`" or cell_val == expected_status, (
                    f"Mismatch in row {prefix} col {col_idx} ({trans_name}): expected {expected_status}, got {cell_val}"
                )

    def test_quick_mode_does_not_claim_unexecuted_parameter_sweeps(self, temp_dir: Path) -> None:
        """Requirement 8: Quick mode does not claim unexecuted parameter sweeps."""
        # Create a quick-mode suite (only default parameters)
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}),
                _make_synthetic_result("dwt_dct_qim", {"delta": 32}),
                _make_synthetic_result("echo", {"alpha": 0.08}),
            ],
        )
        md_path = temp_dir / "quick_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        # In quick mode, delta=16, delta=64, alpha=0.12, alpha=0.15 should not appear in tables or observations
        assert "delta=16" not in content
        assert "delta=64" not in content
        assert "alpha=0.12" not in content
        assert "alpha=0.15" not in content

    def test_synthetic_result_with_different_carrier_duration(self, temp_dir: Path) -> None:
        """Requirement 9: A synthetic result with different carrier duration (e.g. 15.0s) is reported correctly."""
        duration_15s = 15.0
        samples_15s = int(15.0 * 44100)  # 661,500
        suite = _make_synthetic_suite(carrier_duration=duration_15s, total_samples=samples_15s)

        md_path = temp_dir / "report_15s.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert f"{duration_15s:.1f} seconds ({samples_15s:,} audio samples)" in content
        assert "33.0 seconds (1,455,300 audio samples)" not in content

    def test_result_with_missing_metrics_displays_na(self, temp_dir: Path) -> None:
        """Requirement 10: A result with missing metrics displays N/A."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result(
                    algorithm_id="echo",
                    options={"alpha": 0.08},
                    status="CAPACITY_INSUFFICIENT",
                    carrier_duration=1.0,
                    missing_metrics=True,
                )
            ],
        )

        json_path = temp_dir / "na_report.json"
        csv_path = temp_dir / "na_report.csv"
        md_path = temp_dir / "na_report.md"

        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)
        generate_markdown_report(suite, md_path)

        csv_content = csv_path.read_text(encoding="utf-8")
        md_content = md_path.read_text(encoding="utf-8")

        assert "N/A" in csv_content
        assert "N/A" in md_content

    def test_report_does_not_contain_stale_fixed_latency_or_robustness_claims(self, temp_dir: Path) -> None:
        """Requirement 11: The report does not contain stale fixed latency or robustness claims."""
        suite = _make_synthetic_suite()
        md_path = temp_dir / "report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        stale_phrases = [
            "~0.24",
            "~0.34",
            "fails under all non-zero perturbations",
            "between 98 dB and 110 dB",
            "between 21.5 dB and 27.0 dB",
            "PSNR > 125 dB and SNR > 120 dB",
            "Survives additive Gaussian white noise",
        ]
        for phrase in stale_phrases:
            assert phrase not in content, f"Stale phrase found in report: {phrase}"

    def test_canonical_status_terminology_used_throughout_report(self, temp_dir: Path) -> None:
        """Requirement 12: Canonical status terminology is used throughout the generated report."""
        suite = _make_synthetic_suite()
        md_path = temp_dir / "report.md"
        csv_path = temp_dir / "report.csv"
        generate_markdown_report(suite, md_path)
        save_csv_report(suite, csv_path)

        md_content = md_path.read_text(encoding="utf-8")
        csv_content = csv_path.read_text(encoding="utf-8")

        # Must not contain non-canonical abbreviations
        assert "AUTH_FAILED" not in md_content
        assert "AUTH_FAILED" not in csv_content
        assert "CRC_FAILED" not in md_content
        assert "CRC_FAILED" not in csv_content

    def test_regression_dwt_delta_16_survived_reported_as_survived(self, temp_dir: Path) -> None:
        """Regression Test: A DWT delta=16 result marked SURVIVED is reported as SURVIVED, not AUTHENTICATION_FAILED."""
        suite = _make_synthetic_suite(dwt_delta16_noise_status="SURVIVED")
        md_path = temp_dir / "report_dwt16_survived.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        # In section 9, delta=16 should report SURVIVED for noise, not AUTHENTICATION_FAILED
        assert "delta=16 (Noise: `SURVIVED`" in content
        assert "When $\\Delta = 16$, fine quantization noise leads to `AUTHENTICATION_FAILED`" not in content
        assert "When delta = 16, fine quantization noise leads to AUTHENTICATION_FAILED" not in content

    def test_empty_benchmark_suite(self, temp_dir: Path) -> None:
        """Regression: Generating reports for an empty benchmark suite behaves safely."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[],
        )
        json_path = temp_dir / "empty_report.json"
        csv_path = temp_dir / "empty_report.csv"
        md_path = temp_dir / "empty_report.md"

        save_json_report(suite, json_path)
        save_csv_report(suite, csv_path)
        generate_markdown_report(suite, md_path)

        with open(json_path, encoding="utf-8") as f:
            j_data = json.load(f)
        assert j_data["results"] == []

        with open(csv_path, encoding="utf-8") as f:
            c_rows = list(csv.DictReader(f))
        assert len(c_rows) == 0

        md_content = md_path.read_text(encoding="utf-8")
        assert "A total of 0 configurations were executed" in md_content
        assert "No configurations completed embedding with status `SUCCESS`" in md_content
        assert "Carrier format metadata unavailable in this report." in md_content
        assert "Integrity evaluations were conducted on 0 of 0 evaluated configuration(s)" in md_content
        assert "Robustness evaluations were recorded for 0 of 0 configuration(s)" in md_content

    def test_no_successful_configurations(self, temp_dir: Path) -> None:
        """Regression: Suite with only CAPACITY_INSUFFICIENT does not claim authenticated extraction."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result(
                    "echo",
                    {"alpha": 0.08},
                    status="CAPACITY_INSUFFICIENT",
                    carrier_duration=1.0,
                    missing_metrics=True,
                )
            ],
        )
        md_path = temp_dir / "no_success_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "No configurations completed embedding with status `SUCCESS`; integrity evaluation was unavailable." in content
        assert "100%" not in content
        assert "Integrity evaluations were conducted on 0 of 1 evaluated configuration(s)" in content

    def test_successful_configuration_without_accuracy_data(self, temp_dir: Path) -> None:
        """Regression: A SUCCESS embedding without accuracy metrics does not claim 100% or exact recovery."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result(
                    "lsb",
                    {},
                    status="SUCCESS",
                    include_accuracy=False,
                )
            ],
        )
        md_path = temp_dir / "no_acc_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "1 configuration(s) completed embedding with status `SUCCESS`; however, integrity and authenticated extraction evaluation data was unavailable in this run." in content
        assert "Exact plaintext recovery was achieved" not in content
        assert "Integrity evaluations were conducted on 0 of 1 evaluated configuration(s)" in content

    def test_capacity_insufficient_configuration_without_accuracy_data(self, temp_dir: Path) -> None:
        """Regression: Capacity-insufficient runs are explicitly excluded from integrity evaluations."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, status="SUCCESS", include_accuracy=True),
                _make_synthetic_result("echo", {"alpha": 0.08}, status="CAPACITY_INSUFFICIENT", missing_metrics=True),
            ],
        )
        md_path = temp_dir / "insufficient_acc_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "Integrity evaluations were conducted on 1 of 2 evaluated configuration(s)" in content
        assert "Configurations with status `CAPACITY_INSUFFICIENT` did not produce stego audio and therefore did not undergo integrity testing." in content

    def test_configuration_without_robustness_records(self, temp_dir: Path) -> None:
        """Regression: Configurations without robustness records report coverage and display N/A."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, status="SUCCESS", include_robustness=False),
            ],
        )
        md_path = temp_dir / "no_rob_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "Robustness evaluations were recorded for 0 of 1 configuration(s) (1 configuration(s) had no robustness records)." in content
        assert "1. **LSB Robustness:** Not evaluated in this run." in content

    def test_mixed_not_tested_and_evaluated_robustness_statuses(self, temp_dir: Path) -> None:
        """Regression: Mixed NOT TESTED and active evaluations are counted separately and safely."""
        custom_rob = [
            RobustnessResult("Unmodified WAV", "Base", "SURVIVED", True, True, "OK"),
            RobustnessResult("Additive Gaussian Noise", "Noise", "SURVIVED", True, True, "OK"),
            RobustnessResult("Amplitude Scaling", "Scale", "SYNC_FAILED", False, False, "Fail"),
            RobustnessResult("Resampling", "Resample", "NOT TESTED", False, False, "No tool"),
            RobustnessResult("Lossy Compression", "Lossy", "NOT TESTED", False, False, "No tool"),
        ]
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, status="SUCCESS", custom_robustness=custom_rob),
            ],
        )
        md_path = temp_dir / "mixed_rob_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "3 transformation test(s) were actively evaluated" in content
        assert "2 record(s) were classified as `NOT TESTED`" in content
        assert "not interpreted as failures" in content

    def test_psnr_available_but_snr_missing(self, temp_dir: Path) -> None:
        """Regression: PSNR available while SNR is None does not raise and formats correctly."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, psnr_db=125.4, snr_db=None, modification_percent=0.03),
            ],
        )
        md_path = temp_dir / "psnr_only_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "PSNR: 125.40 dB" in content
        assert "SNR: Not evaluated" in content
        assert "modifying 0.03% of samples" in content

    def test_psnr_available_but_modification_percent_missing(self, temp_dir: Path) -> None:
        """Regression: PSNR available while modification percentage is None formats correctly."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, psnr_db=125.4, snr_db=120.1, modification_percent=None),
            ],
        )
        md_path = temp_dir / "mod_missing_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "PSNR: 125.40 dB" in content
        assert "SNR: 120.10 dB" in content
        assert "sample modification percentage: Not evaluated" in content

    def test_all_optional_quality_metrics_missing(self, temp_dir: Path) -> None:
        """Regression: Complete absence of optional quality metrics is handled safely."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result(
                    "dwt_dct_qim",
                    {"delta": 32},
                    psnr_db=None,
                    snr_db=None,
                    mse=None,
                    modification_percent=None,
                    correlation=None,
                ),
            ],
        )
        md_path = temp_dir / "all_quality_missing_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "PSNR: Not evaluated" in content
        assert "SNR: Not evaluated" in content
        assert "sample modification percentage: Not evaluated" in content

    def test_configurable_carrier_metadata_rendered_correctly(self, temp_dir: Path) -> None:
        """Regression: Custom sample rate and channels are rendered without hardcoded 44.1k mono assumptions."""
        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[
                _make_synthetic_result("lsb", {}, sample_rate=48000, channels=2),
            ],
        )
        md_path = temp_dir / "custom_carrier_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "48,000 Hz, 2-channel (Stereo)" in content
        assert "Sample format / bit depth metadata unavailable in this result schema." in content
        assert "44,100 Hz, 16-bit Signed PCM, Mono (single-channel)" not in content

    def test_none_values_do_not_reduce_accuracy_percentage(self, temp_dir: Path) -> None:
        """Accuracy denominators: None values must not count in denominator or artificially deflate percentage."""
        acc_true = AccuracyMetrics(
            extraction_success=True,
            exact_match=True,
            algorithm_identified="lsb",
            algorithm_match=True,
            authentication_verified=True,
            wrong_password_rejected=True,
            sync_corruption_rejected=True,
            checksum_corruption_rejected=True,
            ciphertext_tamper_rejected=True,
        )
        acc_with_none = AccuracyMetrics(
            extraction_success=True,
            exact_match=None,  # Not evaluated for this configuration
            algorithm_identified="dwt_dct_qim",
            algorithm_match=True,
            authentication_verified=True,
            wrong_password_rejected=True,
            sync_corruption_rejected=True,
            checksum_corruption_rejected=True,
            ciphertext_tamper_rejected=True,
        )
        res1 = _make_synthetic_result("lsb", {})
        res1.accuracy = acc_true
        res2 = _make_synthetic_result("dwt_dct_qim", {"delta": 16})
        res2.accuracy = acc_true
        res3 = _make_synthetic_result("dwt_dct_qim", {"delta": 32})
        res3.accuracy = acc_with_none

        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res1, res2, res3],
        )
        md_path = temp_dir / "none_acc_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        # 2 configurations had True, 1 had None -> denominator must be 2, resulting in 2/2 (100.0%)
        assert "exact plaintext recovery was achieved in 2/2 (100.0%) evaluated configurations" in content
        assert "100.0% (2/2) of evaluated configurations with exact-match data yielded bit-for-bit identical recovered plaintexts" in content
        assert "66.7%" not in content

    def test_each_accuracy_metric_uses_own_evaluated_denominator(self, temp_dir: Path) -> None:
        """Each accuracy metric computes its denominator independently from other metrics."""
        # Config 1: wrong_pwd=True, sync=True, chk=True, tamper=True
        acc1 = AccuracyMetrics(
            extraction_success=True,
            exact_match=True,
            algorithm_identified="lsb",
            algorithm_match=True,
            authentication_verified=True,
            wrong_password_rejected=True,
            sync_corruption_rejected=True,
            checksum_corruption_rejected=True,
            ciphertext_tamper_rejected=True,
        )
        # Config 2: wrong_pwd=False, sync=None, chk=True, tamper=None
        acc2 = AccuracyMetrics(
            extraction_success=True,
            exact_match=True,
            algorithm_identified="dwt_dct_qim",
            algorithm_match=True,
            authentication_verified=True,
            wrong_password_rejected=False,
            sync_corruption_rejected=None,
            checksum_corruption_rejected=True,
            ciphertext_tamper_rejected=None,
        )
        # Config 3: wrong_pwd=True, sync=True, chk=None, tamper=None
        acc3 = AccuracyMetrics(
            extraction_success=True,
            exact_match=True,
            algorithm_identified="echo",
            algorithm_match=True,
            authentication_verified=True,
            wrong_password_rejected=True,
            sync_corruption_rejected=True,
            checksum_corruption_rejected=None,
            ciphertext_tamper_rejected=None,
        )
        res1 = _make_synthetic_result("lsb", {})
        res1.accuracy = acc1
        res2 = _make_synthetic_result("dwt_dct_qim", {"delta": 16})
        res2.accuracy = acc2
        res3 = _make_synthetic_result("echo", {"alpha": 0.08})
        res3.accuracy = acc3

        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res1, res2, res3],
        )
        md_path = temp_dir / "indep_denom_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        # Wrong Password: 2 passed out of 3 evaluated (66.7%)
        assert "- **Wrong Password Rejection:** 2/3 (66.7%) evaluated configurations passed." in content
        # Sync Corruption: 2 passed out of 2 evaluated (100.0%)
        assert "- **Sync Corruption Rejection:** 2/2 (100.0%) evaluated configurations passed." in content
        # Checksum Corruption: 2 passed out of 2 evaluated (100.0%)
        assert "- **Checksum Corruption Rejection:** 2/2 (100.0%) evaluated configurations passed." in content
        # Ciphertext Tampering: 1 passed out of 1 evaluated (100.0%)
        assert "- **Ciphertext Tampering Rejection:** 1/1 (100.0%) evaluated configurations passed." in content

    def test_zero_evaluated_accuracy_values_produce_not_evaluated(self, temp_dir: Path) -> None:
        """When an accuracy metric has zero evaluated (True/False) values, it outputs 'Not evaluated in this run.'"""
        acc_all_none = AccuracyMetrics(
            extraction_success=None,
            exact_match=None,
            algorithm_identified="none",
            algorithm_match=None,
            authentication_verified=None,
            wrong_password_rejected=None,
            sync_corruption_rejected=None,
            checksum_corruption_rejected=None,
            ciphertext_tamper_rejected=None,
        )
        res = _make_synthetic_result("lsb", {})
        res.accuracy = acc_all_none

        suite = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res],
        )
        md_path = temp_dir / "zero_eval_report.md"
        generate_markdown_report(suite, md_path)
        content = md_path.read_text(encoding="utf-8")

        assert "- **Wrong Password Rejection:** Not evaluated in this run." in content
        assert "- **Sync Corruption Rejection:** Not evaluated in this run." in content
        assert "- **Checksum Corruption Rejection:** Not evaluated in this run." in content
        assert "- **Ciphertext Tampering Rejection:** Not evaluated in this run." in content
        assert "- **Exact Match Fidelity:** Not evaluated in this run." in content
        assert "- **Cryptographic Tamper Evidence:** Not evaluated in this run." in content
        assert "- **Checksum Separation:** Not evaluated in this run." in content

    def test_carrier_metadata_represented_accurately(self, temp_dir: Path) -> None:
        """Carrier metadata derivation: multi-type carriers and missing carrier names render accurately."""
        # 1. Multi-carrier run with speech and audio carrier
        res_speech = _make_synthetic_result("lsb", {})
        res_speech.carrier_name = "clean_speech_44k.wav"
        res_ambient = _make_synthetic_result("dwt_dct_qim", {"delta": 32})
        res_ambient.carrier_name = "forest_ambient_44k.wav"

        suite_multi = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res_speech, res_ambient],
        )
        md_multi = temp_dir / "multi_carrier_report.md"
        generate_markdown_report(suite_multi, md_multi)
        content_multi = md_multi.read_text(encoding="utf-8")

        assert "`clean_speech_44k.wav` (Speech Audio)" in content_multi
        assert "`forest_ambient_44k.wav` (Audio Carrier)" in content_multi
        assert "1. **Test Carrier Scope:** Evaluations were performed using `clean_speech_44k.wav` (Speech Audio), `forest_ambient_44k.wav` (Audio Carrier)." in content_multi

        # 2. Missing carrier name
        res_missing = _make_synthetic_result("echo", {"alpha": 0.08})
        res_missing.carrier_name = ""
        suite_missing = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res_missing],
        )
        md_missing = temp_dir / "missing_carrier_report.md"
        generate_markdown_report(suite_missing, md_missing)
        content_missing = md_missing.read_text(encoding="utf-8")

        assert "- **Carrier Signal:** Carrier description metadata unavailable in this report." in content_missing
        assert "1. **Test Carrier Scope:** Test carrier metadata was unavailable in this report." in content_missing

    def test_psnr_documentation_non_16_bit_and_generic(self, temp_dir: Path) -> None:
        """PSNR documentation: reflects sample width when specified and explains dynamic engine when unrecorded."""
        # 1. Non-16-bit PCM (24-bit PCM: sample_width=3)
        res_24bit = _make_synthetic_result("lsb", {"sample_width": 3})
        suite_24 = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res_24bit],
        )
        md_24 = temp_dir / "psnr_24bit_report.md"
        generate_markdown_report(suite_24, md_24)
        content_24 = md_24.read_text(encoding="utf-8")

        assert "$MAX = 8388607 (24-bit)$" in content_24

        # 2. Generic / schema unrecorded sample width
        res_generic = _make_synthetic_result("lsb", {})
        suite_gen = BenchmarkSuiteResult(
            timestamp="2026-11-18T21:00:00Z",
            system_info=get_system_environment_info(),
            results=[res_generic],
        )
        md_gen = temp_dir / "psnr_gen_report.md"
        generate_markdown_report(suite_gen, md_gen)
        content_gen = md_gen.read_text(encoding="utf-8")

        assert "The peak amplitude $MAX$ is determined by the audio-quality evaluation engine based on sample width" in content_gen
        assert "$MAX = 127$ for 8-bit, $MAX = 32767$ for 16-bit, $MAX = 8388607$ for 24-bit, $MAX = 2147483647$ for 32-bit PCM" in content_gen
        assert "the current run's sample width is not recorded in the report schema." in content_gen



# ---------------------------------------------------------------------------
# Test Tool Handling and CLI Execution
# ---------------------------------------------------------------------------

class TestToolHandlingAndCLI:
    """External dependency handling and CLI runner execution."""

    def test_lossy_compression_unavailable_recorded_as_not_tested(self, standard_carrier: Path, temp_dir: Path) -> None:
        """When ffmpeg and lame are missing, lossy compression returns NOT TESTED."""
        orig_which = shutil.which
        try:
            # Force shutil.which to return None for ffmpeg and lame
            shutil.which = lambda cmd: None if cmd in ("ffmpeg", "lame") else orig_which(cmd)

            out_wav = temp_dir / "lossy.wav"
            res_path, desc = apply_transformation_lossy_compression(standard_carrier, out_wav)

            assert res_path is None
            assert "not installed" in desc.lower() or "unavailable" in desc.lower()
        finally:
            shutil.which = orig_which

    def test_cli_quick_mode_and_full_mode(self, temp_dir: Path) -> None:
        """Verify CLI runner executes successfully in both quick mode and full mode."""
        script_path = Path("scripts/run_algorithm_benchmark.py").resolve()

        # 1. Quick mode test
        quick_dir = temp_dir / "quick"
        cmd_quick = [
            sys.executable,
            str(script_path),
            "--output-dir",
            str(quick_dir),
            "--quick",
            "--trials",
            "1",
        ]
        res_quick = subprocess.run(
            cmd_quick,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        assert res_quick.returncode == 0, f"Quick mode CLI error: {res_quick.stderr}"
        assert "BENCHMARK EXECUTION COMPLETE" in res_quick.stdout
        assert (quick_dir / "benchmark_report.json").is_file()
        assert (quick_dir / "benchmark_report.csv").is_file()
        assert (quick_dir / "benchmark_report.md").is_file()

        # 2. Full mode test (fast: 2.0s carrier, 1 trial)
        full_dir = temp_dir / "full"
        cmd_full = [
            sys.executable,
            str(script_path),
            "--output-dir",
            str(full_dir),
            "--carrier-duration",
            "2.0",
            "--trials",
            "1",
        ]
        res_full = subprocess.run(
            cmd_full,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        assert res_full.returncode == 0, f"Full mode CLI error: {res_full.stderr}"
        assert "BENCHMARK EXECUTION COMPLETE" in res_full.stdout
        assert (full_dir / "benchmark_report.json").is_file()
        assert (full_dir / "benchmark_report.csv").is_file()
        assert (full_dir / "benchmark_report.md").is_file()

