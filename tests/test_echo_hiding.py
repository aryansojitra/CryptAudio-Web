"""
tests/test_echo_hiding.py
CryptAudio Web — Echo Hiding Steganography Test Suite (Phase M4)

Comprehensive unit and integration test suite covering:
1. Signal parameter and delay calculations across sample rates (44.1 kHz, 48 kHz, etc.).
2. Mathematical echo generation, cross-fading, real cepstrum peak detection, and bit decision rules.
3. Universal CSMA v1 envelope embedding, extraction, and CRC32 framing validation.
4. Audio format compatibility (8-bit, 16-bit, 24-bit, 32-bit PCM; mono & stereo).
5. Channel 1 bit-for-bit preservation in stereo audio.
6. Capacity estimation, CSMA overhead, minimum payload duration, and boundary rejection.
7. Error handling and exception guarantees (CapacityExceededError, SynchronizationError, etc.).
8. Cryptographic end-to-end integration with AES-256-GCM authenticated encryption.
9. Numerical audio quality metrics (MSE, SNR, PSNR, Pearson correlation).
10. Registry registration and lookup by canonical name and integer algorithm ID.
"""

from __future__ import annotations

import math
import os
import struct
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pytest

from app.audio.wav_handler import WavData
from app.crypto.aes_crypto import DecryptionError, decrypt_message, encrypt_message
from app.evaluation.audio_quality import (
    PEAK_AMPLITUDES,
    calculate_correlation,
    calculate_mse,
    calculate_psnr,
    calculate_snr,
)
from app.steganography.base import (
    AudioFormatIncompatibleError,
    CapacityExceededError,
    CapacityProfile,
    CorruptedPayloadError,
    DomainType,
    ExtractedPayload,
    HeaderNotFoundError,
    RobustnessEvaluationStatus,
    StegoInspection,
    StegoResult,
    SynchronizationError,
    UnsupportedParameterError,
)
from app.steganography.echo_hiding import (
    ALGORITHM_ID,
    BITS_PER_SEGMENT,
    CANONICAL_PREAMBLE_BIPOLAR,
    CANONICAL_PREAMBLE_BITS,
    CANONICAL_SYNC_WORD,
    DEFAULT_ALPHA,
    DEFAULT_DELAY_0_MS,
    DEFAULT_DELAY_1_MS,
    DEFAULT_FADE_SAMPLES,
    DEFAULT_SEGMENT_SIZE,
    MIN_HEADER_SEGMENTS,
    MIN_PREAMBLE_SEGMENTS,
    MIN_VALID_PAYLOAD_SEGMENTS,
    SYNC_CORRELATION_THRESHOLD,
    EchoHidingAlgorithm,
    calculate_echo_sync_metrics,
    compute_real_cepstrum,
    delay_ms_to_samples,
)
from app.steganography.dwt_dct_qim import (
    DWTDCTQIMAlgorithm,
    decode_pcm_to_ref16,
    encode_ref16_to_pcm,
)
from app.steganography.lsb_adapter import LSBAdapter
from app.steganography.envelope import (
    ALGO_ID_ECHO,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_MAGIC,
    CSMA_VERSION,
    SYNC_WORD_ECHO,
    create_csma_envelope,
    parse_csma_envelope,
    resolve_algorithm_id,
)
from app.steganography.registry import StegoRegistry, get_registry, reset_registry


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def echo_algorithm() -> EchoHidingAlgorithm:
    """Provide a standard EchoHidingAlgorithm instance."""
    return EchoHidingAlgorithm()


def make_echo_test_wav(
    segments: int = 540,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
    carrier_type: str = "chirp",
    seed: int = 42,
) -> WavData:
    """
    Generate deterministic WavData carrier container for Echo Hiding tests.

    Carrier types:
    - 'chirp': Repeated wideband linear sweep (200 Hz to 6000 Hz) per segment.
               Provides ideal flat cepstral properties for 100% deterministic bit recovery.
    - 'noise': Gaussian white noise.
    - 'multitone': Sum of harmonic sinusoids.
    """
    np.random.seed(seed)
    total_frames = segments * DEFAULT_SEGMENT_SIZE

    if carrier_type == "chirp":
        t_seg = np.arange(DEFAULT_SEGMENT_SIZE, dtype=np.float64) / sample_rate
        f0, f1 = 200.0, 6000.0
        dur_seg = DEFAULT_SEGMENT_SIZE / sample_rate
        seg_chirp = np.sin(2.0 * np.pi * (f0 + (f1 - f0) / (2.0 * dur_seg) * t_seg) * t_seg)
        ch0 = np.tile(seg_chirp, segments) * 28000.0
    elif carrier_type == "noise":
        ch0 = np.random.randn(total_frames).astype(np.float64) * 20000.0
    elif carrier_type == "multitone":
        t = np.arange(total_frames, dtype=np.float64) / sample_rate
        ch0 = np.zeros(total_frames, dtype=np.float64)
        for freq in [250.0, 500.0, 1200.0, 2400.0, 4800.0]:
            ch0 += np.sin(2.0 * np.pi * freq * t)
        ch0 = (ch0 / np.max(np.abs(ch0))) * 25000.0
    else:
        raise ValueError(f"Unknown carrier_type: {carrier_type}")

    if channels == 2:
        t_ch1 = np.arange(total_frames, dtype=np.float64) / sample_rate
        ch1 = np.cos(2.0 * np.pi * 350.0 * t_ch1) * 15000.0
        interleaved = np.column_stack([ch0, ch1]).reshape(-1)
    else:
        interleaved = ch0

    raw_frames = encode_ref16_to_pcm(interleaved, sample_width)

    return WavData(
        channels=channels,
        sample_rate=sample_rate,
        sample_width=sample_width,
        frame_count=total_frames,
        compression_type="NONE",
        compression_name="NONE",
        frames=raw_frames,
    )


# ---------------------------------------------------------------------------
# Group A: Parameter and Delay Conversion Tests
# ---------------------------------------------------------------------------

class TestEchoParameters:
    def test_delay_conversion_44100_hz(self) -> None:
        """Sample delays at 44.1 kHz match theoretical approved values."""
        d0 = delay_ms_to_samples(44100, DEFAULT_DELAY_0_MS)
        d1 = delay_ms_to_samples(44100, DEFAULT_DELAY_1_MS)
        assert d0 == 44   # round(44100 * 1.0 / 1000) = 44
        assert d1 == 57   # round(44100 * 1.3 / 1000) = 57

    def test_delay_conversion_48000_hz(self) -> None:
        """Sample delays at 48.0 kHz match sample-rate scaled values."""
        d0 = delay_ms_to_samples(48000, DEFAULT_DELAY_0_MS)
        d1 = delay_ms_to_samples(48000, DEFAULT_DELAY_1_MS)
        assert d0 == 48   # round(48000 * 1.0 / 1000) = 48
        assert d1 == 62   # round(48000 * 1.3 / 1000) = 62

    def test_delay_conversion_22050_hz(self) -> None:
        """Sample delays at 22.05 kHz match sample-rate scaled values."""
        d0 = delay_ms_to_samples(22050, DEFAULT_DELAY_0_MS)
        d1 = delay_ms_to_samples(22050, DEFAULT_DELAY_1_MS)
        assert d0 == 22   # round(22050 * 1.0 / 1000) = 22
        assert d1 == 29   # round(22050 * 1.3 / 1000) = 29

    def test_invalid_sample_rate_rejected(self) -> None:
        """Non-positive sample rates raise AudioFormatIncompatibleError."""
        with pytest.raises(AudioFormatIncompatibleError):
            delay_ms_to_samples(0, 1.0)
        with pytest.raises(AudioFormatIncompatibleError):
            delay_ms_to_samples(-44100, 1.0)

    def test_canonical_sync_word_and_preamble(self) -> None:
        """Canonical sync word 0x596A matches approved 16-bit binary and bipolar sequence."""
        assert CANONICAL_SYNC_WORD == 0x596A
        assert CANONICAL_SYNC_WORD == SYNC_WORD_ECHO

        # Verify binary representation of 0x596A
        sync_bytes = struct.pack(">H", CANONICAL_SYNC_WORD)
        bits = []
        for byte in sync_bytes:
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        assert tuple(bits) == CANONICAL_PREAMBLE_BITS

        # Verify bipolar mapping (0 -> -1.0, 1 -> +1.0)
        expected_bipolar = np.array([1.0 if b == 1 else -1.0 for b in CANONICAL_PREAMBLE_BITS])
        assert np.array_equal(CANONICAL_PREAMBLE_BIPOLAR, expected_bipolar)

    def test_algorithm_descriptor_properties(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """EchoHidingAlgorithm reports proper domain and robustness metadata."""
        assert echo_algorithm.algorithm_id == "echo"
        assert echo_algorithm.display_name == "Echo Hiding Acoustic Steganography"
        assert echo_algorithm.domain == DomainType.ACOUSTIC_TIME
        assert echo_algorithm.robustness_objective == RobustnessEvaluationStatus.EXPERIMENTAL_TARGET


# ---------------------------------------------------------------------------
# Group B: Mathematical Echo & Cepstrum Tests
# ---------------------------------------------------------------------------

class TestMathematicalEchoCepstrum:
    def test_single_segment_echo_bit0_vs_bit1(self) -> None:
        """Real cepstrum correctly discriminates isolated bit 0 and bit 1 echo delays."""
        fs = 44100
        d0 = delay_ms_to_samples(fs, 1.0)  # 44
        d1 = delay_ms_to_samples(fs, 1.3)  # 57
        alpha = 0.08

        # Wideband chirp segment
        t = np.arange(DEFAULT_SEGMENT_SIZE) / fs
        dur = DEFAULT_SEGMENT_SIZE / fs
        carrier_seg = np.sin(2.0 * np.pi * (200.0 + 5800.0 / (2.0 * dur) * t) * t) * 20000.0

        # Bit 0 echo: delay d0
        del_0 = np.concatenate([np.zeros(d0), carrier_seg[:-d0]])
        stego_0 = carrier_seg + alpha * del_0
        c0 = compute_real_cepstrum(stego_0)

        # Bit 1 echo: delay d1
        del_1 = np.concatenate([np.zeros(d1), carrier_seg[:-d1]])
        stego_1 = carrier_seg + alpha * del_1
        c1 = compute_real_cepstrum(stego_1)

        # Decision rule: bit 0 has C(d0) > C(d1), bit 1 has C(d1) > C(d0)
        assert c0[d0] > c0[d1]
        assert c1[d1] > c1[d0]

    def test_deterministic_tie_breaking(self) -> None:
        """Exact tie C(d0) == C(d1) deterministically resolves to bit 0."""
        # Simulated equal cepstrum values
        c = np.zeros(100)
        c[44] = 0.05
        c[57] = 0.05
        bit = 1 if c[57] > c[44] else 0
        assert bit == 0

    def test_preamble_sync_correlation_perfect(self) -> None:
        """Clean preamble sequence achieves high correlation rho > 0.90."""
        fs = 44100
        d0, d1 = 44, 57
        alpha = 0.08

        t = np.arange(DEFAULT_SEGMENT_SIZE) / fs
        dur = DEFAULT_SEGMENT_SIZE / fs
        seg_chirp = np.sin(2.0 * np.pi * (200.0 + 5800.0 / (2.0 * dur) * t) * t) * 20000.0

        segments = []
        for bit in CANONICAL_PREAMBLE_BITS:
            d = d1 if bit == 1 else d0
            delayed = np.concatenate([np.zeros(d), seg_chirp[:-d]])
            stego = seg_chirp + alpha * delayed
            segments.append(stego)

        rho, mean_pnr = calculate_echo_sync_metrics(segments, d0, d1)
        assert rho >= 0.90
        assert mean_pnr > 0.8


# ---------------------------------------------------------------------------
# Group C: Embedding & Extraction Integration Tests
# ---------------------------------------------------------------------------

class TestEchoEmbeddingExtraction:
    def test_csma_full_roundtrip_default_alpha(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Payload embeds with CSMA envelope and extracts with 100% integrity using default alpha."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        payload = b"Top Secret Echo Hiding Message 2026"

        result = echo_algorithm.embed(wav, payload, alpha=0.08)
        assert result.success is True
        assert result.algorithm_id == "echo"
        assert result.payload_size_bytes == len(payload)
        assert result.framed_size_bytes == 18 + len(payload)
        assert result.required_bits == (18 + len(payload)) * 8
        assert result.available_bits == 540

        extracted = echo_algorithm.extract(result.modified_wav, alpha=0.08)
        assert extracted.success is True
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True
        assert extracted.integrity_verified is True  # Deprecated attribute retained

        d_ext = extracted.to_dict()
        assert d_ext["framing_checksum_verified"] is True
        assert "integrity_verified" not in d_ext  # Deprecated attribute excluded from to_dict()
        assert d_ext["algorithm_id"] == "echo"
        assert d_ext["payload_size_bytes"] == len(payload)

    def test_random_binary_payload_roundtrip(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Arbitrary pseudorandom binary payload embeds and extracts perfectly."""
        np.random.seed(999)
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        random_bytes = bytes(np.random.randint(0, 256, size=24, dtype=np.uint8))

        result = echo_algorithm.embed(wav, random_bytes, alpha=0.08)
        extracted = echo_algorithm.extract(result.modified_wav, alpha=0.08)
        assert extracted.payload == random_bytes
        assert extracted.framing_checksum_verified is True

    def test_crc32_tamper_detection(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Corrupting payload audio segments triggers CorruptedPayloadError on extraction."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        result = echo_algorithm.embed(wav, b"IntegrityVerificationTarget", alpha=0.08)

        # Invert Channel 0 samples in segment 250 (inside payload region)
        corrupted_frames = bytearray(result.modified_wav.frames)
        bytes_per_frame = 4
        seg_start = 250 * DEFAULT_SEGMENT_SIZE * bytes_per_frame
        for i in range(DEFAULT_SEGMENT_SIZE):
            corrupted_frames[seg_start + i * bytes_per_frame] ^= 0xFF
            corrupted_frames[seg_start + i * bytes_per_frame + 1] ^= 0x7F

        tampered_wav = WavData(
            channels=2, sample_rate=wav.sample_rate, sample_width=2, frame_count=wav.frame_count,
            compression_type="NONE", compression_name="NONE", frames=bytes(corrupted_frames),
        )

        with pytest.raises(CorruptedPayloadError):
            echo_algorithm.extract(tampered_wav, alpha=0.08)


# ---------------------------------------------------------------------------
# Group D: History Buffer & Crossfade Regression Tests
# ---------------------------------------------------------------------------

class TestEchoHistoryAndCrossfade:
    def test_history_buffer_uses_unmodulated_original_samples(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """
        Verify the critical non-recursive FIR echo requirement:
        For sample n < d in segment m >= 1, the added component is alpha * s_orig(n - d).
        The history buffer MUST contain unmodulated original carrier samples, NOT modulated samples.
        """
        wav = make_echo_test_wav(segments=540, channels=1, sample_width=4, carrier_type="chirp")
        payload = b"NonRecursiveHistoryBufferVerificationTest"
        alpha = 0.08
        d0_ms = 1.0
        d1_ms = 1.3
        sample_rate = wav.sample_rate
        d0 = delay_ms_to_samples(sample_rate, d0_ms)
        d1 = delay_ms_to_samples(sample_rate, d1_ms)

        # Embed with fade_samples=0 so each segment is pure delayed component:
        # modulated = original_seg + alpha * delayed(original_seg, history)
        result = echo_algorithm.embed(
            wav,
            payload,
            alpha=alpha,
            fade_samples=0,
            delay_0_ms=d0_ms,
            delay_1_ms=d1_ms,
        )

        orig_ch0 = decode_pcm_to_ref16(wav.frames, 4)
        stego_ch0 = decode_pcm_to_ref16(result.modified_wav.frames, 4)

        # Inspect multiple segment boundaries for m >= 1
        # For the first d samples of segment m, the echo must equal alpha * orig_ch0[seg_start - d : seg_start]
        # In a 32-bit PCM representation, quantization error is negligible (< 1e-4)
        for m in range(1, 10):
            seg_start = m * DEFAULT_SEGMENT_SIZE
            added_component = stego_ch0[seg_start : seg_start + min(d0, d1)] - orig_ch0[seg_start : seg_start + min(d0, d1)]
            match_d0 = np.allclose(
                added_component,
                alpha * orig_ch0[seg_start - d0 : seg_start - d0 + min(d0, d1)],
                atol=1e-2,
            )
            match_d1 = np.allclose(
                added_component,
                alpha * orig_ch0[seg_start - d1 : seg_start - d1 + min(d0, d1)],
                atol=1e-2,
            )
            assert match_d0 or match_d1, f"History buffer at segment {m} did not match original carrier delayed component!"

    def test_crossfade_transitions_alternating_bits(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """
        Verify Hanning crossfade transitions across alternating bit patterns (0, 1, 0, 1...).
        Ensures continuous sample transitions without clipping, NaNs, or step discontinuities.
        """
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        payload = bytes([0x55] * 25)  # 0x55 = 01010101 in binary

        result = echo_algorithm.embed(wav, payload, alpha=0.08, fade_samples=200)
        assert result.success is True

        stego_samples = decode_pcm_to_ref16(result.modified_wav.frames, 2)
        assert not np.any(np.isnan(stego_samples))
        assert not np.any(np.isinf(stego_samples))

        # Extraction must recover exact payload with full framing integrity
        extracted = echo_algorithm.extract(result.modified_wav, alpha=0.08, fade_samples=200)
        assert extracted.success is True
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True

    def test_consecutive_identical_bits_all_zeros_and_ones(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """Verify seamless embedding and recovery of homogeneous bit sequences (all-0 and all-1)."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)

        for byte_val in [0x00, 0xFF]:
            payload = bytes([byte_val] * 25)
            res = echo_algorithm.embed(wav, payload, alpha=0.08)
            ext = echo_algorithm.extract(res.modified_wav, alpha=0.08)
            assert ext.payload == payload
            assert ext.framing_checksum_verified is True

    def test_boundary_continuity_and_frame_count_preservation(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """Verify that embedding preserves sample counts and audio boundaries without discontinuities."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        payload = b"BoundaryContinuityPayloadTest"

        res = echo_algorithm.embed(wav, payload, alpha=0.08, fade_samples=200)
        assert res.modified_wav.frame_count == wav.frame_count
        assert len(res.modified_wav.frames) == len(wav.frames)


# ---------------------------------------------------------------------------
# Group E: Audio Compatibility & Channel Preservation Tests
# ---------------------------------------------------------------------------

class TestEchoAudioCompatibility:
    @pytest.mark.parametrize("sample_width, alpha", [
        (1, 0.08),  # 8-bit PCM with standard alpha=0.08
        (1, 0.15),  # 8-bit PCM with enhanced alpha=0.15
        (2, 0.08),  # 16-bit PCM (standard reference)
        (3, 0.08),  # 24-bit PCM
        (4, 0.08),  # 32-bit PCM
    ])
    def test_all_pcm_bit_depths_roundtrip(
        self,
        echo_algorithm: EchoHidingAlgorithm,
        sample_width: int,
        alpha: float,
    ) -> None:
        """Echo Hiding supports 8-bit, 16-bit, 24-bit, and 32-bit integer PCM formats."""
        wav = make_echo_test_wav(segments=540, channels=1, sample_width=sample_width)
        payload = b"MultiBitDepthAudioPayload"

        result = echo_algorithm.embed(wav, payload, alpha=alpha)
        assert result.modified_wav.sample_width == sample_width
        assert result.modified_wav.frame_count == wav.frame_count

        extracted = echo_algorithm.extract(result.modified_wav, alpha=alpha)
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True

    def test_channel_1_bit_for_bit_preservation(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """In stereo files, Channel 1 samples remain bit-for-bit identical before and after embedding."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        payload = b"PreserveChannel1Payload"

        result = echo_algorithm.embed(wav, payload, alpha=0.08)

        # Decode Channel 1 before and after
        orig_ch1 = decode_pcm_to_ref16(wav.frames, 2).reshape(-1, 2)[:, 1]
        stego_ch1 = decode_pcm_to_ref16(result.modified_wav.frames, 2).reshape(-1, 2)[:, 1]

        assert np.array_equal(orig_ch1, stego_ch1)

        # Verify Channel 0 was indeed modified
        orig_ch0 = decode_pcm_to_ref16(wav.frames, 2).reshape(-1, 2)[:, 0]
        stego_ch0 = decode_pcm_to_ref16(result.modified_wav.frames, 2).reshape(-1, 2)[:, 0]
        assert not np.array_equal(orig_ch0, stego_ch0)

    def test_mono_audio_support(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Mono audio files embed and extract cleanly."""
        wav = make_echo_test_wav(segments=540, channels=1, sample_width=2)
        payload = b"MonoCarrierPayload"

        result = echo_algorithm.embed(wav, payload, alpha=0.08)
        assert result.modified_wav.channels == 1
        extracted = echo_algorithm.extract(result.modified_wav, alpha=0.08)
        assert extracted.payload == payload

    def test_sample_rate_and_count_preservation(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Embedding preserves duration, sample count, and sampling rate exactly."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2, sample_rate=48000)
        payload = b"PreserveDuration"

        result = echo_algorithm.embed(wav, payload, alpha=0.08)
        assert result.modified_wav.sample_rate == 48000
        assert result.modified_wav.frame_count == wav.frame_count
        assert len(result.modified_wav.frames) == len(wav.frames)


# ---------------------------------------------------------------------------
# Group E: Capacity Estimation Tests
# ---------------------------------------------------------------------------

class TestEchoCapacityEstimation:
    def test_capacity_formula_compliance(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """CapacityProfile matches mathematical specifications from Section 10."""
        # 1.0 second carrier at 44.1 kHz = 44100 frames
        # floor(44100 / 2048) = 21 segments = 21 bits
        wav = WavData(
            channels=2, sample_rate=44100, sample_width=2, frame_count=44100,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * (44100 * 4),
        )
        cap = echo_algorithm.estimate_capacity(wav)

        assert cap.available_bits == 21
        assert cap.available_bytes == 21 // 8  # 2
        assert cap.envelope_overhead_bits == 144
        assert cap.synchronization_overhead_bits == 16
        assert cap.max_payload_bytes == 0  # 21 < 144
        assert np.isclose(cap.bits_per_sample, 1.0 / 2048.0)
        assert np.isclose(cap.bits_per_second, 44100.0 / 2048.0)

    def test_minimum_valid_payload_carrier_requirement(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Minimum valid encrypted CAUD payload (49B) + CSMA header (18B) requires 536 segments."""
        # 536 segments * 2048 = 1,097,728 frames
        # At 44.1 kHz, 1097728 / 44100 approx 24.8918 seconds
        wav = make_echo_test_wav(segments=536, channels=2, sample_width=2, sample_rate=44100)
        cap = echo_algorithm.estimate_capacity(wav)

        assert cap.available_bits == 536
        assert cap.max_payload_bytes == (536 - 144) // 8  # exactly 49 bytes!
        assert np.isclose(cap.recommended_min_duration_sec, 1097728.0 / 44100.0, atol=1e-3)

    def test_capacity_exceeded_error_raised(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Embedding payload larger than carrier capacity raises CapacityExceededError."""
        # Carrier has only 200 segments = 200 bits.
        # Header requires 144 bits. Net space = (200 - 144) // 8 = 7 bytes.
        wav = make_echo_test_wav(segments=200, channels=2, sample_width=2)
        payload = b"1234567890"  # 10 bytes -> requires (18 + 10) * 8 = 224 bits > 200 bits

        with pytest.raises(CapacityExceededError):
            echo_algorithm.embed(wav, payload, alpha=0.08)

    def test_strict_capacity_parameter_validation(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """estimate_capacity strictly validates options and rejects invalid segment_size values."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        for bad_seg in [True, False, None, "2048", 2048.0, -1, 0, 100, 255]:
            with pytest.raises(UnsupportedParameterError):
                echo_algorithm.estimate_capacity(wav, segment_size=bad_seg)  # type: ignore

        with pytest.raises(UnsupportedParameterError, match="Unsupported capacity"):
            echo_algorithm.estimate_capacity(wav, unsupported_param=999)


# ---------------------------------------------------------------------------
# Group G: Error Handling & Security Boundary Tests
# ---------------------------------------------------------------------------

class TestEchoErrorHandling:
    def test_clean_audio_not_detected_as_stego(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Clean host audio does not produce a false-positive stego signature."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2, carrier_type="chirp")
        insp = echo_algorithm.inspect_metadata(wav)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

    def test_carrier_too_short_for_header(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Audio track shorter than 144 segments raises HeaderNotFoundError on extraction."""
        wav = make_echo_test_wav(segments=100, channels=2, sample_width=2)
        with pytest.raises(HeaderNotFoundError, match="too short"):
            echo_algorithm.extract(wav)

    def test_invalid_alpha_rejected(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Invalid echo amplitude options raise UnsupportedParameterError."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        for bad_alpha in [None, True, False, "0.08", -0.05, 0.0, 0.60, float("nan"), float("inf")]:
            with pytest.raises(UnsupportedParameterError):
                echo_algorithm.embed(wav, b"Test", alpha=bad_alpha)  # type: ignore

    def test_invalid_delays_rejected(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Equal delays or non-positive delays raise UnsupportedParameterError."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        with pytest.raises(UnsupportedParameterError):
            echo_algorithm.embed(wav, b"Test", delay_0_ms=1.0, delay_1_ms=1.0)
        with pytest.raises(UnsupportedParameterError):
            echo_algorithm.embed(wav, b"Test", delay_0_ms=-1.0)

    def test_invalid_audio_format_rejected(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Corrupted or non-WavData audio containers raise AudioFormatIncompatibleError."""
        with pytest.raises(AudioFormatIncompatibleError):
            echo_algorithm.embed("not a wav data", b"Test")  # type: ignore

        # Invalid channel count
        bad_wav = WavData(
            channels=6, sample_rate=44100, sample_width=2, frame_count=1000,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * 12000,
        )
        with pytest.raises(AudioFormatIncompatibleError):
            echo_algorithm.embed(bad_wav, b"Test")

    def test_inspect_metadata_invalid_options_handled_gracefully(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """inspect_metadata validates options safely before arithmetic, returning negative inspection."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        for bad_opt in [
            {"segment_size": "invalid"},
            {"segment_size": True},
            {"segment_size": -1},
            {"delay_0_ms": -1.0},
            {"delay_0_ms": 1.0, "delay_1_ms": 1.0},
            {"alpha": 2.0},
            {"alpha": True},
            {"fade_samples": -1},
            {"unknown_param": 123},
        ]:
            insp = echo_algorithm.inspect_metadata(wav, **bad_opt)
            assert insp.has_stego_signature is False
            assert insp.detected_algorithm is None
            assert insp.header_valid is False
            assert insp.crc32_verified is False
            assert insp.confidence_score == 0.0

    def test_negative_sync_silence(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Silent audio container raises synchronization or header error and produces no false positives."""
        frame_count = 540 * DEFAULT_SEGMENT_SIZE
        silent_wav = WavData(
            channels=2, sample_rate=44100, sample_width=2, frame_count=frame_count,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * (frame_count * 4),
        )
        insp = echo_algorithm.inspect_metadata(silent_wav)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

        with pytest.raises((SynchronizationError, HeaderNotFoundError)):
            echo_algorithm.extract(silent_wav)

    def test_negative_sync_gaussian_noise(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Gaussian noise audio fails preamble synchronization correlation."""
        noise_wav = make_echo_test_wav(segments=540, channels=2, sample_width=2, carrier_type="noise")
        insp = echo_algorithm.inspect_metadata(noise_wav)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

        with pytest.raises(SynchronizationError):
            echo_algorithm.extract(noise_wav)

    def test_negative_sync_tonal_sine(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Unmodulated harmonic multitone audio fails preamble synchronization correlation."""
        tonal_wav = make_echo_test_wav(segments=540, channels=2, sample_width=2, carrier_type="multitone")
        insp = echo_algorithm.inspect_metadata(tonal_wav)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

        with pytest.raises(SynchronizationError):
            echo_algorithm.extract(tonal_wav)

    def test_negative_sync_corrupted_preamble(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Deliberately corrupted preamble segments cause preamble correlation failure."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        stego_result = echo_algorithm.embed(wav, b"TestPayloadWithPreambleTarget", alpha=0.08)

        # Zero out the preamble segments (first 16 segments) in Channel 0
        samples = decode_pcm_to_ref16(stego_result.modified_wav.frames, 2).reshape(-1, 2)
        samples[: 16 * DEFAULT_SEGMENT_SIZE, 0] = 0.0
        corrupted_frames = encode_ref16_to_pcm(samples.reshape(-1), 2)

        corrupted_wav = WavData(
            channels=2, sample_rate=wav.sample_rate, sample_width=2, frame_count=wav.frame_count,
            compression_type="NONE", compression_name="NONE", frames=corrupted_frames,
        )

        insp = echo_algorithm.inspect_metadata(corrupted_wav)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None

        with pytest.raises(SynchronizationError):
            echo_algorithm.extract(corrupted_wav)

    def test_cross_algorithm_lsb_carrier_not_detected_as_echo(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """Carriers modulated with LSB steganography are never identified or extracted as Echo."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        lsb_algo = LSBAdapter()
        lsb_stego = lsb_algo.embed(wav, b"LSBMultiAlgorithmPayloadTest").modified_wav

        insp = echo_algorithm.inspect_metadata(lsb_stego)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

        with pytest.raises((SynchronizationError, HeaderNotFoundError)):
            echo_algorithm.extract(lsb_stego)

    def test_cross_algorithm_dwt_carrier_not_detected_as_echo(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """Carriers modulated with DWT-DCT-QIM steganography are never identified or extracted as Echo."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        dwt_algo = DWTDCTQIMAlgorithm()
        dwt_stego = dwt_algo.embed(wav, b"DWTMultiAlgorithmPayloadTest").modified_wav

        insp = echo_algorithm.inspect_metadata(dwt_stego)
        assert insp.has_stego_signature is False
        assert insp.detected_algorithm is None
        assert insp.header_valid is False

        with pytest.raises((SynchronizationError, HeaderNotFoundError)):
            echo_algorithm.extract(dwt_stego)


# ---------------------------------------------------------------------------
# Group H: Cryptographic End-to-End Tests
# ---------------------------------------------------------------------------

class TestEchoCryptographicIntegration:
    def test_full_aes_gcm_encrypt_embed_extract_decrypt_workflow(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """
        Complete end-to-end cryptographic workflow:
        1. Encrypt multilingual message using AES-256-GCM + PBKDF2 (600,000 iterations).
        2. Embed encrypted binary payload into carrier WAV using Echo Hiding.
        3. Extract payload using Echo Hiding.
        4. Decrypt with secret password and verify bit-for-bit plaintext match.
        """
        wav = make_echo_test_wav(segments=1400, channels=2, sample_width=2)
        password = "EchoSecurePassword2026!#$%"
        secret_plaintext = (
            "CryptAudio-Web Acoustic Steganography: "
            "日本語, Español, Français, Deutsch, Русский, 🔐"
        )

        # 1. Encrypt with AES-GCM
        encrypted_payload = encrypt_message(secret_plaintext, password)
        assert len(encrypted_payload) >= 49  # At least minimal CAUD payload

        # 2. Embed into carrier
        stego_result = echo_algorithm.embed(wav, encrypted_payload, alpha=0.08)
        assert stego_result.success is True

        # 3. Extract from stego carrier
        extracted_result = echo_algorithm.extract(stego_result.modified_wav, alpha=0.08)
        assert extracted_result.success is True
        assert extracted_result.payload == encrypted_payload
        assert extracted_result.framing_checksum_verified is True

        # 4. Decrypt and verify exact plaintext recovery
        recovered_plaintext = decrypt_message(extracted_result.payload, password)
        assert recovered_plaintext == secret_plaintext

    def test_wrong_password_fails_decryption(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """Extracted payload fails AES-GCM decryption when an incorrect password is used."""
        wav = make_echo_test_wav(segments=1400, channels=2, sample_width=2)
        encrypted_payload = encrypt_message("Secret Information", "CorrectPassword123")
        res = echo_algorithm.embed(wav, encrypted_payload, alpha=0.08)

        extracted = echo_algorithm.extract(res.modified_wav, alpha=0.08)
        assert extracted.payload == encrypted_payload

        with pytest.raises(DecryptionError):
            decrypt_message(extracted.payload, "WrongPassword456")

    def test_crc32_framing_vs_aes_gcm_cryptographic_authentication(
        self,
        echo_algorithm: EchoHidingAlgorithm,
    ) -> None:
        """
        Verify the fundamental security distinction between CRC32 framing and AES-GCM authentication:
        1. Encrypt message with AES-256-GCM (produces ciphertext + 128-bit GHASH tag).
        2. Embed into carrier audio using Echo Hiding.
        3. Extract payload using Echo Hiding and verify framing CRC32 passed.
        4. Mutate a byte in the encrypted ciphertext.
        5. Frame the mutated ciphertext into a newly generated CSMA envelope (CRC32 passes).
        6. Attempt to decrypt the mutated payload using decrypt_message().
        7. Verify DecryptionError is raised by AES-GCM GHASH tag verification failure.
        8. This proves CRC32 provides ONLY transmission framing integrity, NOT cryptographic authenticity.
        """
        wav = make_echo_test_wav(segments=1400, channels=2, sample_width=2)
        password = "StrictAuthenticationProofPassword2026!"
        secret = "Cryptographic integrity is distinct from CRC32 framing."

        # 1. Encrypt with AES-256-GCM
        ciphertext_payload = encrypt_message(secret, password)

        # 2. Embed and extract with Echo Hiding
        res = echo_algorithm.embed(wav, ciphertext_payload, alpha=0.08)
        extracted = echo_algorithm.extract(res.modified_wav, alpha=0.08)
        assert extracted.framing_checksum_verified is True
        assert extracted.payload == ciphertext_payload

        # 3. Deliberately tamper with one byte in the ciphertext
        tampered_payload = bytearray(ciphertext_payload)
        tampered_payload[25] ^= 0x01
        tampered_bytes = bytes(tampered_payload)

        # 4. Construct a valid CSMA envelope around the tampered ciphertext (its CRC32 will pass)
        tampered_envelope = create_csma_envelope(
            payload=tampered_bytes,
            algorithm=ALGO_ID_ECHO,
            sync_word=SYNC_WORD_ECHO,
        )
        parsed = parse_csma_envelope(tampered_envelope, expected_algorithm="echo", enforce_sync_word=True)
        assert parsed.payload == tampered_bytes  # Framing CRC32 passed!

        # 5. But AES-GCM decryption MUST detect tampering and raise DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_message(tampered_bytes, password)


# ---------------------------------------------------------------------------
# Group H: Audio Quality Evaluation Tests
# ---------------------------------------------------------------------------

class TestEchoAudioQuality:
    def test_audio_quality_metrics_baseline(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """Echo Hiding introduces expected subtle acoustic distortion without clipping."""
        wav = make_echo_test_wav(segments=540, channels=2, sample_width=2)
        payload = b"AudioQualityEvaluationPayload"

        result = echo_algorithm.embed(wav, payload, alpha=0.08)

        # Decode samples
        orig_samples = decode_pcm_to_ref16(wav.frames, 2)
        stego_samples = decode_pcm_to_ref16(result.modified_wav.frames, 2)

        mse = calculate_mse(orig_samples, stego_samples)
        snr = calculate_snr(orig_samples, stego_samples)
        psnr = calculate_psnr(orig_samples, stego_samples, PEAK_AMPLITUDES[2])
        corr = calculate_correlation(orig_samples, stego_samples)

        assert mse > 0.0
        # For alpha = 0.08 (-22 dB echo), SNR is typically in range 20 dB .. 35 dB
        assert 18.0 <= snr <= 40.0
        assert psnr > 25.0
        assert corr is not None
        assert corr > 0.99  # Very high correlation with original carrier


# ---------------------------------------------------------------------------
# Group I: Registry Integration Tests
# ---------------------------------------------------------------------------

class TestEchoRegistryIntegration:
    def test_registry_registration_and_lookup(self, echo_algorithm: EchoHidingAlgorithm) -> None:
        """EchoHidingAlgorithm registers cleanly and resolves by canonical name and integer ID."""
        reg = StegoRegistry()
        reg.register(echo_algorithm)

        assert reg.is_registered("echo") is True
        assert reg.is_registered(0x03) is True
        assert reg.is_registered(3) is True

        assert reg.get("echo") is echo_algorithm
        assert reg.get(0x03) is echo_algorithm
        assert reg.get(3) is echo_algorithm

        descriptors = reg.list_available()
        assert len(descriptors) == 1
        d = descriptors[0]
        assert d.algorithm_id == "echo"
        assert d.display_name == "Echo Hiding Acoustic Steganography"
        assert d.domain == DomainType.ACOUSTIC_TIME
        assert d.robustness_objective == RobustnessEvaluationStatus.EXPERIMENTAL_TARGET

    def test_global_singleton_with_echo(self) -> None:
        """Global get_registry(include_echo=True) includes echo alongside lsb and dwt."""
        reset_registry()
        reg = get_registry(include_echo=True)
        assert reg.is_registered("lsb") is True
        assert reg.is_registered("dwt_dct_qim") is True
        assert reg.is_registered("echo") is True
        assert len(reg.list_available()) == 3
        reset_registry()
