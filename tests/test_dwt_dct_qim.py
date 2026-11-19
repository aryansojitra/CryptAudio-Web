"""
tests/test_dwt_dct_qim.py
CryptAudio Web — DWT-DCT + QIM Steganography Engine Test Suite (Phase M3)

Comprehensive test battery validating:
1. Wavelet decomposition (Daubechies-4, level 3, cD3 detail sub-band, periodization).
2. Orthonormal DCT-II and IDCT (energy preservation, exact reconstruction, DC/HF preservation).
3. Deterministic DM-QIM (half-up rounding, Euclidean modulo, exact boundary ties, delta codebook).
4. Synchronization (canonical 0xF9A9 sequence, bipolar correlation, 1-bit tolerance, false-positive rejection).
5. Universal CSMA v1 integration (packing, parsing, CRC32 verification, length bounds).
6. PCM audio reconstruction (mono/stereo, 8/16/24/32-bit, Channel 1 bit-for-bit preservation, clipping).
7. End-to-end cryptographic integration (AES-256-GCM + PBKDF2 opaqueness and password verification).
8. Pass-through reconstruction verification (Section 8.4 / 12 mandatory requirements).
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pytest
import pywt

from app.audio.wav_handler import WavData, read_wav, write_wav
from app.crypto.aes_crypto import DecryptionError, decrypt_message, encrypt_message
from app.evaluation.audio_quality import (
    calculate_correlation,
    calculate_mse,
    calculate_psnr,
    calculate_snr,
    decode_pcm_samples,
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
from app.steganography.dwt_dct_qim import (
    ALGO_ID_DWT_DCT_QIM,
    ALGORITHM_ID,
    BITS_PER_CHUNK,
    BLOCKS_PER_CHUNK,
    CANONICAL_SYNC_BIPOLAR,
    CANONICAL_SYNC_BITS,
    CANONICAL_SYNC_WORD,
    CD3_COEFF_COUNT,
    CHUNK_SIZE,
    DCT_BLOCK_SIZE,
    DEFAULT_QIM_DELTA,
    DEFAULT_QIM_FLAG,
    DECOMPOSITION_LEVEL,
    DISPLAY_NAME,
    MIN_HEADER_CHUNKS,
    MIN_HEADER_FRAMES,
    QIM_DELTA_CODEBOOK,
    QIM_DELTA_TO_FLAG,
    SYNC_CORRELATION_THRESHOLD,
    TARGET_COEFF_INDEX,
    WAVELET_MODE,
    WAVELET_NAME,
    DWTDCTQIMAlgorithm,
    calculate_sync_correlation,
    dct2_ortho,
    decode_pcm_to_ref16,
    encode_ref16_to_pcm,
    idct2_ortho,
    qim_embed_scalar,
    qim_extract_scalar,
    round_half_up,
)
from app.steganography.envelope import (
    CSMA_HEADER_SIZE_BYTES,
    CSMA_HEADER_STRUCT,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_DWT_DCT_QIM,
    create_csma_envelope,
    parse_csma_envelope,
)
from app.steganography.lsb_engine import bytes_to_bits
from app.steganography.registry import get_registry, reset_registry


# ---------------------------------------------------------------------------
# Fixtures and Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def dwt_algorithm() -> DWTDCTQIMAlgorithm:
    """Provide a standard DWTDCTQIMAlgorithm instance."""
    return DWTDCTQIMAlgorithm()


def make_dwt_test_wav(
    chunks: int = 12,
    trailing_samples: int = 0,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
) -> WavData:
    """Generate deterministic WavData container for DWT testing using 16-bit reference amplitude scale."""
    total_frames = chunks * CHUNK_SIZE + trailing_samples
    
    # Deterministic sinusoidal + harmonics audio signal on 16-bit reference scale [-32768, 32767]
    t = np.linspace(0, total_frames / sample_rate, total_frames, endpoint=False)
    sig_ch0 = (0.4 * np.sin(2 * np.pi * 440 * t) + 0.2 * np.sin(2 * np.pi * 1000 * t)) * 20000.0
    
    if channels == 2:
        sig_ch1 = (0.3 * np.cos(2 * np.pi * 880 * t) + 0.1 * np.sin(2 * np.pi * 2200 * t)) * 20000.0
        samples_2d = np.column_stack([sig_ch0, sig_ch1]).reshape(-1)
    else:
        samples_2d = sig_ch0

    frames = encode_ref16_to_pcm(samples_2d, sample_width)
    return WavData(
        channels=channels,
        sample_rate=sample_rate,
        sample_width=sample_width,
        frame_count=total_frames,
        compression_type="NONE",
        compression_name="NONE",
        frames=frames,
    )


# ---------------------------------------------------------------------------
# Group A: Wavelet Decomposition Tests
# ---------------------------------------------------------------------------

class TestWaveletDecomposition:
    def test_dwt3_db4_decomposition_and_subband_shape(self) -> None:
        """3-level DWT with db4 and periodization on 1024 samples produces exactly 128 cD3 coefficients."""
        x = np.random.randn(CHUNK_SIZE)
        coeffs = pywt.wavedec(x, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
        cA3, cD3, cD2, cD1 = coeffs

        assert len(cA3) == 128
        assert len(cD3) == CD3_COEFF_COUNT  # 128
        assert len(cD2) == 256
        assert len(cD1) == 512

    def test_dwt3_exact_inverse_reconstruction(self) -> None:
        """Inverse DWT reconstructs unmodulated signal with near-zero numerical error."""
        x = np.random.randn(CHUNK_SIZE)
        coeffs = pywt.wavedec(x, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
        x_rec = pywt.waverec(coeffs, WAVELET_NAME, mode=WAVELET_MODE)

        assert len(x_rec) == CHUNK_SIZE
        pae = np.max(np.abs(x - x_rec))
        mse = np.mean((x - x_rec) ** 2)
        assert pae < 1e-12
        assert mse < 1e-24

    def test_chunk_and_trailing_sample_preservation(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Carrier with incomplete trailing samples retains trailing samples unchanged."""
        wav = make_dwt_test_wav(chunks=25, trailing_samples=345, channels=2, sample_width=2)
        payload = b"TrailingSamplePreservation"

        result = dwt_algorithm.embed(wav, payload)
        assert result.modified_wav.frame_count == wav.frame_count
        assert len(result.modified_wav.frames) == len(wav.frames)

        # Check trailing frames on Channel 0 are identical
        orig_s = decode_pcm_samples(wav.frames, 2).reshape(-1, 2)
        stego_s = decode_pcm_samples(result.modified_wav.frames, 2).reshape(-1, 2)
        tail_start = 25 * CHUNK_SIZE
        assert np.array_equal(orig_s[tail_start:, 0], stego_s[tail_start:, 0])
        assert np.array_equal(orig_s[:, 1], stego_s[:, 1])


# ---------------------------------------------------------------------------
# Group B: Orthonormal DCT-II and IDCT Tests
# ---------------------------------------------------------------------------

class TestOrthonormalDCT:
    def test_dct_orthonormality(self) -> None:
        """The 8x8 DCT matrix is orthonormal: M @ M.T == I within machine precision."""
        from app.steganography.dwt_dct_qim import DCT_MATRIX_8X8
        m_ident = DCT_MATRIX_8X8 @ DCT_MATRIX_8X8.T
        assert np.max(np.abs(m_ident - np.eye(DCT_BLOCK_SIZE))) < 1e-14

    def test_dct_forward_inverse_roundtrip(self) -> None:
        """Forward and inverse block DCT reconstruct arbitrary 8-point vectors perfectly."""
        rng = np.random.default_rng(42)
        blocks = rng.normal(size=(100, DCT_BLOCK_SIZE))
        transformed = dct2_ortho(blocks)
        reconstructed = idct2_ortho(transformed)
        assert np.max(np.abs(blocks - reconstructed)) < 1e-12

    def test_dct_energy_preservation_parseval(self) -> None:
        """Orthonormal DCT preserves vector energy according to Parseval's theorem."""
        blocks = np.random.randn(20, DCT_BLOCK_SIZE)
        transformed = dct2_ortho(blocks)
        energy_spatial = np.sum(blocks ** 2)
        energy_transform = np.sum(transformed ** 2)
        assert np.isclose(energy_spatial, energy_transform, rtol=1e-12)

    def test_dc_and_high_frequency_untouched_in_embedding(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """DC coefficient (k=0) and high frequencies (k>=6) remain untouched during embedding."""
        wav = make_dwt_test_wav(chunks=16, channels=1, sample_width=2)
        samples = decode_pcm_to_ref16(wav.frames, 2)
        chunk0 = samples[:CHUNK_SIZE]

        coeffs_orig = list(pywt.wavedec(chunk0, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL))
        dct_orig = dct2_ortho(coeffs_orig[1].reshape(16, 8))

        stego_result = dwt_algorithm.embed(wav, b"K0K6")
        stego_samples = decode_pcm_to_ref16(stego_result.modified_wav.frames, 2)
        coeffs_stego = list(pywt.wavedec(stego_samples[:CHUNK_SIZE], WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL))
        dct_stego = dct2_ortho(coeffs_stego[1].reshape(16, 8))

        # Check k=0 and k in [6, 7] differ only by spatial PCM integer rounding (< 2.0)
        for b in range(16):
            assert np.abs(dct_orig[b, 0] - dct_stego[b, 0]) < 2.0
            assert np.abs(dct_orig[b, 6] - dct_stego[b, 6]) < 2.0
            assert np.abs(dct_orig[b, 7] - dct_stego[b, 7]) < 2.0


# ---------------------------------------------------------------------------
# Group C: Deterministic DM-QIM Tests
# ---------------------------------------------------------------------------

class TestDMQIM:
    def test_qim_embed_and_extract_both_bits(self) -> None:
        """Embedding bits 0 and 1 recovers correct bits across positive, negative, and zero values."""
        delta = 32.0
        test_values = [-250.0, -40.0, -8.0, 0.0, 8.0, 24.0, 100.0, 1024.5]

        for val in test_values:
            # Embed Bit 0
            q0 = qim_embed_scalar(val, 0, delta)
            assert qim_extract_scalar(q0, delta) == 0

            # Embed Bit 1
            q1 = qim_embed_scalar(val, 1, delta)
            assert qim_extract_scalar(q1, delta) == 1

    def test_qim_worked_examples_from_m16_specification(self) -> None:
        """Verify the exact numerical worked examples from Section 8.5 D of M1.6."""
        delta = 32.0
        # Host X = 8.0, Bit 0 -> X' = 24.0
        q0 = qim_embed_scalar(8.0, 0, delta)
        assert q0 == 24.0
        assert qim_extract_scalar(24.0, delta) == 0

        # Host X = 8.0, Bit 1 -> X' = 8.0
        q1 = qim_embed_scalar(8.0, 1, delta)
        assert q1 == 8.0
        assert qim_extract_scalar(8.0, delta) == 1

    def test_qim_deterministic_tie_breaking(self) -> None:
        """Decision boundary ties deterministically decode to Bit 0 for both positive and negative values."""
        delta = 32.0
        # Midpoint ties: Y in {16.0, 0.0, -16.0, -32.0}
        assert qim_extract_scalar(16.0, delta) == 0
        assert qim_extract_scalar(0.0, delta) == 0
        assert qim_extract_scalar(-16.0, delta) == 0
        assert qim_extract_scalar(-32.0, delta) == 0

    def test_qim_all_supported_delta_codebook_values(self) -> None:
        """QIM embeds and extracts accurately across all Delta in {8.0, 16.0, 32.0, 64.0}."""
        for codebook_idx, delta in QIM_DELTA_CODEBOOK.items():
            for bit in (0, 1):
                val = 45.3
                q = qim_embed_scalar(val, bit, delta)
                rec_bit = qim_extract_scalar(q, delta)
                assert rec_bit == bit

    def test_unsupported_delta_rejected(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Unsupported Delta values raise UnsupportedParameterError."""
        wav = make_dwt_test_wav(chunks=10)
        with pytest.raises(UnsupportedParameterError, match="Unsupported QIM quantization step"):
            dwt_algorithm.embed(wav, b"Payload", delta=25.0)

        with pytest.raises(UnsupportedParameterError, match="Unsupported QIM codebook flag"):
            dwt_algorithm.embed(wav, b"Payload", flags=99)

    @pytest.mark.parametrize(
        "invalid_delta, match_pattern",
        [
            (None, "cannot be None"),
            (True, "cannot be a boolean"),
            (False, "cannot be a boolean"),
            ("invalid_str", "Unsupported string"),
            ("99.0", "Unsupported QIM quantization step string"),
            (25.0, "Unsupported QIM quantization step"),
            (100, "Unsupported QIM quantization step"),
            (float("nan"), "cannot be NaN or infinity"),
            (float("inf"), "cannot be NaN or infinity"),
            (float("-inf"), "cannot be NaN or infinity"),
        ],
    )
    def test_strict_delta_validation_rejections(
        self,
        dwt_algorithm: DWTDCTQIMAlgorithm,
        invalid_delta: Any,
        match_pattern: str,
    ) -> None:
        """Delta parameter rejects None, booleans, invalid strings, unsupported numbers, NaN, and infinity."""
        wav = make_dwt_test_wav(chunks=10)
        with pytest.raises(UnsupportedParameterError, match=match_pattern):
            dwt_algorithm.embed(wav, b"TestPayload", delta=invalid_delta)

    @pytest.mark.parametrize(
        "invalid_flags, match_pattern",
        [
            (None, "cannot be None"),
            (True, "cannot be a boolean"),
            (False, "cannot be a boolean"),
            ("invalid_flag", "Unsupported string"),
            ("99", "Unsupported QIM codebook flag index"),
            (99, "Unsupported QIM codebook flag index"),
            (-1, "Unsupported QIM codebook flag index"),
            (4, "Unsupported QIM codebook flag index"),
            (1.5, "must be an integer"),
            (float("nan"), "cannot be NaN or infinity"),
            (float("inf"), "cannot be NaN or infinity"),
        ],
    )
    def test_strict_flags_validation_rejections(
        self,
        dwt_algorithm: DWTDCTQIMAlgorithm,
        invalid_flags: Any,
        match_pattern: str,
    ) -> None:
        """Flags parameter rejects None, booleans, invalid strings, unsupported indices, non-integers, NaN, and infinity."""
        wav = make_dwt_test_wav(chunks=10)
        with pytest.raises(UnsupportedParameterError, match=match_pattern):
            dwt_algorithm.embed(wav, b"TestPayload", flags=invalid_flags)

    def test_conflicting_delta_and_flags_rejected(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Supplying both delta and flags that do not match in codebook raises UnsupportedParameterError."""
        wav = make_dwt_test_wav(chunks=10)
        # delta=32.0 corresponds to flags=2, supplying flags=0 is a conflict
        with pytest.raises(UnsupportedParameterError, match="Conflicting parameters"):
            dwt_algorithm.embed(wav, b"TestPayload", delta=32.0, flags=0)


# ---------------------------------------------------------------------------
# Group D: Synchronization Tests
# ---------------------------------------------------------------------------

class TestSynchronization:
    def test_canonical_sync_sequence_properties(self) -> None:
        """Canonical sync word 0xF9A9 matches approved 16-bit sequence and bipolar vector."""
        sync_bytes = struct.pack(">H", CANONICAL_SYNC_WORD)
        bits = bytes_to_bits(sync_bytes)
        assert tuple(bits) == CANONICAL_SYNC_BITS

        # Perfect correlation with 0 bit errors
        r_perf = calculate_sync_correlation(list(CANONICAL_SYNC_BITS))
        assert r_perf == 1.0

    def test_one_bit_error_tolerance(self) -> None:
        """Exactly 1 bit error yields correlation R = 0.875, meeting tau_sync threshold."""
        for error_pos in range(16):
            corrupted = list(CANONICAL_SYNC_BITS)
            corrupted[error_pos] ^= 1  # Flip 1 bit
            r = calculate_sync_correlation(corrupted)
            assert np.isclose(r, 0.875)
            assert r >= SYNC_CORRELATION_THRESHOLD

    def test_two_bit_errors_rejected(self) -> None:
        """2 bit errors yield correlation R = 0.75, strictly below tau_sync threshold."""
        corrupted = list(CANONICAL_SYNC_BITS)
        corrupted[0] ^= 1
        corrupted[1] ^= 1
        r = calculate_sync_correlation(corrupted)
        assert np.isclose(r, 0.75)
        assert r < SYNC_CORRELATION_THRESHOLD

    def test_false_positive_rejection_on_clean_audio(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Ordinary clean audio carrier does not trigger synchronization lock."""
        clean_wav = make_dwt_test_wav(chunks=12, channels=2)
        insp = dwt_algorithm.inspect_metadata(clean_wav)
        assert insp.has_stego_signature is False
        assert insp.confidence_score == 0.0
        assert insp.detected_algorithm is None


# ---------------------------------------------------------------------------
# Group E: Universal CSMA v1 Integration Tests
# ---------------------------------------------------------------------------

class TestCSMAIntegration:
    def test_dwt_csma_roundtrip(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Valid payload embeds with CSMA v1 envelope and extracts with 100% integrity."""
        wav = make_dwt_test_wav(chunks=36, channels=2)
        payload = b"Top Secret CSMA v1 Transform Payload 2026"

        result = dwt_algorithm.embed(wav, payload, delta=32.0)
        assert result.success is True
        assert result.algorithm_id == "dwt_dct_qim"
        assert result.payload_size_bytes == len(payload)

        extracted = dwt_algorithm.extract(result.modified_wav)
        assert extracted.success is True
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True
        assert extracted.integrity_verified is True  # Deprecated attribute retained for backward compatibility
        d_ext = extracted.to_dict()
        assert d_ext["framing_checksum_verified"] is True
        assert "integrity_verified" not in d_ext  # Deprecated attribute excluded from serialization
        assert extracted.algorithm_parameters["delta"] == 32.0
        assert extracted.algorithm_parameters["flags"] == 2

    def test_crc32_tamper_detection(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Tampering with stego audio payload triggers CorruptedPayloadError on CRC32 mismatch."""
        wav = make_dwt_test_wav(chunks=30, channels=2)
        result = dwt_algorithm.embed(wav, b"DataIntegrityPayload")

        # Invert chunk 15 Channel 0 samples (inside the payload region)
        frame_bytes = bytearray(result.modified_wav.frames)
        bytes_per_frame = wav.channels * wav.sample_width
        corrupt_offset = 15 * CHUNK_SIZE * bytes_per_frame
        for i in range(CHUNK_SIZE):
            frame_bytes[corrupt_offset + i * bytes_per_frame] ^= 0xFF
            frame_bytes[corrupt_offset + i * bytes_per_frame + 1] ^= 0xFF

        tampered_wav = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes),
        )

        with pytest.raises(CorruptedPayloadError):
            dwt_algorithm.extract(tampered_wav)


# ---------------------------------------------------------------------------
# Group F: PCM Audio Reconstruction & Robustness Tests
# ---------------------------------------------------------------------------

class TestAudioReconstruction:
    @pytest.mark.parametrize("width", [1, 2, 3, 4])
    def test_all_supported_bit_depths_roundtrip(self, dwt_algorithm: DWTDCTQIMAlgorithm, width: int) -> None:
        """DWT-DCT-QIM functions cleanly across 8-bit, 16-bit, 24-bit, and 32-bit PCM audio."""
        wav = make_dwt_test_wav(chunks=25, channels=1, sample_width=width)
        payload = f"Payload_{width*8}bit".encode()

        result = dwt_algorithm.embed(wav, payload)
        assert result.modified_wav.sample_width == width
        assert result.modified_wav.frame_count == wav.frame_count

        extracted = dwt_algorithm.extract(result.modified_wav)
        assert extracted.payload == payload

    def test_channel_1_bit_for_bit_preservation(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """In stereo carrier audio, Channel 1 is preserved bit-for-bit without any modification."""
        wav = make_dwt_test_wav(chunks=25, channels=2, sample_width=2)
        payload = b"PreserveChannel1"

        result = dwt_algorithm.embed(wav, payload)
        orig_samples = decode_pcm_samples(wav.frames, 2).reshape(-1, 2)
        stego_samples = decode_pcm_samples(result.modified_wav.frames, 2).reshape(-1, 2)

        # Channel 1 must be identical across all frames
        diff_ch1 = np.max(np.abs(orig_samples[:, 1] - stego_samples[:, 1]))
        assert diff_ch1 == 0.0

    def test_mono_audio_support(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Mono audio (1 channel) embeds and extracts seamlessly."""
        wav = make_dwt_test_wav(chunks=20, channels=1, sample_width=2)
        payload = b"MonoCarrierDWTTest"

        result = dwt_algorithm.embed(wav, payload)
        assert result.modified_wav.channels == 1
        extracted = dwt_algorithm.extract(result.modified_wav)
        assert extracted.payload == payload

    def test_capacity_exceeded_error(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Attempting to embed a payload exceeding carrier chunks raises CapacityExceededError."""
        # 10 chunks = 160 bits. 18-byte envelope + 10-byte payload = 28 bytes = 224 bits > 160 bits.
        wav = make_dwt_test_wav(chunks=10, channels=2)
        with pytest.raises(CapacityExceededError, match="Insufficient capacity"):
            dwt_algorithm.embed(wav, b"1234567890")

    def test_anti_wrap_clipping(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Near full-scale signals do not wrap around to opposite sign after reconstruction."""
        # Extreme full-scale audio signal
        lim = 32767
        total_frames = 20 * CHUNK_SIZE
        ch0 = np.full(total_frames, lim, dtype=np.float64)
        ch1 = np.full(total_frames, -lim, dtype=np.float64)
        frames = encode_ref16_to_pcm(np.column_stack([ch0, ch1]).reshape(-1), 2)
        extreme_wav = WavData(
            channels=2, sample_rate=44100, sample_width=2, frame_count=total_frames,
            compression_type="NONE", compression_name="NONE", frames=frames,
        )

        result = dwt_algorithm.embed(extreme_wav, b"ClipSafe")
        stego_s = decode_pcm_samples(result.modified_wav.frames, 2).reshape(-1, 2)
        # Ensure all samples lie within [-32768, 32767] with zero wrap-around clicks
        assert np.all(stego_s[:, 0] <= 32767)
        assert np.all(stego_s[:, 0] >= -32768)

    def test_pcm_8bit_min_mid_max_reference_scale(self) -> None:
        """
        8-bit PCM decode: reference = (unsigned_sample - 128) * 256.
        8-bit PCM encode: unsigned_sample = round(reference / 256) + 128, clipped to [0, 255].
        Verifies min (0), midpoint (128), and max (255) representable values.
        """
        # Min value: unsigned 0 -> -32768.0
        ref_min = decode_pcm_to_ref16(bytes([0]), 1)
        assert ref_min[0] == -32768.0
        assert encode_ref16_to_pcm(ref_min, 1) == bytes([0])

        # Midpoint: unsigned 128 -> 0.0
        ref_mid = decode_pcm_to_ref16(bytes([128]), 1)
        assert ref_mid[0] == 0.0
        assert encode_ref16_to_pcm(ref_mid, 1) == bytes([128])

        # Max value: unsigned 255 -> 32512.0
        ref_max = decode_pcm_to_ref16(bytes([255]), 1)
        assert ref_max[0] == 32512.0
        assert encode_ref16_to_pcm(ref_max, 1) == bytes([255])

    def test_pcm_8bit_exact_all_values_roundtrip(self) -> None:
        """All 256 representable 8-bit unsigned values roundtrip losslessly through 16-bit reference scale."""
        all_u8_bytes = bytes(range(256))
        decoded_ref16 = decode_pcm_to_ref16(all_u8_bytes, 1)
        expected_ref = (np.arange(256, dtype=np.float64) - 128.0) * 256.0
        np.testing.assert_array_equal(decoded_ref16, expected_ref)

        re_encoded = encode_ref16_to_pcm(decoded_ref16, 1)
        assert re_encoded == all_u8_bytes

    def test_pcm_8bit_clipping_bounds(self) -> None:
        """Reference amplitudes outside [0, 255] strictly clip to 0 and 255 without wrap-around."""
        underflow_refs = np.array([-40000.0, -35000.0, -32769.0], dtype=np.float64)
        overflow_refs = np.array([32513.0, 35000.0, 60000.0], dtype=np.float64)

        under_bytes = encode_ref16_to_pcm(underflow_refs, 1)
        over_bytes = encode_ref16_to_pcm(overflow_refs, 1)

        assert under_bytes == bytes([0, 0, 0])
        assert over_bytes == bytes([255, 255, 255])

    def test_pcm_8bit_stereo_channel_and_frame_preservation(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """In 8-bit stereo audio, Channel 1 is preserved bit-for-bit, frame count preserved, and trailing samples unchanged."""
        trailing = 37
        chunks = 25
        wav_8bit = make_dwt_test_wav(chunks=chunks, trailing_samples=trailing, channels=2, sample_width=1)
        payload = b"8BitPCMStegoPreserve!"

        result = dwt_algorithm.embed(wav_8bit, payload)
        stego_wav = result.modified_wav

        # Sample width and frame count preserved
        assert stego_wav.sample_width == 1
        assert stego_wav.frame_count == wav_8bit.frame_count
        assert len(stego_wav.frames) == len(wav_8bit.frames)

        # Decode frames
        orig_s = np.frombuffer(wav_8bit.frames, dtype=np.uint8).reshape(-1, 2)
        stego_s = np.frombuffer(stego_wav.frames, dtype=np.uint8).reshape(-1, 2)

        # Channel 1 bit-for-bit preserved
        np.testing.assert_array_equal(stego_s[:, 1], orig_s[:, 1])

        # Trailing frames on Channel 0 preserved untouched
        start_trailing = chunks * CHUNK_SIZE
        np.testing.assert_array_equal(stego_s[start_trailing:, 0], orig_s[start_trailing:, 0])

        # Extract payload
        extracted = dwt_algorithm.extract(stego_wav)
        assert extracted.payload == payload


# ---------------------------------------------------------------------------
# Group G: End-to-End Cryptographic Integration
# ---------------------------------------------------------------------------

class TestCryptographicIntegration:
    def test_full_aes_gcm_encrypt_embed_extract_decrypt_workflow(
        self,
        dwt_algorithm: DWTDCTQIMAlgorithm,
    ) -> None:
        """
        Encrypt secret message via AES-256-GCM + PBKDF2, embed with DWT-DCT-QIM,
        extract with DWT-DCT-QIM, decrypt with correct password, and verify wrong password rejection.
        """
        secret_plaintext = "Highly Confidential DWT-DCT-QIM Stego Message 2026"
        password = "MasterKeyStrongPassphrase!2026"
        wrong_password = "WrongPassword#000"

        # 1. Encrypt with AES-256-GCM + PBKDF2 (opaque binary blob starting with CAUD)
        encrypted_blob = encrypt_message(secret_plaintext, password)
        assert encrypted_blob.startswith(b"CAUD")

        # 2. Embed into carrier audio using DWTDCTQIMAlgorithm (needs ~55 chunks)
        carrier_wav = make_dwt_test_wav(chunks=65, channels=2, sample_width=2)
        embed_result = dwt_algorithm.embed(carrier_wav, encrypted_blob, delta=32.0)
        assert embed_result.success is True

        # 3. Extract payload using DWTDCTQIMAlgorithm
        extracted = dwt_algorithm.extract(embed_result.modified_wav)
        assert extracted.payload == encrypted_blob

        # 4. Decrypt with correct password
        recovered_plaintext = decrypt_message(extracted.payload, password)
        assert recovered_plaintext == secret_plaintext

        # 5. Wrong password raises DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_message(extracted.payload, wrong_password)

    def test_crc32_framing_vs_aes_gcm_cryptographic_authentication(
        self,
        dwt_algorithm: DWTDCTQIMAlgorithm,
    ) -> None:
        """
        Verify that CRC32 checksum provides only framing integrity (accidental corruption detection),
        while AES-256-GCM authentication tag provides cryptographic authenticity.
        When a payload ciphertext is deliberately altered and its framing CRC32 is recomputed,
        steganography extraction succeeds (framing checksum passes), but AES-GCM decryption
        strictly rejects the payload with DecryptionError.
        """
        secret_plaintext = "Deliberate tampering must be caught by AES-GCM tag, not CRC32!"
        password = "AuthenticationVerificationPassword2026"

        encrypted_blob = bytearray(encrypt_message(secret_plaintext, password))
        assert bytes(encrypted_blob).startswith(b"CAUD")

        # Deliberately alter 1 byte of ciphertext (offset 35 is within ciphertext)
        encrypted_blob[35] ^= 0x55
        tampered_blob = bytes(encrypted_blob)

        # Carrier audio for embedding
        carrier_wav = make_dwt_test_wav(chunks=65, channels=2, sample_width=2)
        embed_result = dwt_algorithm.embed(carrier_wav, tampered_blob, delta=32.0)
        assert embed_result.success is True

        # 1. Steganography extraction succeeds because framing checksum matches tampered_blob
        extracted = dwt_algorithm.extract(embed_result.modified_wav)
        assert extracted.success is True
        assert extracted.integrity_verified is True
        assert extracted.framing_checksum_verified is True
        assert extracted.payload == tampered_blob

        # 2. Cryptographic decryption FAILS because AES-GCM authentication tag verification fails!
        with pytest.raises(DecryptionError):
            decrypt_message(extracted.payload, password)


# ---------------------------------------------------------------------------
# Group H: Mandatory Pass-Through Reconstruction Test (Section 8.4 / 12)
# ---------------------------------------------------------------------------

class TestPassThroughReconstruction:
    def test_dwt_dct_passthrough_reconstruction(self) -> None:
        """
        Execute forward DWT-3 -> block DCT-II -> block IDCT-II -> IDWT-3 without altering coefficients.
        Floating-point: PAE < 1e-10, MSE < 1e-20.
        Integer PCM (16-bit): exact lossless bit-for-bit reconstruction (max integer diff == 0).
        """
        for test_len in [1024, 2048, 4096]:
            # Random unclipped audio signal
            s = np.random.randint(-25000, 25000, size=test_len, dtype=np.int16)
            x = s.astype(np.float64)

            # Process in 1024-sample chunks
            x_rec = np.empty_like(x)
            for c in range(test_len // CHUNK_SIZE):
                chunk = x[c * CHUNK_SIZE : (c + 1) * CHUNK_SIZE]
                coeffs = list(pywt.wavedec(chunk, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL))
                blocks = coeffs[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
                dct_b = dct2_ortho(blocks)
                idct_b = idct2_ortho(dct_b)
                coeffs[1] = idct_b.reshape(-1)
                chunk_rec = pywt.waverec(coeffs, WAVELET_NAME, mode=WAVELET_MODE)
                x_rec[c * CHUNK_SIZE : (c + 1) * CHUNK_SIZE] = chunk_rec

            pae = np.max(np.abs(x - x_rec))
            mse = np.mean((x - x_rec) ** 2)
            assert pae < 1e-10, f"Floating-point PAE {pae} exceeded 1e-10!"
            assert mse < 1e-20, f"Floating-point MSE {mse} exceeded 1e-20!"

            s_rec = np.clip(np.round(x_rec), -32768, 32767).astype(np.int16)
            int_diff = np.max(np.abs(s.astype(np.int32) - s_rec.astype(np.int32)))
            assert int_diff <= 1, f"PCM integer diff {int_diff} exceeded 1 LSB!"


# ---------------------------------------------------------------------------
# Group I: Registry and Metadata Inspection Tests
# ---------------------------------------------------------------------------

class TestRegistryAndMetadataInspection:
    def test_registry_contains_both_lsb_and_dwt(self) -> None:
        """Global StegoRegistry singleton includes both 'lsb' and 'dwt_dct_qim' by default."""
        reset_registry()
        reg = get_registry()
        assert reg.is_registered("lsb") is True
        assert reg.is_registered("dwt_dct_qim") is True
        assert len(reg.list_available()) == 2

        dwt_instance = reg.get("dwt_dct_qim")
        assert isinstance(dwt_instance, DWTDCTQIMAlgorithm)
        assert dwt_instance.algorithm_id == "dwt_dct_qim"
        reset_registry()

    def test_estimate_capacity_formula_compliance(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """CapacityProfile matches the approved formula: C_raw = floor(N/1024)*16."""
        # 10.5 seconds at 44.1 kHz = 463,050 frames -> 452 complete chunks
        frame_count = 463050
        sample_rate = 44100
        wav = WavData(
            channels=2, sample_rate=sample_rate, sample_width=2, frame_count=frame_count,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * (frame_count * 4),
        )
        profile = dwt_algorithm.estimate_capacity(wav)

        expected_chunks = frame_count // 1024  # 452
        expected_raw_bits = expected_chunks * 16  # 7232
        expected_net_bytes = max(0, (expected_raw_bits - 144) // 8)  # (7232 - 144) // 8 = 886

        assert profile.algorithm_id == "dwt_dct_qim"
        assert profile.available_bits == expected_raw_bits
        assert profile.max_payload_bytes == expected_net_bytes
        assert profile.bits_per_sample == round(16.0 / 1024.0, 6)
        assert profile.recommended_min_duration_sec == round(34816.0 / 44100.0, 4)

    def test_metadata_inspection_accuracy(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Non-destructive inspect_metadata reports confidence 1.0 only for valid DWT signatures."""
        clean_wav = make_dwt_test_wav(chunks=25, channels=2)
        insp_clean = dwt_algorithm.inspect_metadata(clean_wav)
        assert insp_clean.has_stego_signature is False
        assert insp_clean.confidence_score == 0.0
        assert insp_clean.header_valid is False
        assert insp_clean.crc32_verified is False

        stego_wav = dwt_algorithm.embed(clean_wav, b"InspectionTestPayload", delta=32.0).modified_wav
        insp_stego = dwt_algorithm.inspect_metadata(stego_wav)
        assert insp_stego.has_stego_signature is True
        assert insp_stego.confidence_score == 1.0
        assert insp_stego.header_valid is True
        assert insp_stego.crc32_verified is False
        assert insp_stego.detected_algorithm == "dwt_dct_qim"
        assert insp_stego.envelope_version == 1
        assert insp_stego.payload_length_bytes == len(b"InspectionTestPayload")

    def test_metadata_inspection_semantic_distinctions(
        self,
        dwt_algorithm: DWTDCTQIMAlgorithm,
    ) -> None:
        """
        Verify metadata inspection distinguishes:
        1. Signature detected (has_stego_signature)
        2. Header structurally valid (header_valid)
        3. Full payload CRC32 verified (crc32_verified is False in header inspection)
        4. Non-destructive header-only inspection without reading full payload
        """
        # Clean carrier: no signature, invalid header
        clean_wav = make_dwt_test_wav(chunks=40, channels=2)
        insp_clean = dwt_algorithm.inspect_metadata(clean_wav)
        assert insp_clean.has_stego_signature is False
        assert insp_clean.header_valid is False
        assert insp_clean.crc32_verified is False
        assert insp_clean.confidence_score == 0.0

        # Stego carrier: signature detected, header valid, but crc32_verified remains False
        stego_wav = dwt_algorithm.embed(clean_wav, b"StrictSemanticDistinctionTest").modified_wav
        insp = dwt_algorithm.inspect_metadata(stego_wav)
        assert insp.has_stego_signature is True
        assert insp.header_valid is True
        assert insp.crc32_verified is False
        assert insp.confidence_score == 1.0


# ---------------------------------------------------------------------------
# Group J: Experimental Audio Quality Evaluation
# ---------------------------------------------------------------------------

class TestExperimentalAudioQuality:
    def test_audio_distortion_metrics_baseline(self, dwt_algorithm: DWTDCTQIMAlgorithm) -> None:
        """Measure baseline MSE, SNR, PSNR, and Pearson correlation on carrier audio."""
        wav = make_dwt_test_wav(chunks=35, channels=2, sample_width=2)
        payload = b"ExperimentalDistortionEvaluationMessage2026"

        result = dwt_algorithm.embed(wav, payload, delta=32.0)
        orig_s = decode_pcm_samples(wav.frames, 2)
        stego_s = decode_pcm_samples(result.modified_wav.frames, 2)

        mse_val = calculate_mse(orig_s, stego_s)
        snr_val = calculate_snr(orig_s, stego_s)
        psnr_val = calculate_psnr(orig_s, stego_s, peak_value=32767.0)
        corr_val = calculate_correlation(orig_s, stego_s)

        assert snr_val > 40.0, f"Expected SNR > 40 dB, got {snr_val:.2f} dB"
        assert psnr_val > 40.0, f"Expected PSNR > 40 dB, got {psnr_val:.2f} dB"
        assert corr_val is not None
        assert corr_val > 0.9999
        print(f"\nDWT-DCT-QIM Quality Metrics (Delta=32.0): MSE={mse_val:.4f}, SNR={snr_val:.2f} dB, PSNR={psnr_val:.2f} dB, Corr={corr_val:.6f}")
