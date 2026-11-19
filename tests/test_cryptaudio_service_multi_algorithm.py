"""
tests/test_cryptaudio_service_multi_algorithm.py
CryptAudio Web — Multi-Algorithm Service Integration Test Suite (Phase M5)

Tests centralized multi-algorithm workflows through BaseStegoAlgorithm & StegoRegistry:
1. Algorithm discovery and registry resolution (LSB, DWT-DCT-QIM, Echo Hiding).
2. End-to-end embedding and extraction across all three algorithms.
3. Multilingual UTF-8 text support (English, Gujarati, Hindi, Japanese, Russian, Emojis).
4. Automatic algorithm detection during extraction.
5. Strict separation between CRC32 framing integrity and AES-GCM authentication.
6. Error handling: wrong passwords, corrupted audio, insufficient capacity.
7. Algorithm-specific capacity estimation and non-destructive metadata inspection.
8. Backward compatibility with legacy LSB service calls.
"""

from __future__ import annotations

import io
import os
import sys
import wave
from pathlib import Path

import numpy as np
import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import WavData, inspect_wav, read_wav, write_wav
from app.crypto.aes_crypto import decrypt_message, encrypt_message
from app.services.cryptaudio_service import (
    CapacityEstimate,
    EmbedMessageResult,
    ExtractMessageResult,
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    embed_message,
    estimate_capacity,
    extract_message,
    extract_message_detailed,
    inspect_stego_metadata,
)
from app.steganography.envelope import (
    ALGO_ID_ECHO,
    ALGO_ID_LSB,
    ALGO_ID_DWT_DCT_QIM,
    SYNC_WORD_ECHO,
    SYNC_WORD_LSB,
    SYNC_WORD_DWT_DCT_QIM,
)
from app.steganography.registry import StegoRegistry, get_registry, reset_registry


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------

def make_test_wav_file(
    file_path: Path,
    num_frames: int = 2500000,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
    carrier_type: str = "chirp",
) -> Path:
    """
    Create a deterministic WAV carrier file on disk.
    For Echo Hiding and DWT, wideband chirp signals provide optimal cepstral/wavelet properties.
    2.5M frames provides ~1220 Echo segments, easily accommodating standard test payloads.
    """
    total_samples = num_frames * channels
    if carrier_type == "chirp":
        # Repeated chirp block per 2048 samples
        block_len = 2048
        blocks = int(np.ceil(num_frames / block_len))
        t_block = np.arange(block_len, dtype=np.float64) / sample_rate
        f0, f1 = 200.0, 6000.0
        dur_block = block_len / sample_rate
        block_chirp = np.sin(2.0 * np.pi * (f0 + (f1 - f0) / (2.0 * dur_block) * t_block) * t_block)
        ch0 = np.tile(block_chirp, blocks)[:num_frames] * 26000.0
        if channels == 2:
            t = np.arange(num_frames, dtype=np.float64) / sample_rate
            ch1 = np.cos(2.0 * np.pi * 440.0 * t) * 15000.0
            samples_2d = np.column_stack([ch0, ch1])
            int_samples = np.clip(np.round(samples_2d), -32768, 32767).astype(np.int16)
            frames = int_samples.tobytes()
        else:
            int_samples = np.clip(np.round(ch0), -32768, 32767).astype(np.int16)
            frames = int_samples.tobytes()
    else:
        # Standard pseudo-random noise
        frame_size = channels * sample_width
        frames = bytes((i * 7 + 13) % 256 for i in range(num_frames * frame_size))

    write_wav(
        output_path=file_path,
        frames=frames,
        channels=channels,
        sample_width=sample_width,
        sample_rate=sample_rate,
    )
    return file_path


# ---------------------------------------------------------------------------
# Group A: Registry & Discovery Integration
# ---------------------------------------------------------------------------

class TestServiceRegistryIntegration:
    def test_registry_contains_all_three_algorithms(self) -> None:
        """Global registry accessed with include_echo=True registers LSB, DWT, and Echo."""
        reg = get_registry(include_echo=True)
        assert reg.is_registered("lsb") is True
        assert reg.is_registered("dwt_dct_qim") is True
        assert reg.is_registered("echo") is True

        assert reg.is_registered(ALGO_ID_LSB) is True
        assert reg.is_registered(ALGO_ID_DWT_DCT_QIM) is True
        assert reg.is_registered(ALGO_ID_ECHO) is True

        descriptors = {d.algorithm_id: d for d in reg.list_available()}
        assert "lsb" in descriptors
        assert "dwt_dct_qim" in descriptors
        assert "echo" in descriptors

    def test_unknown_algorithm_rejected_by_service(self, tmp_path: Path) -> None:
        """Service raises MessageEmbeddingError when an unknown algorithm identifier is requested."""
        carrier = make_test_wav_file(tmp_path / "carrier.wav", num_frames=5000)
        stego = tmp_path / "stego.wav"

        with pytest.raises(MessageEmbeddingError, match="Unsupported steganography algorithm"):
            embed_message(carrier, stego, "Message", "Password123", algorithm="quantum_entanglement")

    def test_canonical_synchronization_constants(self) -> None:
        """Verify canonical sync words match M1.6 specification."""
        assert SYNC_WORD_LSB == 0xF9A9
        assert SYNC_WORD_DWT_DCT_QIM == 0xF9A9
        assert SYNC_WORD_ECHO == 0x596A


# ---------------------------------------------------------------------------
# Group B: Multi-Algorithm Service Embedding & Extraction
# ---------------------------------------------------------------------------

class TestServiceMultiAlgorithmWorkflows:
    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_end_to_end_embedding_and_extraction(self, tmp_path: Path, algorithm: str) -> None:
        """
        Full end-to-end workflow for each algorithm:
        1. Encrypt and embed secret message.
        2. Verify returned EmbedMessageResult metadata and output file.
        3. Verify carrier contains encrypted ciphertext, not plaintext.
        4. Extract and decrypt message, verifying bit-for-bit match.
        """
        carrier = make_test_wav_file(tmp_path / f"carrier_{algorithm}.wav", num_frames=2500000)
        stego = tmp_path / f"stego_{algorithm}.wav"
        secret = f"CryptAudio multi-algorithm workflow verification for {algorithm}!"
        password = f"SecurePass_{algorithm}_2026!"

        # 1. Embed
        result = embed_message(carrier, stego, secret, password, algorithm=algorithm)
        assert isinstance(result, EmbedMessageResult)
        assert result.success is True
        assert result.algorithm_id == algorithm
        assert stego.is_file()
        assert result.payload_size_bytes >= 49
        assert result.framed_size_bytes > result.payload_size_bytes
        assert result.utilization_percent > 0.0

        # 2. Verify carrier does NOT contain plaintext
        stego_raw_bytes = stego.read_bytes()
        assert secret.encode("utf-8") not in stego_raw_bytes

        # 3. Extract detailed
        detailed = extract_message_detailed(stego, password, algorithm=algorithm)
        assert isinstance(detailed, ExtractMessageResult)
        assert detailed.success is True
        assert detailed.algorithm_id == algorithm
        assert detailed.message == secret
        assert detailed.framing_checksum_verified is True

        # 4. Extract standard (backward compatibility)
        extracted_text = extract_message(stego, password, algorithm=algorithm)
        assert extracted_text == secret

    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_multilingual_unicode_support(self, tmp_path: Path, algorithm: str) -> None:
        """Verify robust Unicode text embedding and decryption across all algorithms."""
        carrier = make_test_wav_file(tmp_path / f"carrier_multi_{algorithm}.wav", num_frames=2500000)
        stego = tmp_path / f"stego_multi_{algorithm}.wav"
        multilingual_secret = "CryptAudio: ગુપ્ત संदेश 日本語 🔐"
        password = "MultilingualPassword#2026"

        embed_message(carrier, stego, multilingual_secret, password, algorithm=algorithm)
        recovered = extract_message(stego, password, algorithm=algorithm)
        assert recovered == multilingual_secret

    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_wrong_password_fails_decryption(self, tmp_path: Path, algorithm: str) -> None:
        """Wrong password raises MessageExtractionError with authentication failure message."""
        carrier = make_test_wav_file(tmp_path / f"carrier_wp_{algorithm}.wav", num_frames=2500000)
        stego = tmp_path / f"stego_wp_{algorithm}.wav"

        embed_message(carrier, stego, "Classified Information", "CorrectPass123", algorithm=algorithm)

        with pytest.raises(MessageExtractionError, match="Authentication or decryption failed"):
            extract_message(stego, "WrongPassword456", algorithm=algorithm)


# ---------------------------------------------------------------------------
# Group C: Automatic Algorithm Detection
# ---------------------------------------------------------------------------

class TestServiceAutomaticAlgorithmDetection:
    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_auto_detection_resolves_correct_algorithm(self, tmp_path: Path, algorithm: str) -> None:
        """
        When algorithm=None or algorithm='auto', the service automatically detects
        and resolves the correct algorithm from the stego carrier.
        """
        carrier = make_test_wav_file(tmp_path / f"carrier_auto_{algorithm}.wav", num_frames=2500000)
        stego = tmp_path / f"stego_auto_{algorithm}.wav"
        secret = f"Automatic detection payload for {algorithm}"
        password = "AutoDetectPassword2026!"

        embed_message(carrier, stego, secret, password, algorithm=algorithm)

        # Extract with algorithm=None
        res_none = extract_message_detailed(stego, password, algorithm=None)
        assert res_none.algorithm_id == algorithm
        assert res_none.message == secret

        # Extract with algorithm='auto'
        res_auto = extract_message_detailed(stego, password, algorithm="auto")
        assert res_auto.algorithm_id == algorithm
        assert res_auto.message == secret


# ---------------------------------------------------------------------------
# Group D: Capacity Estimation & Metadata Inspection
# ---------------------------------------------------------------------------

class TestServiceCapacityAndMetadata:
    def test_estimate_capacity_all_three_algorithms(self, tmp_path: Path) -> None:
        """Capacity profiles reflect distinct mathematical formulas per algorithm."""
        carrier = make_test_wav_file(tmp_path / "carrier_cap.wav", num_frames=2500000, channels=2)
        message = "Test message for capacity benchmarking"

        cap_lsb = estimate_capacity(carrier, message, algorithm="lsb")
        assert cap_lsb.algorithm_id == "lsb"
        assert cap_lsb.can_fit is True
        assert cap_lsb.available_bits > 0

        cap_dwt = estimate_capacity(carrier, message, algorithm="dwt_dct_qim")
        assert cap_dwt.algorithm_id == "dwt_dct_qim"
        assert cap_dwt.can_fit is True
        # DWT embeds 128 bits per 4096-sample chunk = 1230000 / 4096 * 128 approx 38400 bits
        assert cap_dwt.available_bits < cap_lsb.available_bits

        cap_echo = estimate_capacity(carrier, message, algorithm="echo")
        assert cap_echo.algorithm_id == "echo"
        assert cap_echo.can_fit is True
        # Echo embeds 1 bit per 2048-sample segment = 1230000 / 2048 approx 600 bits
        assert cap_echo.available_bits < cap_dwt.available_bits

    def test_insufficient_capacity_raises_service_error(self, tmp_path: Path) -> None:
        """Carrier too small raises InsufficientAudioCapacityError with clear guidance."""
        carrier = make_test_wav_file(tmp_path / "tiny_carrier.wav", num_frames=500, channels=2)
        stego = tmp_path / "tiny_stego.wav"
        long_message = "A" * 500

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier, stego, long_message, "Pass123", algorithm="echo")

    def test_inspect_stego_metadata_clean_and_stego(self, tmp_path: Path) -> None:
        """inspect_stego_metadata distinguishes clean carriers from stego carriers."""
        carrier = make_test_wav_file(tmp_path / "clean_insp.wav", num_frames=1230000)
        clean_insp = inspect_stego_metadata(carrier)
        assert clean_insp["has_stego_signature"] is False
        assert clean_insp["detected_algorithm"] is None

        # Embed DWT
        stego_dwt = tmp_path / "stego_insp_dwt.wav"
        embed_message(carrier, stego_dwt, "DWT Insp Test", "Pass123", algorithm="dwt_dct_qim")

        dwt_insp = inspect_stego_metadata(stego_dwt)
        assert dwt_insp["has_stego_signature"] is True
        assert dwt_insp["detected_algorithm"] == "dwt_dct_qim"
        assert dwt_insp["header_valid"] is True
        assert dwt_insp["crc32_verified"] is False  # Header-only inspection does not check full payload CRC32


# ---------------------------------------------------------------------------
# Group E: Backward Compatibility with Existing Service Calls
# ---------------------------------------------------------------------------

class TestServiceBackwardCompatibility:
    def test_default_algorithm_is_lsb(self, tmp_path: Path) -> None:
        """Calling embed_message without specifying algorithm defaults to LSB."""
        carrier = make_test_wav_file(tmp_path / "carrier_compat.wav", num_frames=10000)
        stego = tmp_path / "stego_compat.wav"

        result = embed_message(carrier, stego, "Legacy default check", "Pass123")
        assert result.algorithm_id == "lsb"

        # Calling extract_message with 2 arguments only (stego, password)
        msg = extract_message(stego, "Pass123")
        assert msg == "Legacy default check"


# ---------------------------------------------------------------------------
# Group F: M5.1 LSB Capacity Agreement & Detection Failure Tests
# ---------------------------------------------------------------------------

class TestServiceLsbCapacityAgreement:
    def test_mono_carrier_capacity_agreement(self, tmp_path: Path) -> None:
        """Reported capacity and actual embedding feasibility agree on mono carriers."""
        num_frames = 1000
        carrier = make_test_wav_file(tmp_path / "mono_carrier.wav", num_frames=num_frames, channels=1)
        stego = tmp_path / "mono_stego.wav"

        # Fit message
        fit_msg = "Hello"
        est_fit = estimate_capacity(carrier, fit_msg, algorithm="lsb")
        assert est_fit.available_bits == num_frames
        assert est_fit.can_fit is True

        res = embed_message(carrier, stego, fit_msg, "Password123", algorithm="lsb")
        assert res.success is True
        decrypted = extract_message(stego, "Password123")
        assert decrypted == fit_msg

        # Exceed message (requires more than 1000 bits)
        big_msg = "A" * 200  # 200B msg + 49B crypto + 18B header = 267B = 2136 bits
        est_big = estimate_capacity(carrier, big_msg, algorithm="lsb")
        assert est_big.available_bits == num_frames
        assert est_big.can_fit is False

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier, tmp_path / "fail_stego.wav", big_msg, "Password123", algorithm="lsb")

    def test_stereo_carrier_capacity_channel0_policy_agreement(self, tmp_path: Path) -> None:
        """Stereo carrier capacity is strictly Channel 0 (frame_count), matching embedding."""
        num_frames = 1000
        # 1000 frames in stereo = 2000 total samples, but Channel 0 has only 1000 samples
        carrier = make_test_wav_file(tmp_path / "stereo_carrier.wav", num_frames=num_frames, channels=2)
        stego = tmp_path / "stereo_stego.wav"

        # Fit message
        fit_msg = "Fits Channel 0"
        est_fit = estimate_capacity(carrier, fit_msg, algorithm="lsb")
        assert est_fit.available_bits == num_frames  # 1000 bits, NOT 2000 bits
        assert est_fit.can_fit is True

        res = embed_message(carrier, stego, fit_msg, "Password123", algorithm="lsb")
        assert res.success is True
        assert extract_message(stego, "Password123") == fit_msg

        # Message that would fit in 2000 samples but exceeds 1000 samples
        # E.g., 90 bytes msg: 90 + 49 + 18 = 157 bytes = 1256 bits (> 1000 bits, < 2000 bits)
        medium_msg = "M" * 90
        est_medium = estimate_capacity(carrier, medium_msg, algorithm="lsb")
        assert est_medium.available_bits == num_frames
        assert est_medium.can_fit is False  # Correctly identifies it cannot fit in Channel 0

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier, tmp_path / "fail_stereo.wav", medium_msg, "Password123", algorithm="lsb")

    def test_explicit_legacy_cslb_framing_capacity_and_embedding(self, tmp_path: Path) -> None:
        """Explicit legacy framing uses all samples (frame_count * channels)."""
        num_frames = 1000
        carrier = make_test_wav_file(tmp_path / "legacy_stereo.wav", num_frames=num_frames, channels=2)
        stego = tmp_path / "legacy_stego.wav"

        # Medium message (1256 bits): fits across all 2000 samples
        medium_msg = "M" * 90
        est_legacy = estimate_capacity(carrier, medium_msg, algorithm="legacy_cslb")
        assert est_legacy.available_bits == 2000
        assert est_legacy.can_fit is True

        res = embed_message(carrier, stego, medium_msg, "Password123", algorithm="legacy_cslb")
        assert res.success is True
        assert extract_message(stego, "Password123", algorithm="legacy_cslb") == medium_msg


class TestServiceDetectionFailureHandling:
    def test_clean_audio_raises_no_valid_payload_error(self, tmp_path: Path) -> None:
        """Clean carrier with no hidden payload raises MessageExtractionError with clear text."""
        carrier = make_test_wav_file(tmp_path / "clean.wav", num_frames=10000)

        # Auto detection
        with pytest.raises(MessageExtractionError) as exc_info:
            extract_message_detailed(carrier, "Password123")
        assert "no valid hidden payload" in str(exc_info.value).lower()

        # Explicit LSB
        with pytest.raises(MessageExtractionError) as exc_info:
            extract_message_detailed(carrier, "Password123", algorithm="lsb")
        assert "no valid hidden payload" in str(exc_info.value).lower()

        # Explicit DWT
        with pytest.raises(MessageExtractionError) as exc_info:
            extract_message_detailed(carrier, "Password123", algorithm="dwt_dct_qim")
        assert "no valid hidden payload" in str(exc_info.value).lower()

    def test_corrupted_sync_word_raises_no_valid_payload_error(self, tmp_path: Path) -> None:
        """Audio with invalid synchronization word raises MessageExtractionError."""
        carrier = make_test_wav_file(tmp_path / "carrier_sync.wav", num_frames=20000)
        stego = tmp_path / "stego_corrupt_sync.wav"
        embed_message(carrier, stego, "Sync test", "Password123", algorithm="lsb")

        # Corrupt the sync word on Channel 0 (first 16 bits)
        wav_data = read_wav(stego)
        frames = bytearray(wav_data.frames)
        # Flip bits in the sync word
        for i in range(16):
            frames[i * wav_data.channels * wav_data.sample_width] ^= 1

        corrupted_wav = tmp_path / "corrupted_sync.wav"
        write_wav(corrupted_wav, bytes(frames), wav_data.channels, wav_data.sample_width, wav_data.sample_rate)

        with pytest.raises(MessageExtractionError) as exc_info:
            extract_message_detailed(corrupted_wav, "Password123")
        assert any(term in str(exc_info.value).lower() for term in ("synchronization", "no valid hidden payload"))

    def test_authentication_failure_not_classified_as_framing_checksum_failure(self, tmp_path: Path) -> None:
        """Wrong password fails with authentication error, preserving framing integrity distinction."""
        carrier = make_test_wav_file(tmp_path / "carrier_auth.wav", num_frames=20000)
        stego = tmp_path / "stego_auth.wav"
        embed_message(carrier, stego, "Secret payload", "CorrectPass123", algorithm="lsb")

        # Extraction with wrong password
        with pytest.raises(MessageExtractionError) as exc_info:
            extract_message_detailed(stego, "WrongPassword456")

        err_msg = str(exc_info.value).lower()
        assert "authentication or decryption failed" in err_msg
        assert "crc32" not in err_msg

    def test_echo_clean_audio_extraction_raises_no_valid_payload(self, tmp_path: Path) -> None:
        """Clean carrier audio extraction with echo or auto raises clear no-payload error."""
        carrier = make_test_wav_file(tmp_path / "echo_clean.wav", num_frames=300000, carrier_type="chirp")

        # Explicit algorithm="echo" on clean audio
        with pytest.raises(MessageExtractionError) as exc_echo:
            extract_message_detailed(carrier, "Password123", algorithm="echo")
        err_echo = str(exc_echo.value).lower()
        assert any(term in err_echo for term in ("no valid hidden payload", "synchronization"))

        # Automatic algorithm="auto" on clean audio
        with pytest.raises(MessageExtractionError) as exc_auto:
            extract_message_detailed(carrier, "Password123", algorithm="auto")
        err_auto = str(exc_auto.value).lower()
        assert any(term in err_auto for term in ("no valid hidden payload", "no supported steganography algorithm signature detected"))

    def test_legacy_cslb_auto_and_explicit_extraction(self, tmp_path: Path) -> None:
        """Legacy CSLB carrier is extracted via explicit legacy_cslb, explicit lsb, and auto detection."""
        num_frames = 2000
        carrier = make_test_wav_file(tmp_path / "legacy_cslb_carrier.wav", num_frames=num_frames, channels=2)
        stego = tmp_path / "legacy_cslb_stego.wav"
        msg = "Legacy backward-compatible payload"

        embed_res = embed_message(carrier, stego, msg, "Password123", algorithm="legacy_cslb")
        assert embed_res.success is True

        # Explicit algorithm="legacy_cslb"
        assert extract_message(stego, "Password123", algorithm="legacy_cslb") == msg

        # Explicit algorithm="lsb" (LSBAdapter automatically handles legacy CSLB)
        assert extract_message(stego, "Password123", algorithm="lsb") == msg

        # Automatic detection (None and "auto")
        assert extract_message(stego, "Password123", algorithm="auto") == msg
        assert extract_message(stego, "Password123", algorithm=None) == msg


# ---------------------------------------------------------------------------
# Capacity Boundary Tests (LSB, DWT-DCT-QIM, Echo Hiding)
# ---------------------------------------------------------------------------

class TestMultiAlgorithmCapacityBoundaries:
    """Rigorous capacity boundary tests across all three algorithms comparing estimation with embedding."""

    def test_lsb_capacity_boundaries(self, tmp_path: Path) -> None:
        """LSB Channel 0: test exact boundary, 1 byte above, and too short carrier."""
        # 544 frames on Channel 0 = 544 bits available.
        # Header = 18 bytes (144 bits).
        # Max crypto payload bytes = (544 - 144) // 8 = 50 bytes.
        # AES-GCM crypto overhead = 49 bytes.
        # A 1-byte message has len(crypto_payload) = 50 bytes -> exact boundary.
        # A 2-byte message has len(crypto_payload) = 51 bytes -> 1 byte above boundary.
        carrier_exact = make_test_wav_file(tmp_path / "lsb_boundary_544.wav", num_frames=544, channels=2)

        # 1. Exact boundary
        msg_1b = "A"
        est_exact = estimate_capacity(carrier_exact, msg_1b, algorithm="lsb")
        assert est_exact.available_bits == 544
        assert est_exact.can_fit is True
        assert est_exact.framed_payload_bytes == 68  # 50 crypto + 18 CSMA
        assert est_exact.required_bits == 544  # 68 * 8
        assert est_exact.utilization_percent == 100.0

        stego_exact = tmp_path / "lsb_stego_exact.wav"
        res_exact = embed_message(carrier_exact, stego_exact, msg_1b, "Pass123", algorithm="lsb")
        assert res_exact.success is True
        assert res_exact.payload_size_bytes == 50
        assert res_exact.framed_size_bytes == 68
        assert res_exact.required_capacity_bits == 544
        assert res_exact.available_capacity_bits == 544
        assert extract_message(stego_exact, "Pass123", algorithm="lsb") == msg_1b

        # 2. One byte above boundary
        msg_2b = "AB"
        est_over = estimate_capacity(carrier_exact, msg_2b, algorithm="lsb")
        assert est_over.available_bits == 544
        assert est_over.can_fit is False
        assert est_over.framed_payload_bytes == 69  # 51 crypto + 18 CSMA
        assert est_over.required_bits == 552  # 69 * 8 > 544

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_exact, tmp_path / "lsb_over.wav", msg_2b, "Pass123", algorithm="lsb")

        # 3. Carrier too short for minimum header (100 frames < 144 bits header)
        carrier_short = make_test_wav_file(tmp_path / "lsb_short.wav", num_frames=100, channels=2)
        est_short = estimate_capacity(carrier_short, msg_1b, algorithm="lsb")
        assert est_short.available_bits == 100
        assert est_short.can_fit is False

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_short, tmp_path / "lsb_short_out.wav", msg_1b, "Pass123", algorithm="lsb")

    @pytest.mark.parametrize("delta", [16.0, 32.0, 64.0])
    def test_dwt_capacity_boundaries_and_deltas(self, tmp_path: Path, delta: float) -> None:
        """DWT-DCT-QIM: test exact boundary, 1 byte above, too short carrier, and custom deltas."""
        # Chunk size = 1024 frames, 16 bits per chunk.
        # Header = 18 bytes (144 bits) = 9 chunks.
        # For 50 bytes crypto payload (400 bits) -> 25 chunks.
        # Total chunks = 9 + 25 = 34 chunks = 34,816 frames.
        # Available bits = 34 * 16 = 544 bits.
        # Max payload bytes = (544 - 144) // 8 = 50 bytes.
        carrier_exact = make_test_wav_file(
            tmp_path / f"dwt_boundary_{int(delta)}.wav",
            num_frames=34816,
            channels=2,
            carrier_type="chirp",
        )

        # 1. Exact boundary (1-byte message -> 50 bytes crypto payload)
        msg_1b = "D"
        est_exact = estimate_capacity(carrier_exact, msg_1b, algorithm="dwt_dct_qim", delta=delta)
        assert est_exact.available_bits == 544
        assert est_exact.can_fit is True
        assert est_exact.framed_payload_bytes == 68
        assert est_exact.required_bits == 544
        assert est_exact.utilization_percent == 100.0

        stego_exact = tmp_path / f"dwt_stego_{int(delta)}.wav"
        res_exact = embed_message(carrier_exact, stego_exact, msg_1b, "Pass123", algorithm="dwt_dct_qim", delta=delta)
        assert res_exact.success is True
        assert res_exact.payload_size_bytes == 50
        assert res_exact.framed_size_bytes == 68
        assert res_exact.required_capacity_bits == 544
        assert res_exact.available_capacity_bits == 544
        assert extract_message(stego_exact, "Pass123", algorithm="dwt_dct_qim", delta=delta) == msg_1b

        # 2. One byte above boundary (2-byte message -> 51 bytes crypto payload)
        msg_2b = "DX"
        est_over = estimate_capacity(carrier_exact, msg_2b, algorithm="dwt_dct_qim", delta=delta)
        assert est_over.available_bits == 544
        assert est_over.can_fit is False
        assert est_over.framed_payload_bytes == 69
        assert est_over.required_bits == 552

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_exact, tmp_path / f"dwt_over_{int(delta)}.wav", msg_2b, "Pass123", algorithm="dwt_dct_qim", delta=delta)

        # 3. Carrier too short for minimum header (8 chunks = 8192 frames < 9216 frames / 144 bits)
        carrier_short = make_test_wav_file(
            tmp_path / f"dwt_short_{int(delta)}.wav",
            num_frames=8192,
            channels=2,
            carrier_type="chirp",
        )
        est_short = estimate_capacity(carrier_short, msg_1b, algorithm="dwt_dct_qim", delta=delta)
        assert est_short.available_bits == 128
        assert est_short.can_fit is False

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_short, tmp_path / f"dwt_short_out_{int(delta)}.wav", msg_1b, "Pass123", algorithm="dwt_dct_qim", delta=delta)

    @pytest.mark.parametrize("alpha", [0.08, 0.15, 0.25])
    def test_echo_capacity_boundaries_and_alphas(self, tmp_path: Path, alpha: float) -> None:
        """Echo Hiding: test exact boundary, 1 byte above, too short carrier, and custom alphas."""
        # Segment size = 2048 frames, 1 bit per segment.
        # Header = 18 bytes (144 bits) = 144 segments.
        # For 50 bytes crypto payload (400 bits) -> 400 segments.
        # Total segments = 144 + 400 = 544 segments = 544 * 2048 = 1,114,112 frames.
        # Available bits = 544 bits.
        # Max payload bytes = (544 - 144) // 8 = 50 bytes.
        carrier_exact = make_test_wav_file(
            tmp_path / f"echo_boundary_{int(alpha * 100)}.wav",
            num_frames=1114112,
            channels=2,
            carrier_type="chirp",
        )

        # 1. Exact boundary (1-byte message -> 50 bytes crypto payload)
        msg_1b = "E"
        est_exact = estimate_capacity(carrier_exact, msg_1b, algorithm="echo", alpha=alpha)
        assert est_exact.available_bits == 544
        assert est_exact.can_fit is True
        assert est_exact.framed_payload_bytes == 68
        assert est_exact.required_bits == 544
        assert est_exact.utilization_percent == 100.0

        stego_exact = tmp_path / f"echo_stego_{int(alpha * 100)}.wav"
        res_exact = embed_message(carrier_exact, stego_exact, msg_1b, "Pass123", algorithm="echo", alpha=alpha)
        assert res_exact.success is True
        assert res_exact.payload_size_bytes == 50
        assert res_exact.framed_size_bytes == 68
        assert res_exact.required_capacity_bits == 544
        assert res_exact.available_capacity_bits == 544
        assert extract_message(stego_exact, "Pass123", algorithm="echo", alpha=alpha) == msg_1b

        # 2. One byte above boundary (2-byte message -> 51 bytes crypto payload)
        msg_2b = "EX"
        est_over = estimate_capacity(carrier_exact, msg_2b, algorithm="echo", alpha=alpha)
        assert est_over.available_bits == 544
        assert est_over.can_fit is False
        assert est_over.framed_payload_bytes == 69
        assert est_over.required_bits == 552

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_exact, tmp_path / f"echo_over_{int(alpha * 100)}.wav", msg_2b, "Pass123", algorithm="echo", alpha=alpha)

        # 3. Carrier too short for minimum header (143 segments = 292,864 frames < 144 segments)
        carrier_short = make_test_wav_file(
            tmp_path / f"echo_short_{int(alpha * 100)}.wav",
            num_frames=292864,
            channels=2,
            carrier_type="chirp",
        )
        est_short = estimate_capacity(carrier_short, msg_1b, algorithm="echo", alpha=alpha)
        assert est_short.available_bits == 143
        assert est_short.can_fit is False

        with pytest.raises(InsufficientAudioCapacityError):
            embed_message(carrier_short, tmp_path / f"echo_short_out_{int(alpha * 100)}.wav", msg_1b, "Pass123", algorithm="echo", alpha=alpha)


# ---------------------------------------------------------------------------
# Temporary-File Lifecycle Tests (Service Layer)
# ---------------------------------------------------------------------------

class TestServiceTemporaryFileLifecycle:
    """Service-level tests verifying temporary file cleanup and error handling."""

    def test_output_validation_failure_cleans_up_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Output WAV validation failure after writing automatically unlinks partial file."""
        from app.audio.wav_handler import AudioError
        isolated_dir = tmp_path / "isolated_validation_fail"
        isolated_dir.mkdir()
        carrier = make_test_wav_file(isolated_dir / "valid_carrier.wav", num_frames=10000)
        out_path = isolated_dir / "invalid_output.wav"

        initial_files = {carrier}

        # Monkeypatch inspect_wav in cryptaudio_service to simulate output validation failure
        def mock_inspect_wav(path: Path) -> None:
            raise AudioError("Simulated post-write corruption")

        monkeypatch.setattr("app.services.cryptaudio_service.inspect_wav", mock_inspect_wav)

        with pytest.raises(MessageEmbeddingError) as exc_info:
            embed_message(carrier, out_path, "Secret", "Pass123", algorithm="lsb")

        assert "failed validation" in str(exc_info.value).lower()
        # Verify that no unexpected temporary or partial output files remain in the isolated directory
        assert set(isolated_dir.iterdir()) == initial_files

    def test_cleanup_file_safely_suppresses_oserror(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_cleanup_file_safely gracefully suppresses OSError during unlinking."""
        from app.services.cryptaudio_service import _cleanup_file_safely

        test_file = tmp_path / "locked_file.wav"
        test_file.write_bytes(b"dummy")

        def mock_unlink(self: Path) -> None:
            raise OSError("Simulated Windows file lock / permission denied")

        monkeypatch.setattr(Path, "unlink", mock_unlink)

        # Must not raise
        _cleanup_file_safely(test_file)

    def test_partial_output_cleanup_after_write_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """If write_wav leaves a partial file and raises AudioError, file is removed."""
        from app.audio.wav_handler import AudioError
        isolated_dir = tmp_path / "isolated_write_fail"
        isolated_dir.mkdir()
        carrier = make_test_wav_file(isolated_dir / "carrier_write_fail.wav", num_frames=10000)
        out_path = isolated_dir / "partial_output.wav"

        initial_files = {carrier}

        def mock_write_wav(**kwargs: Any) -> None:
            out_p = Path(kwargs["output_path"])
            out_p.write_bytes(b"partial_corrupt_data")
            raise AudioError("Simulated disk write failure")

        monkeypatch.setattr("app.services.cryptaudio_service.write_wav", mock_write_wav)

        with pytest.raises(MessageEmbeddingError) as exc_info:
            embed_message(carrier, out_path, "Secret", "Pass123", algorithm="lsb")

        assert "failed to write output" in str(exc_info.value).lower()
        # Verify that the partial output file was removed and only initial carrier remains
        assert set(isolated_dir.iterdir()) == initial_files

    def test_extraction_wrong_password_leaves_no_temp_files(self, tmp_path: Path) -> None:
        """Wrong password during extraction leaves no unexpected temporary files in the directory."""
        isolated_dir = tmp_path / "isolated_wrong_pass"
        isolated_dir.mkdir()
        carrier = make_test_wav_file(isolated_dir / "carrier.wav", num_frames=20000)
        stego = isolated_dir / "stego.wav"
        embed_message(carrier, stego, "Hello", "CorrectPass", algorithm="lsb")

        initial_files = set(isolated_dir.iterdir())
        assert initial_files == {carrier, stego}

        with pytest.raises(MessageExtractionError):
            extract_message_detailed(stego, "WrongPass")

        # Verify that no temporary files were created or orphaned in the directory
        assert set(isolated_dir.iterdir()) == initial_files

    def test_extraction_no_payload_leaves_no_temp_files(self, tmp_path: Path) -> None:
        """Extracting from clean audio raises no-payload without creating or leaking temporary files."""
        isolated_dir = tmp_path / "isolated_no_payload"
        isolated_dir.mkdir()
        carrier = make_test_wav_file(isolated_dir / "clean.wav", num_frames=10000)

        initial_files = set(isolated_dir.iterdir())
        assert initial_files == {carrier}

        with pytest.raises(MessageExtractionError):
            extract_message_detailed(carrier, "AnyPass")

        # Verify that no unexpected temporary files were created or orphaned in the directory
        assert set(isolated_dir.iterdir()) == initial_files
