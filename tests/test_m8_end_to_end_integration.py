"""
tests/test_m8_end_to_end_integration.py
CryptAudio-Web — Phase M8.2 End-to-End Integration Test Suite

Verifies complete 10-step steganographic lifecycle for all 3 supported algorithms:
1. WAV upload
2. Audio inspection (/api/audio/inspect)
3. Capacity estimation (/api/capacity)
4. AES-256-GCM encryption & PBKDF2 derivation
5. Steganography embedding (/api/embed)
6. Output WAV generation & structural validity
7. Output audio playback readiness (uncompressed PCM frames)
8. Steganography extraction (/api/extract)
9. AES-256-GCM authenticated tag verification
10. Exact plaintext recovery

Covers:
- All 3 algorithms: LSB, DWT-DCT-QIM, Echo Hiding
- Unicode multilingual messages (English, Hindi, Japanese, Emojis, French)
- Empty message rejection (HTTP 400 INVALID_MESSAGE)
- Long messages near capacity limits
- Minimum-capacity carrier boundaries
- Insufficient-capacity carrier rejection (HTTP 422 INSUFFICIENT_CAPACITY)
- Wrong password handling (HTTP 422 AUTHENTICATION_FAILED)
- Corrupted synchronization rejection (HTTP 422 NO_STEGO_PAYLOAD)
- Corrupted CRC32 framing rejection (HTTP 422 PAYLOAD_CORRUPTED)
- Validly reframed ciphertext tampering rejection without plaintext leakage
"""

from __future__ import annotations

import io
import struct
import wave
import zlib
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.audio.wav_handler import inspect_wav, read_wav
from app.main import app
from app.steganography.envelope import (
    CSMA_HEADER_SIZE_BYTES,
    CSMA_MAGIC,
    create_csma_envelope,
    parse_csma_envelope,
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Reusable FastAPI test client."""
    return TestClient(app)


def _generate_sine_wav_bytes(
    duration_sec: float = 1.0,
    sample_rate: int = 44100,
    channels: int = 1,
    sample_width: int = 2,
    freq_hz: float = 440.0,
) -> bytes:
    """Generate a clean PCM WAV in-memory byte buffer."""
    num_samples = int(duration_sec * sample_rate)
    t = np.linspace(0, duration_sec, num_samples, endpoint=False)
    sine_wave = 0.5 * np.sin(2 * np.pi * freq_hz * t)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sample_width)
        wf.setframerate(sample_rate)

        if sample_width == 1:
            raw = np.clip((sine_wave + 1.0) * 127.5, 0, 255).astype(np.uint8).tobytes()
        elif sample_width == 2:
            raw = np.clip(sine_wave * 32767, -32768, 32767).astype(np.int16).tobytes()
        elif sample_width == 3:
            s24 = np.clip(sine_wave * 8388607, -8388608, 8388607).astype(np.int32)
            raw = bytearray()
            for s in s24:
                raw.extend(int(s).to_bytes(3, byteorder="little", signed=True))
            raw = bytes(raw)
        elif sample_width == 4:
            raw = np.clip(sine_wave * 2147483647, -2147483648, 2147483647).astype(np.int32).tobytes()
        else:
            raise ValueError(f"Unsupported sample width: {sample_width}")

        if channels == 2:
            # Duplicate mono to stereo
            if sample_width == 1:
                arr = np.frombuffer(raw, dtype=np.uint8)
                raw = np.column_stack((arr, arr)).tobytes()
            elif sample_width == 2:
                arr = np.frombuffer(raw, dtype=np.int16)
                raw = np.column_stack((arr, arr)).tobytes()
            elif sample_width == 4:
                arr = np.frombuffer(raw, dtype=np.int32)
                raw = np.column_stack((arr, arr)).tobytes()
            elif sample_width == 3:
                stereo_24 = bytearray()
                for i in range(0, len(raw), 3):
                    chunk = raw[i : i + 3]
                    stereo_24.extend(chunk)
                    stereo_24.extend(chunk)
                raw = bytes(stereo_24)

        wf.writeframes(raw)

    return buf.getvalue()


def _generate_chirp_wav_bytes(
    duration_sec: float = 33.0,
    sample_rate: int = 44100,
) -> bytes:
    """Generate wideband chirp audio providing flat cepstral properties for Echo Hiding."""
    segment_size = 2048
    segments = int(np.ceil((duration_sec * sample_rate) / segment_size))
    total_samples = segments * segment_size

    t_seg = np.arange(segment_size, dtype=np.float64) / sample_rate
    f0, f1 = 200.0, 6000.0
    seg_chirp = np.sin(2.0 * np.pi * (f0 + (f1 - f0) / (2.0 * (segment_size / sample_rate)) * t_seg) * t_seg)
    samples = np.tile(seg_chirp, segments) * 28000.0
    pcm16 = np.clip(samples, -32768, 32767).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm16.tobytes())
    return buf.getvalue()

class TestAlgorithmLifecycle:
    """Validates the full 10-step lifecycle for LSB, DWT-DCT-QIM, and Echo Hiding."""

    def test_lsb_full_10_step_lifecycle(self, client: TestClient, tmp_path: Path) -> None:
        """10-Step test for LSB steganography."""
        carrier_wav = _generate_sine_wav_bytes(duration_sec=2.0)
        secret_msg = "CryptAudio LSB Verification 2026! 🔒"
        password = "LSB_Secret_Password_#2026"

        # 1. Audio Inspection
        resp_inspect = client.post(
            "/api/audio/inspect",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"algorithm": "lsb"},
        )
        assert resp_inspect.status_code == 200
        inspect_data = resp_inspect.json()
        assert inspect_data["success"] is True
        assert inspect_data["audio"]["sample_rate"] == 44100
        assert inspect_data["capacity"]["total_samples"] == 88200

        # 2. Capacity Estimation
        resp_cap = client.post(
            "/api/capacity",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": secret_msg, "algorithm": "lsb"},
        )
        assert resp_cap.status_code == 200
        cap_data = resp_cap.json()
        assert cap_data["success"] is True
        assert cap_data["can_fit"] is True
        assert cap_data["available_bits"] == 88200

        # 3. Payload Embedding (includes AES-256-GCM encryption)
        resp_embed = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": secret_msg, "password": password, "algorithm": "lsb"},
        )
        assert resp_embed.status_code == 200
        assert resp_embed.headers["content-type"] == "audio/wav"
        assert resp_embed.headers["x-stego-algorithm"] == "lsb"
        stego_bytes = resp_embed.content

        # 4. Output WAV Verification & Playback Structure
        stego_file = tmp_path / "stego_lsb.wav"
        stego_file.write_bytes(stego_bytes)
        info = inspect_wav(stego_file)
        assert info.channels == 1
        assert info.bit_depth == 16
        assert info.sample_rate == 44100
        assert info.frame_count == 88200

        # 5. Extraction & Authenticated Decryption
        resp_extract = client.post(
            "/api/extract",
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
            data={"password": password, "algorithm": "auto"},
        )
        assert resp_extract.status_code == 200
        extract_data = resp_extract.json()
        assert extract_data["success"] is True
        assert extract_data["message"] == secret_msg
        assert extract_data["algorithm"] == "lsb"
        assert extract_data["framing_checksum_verified"] is True

        # 6. Audio Distortion Evaluation
        resp_eval = client.post(
            "/api/analyze",
            files={
                "original_file": ("orig.wav", carrier_wav, "audio/wav"),
                "stego_file": ("stego.wav", stego_bytes, "audio/wav"),
            },
        )
        assert resp_eval.status_code == 200
        eval_data = resp_eval.json()
        assert eval_data["success"] is True
        assert eval_data["analysis"]["psnr_db"] > 80.0

    @pytest.mark.parametrize("delta", [16, 32, 64])
    def test_dwt_dct_qim_full_10_step_lifecycle(self, client: TestClient, tmp_path: Path, delta: int) -> None:
        """10-Step test for DWT-DCT-QIM across supported delta quantization steps."""
        carrier_wav = _generate_sine_wav_bytes(duration_sec=6.0)
        secret_msg = f"DWT Delta={delta} Test Payload"
        password = "DWT_Secret_Password_2026"

        # 1. Audio Inspection
        resp_inspect = client.post(
            "/api/audio/inspect",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"algorithm": "dwt_dct_qim"},
        )
        assert resp_inspect.status_code == 200

        # 2. Capacity Estimation
        resp_cap = client.post(
            "/api/capacity",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": secret_msg, "algorithm": "dwt_dct_qim", "delta": delta},
        )
        assert resp_cap.status_code == 200
        cap_data = resp_cap.json()
        assert cap_data["can_fit"] is True
        assert cap_data["algorithm"] == "dwt_dct_qim"

        # 3. Payload Embedding
        resp_embed = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={
                "message": secret_msg,
                "password": password,
                "algorithm": "dwt_dct_qim",
                "delta": delta,
            },
        )
        assert resp_embed.status_code == 200
        assert resp_embed.headers["x-stego-algorithm"] == "dwt_dct_qim"
        stego_bytes = resp_embed.content

        # 4. Output WAV Verification
        stego_file = tmp_path / f"stego_dwt_{delta}.wav"
        stego_file.write_bytes(stego_bytes)
        info = inspect_wav(stego_file)
        assert info.channels == 1
        assert info.sample_rate == 44100
        assert info.bit_depth == 16

        # 5. Extraction & Decryption (explicit algorithm with delta, then auto algorithm)
        resp_extract1 = client.post(
            "/api/extract",
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
            data={"password": password, "algorithm": "dwt_dct_qim", "delta": delta},
        )
        assert resp_extract1.status_code == 200
        ext1 = resp_extract1.json()
        assert ext1["success"] is True
        assert ext1["message"] == secret_msg
        assert ext1["algorithm"] == "dwt_dct_qim"

        resp_extract2 = client.post(
            "/api/extract",
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
            data={"password": password, "algorithm": "auto"},
        )
        assert resp_extract2.status_code == 200
        ext2 = resp_extract2.json()
        assert ext2["success"] is True
        assert ext2["message"] == secret_msg
        assert ext2["algorithm"] == "dwt_dct_qim"

    @pytest.mark.parametrize("alpha", [0.08, 0.12])
    def test_echo_hiding_full_10_step_lifecycle(self, client: TestClient, tmp_path: Path, alpha: float) -> None:
        """10-Step test for Echo Hiding across supported alpha attenuation factors."""
        # Echo hiding embeds 1 bit per 2048 samples; 33s carrier provides ~710 bits (~88 bytes)
        carrier_wav = _generate_chirp_wav_bytes(duration_sec=33.0)
        secret_msg = f"Echo {alpha}"
        password = "Echo_Secret_Password_2026"

        # 1. Capacity Estimation
        resp_cap = client.post(
            "/api/capacity",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": secret_msg, "algorithm": "echo", "alpha": alpha},
        )
        assert resp_cap.status_code == 200
        assert resp_cap.json()["can_fit"] is True

        # 2. Embedding
        resp_embed = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={
                "message": secret_msg,
                "password": password,
                "algorithm": "echo",
                "alpha": alpha,
            },
        )
        assert resp_embed.status_code == 200
        stego_bytes = resp_embed.content

        # 3. Extraction (explicit with alpha, then auto)
        resp_extract1 = client.post(
            "/api/extract",
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
            data={"password": password, "algorithm": "echo", "alpha": alpha},
        )
        assert resp_extract1.status_code == 200
        ext1 = resp_extract1.json()
        assert ext1["success"] is True
        assert ext1["message"] == secret_msg
        assert ext1["algorithm"] == "echo"

        resp_extract2 = client.post(
            "/api/extract",
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
            data={"password": password, "algorithm": "auto"},
        )
        assert resp_extract2.status_code == 200
        ext2 = resp_extract2.json()
        assert ext2["success"] is True
        assert ext2["message"] == secret_msg
        assert ext2["algorithm"] == "echo"


# ===========================================================================
# 2. Payload Diversity & Edge Case Matrices
# ===========================================================================

class TestPayloadDiversityAndEdgeCases:
    """Verifies Unicode, long messages, empty messages, and boundary conditions."""

    def test_unicode_multilingual_payloads(self, client: TestClient) -> None:
        """Verifies diverse multilingual Unicode strings across all scripts."""
        carrier_wav = _generate_sine_wav_bytes(duration_sec=4.0)
        password = "Unicode_Pass_2026!"

        multilingual_payloads = [
            "Hindi: नमस्ते दुनिया! यह एक गुप्त संदेश है 🔐",
            "Japanese: こんにちは世界！極秘メッセージです 🚀",
            "French Accents: Café, naïve, résumé, protégé, fête",
            "Complex Emojis: 🛡️ ✨ 🔒 🎧 📊 ⚡ 🌍 🤖",
            "Special Symbols: !@#$%^&*()_+-=[]{}|;':\",./<>?`~",
        ]

        for msg in multilingual_payloads:
            # Embed
            resp_embed = client.post(
                "/api/embed",
                files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
                data={"message": msg, "password": password, "algorithm": "lsb"},
            )
            assert resp_embed.status_code == 200

            # Extract
            resp_extract = client.post(
                "/api/extract",
                files={"file": ("stego.wav", resp_embed.content, "audio/wav")},
                data={"password": password},
            )
            assert resp_extract.status_code == 200
            assert resp_extract.json()["message"] == msg

    def test_empty_message_rejected(self, client: TestClient) -> None:
        """Verifies empty and whitespace-only secret messages are rejected with HTTP 400."""
        carrier_wav = _generate_sine_wav_bytes(duration_sec=1.0)

        for empty_val in ["", "   ", "\t\n  "]:
            # Capacity check
            resp_cap = client.post(
                "/api/capacity",
                files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
                data={"message": empty_val, "algorithm": "lsb"},
            )
            assert resp_cap.status_code == 400
            assert resp_cap.json()["error"]["code"] == "INVALID_MESSAGE"

            # Embed check
            resp_embed = client.post(
                "/api/embed",
                files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
                data={"message": empty_val, "password": "pass", "algorithm": "lsb"},
            )
            assert resp_embed.status_code == 400
            assert resp_embed.json()["error"]["code"] == "INVALID_MESSAGE"

    def test_long_message_capacity_boundaries(self, client: TestClient) -> None:
        """Verifies large message embedding up to available capacity limit."""
        # 3.0s carrier @ 44.1 kHz = 132,300 samples -> ~16,537 bytes raw capacity for LSB
        carrier_wav = _generate_sine_wav_bytes(duration_sec=3.0)
        password = "Long_Message_Pass_2026"

        # 5,000 character message
        long_msg = "CryptAudio High Volume Payload Data Block. " * 115  # ~5,000 bytes
        assert len(long_msg.encode("utf-8")) > 4800

        resp_embed = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": long_msg, "password": password, "algorithm": "lsb"},
        )
        assert resp_embed.status_code == 200

        resp_extract = client.post(
            "/api/extract",
            files={"file": ("stego.wav", resp_embed.content, "audio/wav")},
            data={"password": password},
        )
        assert resp_extract.status_code == 200
        assert resp_extract.json()["message"] == long_msg

    def test_minimum_capacity_carrier_boundary(self, client: TestClient) -> None:
        """Verifies carrier with exact minimal required frames can embed minimal envelope."""
        # CSMA (18B) + AES overhead (49B) + 1-byte message = 68 bytes = 544 bits
        # In LSB, 544 samples is the absolute minimum. Let's provide 600 samples.
        num_samples = 600
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(np.zeros(num_samples, dtype=np.int16).tobytes())
        min_carrier = buf.getvalue()

        resp_embed = client.post(
            "/api/embed",
            files={"file": ("min.wav", min_carrier, "audio/wav")},
            data={"message": "A", "password": "pass", "algorithm": "lsb"},
        )
        assert resp_embed.status_code == 200

        resp_extract = client.post(
            "/api/extract",
            files={"file": ("stego.wav", resp_embed.content, "audio/wav")},
            data={"password": "pass"},
        )
        assert resp_extract.status_code == 200
        assert resp_extract.json()["message"] == "A"

    def test_insufficient_capacity_carrier_rejected(self, client: TestClient) -> None:
        """Verifies that carriers with insufficient samples are rejected with HTTP 422."""
        # 100 samples is far below the 536-bit minimum envelope
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(np.zeros(100, dtype=np.int16).tobytes())
        too_small_carrier = buf.getvalue()

        # Capacity check rejects
        resp_cap = client.post(
            "/api/capacity",
            files={"file": ("small.wav", too_small_carrier, "audio/wav")},
            data={"message": "Hello", "algorithm": "lsb"},
        )
        assert resp_cap.status_code == 200
        assert resp_cap.json()["can_fit"] is False

        # Embed check rejects with HTTP 422
        resp_embed = client.post(
            "/api/embed",
            files={"file": ("small.wav", too_small_carrier, "audio/wav")},
            data={"message": "Hello", "password": "pass", "algorithm": "lsb"},
        )
        assert resp_embed.status_code == 422
        assert resp_embed.json()["error"]["code"] == "INSUFFICIENT_CAPACITY"


# ===========================================================================
# 3. Security & Tamper Rejection (Plaintext Secrecy Guarantee)
# ===========================================================================

class TestSecurityAndTamperRejection:
    """Verifies that an unsuccessful extraction NEVER exposes unverified plaintext."""

    @pytest.fixture
    def stego_sample(self, client: TestClient) -> tuple[bytes, str, str]:
        """Produce a valid stego WAV with known message and password."""
        carrier = _generate_sine_wav_bytes(duration_sec=2.0)
        msg = "Top Secret Classified Intelligence 2026"
        pwd = "Correct_Strong_Password_#1"
        resp = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier, "audio/wav")},
            data={"message": msg, "password": pwd, "algorithm": "lsb"},
        )
        assert resp.status_code == 200
        return resp.content, msg, pwd

    def test_wrong_password_rejected_without_plaintext_leak(
        self, client: TestClient, stego_sample: tuple[bytes, str, str]
    ) -> None:
        """Wrong password fails AES-GCM GHASH verification; response never leaks plaintext."""
        stego_bytes, secret_msg, _ = stego_sample

        wrong_passwords = ["wrongpass", "Correct_Strong_Password_#2", "admin", "12345678"]
        for bad_pwd in wrong_passwords:
            resp = client.post(
                "/api/extract",
                files={"file": ("stego.wav", stego_bytes, "audio/wav")},
                data={"password": bad_pwd},
            )
            assert resp.status_code == 422
            data = resp.json()
            assert data["success"] is False
            assert data["error"]["code"] == "AUTHENTICATION_FAILED"
            # Plaintext assertion: secret message must never appear in response
            assert secret_msg not in resp.text
            assert "message" not in data

    def test_corrupted_synchronization_marker_rejected(
        self, client: TestClient, stego_sample: tuple[bytes, str, str]
    ) -> None:
        """Corrupting carrier samples that hold the CSMA sync marker triggers NO_STEGO_PAYLOAD."""
        stego_bytes, secret_msg, pwd = stego_sample

        # Corrupt the first 32 audio samples in the WAV container
        # WAV header is 44 bytes; samples follow
        stego_arr = bytearray(stego_bytes)
        for i in range(44, 44 + 64):
            stego_arr[i] ^= 0x01  # Flip LSB

        resp = client.post(
            "/api/extract",
            files={"file": ("stego.wav", bytes(stego_arr), "audio/wav")},
            data={"password": pwd},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["error"]["code"] == "NO_STEGO_PAYLOAD"
        assert secret_msg not in resp.text

    def test_corrupted_crc32_checksum_rejected(
        self, client: TestClient, stego_sample: tuple[bytes, str, str]
    ) -> None:
        """Corrupting payload bits triggers CRC32 failure before cryptographic decryption."""
        stego_bytes, secret_msg, pwd = stego_sample

        # In LSB, header is 18 bytes (144 bits/samples).
        # Sample 44 + (144 * 2) = 44 + 288 is the start of payload samples.
        # Flip a bit in the encrypted payload portion
        stego_arr = bytearray(stego_bytes)
        payload_sample_offset = 44 + 288 + 20
        stego_arr[payload_sample_offset] ^= 0x01

        resp = client.post(
            "/api/extract",
            files={"file": ("stego.wav", bytes(stego_arr), "audio/wav")},
            data={"password": pwd},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["error"]["code"] == "PAYLOAD_CORRUPTED"
        assert secret_msg not in resp.text

    def test_validly_reframed_ciphertext_tampering_rejected(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """
        Attacker alters ciphertext bytes and updates CRC32 so framing passes.
        AES-256-GCM authentication tag must fail, rejecting extraction without plaintext leakage.
        """
        carrier_wav = _generate_sine_wav_bytes(duration_sec=2.0)
        secret_msg = "Super Sensitive Corporate Secret 2026"
        pwd = "Pass_Tamper_Test_#2026"

        resp_embed = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_wav, "audio/wav")},
            data={"message": secret_msg, "password": pwd, "algorithm": "lsb"},
        )
        assert resp_embed.status_code == 200
        stego_bytes = resp_embed.content

        # Parse the embedded LSB envelope
        stego_path = tmp_path / "stego_raw.wav"
        stego_path.write_bytes(stego_bytes)
        wav_data = read_wav(stego_path)

        # Extract bits from LSB
        samples = np.frombuffer(wav_data.frames, dtype=np.int16).copy()
        raw_bits = np.bitwise_and(samples, 1).astype(np.uint8)
        packed_bytes = np.packbits(raw_bits).tobytes()

        # Parse valid envelope
        envelope = parse_csma_envelope(packed_bytes)
        assert envelope is not None

        # Tamper 1 byte of the encrypted payload (e.g., in ciphertext or GHASH tag)
        tampered_payload = bytearray(envelope.payload)
        tampered_payload[-5] ^= 0xFF  # Flip byte in GHASH tag / ciphertext

        # Recompute framing envelope with matching CRC32 for the tampered payload
        reframed_bytes = create_csma_envelope(bytes(tampered_payload), algorithm=0x01)

        # Re-embed tampered reframed bits into carrier samples
        reframed_bits = np.unpackbits(np.frombuffer(reframed_bytes, dtype=np.uint8))
        samples[: len(reframed_bits)] = (samples[: len(reframed_bits)] & ~1) | reframed_bits

        # Save tampered WAV
        tampered_wav_path = tmp_path / "stego_tampered.wav"
        with wave.open(str(tampered_wav_path), "wb") as wf:
            wf.setnchannels(wav_data.channels)
            wf.setsampwidth(wav_data.sample_width)
            wf.setframerate(wav_data.sample_rate)
            wf.writeframes(samples.tobytes())

        tampered_wav_bytes = tampered_wav_path.read_bytes()

        # Attempt extraction on the validly reframed but tampered ciphertext
        resp_extract = client.post(
            "/api/extract",
            files={"file": ("tampered.wav", tampered_wav_bytes, "audio/wav")},
            data={"password": pwd},
        )
        assert resp_extract.status_code == 422
        data = resp_extract.json()
        assert data["success"] is False
        assert data["error"]["code"] == "AUTHENTICATION_FAILED"
        assert secret_msg not in resp_extract.text
