"""
tests/test_api_multi_algorithm.py
CryptAudio Web — Multi-Algorithm API Integration Test Suite (Phase M5)

Tests FastAPI endpoints with multi-algorithm extensions:
1. GET /api/algorithms: lists all three algorithms with standardized descriptors.
2. POST /api/embed: supports algorithm selection (lsb, dwt_dct_qim, echo) and defaults to lsb.
3. POST /api/extract: supports explicit algorithm selection and automatic detection.
4. POST /api/capacity: evaluates algorithm-specific capacity for carriers.
5. POST /api/audio/inspect: exposes non-destructive multi-algorithm steganography inspection.
6. Error handling: HTTP 400 for unknown algorithm, HTTP 422 for authentication failure and corruption.
7. Security: temporary file cleanup, no sensitive data or stack traces leaked.
"""

from __future__ import annotations

import io
import os
import sys
import struct
import wave
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.core.config import settings
from app.main import app
from app.steganography.lsb_engine import bytes_to_bits


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI TestClient instance."""
    return TestClient(app, raise_server_exceptions=False)


def create_api_test_wav_bytes(
    num_frames: int = 1500000,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
) -> bytes:
    """Generate in-memory WAV bytes with chirp properties for all algorithms."""
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
    else:
        int_samples = np.clip(np.round(ch0), -32768, 32767).astype(np.int16)

    bio = io.BytesIO()
    with wave.open(bio, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(int_samples.tobytes())
    return bio.getvalue()


# ---------------------------------------------------------------------------
# Group A: Algorithm Discovery Endpoint (GET /api/algorithms)
# ---------------------------------------------------------------------------

class TestApiAlgorithmDiscovery:
    def test_list_algorithms_returns_all_three(self, client: TestClient) -> None:
        """GET /api/algorithms lists LSB, DWT-DCT-QIM, and Echo Hiding."""
        res = client.get("/api/algorithms")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        algorithms = {algo["algorithm_id"]: algo for algo in data["algorithms"]}

        assert "lsb" in algorithms
        assert "dwt_dct_qim" in algorithms
        assert "echo" in algorithms

        assert algorithms["lsb"]["domain"] == "spatial_time_domain"
        assert algorithms["dwt_dct_qim"]["domain"] == "transform_domain"
        assert algorithms["echo"]["domain"] == "acoustic_time_domain"


# ---------------------------------------------------------------------------
# Group B: Multi-Algorithm Embedding (POST /api/embed)
# ---------------------------------------------------------------------------

class TestApiMultiAlgorithmEmbedding:
    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_embed_with_algorithm_selection(self, client: TestClient, algorithm: str) -> None:
        """POST /api/embed accepts algorithm selection and returns WAV with correct headers."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        msg = f"API embedding test for {algorithm}"
        pwd = f"ApiPassword_{algorithm}_123"

        res = client.post(
            "/api/embed",
            data={
                "message": msg,
                "password": pwd,
                "algorithm": algorithm,
            },
            files={"file": ("test.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "audio/wav"
        assert res.headers["x-stego-algorithm"] == algorithm
        assert int(res.headers["x-payload-size-bytes"]) >= 49
        assert float(res.headers["x-utilization-percent"]) > 0.0
        assert len(res.content) > len(wav_bytes) - 100  # Preserves audio length

    def test_embed_default_algorithm_is_lsb(self, client: TestClient) -> None:
        """POST /api/embed without algorithm parameter defaults to LSB for backward compatibility."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res = client.post(
            "/api/embed",
            data={
                "message": "Default algorithm check",
                "password": "Password123",
            },
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.headers["x-stego-algorithm"] == "lsb"

    def test_embed_unknown_algorithm_returns_400(self, client: TestClient) -> None:
        """POST /api/embed with invalid algorithm identifier returns HTTP 400 UNKNOWN_ALGORITHM."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res = client.post(
            "/api/embed",
            data={
                "message": "Test",
                "password": "Password123",
                "algorithm": "unsupported_algo",
            },
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["success"] is False
        assert data["error"]["code"] == "UNKNOWN_ALGORITHM"

    def test_embed_auto_algorithm_returns_400(self, client: TestClient) -> None:
        """POST /api/embed with explicit algorithm='auto' returns HTTP 400 INVALID_PARAMETER."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res = client.post(
            "/api/embed",
            data={
                "message": "Auto embed test",
                "password": "Password123",
                "algorithm": "auto",
            },
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INVALID_PARAMETER"
        assert "extraction" in data["error"]["message"].lower()


# ---------------------------------------------------------------------------
# Group C: Multi-Algorithm Extraction (POST /api/extract)
# ---------------------------------------------------------------------------

class TestApiMultiAlgorithmExtraction:
    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_extract_explicit_algorithm(self, client: TestClient, algorithm: str) -> None:
        """POST /api/extract recovers plaintext using explicit algorithm parameter."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        msg = f"Secret extraction payload for {algorithm}"
        pwd = f"ExtractionPassword_{algorithm}"

        # Embed
        embed_res = client.post(
            "/api/embed",
            data={"message": msg, "password": pwd, "algorithm": algorithm},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200
        stego_bytes = embed_res.content

        # Extract
        extract_res = client.post(
            "/api/extract",
            data={"password": pwd, "algorithm": algorithm},
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
        )
        assert extract_res.status_code == 200
        data = extract_res.json()
        assert data["success"] is True
        assert data["message"] == msg
        assert data["algorithm"] == algorithm

    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_extract_explicit_auto_detection(self, client: TestClient, algorithm: str) -> None:
        """POST /api/extract with explicit algorithm='auto' performs automatic detection across all algorithms."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        msg = f"Explicit auto detection test for {algorithm}"
        pwd = f"ExplicitAutoPassword_{algorithm}"

        embed_res = client.post(
            "/api/embed",
            data={"message": msg, "password": pwd, "algorithm": algorithm},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        stego_bytes = embed_res.content

        extract_res = client.post(
            "/api/extract",
            data={"password": pwd, "algorithm": "auto"},
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
        )
        assert extract_res.status_code == 200
        data = extract_res.json()
        assert data["success"] is True
        assert data["message"] == msg
        assert data["algorithm"] == algorithm
        assert data["framing_checksum_verified"] is True

    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_extract_auto_detection(self, client: TestClient, algorithm: str) -> None:
        """POST /api/extract automatically detects algorithm when algorithm parameter is omitted."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        msg = f"Auto detection test for {algorithm}"
        pwd = f"AutoPassword_{algorithm}"

        embed_res = client.post(
            "/api/embed",
            data={"message": msg, "password": pwd, "algorithm": algorithm},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        stego_bytes = embed_res.content

        # Extract without algorithm parameter
        extract_res = client.post(
            "/api/extract",
            data={"password": pwd},
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
        )
        assert extract_res.status_code == 200
        data = extract_res.json()
        assert data["success"] is True
        assert data["message"] == msg
        assert data["algorithm"] == algorithm

    def test_extract_wrong_password_returns_422(self, client: TestClient) -> None:
        """POST /api/extract with incorrect password returns HTTP 422 AUTHENTICATION_FAILED."""
        wav_bytes = create_api_test_wav_bytes(num_frames=50000)
        stego = client.post(
            "/api/embed",
            data={"message": "Target secret", "password": "CorrectPassword"},
            files={"file": ("c.wav", wav_bytes, "audio/wav")},
        ).content

        res = client.post(
            "/api/extract",
            data={"password": "WrongPassword"},
            files={"file": ("s.wav", stego, "audio/wav")},
        )
        assert res.status_code == 422
        data = res.json()
        assert data["error"]["code"] == "AUTHENTICATION_FAILED"
        assert "Authentication or decryption failed" in data["error"]["message"]


# ---------------------------------------------------------------------------
# Group D: Capacity Endpoint (POST /api/capacity)
# ---------------------------------------------------------------------------

class TestApiCapacityEndpoint:
    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_capacity_calculation_per_algorithm(self, client: TestClient, algorithm: str) -> None:
        """POST /api/capacity calculates capacity metrics per algorithm."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        res = client.post(
            "/api/capacity",
            data={
                "message": "Benchmark capacity message",
                "algorithm": algorithm,
            },
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["algorithm"] == algorithm
        assert data["can_fit"] is True
        assert data["available_bits"] > 0
        assert data["required_bits"] > 0
        assert data["utilization_percent"] > 0.0

    def test_capacity_missing_message_returns_400(self, client: TestClient) -> None:
        """POST /api/capacity with empty message returns HTTP 400 INVALID_MESSAGE."""
        wav_bytes = create_api_test_wav_bytes(num_frames=5000)
        res = client.post(
            "/api/capacity",
            data={"message": "", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_MESSAGE"

    def test_capacity_unknown_algorithm_returns_400(self, client: TestClient) -> None:
        """POST /api/capacity with unknown algorithm returns HTTP 400 UNKNOWN_ALGORITHM."""
        wav_bytes = create_api_test_wav_bytes(num_frames=5000)
        res = client.post(
            "/api/capacity",
            data={"message": "Valid text", "algorithm": "unknown_stego"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "UNKNOWN_ALGORITHM"

    def test_capacity_auto_algorithm_returns_400(self, client: TestClient) -> None:
        """POST /api/capacity with explicit algorithm='auto' returns HTTP 400 INVALID_PARAMETER."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test auto", "algorithm": "auto"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INVALID_PARAMETER"
        assert "extraction" in data["error"]["message"].lower()

    def test_capacity_default_algorithm_is_lsb(self, client: TestClient) -> None:
        """POST /api/capacity with omitted algorithm defaults to lsb."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test default"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["algorithm"] == "lsb"


# ---------------------------------------------------------------------------
# Group E: Audio Inspection Extension (POST /api/audio/inspect)
# ---------------------------------------------------------------------------

class TestApiAudioInspectMultiAlgorithm:
    def test_inspect_includes_stego_inspection_and_algorithms(self, client: TestClient) -> None:
        """POST /api/audio/inspect includes stego_inspection and available_algorithms."""
        wav_bytes = create_api_test_wav_bytes(num_frames=5000)
        res = client.post(
            "/api/audio/inspect",
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert "audio" in data
        assert "capacity" in data
        assert "stego_inspection" in data
        assert "available_algorithms" in data
        assert len(data["available_algorithms"]) == 3


# ---------------------------------------------------------------------------
# Group F: Security & Resource Lifecycle
# ---------------------------------------------------------------------------

class TestApiStrictParameterValidation:
    @pytest.mark.parametrize("delta_val", [16.0, 32.0, 64.0])
    def test_capacity_dwt_valid_delta(self, client: TestClient, delta_val: float) -> None:
        """POST /api/capacity accepts valid delta values for DWT-DCT-QIM."""
        wav_bytes = create_api_test_wav_bytes(num_frames=100000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "dwt_dct_qim", "delta": delta_val},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_capacity_dwt_rejects_invalid_delta(self, client: TestClient) -> None:
        """POST /api/capacity rejects delta values outside codebook for DWT-DCT-QIM."""
        wav_bytes = create_api_test_wav_bytes(num_frames=100000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "dwt_dct_qim", "delta": 25.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_capacity_dwt_rejects_alpha(self, client: TestClient) -> None:
        """POST /api/capacity rejects irrelevant parameter 'alpha' for DWT-DCT-QIM."""
        wav_bytes = create_api_test_wav_bytes(num_frames=100000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "dwt_dct_qim", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    @pytest.mark.parametrize("alpha_val", [0.08, 0.15, 0.25])
    def test_capacity_echo_valid_alpha(self, client: TestClient, alpha_val: float) -> None:
        """POST /api/capacity accepts valid alpha values for Echo Hiding."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2500000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "echo", "alpha": alpha_val},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_capacity_echo_rejects_invalid_alpha(self, client: TestClient) -> None:
        """POST /api/capacity rejects out-of-range alpha values for Echo Hiding."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2500000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "echo", "alpha": 0.85},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_capacity_echo_rejects_delta(self, client: TestClient) -> None:
        """POST /api/capacity rejects irrelevant parameter 'delta' for Echo Hiding."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2500000)
        res = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "echo", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_capacity_lsb_rejects_delta_and_alpha(self, client: TestClient) -> None:
        """POST /api/capacity rejects 'delta' and 'alpha' for LSB."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)
        res1 = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "lsb", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res1.status_code == 400
        assert res1.json()["error"]["code"] == "INVALID_PARAMETER"

        res2 = client.post(
            "/api/capacity",
            data={"message": "Capacity test", "algorithm": "lsb", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res2.status_code == 400
        assert res2.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_embed_and_extract_reject_irrelevant_options(self, client: TestClient) -> None:
        """POST /api/embed and /api/extract return 400 INVALID_PARAMETER for irrelevant options."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        # LSB embed with delta
        res = client.post(
            "/api/embed",
            data={"message": "Test", "password": "Pass", "algorithm": "lsb", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

        # LSB extract with alpha
        res = client.post(
            "/api/extract",
            data={"password": "Pass", "algorithm": "lsb", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

        # Auto extract with both delta and alpha
        res = client.post(
            "/api/extract",
            data={"password": "Pass", "algorithm": "auto", "delta": 32.0, "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_auto_extraction_rejects_custom_delta(self, client: TestClient) -> None:
        """Automatic extraction with custom delta=32 returns HTTP 400 INVALID_PARAMETER."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        # Explicit algorithm="auto" with delta
        res_auto = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "auto", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res_auto.status_code == 400
        assert res_auto.json()["error"]["code"] == "INVALID_PARAMETER"
        assert "delta" in res_auto.json()["error"]["message"].lower()

        # Omitted algorithm parameter with delta (defaults to None / auto)
        res_none = client.post(
            "/api/extract",
            data={"password": "Password123", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res_none.status_code == 400
        assert res_none.json()["error"]["code"] == "INVALID_PARAMETER"
        assert "delta" in res_none.json()["error"]["message"].lower()

    def test_auto_extraction_rejects_custom_alpha(self, client: TestClient) -> None:
        """Automatic extraction with custom alpha=0.15 returns HTTP 400 INVALID_PARAMETER."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        # Explicit algorithm="auto" with alpha
        res_auto = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "auto", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res_auto.status_code == 400
        assert res_auto.json()["error"]["code"] == "INVALID_PARAMETER"
        assert "alpha" in res_auto.json()["error"]["message"].lower()

        # Omitted algorithm parameter with alpha (defaults to None / auto)
        res_none = client.post(
            "/api/extract",
            data={"password": "Password123", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res_none.status_code == 400
        assert res_none.json()["error"]["code"] == "INVALID_PARAMETER"
        assert "alpha" in res_none.json()["error"]["message"].lower()

    def test_explicit_dwt_extraction_with_valid_delta(self, client: TestClient) -> None:
        """Explicit DWT extraction with valid custom delta extracts successfully."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2000000)
        msg = "Explicit DWT with custom delta 32.0"
        pwd = "DWTCustomPassword123"

        embed_res = client.post(
            "/api/embed",
            data={"message": msg, "password": pwd, "algorithm": "dwt_dct_qim", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        extract_res = client.post(
            "/api/extract",
            data={"password": pwd, "algorithm": "dwt_dct_qim", "delta": 32.0},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 200
        assert extract_res.json()["success"] is True
        assert extract_res.json()["message"] == msg
        assert extract_res.json()["algorithm"] == "dwt_dct_qim"

    def test_explicit_echo_extraction_with_valid_alpha(self, client: TestClient) -> None:
        """Explicit Echo extraction with valid custom alpha extracts successfully."""
        wav_bytes = create_api_test_wav_bytes(num_frames=2500000)
        msg = "Explicit Echo with custom alpha 0.15"
        pwd = "EchoCustomPassword123"

        embed_res = client.post(
            "/api/embed",
            data={"message": msg, "password": pwd, "algorithm": "echo", "alpha": 0.15},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        extract_res = client.post(
            "/api/extract",
            data={"password": pwd, "algorithm": "echo", "alpha": 0.15},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 200
        assert extract_res.json()["success"] is True
        assert extract_res.json()["message"] == msg
        assert extract_res.json()["algorithm"] == "echo"


class TestApiDetectionFailureAndErrorMapping:
    def test_clean_audio_extract_returns_422_no_stego_payload(self, client: TestClient) -> None:
        """POST /api/extract on clean audio returns HTTP 422 with NO_STEGO_PAYLOAD."""
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        # Auto detection
        res_auto = client.post(
            "/api/extract",
            data={"password": "AnyPassword123"},
            files={"file": ("clean.wav", wav_bytes, "audio/wav")},
        )
        assert res_auto.status_code == 422
        assert res_auto.json()["error"]["code"] == "NO_STEGO_PAYLOAD"

        # Explicit LSB
        res_lsb = client.post(
            "/api/extract",
            data={"password": "AnyPassword123", "algorithm": "lsb"},
            files={"file": ("clean.wav", wav_bytes, "audio/wav")},
        )
        assert res_lsb.status_code == 422
        assert res_lsb.json()["error"]["code"] == "NO_STEGO_PAYLOAD"

        # Explicit DWT
        res_dwt = client.post(
            "/api/extract",
            data={"password": "AnyPassword123", "algorithm": "dwt_dct_qim"},
            files={"file": ("clean.wav", wav_bytes, "audio/wav")},
        )
        assert res_dwt.status_code == 422
        assert res_dwt.json()["error"]["code"] == "NO_STEGO_PAYLOAD"

    def test_corrupted_sync_word_returns_422_no_stego_payload(self, client: TestClient) -> None:
        """Carrier with invalid synchronization word returns HTTP 422 NO_STEGO_PAYLOAD."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Sync test", "password": "Password123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200
        stego_bytes = bytearray(embed_res.content)

        # Flip synchronization word bits on Channel 0 (first 16 samples * 2 bytes/sample)
        # Header starts at sample 0 of data chunk (after 44-byte RIFF header)
        for i in range(16):
            offset = 44 + (i * 2)
            stego_bytes[offset] ^= 1

        extract_res = client.post(
            "/api/extract",
            data={"password": "Password123"},
            files={"file": ("corrupted_sync.wav", bytes(stego_bytes), "audio/wav")},
        )
        assert extract_res.status_code == 422
        assert extract_res.json()["error"]["code"] == "NO_STEGO_PAYLOAD"

    def test_wrong_password_returns_422_authentication_failed(self, client: TestClient) -> None:
        """Wrong password returns 422 AUTHENTICATION_FAILED (not PAYLOAD_CORRUPTED)."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Auth test", "password": "CorrectPassword123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        extract_res = client.post(
            "/api/extract",
            data={"password": "WrongPassword456"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 422
        assert extract_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    def test_malformed_csma_header_returns_422_corrupted_payload(self, client: TestClient) -> None:
        """Carrier with declared payload length exceeding max returns 422 PAYLOAD_CORRUPTED."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Malformed test", "password": "Password123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200
        stego_bytes = bytearray(embed_res.content)

        # Set declared payload length (bytes 10..13 of CSMA header, Channel 0) to 20,000,000 bytes (> 16MB)
        huge_len_bytes = struct.pack(">I", 20_000_000)
        huge_len_bits = bytes_to_bits(huge_len_bytes)
        for i, bit in enumerate(huge_len_bits):
            sample_idx = 10 * 8 + i
            offset = 44 + (sample_idx * 2)
            stego_bytes[offset] = (stego_bytes[offset] & 0xFE) | bit

        extract_res = client.post(
            "/api/extract",
            data={"password": "Password123"},
            files={"file": ("malformed.wav", bytes(stego_bytes), "audio/wav")},
        )
        assert extract_res.status_code == 422
        assert extract_res.json()["error"]["code"] in ("PAYLOAD_CORRUPTED", "NO_STEGO_PAYLOAD")

    def test_explicit_legacy_cslb_extract_api(self, client: TestClient) -> None:
        """POST /api/extract supports explicit legacy_cslb algorithm parameter."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Legacy CSLB API test", "password": "Password123", "algorithm": "legacy_cslb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        extract_res = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "legacy_cslb"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 200
        assert extract_res.json()["success"] is True
        assert extract_res.json()["message"] == "Legacy CSLB API test"

    def test_clean_audio_echo_extraction_returns_422_no_stego_payload(self, client: TestClient) -> None:
        """POST /api/extract with algorithm='echo' on clean audio returns HTTP 422 NO_STEGO_PAYLOAD."""
        wav_bytes = create_api_test_wav_bytes(num_frames=200000)
        res = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "echo"},
            files={"file": ("clean_echo.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 422
        assert res.json()["success"] is False
        assert res.json()["error"]["code"] == "NO_STEGO_PAYLOAD"
        assert "not contain a valid hidden" in res.json()["error"]["message"].lower()

    def test_clean_audio_auto_extraction_returns_422_no_stego_payload(self, client: TestClient) -> None:
        """POST /api/extract with algorithm='auto' on clean audio returns HTTP 422 NO_STEGO_PAYLOAD."""
        wav_bytes = create_api_test_wav_bytes(num_frames=200000)
        res = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "auto"},
            files={"file": ("clean_auto.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 422
        assert res.json()["success"] is False
        assert res.json()["error"]["code"] == "NO_STEGO_PAYLOAD"
        assert "not contain a valid hidden" in res.json()["error"]["message"].lower()


class TestApiTemporaryFileLifecycle:
    def test_temp_files_cleaned_up_on_successful_embed(self, client: TestClient) -> None:
        """Temporary files are cleaned up after successful embed."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        res = client.post(
            "/api/embed",
            data={"message": "Lifecycle test", "password": "Pass123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 200
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_capacity_failure(self, client: TestClient) -> None:
        """Temporary files are cleaned up after capacity failure."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=500)

        res = client.post(
            "/api/embed",
            data={"message": "A" * 500, "password": "Pass123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 422
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_invalid_wav_upload(self, client: TestClient) -> None:
        """Temporary files are cleaned up after invalid WAV upload."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        bad_bytes = b"NOT_A_WAV_FILE_HEADER_DATA_12345"

        res = client.post(
            "/api/embed",
            data={"message": "Test", "password": "Pass123", "algorithm": "lsb"},
            files={"file": ("bad.wav", bad_bytes, "audio/wav")},
        )
        assert res.status_code in (400, 415)
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_embedding_exception(self, client: TestClient) -> None:
        """Temporary files are cleaned up when invalid parameters cause early error."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        res = client.post(
            "/api/embed",
            data={"message": "Test", "password": "Pass", "algorithm": "lsb", "delta": 32.0},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 400
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_successful_extract(self, client: TestClient) -> None:
        """Temporary files are cleaned up after successful extract."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Extract lifecycle", "password": "Password123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        extract_res = client.post(
            "/api/extract",
            data={"password": "Password123"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 200
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_extraction_exception(self, client: TestClient) -> None:
        """Temporary files are cleaned up when extraction fails (wrong password or no payload)."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        res = client.post(
            "/api/extract",
            data={"password": "WrongPassword"},
            files={"file": ("clean.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code == 422
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_inspect_exception(self, client: TestClient) -> None:
        """Temporary files are cleaned up when audio inspect encounters an error."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        bad_bytes = b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00corrupt"

        res = client.post(
            "/api/audio/inspect",
            files={"file": ("corrupt.wav", bad_bytes, "audio/wav")},
        )
        assert res.status_code in (400, 415)
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_output_validation_failure(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """POST /api/embed cleans up temporary files if output validation fails."""
        from app.audio.wav_handler import AudioError
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        def mock_inspect_wav(path: Path) -> None:
            raise AudioError("Simulated output validation failure")

        monkeypatch.setattr("app.services.cryptaudio_service.inspect_wav", mock_inspect_wav)

        res = client.post(
            "/api/embed",
            data={"message": "Validation fail", "password": "Password123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert res.status_code in (400, 422)
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_cleanup_files_helper_suppresses_oserror(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """cleanup_files helper suppresses OSError without propagating."""
        from app.api.routes import cleanup_files

        test_p = tmp_path / "locked_temp.wav"
        test_p.write_bytes(b"data")

        def mock_unlink(self: Path, missing_ok: bool = False) -> None:
            raise OSError("Windows file lock")

        monkeypatch.setattr(Path, "unlink", mock_unlink)

        # Must not raise
        cleanup_files(test_p)

    def test_temp_files_cleaned_up_on_extraction_wrong_password_on_stego_wav(self, client: TestClient) -> None:
        """POST /api/extract with wrong password on real stego WAV leaves zero temp files."""
        wav_bytes = create_api_test_wav_bytes(num_frames=20000)
        embed_res = client.post(
            "/api/embed",
            data={"message": "Real stego", "password": "RealPassword123", "algorithm": "lsb"},
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
        )
        assert embed_res.status_code == 200

        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        extract_res = client.post(
            "/api/extract",
            data={"password": "WrongPassword456"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 422
        assert extract_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_temp_files_cleaned_up_on_no_payload_extraction(self, client: TestClient) -> None:
        """POST /api/extract on clean audio leaves zero temporary files."""
        initial_files = set(settings.TEMP_DIR.glob("*.wav"))
        wav_bytes = create_api_test_wav_bytes(num_frames=10000)

        extract_res = client.post(
            "/api/extract",
            data={"password": "Password123", "algorithm": "auto"},
            files={"file": ("clean.wav", wav_bytes, "audio/wav")},
        )
        assert extract_res.status_code == 422
        assert extract_res.json()["error"]["code"] == "NO_STEGO_PAYLOAD"
        assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files

    def test_passwords_and_secrets_not_in_error_responses(self, client: TestClient) -> None:
        """Error responses never reflect plaintext passwords or secret text."""
        wav_bytes = create_api_test_wav_bytes(num_frames=5000)
        super_secret_pwd = "SuperSecretPasswordDoNotLeak999!"

        res = client.post(
            "/api/extract",
            data={"password": super_secret_pwd},
            files={"file": ("empty.wav", wav_bytes, "audio/wav")},
        )
        assert super_secret_pwd not in res.text
