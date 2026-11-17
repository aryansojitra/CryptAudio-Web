"""
tests/test_frontend_api_integration.py
CryptAudio Web — Frontend & Backend API Integration Test Suite (Phase 10)

Tests the complete end-to-end client-server workflow:
- Static asset serving (api.js, app.js, theme.js, index.html)
- Health check verification
- Carrier WAV inspection
- Message encryption & LSB embedding (streaming WAV download)
- Message extraction & decryption with passphrase
- Authentication failure handling (incorrect passphrase)
- Full audio quality evaluation (MSE, SNR, PSNR, Pearson r)
- Identical signal comparison with safe Infinity serialization
- Multilingual UTF-8 unicode payload round-trip
"""

from __future__ import annotations

import io
import json
import os
import sys
import wave
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import read_wav
from app.core.config import settings
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Synchronous test client for the FastAPI application."""
    return TestClient(app, raise_server_exceptions=False)


def create_pcm_wav_bytes(
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 3000,
) -> bytes:
    """Generate in-memory PCM WAV bytes for testing."""
    bio = io.BytesIO()
    frame_size = channels * sample_width
    frames = bytes((i * 7 + 11) % 256 for i in range(num_frames * frame_size))
    with wave.open(bio, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(frames)
    return bio.getvalue()


# ---------------------------------------------------------------------------
# 1. Frontend Asset & Integration Contract Tests
# ---------------------------------------------------------------------------

def test_index_html_loads_api_module(client: TestClient) -> None:
    """The root HTML page must include api.js and all processing submit buttons."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # Verify script imports
    assert "/static/js/api.js" in html
    assert "/static/js/app.js" in html
    assert "/static/js/theme.js" in html

    # Verify operational submit buttons
    assert 'id="btn-embed-submit"' in html
    assert 'id="btn-extract-submit"' in html
    assert 'id="btn-inspect-submit"' in html
    assert 'id="btn-analyze-submit"' in html

    # Verify backend status indicator
    assert 'id="backend-status-pill"' in html
    assert 'id="backend-status-dot"' in html
    assert 'id="backend-status-text"' in html


def test_api_js_serves_valid_client(client: TestClient) -> None:
    """api.js must be accessible and contain the CryptAudioAPI service methods."""
    res = client.get("/static/js/api.js")
    assert res.status_code == 200
    js = res.text

    assert "CryptAudioAPI" in js
    assert "checkHealth" in js
    assert "inspectAudio" in js
    assert "embedMessage" in js
    assert "extractMessage" in js
    assert "analyzeAudio" in js
    assert "/api/health" in js
    assert "/api/audio/inspect" in js
    assert "/api/embed" in js
    assert "/api/extract" in js
    assert "/api/analyze" in js


# ---------------------------------------------------------------------------
# 2. End-to-End Workflow Integration Tests
# ---------------------------------------------------------------------------

def test_e2e_health_check(client: TestClient) -> None:
    """1. Frontend health check verifies backend operational status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["application"] == settings.APP_NAME
    assert data["version"] == settings.APP_VERSION


def test_e2e_audio_inspection(client: TestClient) -> None:
    """2. Carrier audio inspection returns valid technical properties & capacity."""
    carrier_bytes = create_pcm_wav_bytes(channels=2, sample_width=2, sample_rate=48000, num_frames=2400)
    files = {"file": ("carrier_test.wav", carrier_bytes, "audio/wav")}

    res = client.post("/api/audio/inspect", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["audio"]["channels"] == 2
    assert data["audio"]["bit_depth"] == 16
    assert data["audio"]["sample_rate"] == 48000
    assert data["capacity"]["total_samples"] == 4800
    assert data["capacity"]["raw_capacity_bytes"] == 600


def test_e2e_full_embed_download_and_extract_lifecycle(client: TestClient, tmp_path: Path) -> None:
    """
    3. Complete E2E Steganography Round-Trip:
       - Upload carrier WAV, message, and password
       - Receive stego WAV download and metadata headers
       - Verify downloaded file is a valid PCM WAV
       - Extract message using the correct password
       - Verify exact plaintext recovery
    """
    carrier_bytes = create_pcm_wav_bytes(channels=1, sample_width=2, sample_rate=44100, num_frames=4000)
    secret_text = "Operation CryptAudio-Web: Top Secret Payload 2026! @#$"
    passphrase = "UltraSecurePassphrase_999!"

    # Step A: Embed
    embed_res = client.post(
        "/api/embed",
        data={"message": secret_text, "password": passphrase},
        files={"file": ("mission_audio.wav", carrier_bytes, "audio/wav")},
    )
    assert embed_res.status_code == 200
    assert embed_res.headers["content-type"] == "audio/wav"
    assert "mission_audio_stego.wav" in embed_res.headers.get("content-disposition", "")
    assert "x-payload-size-bytes" in embed_res.headers
    assert "x-framed-size-bytes" in embed_res.headers
    assert "x-utilization-percent" in embed_res.headers

    stego_wav_bytes = embed_res.content
    assert len(stego_wav_bytes) > 0

    # Step B: Verify valid PCM WAV structure of the returned stego audio
    stego_file = tmp_path / "stego_output.wav"
    stego_file.write_bytes(stego_wav_bytes)
    stego_info = read_wav(stego_file)
    assert stego_info.channels == 1
    assert stego_info.sample_rate == 44100
    assert stego_info.sample_width == 2

    # Step C: Extract with correct passphrase
    extract_res = client.post(
        "/api/extract",
        data={"password": passphrase},
        files={"file": ("stego_output.wav", stego_wav_bytes, "audio/wav")},
    )
    assert extract_res.status_code == 200
    extract_data = extract_res.json()
    assert extract_data["success"] is True
    assert extract_data["message"] == secret_text


def test_e2e_extract_rejects_incorrect_password(client: TestClient) -> None:
    """4. Extraction with wrong passphrase fails safely with HTTP 422 AUTHENTICATION_FAILED."""
    carrier_bytes = create_pcm_wav_bytes(channels=1, sample_width=2, num_frames=3000)
    secret_text = "Classified Message"
    correct_pass = "CorrectPassword123"
    wrong_pass = "WrongPassword456"

    # Embed
    embed_res = client.post(
        "/api/embed",
        data={"message": secret_text, "password": correct_pass},
        files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
    )
    stego_bytes = embed_res.content

    # Extract with wrong password
    extract_res = client.post(
        "/api/extract",
        data={"password": wrong_pass},
        files={"file": ("carrier_stego.wav", stego_bytes, "audio/wav")},
    )
    assert extract_res.status_code == 422
    err_body = extract_res.json()
    assert err_body["success"] is False
    assert err_body["error"]["code"] == "AUTHENTICATION_FAILED"
    # Never leak sensitive plaintext or passwords in error messages
    assert secret_text not in extract_res.text
    assert correct_pass not in extract_res.text


def test_e2e_audio_quality_analysis(client: TestClient) -> None:
    """5. Quality Analysis computes distortion between original carrier and stego audio."""
    carrier_bytes = create_pcm_wav_bytes(channels=2, sample_width=2, num_frames=4000)
    secret_text = "Quality benchmark message"
    passphrase = "Password123"

    embed_res = client.post(
        "/api/embed",
        data={"message": secret_text, "password": passphrase},
        files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
    )
    stego_bytes = embed_res.content

    # Compare
    analyze_res = client.post(
        "/api/analyze",
        files={
            "original_file": ("carrier.wav", carrier_bytes, "audio/wav"),
            "stego_file": ("stego.wav", stego_bytes, "audio/wav"),
        },
    )
    assert analyze_res.status_code == 200
    data = analyze_res.json()
    assert data["success"] is True
    analysis = data["analysis"]
    assert analysis["mse"] >= 0.0
    assert analysis["snr_db"] > 40.0
    assert analysis["psnr_db"] > 50.0  # Transparent LSB
    assert analysis["correlation"] > 0.999
    assert analysis["quality_assessment"] == "Excellent"


def test_e2e_quality_analysis_identical_signals(client: TestClient) -> None:
    """6. Quality Analysis handles identical files and returns safe Infinity string."""
    carrier_bytes = create_pcm_wav_bytes(channels=1, sample_width=2, num_frames=1000)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("carrier.wav", carrier_bytes, "audio/wav"),
            "stego_file": ("carrier.wav", carrier_bytes, "audio/wav"),
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["analysis"]["mse"] == 0.0
    assert data["analysis"]["snr_db"] == "Infinity"
    assert data["analysis"]["psnr_db"] == "Infinity"
    assert data["analysis"]["correlation"] == 1.0


def test_e2e_multilingual_unicode_support(client: TestClient) -> None:
    """7. Full round-trip integration supports English, Gujarati, Hindi, and emoji Unicode."""
    multilingual_text = "Security સુરક્ષા सुरक्षा 🛡️🔐 2026"
    passphrase = "GujaratiHindiPass123!"
    carrier_bytes = create_pcm_wav_bytes(channels=1, sample_width=2, num_frames=3500)

    # Embed
    embed_res = client.post(
        "/api/embed",
        data={"message": multilingual_text, "password": passphrase},
        files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
    )
    assert embed_res.status_code == 200

    # Extract
    extract_res = client.post(
        "/api/extract",
        data={"password": passphrase},
        files={"file": ("stego.wav", embed_res.content, "audio/wav")},
    )
    assert extract_res.status_code == 200
    assert extract_res.json()["message"] == multilingual_text
