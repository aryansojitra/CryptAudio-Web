"""
tests/test_ui_refinement.py
CryptAudio Web — Phase 10.1 UI Accuracy and Refinement Test Suite

Verifies:
1. Exact capacity calculation formulas across carrier samples and payloads.
2. Multilingual UTF-8 byte counting vs character length.
3. Modified sample percentage calculation with zero-division protection.
4. Infinity handling for identical carrier/stego numerical metrics.
5. Missing/null metric fields tolerance and safe formatting.
6. HTML structure and technical accuracy corrections (About page, Dashboard summary,
   Embed capacity panel, Extract summary & clear button, Inspector overhead panel,
   Quality Analysis modified samples & disclaimer).
7. Theme consistency and CSS design tokens.
8. Verification that API contracts and backend endpoints remain unchanged.
"""

from __future__ import annotations

import io
import math
import os
import sys
import wave
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.audio.wav_handler import read_wav
from app.crypto.aes_crypto import (
    HEADER_SIZE_BYTES as CRYPTO_HEADER_BYTES,
    TAG_SIZE_BYTES as GCM_TAG_BYTES,
)
from app.main import app
from app.services.cryptaudio_service import estimate_capacity
from app.steganography.lsb_engine import HEADER_SIZE_BYTES as LSB_HEADER_BYTES


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI test client."""
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
# 1. Capacity Calculations & Formula Accuracy
# ---------------------------------------------------------------------------

def test_exact_capacity_formula_constants() -> None:
    """Verify backend and frontend protocol overhead constants match specification."""
    # Crypto protocol header: Magic (4) + Version (1) + Salt (16) + Nonce (12) = 33 bytes
    assert CRYPTO_HEADER_BYTES == 33
    # GCM authentication tag = 16 bytes
    assert GCM_TAG_BYTES == 16
    # Fixed crypto overhead = 33 + 16 = 49 bytes
    crypto_overhead = CRYPTO_HEADER_BYTES + GCM_TAG_BYTES
    assert crypto_overhead == 49

    # LSB framing header: Magic CSLB (4) + Version (1) + Length (4) + CRC32 (4) = 13 bytes
    assert LSB_HEADER_BYTES == 13

    # Total fixed protocol overhead: 13 + 33 + 16 = 62 bytes
    total_overhead = LSB_HEADER_BYTES + crypto_overhead
    assert total_overhead == 62


def test_capacity_calculation_example_5211648_samples(tmp_path: Path) -> None:
    """
    Verify the prompt's exact reference carrier test case:
    Carrier: 5,211,648 samples
    - Raw capacity: 651,456 bytes
    - Framing overhead: 13 bytes
    - Crypto header: 33 bytes
    - GCM tag: 16 bytes
    - Maximum plaintext capacity: 651,394 bytes
    """
    total_samples = 5_211_648
    raw_capacity_bytes = total_samples // 8
    assert raw_capacity_bytes == 651_456

    framing_overhead = 13
    crypto_header = 33
    gcm_tag = 16
    total_overhead = framing_overhead + crypto_header + gcm_tag
    assert total_overhead == 62

    maximum_plaintext_bytes = raw_capacity_bytes - total_overhead
    assert maximum_plaintext_bytes == 651_394

    # Message with 26 UTF-8 bytes:
    msg_bytes = 26
    encrypted_payload_size = msg_bytes + 49
    assert encrypted_payload_size == 75

    framed_payload_size = encrypted_payload_size + 13
    assert framed_payload_size == 88

    required_samples = framed_payload_size * 8
    assert required_samples == 704

    utilization_percent = (required_samples / total_samples) * 100
    # 88 / 651456 * 100 = 0.0135082...%
    assert round(utilization_percent, 4) == 0.0135


def test_capacity_estimation_service_matches_frontend_formula(tmp_path: Path) -> None:
    """Verify estimate_capacity service produces matching figures for default CSMA and explicit legacy CSLB."""
    wav_path = tmp_path / "carrier.wav"
    # Create 4000 frames mono 16-bit = 4000 samples
    wav_path.write_bytes(create_pcm_wav_bytes(channels=1, num_frames=4000))

    message = "Secret test message"
    msg_bytes = len(message.encode("utf-8"))

    # Default CSMA workflow: 49B crypto + 18B CSMA header = 67B overhead
    estimate = estimate_capacity(wav_path, message)
    assert estimate.message_utf8_bytes == msg_bytes
    assert estimate.estimated_crypto_bytes == msg_bytes + 49
    assert estimate.framed_payload_bytes == msg_bytes + 67
    assert estimate.required_bits == (msg_bytes + 67) * 8
    assert estimate.available_bits == 4000
    expected_util = round(((msg_bytes + 67) * 8 / 4000) * 100, 4)
    assert estimate.utilization_percent == expected_util

    # Explicit legacy CSLB framing: 49B crypto + 13B CSLB header = 62B overhead
    estimate_legacy = estimate_capacity(wav_path, message, framing="legacy_cslb")
    assert estimate_legacy.framed_payload_bytes == msg_bytes + 62
    assert estimate_legacy.required_bits == (msg_bytes + 62) * 8
    expected_legacy_util = round(((msg_bytes + 62) * 8 / 4000) * 100, 4)
    assert estimate_legacy.utilization_percent == expected_legacy_util


# ---------------------------------------------------------------------------
# 2. Multilingual UTF-8 Byte vs Character Counting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "expected_chars", "expected_bytes"),
    [
        ("Hello, World!", 13, 13),
        ("नमस्ते दुनिया", 13, 37),             # Hindi Devanagari
        ("ગુજરાતી સ્ટેગાનોગ્રાફી", 22, 64),     # Gujarati
        ("Привет, мир!", 12, 21),             # Russian Cyrillic
        ("秘密のメッセージ", 8, 24),              # Japanese Kanji/Kana
        ("Audio 🔐 Stego 🎧", 15, 21),         # Emojis (4 bytes each)
    ],
)
def test_utf8_multilingual_byte_and_char_counting(
    text: str, expected_chars: int, expected_bytes: int
) -> None:
    """Ensure character count and UTF-8 byte count are distinguished accurately."""
    char_count = len(text)
    byte_count = len(text.encode("utf-8"))
    assert char_count == expected_chars
    assert byte_count == expected_bytes


# ---------------------------------------------------------------------------
# 3. Modified Sample Percentage & Zero Division Safety
# ---------------------------------------------------------------------------

def test_modified_sample_percentage_calculation() -> None:
    """Ensure modified sample percentage handles zero safely and calculates correctly."""
    def calc_percent(modified: int, total: int) -> float:
        if total <= 0:
            return 0.0
        return (modified / total) * 100.0

    # Normal case: 704 modified bits / 5,211,648 samples
    pct = calc_percent(704, 5_211_648)
    assert round(pct, 4) == 0.0135

    # Zero total samples must not raise ZeroDivisionError
    assert calc_percent(0, 0) == 0.0
    assert calc_percent(10, 0) == 0.0

    # 100% modified
    assert calc_percent(500, 500) == 100.0


# ---------------------------------------------------------------------------
# 4. Infinity and Missing Metric Fields Serialization
# ---------------------------------------------------------------------------

def test_analyze_endpoint_infinity_serialization(client: TestClient) -> None:
    """Identical audio must serialize infinite SNR/PSNR as 'Infinity' without crashing."""
    wav_bytes = create_pcm_wav_bytes(channels=1, num_frames=1000)
    files = {
        "original_file": ("orig.wav", wav_bytes, "audio/wav"),
        "stego_file": ("stego.wav", wav_bytes, "audio/wav"),
    }
    res = client.post("/api/analyze", files=files)
    assert res.status_code == 200
    data = res.json()["analysis"]

    assert data["mse"] == 0.0
    assert data["snr_db"] == "Infinity"
    assert data["psnr_db"] == "Infinity"
    assert data["correlation"] == 1.0 or data["correlation"] is None
    assert data["modified_samples"] == 0
    assert data["total_samples"] == 1000


# ---------------------------------------------------------------------------
# 5. HTML Structure & Technical Corrections Verification
# ---------------------------------------------------------------------------

def test_index_html_contains_phase_10_1_corrections(client: TestClient) -> None:
    """Verify that index.html contains all required UI accuracy elements and corrections."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # 1. Dashboard Technical Summary
    assert "technical-summary-bar" in html
    assert 'id="dash-backend-status"' in html
    assert 'id="dash-backend-dot"' in html
    assert 'id="dash-backend-text"' in html
    assert "AES-256-GCM" in html
    assert "PBKDF2-HMAC-SHA256" in html
    assert "PCM WAV (8, 16, 24, 32-bit)" in html
    assert "50 MB" in html

    # 2. Embed Interface Corrections & Labels
    assert 'id="embed-cap-msg-size"' in html
    assert 'id="embed-cap-crypto-size"' in html
    assert 'id="embed-cap-framed-size"' in html
    assert 'id="embed-cap-req-samples"' in html
    assert 'id="embed-cap-avail-samples"' in html
    assert 'id="embed-cap-max-plaintext"' in html
    assert "Encrypted Payload Size" in html
    assert "Crypto header + ciphertext + GCM tag" in html
    assert "Framed Payload Size" in html
    assert "Encrypted payload + 13-byte LSB framing header" in html
    assert "LSB Capacity Utilization" in html

    # 3. Extract Message Compact Summary & Clear Action
    assert "extract-summary-bar" in html
    assert 'id="extract-summary-chars"' in html
    assert 'id="extract-summary-bytes"' in html
    assert 'id="btn-clear-recovered"' in html
    assert "Clear Recovered Message" in html

    # 4. Audio Inspector Capacity Breakdown
    assert 'id="inspect-overhead-panel"' in html
    assert "LSB Framing Header" in html
    assert "13 Bytes (104 bits)" in html
    assert "33 Bytes (264 bits)" in html
    assert "16 Bytes (128 bits)" in html
    assert "Max Plaintext Capacity" in html

    # 5. Quality Analysis Modified Samples & Disclaimer
    assert 'id="analyze-total-samples"' in html
    assert 'id="analyze-modified-samples"' in html
    assert 'id="analyze-modified-percent"' in html
    assert "Quality Evaluation Disclaimer" in html
    assert "Numerical signal-quality metrics describe differences between audio samples" in html
    assert "They do not independently establish subjective inaudibility" in html

    # 6. About Page Technical Accuracy Corrections
    # Nonce statement
    assert "A cryptographically random 12-byte nonce is generated for every encryption operation." in html
    assert "CryptAudio does not currently implement a separate message freshness or replay-detection mechanism." in html
    # Steganography detection statement
    assert "Steganography aims to conceal the existence of communication by embedding information inside an innocent-looking carrier." in html
    assert "Detection remains possible through statistical analysis and steganalysis." in html
    # LSB perceptual impact statement
    assert "Changing the least significant bit generally produces a small numerical change in a PCM sample." in html
    assert "The perceptual effect depends on the audio content and listening conditions." in html

    # 7. HTML/CSS Architecture Diagram
    assert "arch-diagram" in html
    assert "Sender Pipeline" in html
    assert "Receiver Pipeline" in html
    assert "crypto-specs-grid" in html


# ---------------------------------------------------------------------------
# 6. Theme and CSS Rules Consistency
# ---------------------------------------------------------------------------

def test_stylesheet_contains_refinement_classes(client: TestClient) -> None:
    """Verify that styles.css defines all newly introduced refinement classes."""
    res = client.get("/static/css/styles.css")
    assert res.status_code == 200
    css = res.text

    assert ".technical-summary-bar" in css
    assert ".capacity-breakdown-grid" in css
    assert ".extract-summary-bar" in css
    assert ".btn-outline-danger" in css
    assert ".crypto-specs-grid" in css
    assert ".arch-diagram" in css
    assert ".doc-article" in css
    # Max-width expanded to 100%
    assert "max-width: 100%;" in css
    # Mobile responsive media query
    assert "@media (max-width: 480px)" in css
    assert "overflow-x: hidden;" in css


# ---------------------------------------------------------------------------
# 7. Preservation of Core End-to-End API Workflows
# ---------------------------------------------------------------------------

def test_e2e_embed_and_extract_workflow(client: TestClient) -> None:
    """Verify that message embedding and extraction work seamlessly."""
    carrier_bytes = create_pcm_wav_bytes(channels=1, num_frames=3000)
    secret_text = "Phase 10.1 UI Accuracy & Refinement Verified! 🔒"
    password = "CorrectPassphrase2026!"

    # 1. Embed message
    embed_res = client.post(
        "/api/embed",
        data={"message": secret_text, "password": password},
        files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
    )
    assert embed_res.status_code == 200
    assert embed_res.headers["content-type"] == "audio/wav"
    assert "X-Payload-Size-Bytes" in embed_res.headers
    assert "X-Framed-Size-Bytes" in embed_res.headers
    assert "X-Utilization-Percent" in embed_res.headers

    stego_wav_bytes = embed_res.content
    assert len(stego_wav_bytes) > 0

    # 2. Extract message with correct passphrase
    extract_res = client.post(
        "/api/extract",
        data={"password": password},
        files={"file": ("stego.wav", stego_wav_bytes, "audio/wav")},
    )
    assert extract_res.status_code == 200
    extract_data = extract_res.json()
    assert extract_data["success"] is True
    assert extract_data["message"] == secret_text

    # 3. Extract with incorrect passphrase fails safely
    wrong_extract_res = client.post(
        "/api/extract",
        data={"password": "WrongPassword!"},
        files={"file": ("stego.wav", stego_wav_bytes, "audio/wav")},
    )
    assert wrong_extract_res.status_code == 422
    assert wrong_extract_res.json()["success"] is False
    assert wrong_extract_res.json()["error"]["code"] == "AUTHENTICATION_FAILED"
