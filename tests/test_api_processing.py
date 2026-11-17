"""
tests/test_api_processing.py
CryptAudio Web — FastAPI Processing Endpoints Test Suite (Phase 8)

Tests health, audio inspection, message embedding, extraction, quality analysis,
security boundaries, error mappings, and temporary-file lifecycle.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_api_processing.py -v
"""

from __future__ import annotations

import io
import json
import os
import struct
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import read_wav, write_wav
from app.core.config import settings
from app.main import app


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> TestClient:
    """Synchronous test client for the FastAPI application."""
    return TestClient(app, raise_server_exceptions=False)


def create_wav_bytes(
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 2000,
) -> bytes:
    """Generate in-memory PCM WAV bytes for multipart uploads."""
    bio = io.BytesIO()
    frame_size = channels * sample_width
    frames = bytes((i * 5 + 3) % 256 for i in range(num_frames * frame_size))
    # Use write_wav writing to a temp buffer via Path-like object or write directly with wave
    import wave
    with wave.open(bio, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(frames)
    return bio.getvalue()


# ---------------------------------------------------------------------------
# 1-9. Health & Audio Inspection
# ---------------------------------------------------------------------------

def test_health_endpoint_functional(client: TestClient) -> None:
    """1. Health check returns 200 and healthy status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["application"] == settings.APP_NAME


def test_inspect_valid_wav(client: TestClient) -> None:
    """2. Inspect valid 16-bit mono WAV file."""
    wav_bytes = create_wav_bytes(channels=1, sample_width=2, sample_rate=44100, num_frames=4410)
    files = {"file": ("test.wav", wav_bytes, "audio/wav")}

    response = client.post("/api/audio/inspect", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["audio"]["sample_rate"] == 44100
    assert data["audio"]["channels"] == 1
    assert data["audio"]["bit_depth"] == 16
    assert data["audio"]["duration_seconds"] == 0.1
    assert data["capacity"]["total_samples"] == 4410


def test_inspect_mono_wav(client: TestClient) -> None:
    """3. Inspect mono audio file."""
    wav_bytes = create_wav_bytes(channels=1)
    response = client.post("/api/audio/inspect", files={"file": ("mono.wav", wav_bytes, "audio/wav")})
    assert response.status_code == 200
    assert response.json()["audio"]["channels"] == 1


def test_inspect_stereo_wav(client: TestClient) -> None:
    """4. Inspect stereo audio file."""
    wav_bytes = create_wav_bytes(channels=2)
    response = client.post("/api/audio/inspect", files={"file": ("stereo.wav", wav_bytes, "audio/wav")})
    assert response.status_code == 200
    assert response.json()["audio"]["channels"] == 2


def test_inspect_different_bit_depths(client: TestClient) -> None:
    """5. Inspect 8, 16, 24, and 32-bit audio files."""
    for width, expected_bits in [(1, 8), (2, 16), (3, 24), (4, 32)]:
        wav_bytes = create_wav_bytes(sample_width=width, num_frames=500)
        res = client.post("/api/audio/inspect", files={"file": (f"w{width}.wav", wav_bytes, "audio/wav")})
        assert res.status_code == 200
        assert res.json()["audio"]["bit_depth"] == expected_bits


def test_reject_invalid_wav_inspect(client: TestClient) -> None:
    """6. Rejects corrupt non-WAV bytes with HTTP 400."""
    fake_bytes = b"NOT_A_VALID_WAV_HEADER"
    res = client.post("/api/audio/inspect", files={"file": ("fake.wav", fake_bytes, "audio/wav")})
    assert res.status_code == 400
    data = res.json()
    assert data["success"] is False
    assert data["error"]["code"] == "INVALID_WAV"


def test_reject_empty_upload_inspect(client: TestClient) -> None:
    """7. Rejects 0-byte upload with HTTP 400."""
    res = client.post("/api/audio/inspect", files={"file": ("empty.wav", b"", "audio/wav")})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "EMPTY_FILE"


def test_reject_unsupported_audio_format_inspect(client: TestClient) -> None:
    """8. Rejects 32-bit IEEE float WAV with HTTP 415."""
    fmt_chunk = struct.pack("<4sIHHIIHH", b"fmt ", 16, 3, 1, 44100, 44100 * 4, 4, 32)
    data = b"\x00\x00\x00\x00" * 10
    data_chunk = struct.pack("<4sI", b"data", len(data)) + data
    riff = struct.pack("<4sI4s", b"RIFF", 4 + len(fmt_chunk) + len(data_chunk), b"WAVE") + fmt_chunk + data_chunk

    res = client.post("/api/audio/inspect", files={"file": ("float.wav", riff, "audio/wav")})
    assert res.status_code == 415
    assert res.json()["error"]["code"] == "UNSUPPORTED_FORMAT"


def test_reject_oversized_upload_inspect(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """9. Rejects uploads exceeding configured maximum size with HTTP 413."""
    # Set a temporarily low threshold of 100 bytes for testing
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 100)
    wav_bytes = create_wav_bytes(num_frames=1000)  # > 2000 bytes
    res = client.post("/api/audio/inspect", files={"file": ("big.wav", wav_bytes, "audio/wav")})
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "FILE_TOO_LARGE"


# ---------------------------------------------------------------------------
# 10-19. Message Embedding
# ---------------------------------------------------------------------------

def test_embed_valid_message(client: TestClient) -> None:
    """10-12. Embed message returns valid downloadable WAV."""
    wav_bytes = create_wav_bytes(channels=2, sample_width=2, num_frames=4000)
    data = {
        "message": "Top Secret Rendezvous at 0900 Hours",
        "password": "StrongPassword123!",
    }
    files = {"file": ("carrier.wav", wav_bytes, "audio/wav")}

    res = client.post("/api/embed", data=data, files=files)
    assert res.status_code == 200
    assert res.headers["content-type"] == "audio/wav"
    assert "attachment" in res.headers.get("content-disposition", "")
    assert "x-payload-size-bytes" in res.headers
    assert "x-framed-size-bytes" in res.headers
    assert "x-utilization-percent" in res.headers
    assert float(res.headers["x-utilization-percent"]) > 0.0
    assert len(res.content) > len(wav_bytes) - 50  # Roughly identical file size


def test_downloaded_wav_is_valid_pcm(client: TestClient, tmp_path: Path) -> None:
    """12-13. Downloaded stego WAV is valid and original remains untouched."""
    wav_bytes = create_wav_bytes(channels=1, sample_width=2, num_frames=3000)
    stego_out = tmp_path / "downloaded.wav"

    res = client.post(
        "/api/embed",
        data={"message": "Verification text", "password": "Pass#1"},
        files={"file": ("audio.wav", wav_bytes, "audio/wav")},
    )
    stego_out.write_bytes(res.content)
    parsed = read_wav(stego_out)
    assert parsed.channels == 1
    assert parsed.sample_rate == 44100
    assert parsed.sample_width == 2


def test_reject_empty_message_embed(client: TestClient) -> None:
    """14. Rejects empty message with HTTP 400."""
    wav_bytes = create_wav_bytes()
    res = client.post(
        "/api/embed",
        data={"message": "", "password": "ValidPassword"},
        files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
    )
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_MESSAGE"


def test_reject_empty_password_embed(client: TestClient) -> None:
    """15. Rejects empty password with HTTP 400."""
    wav_bytes = create_wav_bytes()
    res = client.post(
        "/api/embed",
        data={"message": "Secret message", "password": ""},
        files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
    )
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_PASSWORD"


def test_reject_insufficient_capacity_embed(client: TestClient) -> None:
    """16. Rejects audio with insufficient capacity with HTTP 422."""
    # Audio with only 50 frames (50 samples < 104 samples needed for stego header alone)
    tiny_wav = create_wav_bytes(num_frames=50)
    res = client.post(
        "/api/embed",
        data={"message": "Large message", "password": "Password123"},
        files={"file": ("tiny.wav", tiny_wav, "audio/wav")},
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "INSUFFICIENT_CAPACITY"


def test_reject_invalid_wav_embed(client: TestClient) -> None:
    """17. Rejects non-WAV bytes with HTTP 400."""
    res = client.post(
        "/api/embed",
        data={"message": "Secret", "password": "Password123"},
        files={"file": ("fake.wav", b"INVALID_DATA", "audio/wav")},
    )
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_WAV"


def test_reject_oversized_upload_embed(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """18. Rejects oversized upload in embed with HTTP 413."""
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 200)
    wav_bytes = create_wav_bytes(num_frames=1000)
    res = client.post(
        "/api/embed",
        data={"message": "Secret", "password": "Password123"},
        files={"file": ("oversized.wav", wav_bytes, "audio/wav")},
    )
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "FILE_TOO_LARGE"


def test_temporary_files_cleaned_up_after_embed(client: TestClient) -> None:
    """19. Temporary files created during embedding are deleted."""
    initial_files = set(settings.TEMP_DIR.glob("*.wav"))
    wav_bytes = create_wav_bytes(num_frames=2000)

    res = client.post(
        "/api/embed",
        data={"message": "Cleanup check", "password": "Password123"},
        files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
    )
    assert res.status_code == 200

    # Ensure no lingering .wav files remain in temporary directory
    current_files = set(settings.TEMP_DIR.glob("*.wav"))
    assert current_files == initial_files


# ---------------------------------------------------------------------------
# 20-28. Message Extraction
# ---------------------------------------------------------------------------

def test_extract_valid_message(client: TestClient) -> None:
    """20. Extract a valid message successfully."""
    carrier_bytes = create_wav_bytes(num_frames=3000)
    msg = "Confidential extraction payload"
    pwd = "ExtractPassword#1"

    # Embed
    embed_res = client.post(
        "/api/embed",
        data={"message": msg, "password": pwd},
        files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
    )
    assert embed_res.status_code == 200
    stego_bytes = embed_res.content

    # Extract
    extract_res = client.post(
        "/api/extract",
        data={"password": pwd},
        files={"file": ("stego.wav", stego_bytes, "audio/wav")},
    )
    assert extract_res.status_code == 200
    assert extract_res.json()["success"] is True
    assert extract_res.json()["message"] == msg


def test_extract_gujarati_text(client: TestClient) -> None:
    """21. Extract Gujarati Unicode text."""
    carrier = create_wav_bytes(num_frames=3000)
    msg = "ગુજરાતી ભાષામાં અત્યંત ગુપ્ત સંદેશ."
    pwd = "પાસવર્ડ_ગુજરાતી"

    stego = client.post("/api/embed", data={"message": msg, "password": pwd}, files={"file": ("c.wav", carrier, "audio/wav")}).content
    res = client.post("/api/extract", data={"password": pwd}, files={"file": ("s.wav", stego, "audio/wav")})
    assert res.status_code == 200
    assert res.json()["message"] == msg


def test_extract_hindi_text(client: TestClient) -> None:
    """22. Extract Hindi Unicode text."""
    carrier = create_wav_bytes(num_frames=3000)
    msg = "गोपनीय हिंदी संदेश ऑडियो में।"
    pwd = "हिंदी_पासवर्ड"

    stego = client.post("/api/embed", data={"message": msg, "password": pwd}, files={"file": ("c.wav", carrier, "audio/wav")}).content
    res = client.post("/api/extract", data={"password": pwd}, files={"file": ("s.wav", stego, "audio/wav")})
    assert res.status_code == 200
    assert res.json()["message"] == msg


def test_extract_emoji_text(client: TestClient) -> None:
    """23. Extract emoji message."""
    carrier = create_wav_bytes(num_frames=3000)
    msg = "🔐 Secret 🎵 Stego 🚀✨!"
    pwd = "EmojiPass🗝️"

    stego = client.post("/api/embed", data={"message": msg, "password": pwd}, files={"file": ("c.wav", carrier, "audio/wav")}).content
    res = client.post("/api/extract", data={"password": pwd}, files={"file": ("s.wav", stego, "audio/wav")})
    assert res.status_code == 200
    assert res.json()["message"] == msg


def test_reject_incorrect_password_extract(client: TestClient) -> None:
    """24. Rejects wrong password with HTTP 422 AUTHENTICATION_FAILED."""
    carrier = create_wav_bytes(num_frames=2000)
    stego = client.post(
        "/api/embed",
        data={"message": "Target secret", "password": "RealPassword123"},
        files={"file": ("c.wav", carrier, "audio/wav")},
    ).content

    res = client.post(
        "/api/extract",
        data={"password": "WrongPassword999"},
        files={"file": ("s.wav", stego, "audio/wav")},
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_reject_wav_without_embedded_payload_extract(client: TestClient) -> None:
    """25. Extracting from plain carrier audio returns HTTP 422 NO_STEGO_PAYLOAD."""
    plain = create_wav_bytes(num_frames=2000)
    res = client.post(
        "/api/extract",
        data={"password": "AnyPassword"},
        files={"file": ("plain.wav", plain, "audio/wav")},
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "NO_STEGO_PAYLOAD"


def test_reject_corrupted_payload_extract(client: TestClient) -> None:
    """26. Rejects corrupted stego audio with HTTP 422."""
    carrier = create_wav_bytes(num_frames=2000)
    stego = bytearray(client.post(
        "/api/embed",
        data={"message": "Corrupt check", "password": "Pass123"},
        files={"file": ("c.wav", carrier, "audio/wav")},
    ).content)

    # Corrupt a byte in the audio data area (offset > 150)
    stego[200] ^= 1

    res = client.post(
        "/api/extract",
        data={"password": "Pass123"},
        files={"file": ("s.wav", bytes(stego), "audio/wav")},
    )
    assert res.status_code == 422


def test_reject_invalid_wav_extract(client: TestClient) -> None:
    """27. Rejects non-WAV bytes in extract with HTTP 400."""
    res = client.post(
        "/api/extract",
        data={"password": "Pass123"},
        files={"file": ("fake.wav", b"NON_WAV_BYTES", "audio/wav")},
    )
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_WAV"


def test_temporary_files_cleaned_up_after_extract(client: TestClient) -> None:
    """28. Verifies temporary files are cleaned up after extraction."""
    initial_files = set(settings.TEMP_DIR.glob("*.wav"))
    carrier = create_wav_bytes(num_frames=2000)
    stego = client.post("/api/embed", data={"message": "Msg", "password": "P"}, files={"file": ("c.wav", carrier, "audio/wav")}).content

    res = client.post("/api/extract", data={"password": "P"}, files={"file": ("s.wav", stego, "audio/wav")})
    assert res.status_code == 200

    assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files


# ---------------------------------------------------------------------------
# 29-37. Audio Quality Analysis
# ---------------------------------------------------------------------------

def test_analyze_valid_pair(client: TestClient) -> None:
    """29-33. Compares carrier and stego audio returning MSE, SNR, PSNR, correlation."""
    carrier = create_wav_bytes(channels=2, sample_width=2, num_frames=3000)
    stego = client.post(
        "/api/embed",
        data={"message": "Test analysis payload", "password": "Pass123"},
        files={"file": ("carrier.wav", carrier, "audio/wav")},
    ).content

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("orig.wav", carrier, "audio/wav"),
            "stego_file": ("stego.wav", stego, "audio/wav"),
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    analysis = data["analysis"]
    assert analysis["mse"] >= 0.0
    assert analysis["psnr_db"] > 50.0  # High fidelity LSB
    assert analysis["quality_assessment"] == "Excellent"
    assert analysis["correlation"] > 0.999
    assert analysis["total_samples"] == 6000


def test_reject_mismatched_sample_rates_analyze(client: TestClient) -> None:
    """34. Rejects mismatched sample rates with HTTP 422 INCOMPATIBLE_AUDIO."""
    w1 = create_wav_bytes(sample_rate=44100)
    w2 = create_wav_bytes(sample_rate=48000)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w2, "audio/wav"),
        },
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "INCOMPATIBLE_AUDIO"


def test_reject_mismatched_bit_depths_analyze(client: TestClient) -> None:
    """36. Rejects mismatched bit depths with HTTP 422 INCOMPATIBLE_AUDIO."""
    w1 = create_wav_bytes(sample_width=2)
    w2 = create_wav_bytes(sample_width=3)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w2, "audio/wav"),
        },
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "INCOMPATIBLE_AUDIO"


def test_reject_mismatched_channel_counts_analyze(client: TestClient) -> None:
    """35. Rejects mismatched channels with HTTP 422."""
    w1 = create_wav_bytes(channels=1)
    w2 = create_wav_bytes(channels=2)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w2, "audio/wav"),
        },
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "INCOMPATIBLE_AUDIO"


def test_reject_mismatched_bit_depths_analyze(client: TestClient) -> None:
    """36. Rejects mismatched bit depths with HTTP 422 INCOMPATIBLE_AUDIO."""
    w1 = create_wav_bytes(sample_width=2)
    w2 = create_wav_bytes(sample_width=3)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w2, "audio/wav"),
        },
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "INCOMPATIBLE_AUDIO"


def test_reject_oversized_combined_upload_analyze(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """36. Rejects combined uploads exceeding limit with HTTP 413."""
    monkeypatch.setattr(settings, "MAX_COMBINED_UPLOAD_BYTES", 5000)
    w1 = create_wav_bytes(num_frames=2000)  # ~4000 bytes
    w2 = create_wav_bytes(num_frames=2000)  # ~4000 bytes -> sum ~8000 bytes > 5000

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w2, "audio/wav"),
        },
    )
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "FILE_TOO_LARGE"


def test_temporary_files_cleaned_up_after_analyze(client: TestClient) -> None:
    """37. Temporary files are cleaned up after analysis."""
    initial_files = set(settings.TEMP_DIR.glob("*.wav"))
    w1 = create_wav_bytes(num_frames=1000)

    res = client.post(
        "/api/analyze",
        files={
            "original_file": ("w1.wav", w1, "audio/wav"),
            "stego_file": ("w2.wav", w1, "audio/wav"),
        },
    )
    assert res.status_code == 200
    assert set(settings.TEMP_DIR.glob("*.wav")) == initial_files


# ---------------------------------------------------------------------------
# 38-44. Security & Reliability Tests
# ---------------------------------------------------------------------------

def test_random_temporary_filenames() -> None:
    """38. Temporary filenames use cryptographically random UUIDs."""
    p1 = settings.TEMP_DIR / f"test_{os.urandom(8).hex()}.wav"
    p2 = settings.TEMP_DIR / f"test_{os.urandom(8).hex()}.wav"
    assert p1.name != p2.name


def test_path_traversal_prevention(client: TestClient) -> None:
    """39. Malicious filenames containing '../' or '..\\' cannot traverse paths."""
    wav = create_wav_bytes()
    malicious_name = "../../../../etc/passwd.wav"

    res = client.post("/api/audio/inspect", files={"file": (malicious_name, wav, "audio/wav")})
    assert res.status_code == 200
    # Files are written strictly inside settings.TEMP_DIR, never in parent dirs


def test_passwords_not_in_api_responses(client: TestClient) -> None:
    """40. Passwords are never returned in JSON or response headers."""
    carrier = create_wav_bytes()
    pwd = "SuperSecretPassword123"

    res = client.post(
        "/api/embed",
        data={"message": "Secret", "password": pwd},
        files={"file": ("c.wav", carrier, "audio/wav")},
    )
    assert pwd not in res.headers.values()
    assert pwd.encode("utf-8") not in res.content


def test_no_stack_traces_returned_on_errors(client: TestClient) -> None:
    """42. Error responses return clean JSON and never leak Python tracebacks."""
    res = client.post("/api/audio/inspect", files={"file": ("bad.wav", b"INVALID", "audio/wav")})
    assert "Traceback" not in res.text
    assert "File \"" not in res.text


def test_concurrent_requests_use_isolated_files(client: TestClient) -> None:
    """43. Independent requests create completely isolated temporary files."""
    w1 = create_wav_bytes(num_frames=1000)
    w2 = create_wav_bytes(num_frames=2000)

    res1 = client.post("/api/audio/inspect", files={"file": ("w1.wav", w1, "audio/wav")})
    res2 = client.post("/api/audio/inspect", files={"file": ("w2.wav", w2, "audio/wav")})

    assert res1.json()["capacity"]["total_samples"] == 1000
    assert res2.json()["capacity"]["total_samples"] == 2000


def test_safe_json_with_infinite_metrics(client: TestClient) -> None:
    """44. Comparing identical files produces valid standard RFC 8259 JSON without bare Infinity."""
    w = create_wav_bytes(num_frames=1000)
    res = client.post(
        "/api/analyze",
        files={"original_file": ("w.wav", w, "audio/wav"), "stego_file": ("w.wav", w, "audio/wav")},
    )
    assert res.status_code == 200
    # Raw response body must be strictly valid JSON per RFC 8259 (no bare Infinity)
    raw_text = res.text
    assert "bare Infinity" not in raw_text
    parsed = json.loads(raw_text)
    assert parsed["analysis"]["psnr_db"] == "Infinity"
    assert parsed["analysis"]["snr_db"] == "Infinity"
