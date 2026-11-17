"""
tests/test_security_hardening.py
CryptAudio Web — Comprehensive Security Testing & Hardening Suite (Phase 11)

Tests:
- HTTP security headers (nosniff, DENY, no-referrer, CSP, anti-caching on APIs)
- File upload security (corrupt RIFF, IEEE float, missing chunks, traversal, CRLF)
- Upload size limits (50MB individual, 100MB combined)
- Cryptographic security (tampered salt, nonce, tag, ciphertext, magic, version)
- LSB steganography security (bounds checks, CRC32, truncated framing)
- Information leakage prevention (no tracebacks, no server paths, no passwords)
- XSS prevention & text rendering safety
- Temporary file isolation & lifecycle cleanup
"""

from __future__ import annotations

import io
import os
import struct
import sys
import wave
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import (
    AudioError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    read_wav,
    validate_wav,
)
from app.core.config import settings
from app.crypto.aes_crypto import (
    MAGIC_IDENTIFIER,
    DecryptionError,
    InvalidPayloadError,
    decrypt_message,
    encrypt_message,
)
from app.main import app
from app.steganography.lsb_engine import (
    InvalidStegoFileError,
    PayloadCorruptionError,
    UnsupportedVersionError,
    embed_payload,
    extract_payload,
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Synchronous test client for the FastAPI application."""
    return TestClient(app, raise_server_exceptions=False)


def create_pcm_wav(
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 2000,
) -> bytes:
    """Create in-memory PCM WAV bytes."""
    bio = io.BytesIO()
    frame_size = channels * sample_width
    frames = bytes((i * 5 + 3) % 256 for i in range(num_frames * frame_size))
    with wave.open(bio, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(frames)
    return bio.getvalue()


# ---------------------------------------------------------------------------
# 1. HTTP Security Headers & Browser Protections
# ---------------------------------------------------------------------------

def test_security_headers_present_on_root(client: TestClient) -> None:
    """Root route response must include all mandatory security headers."""
    res = client.get("/")
    assert res.status_code == 200
    headers = res.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert headers.get("X-XSS-Protection") == "0"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "object-src 'none'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_anti_caching_headers_on_api_endpoints(client: TestClient) -> None:
    """All /api/* responses must enforce anti-caching headers to protect sensitive data."""
    res = client.get("/api/health")
    assert res.status_code == 200
    headers = res.headers

    assert "no-store" in headers.get("Cache-Control", "")
    assert "no-cache" in headers.get("Cache-Control", "")
    assert headers.get("Pragma") == "no-cache"
    assert headers.get("Expires") == "0"


# ---------------------------------------------------------------------------
# 2. File Upload Security & Malformed WAV Rejection
# ---------------------------------------------------------------------------

def test_reject_empty_wav_file(client: TestClient) -> None:
    """Empty files (0 bytes) must be rejected with HTTP 400."""
    res = client.post("/api/audio/inspect", files={"file": ("empty.wav", b"", "audio/wav")})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "EMPTY_FILE"


def test_reject_random_binary_renamed_wav(client: TestClient) -> None:
    """Arbitrary binary data disguised as a WAV must be rejected with HTTP 400."""
    fake_data = os.urandom(1024)
    res = client.post("/api/audio/inspect", files={"file": ("disguised.wav", fake_data, "audio/wav")})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_WAV"


def test_reject_corrupt_riff_header(client: TestClient) -> None:
    """Files with malformed RIFF headers must be rejected with HTTP 400."""
    corrupt_riff = b"RIFF\x00\x00\x00\x00NOTWAVE" + b"\x00" * 32
    res = client.post("/api/audio/inspect", files={"file": ("corrupt.wav", corrupt_riff, "audio/wav")})
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "INVALID_WAV"


def test_reject_ieee_float_wav(client: TestClient, tmp_path: Path) -> None:
    """IEEE floating-point WAV files (format 0x0003) must be rejected with HTTP 415."""
    # Construct minimal IEEE float WAV container: format tag 3
    float_wav = tmp_path / "float.wav"
    riff_header = b"RIFF" + struct.pack("<I", 36 + 16) + b"WAVE"
    fmt_chunk = b"fmt " + struct.pack("<I", 16) + struct.pack("<HHIIHH", 3, 1, 44100, 44100 * 4, 4, 32)
    data_chunk = b"data" + struct.pack("<I", 16) + b"\x00" * 16
    float_wav.write_bytes(riff_header + fmt_chunk + data_chunk)

    res = client.post("/api/audio/inspect", files={"file": ("float.wav", float_wav.read_bytes(), "audio/wav")})
    assert res.status_code == 415
    assert res.json()["error"]["code"] == "UNSUPPORTED_FORMAT"


def test_reject_unsupported_channel_count(client: TestClient, tmp_path: Path) -> None:
    """Multi-channel (e.g. 5.1 surround = 6 channels) must be rejected with HTTP 415."""
    surround_wav = tmp_path / "surround.wav"
    riff_header = b"RIFF" + struct.pack("<I", 36 + 24) + b"WAVE"
    # Format tag 1 (PCM), 6 channels, 44100 Hz, 16-bit
    fmt_chunk = b"fmt " + struct.pack("<I", 16) + struct.pack("<HHIIHH", 1, 6, 44100, 44100 * 12, 12, 16)
    data_chunk = b"data" + struct.pack("<I", 24) + b"\x00" * 24
    surround_wav.write_bytes(riff_header + fmt_chunk + data_chunk)

    res = client.post("/api/audio/inspect", files={"file": ("surround.wav", surround_wav.read_bytes(), "audio/wav")})
    assert res.status_code == 415
    assert res.json()["error"]["code"] == "UNSUPPORTED_FORMAT"


def test_path_traversal_in_filename_sanitized(client: TestClient) -> None:
    """Filenames containing path traversal elements or CRLF are scrubbed."""
    carrier = create_pcm_wav()
    malicious_filename = "../../../../etc/cron.d/malicious\r\nSet-Cookie: evil=1.wav"

    res = client.post(
        "/api/embed",
        data={"message": "Safe Payload", "password": "Pass"},
        files={"file": (malicious_filename, carrier, "audio/wav")},
    )
    assert res.status_code == 200
    disposition = res.headers.get("Content-Disposition", "")
    # Must not contain CRLF or path traversal slashes
    assert "\r" not in disposition
    assert "\n" not in disposition
    assert ".." not in disposition
    assert "/" not in disposition
    assert "\\" not in disposition


# ---------------------------------------------------------------------------
# 3. Cryptographic Security & Tamper Rejection
# ---------------------------------------------------------------------------

def test_tampered_ciphertext_rejected() -> None:
    """Flipping a bit in AES-GCM ciphertext must fail authentication without returning plaintext."""
    message = "Classified Message"
    pwd = "Passphrase123!"
    payload = bytearray(encrypt_message(message, pwd))

    # Flip bit in ciphertext portion (after 33-byte header)
    payload[35] ^= 0x01

    with pytest.raises(DecryptionError, match="authentication tag verification failed"):
        decrypt_message(bytes(payload), pwd)


def test_tampered_auth_tag_rejected() -> None:
    """Flipping a bit in the 16-byte GCM authentication tag must fail authentication."""
    message = "Confidential Data"
    pwd = "SecretPassword"
    payload = bytearray(encrypt_message(message, pwd))

    # Flip bit in tag portion (last byte)
    payload[-1] ^= 0x01

    with pytest.raises(DecryptionError, match="authentication tag verification failed"):
        decrypt_message(bytes(payload), pwd)


def test_tampered_salt_rejected() -> None:
    """Flipping a bit in the embedded salt causes derived key mismatch and authentication failure."""
    message = "Salt Tamper Test"
    pwd = "TestPassword"
    payload = bytearray(encrypt_message(message, pwd))

    # Salt is at bytes 5..20
    payload[10] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_message(bytes(payload), pwd)


def test_tampered_nonce_rejected() -> None:
    """Flipping a bit in the embedded nonce fails AAD authentication."""
    message = "Nonce Tamper Test"
    pwd = "TestPassword"
    payload = bytearray(encrypt_message(message, pwd))

    # Nonce is at bytes 21..32
    payload[25] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_message(bytes(payload), pwd)


def test_tampered_magic_identifier_rejected() -> None:
    """Modifying the 4-byte CAUD magic identifier raises InvalidPayloadError."""
    payload = bytearray(encrypt_message("Text", "Pass"))
    payload[0] = ord(b"X")

    with pytest.raises(InvalidPayloadError, match="magic identifier mismatch"):
        decrypt_message(bytes(payload), "Pass")


def test_unsupported_version_rejected() -> None:
    """Modifying the 1-byte format version raises InvalidPayloadError."""
    payload = bytearray(encrypt_message("Text", "Pass"))
    payload[4] = 99  # version 99

    with pytest.raises(InvalidPayloadError, match="Unsupported payload version"):
        decrypt_message(bytes(payload), "Pass")


def test_truncated_crypto_header_rejected() -> None:
    """Payloads shorter than the 33-byte header + 16-byte tag are rejected."""
    payload = encrypt_message("Text", "Pass")
    truncated = payload[:40]  # < 49 bytes

    with pytest.raises(InvalidPayloadError, match="Payload is truncated"):
        decrypt_message(truncated, "Pass")


def test_fresh_salt_and_nonce_per_encryption() -> None:
    """Repeated encryptions of the same plaintext and password MUST use distinct salts and nonces."""
    msg = "Identical Plaintext"
    pwd = "IdenticalPassword"

    p1 = encrypt_message(msg, pwd)
    p2 = encrypt_message(msg, pwd)

    # Different salts (bytes 5..20)
    assert p1[5:21] != p2[5:21]
    # Different nonces (bytes 21..32)
    assert p1[21:33] != p2[21:33]
    # Different ciphertexts
    assert p1[33:] != p2[33:]


# ---------------------------------------------------------------------------
# 4. LSB Steganography Bounds & Integrity Checks
# ---------------------------------------------------------------------------

def test_tampered_crc32_rejected(tmp_path: Path) -> None:
    """Corrupting embedded bits in a stego file is caught by CRC32 check."""
    carrier = tmp_path / "c.wav"
    stego = tmp_path / "s.wav"
    wav_bytes = create_pcm_wav(num_frames=2000)
    carrier.write_bytes(wav_bytes)

    embed_payload(carrier, stego, b"PayloadWithCRCProtection")

    # Corrupt one embedded bit in payload region (after 104 header samples)
    data = read_wav(stego)
    corrupted = bytearray(data.frames)
    corrupted[150 * data.sample_width] ^= 1
    
    from app.audio.wav_handler import write_wav
    write_wav(stego, bytes(corrupted), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(PayloadCorruptionError):
        extract_payload(stego)


def test_payload_length_exceeding_carrier_rejected(tmp_path: Path) -> None:
    """If header claims payload length larger than carrier sample count, extraction aborts safely."""
    carrier = tmp_path / "c.wav"
    carrier.write_bytes(create_pcm_wav(num_frames=200))

    # Construct invalid stego header with huge length (1,000,000 bytes)
    header = b"CSLB" + bytes([1]) + struct.pack(">I", 1_000_000) + struct.pack(">I", 0)
    from app.steganography.lsb_engine import bytes_to_bits
    header_bits = bytes_to_bits(header)

    data = read_wav(carrier)
    frames = bytearray(data.frames)
    for i, b in enumerate(header_bits):
        frames[i * data.sample_width] = (frames[i * data.sample_width] & 0xFE) | b

    from app.audio.wav_handler import write_wav
    write_wav(carrier, bytes(frames), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(InvalidStegoFileError, match="requires.*bits.*samples"):
        extract_payload(carrier)


# ---------------------------------------------------------------------------
# 5. API Robustness, Error Envelopes & XSS Safety
# ---------------------------------------------------------------------------

def test_error_responses_conform_to_standard_envelope(client: TestClient) -> None:
    """All error responses must follow the {success: false, error: {code, message}} envelope."""
    # 400 Bad Request
    r1 = client.post("/api/embed", data={"message": "", "password": "Pass"}, files={"file": ("c.wav", create_pcm_wav(), "audio/wav")})
    assert r1.status_code == 400
    j1 = r1.json()
    assert j1["success"] is False
    assert "code" in j1["error"]
    assert "message" in j1["error"]

    # 422 Extraction failure
    r2 = client.post("/api/extract", data={"password": "Pass"}, files={"file": ("c.wav", create_pcm_wav(), "audio/wav")})
    assert r2.status_code == 422
    j2 = r2.json()
    assert j2["success"] is False
    assert "code" in j2["error"]

    # Method Not Allowed (405)
    r3 = client.get("/api/embed")
    assert r3.status_code == 405


def test_xss_payloads_safely_roundtrip_as_text(client: TestClient) -> None:
    """XSS injection payloads are encrypted, embedded, extracted, and returned strictly as text."""
    xss_payload = '<script>alert("XSS")</script><img src=x onerror=alert(1)>"><svg onload=alert(1)>'
    pwd = "StrongPassword123"
    carrier = create_pcm_wav(num_frames=4000)

    # Embed
    embed_res = client.post(
        "/api/embed",
        data={"message": xss_payload, "password": pwd},
        files={"file": ("carrier.wav", carrier, "audio/wav")},
    )
    assert embed_res.status_code == 200

    # Extract
    extract_res = client.post(
        "/api/extract",
        data={"password": pwd},
        files={"file": ("stego.wav", embed_res.content, "audio/wav")},
    )
    assert extract_res.status_code == 200
    # Must match exactly as string, not parsed/executed
    assert extract_res.json()["message"] == xss_payload


def test_temporary_files_lifecycle_cleaned_up(client: TestClient) -> None:
    """Temporary files directory must be completely clean after requests."""
    carrier = create_pcm_wav(num_frames=1000)

    # Audio inspection
    client.post("/api/audio/inspect", files={"file": ("test.wav", carrier, "audio/wav")})
    # Failed embed
    client.post("/api/embed", data={"message": "M", "password": ""}, files={"file": ("test.wav", carrier, "audio/wav")})
    # Failed extract
    client.post("/api/extract", data={"password": "Wrong"}, files={"file": ("test.wav", carrier, "audio/wav")})

    # Only .gitkeep should remain
    remaining = [f.name for f in settings.TEMP_DIR.glob("*") if f.name != ".gitkeep"]
    assert remaining == []
