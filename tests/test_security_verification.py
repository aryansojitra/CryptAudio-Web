"""
tests/test_security_verification.py
CryptAudio Web — Phase 11.1 Security Verification & CSP Refinement Suite

Comprehensive verification of:
1. Strict Content-Security-Policy (zero-inline script-src, no external CDNs on application routes).
2. Upload boundaries (50MB file limit, 100MB combined limit, empty/truncated uploads).
3. Low-level WAVE_FORMAT_EXTENSIBLE validation (integer PCM vs float, subformat GUIDs, valid bits, block alignment).
4. Browser XSS immunity across HTML/JS architecture and payload roundtripping.
5. Temporary file lifecycle across success, failure, and startup conditions.
"""

from __future__ import annotations

import io
import os
import re
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
    KSDATAFORMAT_SUBTYPE_IEEE_FLOAT,
    KSDATAFORMAT_SUBTYPE_PCM,
    InvalidWavError,
    UnsupportedAudioFormatError,
    read_wav,
    validate_wav,
)
from app.core.config import settings
from app.main import app, cleanup_orphaned_temp_files
from app.services.cryptaudio_service import embed_message, extract_message


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI test client."""
    return TestClient(app, raise_server_exceptions=False)


def _build_test_wav_bytes(
    channels: int = 1,
    sample_rate: int = 44100,
    sample_width: int = 2,
    num_frames: int = 1000,
) -> bytes:
    """Helper to generate a pristine PCM WAV in memory."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        if sample_width == 1:
            raw_frames = b"\x80" * (num_frames * channels)
        elif sample_width == 2:
            raw_frames = b"\x00\x00" * (num_frames * channels)
        elif sample_width == 3:
            raw_frames = b"\x00\x00\x00" * (num_frames * channels)
        else:
            raw_frames = b"\x00\x00\x00\x00" * (num_frames * channels)
        w.writeframes(raw_frames)
    return buf.getvalue()


def _build_extensible_wav_bytes(
    subformat_guid: bytes = KSDATAFORMAT_SUBTYPE_PCM,
    channels: int = 1,
    sample_rate: int = 44100,
    bits_per_sample: int = 16,
    valid_bits: int = 16,
    block_align: int | None = None,
    num_frames: int = 100,
) -> bytes:
    """Helper to generate a WAVE_FORMAT_EXTENSIBLE WAV file."""
    sample_width = (bits_per_sample + 7) // 8
    if block_align is None:
        block_align = channels * sample_width
    avg_bytes_per_sec = sample_rate * block_align
    cb_size = 22
    channel_mask = 1 if channels == 1 else 3

    # fmt chunk data (40 bytes)
    fmt_data = struct.pack(
        "<HHIIHHHHI",
        0xFFFE,  # WAVE_FORMAT_EXTENSIBLE
        channels,
        sample_rate,
        avg_bytes_per_sec,
        block_align,
        bits_per_sample,
        cb_size,
        valid_bits,
        channel_mask,
    ) + subformat_guid

    data_payload = b"\x00" * (num_frames * block_align)
    fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_data)) + fmt_data
    data_chunk = b"data" + struct.pack("<I", len(data_payload)) + data_payload
    riff_header = b"RIFF" + struct.pack("<I", 4 + len(fmt_chunk) + len(data_chunk)) + b"WAVE"
    return riff_header + fmt_chunk + data_chunk


# ===========================================================================
# 1. Content Security Policy & Security Headers Verification
# ===========================================================================

def test_csp_application_routes_has_no_unsafe_inline_and_no_cdn(client: TestClient):
    """
    Verify application routes enforce script-src 'self' without 'unsafe-inline'
    and without external CDNs (jsdelivr, etc.).
    """
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    # Application script-src must strictly be 'self' (no unsafe-inline, no external CDNs)
    assert "script-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    assert "jsdelivr" not in csp

    # Anti-framing and MIME-sniffing
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_csp_style_src_documents_necessary_unsafe_inline(client: TestClient):
    """
    Verify style-src allows 'self' and 'unsafe-inline' for dynamic UI state changes,
    but does not permit external style CDNs on application routes.
    """
    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "https://cdn.jsdelivr.net" not in csp


def test_api_routes_contain_anti_caching_and_csp(client: TestClient):
    """Verify API routes enforce anti-caching and application CSP."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert "no-store" in response.headers.get("Cache-Control", "")
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("Expires") == "0"
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'self'" in csp
    assert "jsdelivr" not in csp


def test_docs_route_retains_swagger_compatibility(client: TestClient):
    """Verify /docs keeps Swagger-compatible CSP with CDN dependencies."""
    response = client.get("/docs")
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "cdn.jsdelivr.net" in csp


# ===========================================================================
# 2. Upload Boundaries & Memory Safety Verification
# ===========================================================================

def test_reject_upload_exceeding_individual_50mb_limit(client: TestClient, monkeypatch):
    """Verify upload strictly rejects files exceeding individual 50MB limit."""
    # Temporarily set max size to 2000 bytes to test the streaming 413 ceiling
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 2000)
    oversized_data = b"RIFF" + b"\x00" * 2500
    files = {"file": ("oversized.wav", oversized_data, "audio/wav")}
    response = client.post("/api/audio/inspect", files=files)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "FILE_TOO_LARGE"


def test_reject_combined_upload_exceeding_100mb_limit(client: TestClient, monkeypatch):
    """Verify /api/analyze strictly rejects combined files exceeding limit."""
    monkeypatch.setattr(settings, "MAX_COMBINED_UPLOAD_BYTES", 3000)
    data1 = _build_test_wav_bytes(num_frames=200)  # ~444 bytes
    data2 = _build_test_wav_bytes(num_frames=2000)  # ~4044 bytes
    files = {
        "original_file": ("orig.wav", data1, "audio/wav"),
        "stego_file": ("stego.wav", data2, "audio/wav"),
    }
    response = client.post("/api/analyze", files=files)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "FILE_TOO_LARGE"


def test_reject_empty_file_upload(client: TestClient):
    """Verify empty upload is cleanly rejected with 400 EMPTY_FILE."""
    files = {"file": ("empty.wav", b"", "audio/wav")}
    response = client.post("/api/audio/inspect", files=files)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "EMPTY_FILE"


def test_reject_truncated_wav_header(client: TestClient):
    """Verify truncated WAV header is rejected with 400 INVALID_WAV."""
    files = {"file": ("truncated.wav", b"RIFF\x20\x00\x00\x00WAV", "audio/wav")}
    response = client.post("/api/audio/inspect", files=files)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_WAV"


# ===========================================================================
# 3. WAVE_FORMAT_EXTENSIBLE Validation & Audio Parsing Safety
# ===========================================================================

def test_extensible_valid_pcm_16bit_accepted(tmp_path: Path):
    """Verify valid WAVE_FORMAT_EXTENSIBLE 16-bit PCM WAV is accepted."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_PCM,
        bits_per_sample=16,
        valid_bits=16,
    )
    test_file = tmp_path / "valid_extensible_16.wav"
    test_file.write_bytes(wav_bytes)

    wav_data = validate_wav(test_file)
    assert wav_data.channels == 1
    assert wav_data.sample_width == 2
    assert wav_data.frame_count == 100


def test_extensible_valid_pcm_24bit_accepted(tmp_path: Path):
    """Verify valid WAVE_FORMAT_EXTENSIBLE 24-bit PCM WAV is accepted."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_PCM,
        bits_per_sample=24,
        valid_bits=24,
    )
    test_file = tmp_path / "valid_extensible_24.wav"
    test_file.write_bytes(wav_bytes)

    wav_data = validate_wav(test_file)
    assert wav_data.sample_width == 3
    assert wav_data.frame_count == 100


def test_extensible_valid_pcm_32bit_accepted(tmp_path: Path):
    """Verify valid WAVE_FORMAT_EXTENSIBLE 32-bit integer PCM WAV is accepted."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_PCM,
        bits_per_sample=32,
        valid_bits=32,
    )
    test_file = tmp_path / "valid_extensible_32.wav"
    test_file.write_bytes(wav_bytes)

    wav_data = validate_wav(test_file)
    assert wav_data.sample_width == 4
    assert wav_data.frame_count == 100


def test_extensible_ieee_float_rejected(tmp_path: Path):
    """Verify WAVE_FORMAT_EXTENSIBLE with IEEE Float GUID is rejected."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_IEEE_FLOAT,
        bits_per_sample=32,
        valid_bits=32,
    )
    test_file = tmp_path / "float_extensible.wav"
    test_file.write_bytes(wav_bytes)

    with pytest.raises(UnsupportedAudioFormatError) as exc_info:
        validate_wav(test_file)
    assert "IEEE float" in str(exc_info.value)


def test_extensible_unknown_guid_rejected(tmp_path: Path):
    """Verify WAVE_FORMAT_EXTENSIBLE with unknown/non-PCM GUID is rejected."""
    unknown_guid = b"\xff" * 16
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=unknown_guid,
        bits_per_sample=16,
        valid_bits=16,
    )
    test_file = tmp_path / "unknown_guid_extensible.wav"
    test_file.write_bytes(wav_bytes)

    with pytest.raises(UnsupportedAudioFormatError) as exc_info:
        validate_wav(test_file)
    assert "guid" in str(exc_info.value).lower()


def test_extensible_partial_bit_depth_rejected(tmp_path: Path):
    """Verify WAVE_FORMAT_EXTENSIBLE with partial bit depth (e.g. 18-bit in 24-bit) is rejected."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_PCM,
        bits_per_sample=24,
        valid_bits=18,  # Partial bit depth
    )
    test_file = tmp_path / "partial_bits_extensible.wav"
    test_file.write_bytes(wav_bytes)

    with pytest.raises(UnsupportedAudioFormatError) as exc_info:
        validate_wav(test_file)
    assert "partial bit-depth" in str(exc_info.value).lower()


def test_extensible_invalid_block_align_rejected(tmp_path: Path):
    """Verify WAVE_FORMAT_EXTENSIBLE with invalid block alignment is rejected."""
    wav_bytes = _build_extensible_wav_bytes(
        subformat_guid=KSDATAFORMAT_SUBTYPE_PCM,
        bits_per_sample=16,
        block_align=99,  # Invalid block align (expected 2)
    )
    test_file = tmp_path / "bad_align_extensible.wav"
    test_file.write_bytes(wav_bytes)

    with pytest.raises(InvalidWavError) as exc_info:
        validate_wav(test_file)
    assert "block alignment" in str(exc_info.value).lower()


def test_wav_truncated_chunk_length_rejected(tmp_path: Path):
    """Verify WAV claiming chunk size beyond actual file length is rejected."""
    # Chunk claims 50,000 bytes but only has 10 bytes
    malformed = b"RIFF\x50\x00\x00\x00WAVEfmt \x00\xc3\x00\x00" + b"\x00" * 10
    test_file = tmp_path / "truncated_chunk.wav"
    test_file.write_bytes(malformed)

    with pytest.raises(InvalidWavError) as exc_info:
        validate_wav(test_file)
    assert "exceeding file size" in str(exc_info.value).lower() or "truncated" in str(exc_info.value).lower()


# ===========================================================================
# 4. Browser-Based XSS Prevention & Text Rendering Verification
# ===========================================================================

def test_html_contains_zero_inline_scripts():
    """Verify index.html contains no inline <script> tags or inline event handlers."""
    html_path = Path(PROJECT_ROOT) / "frontend" / "index.html"
    content = html_path.read_text(encoding="utf-8")

    # Match all <script> tags
    script_tags = re.findall(r"<script(.*?)>", content, flags=re.IGNORECASE)
    assert len(script_tags) == 3  # exactly theme.js, api.js, and app.js
    for tag in script_tags:
        assert 'src="' in tag, f"Found inline <script> tag without src: <script{tag}>"

    # Match inline event handlers (onclick=, onerror=, onload=, onsubmit=)
    inline_handlers = re.findall(r"\s+on\w+\s*=", content, flags=re.IGNORECASE)
    assert len(inline_handlers) == 0, f"Found inline event handlers: {inline_handlers}"


def test_theme_js_executes_in_head_before_body():
    """Verify theme.js is synchronously included in <head> to prevent FOUC without inline JS."""
    html_path = Path(PROJECT_ROOT) / "frontend" / "index.html"
    content = html_path.read_text(encoding="utf-8")
    head_match = re.search(r"<head>(.*?)</head>", content, flags=re.DOTALL | re.IGNORECASE)
    assert head_match is not None
    head_content = head_match.group(1)
    assert '<script src="/static/js/theme.js"></script>' in head_content


def test_all_xss_attack_vectors_roundtrip_as_plain_text(tmp_path: Path):
    """
    Verify diverse XSS attack vectors embed, extract, and preserve exact plain-text
    fidelity without executing or corrupting data.
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        '"><svg onload=alert("XSS")>',
        "';alert(document.cookie)//",
        '<a href="javascript:alert(1)">Click Me</a>',
        "<style>body{background:red;}</style>",
        "<iframe src=\"javascript:alert('xss')\"></iframe>",
    ]

    carrier_bytes = _build_test_wav_bytes(num_frames=5000)
    carrier_path = tmp_path / "carrier.wav"
    carrier_path.write_bytes(carrier_bytes)
    password = "SuperSecretPassword123!"

    for idx, payload in enumerate(xss_payloads):
        stego_path = tmp_path / f"stego_{idx}.wav"
        embed_result = embed_message(
            input_wav=carrier_path,
            output_wav=stego_path,
            message=payload,
            password=password,
        )
        assert embed_result.framed_size_bytes > 0

        recovered = extract_message(
            stego_wav=stego_path,
            password=password,
        )
        assert recovered == payload, f"Failed roundtrip for payload: {payload}"


# ===========================================================================
# 5. Temporary File Lifecycle & Cleanup Verification
# ===========================================================================

def test_temporary_files_lifecycle_cleaned_up_on_success(client: TestClient):
    """Verify temporary files are completely unlinked after successful processing."""
    wav_bytes = _build_test_wav_bytes(num_frames=2000)
    files = {"file": ("carrier.wav", wav_bytes, "audio/wav")}
    data = {"message": "Clean Lifecycle Test", "password": "Password123!"}

    response = client.post("/api/embed", files=files, data=data)
    assert response.status_code == 200
    # Consume response content to trigger background task cleanup
    _ = response.content

    # Inspect temporary directory
    temp_wavs = list(settings.TEMP_DIR.glob("*.wav"))
    assert len(temp_wavs) == 0, f"Found lingering temporary files: {temp_wavs}"


def test_temporary_files_lifecycle_cleaned_up_on_failure(client: TestClient):
    """Verify temporary files are cleaned up even when an operation fails."""
    wav_bytes = _build_test_wav_bytes(num_frames=500)
    # Attempt extraction on non-stego audio
    files = {"file": ("not_stego.wav", wav_bytes, "audio/wav")}
    data = {"password": "Password123!"}

    response = client.post("/api/extract", files=files, data=data)
    assert response.status_code in (400, 422)

    temp_wavs = list(settings.TEMP_DIR.glob("*.wav"))
    assert len(temp_wavs) == 0, f"Found lingering temporary files after failure: {temp_wavs}"


def test_startup_cleanup_removes_orphaned_wav_files():
    """Verify startup lifespan cleanup purges lingering .wav files while preserving .gitkeep."""
    temp_dir = settings.TEMP_DIR
    temp_dir.mkdir(parents=True, exist_ok=True)

    orphan1 = temp_dir / "orphan_carrier_123.wav"
    orphan2 = temp_dir / "orphan_stego_456.wav"
    gitkeep = temp_dir / ".gitkeep"

    orphan1.write_bytes(b"dummy wav data")
    orphan2.write_bytes(b"dummy wav data")
    gitkeep.touch()

    assert orphan1.exists()
    assert orphan2.exists()

    # Trigger cleanup
    cleanup_orphaned_temp_files()

    assert not orphan1.exists()
    assert not orphan2.exists()
    assert gitkeep.exists()
