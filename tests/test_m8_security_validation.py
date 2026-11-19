"""
tests/test_m8_security_validation.py
CryptAudio-Web — Phase M8.4: Comprehensive Security Validation Suite

Rigorously verifies:
1. File Upload Security & Malicious Filenames (Path traversal, extension spoofing, non-WAV, corrupt RIFF, zero-byte).
2. Non-PCM Audio Format Rejection across all steganography algorithms.
3. Cryptographic Security & Nonce/Salt Randomness (AES-256-GCM, PBKDF2 600,000 iterations).
4. Tamper Sensitivity across LSB, DWT-DCT-QIM, and Echo Hiding.
5. Parameter Injection & Boundary Enforcement (delta, alpha, algorithm IDs).
6. Information Disclosure Prevention (Zero stack traces, zero OS paths in error responses).
7. HTTP Security Headers & Anti-Caching.
8. Temporary File Lifecycle & Leakage Prevention.
"""

from __future__ import annotations

import io
import os
import secrets
import struct
import tempfile
import wave
from pathlib import Path
from typing import Generator

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.audio.wav_handler import (
    AudioError,
    InvalidWavError,
    UnsupportedAudioFormatError,
)
from app.core.config import settings
from app.crypto.aes_crypto import (
    KEY_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    TAG_SIZE_BYTES,
    PBKDF2_ITERATIONS,
    SALT_SIZE_BYTES,
    HEADER_SIZE_BYTES,
    DecryptionError,
    _derive_key,
    encrypt_message,
    decrypt_message,
)
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI TestClient with server exceptions suppressed to test 500 handlers."""
    return TestClient(app, raise_server_exceptions=False)


def _generate_valid_wav_bytes(
    duration_sec: float = 1.0,
    sample_rate: int = 44100,
    channels: int = 1,
    sample_width: int = 2,
    freq: float = 440.0,
) -> bytes:
    """Generate a clean PCM WAV file in memory."""
    num_samples = int(duration_sec * sample_rate)
    t = np.linspace(0, duration_sec, num_samples, endpoint=False)
    samples = (0.5 * 32767 * np.sin(2 * np.pi * freq * t)).astype(np.int16)
    if channels == 2:
        samples = np.column_stack([samples, samples]).flatten()

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(samples.tobytes())
    return buf.getvalue()


# ===========================================================================
# 1. File Upload Security & Malicious Input Handling
# ===========================================================================

class TestFileUploadSecurity:
    """Verifies strict rejection of malicious or non-WAV uploads."""

    def test_rejection_of_non_wav_formats(self, client: TestClient) -> None:
        """Non-WAV files (mp3, flac, ogg, exe, sh, py, html) must be rejected with 400."""
        extensions_and_payloads = [
            ("music.mp3", b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 100),
            ("track.flac", b"fLaC\x00\x00\x00\x22" + b"\x00" * 100),
            ("audio.ogg", b"OggS\x00\x02\x00\x00" + b"\x00" * 100),
            ("evil.exe", b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100),
            ("script.sh", b"#!/bin/bash\nrm -rf /\n"),
            ("malicious.py", b"import os; os.system('calc')\n"),
            ("exploit.html", b"<script>alert(1)</script>"),
        ]

        for filename, payload in extensions_and_payloads:
            resp = client.post(
                "/api/audio/inspect",
                files={"file": (filename, payload, "audio/wav")},
            )
            assert resp.status_code in (400, 415), f"Expected 400/415 for {filename}, got {resp.status_code}"
            data = resp.json()
            assert data["success"] is False
            assert "WAV" in data["error"]["message"] or "INVALID" in data["error"]["code"] or "FORMAT" in data["error"]["code"]

    def test_extension_spoofing_rejected(self, client: TestClient) -> None:
        """Executable or text file named evil.wav is rejected by RIFF magic check."""
        fake_wavs = [
            b"MZ\x90\x00\x03\x00" + b"\x00" * 64,  # Windows PE binary
            b"#!/bin/sh\necho pwned\n",              # Shell script
            b"%PDF-1.4\n1 0 obj\n<<>>",             # PDF
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,    # PNG
            b"GIF89a" + b"\x00" * 32,               # GIF
        ]

        for payload in fake_wavs:
            resp = client.post(
                "/api/audio/inspect",
                files={"file": ("spoofed.wav", payload, "audio/wav")},
            )
            assert resp.status_code == 400
            data = resp.json()
            assert data["success"] is False
            assert "INVALID" in data["error"]["code"] or "WAV" in data["error"]["message"]

    def test_zero_byte_file_rejected_across_all_endpoints(self, client: TestClient) -> None:
        """Empty 0-byte file must be rejected across all four audio endpoints."""
        endpoints = [
            ("/api/audio/inspect", {"file": ("empty.wav", b"", "audio/wav")}, {}),
            ("/api/embed", {"file": ("empty.wav", b"", "audio/wav")}, {"message": "Test", "password": "pass"}),
            ("/api/extract", {"file": ("empty.wav", b"", "audio/wav")}, {"password": "pass"}),
            ("/api/analyze", {
                "original_file": ("empty.wav", b"", "audio/wav"),
                "stego_file": ("empty.wav", b"", "audio/wav"),
            }, {}),
        ]

        for path, files, form_data in endpoints:
            resp = client.post(path, files=files, data=form_data)
            assert resp.status_code == 400, f"Endpoint {path} failed to reject 0-byte file: {resp.status_code}"
            assert resp.json()["success"] is False

    def test_path_traversal_filenames_handled_safely(self, client: TestClient) -> None:
        """Malicious filenames with path traversal patterns must not escape temp directory or leak paths."""
        traversal_names = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\calc.exe",
            "....//....//boot.ini",
            "/absolute/root/file.wav",
            "carrier\x00nullbyte.wav",
            "..%2F..%2Fevil.wav",
        ]
        valid_wav = _generate_valid_wav_bytes(duration_sec=0.5)

        for name in traversal_names:
            resp = client.post(
                "/api/audio/inspect",
                files={"file": (name, valid_wav, "audio/wav")},
            )
            # Must succeed in inspection or cleanly fail validation, but NEVER leak host paths
            assert resp.status_code in (200, 400)
            text = resp.text
            assert "Traceback" not in text
            assert "C:\\Users\\" not in text
            assert "C:/Users/" not in text

        # Verify static file mount blocks path traversal
        traversal_resp = client.get("/static/../../app/main.py")
        assert traversal_resp.status_code in (404, 400)

    def test_malformed_riff_headers_rejected(self, client: TestClient) -> None:
        """Truncated, corrupted, or invalid RIFF chunks must be cleanly rejected with 400."""
        valid_wav = _generate_valid_wav_bytes(duration_sec=0.2)

        corruptions = [
            ("truncated_riff", b"RIFF\x10\x00\x00\x00"),                           # Truncated right after header
            ("rifx_endian", b"RIFX" + valid_wav[4:]),                               # Big-endian RIFX magic
            ("form_aiff", b"FORM" + valid_wav[4:]),                                 # AIFF magic
            ("avi_format", valid_wav[:8] + b"AVI " + valid_wav[12:]),              # Non-WAVE format ID
            ("missing_fmt", valid_wav[:12] + b"junk" + valid_wav[16:]),             # Missing fmt chunk
            ("missing_data", valid_wav[:36] + b"junk" + valid_wav[40:]),           # Missing data chunk
        ]

        for name, corrupted in corruptions:
            resp = client.post(
                "/api/audio/inspect",
                files={"file": (f"{name}.wav", corrupted, "audio/wav")},
            )
            assert resp.status_code in (400, 415), f"Failed for {name}: {resp.status_code}"
            assert resp.json()["success"] is False

    def test_non_pcm_formats_rejected(self, client: TestClient) -> None:
        """IEEE float (format 3), A-law (format 6), and mu-law (format 7) must be rejected with 415."""
        valid_wav = _generate_valid_wav_bytes(duration_sec=0.2)

        non_pcm_tags = [
            (3, "IEEE Float"),
            (6, "A-law"),
            (7, "mu-law"),
            (0xFFFE, "Extensible non-PCM"),
        ]

        for tag, name in non_pcm_tags:
            bad_wav = bytearray(valid_wav)
            bad_wav[20:22] = struct.pack("<H", tag)
            resp = client.post(
                "/api/audio/inspect",
                files={"file": (f"{name}.wav", bytes(bad_wav), "audio/wav")},
            )
            assert resp.status_code in (400, 415), f"Expected 400 or 415 for {name}, got {resp.status_code}"
            assert resp.json()["success"] is False
            assert "FORMAT" in resp.json()["error"]["code"] or "PCM" in resp.json()["error"]["message"] or "INVALID" in resp.json()["error"]["code"]


# ===========================================================================
# 2. Cryptographic Security & Salt and Nonce Uniqueness Sanity Check
# ===========================================================================

class TestCryptographicSecurity:
    """Verifies AES-256-GCM parameters, salt/nonce uniqueness sanity checks, and PBKDF2 key derivation."""

    def test_pbkdf2_iterations_is_strictly_600000(self) -> None:
        """PBKDF2 iteration count must strictly equal 600,000 as specified."""
        assert PBKDF2_ITERATIONS == 600_000

    def test_salt_uniqueness_sanity_check_across_successive_encryptions(self) -> None:
        """
        Salt and Nonce Uniqueness Sanity Check:
        20 successive encryptions produce 20 unique 16-byte cryptographically random salts.
        Note: 20 unique samples serve as an implementation sanity check against static or reused salts;
        they do not mathematically establish entropy quality.
        """
        salts = set()
        password = "ConsistentSecretPassword2026!"
        message = "Cryptographic Randomness Test"

        for _ in range(20):
            payload = encrypt_message(message, password)
            salt = payload[5:21]
            assert len(salt) == SALT_SIZE_BYTES == 16
            salts.add(salt)

        assert len(salts) == 20, "Salt was reused across encryptions!"

    def test_nonce_uniqueness_sanity_check_across_successive_encryptions(self) -> None:
        """
        Salt and Nonce Uniqueness Sanity Check:
        20 successive encryptions produce 20 unique 12-byte GCM nonces.
        Note: 20 unique samples serve as an implementation sanity check against static or reused nonces;
        they do not mathematically establish entropy quality.
        """
        nonces = set()
        password = "ConsistentSecretPassword2026!"
        message = "Cryptographic Nonce Test"

        for _ in range(20):
            payload = encrypt_message(message, password)
            nonce = payload[21:33]
            assert len(nonce) == NONCE_SIZE_BYTES == 12
            nonces.add(nonce)

        assert len(nonces) == 20, "Nonce was reused across encryptions!"

    def test_ciphertext_non_deterministic(self) -> None:
        """Identical plaintext and password produces distinct ciphertexts every time."""
        ciphertexts = set()
        password = "NonDeterministicPassword"
        message = "The exact same payload bytes"

        for _ in range(20):
            payload = encrypt_message(message, password)
            ciphertexts.add(payload)

        assert len(ciphertexts) == 20

    def test_tamper_sensitivity_single_bit_flip(self) -> None:
        """Any single-bit modification in ciphertext, tag, or salt causes DecryptionError."""
        password = "TamperDetectionPassword"
        message = "Authentic authenticated data message"
        payload = encrypt_message(message, password)
        raw = bytearray(payload)

        # Offsets in payload: 0..3 Magic, 4 Version, 5..20 Salt, 21..32 Nonce, 33..48 Tag, 49.. Ciphertext
        test_offsets = [5, 10, 22, 35, 45, len(raw) - 1]

        for offset in test_offsets:
            tampered = bytearray(raw)
            tampered[offset] ^= 0x01  # Flip 1 bit

            with pytest.raises(DecryptionError):
                decrypt_message(bytes(tampered), password)

    def test_distinct_passphrases_produce_distinct_derived_keys(self) -> None:
        """
        Distinct Passphrases Produce Distinct PBKDF2-Derived Keys:
        Different passphrases produce distinct 256-bit cryptographic keys even when given an identical salt.
        Note: Comparing outputs across different passphrases verifies that the derivation function produces distinct keys;
        it does not demonstrate independent cryptographic domain separation.
        """
        salt = secrets.token_bytes(16)
        key1 = _derive_key("Password_Alpha_1", salt)
        key2 = _derive_key("Password_Alpha_2", salt)
        key3 = _derive_key("Password_ALPHA_1", salt)

        assert key1 != key2
        assert key1 != key3
        assert len(key1) == KEY_SIZE_BYTES == 32
        assert len(key2) == KEY_SIZE_BYTES == 32


# ===========================================================================
# 3. Multi-Algorithm Carrier Tamper Rejection (End-to-End API)
# ===========================================================================

class TestMultiAlgorithmCarrierTamperRejection:
    """
    Verifies that carrier audio modifications are safely rejected across all algorithms.

    Important distinction of rejection modes:
    - Modifying carrier samples can cause preamble/synchronization loss (HTTP 422 NO_STEGO_PAYLOAD),
      framing/CRC32 checksum mismatch (HTTP 422 PAYLOAD_CORRUPTED), or decryption rejection.
    - CRC32 provides transport/framing error detection, NOT cryptographic authentication.
    - Cryptographic authentication is provided solely by AES-256-GCM authenticated tag verification,
      exercised in test_validly_reframed_ciphertext_tampering_rejected and TestCryptographicSecurity.
    - This test verifies that across all 3 algorithms (LSB, DWT-DCT-QIM, Echo), carrier sample tampering
      is safely rejected without ever leaking secret plaintext.
    """

    @pytest.mark.parametrize("algorithm", ["lsb", "dwt_dct_qim", "echo"])
    def test_carrier_audio_tampering_rejection(self, client: TestClient, algorithm: str) -> None:
        """Modifying samples in stego audio triggers safe rejection (HTTP 400 or 422) without plaintext leakage."""
        # For echo hiding, 1 bit requires 2048 samples; for "M8" payload (67 B = 536 bits), we need ~26s
        duration_sec = 26.0 if algorithm == "echo" else 2.5
        t = np.linspace(0, duration_sec, int(duration_sec * 44100), endpoint=False)
        chirp = (0.5 * 32767 * np.sin(2 * np.pi * (200 + 1000 * t) * t)).astype(np.int16)

        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(44100)
            w.writeframes(chirp.tobytes())
        carrier_bytes = buf.getvalue()

        passphrase = "TamperResistancePass2026!"
        secret = "M8"

        embed_form = {
            "message": secret,
            "password": passphrase,
            "algorithm": algorithm,
        }
        if algorithm == "dwt_dct_qim":
            embed_form["delta"] = "32"
        elif algorithm == "echo":
            embed_form["alpha"] = "0.08"

        # Embed via API
        embed_resp = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
            data=embed_form,
        )
        assert embed_resp.status_code == 200, f"Embed failed: {embed_resp.text}"
        stego_bytes = embed_resp.content

        # Parse WAV with standard wave module and flip audio samples in the middle
        with wave.open(io.BytesIO(stego_bytes), "rb") as w_in:
            nchannels = w_in.getnchannels()
            sampwidth = w_in.getsampwidth()
            framerate = w_in.getframerate()
            raw_frames = w_in.readframes(w_in.getnframes())

        samples = np.frombuffer(raw_frames, dtype=np.int16).copy()

        # Invert samples in the active embedding region
        if algorithm == "echo":
            # For echo hiding, perturb middle segment
            mid = len(samples) // 2
            samples[mid:mid + 1000] = ~samples[mid:mid + 1000]
        else:
            # For LSB and DWT-DCT-QIM, perturb initial embedding samples (where envelope/payload reside)
            samples[20:200] = ~samples[20:200]

        tampered_stego = io.BytesIO()
        with wave.open(tampered_stego, "wb") as w_out:
            w_out.setnchannels(nchannels)
            w_out.setsampwidth(sampwidth)
            w_out.setframerate(framerate)
            w_out.writeframes(samples.tobytes())
        tampered_bytes = tampered_stego.getvalue()

        # Extraction on tampered audio must FAIL safely (HTTP 422) and NEVER return plaintext
        extract_form = {"password": passphrase, "algorithm": algorithm}
        if algorithm == "dwt_dct_qim":
            extract_form["delta"] = "32"
        elif algorithm == "echo":
            extract_form["alpha"] = "0.08"

        extract_resp = client.post(
            "/api/extract",
            files={"file": ("tampered_stego.wav", tampered_bytes, "audio/wav")},
            data=extract_form,
        )
        assert extract_resp.status_code in (400, 422)
        assert extract_resp.json()["success"] is False
        assert secret not in extract_resp.text


# ===========================================================================
# 4. Parameter Injection & Boundary Enforcement
# ===========================================================================

class TestParameterValidationAndBoundaries:
    """Verifies that invalid algorithm names, delta, and alpha are rejected."""

    def test_invalid_algorithm_names_rejected(self, client: TestClient) -> None:
        """Injecting unknown or traversal algorithm names must return 400."""
        wav_bytes = _generate_valid_wav_bytes(duration_sec=0.5)

        invalid_algos = [
            "unknown_algo",
            "../../etc/passwd",
            "lsb; DROP TABLE users;",
            "dwt_dct_qim\x00extra",
            "SELECT * FROM algorithms",
            "__import__('os').system('dir')",
        ]

        for algo in invalid_algos:
            resp = client.post(
                "/api/embed",
                files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
                data={
                    "message": "Hello",
                    "password": "ValidPassphrase123",
                    "algorithm": algo,
                },
            )
            assert resp.status_code == 400
            assert resp.json()["success"] is False
            assert "INVALID_ALGORITHM" in resp.json()["error"]["code"] or "algorithm" in resp.json()["error"]["message"].lower()

    def test_dwt_delta_boundary_enforcement(self, client: TestClient) -> None:
        """DWT delta must be in allowed range [1, 256]."""
        wav_bytes = _generate_valid_wav_bytes(duration_sec=0.5)

        invalid_deltas = [-10, 0, 300, 1000, "not_a_number"]
        for d in invalid_deltas:
            resp = client.post(
                "/api/embed",
                files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
                data={
                    "message": "Hello",
                    "password": "ValidPassphrase123",
                    "algorithm": "dwt_dct_qim",
                    "delta": str(d),
                },
            )
            assert resp.status_code in (400, 422)
            assert resp.json()["success"] is False

    def test_echo_alpha_boundary_enforcement(self, client: TestClient) -> None:
        """Echo alpha must be in allowed range (0.0, 1.0)."""
        wav_bytes = _generate_valid_wav_bytes(duration_sec=0.5)

        invalid_alphas = [-0.1, 0.0, 1.0, 2.5, "invalid_float"]
        for a in invalid_alphas:
            resp = client.post(
                "/api/embed",
                files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
                data={
                    "message": "Hello",
                    "password": "ValidPassphrase123",
                    "algorithm": "echo",
                    "alpha": str(a),
                },
            )
            assert resp.status_code in (400, 422)
            assert resp.json()["success"] is False


# ===========================================================================
# 5. Information Disclosure & Security Headers
# ===========================================================================

class TestInformationDisclosureAndHeaders:
    """Verifies that error responses never leak stack traces and headers are enforced."""

    def test_client_error_responses_do_not_leak_internals_400_and_422(self, client: TestClient) -> None:
        """Client-side error responses on HTTP 400 and 422 must not contain tracebacks, server paths, or plaintexts."""
        # 1. HTTP 400: Corrupt audio file upload on embed
        resp_400 = client.post(
            "/api/embed",
            files={"file": ("corrupt.wav", b"Not a WAV", "audio/wav")},
            data={"message": "secret_data", "password": "pass"},
        )
        assert resp_400.status_code == 400
        text_400 = resp_400.text
        assert "Traceback (most recent call last)" not in text_400
        assert ".py\"" not in text_400
        assert "site-packages" not in text_400
        assert "secret_data" not in text_400

        # 2. HTTP 422: Valid audio carrier with invalid extraction password
        valid_wav = _generate_valid_wav_bytes(duration_sec=0.5)
        resp_422 = client.post(
            "/api/extract",
            files={"file": ("carrier.wav", valid_wav, "audio/wav")},
            data={"password": "WrongPassword123", "algorithm": "lsb"},
        )
        assert resp_422.status_code == 422
        text_422 = resp_422.text
        assert "Traceback (most recent call last)" not in text_422
        assert ".py\"" not in text_422
        assert "site-packages" not in text_422

    def test_global_exception_handler_sanitizes_500_response(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Direct test of the global exception handler:
        An unexpected server-side exception must return a generic sanitized HTTP 500 response
        without leaking Python tracebacks, internal filesystem paths, exception details, or sensitive message content.
        """
        def _exploding_embed(*args, **kwargs):
            raise RuntimeError(
                "Simulated server crash: DB connection dropped at /var/www/internal/secrets/db.key "
                "with sensitive credentials 'SENSITIVE_SECRET_TOKEN_XYZ'"
            )

        monkeypatch.setattr("app.api.routes.embed_message", _exploding_embed)

        valid_wav = _generate_valid_wav_bytes(duration_sec=0.5)
        sensitive_secret = "Confidential_Payload_999"
        sensitive_password = "Confidential_Password_888"

        resp = client.post(
            "/api/embed",
            files={"file": ("carrier.wav", valid_wav, "audio/wav")},
            data={
                "message": sensitive_secret,
                "password": sensitive_password,
                "algorithm": "lsb",
            },
        )

        assert resp.status_code == 500
        resp_json = resp.json()
        assert resp_json["success"] is False
        assert resp_json["error"]["code"] == "INTERNAL_ERROR"
        assert "An unexpected error occurred" in resp_json["error"]["message"]

        text = resp.text
        assert "Traceback" not in text
        assert "RuntimeError" not in text
        assert "/var/www/internal" not in text
        assert "db.key" not in text
        assert "SENSITIVE_SECRET_TOKEN_XYZ" not in text
        assert sensitive_secret not in text
        assert sensitive_password not in text
        assert ".py" not in text
        assert "site-packages" not in text

    @pytest.mark.anyio
    async def test_direct_global_exception_handler_sanitization(self) -> None:
        """
        Direct test of the global exception handler function:
        Confirms that when invoked with an unexpected Exception containing sensitive internal paths and credentials,
        it returns an HTTP 500 JSONResponse with exact sanitized structure and no sensitive leaks.
        """
        import json
        from starlette.requests import Request
        from app.main import global_exception_handler

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/internal/test",
            "headers": [],
        }
        dummy_request = Request(scope)
        sensitive_error = RuntimeError(
            "Fatal DB exception: user=admin password=SuperSecretPassword123 "
            "at /etc/ssl/certs/private.key"
        )

        response = await global_exception_handler(dummy_request, sensitive_error)
        assert response.status_code == 500
        data = json.loads(response.body.decode("utf-8"))
        assert data == {
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. Please try again.",
            },
        }

        body_str = response.body.decode("utf-8")
        assert "SuperSecretPassword123" not in body_str
        assert "private.key" not in body_str
        assert "Traceback" not in body_str
        assert "RuntimeError" not in body_str

    def test_security_headers_present_on_all_responses(self, client: TestClient) -> None:
        """All responses must contain hardened security headers."""
        resp = client.get("/")
        assert resp.status_code == 200

        headers = resp.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "no-referrer"
        assert headers.get("X-XSS-Protection") == "0"
        assert "Content-Security-Policy" in headers

        csp = headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_api_anti_caching_headers(self, client: TestClient) -> None:
        """API endpoints must return strict Cache-Control headers."""
        resp = client.post(
            "/api/audio/inspect",
            files={"file": ("test.wav", _generate_valid_wav_bytes(0.2), "audio/wav")},
        )
        assert resp.status_code == 200
        assert "no-store" in resp.headers.get("Cache-Control", "")
        assert "no-cache" in resp.headers.get("Pragma", "")


# ===========================================================================
# 6. Temporary File Lifecycle & Cleanliness
# ===========================================================================

class TestTempFileLifecycle:
    """Verifies that temporary files are never leaked under normal or error conditions."""

    def test_no_leaked_temp_files_on_failure(self, client: TestClient) -> None:
        """Temporary files created during requests must be deleted even if extraction fails."""
        temp_dir = settings.TEMP_DIR
        temp_dir.mkdir(parents=True, exist_ok=True)
        before_count = len(list(temp_dir.glob("*.wav")))

        # Issue invalid extraction request with wrong password
        wav_bytes = _generate_valid_wav_bytes(duration_sec=0.5)
        resp = client.post(
            "/api/extract",
            files={"file": ("carrier.wav", wav_bytes, "audio/wav")},
            data={"password": "WrongPassword123"},
        )
        assert resp.status_code in (400, 422)

        # Count temp files after
        after_count = len(list(temp_dir.glob("*.wav")))
        assert after_count == before_count, "Temporary file was leaked on failure!"
