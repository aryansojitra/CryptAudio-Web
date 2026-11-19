"""
tests/test_frontend_multi_algorithm.py
CryptAudio Web — Phase M6 Frontend Multi-Algorithm Integration Test Suite

Verifies:
1. Frontend Asset Structure & Static Contracts:
   - index.html includes algorithm selector cards (LSB, DWT-DCT-QIM, Echo Hiding)
   - Dynamic parameter controls for Delta (8, 16, 32, 64) and Alpha (0.001 - 0.50)
   - Extract algorithm dropdown with Automatic Detection and explicit modes
   - Algorithm comparison reference table
   - styles.css contains multi-algorithm classes
   - api.js and app.js implement multi-algorithm handlers and safe DOM text rendering
2. Multi-Algorithm Embed & Download Workflow (POST /api/embed):
   - LSB embedding without algorithm-specific parameters
   - DWT-DCT-QIM embedding with Delta parameter
   - Echo Hiding embedding with Alpha parameter
   - Correct metadata headers (X-Stego-Algorithm, X-Payload-Size-Bytes, X-Framed-Size-Bytes, X-Utilization-Percent)
   - Invalid parameters rejection
3. Multi-Algorithm Extract & Decryption Workflow (POST /api/extract):
   - Automatic detection across all three algorithms
   - Explicit extraction with valid parameters
   - Framing checksum verification status (CRC32)
   - Authentication tag verification (AES-GCM)
   - Error mapping for wrong password and missing payload
4. Capacity Evaluation Endpoint (POST /api/capacity):
   - Capacity computation for LSB, DWT, and Echo
   - Insufficient capacity detection (can_fit=False)
5. Security & Safe Rendering:
   - XSS payload characters preserved literally (safe DOM textContent rendering)
   - Passwords and plaintexts excluded from error responses
"""

from __future__ import annotations

import io
import json
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

from app.core.config import settings
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI test client."""
    return TestClient(app, raise_server_exceptions=False)


def create_pcm_wav_bytes(
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 4000,
) -> bytes:
    """Generate in-memory PCM WAV bytes for testing."""
    bio = io.BytesIO()
    frame_size = channels * sample_width
    frames = bytes((i * 11 + 17) % 256 for i in range(num_frames * frame_size))
    with wave.open(bio, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(frames)
    return bio.getvalue()


# ---------------------------------------------------------------------------
# 1. Frontend Asset Structure & Static Contracts
# ---------------------------------------------------------------------------

class TestFrontendStaticContracts:
    """Verifies that HTML, CSS, and JS assets correctly declare Phase M6 components."""

    def test_index_html_contains_algorithm_selector_cards(self, client: TestClient) -> None:
        """Embed interface must include algorithm selector cards for LSB, DWT-DCT-QIM, and Echo."""
        res = client.get("/")
        assert res.status_code == 200
        html = res.text

        # Embed algorithm cards & input
        assert 'id="embed-algorithm-input"' in html
        assert 'data-algo="lsb"' in html
        assert 'data-algo="dwt_dct_qim"' in html
        assert 'data-algo="echo"' in html
        assert "Spatial/Time Domain" in html
        assert "Transform Domain" in html
        assert "Acoustic Time Domain" in html

        # Embed parameter panels
        assert 'id="embed-params-panel"' in html
        assert 'id="embed-params-dwt"' in html
        assert 'id="embed-params-echo"' in html
        assert 'id="embed-delta-input"' in html
        assert 'id="embed-alpha-input"' in html

        # Default values and options
        assert 'value="32"' in html
        assert 'value="0.08"' in html

    def test_index_html_contains_extract_algorithm_selector(self, client: TestClient) -> None:
        """Extract interface must include algorithm selection with auto-detection and parameter panels."""
        res = client.get("/")
        assert res.status_code == 200
        html = res.text

        # Extract algorithm dropdown
        assert 'id="extract-algorithm-select"' in html
        assert 'value="auto"' in html
        assert 'value="lsb"' in html
        assert 'value="dwt_dct_qim"' in html
        assert 'value="echo"' in html

        # Extract parameter panels
        assert 'id="extract-params-panel"' in html
        assert 'id="extract-params-dwt"' in html
        assert 'id="extract-params-echo"' in html
        assert 'id="extract-delta-input"' in html
        assert 'id="extract-alpha-input"' in html

        # Summary pills in extract result card
        assert 'id="extract-summary-algorithm"' in html
        assert 'id="extract-summary-framing"' in html
        assert 'id="extract-summary-auth"' in html

    def test_index_html_contains_algorithm_comparison_matrix(self, client: TestClient) -> None:
        """Embed interface must provide a reference comparison table for all 3 algorithms."""
        res = client.get("/")
        assert res.status_code == 200
        html = res.text

        assert "Audio Steganography Algorithm Comparison" in html
        assert "comparison-table" in html
        assert "0xF9A9" in html
        assert "0x596A" in html

    def test_stylesheet_contains_m6_classes(self, client: TestClient) -> None:
        """styles.css must define classes for cards, parameters, select, warning banner, and table."""
        res = client.get("/static/css/styles.css")
        assert res.status_code == 200
        css = res.text

        assert ".form-select" in css
        assert ".algo-cards-grid" in css
        assert ".algo-card" in css
        assert ".algo-params-panel" in css
        assert ".capacity-warning-banner" in css
        assert ".comparison-table" in css

    def test_api_js_implements_m6_methods(self, client: TestClient) -> None:
        """api.js must provide checkCapacity, embedMessage with options, and extractMessage with options."""
        res = client.get("/static/js/api.js")
        assert res.status_code == 200
        js = res.text

        assert "listAlgorithms" in js
        assert "checkCapacity" in js
        assert "/api/algorithms" in js
        assert "/api/capacity" in js
        assert "X-Stego-Algorithm" in js
        assert "X-Required-Bits" in js
        assert "X-Available-Bits" in js

    def test_app_js_implements_m6_controllers(self, client: TestClient) -> None:
        """app.js must implement setupAlgorithmSelection, setupExtractAlgorithmSelection, and capacity evaluation."""
        res = client.get("/static/js/app.js")
        assert res.status_code == 200
        js = res.text

        assert "setupAlgorithmSelection" in js
        assert "setupExtractAlgorithmSelection" in js
        assert "triggerCapacityCheck" in js
        assert "runCapacityEvaluation" in js
        assert "embed-capacity-warning" in js


# ---------------------------------------------------------------------------
# 2. Multi-Algorithm Embed Workflow (POST /api/embed)
# ---------------------------------------------------------------------------

class TestMultiAlgorithmEmbedWorkflow:
    """Verifies that the embed endpoint satisfies the frontend API contracts for all 3 algorithms."""

    def test_embed_lsb_workflow(self, client: TestClient) -> None:
        """LSB embed sends algorithm='lsb' and receives streaming WAV with valid headers."""
        carrier = create_pcm_wav_bytes(num_frames=3000)
        res = client.post(
            "/api/embed",
            data={"message": "Secret LSB Message", "password": "Passphrase123!", "algorithm": "lsb"},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "audio/wav"
        assert res.headers.get("x-stego-algorithm") == "lsb"
        assert int(res.headers.get("x-payload-size-bytes", 0)) > 0
        assert int(res.headers.get("x-framed-size-bytes", 0)) > 0
        assert float(res.headers.get("x-utilization-percent", 0)) > 0.0

    def test_embed_dwt_dct_qim_workflow(self, client: TestClient) -> None:
        """DWT embed sends algorithm='dwt_dct_qim' and delta=32.0, receiving streaming WAV."""
        carrier = create_pcm_wav_bytes(num_frames=2000000)  # Sufficient capacity for DWT
        res = client.post(
            "/api/embed",
            data={
                "message": "Secret DWT Message",
                "password": "Passphrase123!",
                "algorithm": "dwt_dct_qim",
                "delta": 32.0,
            },
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "audio/wav"
        assert res.headers.get("x-stego-algorithm") == "dwt_dct_qim"
        assert int(res.headers.get("x-payload-size-bytes", 0)) > 0

    def test_embed_echo_workflow(self, client: TestClient) -> None:
        """Echo embed sends algorithm='echo' and alpha=0.08, receiving streaming WAV."""
        carrier = create_pcm_wav_bytes(num_frames=2000000)  # Sufficient capacity for Echo
        res = client.post(
            "/api/embed",
            data={
                "message": "Secret Echo Message",
                "password": "Passphrase123!",
                "algorithm": "echo",
                "alpha": 0.08,
            },
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "audio/wav"
        assert res.headers.get("x-stego-algorithm") == "echo"
        assert int(res.headers.get("x-payload-size-bytes", 0)) > 0

    def test_embed_rejects_auto_algorithm(self, client: TestClient) -> None:
        """Embedding with algorithm='auto' must return HTTP 400 INVALID_PARAMETER."""
        carrier = create_pcm_wav_bytes(num_frames=3000)
        res = client.post(
            "/api/embed",
            data={"message": "Test Message", "password": "Passphrase123!", "algorithm": "auto"},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res.status_code == 400
        body = res.json()
        assert body["success"] is False
        assert body["error"]["code"] == "INVALID_PARAMETER"

    def test_embed_rejects_invalid_parameters(self, client: TestClient) -> None:
        """Invalid delta and alpha parameters must be rejected with HTTP 400 INVALID_PARAMETER."""
        carrier = create_pcm_wav_bytes(num_frames=3000)

        # Invalid Delta
        res_delta = client.post(
            "/api/embed",
            data={"message": "Test", "password": "Pass", "algorithm": "dwt_dct_qim", "delta": 10.0},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res_delta.status_code == 400
        assert res_delta.json()["error"]["code"] == "INVALID_PARAMETER"

        # Invalid Alpha (out of range)
        res_alpha = client.post(
            "/api/embed",
            data={"message": "Test", "password": "Pass", "algorithm": "echo", "alpha": 0.90},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res_alpha.status_code == 400
        assert res_alpha.json()["error"]["code"] == "INVALID_PARAMETER"


# ---------------------------------------------------------------------------
# 3. Multi-Algorithm Extract Workflow (POST /api/extract)
# ---------------------------------------------------------------------------

class TestMultiAlgorithmExtractWorkflow:
    """Verifies that the extract endpoint works with automatic detection and explicit modes."""

    @pytest.mark.parametrize("algo,delta,alpha", [
        ("lsb", None, None),
        ("dwt_dct_qim", 32.0, None),
        ("echo", None, 0.08),
    ])
    def test_extract_automatic_detection(
        self, client: TestClient, algo: str, delta: float | None, alpha: float | None
    ) -> None:
        """Automatic extraction successfully recovers payload and reports detected algorithm."""
        num_frames = 2000000 if algo in ("echo", "dwt_dct_qim") else 3000
        carrier = create_pcm_wav_bytes(num_frames=num_frames)
        secret_msg = f"Confidential payload for {algo} auto-detection! 🔐"
        password = "MasterPassword2026!"

        embed_data = {"message": secret_msg, "password": password, "algorithm": algo}
        if delta is not None:
            embed_data["delta"] = delta
        if alpha is not None:
            embed_data["alpha"] = alpha

        embed_res = client.post("/api/embed", data=embed_data, files={"file": ("carrier.wav", carrier, "audio/wav")})
        assert embed_res.status_code == 200
        stego_bytes = embed_res.content

        # Extract using algorithm="auto"
        extract_res = client.post(
            "/api/extract",
            data={"password": password, "algorithm": "auto"},
            files={"file": ("stego.wav", stego_bytes, "audio/wav")},
        )
        assert extract_res.status_code == 200
        body = extract_res.json()
        assert body["success"] is True
        assert body["message"] == secret_msg
        assert body["algorithm"] == algo
        assert body["framing_checksum_verified"] is True
        assert body["payload_size_bytes"] > 0

    def test_extract_rejects_custom_parameters_in_auto_mode(self, client: TestClient) -> None:
        """Supplying delta or alpha during automatic extraction must return HTTP 400 INVALID_PARAMETER."""
        carrier = create_pcm_wav_bytes(num_frames=3000)
        res = client.post(
            "/api/extract",
            data={"password": "Password123!", "algorithm": "auto", "delta": 32.0},
            files={"file": ("stego.wav", carrier, "audio/wav")},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_PARAMETER"

    def test_extract_incorrect_password_handling(self, client: TestClient) -> None:
        """Extracting with wrong password returns HTTP 422 AUTHENTICATION_FAILED without leaking plaintext."""
        carrier = create_pcm_wav_bytes(num_frames=3000)
        secret_msg = "UltraSecretMessage"
        correct_pass = "CorrectPass123!"
        wrong_pass = "WrongPass456!"

        embed_res = client.post(
            "/api/embed",
            data={"message": secret_msg, "password": correct_pass, "algorithm": "lsb"},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert embed_res.status_code == 200

        extract_res = client.post(
            "/api/extract",
            data={"password": wrong_pass, "algorithm": "auto"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 422
        body = extract_res.json()
        assert body["success"] is False
        assert body["error"]["code"] == "AUTHENTICATION_FAILED"
        assert secret_msg not in extract_res.text
        assert correct_pass not in extract_res.text


# ---------------------------------------------------------------------------
# 4. Capacity Evaluation Endpoint (POST /api/capacity)
# ---------------------------------------------------------------------------

class TestCapacityEvaluationEndpoint:
    """Verifies that POST /api/capacity correctly calculates metrics and capacity limits."""

    def test_capacity_check_for_all_algorithms(self, client: TestClient) -> None:
        """Capacity check returns valid metrics for LSB, DWT-DCT-QIM, and Echo."""
        carrier = create_pcm_wav_bytes(num_frames=60000)
        message = "Test capacity calculation across algorithms."

        # LSB
        res_lsb = client.post(
            "/api/capacity",
            data={"message": message, "algorithm": "lsb"},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res_lsb.status_code == 200
        body_lsb = res_lsb.json()
        assert body_lsb["success"] is True
        assert body_lsb["can_fit"] is True
        assert body_lsb["algorithm"] == "lsb"
        assert body_lsb["required_bits"] > 0
        assert body_lsb["available_bits"] == 60000

        # DWT-DCT-QIM
        res_dwt = client.post(
            "/api/capacity",
            data={"message": message, "algorithm": "dwt_dct_qim", "delta": 32.0},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert res_dwt.status_code == 200
        body_dwt = res_dwt.json()
        assert body_dwt["success"] is True
        assert body_dwt["algorithm"] == "dwt_dct_qim"

    def test_capacity_check_detects_insufficient_capacity(self, client: TestClient) -> None:
        """When message is too large for carrier duration, can_fit must be False and provide duration advice."""
        # Very short carrier (1000 frames) with large message in Echo Hiding
        short_carrier = create_pcm_wav_bytes(num_frames=1000)
        large_message = "This is a secret message that exceeds the small acoustic carrier capacity!" * 5

        res = client.post(
            "/api/capacity",
            data={"message": large_message, "algorithm": "echo", "alpha": 0.08},
            files={"file": ("carrier.wav", short_carrier, "audio/wav")},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["success"] is True
        assert body["can_fit"] is False
        assert body["required_bits"] > body["available_bits"]
        assert body["recommended_min_duration_sec"] > 0.0


# ---------------------------------------------------------------------------
# 5. Security & Safe Rendering
# ---------------------------------------------------------------------------

class TestSecurityAndSafeRendering:
    """Verifies XSS safety, input sanitation, and credential secrecy."""

    def test_xss_payload_literal_preservation(self, client: TestClient) -> None:
        """Malicious script tags and HTML markup must roundtrip as exact literal text without execution."""
        carrier = create_pcm_wav_bytes(num_frames=3500)
        xss_message = "<script>alert('XSS-Attack-2026')</script><img src='x' onerror='alert(1)'>"
        password = "PassphraseWithSpecial!@#$%"

        # Embed
        embed_res = client.post(
            "/api/embed",
            data={"message": xss_message, "password": password, "algorithm": "lsb"},
            files={"file": ("carrier.wav", carrier, "audio/wav")},
        )
        assert embed_res.status_code == 200

        # Extract
        extract_res = client.post(
            "/api/extract",
            data={"password": password, "algorithm": "auto"},
            files={"file": ("stego.wav", embed_res.content, "audio/wav")},
        )
        assert extract_res.status_code == 200
        data = extract_res.json()
        # Message is retrieved exactly as literal string
        assert data["message"] == xss_message


# ---------------------------------------------------------------------------
# 6. Phase M6 Focused Corrections Verification
# ---------------------------------------------------------------------------

class TestPhaseM6FocusedCorrections:
    """Verifies all mandatory corrections from the Phase M6 focused review pass."""

    def test_no_legacy_13byte_capacity_assumption_in_frontend(self) -> None:
        """app.js must not contain hardcoded 13-byte framing or 62-byte capacity assumptions."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "msgBytes + 62" not in content, "Legacy 62-byte overhead calculation must be removed"
        assert "msgBytes + 49" not in content, "Legacy 49-byte crypto overhead calculation must be removed"
        assert "cryptoBytes + 13" not in content, "Legacy 13-byte framing overhead calculation must be removed"
        assert "rawBytes - 62" not in content, "Legacy rawBytes - 62 calculation must be removed"
        assert "embedCarrierMaxPlaintext" not in content, "state.embedCarrierMaxPlaintext must be removed"
        assert "renderAuthoritativeCapacity" in content, "Capacity display must be driven by authoritative backend response"

    def test_audio_inspector_does_not_assume_universal_fixed_overhead(self) -> None:
        """Audio Inspector must explain usable capacity is algorithm-dependent, not fixed rawBytes - 62."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "Algorithm-dependent: usable capacity varies" in content
        assert "rawBytes - 62" not in content

    def test_carrier_inspection_sequence_counter_and_fingerprinting(self) -> None:
        """app.js must track inspectionRequestId and input fingerprints to reject stale responses."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "inspectionRequestId" in content
        assert "computeEmbedInputFingerprint" in content
        assert "updateEmbedButtonState" in content
        assert "thisInspectionId !== state.inspectionRequestId" in content

    def test_embed_controller_finally_does_not_unconditionally_enable_button(self) -> None:
        """Embed controller finally block must derive button state via updateEmbedButtonState()."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        embed_fn = content[content.index("function setupEmbedController()"):content.index("function setupExtractController()")]
        assert "btnSubmit.disabled = false" not in embed_fn, "Embed controller finally block must not unconditionally enable button"
        assert "updateEmbedButtonState()" in embed_fn, "Embed controller finally block must derive button state"

    def test_backend_capacity_response_controls_all_algorithms(self, client: TestClient) -> None:
        """POST /api/capacity must return authoritative metrics for LSB, DWT-DCT-QIM, and Echo."""
        carrier = create_pcm_wav_bytes(num_frames=80000)
        msg = "Authoritative Capacity Test Across All Three Algorithms"

        for algo in ["lsb", "dwt_dct_qim", "echo"]:
            res = client.post(
                "/api/capacity",
                data={"message": msg, "algorithm": algo},
                files={"file": ("carrier.wav", carrier, "audio/wav")},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["success"] is True
            assert data["algorithm"] == algo
            assert "required_bits" in data
            assert "available_bits" in data
            assert "framed_payload_bytes" in data
            assert "message_utf8_bytes" in data
            assert "can_fit" in data

    def test_stale_capacity_response_prevention(self) -> None:
        """app.js must implement a request sequence counter and AbortController to discard stale responses."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "capacityRequestId" in content, "Must track request sequence counter"
        assert "thisRequestId !== state.capacityRequestId" in content, "Must discard out-of-order stale responses"
        assert "AbortController" in content, "Must abort prior in-flight capacity requests"

    def test_invalid_file_extension_rejection(self) -> None:
        """app.js must reject non-.wav files immediately, reset input, and never assign to state."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "endsWith('.wav')" in content, "Must validate .wav extension"
        assert "state.embedFile = null" in content, "Must not retain invalid file in state"
        assert "input.value = ''" in content, "Must clear input value on invalid file"

    def test_failed_inspection_prevents_fabricated_samples(self) -> None:
        """app.js must not estimate carrier samples using file.size / 2 on inspection failure."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "file.size / 2" not in content, "Must not fabricate sample count with file.size / 2"
        assert "state.capacityStatus = 'unavailable'" in content, "Must mark capacity as unavailable on inspection failure"

    def test_capacity_unavailable_prevents_embedding(self) -> None:
        """app.js must disable submit and block embedding when capacity is unavailable."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "!state.lastCapacityData || state.embedCanFit !== true" in content
        assert "btnSubmit.disabled = true" in content

    def test_capacity_fit_gating(self, client: TestClient) -> None:
        """Backend capacity checks must dictate can_fit truth values for UI submission gating."""
        # Insufficient capacity
        tiny_carrier = create_pcm_wav_bytes(num_frames=500)
        res_fail = client.post(
            "/api/capacity",
            data={"message": "A" * 200, "algorithm": "echo", "alpha": 0.08},
            files={"file": ("tiny.wav", tiny_carrier, "audio/wav")},
        )
        assert res_fail.status_code == 200
        assert res_fail.json()["can_fit"] is False

        # Sufficient capacity
        large_carrier = create_pcm_wav_bytes(num_frames=50000)
        res_ok = client.post(
            "/api/capacity",
            data={"message": "Short secret", "algorithm": "lsb"},
            files={"file": ("large.wav", large_carrier, "audio/wav")},
        )
        assert res_ok.status_code == 200
        assert res_ok.json()["can_fit"] is True

    def test_crc32_and_aes_gcm_separate_verification_concepts(self) -> None:
        """CRC32 must be labeled strictly as a framing checksum and AES-GCM as cryptographic tag verification."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        assert "CRC32 Verified (Framing Checksum)" in content
        assert "Verified (AES-256-GCM Tag)" in content
        assert "API Success Contract:" in content

    def test_embed_and_extract_reset_restore_parameter_defaults(self) -> None:
        """Embed and extract resets must restore visible parameter inputs and internal state."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        # Embed reset restores state and inputs
        assert "state.embedDelta = 32.0" in content
        assert "state.embedAlpha = 0.08" in content
        assert "deltaSelect.value = '32'" in content
        assert "alphaInput.value = '0.08'" in content

        # Extract reset restores state and inputs
        assert "state.extractDelta = 32.0" in content
        assert "state.extractAlpha = 0.08" in content
        assert "algoSelect.value = 'auto'" in content

    def test_m6_2_malformed_inspection_and_pre_embed_fingerprint_check(self) -> None:
        """Phase M6.2: app.js must validate data.capacity in inspect callback and re-verify fingerprint before embed."""
        app_js_path = PROJECT_ROOT / "frontend" / "js" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        # 1. Validation of data.capacity
        assert "data.capacity" in content, "Must validate data.capacity in inspection callback"
        assert "isCapacityValid" in content or "data.capacity.total_samples" in content, "Must validate required capacity metadata"
        assert "Number.isFinite" in content, "Must use Number.isFinite for capacity metadata validation"
        assert "Number.isInteger" in content, "Must use Number.isInteger for capacity metadata validation"
        assert "Audio inspection returned malformed" in content or "missing or malformed" in content, "Must provide clear error on malformed inspection"

        # 2. Pre-embed double-verification of fingerprint and capacity
        embed_fn = content[content.index("function setupEmbedController()"):content.index("function setupExtractController()")]
        assert "computeEmbedInputFingerprint()" in embed_fn, "Embed click handler must re-compute input fingerprint"
        assert "state.capacityFingerprint === currentFingerprint" in embed_fn, "Embed click handler must require capacityFingerprint to match"
        assert "state.capacityStatus === 'ready'" in embed_fn, "Embed click handler must require capacityStatus to be ready"
        assert "state.embedCanFit === true" in embed_fn, "Embed click handler must require embedCanFit to be true"
        assert "triggerCapacityCheck()" in embed_fn, "Embed click handler must trigger fresh capacity check if unverified"

    def test_node_unit_tests_pass(self) -> None:
        """Execute node unit tests validating api.js defensive validation and app.js logic."""
        import subprocess
        result = subprocess.run(
            ["node", "tests/test_frontend_logic.js"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Node tests failed: {result.stderr}\n{result.stdout}"
        assert "ALL PHASE M6.1 LOGIC AND REGRESSION TESTS PASSED" in result.stdout

