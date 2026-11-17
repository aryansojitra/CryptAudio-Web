"""
scripts/run_manual_e2e.py
CryptAudio Web — Manual End-to-End Workflow Verification Harness

Simulates a human user performing all 15 core application actions via API:
1. Open CryptAudio-Web root (GET /)
2. Confirm backend health (GET /api/health)
3. Carrier audio inspection (POST /api/audio/inspect)
4-7. Secret message embedding (POST /api/embed)
8. Verify downloaded stego WAV container format
9-13. Message extraction with correct password (POST /api/extract)
14. Message extraction with incorrect password (POST /api/extract -> HTTP 422)
15. Audio quality comparison (POST /api/analyze)
"""

from __future__ import annotations

import io
import os
import sys
import wave

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

print("\n=== CryptAudio-Web Manual E2E Workflow Verification ===")

# Step 1: Open CryptAudio-Web
r_root = client.get("/")
assert r_root.status_code == 200
print("[Step 1] Open CryptAudio-Web: HTTP 200 OK (Served index.html)")

# Step 2: Confirm backend connection
r_health = client.get("/api/health")
assert r_health.status_code == 200
health = r_health.json()
assert health["status"] == "healthy"
print(f"[Step 2] Backend Health: Connected (app={health['application']}, v={health['version']})")

# Generate synthetic pristine PCM WAV
bio = io.BytesIO()
with wave.open(bio, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(44100)
    w.writeframes(bytes((i * 3 + 7) % 256 for i in range(5000 * 2)))
carrier_bytes = bio.getvalue()

# Step 3: Inspect carrier
r_inspect = client.post("/api/audio/inspect", files={"file": ("carrier.wav", carrier_bytes, "audio/wav")})
assert r_inspect.status_code == 200
inspect_data = r_inspect.json()
print(
    f"[Step 3] Audio Inspector: Channels={inspect_data['audio']['channels']}, "
    f"Rate={inspect_data['audio']['sample_rate']}Hz, "
    f"Depth={inspect_data['audio']['bit_depth']}-bit, "
    f"Capacity={inspect_data['capacity']['raw_capacity_bytes']}B"
)

# Step 4-7: Embed message
secret = "National Forensic Sciences University — Academic Stego 2026"
password = "TestPassphrase_123!"
r_embed = client.post(
    "/api/embed",
    data={"message": secret, "password": password},
    files={"file": ("carrier.wav", carrier_bytes, "audio/wav")},
)
assert r_embed.status_code == 200
assert r_embed.headers["content-type"] == "audio/wav"
payload_size = r_embed.headers.get("x-payload-size-bytes")
util_pct = r_embed.headers.get("x-utilization-percent")
stego_bytes = r_embed.content
print(f"[Step 4-7] Embed Message: Succeeded. Payload={payload_size}B, Util={util_pct}%, Received {len(stego_bytes)}B stego WAV")

# Step 8: Verify stego WAV is valid PCM
bio_stego = io.BytesIO(stego_bytes)
with wave.open(bio_stego, "rb") as w:
    assert w.getnchannels() == 1
    assert w.getsampwidth() == 2
    assert w.getframerate() == 44100
print("[Step 8] Downloaded Stego WAV: Valid 16-bit 44.1kHz PCM container")

# Step 9-13: Extract with correct password
r_extract = client.post("/api/extract", data={"password": password}, files={"file": ("stego.wav", stego_bytes, "audio/wav")})
assert r_extract.status_code == 200
recovered = r_extract.json()["message"]
assert recovered == secret
print(f"[Step 9-13] Extract Message (Correct Password): Succeeded! Recovered: '{recovered}' (Exact Match: True)")

# Step 14: Extract with incorrect password
r_extract_fail = client.post("/api/extract", data={"password": "WrongPassword999"}, files={"file": ("stego.wav", stego_bytes, "audio/wav")})
assert r_extract_fail.status_code == 422
err = r_extract_fail.json()["error"]
print(f"[Step 14] Extract Message (Incorrect Password): Safe rejection HTTP 422, Code={err['code']}, Msg='{err['message']}'")

# Step 15: Quality Analysis
r_analyze = client.post(
    "/api/analyze",
    files={
        "original_file": ("carrier.wav", carrier_bytes, "audio/wav"),
        "stego_file": ("stego.wav", stego_bytes, "audio/wav"),
    },
)
assert r_analyze.status_code == 200
analysis = r_analyze.json()["analysis"]
print(
    f"[Step 15] Quality Analysis: MSE={analysis['mse']}, "
    f"SNR={analysis['snr_db']}dB, "
    f"PSNR={analysis['psnr_db']}dB, "
    f"r={analysis['correlation']}, "
    f"Assessment='{analysis['quality_assessment']}'"
)

print("\n=== ALL 15 MANUAL E2E WORKFLOW CHECKS PASSED ===\n")
