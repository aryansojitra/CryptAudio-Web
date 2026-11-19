# CryptAudio-Web

**Production-Grade Multi-Algorithm Cryptographic Audio Steganography & Distortion Analysis System**

[![Tests](https://img.shields.io/badge/pytest-711%20passed-brightgreen.svg)](#testing--verification)
[![Frontend Tests](https://img.shields.io/badge/node%20tests-17%20passed-brightgreen.svg)](#testing--verification)
[![Browser Tests](https://img.shields.io/badge/playwright-13%20passed-blue.svg)](#testing--verification)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](#system-requirements)
[![Security](https://img.shields.io/badge/AES--256--GCM-PBKDF2--600k-gold.svg)](#cryptographic-design)
[![Version](https://img.shields.io/badge/release-v1.0.0-purple.svg)](#release-readiness)

---

## 1. Project Overview

**CryptAudio-Web** is an extensible, local web-based cryptographic audio steganography system developed for academic research in applied cryptography, audio signal processing, and digital media forensics. It combines authenticated symmetric encryption with multi-algorithm audio steganography, allowing users to conceal confidential messages inside uncompressed PCM WAV carrier files across three complementary domains:

1. **Least Significant Bit (LSB)** — Time/Spatial domain substitution.
2. **DWT-DCT-QIM** — Transform-domain multi-resolution wavelet and discrete cosine transform quantization index modulation.
3. **Echo Hiding** — Acoustic psychoacoustic time-domain delay encoding with cepstral deconvolution.

### The Cryptographic & Steganographic Duality
Standard encryption guarantees message confidentiality during transit but reveals that encrypted communication is occurring. Conversely, classical steganography conceals the presence of communication but lacks cryptographic confidentiality and integrity guarantees if the steganographic algorithm is known. 

CryptAudio-Web resolves this tension by implementing a two-layer defense-in-depth scheme:
- **Layer 1: Cryptographic Authentication & Confidentiality** — All plaintext messages are encrypted with AES-256-GCM using keys derived via PBKDF2-HMAC-SHA256 (600,000 iterations). 
- **Layer 2: Multi-Algorithm Steganographic Concealment** — The authenticated payload is framed with the universal **CSMA v1** envelope (or legacy CSLB) and embedded into carrier audio.

---

## 2. Steganography Algorithm Comparison

| Algorithm | Domain | Theoretical Capacity | Audio Quality (PSNR) | Robustness | Execution Speed | Primary Use Case |
|---|---|---|---|---|---|---|
| **LSB** | Time / Spatial | High (1 bit / sample, ~12.5% of audio) | Excellent ($> 85$ dB) | Fragile (Vulnerable to noise/filtering) | Real-time (< 0.1s) | High-throughput local covert storage |
| **DWT-DCT-QIM** | Transform (Wavelet + DCT) | Medium (1 bit / 16 samples) | High ($> 45$ dB) | Resilient (Survives slight noise, scaling) | Fast (~0.3s) | Robust transmission across linear channels |
| **Echo Hiding** | Acoustic Time Domain | Low (1 bit / 2048 samples) | Good ($> 35$ dB) | Highly Robust (Resistant to lossy processing) | Moderate (~0.8s) | Covert signaling through acoustic/analog links |

---

## 3. Technology Stack

| Layer | Component | Version / Details | Purpose |
|---|---|---|---|
| **Backend** | Python | 3.13.17 | Modern high-performance runtime |
| **API Framework** | FastAPI | 0.115+ | High-performance asynchronous REST API |
| **ASGI Server** | Uvicorn | Standard | Loopback server (`127.0.0.1:8000`) and cloud runner |
| **Cryptography** | `cryptography` | 44.0+ | OpenSSL-backed AES-256-GCM and PBKDF2 |
| **Transforms** | `PyWavelets` | 1.8.0+ | Discrete Wavelet Transform decomposition |
| **Audio Processing** | `wave` (stdlib) | Python standard library | Lossless PCM WAV container parsing and validation |
| **Numerical Analysis**| `numpy` | 2.2+ | Vectorized MSE, SNR, PSNR, correlation, and cepstrum |
| **Visualizations** | `matplotlib` | 3.10+ | Scientific distortion analysis visualization |
| **Browser Testing** | `playwright` | 1.50+ | Automated headless Chrome browser E2E verification |
| **Frontend UI** | HTML5 / CSS3 / Vanilla JS | ECMAScript 2022 | Zero-framework responsive cybersecurity interface |
| **Unit Testing** | `pytest`, `httpx` | 9.2.0, 0.28.1 | Comprehensive automated unit and integration suite |

---

## 4. Architecture & Framing Protocol

CryptAudio-Web implements the **CSMA v1** (CryptAudio Stego Multi-Algorithm) framing protocol:

```text
+---------------------------------------------------------------------------------------+
|                               CSMA v1 PAYLOAD PROTOCOL                                |
+--------+--------+--------+--------+---------+----------------+----------+-------------+
| Sync   | Magic  | AlgoID | Version| Flags   | Payload Length | CRC32    | Encrypted   |
| 2B     | 4B     | 1B     | 1B     | 2B      | 4B             | 4B       | Payload (N) |
| 0xF9A9 | "CSMA" | 1/2/3  | 0x01   | (param) | Big-Endian uint| Checksum | CAUD Header |
+--------+--------+--------+--------+---------+----------------+----------+-------------+
```

### Overhead Breakdown:
- **Cryptographic Header (33 bytes)**: Magic `CAUD` (4B) + Version `0x01` (1B) + Salt (16B) + Nonce (12B). Authenticated as AAD.
- **AES-GCM Authentication Tag (16 bytes)**: 128-bit cryptographic integrity tag.
- **Universal CSMA Envelope (18 bytes)**: Sync (2B) + Magic `CSMA` (4B) + Algorithm ID (1B) + Version (1B) + Flags (2B) + Length (4B) + CRC32 (4B).
- **Total Fixed Protocol Overhead**: $33 + 16 + 18 = 67$ bytes ($536$ bits).

---

## 5. Quick-Start Guide

### Prerequisites
- Python 3.13 or higher
- Windows, Linux, or macOS

### Option A: Local Run (Cross-Platform Python)
```bash
# 1. Clone repository and navigate to root
git clone <repo-url>
cd CryptAudio-Web

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# 3. Install production and test dependencies
pip install -r requirements.txt

# 4. Launch application server
python run.py
```
Open your browser at **http://127.0.0.1:8000**.

### Option B: Windows PowerShell Launcher
```powershell
.\run.ps1
```

### Option C: Cloud Deployment (Render Blueprint)
CryptAudio-Web includes a pre-configured `render.yaml` deployment specification:
```yaml
# Build command: pip install -r requirements.txt
# Start command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```
1. Connect repository to Render as a Web Service.
2. Select Environment: `Python 3`.
3. Set Build Command: `pip install -r requirements.txt`.
4. Set Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.

---

## 6. API Reference Summary

| Endpoint | Method | Description | Parameters |
|---|---|---|---|
| `/api/health` | `GET` | Health check & service status | None |
| `/api/algorithms` | `GET` | List available steganography algorithms & parameter ranges | None |
| `/api/audio/inspect` | `POST` | Inspect technical properties of audio WAV file | `file` (WAV), `algorithm` (optional) |
| `/api/capacity` | `POST` | Calculate authoritative capacity for file, message, & algorithm | `file` (WAV), `message`, `algorithm`, `delta`, `alpha` |
| `/api/embed` | `POST` | Encrypt and embed secret payload into carrier audio | `file` (WAV), `message`, `password`, `algorithm`, `delta`, `alpha` |
| `/api/extract` | `POST` | Extract and decrypt secret message from stego audio | `file` (WAV), `password`, `algorithm` (or `auto`), `delta`, `alpha` |
| `/api/analyze` | `POST` | Calculate MSE, SNR, PSNR, Pearson Correlation between audio pair | `original_file` (WAV), `stego_file` (WAV) |

---

## 7. Testing & Verification

The test suite validates correctness across unit, integration, browser, and security domains:

```bash
# Run all 711 automated pytest tests
.\.venv\Scripts\python.exe -m pytest -v

# Run Phase M8 end-to-end integration tests
.\.venv\Scripts\python.exe -m pytest tests/test_m8_end_to_end_integration.py -v

# Run Phase M8 Playwright browser automation tests (headless Chrome)
.\.venv\Scripts\python.exe -m pytest tests/test_m8_browser_playwright.py -v

# Run Phase M8 security validation suite
.\.venv\Scripts\python.exe -m pytest tests/test_m8_security_validation.py -v

# Run Phase M8 performance and resource tests
.\.venv\Scripts\python.exe -m pytest tests/test_m8_performance_resource.py -v

# Run Frontend logic unit tests (Node.js)
node tests/test_frontend_logic.js

# Run environment verification
.\.venv\Scripts\python.exe scripts\verify_environment.py
```

---

## 8. Security Model & Defensive Guarantees

1. **Cryptographic Integrity**: AES-256-GCM authentication tags guarantee that any modification to the stego audio causes extraction to safely abort (`AUTHENTICATION_FAILED`) with zero plaintext leakage.
2. **Key Derivation Work Factor**: PBKDF2-HMAC-SHA256 with 600,000 iterations defends against offline dictionary attacks.
3. **Hardened HTTP Headers**: Strict `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
4. **Information Disclosure Prevention**: All exceptions return structured JSON errors without Python tracebacks, internal file system paths, or secret keys.
5. **Safe DOM Rendering**: All user-supplied text (recovered messages, filenames) is rendered strictly via `element.textContent`, preventing Cross-Site Scripting (XSS).
6. **Upload Isolation**: File uploads are strictly bounded to 50 MB (100 MB combined for analysis) and processed in isolated temporary storage with guaranteed cleanup on success or error.

---

## 9. License & Academic Attribution
Developed as an applied academic research project in applied cryptography and digital forensics. All rights reserved.
