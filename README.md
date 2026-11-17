# CryptAudio-Web

**Local Cryptographic Audio Steganography & Distortion Analysis Application**

[![Tests](https://img.shields.io/badge/pytest-298%20passed-brightgreen.svg)](#testing)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](#system-requirements)
[![Security](https://img.shields.io/badge/AES--256--GCM-PBKDF2--600k-gold.svg)](#cryptographic-design)
[![Deployment](https://img.shields.io/badge/host-127.0.0.1%3A8000-lightgrey.svg)](#running-the-application)

---

## 1. Project Overview

**CryptAudio-Web** is a local web-based cryptographic audio steganography application developed for academic research in applied cryptography and digital forensics. It combines authenticated symmetric encryption with Least Significant Bit (LSB) audio steganography, allowing users to conceal confidential messages inside uncompressed PCM WAV carrier files.

### Problem Statement
Standard encryption protects message confidentiality during transit but reveals that encrypted communication is occurring. Conversely, classical steganography conceals the presence of communication but lacks cryptographic confidentiality and integrity guarantees if the steganographic algorithm is known. CryptAudio-Web addresses this duality by implementing a two-layer defense-in-depth scheme: strong authenticated encryption followed by sample-level spatial audio concealment.

### Project Objectives
1. **Confidentiality & Authentication**: Encrypt arbitrary Unicode text with AES-256-GCM using keys derived from user passwords via PBKDF2-HMAC-SHA256 (600,000 iterations).
2. **Lossless Audio Steganography**: Embed binary payloads into integer PCM WAV audio samples using bit-level LSB replacement without audible distortion.
3. **Integrity Verification**: Provide two layers of tampering detection: CRC32 for accidental transmission bit corruption and 128-bit AES-GCM tags for cryptographic authenticity.
4. **Distortion Evaluation**: Quantify waveform distortion introduced by steganographic modification using objective metrics: Mean Squared Error (MSE), Signal-to-Noise Ratio (SNR), Peak Signal-to-Noise Ratio (PSNR), and Pearson Correlation ($r$).
5. **Local Privacy**: Run completely on the local host (`127.0.0.1`) without external cloud services, third-party databases, tracking, or remote network dependencies.

---

## 2. Key Features

- **AES-256-GCM Encryption**: Authenticated symmetric encryption with a fresh 12-byte random nonce and 16-byte authentication tag per encryption.
- **Hardened Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations and a cryptographically secure 16-byte salt (`os.urandom(16)`).
- **Authenticated Associated Data (AAD)**: 33-byte cryptographic header is cryptographically bound to the ciphertext, preventing salt/nonce/version tampering.
- **Uncompressed PCM WAV Support**: Inspects, validates, and processes 8-bit, 16-bit, 24-bit, and 32-bit mono and stereo PCM WAV files across sample rates from 8,000 Hz to 384,000 Hz.
- **WAVE_FORMAT_EXTENSIBLE Validation**: Low-level parser validates extensible containers, enforces PCM subformat GUIDs, and rejects IEEE float or partial bit depths.
- **Sample-Level LSB Steganography**: 1-bit-per-sample replacement with 13-byte `CSLB` framing protocol and CRC32 accidental corruption detection.
- **Zero-Modification Trailing**: Carrier audio samples beyond the required payload remain completely untouched.
- **Numerical Audio Quality Evaluation**: Vectorized NumPy engine calculates MSE, SNR (dB), PSNR (dB), and Pearson Correlation ($r$), classifying distortion quality.
- **Strict Content Security Policy (CSP)**: Zero-inline script policy (`script-src 'self'`) with all external CDN dependencies eliminated from application endpoints.
- **Dual-Theme Dashboard**: Clean cybersecurity aesthetic featuring default Light Theme and Dark Theme toggle with `localStorage` persistence and FOUC prevention.

---

## 3. Technology Stack

| Layer | Component | Version / Details | Purpose |
|---|---|---|---|
| **Backend** | Python | 3.13.17 | Core runtime environment |
| **API Framework** | FastAPI | 0.115+ | High-performance asynchronous REST API |
| **ASGI Server** | Uvicorn | Standard | Local loopback web server (`127.0.0.1:8000`) |
| **Cryptography** | `cryptography` | 44.0+ | OpenSSL-backed AES-256-GCM and PBKDF2 |
| **Audio Processing** | `wave` (stdlib) | Python standard library | Lossless PCM WAV container reading and writing |
| **Numerical Analysis**| `numpy` | 2.2+ | Vectorized MSE, SNR, PSNR, and correlation metrics |
| **Visualizations** | `matplotlib` | 3.10+ | Scientific visualization utilities |
| **Frontend UI** | HTML5 / CSS3 / Vanilla JS | ECMAScript 2022 | Zero-framework responsive client interface |
| **Test Suite** | `pytest`, `httpx` | 9.2.0, 0.28.1 | Automated unit, API, integration, and security tests |
| **File Uploads** | `python-multipart` | 0.0.20 | Chunked streaming multipart form handling |

### Decoupled Directory Structure

CryptAudio-Web employs a clean architectural separation between the client presentation layer (`frontend/`) and the core backend service engine (`app/`). This decoupled layout preserves full local development compatibility while facilitating independent hosting migration (such as static hosting on Vercel for the frontend and containerized web service hosting on Render for the FastAPI backend):

```text
CryptAudio-Web/
├── frontend/                     # Client Presentation Layer (Vercel target)
│   ├── index.html                # Single-page dashboard interface
│   ├── css/
│   │   ├── styles.css            # Component rules, layouts, light/dark themes
│   │   └── variables.css         # Theme design tokens & CSS custom properties
│   ├── js/
│   │   ├── api.js                # Centralized REST API client
│   │   ├── app.js                # UI controller, event bindings, client validation
│   │   └── theme.js              # Theme manager (synchronously loaded in head)
│   └── assets/                   # Static graphical assets and icons
├── app/                          # Backend Service Engine (Render target)
│   ├── api/                      # REST API routing (/api/health, /api/embed, etc.)
│   ├── audio/                    # PCM WAV parser, validator, and capacity calculator
│   ├── core/                     # Application settings & security limits
│   ├── crypto/                   # AES-256-GCM authenticated encryption & PBKDF2
│   ├── evaluation/               # NumPy audio quality evaluation (MSE, SNR, PSNR, r)
│   ├── services/                 # Business logic orchestration service
│   ├── steganography/            # 1-bit LSB steganography engine with CRC32 framing
│   ├── __init__.py
│   └── main.py                   # FastAPI entry point, middleware, static mount
├── docs/                         # Technical architecture and data flow documentation
├── scripts/                      # Verification, packaging, and manual test scripts
├── tests/                        # Automated unit, integration, and security test suite
├── temporary/                    # Ephemeral disk storage for streaming audio operations
├── requirements.txt              # Production Python dependencies
└── README.md                     # Main documentation
```

---

## 4. System Requirements

- **Operating System**: Microsoft Windows 10/11 (tested on Windows 11 64-bit).
- **Python**: Python 3.13 or higher (tested on Python 3.13.17).
- **Memory**: Minimum 512 MB RAM (streaming uploads enforce 50 MB / 100 MB limits without buffering files in memory).
- **Disk Space**: ~150 MB for Python virtual environment and dependencies.
- **Web Browser**: Any modern evergreen browser (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari) with JavaScript enabled.

---

## 5. Installation Instructions

Execute the following commands in **Windows PowerShell**:

```powershell
# 1. Navigate to the project root directory
cd CryptAudio-Web

# 2. Create an isolated Python 3.13 virtual environment
python -m venv .venv

# 3. Install required dependencies using the direct virtual environment executable
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 4. Verify environment setup and required packages
.\.venv\Scripts\python.exe scripts\verify_environment.py
```

> [!NOTE]
> Always execute commands via `.\.venv\Scripts\python.exe` directly. This avoids PowerShell script execution policy restrictions (`ExecutionPolicy`).

---

## 6. Running the Application

### Start the Local Server
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Alternatively, you can run the provided convenience script:
```powershell
.\run.ps1
```

### Accessing the System
Once started, access the application via your browser:
- **Main Application**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Backend Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

> [!IMPORTANT]
> The server binds strictly to the loopback address `127.0.0.1`. It does NOT bind to `0.0.0.0` and is intentionally configured solely for local operations.

---

## 7. User Guide & Core Workflows

### Workflow 1: Embedding a Secret Message
1. Navigate to the **Embed Message** tab in the web dashboard.
2. Drag and drop or browse to select a supported carrier PCM WAV audio file.
3. The client automatically queries `/api/audio/inspect` to display carrier duration, sample rate, channels, bit depth, and available capacity.
4. Enter your secret text message into the text area.
5. Enter a strong password into the passphrase field.
6. Observe the real-time capacity calculator verifying that your message fits within the carrier audio.
7. Click **Encrypt & Conceal in Audio**.
8. The server performs authenticated encryption, embeds the payload into sample LSBs, and prompts you to download the resulting `*_stego.wav` file.

### Workflow 2: Extracting a Secret Message
1. Navigate to the **Extract Message** tab.
2. Select or drop your `*_stego.wav` file.
3. Enter the exact password used during embedding.
4. Click **Extract & Decrypt Message**.
5. If the password is correct, the original plaintext message is displayed.
6. **Incorrect Password Behavior**: If an incorrect password is provided, or if the carrier audio has been modified, the backend safely rejects the request with HTTP 422 (`AUTHENTICATION_FAILED`). Zero plaintext or partial fragments are leaked.

### Workflow 3: Audio Inspector
1. Navigate to the **Audio Inspector** tab.
2. Upload any WAV file to inspect technical container parameters (channels, sample rate, bit depth, frame count, audio format, and theoretical embedding capacity).

### Workflow 4: Audio Quality Analysis
1. Navigate to the **Quality Analysis** tab.
2. Upload the **Original Carrier WAV** in the left drop zone.
3. Upload the **Stego WAV** in the right drop zone.
4. Click **Run Quality Analysis**.
5. The system computes and displays objective metrics:
   - **MSE (Mean Squared Error)**: Average squared sample difference.
   - **SNR (Signal-to-Noise Ratio)**: Ratio of original signal power to noise power in dB.
   - **PSNR (Peak Signal-to-Noise Ratio)**: Peak signal-to-noise ratio in dB.
   - **Pearson Correlation ($r$)**: Waveform shape correlation coefficient ($1.000000$ indicates near-identical signals).
   - **Modified Samples**: Exact count and percentage of carrier samples altered during embedding.

---

## 8. Cryptographic & Framing Overhead

The exact embedding capacity equation is:

$$\text{Encrypted Payload Bytes} = \text{Plaintext UTF-8 Bytes} + 49$$
$$\text{Framed Payload Bytes} = \text{Encrypted Payload Bytes} + 13 = \text{Plaintext UTF-8 Bytes} + 62$$
$$\text{Required Samples} = \text{Framed Payload Bytes} \times 8$$
$$\text{Maximum Plaintext Capacity} = \left\lfloor \frac{\text{Total Carrier Samples}}{8} \right\rfloor - 62 \text{ bytes}$$

### Overhead Breakdown (62 Bytes Total)
- **Cryptographic Header (33 bytes)**: Magic `CAUD` (4B) + Version `0x01` (1B) + Salt (16B) + Nonce (12B). Authenticated as AAD.
- **AES-GCM Authentication Tag (16 bytes)**: 128-bit cryptographic integrity tag.
- **LSB Framing Header (13 bytes)**: Magic `CSLB` (4B) + Version `0x01` (1B) + Length (4B) + CRC32 Checksum (4B).

---

## 9. Testing & Verification

Run the complete automated test suite:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Execute the environment verification script:
```powershell
.\.venv\Scripts\python.exe scripts\verify_environment.py
```

Execute the manual end-to-end workflow verification harness:
```powershell
.\.venv\Scripts\python.exe scratch\run_manual_e2e.py
```

---

## 10. System Limitations & Security Boundary

1. **Audio Format Scope**: Only uncompressed integer PCM WAV files (8-bit, 16-bit, 24-bit, 32-bit; mono/stereo) are supported. Compressed formats (MP3, AAC, OGG, FLAC) and IEEE float WAVs are strictly rejected.
2. **Steganography Fragility**: LSB steganography is fragile to lossy compression, transcoding, resampling, equalization, or audio filtering. Any modification to sample amplitudes permanently destroys the concealed payload.
3. **Steganalysis Exposure**: While the payload is strongly encrypted and resembles pseudorandom noise, statistical steganalysis techniques (Chi-squared, sample pair analysis) can detect distribution shifts in the carrier waveform.
4. **Password Strength**: Security is fundamentally bounded by user passphrase entropy. A weak or short password remains vulnerable to offline dictionary or brute-force attacks against PBKDF2.
5. **Browser Memory Hygiene**: JavaScript runtime engines do not guarantee secure zeroization of memory variables or strings upon garbage collection.
6. **Local-Only Deployment**: The application is intended strictly for local development and academic evaluation on `127.0.0.1:8000`. It does not include TLS termination, external authentication, or rate limiting required for hostile public network exposure.
