# CryptAudio Web

**Cryptographic Audio Steganography Application**

---

## Project Overview

CryptAudio Web is a local browser-based application that enables users to encrypt secret text messages using strong symmetric cryptography and conceal them inside audio files using Least Significant Bit (LSB) audio steganography.

The application runs entirely on the user's machine — no cloud, no external servers, no database. All cryptographic operations and audio processing occur locally.

---

## Project Objectives

1. Provide AES-256-GCM encryption of plaintext messages secured by a user-supplied passphrase.
2. Derive encryption keys from passphrases using PBKDF2-HMAC-SHA256 with a random salt.
3. Embed encrypted ciphertext inside PCM WAV audio files via LSB steganography.
4. Extract and decrypt hidden ciphertext from stego audio files.
5. Evaluate stego audio quality using SNR and PSNR metrics via NumPy.
6. Expose all functionality through a FastAPI backend with a clean browser-based UI.

---

## Planned Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, Uvicorn |
| Cryptography | AES-256-GCM, PBKDF2-HMAC-SHA256 (`cryptography` library) |
| Audio I/O | Python standard library `wave` module |
| Audio Processing | NumPy |
| Steganography | LSB (Least Significant Bit) on PCM WAV samples |
| Quality Evaluation | NumPy (SNR, PSNR) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Testing | pytest, httpx |
| File Upload | python-multipart |
| Visualisation | Matplotlib |

---

## Initial Project Architecture

```
CryptAudio-Web/
│
├── app/
│   ├── __init__.py
│   ├── main.py                  ← FastAPI application entry point
│   │
│   ├── api/                     ← API route handlers
│   │   └── __init__.py
│   │
│   ├── core/                    ← Configuration and shared utilities
│   │   └── __init__.py
│   │
│   ├── crypto/                  ← AES-256-GCM + PBKDF2 implementation
│   │   └── __init__.py
│   │
│   ├── audio/                   ← PCM WAV reading and writing
│   │   └── __init__.py
│   │
│   ├── steganography/           ← LSB embedding and extraction
│   │   └── __init__.py
│   │
│   ├── services/                ← Business logic orchestration
│   │   └── __init__.py
│   │
│   ├── evaluation/              ← Audio quality metrics (SNR, PSNR)
│   │   └── __init__.py
│   │
│   └── static/                  ← Frontend assets served by FastAPI
│       ├── index.html
│       ├── css/
│       ├── js/
│       └── assets/
│
├── tests/                       ← pytest test suite
├── scripts/                     ← Utility and verification scripts
│
├── temporary/                   ← Scratch space (not committed)
│   └── .gitkeep
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Python Version

**Python 3.13** is required.

---

## Installation Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd CryptAudio-Web
```

### 2. Verify Python Version

```bash
python --version
# Expected: Python 3.13.x
```

### 3. Create Virtual Environment

```bash
python -m venv .venv
```

### 4. Install Dependencies

Use the virtual environment interpreter directly (avoids PowerShell execution policy issues):

```bash
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 5. Verify Environment

```bash
.venv\Scripts\python.exe scripts\verify_environment.py
```

### 6. Run Tests

```bash
.venv\Scripts\python.exe -m pytest tests/test_environment.py -v
```

### 7. Start Application *(Phase 2+)*

```bash
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## Planned Development Phases

| Phase | Title | Description |
|---|---|---|
| **Phase 1** | Project Setup | Environment, dependencies, structure, Git |
| **Phase 2** | FastAPI Backend | Application entry point, static file serving, health endpoint |
| **Phase 3** | Cryptography | AES-256-GCM encryption/decryption, PBKDF2 key derivation |
| **Phase 4** | Audio Processing | PCM WAV reading, writing, validation using `wave` |
| **Phase 5** | Steganography | LSB embedding and extraction of ciphertext in WAV |
| **Phase 6** | Quality Evaluation | SNR, PSNR computation using NumPy |
| **Phase 7** | Frontend | HTML5/CSS3/JS browser interface |
| **Phase 8** | Integration & Testing | End-to-end tests, API tests with httpx/pytest |

---

## Current Project Status

**Current Phase: Phase 1 — Project Setup**

| Component | Status |
|---|---|
| Project structure | ✅ Complete |
| Python virtual environment | ✅ Complete |
| Dependencies installed | ✅ Complete |
| `requirements.txt` | ✅ Complete |
| `.gitignore` | ✅ Complete |
| `README.md` | ✅ Complete |
| Package `__init__.py` files | ✅ Complete |
| Environment verification script | ✅ Complete |
| Initial test suite | ✅ Complete |
| Git initialised | ✅ Complete |
| AES-256-GCM encryption | ⏳ Pending Phase 3 |
| PBKDF2 key derivation | ⏳ Pending Phase 3 |
| PCM WAV processing | ⏳ Pending Phase 4 |
| LSB embedding | ⏳ Pending Phase 5 |
| LSB extraction | ⏳ Pending Phase 5 |
| Quality evaluation | ⏳ Pending Phase 6 |
| FastAPI routes | ⏳ Pending Phase 2 |
| Frontend UI | ⏳ Pending Phase 7 |

---

## Security Notice

This application is an academic cybersecurity project.

- All cryptographic operations occur locally.
- No data is transmitted externally.
- Do not commit `.env` files, passphrases, or private keys.
- Do not use this tool to conceal information in production or legal contexts without appropriate authorisation.

---

*NFSU — Applied Cryptography — Academic Project*
