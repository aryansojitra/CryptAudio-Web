# CryptAudio-Web — Phase-wise Development Changelog

All notable technical milestones and architectural implementations of the CryptAudio-Web project are documented below.

---

## Phase 1 — Project Setup & Environment Baseline
- Initialized Python virtual environment (`.venv`) on Windows.
- Established clean directory structure (`app/`, `app/api/`, `app/core/`, `app/crypto/`, `app/audio/`, `app/steganography/`, `app/services/`, `app/evaluation/`, `app/static/`, `tests/`, `scripts/`, `temporary/`).
- Added baseline dependencies (`fastapi`, `uvicorn`, `cryptography`, `numpy`, `matplotlib`, `pytest`, `httpx`, `python-multipart`).
- Authored `scripts/verify_environment.py` with 40 automated structural and import checks.

## Phase 2 — FastAPI Backend Foundation
- Configured FastAPI application in `app/main.py` with local-only host binding (`127.0.0.1:8000`).
- Implemented `GET /api/health` returning system operational status and application metadata.
- Mounted static directory for frontend assets and configured root route serving `index.html`.
- Established standardized JSON error response envelope (`{success: false, error: {code, message}}`).

## Phase 3 — AES-256-GCM Cryptographic Engine
- Implemented `app/crypto/aes_crypto.py`.
- Enforced PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations and 16-byte cryptographically secure random salt.
- Implemented AES-256-GCM authenticated encryption with 12-byte random nonce.
- Designed 33-byte cryptographic header (`CAUD` magic, version `0x01`, salt, nonce) authenticated as Additional Authenticated Data (AAD).
- Authenticated 16-byte (128-bit) GCM tag prevents tampering of ciphertext or header metadata.

## Phase 4 — Audio Processing Engine
- Implemented `app/audio/wav_handler.py`.
- Developed RIFF/WAVE container validator verifying magic bytes, chunk lengths, and uncompressed integer PCM parameters.
- Supported mono and stereo channels (1, 2) and bit depths 8, 16, 24, and 32 bits across sample rates 8,000 to 384,000 Hz.
- Preserved exact sample frame bytes without resampling, re-quantization, or amplitude normalization.
- Implemented theoretical LSB raw capacity calculation ($1 \text{ bit per sample}$).

## Phase 5 — LSB Steganography Engine
- Implemented `app/steganography/lsb_engine.py`.
- Designed 13-byte framing protocol (`CSLB` magic, version `0x01`, 4-byte payload length, 4-byte CRC32 checksum).
- Developed sample-level bitwise LSB replacement (`(sample & ~1) | bit`).
- Implemented sequential bit extraction and CRC32 accidental corruption verification.
- Enforced strict buffer bounds checking to prevent buffer overruns or partial corruptions.

## Phase 6 — Centralized Service Integration
- Implemented `app/services/cryptaudio_service.py` coordinating Crypto, Audio, and Stego engines.
- Built end-to-end `embed_message()` workflow: path validation, carrier inspection, encryption, capacity checks, embedding, and stego validation.
- Built end-to-end `extract_message()` workflow: stego inspection, LSB payload extraction, CRC32 verification, and authenticated decryption.
- Formulated exact mathematical overhead calculation: $62 \text{ bytes}$ total overhead ($49\text{B crypto} + 13\text{B framing}$).

## Phase 7 — Audio Quality Evaluation Engine
- Implemented `app/evaluation/audio_metrics.py` and `app/evaluation/audio_quality.py`.
- Vectorized numerical difference calculations using NumPy arrays.
- Computed Mean Squared Error (MSE), Signal-to-Noise Ratio (SNR), Peak Signal-to-Noise Ratio (PSNR), and Pearson Correlation ($r$).
- Implemented automated qualitative categorization (`Excellent`, `Good`, `Fair`, `Poor`).

## Phase 8 — FastAPI Processing APIs
- Implemented `app/api/routes.py` exposing full REST capabilities.
- Implemented `POST /api/audio/inspect` for carrier metadata and raw capacity.
- Implemented `POST /api/embed` returning streaming stego WAV download with `X-Payload-Size-Bytes`, `X-Framed-Size-Bytes`, and `X-Utilization-Percent` headers.
- Implemented `POST /api/extract` returning decrypted plaintext.
- Implemented `POST /api/analyze` comparing carrier and stego audio.
- Added streaming upload size enforcement (50 MB per file, 100 MB combined) with immediate HTTP 413 rejection.

## Phase 9 — Frontend Design (Light Primary + Dark Theme)
- Designed modern cybersecurity dashboard in `app/static/index.html` and `app/static/css/styles.css`.
- Established Light Theme as default primary aesthetic, with Dark Theme toggle persisted in `localStorage`.
- Built modular responsive views: Dashboard, Embed Message, Extract Message, Audio Inspector, Quality Analysis, and About.
- Created audio file drop zones, capacity gauges, waveform previews, and metrics visualization grids.

## Phase 10 — Frontend and Backend API Integration
- Implemented `app/static/js/api.js` and `app/static/js/app.js`.
- Connected all UI views to backend REST endpoints via asynchronous `fetch` calls.
- Implemented live client-side WAV inspection and capacity calculation before embedding.
- Handled audio playback for original and stego WAV files.
- Provided clear error handling and toast notifications for failed password authentications and invalid files.

## Phase 10.1 — UI Accuracy and Refinement
- Corrected technical labeling: updated capacity equation to exact 62-byte overhead formula.
- Added 6-metric capacity and framing calculation grid on Embed view.
- Added Technical Summary Bar on Dashboard and Protocol Overhead panel on Audio Inspector.
- Added modified sample count tracking and perceptual disclaimer on Quality Analysis view.
- Added "Clear Recovered Message" button with zero-storage persistence on Extract view.
- Resolved responsive layout constraints on mobile viewports down to 375px.

## Phase 11 — Comprehensive Security Testing and Hardening
- Conducted full-stack security review across crypto, WAV parsing, LSB bounds, API endpoints, and DOM manipulation.
- Implemented `security_headers_middleware` in `app/main.py` (`nosniff`, `DENY`, `no-referrer`, anti-caching on `/api/*`, Content Security Policy).
- Sanitized `Content-Disposition` filename stems in `/api/embed` against header injection.
- Replaced toast notification string assembly with safe DOM element creation (`textContent`).
- Added FastAPI `lifespan` startup purge for orphaned temporary files.
- Standardized global 500 error envelope to `{success: false, error: {code, message}}`.
- Authored `tests/test_security_hardening.py` with 21 automated regression tests (262 tests passing).

## Phase 11.1 — Security Verification and CSP Refinement
- Extracted pre-render theme application to `app/static/js/theme.js` in `<head>` to prevent FOUC.
- Purged `'unsafe-inline'` completely from application `script-src` and removed all inline scripts from `index.html`.
- Removed external CDN permissions (`https://cdn.jsdelivr.net`) from all application routes, isolating CDN access to `/docs`.
- Implemented low-level `_verify_riff_wave_format()` in `app/audio/wav_handler.py`:
  - Enforced integer PCM validation (`KSDATAFORMAT_SUBTYPE_PCM`).
  - Strictly rejected IEEE float subformats (`0x0003` and extensible float GUID).
  - Validated subformat GUIDs, chunk boundaries, block alignment, and rejected partial bit depths (e.g. 18-bit in 24-bit container).
- Verified upload streaming boundaries (50MB individual, 100MB combined) and temporary file unlinking.
- Authored `tests/test_security_verification.py` with 22 new tests (298 tests passing).

## Phase 12 — Final Documentation, Deliverables & Packaging
- Authored comprehensive `README.md` with system requirements, installation, run commands, and usage guides.
- Authored 26-section academic project report `PROJECT_REPORT.md`.
- Authored architecture and data flow documentation with Mermaid diagrams in `docs/ARCHITECTURE.md` and `docs/DATA_FLOW.md`.
- Consolidated security assessment in `SECURITY_ASSESSMENT.md`.
- Authored test report in `TEST_REPORT.md` and API reference in `API_DOCUMENTATION.md`.
- Packaged clean, distributable release archive `CryptAudio-Web-Final.zip`.
