# CryptAudio-Web — Phase-wise Development Changelog

All notable technical milestones and architectural implementations of the CryptAudio-Web project are documented below.

---

## Phase 1 — Project Setup & Environment Baseline
- Initialized Python virtual environment (`.venv`) on Windows.
- Established clean directory structure (`app/`, `app/api/`, `app/core/`, `app/crypto/`, `app/audio/`, `app/steganography/`, `app/services/`, `app/evaluation/`, `frontend/`, `tests/`, `scripts/`, `temporary/`).
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
- Designed responsive cybersecurity interface with semantic HTML5, CSS3 variables, and vanilla ES2022 JavaScript.
- Implemented primary Light Theme with high-contrast Dark Theme toggle persisted in `localStorage`.
- Integrated pre-render head script preventing Flash of Unstyled Content (FOUC).
- Implemented tabbed views for Dashboard, Embed, Extract, Audio Inspector, and Quality Analysis.

## Phase 10 — Frontend Integration & Real-Time Capacity
- Connected frontend API client (`frontend/js/api.js`) to backend endpoints.
- Implemented debounced real-time capacity calculator with dynamic progress bar and color-coded status pills.
- Added drag-and-drop file upload zones with visual state transitions.
- Integrated HTML5 Web Audio API waveform and audio player previews.

## Phase 11 & 11.1 — Security Hardening, Verification & Decoupling
- Implemented `security_headers_middleware` in `app/main.py`: `nosniff`, `DENY`, `no-referrer`, anti-caching on `/api/*`.
- Enforced strict Content Security Policy (`script-src 'self'`) eliminating external CDN script dependencies.
- Sanitized `Content-Disposition` download filenames against header injection attacks.
- Standardized error envelopes and implemented lifespan startup cleanup of orphaned temporary files.
- Decoupled client presentation (`frontend/`) and backend service (`app/`) for independent deployment readiness.

## Phase 12 — Final Documentation & Release Packaging
- Consolidated academic project report, test report, API documentation, and security assessment.
- Created `scripts/package_release.py` generating clean release archive (`CryptAudio-Web-Final.zip`).

---

## Phase M1 — Multi-Algorithm Steganography Architecture Design
- Formulated extensible multi-algorithm architecture supporting LSB, DWT-DCT-QIM, and Echo Hiding.
- Authored `MULTI_ALGORITHM_ARCHITECTURE.md` specifying interface abstractions, parameter schemas, and backward compatibility.

## Phase M2 — Universal Steganography Framing & Algorithm Registry
- Implemented universal **CSMA v1** envelope protocol (`app/steganography/envelope.py`) with 2-byte sync words (`0xF9A9`, `0x596A`), algorithm flags, length encoding, and CRC32 framing.
- Implemented `StegoAlgorithmRegistry` (`app/steganography/registry.py`) providing discovery, descriptor metadata, and dynamic instantiation.
- Preserved 100% backward compatibility for legacy `CSLB` (Phase 5) payloads.

## Phase M3 — DWT-DCT-QIM Steganography Engine
- Implemented `app/steganography/dwt_dct_qim_engine.py` using `PyWavelets` and `NumPy`.
- Decomposed audio into approximation sub-bands via Discrete Wavelet Transform.
- Applied Discrete Cosine Transform (DCT) on sub-band blocks and embedded payload bits via Quantization Index Modulation (QIM).
- Parameterized quantization step size $\Delta \in [16.0, 64.0]$ (default: 32.0).

## Phase M4 — Echo Hiding Steganography Engine
- Implemented `app/steganography/echo_hiding_engine.py`.
- Encoded payload bits into segments of 2048 samples using dual artificial echo delays ($d_0 = 44, d_1 = 57$) with configurable attenuation $\alpha \in [0.05, 0.20]$ (default: 0.08).
- Implemented cepstral deconvolution recovery using complex cepstrum analysis.

## Phase M5 & M5.1 — Multi-Algorithm Service & REST API Integration
- Extended `app/services/cryptaudio_service.py` with multi-algorithm routing, capacity estimation, and automatic algorithm detection.
- Extended REST endpoints: added `GET /api/algorithms`, added `POST /api/capacity`, and updated `/api/embed`, `/api/extract`, and `/api/audio/inspect`.
- Enforced strict input validation rejecting invalid algorithm names and out-of-bounds parameters.

## Phase M6, M6.1 & M6.2 — Multi-Algorithm Frontend Expansion
- Extended single-page dashboard with interactive algorithm selection cards (LSB, DWT-DCT-QIM, Echo Hiding).
- Added dynamic parameter control panels (Delta slider for DWT, Alpha input for Echo).
- Implemented asynchronous race guards and dynamic input fingerprinting to prevent stale capacity responses.
- Added comprehensive Node.js behavioral test suite (`tests/test_frontend_logic.js`).

## Phase M7, M7.1 & M7.2 — Comparative Benchmarking & Scientific Evaluation
- Implemented automated comparative benchmarking harness (`app/evaluation/benchmark.py`).
- Scientifically evaluated capacity, audio quality (MSE, SNR, PSNR, Pearson Correlation), processing time, and robustness across LSB, DWT-DCT-QIM, and Echo Hiding.
- Produced comprehensive benchmark report in JSON, CSV, and Markdown formats (`BENCHMARK.md`).

## Phase M8 — Final Integration, Security Validation & Release Readiness (v1.0.0)
- **M8.1 Audit & Approval**: Full repository inspection and architecture review; user approval obtained.
- **M8.2 End-to-End Integration**: 15 comprehensive lifecycle integration tests covering all three algorithms, multilingual Unicode, boundary cases, and tampering.
- **M8.3 Playwright Browser Automation**: 13 automated headless Chrome tests verifying UI controls, theme toggling, responsive layouts, live embedding, file downloading, extraction, and in-browser XSS resistance.
- **M8.4 Security Validation**: 22 dedicated security tests verifying non-WAV rejection, malformed RIFF handling, non-PCM rejection, salt/nonce randomness, tamper sensitivity, and zero information leakage.
- **M8.5 Performance & Resource Profile**: Validated processing times, tracemalloc peak memory usage (< 120 MB), 5-way concurrent request handling, and zero temporary file leakage under load.
- **M8.6 Deployment Verification**: Created `render.yaml` deployment blueprint, added cross-platform `run.py`, updated `app/core/config.py` for dynamic cloud port binding, and verified 40/40 environment checks.
- **M8.7 Documentation & Packaging**: Updated `README.md`, `PROJECT_REPORT.md`, `SECURITY_ASSESSMENT.md`, `TEST_REPORT.md`, and `API_DOCUMENTATION.md`; created clean `CryptAudio-Web-Final.zip` distribution package.
- **M8.8 Final Regression**: Executed all 711 pytest tests and 17 Node.js tests with 100% pass rate.
