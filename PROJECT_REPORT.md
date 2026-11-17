# CryptAudio-Web — Academic Project Report

**A Local Web-Based Cryptographic Audio Steganography and Distortion Analysis System**

---

## 1. Title Page

- **Project Title**: CryptAudio-Web: Design and Implementation of an Authenticated Cryptographic Audio Steganography System with Numerical Distortion Evaluation
- **Course**: Applied Cryptography (Sem 1)
- **Institution**: National Forensic Sciences University (NFSU)
- **Application Version**: 1.0.0
- **Technology Stack**: Python 3.13, FastAPI, AES-256-GCM, PBKDF2-HMAC-SHA256, NumPy, HTML5, CSS3, Vanilla JavaScript
- **Date**: November 2026

---

## 2. Abstract

In digital communication, privacy requires both confidentiality and covertness. Cryptography scrambles plaintext into unreadable ciphertext, but reveals the existence of confidential communication, attracting adversarial interception. Conversely, steganography embeds secret data into innocuous media (such as audio), but classical steganography lacks cryptographic confidentiality and integrity guarantees if the embedding mechanism is discovered.

This project presents **CryptAudio-Web**, a local web-based cryptographic audio steganography system that couples authenticated symmetric encryption with Least Significant Bit (LSB) audio steganography. CryptAudio-Web implements AES-256-GCM authenticated encryption with keys derived via PBKDF2-HMAC-SHA256 (600,000 iterations). Plaintexts are transformed into authenticated binary streams and embedded into uncompressed PCM WAV audio samples using spatial bit-level replacement. The system integrates numerical distortion analysis (MSE, SNR, PSNR, and Pearson Correlation) using NumPy to evaluate signal degradation. The software runs entirely on the local loopback interface (`127.0.0.1:8000`) with zero cloud dependencies, safe DOM text binding, and a zero-inline Content Security Policy. The system is validated through 298 automated test cases, 40 environment checks, and an automated end-to-end workflow verification harness.

---

## 3. Introduction

Digital steganography is the art and science of hiding secret data within cover media (images, audio, video) such that an unauthorized observer cannot perceive the presence of the hidden message. While image steganography operates on pixel color channels, audio steganography operates on audio sample amplitudes across time. 

The Human Auditory System (HAS) is extraordinarily sensitive to frequency and phase distortions but is relatively insensitive to minute amplitude variations at the least-significant bit level of high-resolution digital audio samples. When audio is sampled at standard consumer depths (16-bit, 24-bit, or 32-bit integer PCM), modifying the least-significant bit (LSB) of each sample introduces amplitude perturbations on the order of $1 / 2^{15}$ (for 16-bit audio), which is virtually imperceptible to human listeners.

CryptAudio-Web leverages this auditory property to provide a comprehensive, academically rigorous implementation of cryptographic audio steganography, complete with rigorous cryptographic key derivation, container validation, tamper detection, and numerical audio quality benchmarking.

---

## 4. Problem Statement

Contemporary information security solutions face two opposing vulnerabilities:
1. **Cryptographic Detectability**: Strong encryption algorithms (such as AES-GCM or ChaCha20-Poly1305) provide robust mathematical confidentiality. However, transmitting encrypted binary blobs across communication channels immediately flags the sender and receiver as communicating parties, exposing them to targeted traffic analysis, censorship, or cryptanalytic surveillance.
2. **Steganographic Fragility and Insecurity**: Classical steganographic systems often embed unencrypted plaintext or weakly obfuscated strings directly into media samples. If an adversary discovers the embedding protocol or performs statistical steganalysis, the hidden message is revealed in its entirety. Furthermore, classical steganography lacks cryptographic message integrity verification.

There is a clear academic and forensic need for a unified system that integrates authenticated symmetric cryptography with sample-level audio steganography and objective distortion analysis within a defensible, accessible local architecture.

---

## 5. Objectives

The primary technical objectives of CryptAudio-Web are:
1. **Cryptographic Confidentiality & Integrity**: Implement AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations), authenticating the entire 33-byte cryptographic header as Additional Authenticated Data (AAD).
2. **Covert Sample Embedding**: Implement a 1-bit-per-sample LSB replacement algorithm that embeds framed binary payloads into uncompressed integer PCM WAV files without audible distortion.
3. **Container Robustness**: Develop a low-level RIFF/WAVE container validator that validates chunk lengths, enforces integer PCM subformat GUIDs, and rejects IEEE float formats or partial bit depths.
4. **Objective Distortion Assessment**: Construct a vectorized NumPy audio evaluation engine to compute Mean Squared Error (MSE), Signal-to-Noise Ratio (SNR), Peak Signal-to-Noise Ratio (PSNR), and Pearson Correlation ($r$).
5. **Defensive Web Architecture**: Implement a local-first FastAPI backend with chunked streaming upload ceilings (50 MB per file, 100 MB combined), automated temporary file lifecycle unlinking, zero-inline Content Security Policy, and safe DOM rendering.

---

## 6. Scope of the Project

### In-Scope
- Single-page web interface (Light Theme default with Dark Theme toggle) running on `http://127.0.0.1:8000`.
- Uncompressed integer PCM WAV files (8-bit, 16-bit, 24-bit, and 32-bit; mono and stereo; 8,000 Hz to 384,000 Hz).
- Full support for `WAVE_FORMAT_EXTENSIBLE` (0xFFFE) with `KSDATAFORMAT_SUBTYPE_PCM` GUID.
- AES-256-GCM encryption with 600,000 PBKDF2-HMAC-SHA256 iterations and 16-byte random salt.
- Framing protocol (`CSLB`) with CRC32 accidental corruption detection.
- Vectorized NumPy audio distortion evaluation.
- Streaming upload enforcement and local temporary file hygiene.

### Out-of-Scope
- Compressed lossy formats (MP3, AAC, OGG, WMA) or losslessly compressed formats (FLAC, ALAC).
- Non-PCM formats (IEEE 754 float, A-law, $\mu$-law).
- Public internet hosting, multi-tenant databases, user account management, or cloud deployment.
- Frequency-domain steganography (DWT, DCT, spread-spectrum embedding).

---

## 7. Existing System vs. Proposed System

| Dimension | Typical Existing Steganography Systems | CryptAudio-Web (Proposed System) |
|---|---|---|
| **Encryption** | None, or basic Caesar / XOR / unauthenticated AES-CBC | Authenticated AES-256-GCM with 16-byte tag |
| **Key Derivation** | Direct password hashing (single MD5 or SHA-256) | PBKDF2-HMAC-SHA256 with 600,000 iterations & fresh salt |
| **Tamper Resistance** | None; bit flips silently corrupt plaintext | GCM tag + AAD rejects tampered data with HTTP 422 |
| **Audio Container Support** | Fragile 16-bit standard PCM only; crashes on float/extensible | Rigorous low-level RIFF chunk walker; supports 8/16/24/32-bit PCM & Extensible PCM |
| **Distortion Evaluation** | Subjective listening or external manual scripts | Vectorized NumPy engine computing MSE, SNR, PSNR, & $r$ |
| **Transport Security** | None, or permissive CSP allowing inline scripts | Strict zero-inline CSP (`script-src 'self'`) & anti-caching |
| **Memory & Storage** | In-memory buffering prone to OOM denial-of-service | Streaming upload limits (50MB / 100MB) & automated cleanup |

---

## 8. System Requirements

### Hardware Requirements
- **Processor**: x86-64 dual-core processor (2.0 GHz or higher).
- **RAM**: 512 MB minimum (1 GB recommended). Streaming uploads prevent large RAM spikes.
- **Storage**: Minimum 150 MB free disk space for Python runtime and virtual environment.

### Software Requirements
- **Operating System**: Microsoft Windows 10 or 11 (64-bit).
- **Runtime**: Python 3.13 or higher (tested on Python 3.13.17).
- **Web Browser**: Modern standards-compliant browser (Google Chrome 120+, Mozilla Firefox 120+, Microsoft Edge 120+).

---

## 9. Technology Stack

- **Python 3.13.17**: Core application runtime.
- **FastAPI 0.115+**: Asynchronous web API framework providing OpenAPI documentation and request validation.
- **Uvicorn (Standard)**: High-performance ASGI web server bound to `127.0.0.1:8000`.
- **Cryptography 44.0+**: OpenSSL-backed cryptographic library providing PBKDF2 and AES-GCM primitives.
- **Python `wave` & `struct` (Standard Library)**: Low-level binary RIFF/WAVE parsing and serialization.
- **NumPy 2.2+**: High-performance vectorized numerical array processing for distortion analysis.
- **HTML5, CSS3, Vanilla JavaScript (ES2022)**: Zero-framework responsive web interface with strict DOM separation.
- **Pytest 9.2.0 & HTTPX 0.28.1**: Comprehensive automated testing framework.

---

## 10. System Architecture

The architecture enforces strict separation of concerns across four discrete layers:

```
+-----------------------------------------------------------------------+
|                           PRESENTATION LAYER                          |
|         app/static/ (index.html, styles.css, theme.js, app.js)        |
+-----------------------------------------------------------------------+
                                   | (HTTP REST / Multipart / JSON)
                                   v
+-----------------------------------------------------------------------+
|                       TRANSPORT & GATEWAY LAYER                       |
|           app/main.py (Lifespan, Security Headers Middleware)         |
|           app/api/routes.py (Streaming Uploads, Route Handlers)       |
+-----------------------------------------------------------------------+
                                   | (Python Function Calls)
                                   v
+-----------------------------------------------------------------------+
|                       SERVICE COORDINATION LAYER                      |
|         app/services/cryptaudio_service.py (Workflow Orchestration)   |
+-----------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
+------------------+     +-------------------+     +--------------------+
|  CRYPTO ENGINE   |     |   AUDIO ENGINE    |     |    STEGO ENGINE    |
| aes_crypto.py    |     |   wav_handler.py  |     |    lsb_engine.py   |
| (AES-256-GCM /   |     |   (RIFF Parser /  |     |    (CSLB Framing / |
|  PBKDF2-SHA256)  |     |    PCM I/O)       |     |     Bit Injection) |
+------------------+     +-------------------+     +--------------------+
                                   |
                                   v
                         +-------------------+
                         | EVALUATION ENGINE |
                         | audio_metrics.py  |
                         | (MSE / SNR / PSNR)|
                         +-------------------+
```

---

## 11. Module Description

1. **`app.core.config`**: Centralizes application constants, server binding (`127.0.0.1:8000`), upload thresholds (`MAX_UPLOAD_BYTES = 50 MB`, `MAX_COMBINED_UPLOAD_BYTES = 100 MB`), and filesystem paths.
2. **`app.crypto.aes_crypto`**: Handles symmetric key derivation and authenticated encryption.
3. **`app.audio.wav_handler`**: Implements low-level RIFF chunk inspection (`_verify_riff_wave_format`) and PCM read/write operations.
4. **`app.steganography.lsb_engine`**: Implements bit-level sample manipulation and `CSLB` framing.
5. **`app.services.cryptaudio_service`**: Centralized facade orchestrating end-to-end embedding and extraction workflows.
6. **`app.evaluation.audio_metrics`**: Vectorized NumPy module computing statistical distortion metrics between audio signals.
7. **`app.api.routes`**: Exposes REST endpoints, validates multipart parameters, and streams audio downloads.
8. **`app.main`**: Configures FastAPI lifespan, exception handlers, static file mounting, and security headers middleware.

---

## 12. Cryptographic Design

The cryptographic architecture implements **Authenticated Encryption with Associated Data (AEAD)** using the **AES-256-GCM** algorithm:

```
Passphrase (Password)
      |
      |  +-- Salt (16 Bytes, os.urandom)
      v  v
[ PBKDF2-HMAC-SHA256 ] (600,000 iterations)
      |
      v
Symmetric Key (32 Bytes / 256 Bits)
      |
      |  +-- Nonce / IV (12 Bytes, os.urandom)
      |  |  +-- Plaintext Message (UTF-8 Bytes)
      |  |  |  +-- AAD = 33-Byte Cryptographic Header
      v  v  v  v
[ AES-256-GCM Encrypt ]
      |
      +---> Ciphertext (N Bytes)
      +---> Authentication Tag (16 Bytes / 128 Bits)
```

### Cryptographic Parameters
- **Cipher**: AES-256 in Galois/Counter Mode (GCM).
- **Key Derivation Function**: PBKDF2-HMAC-SHA256.
- **Iteration Count**: 600,000 iterations (exceeds OWASP minimum baseline).
- **Derived Key Length**: 32 bytes (256 bits).
- **Salt**: 16 bytes (128 bits) generated via cryptographically secure `os.urandom(16)`.
- **Initialization Vector (Nonce)**: 12 bytes (96 bits) generated fresh per encryption.
- **Authentication Tag**: 16 bytes (128 bits).
- **Authenticated Associated Data (AAD)**: Complete 33-byte cryptographic header.

---

## 13. Audio Processing Engine

The audio engine handles uncompressed integer PCM WAV files.

### Container Validation Logic (`_verify_riff_wave_format`)
1. Reads 12-byte RIFF header, checking `RIFF` magic and `WAVE` format identifier.
2. Iterates over all sub-chunks, validating that declared chunk sizes fit within file boundaries.
3. Inspects the `fmt ` chunk:
   - For `0x0001` (WAVE_FORMAT_PCM): Validates channels (1 or 2), sample width (1, 2, 3, 4 bytes), and sample rate (8,000 to 384,000 Hz).
   - For `0x0003` (WAVE_FORMAT_IEEE_FLOAT): Strictly rejects with `UnsupportedAudioFormatError`.
   - For `0xFFFE` (WAVE_FORMAT_EXTENSIBLE): Enforces `fmt ` chunk size $\ge 40$ bytes, `cbSize \ge 22`, and inspects the 16-byte `SubFormat` GUID:
     - `KSDATAFORMAT_SUBTYPE_PCM` (`00000001-0000-0010-8000-00aa00389b71`): Accepted.
     - `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT` (`00000003-0000-0010-8000-00aa00389b71`): Strictly rejected.
     - Partial Bit Depths: Verifies `wValidBitsPerSample == wBitsPerSample`. Rejects partial bit depths (e.g. 18-bit valid in 24-bit container).
   - Validates block alignment: `nBlockAlign == nChannels * sample_width`.

---

## 14. LSB Steganography Algorithm

The steganography engine embeds binary bits into the least-significant bit of each PCM sample byte:

### Bitwise Embedding Operation
For sample byte $S$ and binary bit $b \in \{0, 1\}$:
```c
S_stego = (S & ~1) | b
```

### Bitwise Extraction Operation
For stego sample byte $S_{\text{stego}}$:
```c
b = S_stego & 1
```

### Embedding Rules
1. Embedding proceeds sequentially through audio sample bytes starting at sample byte 0.
2. Bits are ordered most-significant bit (MSB) to least-significant bit (LSB) per payload byte.
3. Once all framed payload bits are embedded, sample modification ceases immediately. All subsequent audio samples remain untouched.

---

## 15. Binary Payload & Framing Structure

### A. Cryptographic Payload Structure

| Field Name | Byte Offset | Size | Data Type | Description |
|---|---:|---:|---|---|
| `Magic` | 0 | 4 bytes | ASCII (`CAUD`) | CryptAudio cryptographic identifier |
| `Version` | 4 | 1 byte | uint8 (`0x01`) | Cryptographic format version |
| `Salt` | 5 | 16 bytes | Binary | PBKDF2 random salt |
| `Nonce` | 21 | 12 bytes | Binary | AES-GCM random initialization vector |
| `Ciphertext` | 33 | $N$ bytes | Binary | AES-GCM encrypted message bytes |
| `GCM Tag` | $33 + N$ | 16 bytes | Binary | AES-GCM 128-bit authentication tag |

- **Crypto Header Size**: 33 bytes.
- **Minimum Cryptographic Overhead**: 49 bytes ($33\text{B header} + 16\text{B tag}$).

### B. LSB Framing Protocol Structure

| Field Name | Byte Offset | Size | Data Type | Description |
|---|---:|---:|---|---|
| `Magic` | 0 | 4 bytes | ASCII (`CSLB`) | CryptAudio Stego LSB framing identifier |
| `Version` | 4 | 1 byte | uint8 (`0x01`) | Framing format version |
| `Payload Length` | 5 | 4 bytes | uint32 (BE) | Byte length of contained crypto payload ($N + 49$) |
| `CRC32 Checksum`| 9 | 4 bytes | uint32 (BE) | IEEE 802.3 CRC32 of crypto payload |
| `Payload` | 13 | Variable | Binary | Contained cryptographic payload stream |

- **Framing Header Size**: 13 bytes.
- **Total Combined Protocol Overhead**: 62 bytes ($49\text{B crypto overhead} + 13\text{B framing overhead}$).

> [!NOTE]
> The CRC32 checksum in the framing header is designed solely for rapid accidental transmission corruption detection. Cryptographic authenticity is provided exclusively by the 128-bit AES-GCM authentication tag.

---

## 16. Capacity Calculation & Formulae

Given an uncompressed PCM WAV file with $F$ frames and $C$ channels:

$$\text{Total Audio Samples} = F \times C$$
$$\text{Raw Capacity Bytes} = \left\lfloor \frac{\text{Total Audio Samples}}{8} \right\rfloor$$

For a plaintext message of $M$ UTF-8 bytes:
$$\text{Encrypted Payload Bytes} = M + 49$$
$$\text{Framed Payload Bytes} = (M + 49) + 13 = M + 62$$
$$\text{Required Samples} = (M + 62) \times 8$$

### Capacity Feasibility Check
A message can be embedded if and only if:
$$\text{Required Samples} \le \text{Total Audio Samples}$$

$$\text{Maximum Plaintext Capacity (Bytes)} = \left\lfloor \frac{\text{Total Audio Samples}}{8} \right\rfloor - 62$$

$$\text{Capacity Utilization (\%)} = \left( \frac{\text{Required Samples}}{\text{Total Audio Samples}} \right) \times 100$$

---

## 17. Audio Quality Evaluation Metrics

Distortion analysis compares original sample array $X$ and stego sample array $Y$, both of length $N$:

### 1. Mean Squared Error (MSE)
Quantifies the average squared difference across all samples:
$$\text{MSE} = \frac{1}{N} \sum_{i=1}^{N} (X_i - Y_i)^2$$
*(Lower MSE indicates higher fidelity; $\text{MSE} = 0$ indicates identical signals).*

### 2. Signal-to-Noise Ratio (SNR)
Measures original signal power relative to the distortion (noise) power in decibels:
$$\text{SNR}_{\text{dB}} = 10 \cdot \log_{10} \left( \frac{\sum_{i=1}^{N} X_i^2}{\sum_{i=1}^{N} (X_i - Y_i)^2} \right)$$
*(Higher SNR indicates negligible noise).*

### 3. Peak Signal-to-Noise Ratio (PSNR)
Measures the ratio between maximum possible sample amplitude $\text{MAX}_I$ and mean squared error:
$$\text{PSNR}_{\text{dB}} = 10 \cdot \log_{10} \left( \frac{\text{MAX}_I^2}{\text{MSE}} \right) = 20 \cdot \log_{10} \left( \frac{\text{MAX}_I}{\sqrt{\text{MSE}}} \right)$$
Where $\text{MAX}_I$ is the maximum representable amplitude for the sample width:
- 8-bit unsigned: $\text{MAX}_I = 255$
- 16-bit signed: $\text{MAX}_I = 32,767$
- 24-bit signed: $\text{MAX}_I = 8,388,607$
- 32-bit signed: $\text{MAX}_I = 2,147,483,647$

### 4. Pearson Correlation Coefficient ($r$)
Measures waveform linear correlation and shape preservation:
$$r = \frac{\sum_{i=1}^{N} (X_i - \bar{X})(Y_i - \bar{Y})}{\sqrt{\sum_{i=1}^{N} (X_i - \bar{X})^2 \sum_{i=1}^{N} (Y_i - \bar{Y})^2}}$$
*(Values $r \ge 0.9999$ indicate near-perfect waveform shape preservation).*

### Qualitative Categorization
- **Excellent**: $\text{PSNR} \ge 40\text{ dB}$ and $r \ge 0.9999$.
- **Good**: $\text{PSNR} \ge 30\text{ dB}$ and $r \ge 0.99$.
- **Fair**: $\text{PSNR} \ge 20\text{ dB}$ and $r \ge 0.90$.
- **Poor**: $\text{PSNR} < 20\text{ dB}$ or $r < 0.90$.

---

## 18. API Design

The application provides five REST endpoints:
1. `GET /api/health`: Returns health status and version metadata.
2. `POST /api/audio/inspect`: Inspects WAV file and returns metadata and capacity.
3. `POST /api/embed`: Encrypts message and embeds into carrier audio; streams stego WAV download.
4. `POST /api/extract`: Extracts and decrypts message from stego WAV.
5. `POST /api/analyze`: Computes numerical distortion comparison between carrier and stego files.

All endpoints adhere to unified error envelopes (`{success: false, error: {code, message}}`).

---

## 19. Frontend Design

- **Architecture**: Modular single-page architecture built strictly with semantic HTML5, CSS3, and Vanilla JavaScript (ES2022). Zero frameworks.
- **Theming**: Default primary Light Theme with high-contrast Dark Theme toggle persisted in `localStorage`.
- **FOUC Prevention**: Theme pre-render initialization script loaded synchronously in `<head>`.
- **DOM Safety**: All dynamic data rendered via `textContent` and `createElement`.
- **Components**: Sidebar navigation, drag-and-drop audio dropzones, real-time capacity calculator, HTML5 audio waveform preview, and metrics grid.

---

## 20. Security Assessment Summary

During Phase 11 and Phase 11.1, five findings were identified and remediated:
1. **SEC-01 (Medium)**: Added `security_headers_middleware` enforcing `nosniff`, `DENY`, `no-referrer`, anti-caching on `/api/*`, and zero-inline CSP (`script-src 'self'`).
2. **SEC-02 (Low)**: Sanitized `Content-Disposition` download filenames against header injection.
3. **SEC-03 (Low)**: Replaced toast notification template strings with safe DOM element creation.
4. **SEC-04 (Info)**: Implemented lifespan startup cleanup to purge orphaned `.wav` files.
5. **SEC-05 (Info)**: Standardized global 500 error envelope.

---

## 21. Testing Methodology

Testing employed a layered verification strategy:
- **Unit Tests**: Cryptographic engine, RIFF/WAVE parsing, LSB bitwise embedding, NumPy metrics.
- **API Tests**: Endpoint routing, multipart parsing, response envelopes, HTTP status codes.
- **Boundary & Security Tests**: 50 MB / 100 MB limits, empty files, truncated chunks, tampered salts/nonces/tags, XSS payload roundtrips.
- **Integration Tests**: End-to-end service workflows and UI contract compatibility.
- **Manual Workflow Harness**: 15-step simulated client workflow script.

---

## 22. Test Results

- **Automated Regression Suite (`pytest`)**: **298 / 298 passed (100%)** in 20.01s (with 1 remaining upstream Starlette testclient notice).
- **Environment Verification (`verify_environment.py`)**: **40 / 40 checks passed (100%)**.
- **Manual Workflow Harness (`run_manual_e2e.py`)**: **15 / 15 checks passed (100%)**.

---

## 23. System Limitations

1. **Format Restriction**: Strictly uncompressed integer PCM WAV files only.
2. **Lossy Compression Fragility**: Transcoding to MP3 or AAC alters sample amplitudes and permanently destroys the hidden payload.
3. **Statistical Steganalysis**: Chi-squared and sample-pair steganalysis can detect distribution shifts if carrier audio is inspected.
4. **Password Entropy**: Security depends on passphrase strength against offline PBKDF2 dictionary attacks.
5. **Deployment Scope**: Local loopback execution (`127.0.0.1:8000`) only. Not intended for direct public internet hosting.
6. **Testing Verification Scope**: Actual browser-based XSS execution was not evidenced using a headless browser automation driver (such as Playwright or Puppeteer). Static DOM inspection, test client requests, and test-harness assertions verify architecture and headers, but must not be represented as equivalent to dynamic browser penetration testing.
7. **Remaining CSP Relaxation**: `style-src` retains `'unsafe-inline'` to support dynamic CSS transitions and DOM visibility toggles.

---

## 24. Future Enhancements

1. **Frequency-Domain Steganography**: Incorporate Discrete Wavelet Transform (DWT) or Discrete Cosine Transform (DCT) embedding to improve robustness against lossy compression.
2. **Dynamic LSB Spreading**: Implement pseudorandom sample selection keyed to a cryptographic seed to prevent sequential statistical detection.
3. **Multi-Carrier Sharding**: Distribute large encrypted payloads across multiple audio files.
4. **Hardware Acceleration**: Leverage OpenCL or CUDA for accelerated NumPy metric calculations on multi-gigabyte audio datasets.

---

## 25. Conclusion

CryptAudio-Web successfully achieves its academic and practical objectives by uniting authenticated AES-256-GCM symmetric encryption with sample-level LSB audio steganography. By combining 600,000 PBKDF2 iterations, authenticated associated data headers, strict container validation, objective NumPy distortion metrics, and a defensible local web architecture, the system provides a robust reference implementation for secure, covert digital communications research.

---

## 26. References

1. Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: The Galois/Counter Mode (GCM) and GMAC*. NIST Special Publication 800-38D.
2. Moriarty, K., Kaliski, B., & Rusch, A. (2017). *PKCS #5: Password-Based Cryptography Specification Version 2.1*. RFC 8018, Internet Engineering Task Force.
3. Microsoft Corporation. (2007). *Multiple Channel Audio Data and WAVE Files*. Windows Hardware Developer Central.
4. Westfeld, A., & Pfitzmann, A. (1999). *Attacks on Steganographic Systems: Breaking the Steganographic Utilities EzStego, Jsteg, Steganos, and S-Tools*. Information Hiding, LNCS 1768, pp. 61–76.
5. Johnson, N. F., & Jajodia, S. (1998). *Exploring Steganography: Seeing the Unseen*. IEEE Computer, 31(2), pp. 26–34.
6. Open Web Application Security Project (OWASP). (2023). *Password Storage Cheat Sheet*. OWASP Foundation.
