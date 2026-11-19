# CryptAudio-Web — Complete Project Technical Documentation
**High-Assurance Audio Steganography & Authenticated Cryptography Platform**

---

## 1. Executive Summary & System Overview

**CryptAudio-Web** is an enterprise-grade, defense-in-depth audio steganography and cryptography platform. The system conceals confidential data within uncompressed Pulse Code Modulation (PCM) WAVE (`.wav`) audio files by chaining two distinct security paradigms:

1. **Cryptographic Confidentiality & Integrity**: Before any hiding takes place, confidential UTF-8 plaintext messages are encrypted using authenticated symmetric cryptography (**AES-256-GCM**) with cryptographic keys derived via **PBKDF2-HMAC-SHA256** (600,000 iterations).
2. **Steganographic Concealment**: The resulting binary ciphertext is framed into a standard envelope (**CSMA v1**) and embedded across carrier audio waveforms using one of three domain-specific steganography algorithms:
   - **LSB Replacement** (Time/Spatial Domain)
   - **DWT-DCT-QIM** (Transform Domain: Wavelet + Cosine Quantization Index Modulation)
   - **Echo Hiding** (Cepstral / Time-Delay Domain with bipolar sub-echoes)

By combining cryptographic authentication with steganographic concealment, CryptAudio ensures that even if an adversary detects the presence of hidden data through statistical steganalysis or audio signal extraction, they cannot decipher the message contents without the secret passphrase or forge/tamper with the payload without failing AES-GCM authentication.

```
+--------------------------------------------------------------------------------------------------+
|                                    SENDER EMBEDDING PIPELINE                                     |
|                                                                                                  |
|  [Plaintext Message]                                                                             |
|          |                                                                                       |
|          v                                                                                       |
|  [PBKDF2-HMAC-SHA256] <--- [Passphrase] + [Random 16B Salt] (600,000 Iterations)                 |
|          |                                                                                       |
|          v (256-bit Symmetric Key)                                                               |
|  [AES-256-GCM Encryption] <--- [Random 12B Nonce] + [33B CAUD Header as AAD]                     |
|          |                                                                                       |
|          v (49B+ Ciphertext & 16B GCM Auth Tag)                                                  |
|  [CSMA Framing Header] <--- [Algorithm ID] + [16B Sync Word] + [CRC32 Checksum] (18B Overhead)  |
|          |                                                                                       |
|          v (Framed Payload Stream)                                                               |
|  [Steganographic Engine] <--- [Carrier WAV: 8/16/24/32-bit PCM]                                  |
|          |                      |                                                                |
|          +---> (LSB / DWT-DCT-QIM / Echo Hiding)                                                 |
|          |                                                                                       |
|          v                                                                                       |
|  [Stego WAV Output File]                                                                         |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. System Architecture & Technology Stack

CryptAudio-Web is built upon an asynchronous, decoupled client-server architecture designed for zero client-side dependencies, high throughput, and memory safety.

```
+--------------------------------------------------------------------------------------------------+
|                                  CRYPTAUDIO-WEB ARCHITECTURE                                     |
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   | FRONTEND CLIENT (Browser SPA - Vanilla ES6+ / HTML5 / CSS3)                             |   |
|   |  * theme.js: Synchronous pre-render theme manager (Light/Dark mode)                      |   |
|   |  * api.js: Typed async client, input validation, stale request fingerprinting            |   |
|   |  * app.js: SPA routing, drag-drop audio preview, sequence counters, DOM XSS guards       |   |
|   |  * styles.css / variables.css: Modern responsive CSS variables & layouts                 |   |
|   +------------------------------------------------------------------------------------------+   |
|                                           | (HTTP REST Multipart Form / JSON)                    |
|                                           v                                                      |
|   +------------------------------------------------------------------------------------------+   |
|   | FASTAPI / UVICORN ASGI BACKEND (Python 3.10+)                                            |   |
|   |  * app/api/routes.py: Clean REST endpoints, MIME verification, error sanitization        |   |
|   |  * app/services/cryptaudio_service.py: High-level business logic orchestration           |   |
|   |  * app/crypto/aes_crypto.py: PBKDF2-HMAC-SHA256 (600k rounds) & AES-256-GCM engine       |   |
|   |  * app/audio/wav_handler.py: PCM WAV validator, parsing 8/16/24/32-bit int samples       |   |
|   |  * app/evaluation/metrics.py: Objective audio quality metrics (MSE, SNR, PSNR, Pearson)  |   |
|   |  * app/steganography/: Multi-algorithm extensible engine registry                        |   |
|   |      - envelope.py: CSMA v1 49B framing & CSLB legacy parser                             |   |
|   |      - registry.py: Thread-safe algorithm discovery & factory                            |   |
|   |      - lsb_adapter.py: Sample-level Least Significant Bit engine                         |   |
|   |      - dwt_dct_qim.py: Discrete Wavelet & Cosine Transform QIM engine                    |   |
|   |      - echo_hiding.py: Bipolar sub-echo cepstral deconvolution engine                   |   |
|   +------------------------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------------------------+
```

### 2.1 Backend Framework
- **FastAPI**: Asynchronous web framework providing automatic OpenAPI schema generation, fast request serialization, and strict Pydantic v2 input model enforcement.
- **Uvicorn (Standard)**: High-performance ASGI web server running on uvloop and httptools.
- **Python 3.10+ / 3.13 Compatible**: Utilizes modern typing semantics, explicit dataclasses, and strict context management.

### 2.2 Frontend Client
- **Zero Third-Party Bundlers**: Built entirely with Vanilla ES6+ JavaScript, CSS3 Grid/Flexbox, and HTML5. No external frameworks (React, Vue, Angular) or heavy bundle footprints.
- **Instant Pre-Render Theming (`theme.js`)**: Executes synchronously in `<head>` before DOM parsing to completely eliminate Flash of Unstyled Content (FOUC).
- **Asynchronous State Machine (`app.js` & `api.js`)**: Employs monotonic sequence counters and state fingerprinting to eliminate promise race conditions during asynchronous audio inspection and capacity recalculation.
- **Strict DOM Sanitization**: Eliminates Cross-Site Scripting (XSS) risks by avoiding `innerHTML` interpolation for user-controlled inputs (file names, extracted plaintexts, and error payloads) in favor of safe `textContent` bindings.

---

## 3. Third-Party Libraries & Dependencies

All project dependencies are rigorously pinned to prevent supply-chain drift and ensure security auditability:

| Package Name | Minimum Version | Architectural Role | Security & Functional Justification |
| :--- | :--- | :--- | :--- |
| **`fastapi`** | Latest (`^0.115`) | Web Framework | Provides high-speed RESTful routing, multipart form parsing, and clean exception handling. |
| **`uvicorn[standard]`** | Latest (`^0.34`) | ASGI Server | Async event loop execution with native HTTP protocol parsing. |
| **`python-multipart`** | Latest (`^0.0.12`) | Form Data Parser | Handles streaming binary audio file uploads up to 50 MB with strict temporary file lifecycle management. |
| **`cryptography`** | Latest (`^44.0`) | Cryptographic Engine | Python Cryptographic Authority implementation of OpenSSL-backed AES-256-GCM and PBKDF2-HMAC-SHA256. |
| **`numpy`** | Latest (`^2.2`) | Numerical Processing | Vectorized array operations for sample bit extraction, DCT matrix multiplication, and cepstral analysis. |
| **`PyWavelets`** | `^1.8.0` | Wavelet Transforms | Fast 1D Discrete Wavelet Transform (`pywt.dwt` / `pywt.idwt`) for multi-resolution audio decomposition. |
| **`matplotlib`** | Latest (`^3.10`) | Visualization | Generates benchmark graphs, bit error distributions, and SNR tradeoff curves. |
| **`pytest`** | Latest (`^9.2`) | Test Harness | Orchestrates 718+ automated unit, regression, and security verification tests. |
| **`httpx`** | Latest (`^0.28`) | HTTP Client | TestClient driver for end-to-end REST API integration testing. |
| **`playwright`** | Latest (`^1.49`) | Browser Automation | Headless Chromium driver for real-world E2E browser testing, responsive layout verification, and UI security auditing. |

---

## 4. Cryptographic Implementation (AES-256-GCM + PBKDF2)

CryptAudio enforces strict authenticated symmetric encryption. It guarantees **Confidentiality** (ciphertext cannot be read without the key) and **Integrity/Authenticity** (any bit flips in ciphertext or header metadata cause decryption to fail immediately).

### 4.1 Key Derivation Function (PBKDF2-HMAC-SHA256)
A raw user passphrase is never used directly as an encryption key. Instead, it is transformed using Password-Based Key Derivation Function 2:

$$\text{Key} = \text{PBKDF2-HMAC-SHA256}(\text{Passphrase}, \text{Salt}, \text{Iterations} = 600,000, \text{Length} = 32\text{ bytes})$$

- **Salt**: 16 bytes (128 bits) of cryptographically secure randomness generated via `secrets.token_bytes(16)`. A unique salt is generated for every embedding operation, preventing rainbow table attacks and cross-message key reuse.
- **Iteration Count**: **600,000 rounds**. This significantly exceeds current OWASP recommendations (210,000 rounds for SHA-256) and provides high resistance against GPU and ASIC-based offline dictionary attacks.
- **Derived Key**: 32 bytes (256 bits), matching the key length requirement of AES-256.

### 4.2 Authenticated Cipher (AES-256-GCM)
The derived 256-bit key encrypts the message using Galois/Counter Mode (GCM):

- **Nonce (Initialization Vector)**: 12 bytes (96 bits) generated uniquely for each operation via `secrets.token_bytes(12)`.
- **Authentication Tag**: 16 bytes (128 bits) calculated by the GHASH polynomial authenticator.
- **Authenticated Associated Data (AAD)**: The entire 33-byte `CAUD` header is passed as AAD:
  $$\text{AAD} = \text{Magic (4B)} \parallel \text{Version (1B)} \parallel \text{Salt (16B)} \parallel \text{Nonce (12B)}$$
  Binding the header as AAD cryptographically guarantees that an attacker cannot tamper with the salt, nonce, or version without causing decryption to abort.

### 4.3 Binary Cryptographic Payload Format (`CAUD` Packet)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Magic Identifier: b"CAUD"                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)|                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                       Random Salt (16 Bytes)                  +
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                       Random Nonce (12 Bytes)                 |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
|                  AES-256-GCM Ciphertext                       |
|                       (Variable Length)                       |
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   AES-GCM Auth Tag (16 Bytes)                 +
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |
+-+-+-+-+-+-+-+-+
```

Total Cryptographic Overhead: **49 bytes** (33-byte header + 16-byte authentication tag).

---

## 5. Steganography Implementation (Multi-Domain Architecture)

CryptAudio includes an extensible steganography engine architecture (`BaseStegoAlgorithm`) supporting three distinct algorithms:

```
                          BaseStegoAlgorithm (Abstract Base Class)
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
  LsbStegoAlgorithm           DwtDctQimAlgorithm           EchoHidingAlgorithm
  (Time / Spatial Domain)     (Transform Domain)           (Cepstral Domain)
```

---

### 5.1 Algorithm 1: Least Significant Bit (LSB) Replacement
- **Domain**: Time / Spatial domain.
- **Mechanism**: Modifies the least significant bit ($2^0$) of individual audio PCM sample values.
- **Embedding Rule**:
  $$\text{Sample}' = (\text{Sample} \ \& \ \sim 1) \ | \ \text{Bit}$$
- **Key Characteristics**:
  - **Highest Capacity**: $\approx 1$ bit per audio sample. A 44.1 kHz, 16-bit stereo track provides $\approx 11.025$ KB/sec of payload capacity.
  - **Exceptional Perceptual Transparency**: SNR typically exceeds $80\text{ dB}$, PSNR $> 90\text{ dB}$, and Pearson correlation $r > 0.999999$.
  - **Fragile**: Highly sensitive to lossy compression (MP3/AAC), resampling, filtering, or amplitude scaling.

---

### 5.2 Algorithm 2: DWT-DCT-QIM (Wavelet + Cosine Quantization Index Modulation)
- **Domain**: Frequency / Transform domain.
- **Mechanism**:
  1. Decomposes the carrier audio waveform using a 1-level Discrete Wavelet Transform (Haar filter bank) into approximation subband ($cA$) and detail subband ($cD$):
     $$cA, cD = \text{DWT}(x, \text{"haar"})$$
  2. Divides the approximation subband $cA$ into blocks of $N = 8$ samples and applies a 1D Discrete Cosine Transform (DCT-II):
     $$C_k = \sum_{n=0}^{N-1} cA_n \cos \left[ \frac{\pi}{N} \left(n + \frac{1}{2}\right) k \right]$$
  3. Selects middle-frequency DCT coefficients ($k \in [2, 5]$) and embeds payload bits using **Quantization Index Modulation (QIM)** with step size $\Delta \in \{8.0, 16.0, 32.0, 64.0\}$:
     $$C'_k = \text{round}\left(\frac{C_k - d_i}{\Delta}\right) \cdot \Delta + d_i, \quad d_i = \begin{cases} -\Delta/4 & \text{if bit } = 0 \\ +\Delta/4 & \text{if bit } = 1 \end{cases}$$
  4. Reconstructs the modified audio by applying Inverse DCT (IDCT) followed by Inverse DWT (IDWT):
     $$cA' = \text{IDCT}(C'), \quad x' = \text{IDWT}(cA', cD)$$
- **Key Characteristics**:
  - **Robustness**: High resilience against mild additive noise, low-pass filtering, and amplitude scaling.
  - **Tradeoff**: Lower throughput than LSB (requires 8 to 16 samples per embedded bit).

---

### 5.3 Algorithm 3: Echo Hiding (Cepstral / Time-Delay Modulation)
- **Domain**: Time-delay / Cepstral domain.
- **Mechanism**:
  1. Introduces imperceptible artificial sub-echoes into audio frames ($N = 2048$ samples).
  2. Encodes binary bits using distinct delay intervals:
     - **Bit 0**: Delay $d_0 = 44\text{ samples}$ ($\approx 0.998\text{ ms}$ at 44.1 kHz)
     - **Bit 1**: Delay $d_1 = 57\text{ samples}$ ($\approx 1.293\text{ ms}$ at 44.1 kHz)
  3. Employs a **bipolar sub-echo kernel** to prevent audible comb-filtering coloration:
     $$x_{stego}(n) = x(n) + \alpha \cdot x(n - d_i) - \alpha \cdot x(n - d_i - \Delta_{sub})$$
     where $\alpha$ is the echo amplitude ($0.001 \le \alpha \le 0.50$, default $0.08$).
  4. **Preamble Synchronization**: Embeds a 16-bit pseudo-random synchronization sequence (`0xB42B`) prior to the payload envelope to ensure exact frame alignment on extraction.
  5. **Cepstral Decoding**: Extraction is performed using **Real Cepstrum Analysis**:
     $$c(n) = \mathcal{F}^{-1}\left\{ \ln |\mathcal{F}\{x(n)\}| \right\}$$
     The receiver inspects the cepstral peak magnitude at lag $d_0$ vs $d_1$:
     $$\text{Decoded Bit} = \begin{cases} 0 & \text{if } c(d_0) > c(d_1) \\ 1 & \text{if } c(d_1) \ge c(d_0) \end{cases}$$
- **Key Characteristics**:
  - **Acoustic Inaudibility**: Exploits the temporal psychoacoustic masking threshold of human hearing (echoes $< 2\text{ ms}$ are integrated by the auditory system as natural reverberation).
  - **Requires Broadband Carrier**: Requires continuous harmonic or wideband audio content (avoiding long digital silences or pure sinusoidal tones).

---

## 6. Envelope Protocols & Framing Specification

To decouple steganography from cryptography and enable multi-algorithm interoperability, CryptAudio supports the universal **CSMA v1 Envelope** alongside legacy **CSLB** framing.

### 6.1 Universal CSMA v1 Framing Envelope (18 Bytes Header)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Sync Word (0xF9A9)      |      Magic: b"CSMA" (Part 1)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic: b"CSMA" (Part 2)   | Algo ID (1B)  | Version (0x01)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Algorithm Flags (2B)     |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      (Payload Length cont.)   |         CRC32 Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     (CRC32 Checksum cont.)    |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
|        Raw Cryptographic Payload (CAUD Header + Ciphertext)   |
|                                                               |
```

| Field Name | Byte Offset | Size | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Sync Word** | 0 | 2 Bytes | `uint16_be` | Framing synchronizer (`0xF9A9`). Detects bit slips. |
| **Magic Identifier** | 2 | 4 Bytes | `bytes[4]` | Static ASCII string `b"CSMA"`. |
| **Algorithm ID** | 6 | 1 Byte | `uint8` | `0x01` = LSB, `0x02` = DWT-DCT-QIM, `0x03` = ECHO. |
| **Format Version** | 7 | 1 Byte | `uint8` | `0x01` (Version 1). |
| **Algorithm Flags** | 8 | 2 Bytes | `uint16_be` | Bit-packed parameters ($\Delta$ index or $\alpha \times 1000$). |
| **Payload Length ($N$)**| 10 | 4 Bytes | `uint32_be` | Total byte length of following cryptographic payload. |
| **CRC32 Checksum** | 14 | 4 Bytes | `uint32_be` | Transmission integrity checksum across the $N$ payload bytes. |
| **Payload Data** | 18 | $N$ Bytes| `bytes[N]` | Complete binary cryptographic `CAUD` packet. |

### 6.2 CRC32 vs. AES-GCM Security Distinction
CryptAudio strictly distinguishes transmission integrity from cryptographic authenticity:
- **CRC32 Checksum**: Non-cryptographic checksum. It detects accidental synchronization loss, truncated bitstreams, or random transmission corruption. It does **not** protect against deliberate tampering.
- **AES-GCM Tag**: Cryptographic message authentication code (MAC). It mathematically guarantees that the ciphertext and AAD have not been forged, tampered with, or modified by an active adversary.

---

## 7. REST API Route Reference

The backend exposes a clean, strongly typed REST API documented via OpenAPI / Swagger at `/docs`:

```
+---------------------------------------------------------------------------------------------+
| METHOD | ROUTE              | DESCRIPTION                                                   |
+---------------------------------------------------------------------------------------------+
| POST   | /api/v1/embed      | Encrypts plaintext and embeds into carrier WAV file.         |
| POST   | /api/v1/extract    | Extracts and decrypts hidden payload from stego WAV file.     |
| POST   | /api/v1/capacity   | Calculates authoritative capacity for message & parameters.  |
| POST   | /api/v1/inspect    | Analyzes carrier WAV audio properties & available capacity.   |
| POST   | /api/v1/analyze    | Computes distortion metrics between original and stego WAV.   |
| GET    | /api/v1/algorithms | Discovers registered algorithms and parameter configurations.|
| GET    | /api/v1/health     | Returns service status and application metadata.              |
| GET    | /                  | Serves the Single-Page Application (SPA) HTML interface.     |
+---------------------------------------------------------------------------------------------+
```

### 7.1 `POST /api/v1/embed`
- **Request**: `multipart/form-data`
  - `audio_file`: Binary PCM WAV carrier file (Max 50 MB).
  - `secret_message`: UTF-8 string plaintext to conceal.
  - `passphrase`: Secret passphrase used for PBKDF2 key derivation.
  - `algorithm`: Optional (`"lsb"`, `"dwt_dct_qim"`, `"echo"`). Default: `"lsb"`.
  - `delta`: Optional float for DWT-DCT-QIM (`8.0`, `16.0`, `32.0`, `64.0`).
  - `alpha`: Optional float for Echo Hiding (`0.001` to `0.50`).
- **Response**: Binary WAV audio stream (`audio/wav`) with custom response headers:
  - `X-Stego-Algorithm`: Active algorithm ID.
  - `X-Stego-Payload-Bytes`: Total embedded payload byte length.
  - `X-Stego-Samples-Modified`: Count of modified audio samples.

### 7.2 `POST /api/v1/extract`
- **Request**: `multipart/form-data`
  - `stego_file`: Binary stego WAV file.
  - `passphrase`: Passphrase required to decrypt payload.
  - `algorithm`: Optional (`"auto"`, `"lsb"`, `"dwt_dct_qim"`, `"echo"`). Default: `"auto"`.
- **Response**: `application/json`
  ```json
  {
    "status": "success",
    "message": "Top Secret Plaintext Message",
    "algorithm": "lsb",
    "framing_verified": true,
    "authenticated": true
  }
  ```

### 7.3 `POST /api/v1/analyze`
- **Request**: `multipart/form-data` with `original_file` and `stego_file`.
- **Response**: `application/json` containing signal-quality distortion metrics:
  ```json
  {
    "status": "success",
    "metrics": {
      "mse": 0.000012,
      "snr_db": 84.21,
      "psnr_db": 96.34,
      "pearson_correlation": 0.9999998,
      "samples_evaluated": 529200
    }
  }
  ```

---

## 8. Audio Quality & Forensic Evaluation Metrics

To evaluate steganographic distortion and perceptual transparency, CryptAudio implements four mathematical metrics in `app/evaluation/metrics.py`:

### 8.1 Mean Squared Error (MSE)
Quantifies the average squared amplitude difference between original sample $x_i$ and stego sample $y_i$:
$$\text{MSE} = \frac{1}{N} \sum_{i=1}^{N} (x_i - y_i)^2$$

### 8.2 Signal-to-Noise Ratio (SNR)
Measures the ratio of original audio signal power to the introduced steganographic noise power (in decibels):
$$\text{SNR (dB)} = 10 \cdot \log_{10} \left( \frac{\sum_{i=1}^{N} x_i^2}{\sum_{i=1}^{N} (x_i - y_i)^2 + \epsilon} \right)$$

### 8.3 Peak Signal-to-Noise Ratio (PSNR)
Evaluates distortion relative to the maximum possible sample amplitude $MAX_I$ (e.g., $32,767$ for 16-bit audio):
$$\text{PSNR (dB)} = 10 \cdot \log_{10} \left( \frac{MAX_I^2}{\text{MSE} + \epsilon} \right)$$

### 8.4 Pearson Correlation Coefficient ($r$)
Measures the linear waveform fidelity between original and stego signals ($1.0$ represents identical waveforms):
$$r = \frac{\sum_{i=1}^N (x_i - \bar{x})(y_i - \bar{y})}{\sqrt{\sum_{i=1}^N (x_i - \bar{x})^2} \sqrt{\sum_{i=1}^N (y_i - \bar{y})^2}}$$

---

## 9. Frontend Architecture & Defensive Controls

The frontend interface (`frontend/`) is engineered with defensive architectural patterns:

```
+--------------------------------------------------------------------------------------------------+
| FRONTEND DEFENSIVE STATE MACHINE                                                                |
|                                                                                                  |
|  [File Drop / Message Input]                                                                     |
|          |                                                                                       |
|          v                                                                                       |
|  [Generate Fingerprint] ---> {File Name, File Size, Message Bytes, Algorithm, Delta, Alpha}     |
|          |                                                                                       |
|          v                                                                                       |
|  [Increment Sequence ID] --> sequenceId = ++_currentSequenceId                                   |
|          |                                                                                       |
|          v                                                                                       |
|  [Async Authoritative Capacity API]                                                              |
|          |                                                                                       |
|          v                                                                                       |
|  [Check Sequence Lock] ----> If response.sequenceId < _currentSequenceId: DISCARD (Stale)       |
|          |                                                                                       |
|          v                                                                                       |
|  [Validate Fingerprint] ---> If response.fingerprint != currentFingerprint: DISCARD (Stale)     |
|          |                                                                                       |
|          v                                                                                       |
|  [Safe DOM Binding] -------> Bind text via el.textContent (Zero innerHTML XSS injection vectors) |
+--------------------------------------------------------------------------------------------------+
```

1. **Race Condition Prevention**: Prevents fast typing or rapid file swapping from allowing an older, slower capacity response from overriding a newer calculation.
2. **Authoritative Capacity Enforcement**: The UI never estimates payload capacity locally; it calls `POST /api/v1/capacity` to enforce authoritative backend capacity rules.
3. **Multilingual Byte Counting**: Accurately counts UTF-8 byte lengths for multilingual text (e.g. Gujarati, Hindi, Cyrillic, Japanese, and Emojis) where 1 character spans up to 4 bytes.
4. **XSS Protection**: All user plaintexts, filenames, and server error messages are rendered via standard DOM text properties (`textContent`), strictly avoiding raw HTML string interpolation.

---

## 10. Threat Modeling & Security Boundaries

CryptAudio maintains clear threat boundaries regarding what steganography and cryptography can and cannot guarantee:

| Security Domain | What CryptAudio Web Guarantees | Academic Limitations & Non-Goals |
| :--- | :--- | :--- |
| **Confidentiality** | AES-256-GCM guarantees no adversary can read message content without the passphrase. | Weak passphrases remain vulnerable to offline brute-force attacks if captured. |
| **Authenticity** | 128-bit GCM authentication tag guarantees tamper detection on all encrypted payloads. | Does not prevent an adversary from completely overwriting or deleting carrier audio. |
| **Transmission Integrity** | CRC32 detects accidental bit slips, framing truncation, and random transmission corruption. | CRC32 is not a cryptographic signature and can be forged if the ciphertext is replaced. |
| **Steganographic Secrecy** | Conceals payload bits within audio waveforms with minimal perceptual distortion (SNR $> 80\text{ dB}$). | Not mathematically undetectable against advanced higher-order statistical steganalysis. |
| **Channel Robustness** | DWT-DCT-QIM and Echo Hiding resist mild additive noise and filtering. | Lossy recompression (MP3, AAC, OGG) destroys high-frequency LSB and transform coefficients. |

---

## 11. Testing & Verification Guide

The codebase includes an exhaustive test suite of **718+ automated tests**:

```bash
# 1. Run complete Pytest suite
pytest -v

# 2. Run Playwright end-to-end browser integration tests
pytest -v tests/test_m8_browser_playwright.py

# 3. Run Node.js frontend state machine tests
node tests/test_frontend_logic.js

# 4. Execute quick multi-algorithm benchmark
python scripts/run_algorithm_benchmark.py --quick

# 5. Build clean, verified distribution ZIP
python scripts/package_release.py
```

---

## 12. Summary of Repository Structure

```
CryptAudio-Web/
├── app/                            # FastAPI backend application package
│   ├── api/routes.py               # REST API endpoints & exception mapping
│   ├── audio/wav_handler.py        # PCM WAV validation, headers & parsing
│   ├── core/config.py              # Application settings & constants
│   ├── crypto/aes_crypto.py        # AES-256-GCM & PBKDF2-HMAC-SHA256 engine
│   ├── evaluation/metrics.py       # Signal distortion metrics (MSE, SNR, PSNR)
│   ├── services/cryptaudio_service.py # Core business logic orchestration
│   └── steganography/              # Multi-algorithm steganography framework
│       ├── base.py                 # Abstract BaseStegoAlgorithm definition
│       ├── envelope.py             # CSMA v1 49-byte framing & CSLB legacy parser
│       ├── registry.py             # Central algorithm discovery & factory
│       ├── lsb_adapter.py          # Spatial Least Significant Bit adapter
│       ├── dwt_dct_qim.py          # Discrete Wavelet & Cosine QIM engine
│       └── echo_hiding.py          # Bipolar sub-echo cepstral engine
├── frontend/                       # Browser Single-Page Application (SPA)
│   ├── index.html                  # Responsive modern HTML5 interface
│   ├── css/                        # CSS styles & theme variables
│   │   ├── styles.css              # Main component & layout stylesheets
│   │   └── variables.css           # Color tokens & dark/light mode themes
│   └── js/                         # Zero-dependency vanilla ES6 scripts
│       ├── api.js                  # Typed API client & input validation
│       ├── app.js                  # State machine, navigation & UI binding
│       └── theme.js                # Instant pre-render theme manager
├── scripts/                        # Operational & release tooling
│   ├── package_release.py          # Secure distributable packaging script
│   └── run_algorithm_benchmark.py  # Automated performance & distortion benchmark
├── tests/                          # 718+ Automated test cases
│   ├── test_api.py                 # API contract tests
│   ├── test_crypto.py              # Cryptographic security & PBKDF2 tests
│   ├── test_steganography.py       # LSB embedding & framing unit tests
│   ├── test_dwt_dct_qim.py         # DWT-DCT-QIM transform domain tests
│   ├── test_echo_hiding.py         # Echo Hiding cepstral tests
│   ├── test_m8_browser_playwright.py # Headless browser E2E tests
│   └── test_frontend_logic.js      # Frontend state-machine unit tests
├── requirements.txt                # Pinned production Python dependencies
└── PROJECT_DOCUMENTATION.md        # Comprehensive technical documentation
```
