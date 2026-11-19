# CryptAudio-Web — Academic Project Report

**A Multi-Algorithm Web-Based Cryptographic Audio Steganography and Distortion Analysis System**

---

## 1. Title Page

- **Project Title**: CryptAudio-Web: Design and Implementation of an Authenticated Multi-Algorithm Cryptographic Audio Steganography System with Numerical Distortion Evaluation
- **Course**: Applied Cryptography (Sem 1)
- **Institution**: National Forensic Sciences University (NFSU)
- **Application Version**: 1.0.0
- **Technology Stack**: Python 3.13, FastAPI, AES-256-GCM, PBKDF2-HMAC-SHA256, PyWavelets, NumPy, Playwright, HTML5, CSS3, Vanilla JavaScript
- **Date**: November 2026

---

## 2. Abstract

In digital communication, privacy requires both confidentiality and covertness. Cryptography scrambles plaintext into unreadable ciphertext, but reveals the existence of confidential communication, attracting adversarial interception. Conversely, steganography embeds secret data into innocuous media (such as audio), but classical steganography lacks cryptographic confidentiality and integrity guarantees if the embedding mechanism is discovered.

This project presents **CryptAudio-Web**, a production-grade, local web-based cryptographic audio steganography system that couples authenticated symmetric encryption with multi-domain audio steganography:
1. **Least Significant Bit (LSB)** — High-capacity spatial/time-domain embedding.
2. **DWT-DCT-QIM** — Transform-domain embedding using discrete wavelet and discrete cosine transform quantization index modulation.
3. **Echo Hiding** — Acoustic psychoacoustic time-domain echo delay encoding with cepstral deconvolution recovery.

CryptAudio-Web implements AES-256-GCM authenticated encryption with keys derived via PBKDF2-HMAC-SHA256 (600,000 iterations). Plaintexts are transformed into authenticated binary streams, framed with the universal **CSMA v1** envelope (with backward-compatible support for legacy CSLB), and embedded into uncompressed PCM WAV audio. The system integrates numerical distortion analysis (MSE, SNR, PSNR, and Pearson Correlation) using NumPy to evaluate signal degradation. The software runs entirely on the local loopback interface (`127.0.0.1:8000`) or cloud containers (Render) with zero external dependencies, safe DOM text binding, and a zero-inline Content Security Policy. The system is validated through **728 executed tests** (711 automated pytest tests across 23 modules, 17 frontend logic tests, and 13 Playwright headless Chrome browser tests) with a **100% pass rate**.

---

## 3. Introduction

Digital steganography is the art and science of hiding secret data within cover media (images, audio, video) such that an unauthorized observer cannot perceive the presence of the hidden message. While image steganography operates on pixel color channels, audio steganography operates on audio sample amplitudes across time or frequency domains.

The Human Auditory System (HAS) is extraordinarily sensitive to frequency and phase distortions across the 20 Hz – 20 kHz range, but has specific psychoacoustic masking thresholds:
- In the **spatial/time domain**, modifying the least significant bit (LSB) of 16-bit or 24-bit PCM samples introduces imperceptible quantization noise on the order of $-96$ dB to $-144$ dB.
- In the **transform domain**, mid-frequency DWT-DCT coefficients can be quantized using Quantization Index Modulation (QIM), providing resilience against small perturbations and noise.
- In the **acoustic domain**, adding low-amplitude artificial echoes ($\alpha < 0.1$) with microsecond delays ($d_0, d_1$) falls beneath the auditory echo perception threshold while remaining detectable via cepstral deconvolution.

CryptAudio-Web leverages these complementary properties to provide an academically rigorous implementation of cryptographic audio steganography with comprehensive key derivation, container validation, anti-tampering verification, and scientific distortion benchmarking.

---

## 4. Problem Statement

Contemporary information security solutions face two opposing vulnerabilities:
1. **Cryptographic Detectability**: Strong encryption algorithms (such as AES-GCM or ChaCha20-Poly1305) provide robust mathematical confidentiality. However, transmitting encrypted binary blobs across communication channels immediately flags the communicating parties, exposing them to targeted traffic analysis, censorship, or cryptanalytic surveillance.
2. **Steganographic Fragility and Insecurity**: Classical steganographic systems often embed unencrypted plaintext or weakly obfuscated strings directly into media samples. If an adversary discovers the embedding protocol or performs statistical steganalysis, the hidden message is revealed in its entirety. Furthermore, classical steganography lacks cryptographic message integrity verification.

There is a clear academic and forensic need for a unified system that integrates authenticated symmetric cryptography with multi-domain audio steganography and objective distortion analysis within a defensible, accessible local and cloud-portable architecture.

---

## 5. Objectives

The primary technical objectives of CryptAudio-Web are:
1. **Cryptographic Confidentiality & Integrity**: Implement AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations), authenticating the entire 33-byte cryptographic header as Additional Authenticated Data (AAD).
2. **Multi-Algorithm Steganographic Concealment**: Implement three complementary steganographic engines:
   - Spatial LSB (1 bit / sample, high capacity).
   - Transform DWT-DCT-QIM (wavelet decomposition, DCT coefficients, quantization step $\Delta$).
   - Acoustic Echo Hiding (bipolar/unipolar delay encoding, cepstral deconvolution).
3. **Universal Envelope Protocol**: Formulate and implement the CSMA v1 framing protocol supporting sync words (`0xF9A9`, `0x596A`), algorithm flags, length encoding, and CRC32 framing integrity.
4. **Container Robustness**: Develop a low-level RIFF/WAVE container validator that validates chunk lengths, enforces integer PCM subformat GUIDs, and rejects IEEE float formats or partial bit depths.
5. **Objective Distortion Assessment**: Construct a vectorized NumPy audio evaluation engine to compute Mean Squared Error (MSE), Signal-to-Noise Ratio (SNR), Peak Signal-to-Noise Ratio (PSNR), and Pearson Correlation ($r$).
6. **Defensive Web Architecture**: Implement a local-first FastAPI backend with chunked streaming upload ceilings (50 MB per file, 100 MB combined), automated temporary file lifecycle unlinking, zero-inline Content Security Policy, and safe DOM rendering.
7. **End-to-End Verification**: Validate system robustness through automated unit testing, end-to-end integration testing, headless Chrome browser automation, security exploitation testing, and performance profiling.

---

## 6. Multi-Algorithm Steganography Architecture

CryptAudio-Web organizes its steganographic engines via an extensible registry pattern (`app/steganography/registry.py`):

```text
                    ┌────────────────────────────┐
                    │    StegoAlgorithm Base     │
                    │   - embed(wav, payload)    │
                    │   - extract(wav)           │
                    │   - estimate_capacity(wav) │
                    └─────────────┬──────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   LSB Engine     │    │   DWT-DCT-QIM    │    │   Echo Hiding    │
│ (Time / Spatial) │    │(Wavelet + DCT)   │    │(Acoustic Cepstrum│
│ 1 bit / sample   │    │ $\Delta \in[16..64]$│ │ $\alpha \in[0.05..0.2]$│
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

### 1. Spatial Least Significant Bit (LSB)
- **Domain**: Spatial time domain.
- **Mechanism**: Modifies bit 0 of 16-bit integer PCM samples sequentially.
- **Overhead & Capacity**: 1 bit per audio sample. Trailing samples remain untouched.
- **PSNR**: Exceeds 85 dB (imperceptible distortion).
- **Complexity**: $O(N)$ real-time execution.

### 2. DWT-DCT-QIM (Discrete Wavelet + DCT Quantization)
- **Domain**: Transform frequency domain.
- **Mechanism**: Decomposes audio using Haar / Daubechies wavelets into approximation and detail coefficients, computes DCT on sub-bands, and embeds payload bits via Quantization Index Modulation:
  $$c' = \left\lfloor \frac{c}{\Delta} \right\rfloor \cdot \Delta + \left( b \cdot \frac{\Delta}{2} \right)$$
- **Capacity**: 1 bit per 16 samples.
- **PSNR**: Exceeds 45 dB.
- **Resilience**: Preserves payload across mild amplitude scaling and Gaussian noise.

### 3. Echo Hiding
- **Domain**: Acoustic time-delay domain.
- **Mechanism**: Divides carrier into segments of 2048 samples and introduces micro-echoes at delay $d_0 = 44$ (bit 0) or $d_1 = 57$ (bit 1) with echo amplitude $\alpha \approx 0.08$:
  $$y[n] = x[n] + \alpha \cdot x[n - d]$$
- **Extraction**: Computes the complex cepstrum of each segment via FFT and inverse FFT:
  $$\hat{y}[n] = \mathcal{F}^{-1} \{\log |\mathcal{F} \{y[n]\}|\}$$
  and detects the peak delay between $d_0$ and $d_1$.
- **Capacity**: 1 bit per 2048 samples.
- **PSNR**: Exceeds 35 dB.
- **Resilience**: Highly robust against linear filtering and acoustic capture.

---

## 7. Universal Payload & Framing Protocol (CSMA v1)

CryptAudio-Web standardizes binary transmission using the **CSMA v1** protocol:

| Offset | Field | Size | Data Type | Value / Purpose |
|---|---|---|---|---|
| 0 | Sync Word | 2 bytes | uint16 (BE) | `0xF9A9` (LSB/DWT) or `0x596A` (Echo) |
| 2 | Magic Identifier | 4 bytes | ASCII | `CSMA` (CryptAudio Stego Multi-Algorithm) |
| 6 | Algorithm ID | 1 byte | uint8 | `0x01` (LSB), `0x02` (DWT-DCT-QIM), `0x03` (Echo) |
| 7 | Format Version | 1 byte | uint8 | `0x01` (Version 1) |
| 8 | Algorithm Flags | 2 bytes | uint16 (BE) | Packed parameters (e.g. delta $\Delta$, alpha $\alpha$) |
| 10 | Payload Length | 4 bytes | uint32 (BE) | Byte length of encrypted payload ($N$) |
| 14 | CRC32 Checksum | 4 bytes | uint32 (BE) | IEEE 802.3 framing checksum |
| 18 | Encrypted Payload | $N$ bytes | Binary | `CAUD` header + AES-GCM ciphertext + tag |

Total protocol overhead: **67 bytes** (18-byte CSMA envelope + 33-byte crypto header + 16-byte GCM tag).

---

## 8. Comparative Benchmarking & Scientific Evaluation (Phase M7)

The comparative benchmarking framework scientifically measured all three algorithms across a standardized audio corpus:

| Evaluation Metric | Spatial LSB | DWT-DCT-QIM ($\Delta=32$) | Echo Hiding ($\alpha=0.08$) |
|---|---|---|---|
| **Raw Bit Capacity** | 44,100 bits/sec | 2,756 bits/sec | 21.5 bits/sec |
| **Plaintext Capacity (30s Audio)**| 165,313 bytes | 10,268 bytes | 13 bytes |
| **Mean PSNR (dB)** | **88.42 dB** | **47.15 dB** | **38.92 dB** |
| **Pearson Correlation ($r$)** | **0.999999** | **0.999850** | **0.998920** |
| **Embedding Speed** | **0.015s** | **0.210s** | **0.650s** |
| **Extraction Speed** | **0.010s** | **0.180s** | **0.580s** |
| **Noise Resilience (AWGN)** | Low | High | Very High |
| **Amplitude Scaling Resilience** | Low | High | High |
| **Tamper Sensitivity** | 100% Detected | 100% Detected | 100% Detected |

---

## 9. Security & Penetration Testing (Phase M8)

The security assessment encompassed automated exploitation scripts and dynamic headless browser penetration testing via Playwright:
1. **Cryptographic Integrity**: AES-256-GCM authentication tags guarantee that any modification to stego audio causes extraction to abort with HTTP 422 (`AUTHENTICATION_FAILED`) without plaintext leakage.
2. **Key Derivation Work Factor**: PBKDF2-HMAC-SHA256 with 600,000 iterations defends against offline dictionary attacks.
3. **Browser Cross-Site Scripting (XSS)**: Validated in live Google Chrome sessions. Payloads containing `<script>`, `<img>`, and `<svg>` attack vectors rendered harmlessly as plain text via DOM `textContent` binding; zero script execution verified in browser context.
4. **Container Exploitation**: Malformed RIFF headers, non-PCM format tags (IEEE Float, A-law, mu-law), and path traversal filenames (`../../etc/passwd`) strictly rejected.
5. **Information Disclosure Prevention**: Error responses return sanitized JSON envelopes without exposing Python tracebacks, internal file system paths, or secret keys.

---

## 10. Test Execution Summary

| Test Domain | Suite / File | Tests | Pass Rate | Status |
|---|---|---|---|---|
| Unit Testing | `test_crypto.py`, `test_audio.py`, `test_steganography.py`, `test_evaluation.py` | 108 | 100% | **PASS** |
| Transform Steganography | `test_dwt_dct_qim.py`, `test_echo_hiding.py`, `test_m2_core_architecture.py` | 148 | 100% | **PASS** |
| Comparative Benchmarking | `test_benchmark.py` | 75 | 100% | **PASS** |
| Service & API Integration | `test_api.py`, `test_api_processing.py`, `test_api_multi_algorithm.py`, `test_service.py` | 175 | 100% | **PASS** |
| Frontend Contracts & UI | `test_frontend_api_integration.py`, `test_frontend_multi_algorithm.py`, `test_ui_refinement.py` | 56 | 100% | **PASS** |
| System & Security | `test_environment.py`, `test_security_hardening.py`, `test_security_verification.py` | 91 | 100% | **PASS** |
| Phase M8 E2E Integration | `test_m8_end_to_end_integration.py` | 15 | 100% | **PASS** |
| Phase M8 Browser Automation | `test_m8_browser_playwright.py` (Headless Chrome) | 13 | 100% | **PASS** |
| Phase M8 Security Validation | `test_m8_security_validation.py` | 22 | 100% | **PASS** |
| Phase M8 Performance & Load | `test_m8_performance_resource.py` | 8 | 100% | **PASS** |
| **Pytest Total** | **23 Test Modules** | **711** | **100%** | **PASS** |
| Frontend Unit Tests | `test_frontend_logic.js` (Node.js) | 17 | 100% | **PASS** |
| **Consolidated Total** | | **728** | **100%** | **PASS** |

---

## 11. Conclusion

CryptAudio-Web successfully achieves its academic and practical objectives by uniting authenticated AES-256-GCM symmetric encryption with multi-algorithm audio steganography across the time, transform, and acoustic domains. By combining 600,000 PBKDF2 iterations, authenticated associated data headers, strict container validation, objective NumPy distortion metrics, full Playwright browser verification, and a defensible local and cloud-portable architecture, the system provides a robust reference implementation for secure, covert digital communications research.

---

## 12. References

1. Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: The Galois/Counter Mode (GCM) and GMAC*. NIST Special Publication 800-38D.
2. Moriarty, K., Kaliski, B., & Rusch, A. (2017). *PKCS #5: Password-Based Cryptography Specification Version 2.1*. RFC 8018, Internet Engineering Task Force.
3. Bender, W., Gruhl, D., Morimoto, N., & Lu, A. (1996). *Techniques for data hiding*. IBM Systems Journal, 35(3.4), pp. 313–336.
4. Chen, B., & Wornell, G. W. (2001). *Quantization index modulation: A class of provably good methods for digital watermarking and information embedding*. IEEE Transactions on Information Theory, 47(4), pp. 1423–1443.
5. Westfeld, A., & Pfitzmann, A. (1999). *Attacks on Steganographic Systems: Breaking the Steganographic Utilities EzStego, Jsteg, Steganos, and S-Tools*. Information Hiding, LNCS 1768, pp. 61–76.
6. Open Web Application Security Project (OWASP). (2023). *Password Storage & Cryptographic Storage Cheat Sheets*. OWASP Foundation.
