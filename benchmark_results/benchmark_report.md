# CryptAudio-Web: Comparative Steganography Algorithm Benchmark & Evaluation

> **Report Generated:** `2026-11-19T12:48:51.713796+00:00`  
> **Evaluator:** Automated CryptAudio Benchmark Engine (Phase M7.2)  

## 1. Executive Summary

This evaluation report presents an empirical, scientific benchmark comparing the three audio steganography algorithms implemented in **CryptAudio-Web**: Least Significant Bit (**LSB**), Discrete Wavelet Transform + Discrete Cosine Transform + Quantization Index Modulation (**DWT-DCT-QIM**), and **Echo Hiding**.
Each algorithm was evaluated in conjunction with the application's mandatory cryptographic layer (**AES-256-GCM** with **PBKDF2-HMAC-SHA256** at 600,000 iterations) and the universal **CSMA v1 Binary Envelope** framing protocol.

### Key Empirical Observations from This Benchmark Run:

1. **Evaluated Configurations:** A total of 8 configurations were executed across algorithms: `dwt_dct_qim`, `echo`, `lsb`. Among these, 7 completed embedding with status `SUCCESS`, and 1 recorded status `CAPACITY_INSUFFICIENT`.
2. **Capacity Hierarchy:** `dwt_dct_qim` provides 2,842 B (22,736 bits) raw capacity on a 33.0s carrier; `echo` provides 88 B (710 bits) raw capacity on a 33.0s carrier; `lsb` provides 181,912 B (1,455,300 bits) raw capacity on a 33.0s carrier.
3. **Cryptographic Integrity & Authenticated Extraction:** Of 7 successfully embedded configuration(s), 7 configuration(s) had accuracy records available. Among evaluated metrics: exact plaintext recovery was achieved in 7/7 (100.0%) evaluated configurations; AES-256-GCM authentication was verified in 7/7 (100.0%) evaluated configurations. Independent integrity experiments (wrong password, sync corruption, CRC32 checksum corruption, ciphertext tampering) were evaluated on configurations with available accuracy metrics.

## 2. Experimental Methodology

All measurements were conducted programmatically using the live CryptAudio backend engine (`app.services.cryptaudio_service` and `app.evaluation.audio_quality`). No theoretical or hardcoded estimates were used.

### 2.1 Test Carrier Synthesis
- **Carrier Signal:** `short_carrier_1s` (Audio Carrier), `standard_chirp_33s` (Synthetic Chirp).
- **Carrier Format:** 44,100 Hz, 1-channel (Mono). Sample format / bit depth metadata unavailable in this result schema.
- **Primary Carrier Duration:** 33.0 seconds (1,455,300 audio samples).
- **Secondary / Boundary Carrier Durations:** 1.0s (44,100 samples).

### 2.2 Payload Structure & Framing Overhead
- **Cryptographic Layer (AES-256-GCM):** 33-byte fixed header (Magic 4B + Version 1B + Salt 16B + Nonce 12B) + ciphertext + 16-byte GHASH tag.
  - Minimum AES-GCM crypto overhead: **49 bytes**.
- **Framing Envelope (CSMA v1):** 18-byte universal framing header (Sync 2B + Magic 4B + Algo 1B + Ver 1B + Flags 2B + Len 4B + CRC32 4B) = **144 bits**.
  - Minimum valid framed encrypted payload (empty message): $18 + 49 = 67$ bytes (**536 bits**).
  - Evaluated payload required bitstream: **616 bits**.

### 2.3 Evaluation Metric Definitions
- **Mean Squared Error (MSE):** $\text{MSE} = \frac{1}{N} \sum_{i=1}^N (x_i - y_i)^2$
- **Signal-to-Noise Ratio (SNR):** $\text{SNR}_{\text{dB}} = 10 \log_{10} \left( \frac{\sum x_i^2}{\sum (x_i - y_i)^2} \right)$
- **Peak Signal-to-Noise Ratio (PSNR):** $\text{PSNR}_{\text{dB}} = 10 \log_{10} \left( \frac{MAX^2}{\text{MSE}} \right)$. The peak amplitude $MAX$ is determined by the audio-quality evaluation engine based on sample width ($MAX = 127$ for 8-bit, $MAX = 32767$ for 16-bit, $MAX = 8388607$ for 24-bit, $MAX = 2147483647$ for 32-bit PCM); the current run's sample width is not recorded in the report schema.
- **Pearson Correlation Coefficient:** $r = \frac{\sum (x_i - \bar{x})(y_i - \bar{y})}{\sqrt{\sum(x_i - \bar{x})^2 \sum(y_i - \bar{y})^2}}$
- **Traced Memory:** Measured via Python `tracemalloc` peak heap allocation of Python objects during embedding. Note: this tracks Python-allocated heap objects and does not measure complete OS process RSS or native external C-extension memory.
- **Execution Latency:** Measured using `time.perf_counter()` over configured trials, reporting mean and standard deviation.

## 3. Test Environment

| Parameter | Configuration / Specification |
| :--- | :--- |
| **Operating System** | `Windows-11-10.0.26300-SP0` |
| **Python Runtime** | `3.13.17` |
| **CPU Architecture** | `AMD64 Family 23 Model 104 Stepping 1, AuthenticAMD (12 cores)` |
| **NumPy Version** | `2.5.5` |
| **PyWavelets Version** | `1.8.0` |
| **FFmpeg Binary** | `Not installed` |
| **LAME Binary** | `Not installed` |
| **Evaluation Timestamp (UTC)** | `2026-11-19T12:48:42.323236+00:00` |

## 4. Algorithm Configurations

The algorithms evaluated in this benchmark run were configured as follows:

1. **LSB (Least Significant Bit):**
   - Carrier embedding: Sample-domain replacement of the least significant bit ($b_0$) in Channel 0.
   - Framing: Universal CSMA v1 envelope (18 bytes overhead).
   - Operating parameters: Default (1 bit per sample).

2. **DWT-DCT-QIM (Discrete Wavelet + DCT + Quantization Index Modulation):**
   - Wavelet transform: 3-level discrete wavelet decomposition using Daubechies 4 (`db4`, `WAVELET_NAME = 'db4'`).
   - Embedding target: Block DCT over detail sub-band `cD3` (`DECOMPOSITION_LEVEL = 3`).
   - Chunk size: 1024 audio samples per chunk. Each chunk embeds 16 bits across 16 DCT blocks.
   - Supported quantization step sizes: $\Delta \in \{8, 16, 32, 64\}$. Native default: $\Delta = 32$.
   - Tested quantization steps in this run: $\Delta \in {16, 32, 64}$.

3. **Echo Hiding:**
   - Kernel delays: $d_0 = 44$ samples (bit 0), $d_1 = 57$ samples (bit 1) at 44.1 kHz.
   - Segment size: 2048 audio samples per bit ($21.53\text{ bps}$).
   - Supported attenuation factors: positive float $< 1.0$ (typical $0.05 - 0.20$). Native default: $\alpha = 0.08$.
   - Tested attenuation factors in this run: $\alpha \in {0.08, 0.12, 0.15}$.

## 5. Capacity Comparison

| Algorithm | Parameters | Carrier Duration | Raw Capacity (bits) | Raw Capacity (bytes) | Usable Payload (bytes) | Max Plaintext Message | Utilization % |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lsb` | `default` | 33.0s | 1,455,300 bits | 181,912 B | 181,894 B | 181,845 B | 0.042% |
| `dwt_dct_qim` | `delta=32` | 33.0s | 22,736 bits | 2,842 B | 2,824 B | 2,775 B | 2.709% |
| `echo` | `alpha=0.08` | 33.0s | 710 bits | 88 B | 70 B | 21 B | 86.761% |
| `dwt_dct_qim` | `delta=16` | 33.0s | 22,736 bits | 2,842 B | 2,824 B | 2,775 B | 2.709% |
| `dwt_dct_qim` | `delta=64` | 33.0s | 22,736 bits | 2,842 B | 2,824 B | 2,775 B | 2.709% |
| `echo` | `alpha=0.12` | 33.0s | 710 bits | 88 B | 70 B | 21 B | 86.761% |
| `echo` | `alpha=0.15` | 33.0s | 710 bits | 88 B | 70 B | 21 B | 86.761% |
| `echo` | `alpha=0.08` | 1.0s | 21 bits | 2 B | 0 B | 0 B | 2933.333% |

### Capacity Observations:
- **LSB Capacity:** On the 33.0s carrier (1,455,300 samples), LSB yielded 1,455,300 raw bits (181,912 bytes), usable payload of 181,894 bytes, and max plaintext message of 181,845 bytes (utilization: 0.042%).
- **DWT-DCT-QIM Capacity:** On the 33.0s carrier (1,455,300 samples), DWT-DCT-QIM yielded 22,736 raw bits (2,842 bytes), usable payload of 2,824 bytes, and max plaintext message of 2,775 bytes (utilization: 2.709%).
- **Echo Hiding Capacity:** On the 33.0s carrier (1,455,300 samples), Echo Hiding yielded 710 raw bits (88 bytes), usable payload of 70 bytes, and max plaintext message of 21 bytes (utilization: 86.761%).
- **Capacity Boundary Enforcement:** Evaluated configurations on insufficient carrier lengths (`echo` (1.0s carrier)) recorded `CAPACITY_INSUFFICIENT`, verifying that embeddings are prevented when raw capacity falls below the 536-bit minimum framing requirement.

## 6. Audio Quality Comparison

Numerical distortion metrics computed by `app.evaluation.audio_quality` (comparing original carrier vs. stego audio):

| Algorithm | Parameters | MSE | SNR (dB) | PSNR (dB) | Correlation | Modified Samples | Modified % | Quality Rating |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lsb` | `default` | 0.000216 | 122.53 dB | 126.96 dB | 1.000000 | 315 | 0.02% | **Excellent** |
| `dwt_dct_qim` | `delta=32` | 0.039531 | 99.91 dB | 104.34 dB | 1.000000 | 23,768 | 1.63% | **Excellent** |
| `echo` | `alpha=0.08` | 2141560.231485 | 22.57 dB | 27.00 dB | 0.997237 | 1,260,583 | 86.62% | **Moderate** |
| `dwt_dct_qim` | `delta=16` | 0.010460 | 105.69 dB | 110.11 dB | 1.000000 | 13,611 | 0.94% | **Excellent** |
| `dwt_dct_qim` | `delta=64` | 0.147463 | 94.19 dB | 98.62 dB | 1.000000 | 30,024 | 2.06% | **Excellent** |
| `echo` | `alpha=0.12` | 4818735.130118 | 19.05 dB | 23.48 dB | 0.993801 | 1,260,579 | 86.62% | **Moderate** |
| `echo` | `alpha=0.15` | 7528445.261168 | 17.11 dB | 21.54 dB | 0.990349 | 1,260,589 | 86.62% | **Moderate** |
| `echo` | `alpha=0.08` | N/A | N/A | N/A | N/A | N/A | N/A | `CAPACITY_INSUFFICIENT` |

### Quality Observations:
- **LSB Quality:** Measured PSNR: 126.96 dB, SNR: 122.53 dB, modifying 0.02% of samples.
- **DWT-DCT-QIM Quality:** Measured PSNR: 98.62 dB to 110.11 dB, SNR: 94.19 dB to 105.69 dB, modifying 0.94% to 2.06% of samples.
- **Echo Hiding Quality:** Measured PSNR: 21.54 dB to 27.00 dB, SNR: 17.11 dB to 22.57 dB, modifying 86.62% to 86.62% of samples.
- *Note on Quality Ratings:* Quality ratings ('Excellent', 'Good', 'Moderate', 'Poor') represent mathematical classifications based on PSNR thresholds (> 45 dB = Excellent, > 35 dB = Good, > 25 dB = Moderate), not formal subjective listening evaluations.

## 7. Processing Performance Comparison

| Algorithm | Parameters | Embed Mean (s) | Embed Std (s) | Extract Mean (s) | Extract Std (s) | Total Pipeline Mean (s) | Peak Traced Memory (MB) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lsb` | `default` | 0.1385 s | 0.0000 s | 0.1145 s | 0.0000 s | 0.2530 s | 8.34 MB |
| `dwt_dct_qim` | `delta=32` | 0.1773 s | 0.0000 s | 0.1286 s | 0.0000 s | 0.3059 s | 47.22 MB |
| `echo` | `alpha=0.08` | 0.2014 s | 0.0000 s | 0.1756 s | 0.0000 s | 0.3770 s | 47.27 MB |
| `dwt_dct_qim` | `delta=16` | 0.1622 s | 0.0000 s | 0.1318 s | 0.0000 s | 0.2939 s | 47.22 MB |
| `dwt_dct_qim` | `delta=64` | 0.1621 s | 0.0000 s | 0.1139 s | 0.0000 s | 0.2759 s | 47.22 MB |
| `echo` | `alpha=0.12` | 0.1980 s | 0.0000 s | 0.1561 s | 0.0000 s | 0.3541 s | 47.27 MB |
| `echo` | `alpha=0.15` | 0.1927 s | 0.0000 s | 0.1564 s | 0.0000 s | 0.3491 s | 47.27 MB |
| `echo` | `alpha=0.08` | N/A | N/A | N/A | N/A | N/A | N/A |

### Performance Observations:
- **Pipeline Latency:** Measured total pipeline latency ranged from 0.2530s to 0.3770s across evaluated configurations (`dwt_dct_qim` mean total: 0.2919s; `echo` mean total: 0.3601s; `lsb` mean total: 0.2530s).
- **Memory Measurement:** Peak traced memory was tracked via Python `tracemalloc`. This metric reflects peak allocations of Python objects during execution and does not represent full operating system resident set size (RSS).

## 8. Extraction Accuracy & Independent Integrity Experiments

Integrity evaluations were conducted on 7 of 8 evaluated configuration(s) (1 configuration(s) lacked accuracy data or were capacity-insufficient). Configurations with status `CAPACITY_INSUFFICIENT` did not produce stego audio and therefore did not undergo integrity testing.

Experimental outcomes across evaluated configurations:
- **Wrong Password Rejection:** 7/7 (100.0%) evaluated configurations passed.
- **Sync Corruption Rejection:** 7/7 (100.0%) evaluated configurations passed.
- **Checksum Corruption Rejection:** 7/7 (100.0%) evaluated configurations passed.
- **Ciphertext Tampering Rejection:** 7/7 (100.0%) evaluated configurations passed.

| Algorithm | Parameters | Extraction Success | Exact Match | Algo Match | Auth Verified | Wrong Pwd Rejected | Sync Corrupt Rejected | Checksum Corrupt Rejected | Ciphertext Tamper Rejected |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lsb` | `default` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `dwt_dct_qim` | `delta=32` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `echo` | `alpha=0.08` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `dwt_dct_qim` | `delta=16` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `dwt_dct_qim` | `delta=64` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `echo` | `alpha=0.12` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `echo` | `alpha=0.15` | PASS | 100% | MATCH | VERIFIED | REJECTED | REJECTED | REJECTED | REJECTED |
| `echo` | `alpha=0.08` | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |

### Integrity & Authentication Observations:
- **Exact Match Fidelity:** 100.0% (7/7) of evaluated configurations with exact-match data yielded bit-for-bit identical recovered plaintexts.
- **Cryptographic Tamper Evidence:** In 7/7 (100.0%) of evaluated configurations with tampered ciphertext and valid framing, AES-256-GCM authentication failed and was rejected.
- **Checksum Separation:** In 7/7 (100.0%) of evaluated configurations with corrupted payload bits, the framing layer rejected extraction via CRC32 mismatch independently of cryptographic decryption.

## 9. Robustness Evaluation Across Controlled Channel Transformations

Robustness evaluations were recorded for 7 of 8 configuration(s) (1 configuration(s) had no robustness records). Across all recorded records, 28 transformation test(s) were actively evaluated, and 7 record(s) were classified as `NOT TESTED` due to unavailable external dependencies. Missing records or `NOT TESTED` outcomes reflect environment constraints or unperformed evaluations and are not interpreted as failures.

| Algorithm | Parameters | Unmodified | Gaussian Noise ($\sigma=1.0$) | Amplitude Scaling (0.95x) | Resampling (44k $\to$ 22k $\to$ 44k) | Lossy Compression |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `lsb` | `default` | SURVIVED | SYNC_FAILED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| `dwt_dct_qim` | `delta=32` | SURVIVED | SURVIVED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| `echo` | `alpha=0.08` | SURVIVED | SURVIVED | SURVIVED | SYNC_FAILED | NOT TESTED |
| `dwt_dct_qim` | `delta=16` | SURVIVED | SURVIVED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| `dwt_dct_qim` | `delta=64` | SURVIVED | SURVIVED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| `echo` | `alpha=0.12` | SURVIVED | SURVIVED | SURVIVED | SYNC_FAILED | NOT TESTED |
| `echo` | `alpha=0.15` | SURVIVED | SURVIVED | SURVIVED | SYNC_FAILED | NOT TESTED |
| `echo` | `alpha=0.08` | N/A | N/A | N/A | N/A | N/A |

### Robustness Observations & Failure Modes:
1. **LSB Resilience:** Evaluated outcomes: Gaussian Noise -> `SYNC_FAILED`, Amplitude Scaling -> `SYNC_FAILED`, Resampling -> `SYNC_FAILED`.
2. **DWT-DCT-QIM Resilience:** Evaluated configurations: delta=32 (Noise: `SURVIVED`, Scale: `SYNC_FAILED`, Resample: `SYNC_FAILED`); delta=16 (Noise: `SURVIVED`, Scale: `SYNC_FAILED`, Resample: `SYNC_FAILED`); delta=64 (Noise: `SURVIVED`, Scale: `SYNC_FAILED`, Resample: `SYNC_FAILED`).
3. **Echo Hiding Resilience:** Evaluated configurations: alpha=0.08 (Noise: `SURVIVED`, Scale: `SURVIVED`, Resample: `SYNC_FAILED`); alpha=0.12 (Noise: `SURVIVED`, Scale: `SURVIVED`, Resample: `SYNC_FAILED`); alpha=0.15 (Noise: `SURVIVED`, Scale: `SURVIVED`, Resample: `SYNC_FAILED`).
4. **Lossy Compression Status:** Because external encoding tools (FFmpeg / LAME) were not available on this host environment, lossy compression was marked `NOT TESTED` (this is not equivalent to failure).

## 10. Limitations of the Benchmark

1. **Test Carrier Scope:** Evaluations were performed using `short_carrier_1s` (Audio Carrier), `standard_chirp_33s` (Synthetic Chirp). Real-world audio carriers (speech, orchestral music, field recordings) present distinct spectral profiles that may influence masking and SNR.
2. **Resampling Simulation Scope:** The resampling evaluation is a controlled interpolation simulation (44.1 kHz $\to$ 22.05 kHz $\to$ 44.1 kHz via linear interpolation) and does not represent every commercial anti-aliasing sinc-filter resampling pipeline.
3. **Missing External Codecs:** FFmpeg and LAME were not installed on the system; lossy perceptual compression resilience was marked `NOT TESTED`.
4. **Acoustic Air-Gap:** Acoustic air-gap (speaker-to-microphone transmission) was outside the scope of this file-based benchmark.

## 11. Final Comparative Analysis & Engineering Recommendations

> [!NOTE]
> **Distinction between Architectural Guidance and Measured Findings:**
> The matrix and takeaways below provide architectural engineering guidance derived from cryptographic and > signal-processing characteristics. They do not constitute universal empirical proofs across all audio genres > or arbitrary carrier waveforms. Measured performance on `short_carrier_1s`, `standard_chirp_33s` is recorded in > Sections 5–9 above. Robustness and perceptual transparency in production must be validated against target > audio material (e.g., speech, orchestral, ambient).

### 11.1 Algorithm Selection Matrix

| Operational Criterion | Recommended Algorithm | Recommended Parameters | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **High-Capacity / Large Documents** | **LSB** | Default (`framing='csma'`) | Highest raw bit density (1 bit/sample), low computational complexity. |
| **Audiophile Transparency / Low Distortion** | **LSB** or **DWT-DCT-QIM** | LSB or DWT ($\Delta=16$) | Minimal waveform perturbation; high theoretical PSNR. |
| **Noisy Digital Channels** | **DWT-DCT-QIM** | $\Delta = 32$ or $\Delta = 64$ | Quantization index modulation in detail wavelet subband resists moderate additive perturbations. |
| **Volume Attenuation / Amplitude Scaling** | **Echo Hiding** | $\alpha = 0.08$ | Cepstral ratio peak detection provides theoretical scale invariance. |
| **Short Audio Clips (< 10 seconds)** | **LSB** | Default | High bit density required to accommodate the 536-bit minimum encrypted CSMA envelope. |

### 11.2 Key Engineering Takeaways

1. **LSB is strictly for lossless channels:** Sample-domain LSB replacement cannot withstand noise, amplitude alteration, or lossy re-encoding.
2. **DWT-DCT-QIM noise resilience trade-off:** Higher quantization step $\Delta$ enhances noise tolerance while lower $\Delta$ improves imperceptibility (PSNR).
3. **Echo Hiding carrier duration constraint:** Because Echo Hiding embeds 1 bit per 2,048 samples and the minimum encrypted CSMA envelope is 536 bits, carriers under ~25 seconds lack sufficient capacity.
4. **Carrier Generalization:** Robustness observed under evaluated test carriers does not guarantee identical resilience across all natural acoustic signals.

---
*Report generated automatically by CryptAudio-Web Benchmarking Framework (Phase M7.2).*