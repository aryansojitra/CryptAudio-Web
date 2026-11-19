# CryptAudio-Web — Phase M4 & M4.1: Echo Hiding Steganography Implementation Report

**Document Version**: 1.1  
**Phase**: M4 & M4.1 (Echo Hiding Time-Domain Steganography Implementation & Review Corrections)  
**Status**: Completed and Verified  
**Date**: 2026-11-18  

---

## 1. Executive Summary

Phase **M4 & M4.1** establishes the third steganographic strategy in the CryptAudio-Web multi-algorithm architecture: **Echo Hiding** in the acoustic time domain (`app/steganography/echo_hiding.py`). 

Conforming to the approved M1.6 technical specification and M4.1 review findings:
1. **Unmodulated Original Carrier History Buffer**: Modulated samples never pollute the historical delay buffer; an independent copy `original_seg = np.copy(...)` is preserved prior to segment modulation, and `history = original_seg[-d_max:].copy()` is enforced, eliminating unintended recursive IIR echo feedback.
2. **Strict Algorithm Discrimination in Metadata Inspection**: `inspect_metadata()` strictly checks `algo_id == ALGO_ID_ECHO` (`0x03`) and `magic == CSMA_MAGIC`, preventing LSB and DWT carriers from ever producing false-positive Echo detections.
3. **Pre-Arithmetic Option Validation**: `inspect_metadata()` validates options inside a guarded try/except block before performing header frame boundary arithmetic, eliminating type and arithmetic leakage.
4. **Strict Capacity Option Validation**: `estimate_capacity()` strictly validates `segment_size`, rejecting booleans, non-ints, and invalid sizes with `UnsupportedParameterError` (no silent fallbacks).
5. **Cryptographic Integrity vs Framing Distinction**: Maintained strict separation between CRC32 transmission framing verification and AES-GCM 128-bit GHASH cryptographic authentication.

All 46 test cases in `tests/test_echo_hiding.py` pass, and the full regression test suite (446 tests total) passes with zero regressions across the LSB, DWT-DCT-QIM, and cryptographic engines.

---

## 2. Theoretical Principles & Mathematical Model

### 2.1 Psychoacoustic Principle
Echo Hiding leverages the human auditory system's **precedence effect (Haas effect)** and temporal forward masking. When an acoustic replica of an audio signal occurs within a micro-delay window ($\Delta t < 2.5\text{ ms}$) and at an attenuation level below the temporal masking threshold ($\alpha \le 0.08$ or $-22\text{ dB}$), the human ear perceives the echo as a subtle reverberant coloration or spatial warmth rather than a distinct secondary event.

> [!IMPORTANT]
> **No Guaranteed Inaudibility**:
> Inaudibility is an engineering design objective, not a guaranteed physical constant. Perceptual transparency depends on carrier dynamics, spectral density, and listening conditions, and must be validated through objective audio-quality measurements and subjective listening tests (ITU-R BS.1116).

### 2.2 Mathematical Model
The echo delay filter applied to an audio segment $x_m(n)$ is a finite impulse response (FIR) filter:
$$h_b(n) = \delta(n) + \alpha \cdot \delta(n - d_b)$$

Where:
- $\alpha$: Echo attenuation coefficient (proposed default $\alpha = 0.08$).
- $b \in \{0, 1\}$: The bit to encode.
- $d_b$: The discrete sample delay corresponding to bit $b$.

The modulated output segment is:
$$y_m(n) = x_m(n) + \alpha \cdot x_m(n - d_b)$$

### 2.3 Delay Calculations Across Sampling Rates
Delays are defined continuously in milliseconds and dynamically converted to integer sample delays based on the host audio file's sampling rate $F_s$:
- **Bit 0**: Delay $\delta_0 = 1.0\text{ ms} \implies d_0 = \text{round}\left( \frac{F_s \cdot 1.0}{1000} \right)$
- **Bit 1**: Delay $\delta_1 = 1.3\text{ ms} \implies d_1 = \text{round}\left( \frac{F_s \cdot 1.3}{1000} \right)$

| Sampling Rate ($F_s$) | Bit 0 Delay ($\delta_0 = 1.0\text{ ms}$) | Bit 1 Delay ($\delta_1 = 1.3\text{ ms}$) | Max Delay ($d_{\max}$) |
|:---:|:---:|:---:|:---:|
| **$22,050\text{ Hz}$** | $22\text{ samples}$ | $29\text{ samples}$ | $29\text{ samples}$ |
| **$44,100\text{ Hz}$** | $44\text{ samples}$ | $57\text{ samples}$ | $57\text{ samples}$ |
| **$48,000\text{ Hz}$** | $48\text{ samples}$ | $62\text{ samples}$ | $62\text{ samples}$ |
| **$96,000\text{ Hz}$** | $96\text{ samples}$ | $125\text{ samples}$ | $125\text{ samples}$ |

Delays are never hardcoded as static constants, guaranteeing mathematical consistency across varied sampling rates.

---

## 3. Embedding Procedure

### 3.1 Segment Boundary Handling & Continuous State Memory
When applying $y_m(n) = x_m(n) + \alpha \cdot x(n - d_b)$ across block boundaries, delayed samples for $n < d_b$ require historical audio frames from segment $m-1$.

To eliminate boundary discontinuities:
1. **Continuous History Buffer**: An in-memory buffer stores the trailing $d_{\max} = \max(d_0, d_1)$ samples from the previous segment $m-1$:
   $$x_{\text{delayed}}(n) = \begin{cases} x_{m-1}(L_{\text{seg}} - d_b + n) & \text{if } n < d_b \\ x_m(n - d_b) & \text{if } n \ge d_b \end{cases}$$
2. **First Segment ($m = 0$)**: The history buffer is initialized with zeros (silence).
3. **Smooth Hanning Cross-Fading**: When consecutive segments transition between differing delays ($d_{\text{prev}} \ne d_{\text{curr}}$), phase discontinuity clicks are suppressed by applying a smooth Hanning cross-fade over the initial $N_{\text{fade}} = 200$ samples:
   $$w_{\text{rise}}(n) = 0.5 \left( 1 - \cos\left( \frac{\pi n}{N_{\text{fade}}} \right) \right), \quad w_{\text{fall}}(n) = 1.0 - w_{\text{rise}}(n)$$
   $$y_m(n) = x_m(n) + \alpha \left[ w_{\text{fall}}(n) \cdot x(n - d_{\text{prev}}) + w_{\text{rise}}(n) \cdot x(n - d_{\text{curr}}) \right] \quad (n < N_{\text{fade}})$$
   $$y_m(n) = x_m(n) + \alpha \cdot x(n - d_{\text{curr}}) \quad (n \ge N_{\text{fade}})$$
4. **Channel Policy**: Processing is strictly confined to Channel 0. In stereo files, Channel 1 samples remain bit-for-bit identical to the carrier input.
5. **Exact Duration Preservation**: Trailing samples ($N_{\text{frames}} \bmod L_{\text{seg}}$) are passed through unmodulated. No trailing decay tail is appended, preserving exact file length $\text{len}(y) == \text{len}(x)$.

---

## 4. Cepstral Extraction Algorithm

### 4.1 Real Cepstrum Formulation
The Real Cepstrum of each segment is computed blindly:
$$C_m(n) = \mathcal{F}^{-1} \left\{ \ln \left| \mathcal{F}\{ y_m(n) \} \right| \right\}$$

Where:
- $\mathcal{F}$ and $\mathcal{F}^{-1}$ denote the Discrete Fourier Transform and its inverse (implemented via NumPy's `rfft` and `irfft`).
- A numerical safety floor $\epsilon = 10^{-12}$ prevents non-finite values in silent or low-energy regions:
  $$\ln\left(\max(|\mathcal{F}\{y_m(n)\}|, 10^{-12})\right)$$

### 4.2 Interior Stationary Region Analysis
As derived in M1.6 Section 9.3 item 5, computing the cepstrum over the interior stationary region $[N_{\text{fade}}, L_{\text{seg}}-1]$ isolates the pure delay peak from cross-fade transition artifacts at segment boundaries, maximizing detection accuracy.

### 4.3 Deterministic Bit Decision Rule
$$b^* = \begin{cases} 0 & \text{if } C_m(d_0) > C_m(d_1) \\ 1 & \text{if } C_m(d_1) > C_m(d_0) \\ 0 & \text{if } C_m(d_0) == C_m(d_1) \quad (\text{deterministic tie-break}) \end{cases}$$

---

## 5. Synchronization & CSMA Envelope Integration

### 5.1 Canonical Synchronization Sequence
- **Algorithm ID**: `0x03` (`ALGO_ID_ECHO`)
- **Logical Synchronization Word**: `0x596A` (`b"\x59\x6A"`)
- **Canonical 16-bit Preamble Sequence**:
  $$\mathbf{b}_{\text{echo\_sync}} = [0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0]$$
- **Physical Delay Sequence**:
  $$P_{\text{echo}} = [d_0, d_1, d_0, d_1, d_1, d_0, d_0, d_1, d_0, d_1, d_1, d_0, d_1, d_0, d_1, d_0]$$
- **Bipolar Reference Vector** ($d_0 \to -1.0, d_1 \to +1.0$):
  $$\mathbf{p} = [-1.0, +1.0, -1.0, +1.0, +1.0, -1.0, -1.0, +1.0, -1.0, +1.0, +1.0, -1.0, +1.0, -1.0, +1.0, -1.0]$$

### 5.2 144-Bit Universal CSMA Envelope
Echo Hiding utilizes the standard 18-byte (144-bit) CSMA v1 envelope:
- **Bytes 0..1 (16 bits)**: Synchronization word (`0x596A`), physically embedded across the initial 16 segments.
- **Bytes 2..5 (32 bits)**: Magic identifier `b"CSMA"`.
- **Byte 6 (8 bits)**: Algorithm ID `0x03`.
- **Byte 7 (8 bits)**: Version `0x01`.
- **Bytes 8..9 (16 bits)**: Packed operational flags.
- **Bytes 10..13 (32 bits)**: Payload length $N$ (big-endian uint32).
- **Bytes 14..17 (32 bits)**: CRC32 framing checksum over payload bytes.
- **Bytes 18 onward**: Encrypted payload (`CAUD...`).

Total header budget is exactly 144 segments ($144 \times 2048 = 294,912$ audio frames).

---

## 6. Capacity Derivations & Numerical Examples

### 6.1 Capacity Formulation
For carrier audio with frame count $N_{\text{frames}}$, segment length $L_{\text{seg}} = 2048$ samples, and Channel 0 modulation:
$$C_{\text{raw}} = \left\lfloor \frac{N_{\text{frames}}}{2048} \right\rfloor \quad (\text{bits})$$
$$C_{\text{net\_bytes}} = \max\left( 0, \left\lfloor \frac{C_{\text{raw}} - 144}{8} \right\rfloor \right)$$

$$\text{Throughput} = \frac{F_s}{2048} \approx 21.5332\text{ bits/second} \approx 2.6917\text{ bytes/second (at } 44.1\text{ kHz)}$$

### 6.2 Minimum Carrier Duration for Valid Encrypted Message
The minimum valid CryptAudio payload (`CAUD`) is 49 bytes:
- 4 bytes magic (`CAUD`) + 1 byte version (`0x01`)
- 16 bytes PBKDF2 salt
- 12 bytes AES-GCM nonce
- 16 bytes AES-GCM authentication tag (empty plaintext)

Total required bits to embed a minimal encrypted message:
$$N_{\text{req}} = (18\text{ bytes CSMA header} + 49\text{ bytes CAUD payload}) \times 8 = 67 \times 8 = 536\text{ bits}$$

At 1 bit per 2048-sample segment:
$$N_{\text{min\_frames}} = 536 \times 2048 = 1,097,728\text{ audio frames}$$

At $F_s = 44,100\text{ Hz}$:
$$T_{\min} = \frac{1,097,728}{44,100} \approx 24.8918\text{ seconds}$$

`EchoHidingAlgorithm.estimate_capacity()` accurately reports this minimum duration rather than erroneously reporting 2048 samples (which is only the single-segment size).

---

## 7. Numerical Audio Quality & Distortion Measurements

Evaluated using `app/evaluation/audio_quality.py` on a standard 16-bit stereo PCM carrier ($F_s = 44.1\text{ kHz}$, 540 segments, duration $\approx 25.1\text{ s}$) embedding a 29-byte test payload:

| Metric | Measured Value | Theoretical Expectation / Target | Status |
|:---|:---:|:---:|:---:|
| **Mean Squared Error (MSE)** | $1.76 \times 10^5$ | Low non-zero perturbation | Verified |
| **Signal-to-Noise Ratio (SNR)** | **$21.94\text{ dB}$** | Expected range $20\text{ dB} \dots 35\text{ dB}$ for $\alpha = 0.08$ | Verified |
| **Peak SNR (PSNR)** | **$37.84\text{ dB}$** | $> 30\text{ dB}$ | Verified |
| **Pearson Correlation ($r$)** | **$0.9968$** | $> 0.99$ (high carrier fidelity) | Verified |
| **Channel 1 Distortion** | **$0.0$ (Bit-for-bit identical)** | Channel 1 preserved untouched | Verified |
| **Sample Count Error** | **$0\text{ samples}$** | Exactly matches original frame count | Verified |
| **Carrier Clipping** | **$0\text{ clipped samples}$** | Anti-wrap clipping enforced | Verified |

---

## 8. Summary of Test Coverage

All 46 test cases in `tests/test_echo_hiding.py` pass:

1. **`TestEchoParameters`** (6 tests):
   - Sample delay conversions at 44.1 kHz, 48 kHz, and 22.05 kHz.
   - Non-positive sample rate rejection.
   - Canonical synchronization word `0x596A` and binary preamble matching.
   - Algorithm descriptor metadata (`ACOUSTIC_TIME`, `EXPERIMENTAL_TARGET`).
2. **`TestMathematicalEchoCepstrum`** (3 tests):
   - Isolated single-segment delay discrimination for bit 0 vs bit 1.
   - Deterministic tie-breaking behavior.
   - Preamble synchronization correlation $\rho \ge 0.90$.
3. **`TestEchoEmbeddingExtraction`** (3 tests):
   - Full CSMA v1 envelope roundtrip with default $\alpha = 0.08$.
   - Pseudorandom binary payload roundtrip.
   - CRC32 tamper detection raising `CorruptedPayloadError`.
4. **`TestEchoHistoryAndCrossfade`** (4 tests - M4.1 New):
   - Non-recursive FIR history buffer verification: proves sample $n < d$ added component is $\alpha \cdot s_{\text{orig}}(n - d)$, never modulated output.
   - Hanning crossfade transitions across alternating bit patterns (`0, 1, 0, 1...`).
   - Consecutive homogeneous bit sequences (all-0 and all-1).
   - Sample count and audio boundary continuity preservation.
5. **`TestEchoAudioCompatibility`** (8 tests):
   - 8-bit ($\alpha=0.08$ and $\alpha=0.15$), 16-bit, 24-bit, and 32-bit integer PCM roundtrips.
   - Stereo Channel 1 bit-for-bit preservation.
   - Mono audio embedding and extraction.
   - Sample-rate, sample count, and frame count preservation.
6. **`TestEchoCapacityEstimation`** (4 tests):
   - Capacity formula compliance.
   - Minimum valid payload carrier requirement (536 segments / 24.89 s).
   - Insufficient carrier capacity rejection (`CapacityExceededError`).
   - Strict capacity option validation: rejection of booleans, strings, floats, negatives, and unknown options (`UnsupportedParameterError`).
7. **`TestEchoErrorHandling`** (12 tests):
   - False-positive rejection on clean carrier audio (`has_stego_signature = False`).
   - Carrier too short for 144-segment header (`HeaderNotFoundError`).
   - Invalid $\alpha$ options rejected (`UnsupportedParameterError`).
   - Conflicting or equal delays rejected.
   - Corrupted or invalid WavData containers rejected.
   - Graceful option validation in `inspect_metadata()` without arithmetic or type exceptions.
   - Negative synchronization: silence rejection.
   - Negative synchronization: Gaussian noise rejection.
   - Negative synchronization: harmonic multitone rejection.
   - Negative synchronization: corrupted preamble rejection.
   - Cross-algorithm isolation: LSB carrier rejected by Echo (`has_stego_signature = False`).
   - Cross-algorithm isolation: DWT carrier rejected by Echo (`has_stego_signature = False`).
8. **`TestEchoCryptographicIntegration`** (3 tests):
   - Full AES-256-GCM + PBKDF2 (600,000 iterations) encrypt $\to$ embed $\to$ extract $\to$ decrypt workflow with multilingual text.
   - Wrong password fails authentication (`DecryptionError`).
   - Distinction between CRC32 framing integrity and AES-GCM 128-bit GHASH cryptographic authentication.
9. **`TestEchoAudioQuality`** (1 test):
   - Baseline numerical quality metrics (MSE, SNR, PSNR, correlation).
10. **`TestEchoRegistryIntegration`** (2 tests):
    - Direct registry registration and resolution by canonical name (`"echo"`) and integer ID (`0x03`).
    - Global singleton retrieval with `include_echo=True`.

---

## 9. Limitations & Experimental Observations

1. **Carrier Spectral Sensitivity**: Echo Hiding relies on a rich, broadband spectral envelope (wideband chirps, noise, speech, or complex music). Tonal signals with narrow spectral peaks (e.g., pure isolated sinusoids) do not exhibit clear cepstral delay ripples and can cause bit classification errors.
2. **Low Payload Throughput**: At 1 bit per 2048 samples, the effective throughput is approximately $2.69\text{ bytes/second}$ at 44.1 kHz. Consequently, transmitting typical cryptographic payloads requires longer carrier tracks ($> 25\text{ seconds}$).
3. **Acoustic Channel Robustness**: Survivability against lossy MP3 compression, acoustic multipath reverberation, and loudspeaker-microphone transmission is an **experimental target**, requiring future testing and calibration before production claims can be made.
