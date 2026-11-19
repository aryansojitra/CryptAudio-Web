# CryptAudio-Web Steganography Benchmarking Framework (Phase M7.2)

## Overview

**CryptAudio-Web Phase M7.2** provides an automated, rigorous, and scientific benchmarking suite for audio steganography.
It empirically evaluates the three implemented steganography algorithms:

1. **LSB (Least Significant Bit)**: Sample-domain replacement of the least significant bit ($b_0$) with universal CSMA v1 envelope framing.
2. **DWT-DCT-QIM**: Multi-resolution Daubechies 4 discrete wavelet transform (`db4`, 3 decomposition levels), block discrete cosine transform over detail subband `cD3`, and quantization index modulation.
3. **Echo Hiding**: Multi-segment temporal delay resonance with forward filtering ($d_0 = 44, d_1 = 57$ samples at 44.1 kHz) and autocepstral delay peak detection.

Every algorithm is evaluated end-to-end through the mandatory **AES-256-GCM** encryption layer with **PBKDF2-HMAC-SHA256** (600,000 iterations) and the universal **CSMA v1 Binary Envelope** framing protocol.

---

## Algorithm Specifications & Parameter Distinctions

To ensure scientific clarity, CryptAudio-Web distinguishes among **supported**, **default**, and **empirically tested** parameters:

### 1. Least Significant Bit (LSB)
- **Supported Parameters**: Fixed 1 bit per sample in Channel 0 (`framing='csma'`).
- **Default Parameter**: Native default (1 bit per sample).
- **Tested in Benchmark**: Standard baseline configuration.

### 2. DWT-DCT-QIM
- **Wavelet Transform**: Discrete Wavelet Transform using Daubechies 4 (`db4`, 3 levels of decomposition). *Note: This implementation does not use Haar wavelets.*
- **Embedding Sub-band**: Block DCT over detail sub-band `cD3` (`DECOMPOSITION_LEVEL = 3`).
- **Chunk Geometry**: 1,024 audio samples per chunk. Each chunk embeds 16 bits across 16 DCT blocks.
- **Supported Quantization Step Sizes**: $\Delta \in \{8, 16, 32, 64\}$.
- **Default Parameter**: Native default is $\Delta = 32$.
- **Tested in Full Benchmark**: Baseline default ($\Delta = 32$) plus parameter sweep across $\Delta \in \{16, 32, 64\}$. In quick mode, only default $\Delta = 32$ is evaluated.

### 3. Echo Hiding
- **Kernel Delays**: $d_0 = 44$ samples (bit 0), $d_1 = 57$ samples (bit 1) at 44.1 kHz.
- **Segment Size**: 2,048 audio samples per bit ($21.53\text{ bps}$).
- **Supported Attenuation Factors**: Positive float $\alpha < 1.0$ (typical operational range $0.05 \le \alpha \le 0.20$).
- **Default Parameter**: Native default is $\alpha = 0.08$.
- **Tested in Full Benchmark**: Baseline default ($\alpha = 0.08$) plus parameter sweep across $\alpha \in \{0.08, 0.12, 0.15\}$. In quick mode, only default $\alpha = 0.08$ is evaluated.

---

## Architecture & Code Structure

The benchmark suite is organized into clean, reusable modules under `app/evaluation/`:

- [`app/evaluation/benchmark.py`](file:///c:/Users/91901/OneDrive/Documents/college%20nfsu/sem%201/AC%20-%20APPLIED%20CRYPTOGRAPHY/TA%202/CryptAudio-Web/app/evaluation/benchmark.py):
  - Data models: `BenchmarkCarrierConfig`, `CapacityMetrics`, `QualityMetrics`, `PerformanceMetrics`, `AccuracyMetrics`, `RobustnessResult`, `AlgorithmBenchmarkResult`, `BenchmarkSuiteResult`.
  - Multi-width carrier synthesis: `generate_carrier_wav(config, path, seed)` supporting 8-bit unsigned, 16-bit signed, 24-bit signed, and 32-bit signed PCM, both mono and stereo.
  - Multi-channel robustness transformations: Gaussian noise, amplitude scaling, resampling simulation, and lossy compression (with `NOT TESTED` fallback when external encoders are absent).
  - 4 independent integrity/tamper experiments:
    1. Wrong password authentication rejection.
    2. Synchronization / preamble corruption rejection.
    3. Framing CRC32 checksum corruption rejection.
    4. Genuine ciphertext tampering with recomputed CSMA CRC32 (AES-GCM authentication verification).
  - Defensive input validation and guaranteed `tracemalloc` cleanup via `try/finally`.
- [`app/evaluation/benchmark_report.py`](file:///c:/Users/91901/OneDrive/Documents/college%20nfsu/sem%201/AC%20-%20APPLIED%20CRYPTOGRAPHY/TA%202/CryptAudio-Web/app/evaluation/benchmark_report.py):
  - `save_json_report(suite, path)`: Machine-readable JSON output.
  - `save_csv_report(suite, path)`: Tabular CSV metrics export with 42 columns.
  - `generate_markdown_report(suite, path)`: Fully data-driven 11-section Markdown evaluation report dynamically synthesized from actual benchmark suite results.
- [`scripts/run_algorithm_benchmark.py`](file:///c:/Users/91901/OneDrive/Documents/college%20nfsu/sem%201/AC%20-%20APPLIED%20CRYPTOGRAPHY/TA%202/CryptAudio-Web/scripts/run_algorithm_benchmark.py):
  - Command-line runner supporting custom carrier durations, trials, quick mode, and output directories with strict CLI input validation.
- [`tests/test_benchmark.py`](file:///c:/Users/91901/OneDrive/Documents/college%20nfsu/sem%201/AC%20-%20APPLIED%20CRYPTOGRAPHY/TA%202/CryptAudio-Web/tests/test_benchmark.py):
  - Automated pytest test suite covering PCM synthesis, transformations, integrity experiments, capacity limits, report data consistency, and CLI execution.

---

## How to Run the Benchmark

### 1. Full Benchmark Run (Default)
Executes standard baseline algorithms, parameter sweeps ($\Delta \in \{16, 32, 64\}$, $\alpha \in \{0.08, 0.12, 0.15\}$), and the short carrier capacity-insufficient boundary test:

```powershell
python scripts/run_algorithm_benchmark.py --output-dir benchmark_results
```

### 2. Rapid / Quick Mode
Executes only the baseline default configurations across the three algorithms:

```powershell
python scripts/run_algorithm_benchmark.py --output-dir benchmark_results --quick
```

### 3. Custom Carrier Duration and Timing Trials
Configure carrier duration (in seconds) and repeated trials for execution latency averaging:

```powershell
python scripts/run_algorithm_benchmark.py --output-dir benchmark_results --carrier-duration 45.0 --trials 3
```

### 4. Running the Benchmark Test Suite
Execute the automated pytest suite without network dependencies:

```powershell
pytest tests/test_benchmark.py -v
```

---

## Evaluated Metrics Explained

### A. Capacity & Embedding Density
- **Total Samples**: Number of PCM audio samples in the carrier.
- **Raw Capacity (bits / bytes)**: Total available embeddable bitstream space before protocol overhead:
  - LSB: 1 bit per sample ($1,455,300$ bits / $181,912$ bytes on 33s carrier).
  - DWT-DCT-QIM: 16 bits per 1,024-sample chunk ($1,421$ complete chunks $\implies 22,736$ bits / $2,842$ bytes on 33s carrier).
  - Echo Hiding: 1 bit per 2,048-sample segment ($710$ segments $\implies 710$ bits / $88$ bytes on 33s carrier).
- **Usable Encrypted-Payload Capacity (bytes)**: Capacity remaining after subtracting the 18-byte (144-bit) CSMA v1 envelope header: $\lfloor(\text{Raw Bits} - 144) / 8\rfloor$.
- **Max Plaintext Message (bytes)**: Plaintext byte capacity remaining after subtracting both CSMA envelope overhead (18 B) and AES-256-GCM cryptographic overhead (49 B = 33 B header + 16 B GHASH tag).
- **Minimum Valid Encrypted Envelope**: $18\text{ B CSMA} + 49\text{ B AES-GCM} = 67\text{ bytes} = 536\text{ bits}$.
- **Utilization (%)**: $\frac{\text{Required Bits}}{\text{Available Bits}} \times 100\%$.

### B. Numerical Audio Quality
- **MSE (Mean Squared Error)**: Average squared difference between original carrier and stego audio samples.
- **SNR (Signal-to-Noise Ratio, dB)**: Logarithmic ratio of original signal power to modification error power.
- **PSNR (Peak Signal-to-Noise Ratio, dB)**: Peak signal power relative to MSE, where $MAX$ is determined by the PCM sample bit depth ($MAX = 127$ for 8-bit, $32767$ for 16-bit, $8388607$ for 24-bit, $2147483647$ for 32-bit PCM). Values $> 45\text{ dB}$ are classified mathematically as 'Excellent'.
- **Pearson Correlation ($r$)**: Linear correlation between original and stego waveforms ($1.000$ indicates identical shape).
- **Modified Sample Percentage**: Fraction of total audio samples modified during embedding.

### C. Processing Performance
- **Embedding Latency (s)**: Wall-clock time required for PBKDF2 derivation, AES-256-GCM encryption, steganography embedding, and WAV container export (mean ± standard deviation across trials).
- **Extraction Latency (s)**: Wall-clock time required for WAV reading, algorithm signature detection, steganography extraction, and AES-256-GCM authenticated decryption.
- **Total Pipeline Latency (s)**: Round-trip embedding + extraction execution time.
- **Peak Traced Memory (MB)**: Maximum heap allocation of Python objects during execution, measured via Python `tracemalloc`. Does not represent full OS process RSS or native non-Python allocations.

### D. Extraction Accuracy & Independent Integrity Experiments
- **Extraction Success Rate**: Boolean indicator of whether extraction completed without unhandled exceptions.
- **Exact Recovered Plaintext Match**: Byte-for-byte identity check between recovered message and original plaintext.
- **Algorithm Identification**: Verification that the auto-detector correctly identified the active algorithm.
- **Authentication Verification**: Successful AES-256-GCM GHASH authentication tag verification.
- **Wrong Password Rejection**: Passphrase authentication failure in AES-256-GCM.
- **Sync Corruption Rejection**: Deliberate corruption of synchronization preamble / header.
- **Checksum Corruption Rejection**: Modification of framed payload data without updating CRC32. Demonstrates framing-level detection independent of cryptography.
- **Ciphertext Tampering Rejection**: Modification of ciphertext with validly recomputed CSMA framing, proving AES-GCM tamper evidence.

### E. Canonical Robustness Status Definitions
Outcomes under controlled channel transformations are strictly classified into 6 canonical statuses:
- `SURVIVED`: Plaintext message extracted and verified with 100% exact bit-for-bit match.
- `SYNC_FAILED`: Synchronization preamble correlation or CSMA header missing or unlocatable.
- `CHECKSUM_FAILED`: Framing CRC32 checksum mismatch. Demonstrates that accidental corruption was caught at the container layer.
- `AUTHENTICATION_FAILED`: AES-256-GCM GHASH authentication tag rejected (`DecryptionError`). Demonstrates cryptographic tamper evidence. *Must only represent genuine cryptographic authentication failure.*
- `FAILED`: General extraction or transformation failure.
- `NOT TESTED`: Required external dependency (e.g., FFmpeg / LAME) was unavailable in the test environment. *This is an operational indicator, not equivalent to algorithmic failure.*

---

## Framing CRC32 vs. AES-256-GCM Cryptographic Authentication

It is essential to distinguish between framing checksums and cryptographic authentication:

1. **CSMA v1 Envelope CRC32 Checksum**:
   - Purpose: Detect accidental framing transmission errors and bit-flips during transport.
   - Security: CRC32 is a linear cyclic redundancy check and provides **no cryptographic security** against intentional manipulation.
   - Result on failure: `CHECKSUM_FAILED` (raises `CorruptedPayloadError`).

2. **AES-256-GCM GHASH Authentication Tag**:
   - Purpose: Provide cryptographic integrity, authenticity, and non-malleability over ciphertext and associated data.
   - Security: Authenticates that the ciphertext was generated by a holder of the PBKDF2-derived 256-bit key and was not modified in transit.
   - Result on failure: `AUTHENTICATION_FAILED` (raises `DecryptionError`).

---

## Empirical Benchmark Findings Summary

Measured on standard 33.0-second chirp carrier (1,455,300 samples, 44.1 kHz, 16-bit Mono):

| Algorithm | Parameters | Raw Capacity | PSNR (dB) | SNR (dB) | Pipeline Mean | Noise ($\sigma=1.0$) | Scale ($0.95\times$) | Resampling | Lossy MP3 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LSB** | Default | **181,912 B** | **127.1 dB** | **122.7 dB** | **0.26 s** | SYNC_FAILED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| **DWT-DCT-QIM** | $\Delta = 16$ | 2,842 B | 110.2 dB | 105.7 dB | 0.29 s | AUTHENTICATION_FAILED | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| **DWT-DCT-QIM** | $\Delta = 32$ *(Default)* | 2,842 B | 104.6 dB | 100.2 dB | 0.28 s | **SURVIVED** | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| **DWT-DCT-QIM** | $\Delta = 64$ | 2,842 B | 98.6 dB | 94.1 dB | 0.30 s | **SURVIVED** | SYNC_FAILED | SYNC_FAILED | NOT TESTED |
| **Echo Hiding** | $\alpha = 0.08$ *(Default)* | 88 B | 27.0 dB | 22.6 dB | 0.38 s | **SURVIVED** | **SURVIVED** | SYNC_FAILED | NOT TESTED |
| **Echo Hiding** | $\alpha = 0.12$ | 88 B | 23.5 dB | 19.1 dB | 0.38 s | **SURVIVED** | **SURVIVED** | SYNC_FAILED | NOT TESTED |
| **Echo Hiding** | $\alpha = 0.15$ | 88 B | 21.5 dB | 17.1 dB | 0.40 s | **SURVIVED** | **SURVIVED** | SYNC_FAILED | NOT TESTED |

---

## Algorithm Selection Guide (Design Guidelines)

> [!NOTE]
> The table below summarizes architectural engineering design recommendations based on cryptographic and digital signal processing properties. Operational performance must be verified against empirical benchmark results recorded above.

| Operational Scenario | Recommended Algorithm | Recommended Parameter | Architectural Justification |
| :--- | :--- | :--- | :--- |
| **High Capacity / Large Text Files** | **LSB** | Default | Highest raw bit density (1 bit/sample), low computational complexity. |
| **Audiophile Transparency** | **LSB** or **DWT-DCT-QIM** | LSB or DWT ($\Delta=16$) | PSNR > 100 dB, minimal waveform distortion in time or wavelet domains. |
| **Noisy Digital Channels** | **DWT-DCT-QIM** | $\Delta = 32$ or $\Delta = 64$ | Frequency-domain quantization index modulation provides resilience against additive noise. |
| **Volume Attenuation / Amplitude Scaling** | **Echo Hiding** | $\alpha = 0.08$ | Ratio-based cepstral auto-correlation peak detection provides scale invariance. |
| **Short Audio Clips (< 10 seconds)** | **LSB** | Default | High bit density required to accommodate the 536-bit minimum encrypted CSMA envelope. |
