# Phase M5: Multi-Algorithm Service and API Integration Specification & Report

## 1. Executive Summary

Phase M5 integrates all three implemented steganography algorithms into the unified CryptAudio-Web service layer (`app/services/cryptaudio_service.py`) and FastAPI REST API layer (`app/api/routes.py`).

The three registered steganography engines are:
1. **LSB (Least Significant Bit)**: Domain `spatial_time_domain`, canonical sync `0xF9A9`, Fragile by design.
2. **DWT-DCT-QIM**: Domain `transform_domain`, canonical sync `0xF9A9`, Wavelet/DCT transform domain with QIM scalar quantizer ($\Delta$).
3. **Echo Hiding**: Domain `acoustic_time_domain`, canonical sync `0x596A`, Bipolar dual-kernel acoustic echo modulation ($\alpha$, $d_0, d_1$).

The integration strictly respects the object-oriented strategy pattern via `StegoRegistry` and `BaseStegoAlgorithm`, eliminating hardcoded algorithmic dispatch in the service and API layers.

---

## 2. Service Layer Integration (`app/services/cryptaudio_service.py`)

### 2.1 Strategy Dispatch Pattern
Instead of hardcoded `if/elif` blocks, `CryptAudioService` resolves algorithm implementations dynamically from `get_registry(include_echo=True)`:
```python
def _resolve_algorithm(self, algorithm_id: str | None = None) -> BaseStegoAlgorithm:
    algo_id = (algorithm_id or self.DEFAULT_ALGORITHM).strip().lower()
    if not self.registry.is_registered(algo_id):
        raise StegoServiceError(
            f"Requested algorithm '{algo_id}' is not registered or unavailable.",
            error_code="UNKNOWN_ALGORITHM",
        )
    return self.registry.get(algo_id)
```

### 2.2 Core Operations
1. **`embed_message(input_wav, output_wav, message, password, algorithm="lsb", **options) -> EmbedMessageResult`**:
   - Derives AES key using PBKDF2-HMAC-SHA256 (600,000 iterations).
   - Encrypts plaintext message with AES-256-GCM.
   - Dispatches embedding of the ciphertext binary payload into the carrier WAV using the selected algorithm strategy.
   - Returns metadata dataclass `EmbedMessageResult` (algorithm used, carrier/payload metrics).
2. **`extract_message(stego_wav, password, algorithm=None, **options) -> str`**:
   - Backward-compatible wrapper returning the decrypted plaintext string directly.
3. **`extract_message_detailed(stego_wav, password, algorithm=None, **options) -> ExtractMessageResult`**:
   - Supports explicit algorithm selection or automatic detection across registered algorithms when `algorithm=None`.
   - Extracts payload via algorithm strategy; verifies transmission framing checksum (CRC32).
   - Authenticates and decrypts ciphertext using AES-256-GCM.
   - Returns structured `ExtractMessageResult` containing decrypted message, resolved algorithm ID, and framing verification status.
4. **`estimate_capacity(input_wav, message="", algorithm="lsb", **options) -> CapacityEstimate`**:
   - Obtains accurate algorithm-specific capacity estimates via `algo.estimate_capacity()`.
   - Maintains full backward compatibility with legacy tests when algorithm is `lsb` and framing options are omitted.
5. **`inspect_stego_metadata(input_wav, algorithm=None, **options) -> dict`**:
   - Non-destructive inspection checking synchronization words and envelope preambles without modifying audio.

---

## 3. REST API Layer Integration (`app/api/routes.py`)

### 3.1 Endpoint Specifications
- **`GET /api/algorithms`**:
  - Returns descriptors of all registered algorithms (`lsb`, `dwt_dct_qim`, `echo`), including domain, robustness status, parameter schemas, defaults, and envelope versions.
- **`POST /api/embed`**:
  - Multipart form accepting `file`, `message`, `password`, optional `algorithm` (default `"lsb"`), and algorithm options (`delta`, `alpha`).
  - Emits response header `X-Stego-Algorithm: <algorithm_id>`.
  - Content-Type: `audio/wav`.
- **`POST /api/extract`**:
  - Multipart form accepting `file`, `password`, optional `algorithm` (default `None` for auto-detection), and options.
  - JSON response returns `message`, `algorithm`, and `framing_checksum_verified`.
- **`POST /api/capacity`**:
  - Accepts `file`, `message`, optional `algorithm` (default `"lsb"`), and options.
  - JSON response returns algorithm-specific capacity metrics and sufficiency status.
- **`POST /api/audio/inspect`**:
  - Extended to return `stego_inspection` metadata and `available_algorithms` alongside carrier audio metrics.

### 3.2 Error Code Mapping
| Exception / Condition | HTTP Status | Response `detail.error_code` |
|---|---|---|
| `UNKNOWN_ALGORITHM` | 400 Bad Request | `UNKNOWN_ALGORITHM` |
| `INVALID_PARAMETER` / Validation error | 400 Bad Request | `INVALID_PARAMETER` |
| `UnsupportedAudioFormatError` / non-PCM | 415 Unsupported Media Type | `UNSUPPORTED_FORMAT` |
| `INSUFFICIENT_CAPACITY` | 422 Unprocessable Entity | `INSUFFICIENT_CAPACITY` |
| `NO_STEGO_PAYLOAD` / `HeaderNotFoundError` | 422 Unprocessable Entity | `NO_STEGO_PAYLOAD` |
| `AUTHENTICATION_FAILED` (AES-GCM tag mismatch) | 422 Unprocessable Entity | `AUTHENTICATION_FAILED` |
| `PAYLOAD_CORRUPTED` (CRC32 mismatch) | 422 Unprocessable Entity | `PAYLOAD_CORRUPTED` |

---

## 4. Cryptographic Security & Integrity Architecture

1. **Two-Stage Integrity Architecture**:
   - **Stage 1 (Framing Checksum)**: 32-bit CRC32 checksum in CSMA header validates envelope transmission boundaries and detects physical bit errors. It is explicitly documented and reported as a framing integrity check, **never** cryptographic authentication.
   - **Stage 2 (Cryptographic Authentication)**: 128-bit AES-256-GCM authentication tag guarantees ciphertext authenticity and confidentiality. Any alteration of ciphertext or key produces `AUTHENTICATION_FAILED`.
2. **Zero-Leakage Security Posture**:
   - Passwords and encryption keys are strictly zeroized or scoped to memory stack frames during operation.
   - API error responses never echo submitted passwords, keys, temporary paths, or server stack traces.
   - Temporary uploaded files and output files are created with cryptographically random UUIDs and cleaned up in `finally` blocks.

---

## 5. Verification Test Matrix

- `tests/test_cryptaudio_service_multi_algorithm.py`: 19 tests verifying service registry dispatch, multi-algorithm embedding/extraction, auto-detection, multilingual Unicode, capacity, and error handling.
- `tests/test_api_multi_algorithm.py`: 21 tests verifying API endpoints (`/api/algorithms`, `/api/embed`, `/api/extract`, `/api/capacity`, `/api/audio/inspect`), parameter passing, error codes, and lifecycle file cleanup.
- Legacy regression suites (`test_service.py`, `test_api_processing.py`, `test_api.py`, `test_m2_core_architecture.py`, `test_dwt_dct_qim.py`, `test_echo_hiding.py`): 100% passing.
