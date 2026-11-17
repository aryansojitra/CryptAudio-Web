# CryptAudio-Web — Consolidated Security Assessment

## 1. Executive Summary

This report provides a consolidated security assessment for **CryptAudio-Web**, documenting vulnerabilities and hardening measures identified, remediated, and verified during Phase 11 and Phase 11.1.

CryptAudio-Web implements authenticated cryptographic audio steganography on a local web stack. Security analysis evaluated:
- Cryptographic construction integrity and tamper resistance.
- RIFF/WAVE parsing and chunk bounds safety.
- LSB framing and buffer manipulation bounds.
- REST API transport security, streaming upload ceilings, and error disclosure.
- Frontend DOM manipulation and browser execution policies (CSP).
- Local filesystem isolation and temporary file lifecycle.

---

## 2. Categorization of Assessment Findings

The assessment identified five findings, categorized into three security vulnerabilities, one lifecycle hardening improvement, and one consistency improvement:

| Finding ID | Title | Category | Severity | Status |
|---|---|---|---|---|
| **SEC-01** | Missing HTTP Security Headers & Browser Anti-Caching | Security Vulnerability | Medium | **Remediated** |
| **SEC-02** | Content-Disposition Filename Injection Surface | Security Vulnerability | Low | **Remediated** |
| **SEC-03** | Potential XSS Vector in Toast Notifications | Security Vulnerability | Low | **Remediated** |
| **SEC-04** | Orphaned Temporary Files from Abnormal Process Halts | Lifecycle Hardening | Informational / Low | **Remediated** |
| **SEC-05** | Inconsistent Global 500 Error Response Format | Consistency Improvement | Informational | **Remediated** |

---

## 3. Detailed Finding Descriptions & Remediations

### Finding SEC-01: Missing HTTP Security Headers & Anti-Caching Protections
- **Category**: Security Vulnerability
- **Severity**: **Medium**
- **Affected Component**: `app/main.py`
- **Description**: Responses initially lacked standard browser security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy`), leaving client browsers exposed to MIME-type sniffing, clickjacking/framing, and local disk caching of sensitive cryptographic processing endpoints (`/api/*`).
- **Potential Impact**: Attackers could frame the application in an external iframe, trigger MIME-confusion vulnerabilities, or extract sensitive plaintexts/stego files from browser disk cache on shared machines.
- **Remediation Implemented**:
  1. Implemented `security_headers_middleware` in `app/main.py`.
  2. Applied `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `X-XSS-Protection: 0`.
  3. Applied strict anti-caching to all `/api/*` endpoints: `Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, `Expires: 0`.
  4. Enforced strict Content Security Policy:
     - On application routes (`/`, `/static/*`, `/api/*`): `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none';`
     - Removed external CDNs (`jsdelivr`) from application endpoints.
     - Preserved CDN permissions solely on `/docs` and `/redoc` for isolated Swagger UI rendering.
- **Verification Performed**: Verified via `test_security_headers_present_on_root`, `test_anti_caching_headers_on_api_endpoints`, and `test_csp_application_routes_has_no_unsafe_inline_and_no_cdn` in `tests/test_security_verification.py`.

---

### Finding SEC-02: Content-Disposition Filename Injection Surface
- **Category**: Security Vulnerability
- **Severity**: **Low**
- **Affected Component**: `app/api/routes.py`
- **Description**: In `POST /api/embed`, the downloaded stego audio filename in the `Content-Disposition` header was constructed directly from `Path(file.filename).stem`. While the file on disk was stored with an unpredictable UUID, an attacker submitting a filename containing carriage returns, newlines (`\r\n`), or double quotes could attempt HTTP header injection or response splitting in older client user agents.
- **Potential Impact**: Response splitting or corrupted download filenames.
- **Remediation Implemented**: Sanitized `raw_stem` using regex character whitelisting: `re.sub(r"[^\w\-.]", "_", raw_stem).strip("._")` before building the `Content-Disposition` header.
- **Verification Performed**: Verified via `test_path_traversal_in_filename_sanitized` in `tests/test_security_hardening.py`.

---

### Finding SEC-03: Potential XSS Vector in Toast Notifications
- **Category**: Security Vulnerability
- **Severity**: **Low**
- **Affected Component**: `app/static/js/app.js`
- **Description**: In `showToast()`, notifications were assembled using string interpolation into `toast.innerHTML = ...`. While `escapeHtml()` was applied, relying on regular expression HTML escaping creates unnecessary residual risk if unexpected objects or bypass patterns reach the notification function.
- **Potential Impact**: Cross-Site Scripting (XSS) if untrusted input bypassed the regex.
- **Remediation Implemented**: Replaced `innerHTML` string interpolation with direct DOM element creation using `document.createElement('span')` and setting message content strictly via `textContent`.
- **Verification Performed**: Verified via `test_xss_payloads_safely_roundtrip_as_text` and `test_all_xss_attack_vectors_roundtrip_as_plain_text` in `tests/test_security_verification.py`.

---

### Finding SEC-04: Orphaned Temporary Files from Abnormal Process Halts
- **Category**: Lifecycle Hardening
- **Severity**: **Informational / Low**
- **Affected Component**: `app/main.py`
- **Description**: Per-request cleanup via background tasks and `finally` blocks reliably unlinks temporary carrier/stego files during normal operations. However, an abrupt power failure, OS termination (`kill -9`), or abnormal crash could leave orphaned `.wav` files inside the `temporary/` folder.
- **Potential Impact**: Gradual accumulation of stale files on disk and risk of plaintext/carrier residue across server restarts.
- **Remediation Implemented**: Added `cleanup_orphaned_temp_files()` within the FastAPI `lifespan` context manager in `app/main.py` that automatically purges all lingering `.wav` files in `temporary/` upon application startup while preserving `temporary/.gitkeep`.
- **Verification Performed**: Verified via `test_startup_cleanup_removes_orphaned_wav_files` in `tests/test_security_verification.py`.

---

### Finding SEC-05: Inconsistent Global 500 Error Response Format
- **Category**: Consistency Improvement
- **Severity**: **Informational**
- **Affected Component**: `app/main.py`
- **Description**: The unhandled exception handler initially returned a non-standard JSON envelope (`{"error": "internal_server_error", "message": "..."}`), differing from the project's standard `{success: false, error: {code: "...", message: "..."}}` format.
- **Potential Impact**: Parsing failures or unhandled edge cases in frontend API integration upon encountering unexpected 500 responses.
- **Remediation Implemented**: Aligned `global_exception_handler` to return:
  ```json
  {
    "success": false,
    "error": {
      "code": "INTERNAL_ERROR",
      "message": "An unexpected error occurred. Please try again."
    }
  }
  ```
- **Verification Performed**: Verified via `test_error_responses_conform_to_standard_envelope` in `tests/test_security_hardening.py`.

---

## 4. Architectural Security Controls

### A. Cryptographic Key Derivation & Encryption
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations and a 16-byte cryptographically secure random salt (`os.urandom(16)`). Exceeds current OWASP minimum recommendations (600,000 iterations for PBKDF2-HMAC-SHA256).
- **Authenticated Encryption**: AES-256 in Galois/Counter Mode (GCM) using a 12-byte cryptographically fresh nonce per encryption.
- **Header Authentication**: The entire 33-byte header (`CAUD` magic, version `0x01`, salt, and nonce) is authenticated as Additional Authenticated Data (AAD). Any modification to salt, nonce, version, or magic causes decryption failure before any ciphertext processing.
- **Integrity Guarantee**: A 16-byte (128-bit) authentication tag verifies both ciphertext and header integrity. Tampered payloads fail with `DecryptionError` without leaking plaintext fragments.

### B. Input Validation & Container Defense
- **Low-Level Chunk Verification**: `_verify_riff_wave_format()` walks RIFF chunks and validates length fields against total file size, preventing integer overflow or buffer overread.
- **Codec Filtering**: Strictly enforces uncompressed integer PCM (`0x0001` or `WAVE_FORMAT_EXTENSIBLE` with `KSDATAFORMAT_SUBTYPE_PCM`). Rejects IEEE float (`0x0003` and extensible float GUID) and partial bit depths.
- **Upload Streaming Ceilings**: Enforces streaming size limits of 50 MB per file (`MAX_UPLOAD_BYTES = 52,428,800`) and 100 MB combined (`MAX_COMBINED_UPLOAD_BYTES = 104,857,600`). Files exceeding these limits are immediately aborted with HTTP 413 `FILE_TOO_LARGE` without exhausting server memory.

### C. Filesystem Isolation & Temporary Lifecycle
- **Unpredictable Filenames**: All uploaded and generated audio files are stored in `temporary/` using `prefix_{uuid4().hex}.wav` basenames. User-supplied filenames are never used on disk.
- **Automated Lifecycle**: Temporary files are deleted in `finally` blocks and FastAPI `BackgroundTask` handlers upon HTTP response completion.
- **Startup Hygiene**: The `lifespan` handler purges stale `.wav` files on process initialization.

### D. Safe DOM Rendering & Zero-Inline CSP
- **Safe DOM Binding**: User-controllable text (recovered messages, filenames, notifications) is exclusively bound using `textContent` and `createElement`, preventing DOM-based HTML/script interpretation.
- **No Inline JavaScript**: All inline scripts have been removed from `index.html`. Pre-render theme initialization is performed via an external synchronous script (`theme.js`) in `<head>`, allowing CSP `script-src` to be locked strictly to `'self'`.

---

## 5. Residual Risks & Inherent Limitations

1. **LSB Steganography Detectability**: LSB modification alters the natural statistical distribution of carrier sample amplitudes. While the payload is strongly encrypted and resembles pseudorandom noise, statistical steganalysis techniques (Chi-squared analysis, Sample Pair Analysis, RS analysis) can detect the presence of hidden data if the carrier waveform is examined.
2. **Fragility to Lossy Signal Processing**: LSB embedding is highly fragile. Any lossy transcoding (conversion to MP3, AAC, OGG), resampling, dynamic range compression, equalization, or noise reduction will alter sample LSBs and permanently destroy the concealed payload.
3. **Password Entropy & Brute Force**: While 600,000 PBKDF2 iterations impose substantial computational cost on offline password cracking, a weak, short, or dictionary-based password remains vulnerable to targeted guessing attacks.
4. **Browser Memory Hygiene**: In modern JavaScript execution environments, strings and variables cannot be explicitly zeroized or scrubbed from heap memory; memory clearing depends on the browser's garbage collector.
5. **Remaining CSP Relaxation**: `style-src` retains `'unsafe-inline'` to support dynamic CSS transitions and DOM visibility toggles.
6. **Testing Verification Scope**: Actual browser-based XSS execution was not evidenced using a headless browser engine (such as Playwright or Puppeteer). Static DOM inspection, test client requests, and test-harness assertions verify architecture and headers, but must not be represented as equivalent to dynamic browser penetration testing.
7. **Local Deployment Scope**: The application is explicitly designed and configured for local loopback execution (`127.0.0.1:8000`). It does not include TLS/HTTPS termination or rate limiting suitable for hostile public network exposure.
