# CryptAudio-Web — REST API Documentation

This document provides the complete technical specification for all backend REST endpoints provided by CryptAudio-Web.

All application endpoints are served locally on `http://127.0.0.1:8000` with strict anti-caching headers (`Cache-Control: no-store`) and Content Security Policy (`script-src 'self'`).

Interactive Swagger UI documentation is available locally at:
`http://127.0.0.1:8000/docs`

---

## 1. Unified Response Formats

### Success Response Envelope (JSON)
Most JSON endpoints return a standardized envelope containing `"success": true`:
```json
{
  "success": true,
  "...": "..."
}
```

### Standard Error Response Envelope (JSON)
All errors return consistent HTTP status codes and a structured error object:
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE_STRING",
    "message": "Human-readable explanation of the error."
  }
}
```

---

## 2. API Endpoints

### Endpoint 1: Health Check

- **URL**: `/api/health`
- **Method**: `GET`
- **Purpose**: Verifies that the backend server is operational and returns version metadata.
- **Request Parameters**: None.
- **Response**: `200 OK` (JSON)
  ```json
  {
    "status": "healthy",
    "application": "CryptAudio",
    "version": "1.0.0"
  }
  ```

---

### Endpoint 2: Audio Inspection

- **URL**: `/api/audio/inspect`
- **Method**: `POST`
- **Purpose**: Inspects an uploaded PCM WAV file, extracts container properties, and calculates raw LSB steganographic capacity.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): The WAV audio file to inspect. Maximum size: 50 MB.
- **Success Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "filename": "carrier.wav",
    "audio": {
      "duration_seconds": 2.5000,
      "sample_rate": 44100,
      "channels": 2,
      "sample_width": 2,
      "bit_depth": 16,
      "frame_count": 110250,
      "audio_format": "PCM"
    },
    "capacity": {
      "total_samples": 220500,
      "raw_capacity_bits": 220500,
      "raw_capacity_bytes": 27562
    }
  }
  ```
- **Error Responses**:
  - `400 Bad Request` (`code: EMPTY_FILE`): File is 0 bytes.
  - `400 Bad Request` (`code: INVALID_WAV`): File is not a valid RIFF/WAVE container or has corrupted chunks.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): File exceeds 50 MB (52,428,800 bytes).
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Audio format is non-PCM (e.g. IEEE float, MP3) or channels > 2.

---

### Endpoint 3: Encrypt and Embed Message

- **URL**: `/api/embed`
- **Method**: `POST`
- **Purpose**: Encrypts a secret message using AES-256-GCM (PBKDF2-HMAC-SHA256, 600,000 iterations) and embeds it into the carrier WAV audio using sample-level LSB steganography.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): The carrier PCM WAV file. Maximum size: 50 MB.
  - `message` (Form string, required): Secret plaintext message to conceal.
  - `password` (Form string, required): Passphrase for PBKDF2 encryption key derivation.
- **Success Response**: `200 OK` (Binary Stream `audio/wav`)
  - **Body**: Complete binary stego WAV file stream.
  - **Headers**:
    - `Content-Disposition`: `attachment; filename="<sanitized_stem>_stego.wav"`
    - `Content-Type`: `audio/wav`
    - `X-Payload-Size-Bytes`: Byte length of encrypted crypto payload ($N + 49$).
    - `X-Framed-Size-Bytes`: Total bytes embedded including 13-byte LSB framing ($N + 62$).
    - `X-Utilization-Percent`: Percentage of carrier sample capacity utilized.
- **Error Responses**:
  - `400 Bad Request` (`code: INVALID_MESSAGE`): Message is empty or whitespace.
  - `400 Bad Request` (`code: INVALID_PASSWORD`): Password is empty.
  - `400 Bad Request` (`code: CAPACITY_EXCEEDED`): Carrier audio has fewer samples than required bits ($(N+62) \times 8$).
  - `400 Bad Request` (`code: EMPTY_FILE`): Carrier file is 0 bytes.
  - `400 Bad Request` (`code: INVALID_WAV`): Carrier file is not a valid PCM WAV container.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): Carrier file exceeds 50 MB.
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Carrier is IEEE float or compressed codec.

---

### Endpoint 4: Extract and Decrypt Message

- **URL**: `/api/extract`
- **Method**: `POST`
- **Purpose**: Extracts concealed binary payload from sample LSBs, verifies framing CRC32, and performs authenticated AES-256-GCM decryption with the provided password.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): The stego PCM WAV file. Maximum size: 50 MB.
  - `password` (Form string, required): Secret passphrase for key derivation and decryption.
- **Success Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "message": "Recovered plaintext message content"
  }
  ```
- **Error Responses**:
  - `400 Bad Request` (`code: INVALID_PASSWORD`): Password field is empty.
  - `400 Bad Request` (`code: INVALID_WAV`): File is not a valid WAV container.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): Upload exceeds 50 MB.
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Non-PCM WAV format.
  - `422 Unprocessable Content` (`code: AUTHENTICATION_FAILED`): Password incorrect or GCM tag verification failed (tampered ciphertext). Zero plaintext leaked.
  - `422 Unprocessable Content` (`code: NO_STEGO_PAYLOAD`): Audio does not contain valid `CSLB` framing header.
  - `422 Unprocessable Content` (`code: PAYLOAD_CORRUPTED`): Framing header failed CRC32 integrity check.

---

### Endpoint 5: Audio Quality Analysis

- **URL**: `/api/analyze`
- **Method**: `POST`
- **Purpose**: Compares the original carrier WAV and the stego WAV to calculate objective distortion metrics.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `original_file` (UploadFile, required): Original carrier WAV file.
  - `stego_file` (UploadFile, required): Stego WAV file to evaluate against original.
- **Constraints**: Combined upload size (`original_file` + `stego_file`) cannot exceed 100 MB (`MAX_COMBINED_UPLOAD_BYTES = 104,857,600`).
- **Success Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "analysis": {
      "mse": 0.0975,
      "snr_db": 95.654321,
      "psnr_db": 100.441234,
      "correlation": 1.0,
      "quality_assessment": "Excellent",
      "sample_rate": 44100,
      "channels": 1,
      "bit_depth": 16,
      "total_samples": 110250,
      "modified_samples": 880,
      "max_absolute_difference": 1.0,
      "average_absolute_difference": 0.007982
    }
  }
  ```
- **Error Responses**:
  - `400 Bad Request` (`code: EMPTY_FILE`): Either file is 0 bytes.
  - `400 Bad Request` (`code: INVALID_WAV`): Either file is malformed.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): Combined upload exceeds 100 MB.
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Either file is non-PCM.
  - `422 Unprocessable Content` (`code: INCOMPATIBLE_AUDIO`): Files have mismatched sample rates, channels, bit depths, or sample lengths.
