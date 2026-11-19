# CryptAudio-Web — REST API Documentation (v1.0.0 Release)

This document provides the complete technical specification for all backend REST endpoints provided by CryptAudio-Web.

All application endpoints are served on `http://127.0.0.1:8000` (or `0.0.0.0:$PORT` on cloud containers) with strict anti-caching headers (`Cache-Control: no-store`) and Content Security Policy (`script-src 'self'`).

Interactive Swagger UI documentation is available at:
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

### Endpoint 2: List Available Steganography Algorithms
- **URL**: `/api/algorithms`
- **Method**: `GET`
- **Purpose**: Returns the list of registered steganography algorithms with parameter schemas, descriptions, and ranges.
- **Request Parameters**: None.
- **Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "algorithms": [
      {
        "id": "lsb",
        "name": "Least Significant Bit (LSB)",
        "domain": "time",
        "description": "Standard 1-bit per sample spatial/time domain substitution",
        "parameters": {}
      },
      {
        "id": "dwt_dct_qim",
        "name": "DWT-DCT-QIM",
        "domain": "transform",
        "description": "Discrete Wavelet + Discrete Cosine Transform with Quantization Index Modulation",
        "parameters": {
          "delta": {
            "type": "float",
            "default": 32.0,
            "min": 1.0,
            "max": 256.0,
            "description": "Quantization step size"
          }
        }
      },
      {
        "id": "echo",
        "name": "Echo Hiding",
        "domain": "acoustic",
        "description": "Time-domain artificial micro-echo delay encoding with cepstral deconvolution",
        "parameters": {
          "alpha": {
            "type": "float",
            "default": 0.08,
            "min": 0.01,
            "max": 0.5,
            "description": "Echo attenuation amplitude"
          }
        }
      }
    ]
  }
  ```

---

### Endpoint 3: Audio Inspection
- **URL**: `/api/audio/inspect`
- **Method**: `POST`
- **Purpose**: Inspects an uploaded PCM WAV file, extracts container properties, raw capacity, and steganography signature inspection.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): The WAV audio file to inspect. Maximum size: 50 MB.
  - `algorithm` (Form string, optional): Algorithm identifier to inspect against (`lsb`, `dwt_dct_qim`, `echo`).
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
    },
    "stego_inspection": {
      "has_stego_signature": false,
      "detected_algorithm": null
    },
    "available_algorithms": [...]
  }
  ```
- **Error Responses**:
  - `400 Bad Request` (`code: EMPTY_FILE`): File is 0 bytes.
  - `400 Bad Request` (`code: INVALID_WAV`): File is not a valid RIFF/WAVE container.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): File exceeds 50 MB.
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Audio format is non-PCM.

---

### Endpoint 4: Authoritative Capacity Check
- **URL**: `/api/capacity`
- **Method**: `POST`
- **Purpose**: Calculates authoritative capacity for an uploaded WAV file, secret message, and chosen algorithm.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): Carrier WAV file.
  - `message` (Form string, optional): Secret plaintext message (default: empty string).
  - `algorithm` (Form string, optional): Algorithm name (`lsb`, `dwt_dct_qim`, `echo`; default: `lsb`).
  - `delta` (Form float, optional): Delta parameter for DWT-DCT-QIM.
  - `alpha` (Form float, optional): Alpha parameter for Echo Hiding.
- **Success Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "algorithm": "lsb",
    "carrier_samples": 220500,
    "raw_capacity_bytes": 27562,
    "usable_capacity_bytes": 27495,
    "required_bytes": 105,
    "can_fit": true,
    "utilization_percent": 0.38
  }
  ```

---

### Endpoint 5: Encrypt and Embed Message
- **URL**: `/api/embed`
- **Method**: `POST`
- **Purpose**: Encrypts secret message using AES-256-GCM (PBKDF2-HMAC-SHA256, 600,000 iterations) and embeds it into carrier WAV audio using selected steganography algorithm.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): Carrier PCM WAV file. Maximum size: 50 MB.
  - `message` (Form string, required): Secret plaintext message.
  - `password` (Form string, required): Passphrase for PBKDF2 encryption key derivation.
  - `algorithm` (Form string, optional): Algorithm (`lsb`, `dwt_dct_qim`, `echo`; default: `lsb`).
  - `delta` (Form float, optional): Quantization delta for DWT-DCT-QIM.
  - `alpha` (Form float, optional): Attenuation alpha for Echo Hiding.
- **Success Response**: `200 OK` (Binary Stream `audio/wav`)
  - **Headers**:
    - `Content-Disposition`: `attachment; filename="<sanitized_stem>_stego.wav"`
    - `Content-Type`: `audio/wav`
    - `X-Stego-Algorithm`: Active algorithm ID.
    - `X-Payload-Size-Bytes`: Byte length of encrypted crypto payload.
    - `X-Framed-Size-Bytes`: Total bytes embedded including CSMA envelope.
    - `X-Utilization-Percent`: Percentage of carrier sample capacity utilized.
- **Error Responses**:
  - `400 Bad Request` (`code: INVALID_MESSAGE`): Message is empty.
  - `400 Bad Request` (`code: INVALID_PASSWORD`): Password is empty.
  - `400 Bad Request` (`code: INVALID_ALGORITHM`): Unknown algorithm identifier.
  - `422 Unprocessable Content` (`code: INSUFFICIENT_CAPACITY`): Carrier has fewer samples than required.
  - `413 Content Too Large` (`code: FILE_TOO_LARGE`): File exceeds 50 MB.
  - `415 Unsupported Media Type` (`code: UNSUPPORTED_FORMAT`): Non-PCM format.

---

### Endpoint 6: Extract and Decrypt Message
- **URL**: `/api/extract`
- **Method**: `POST`
- **Purpose**: Extracts concealed payload, verifies CRC32 framing, and decrypts with AES-256-GCM.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `file` (UploadFile, required): Stego PCM WAV file. Maximum size: 50 MB.
  - `password` (Form string, required): Secret passphrase for decryption.
  - `algorithm` (Form string, optional): Algorithm (`lsb`, `dwt_dct_qim`, `echo`, or `auto`; default: `auto`).
  - `delta` (Form float, optional): Delta parameter if explicitly specifying `dwt_dct_qim`.
  - `alpha` (Form float, optional): Alpha parameter if explicitly specifying `echo`.
- **Success Response**: `200 OK` (JSON)
  ```json
  {
    "success": true,
    "message": "Recovered plaintext message content",
    "algorithm": "lsb",
    "extracted_bytes": 105
  }
  ```
- **Error Responses**:
  - `400 Bad Request` (`code: INVALID_PASSWORD`): Password field is empty.
  - `422 Unprocessable Content` (`code: AUTHENTICATION_FAILED`): Password incorrect or GCM tag verification failed (tampered ciphertext). Zero plaintext leaked.
  - `422 Unprocessable Content` (`code: NO_STEGO_PAYLOAD`): Audio does not contain valid CSMA/CSLB framing.
  - `422 Unprocessable Content` (`code: PAYLOAD_CORRUPTED`): Framing header failed CRC32 integrity check.

---

### Endpoint 7: Audio Quality Analysis
- **URL**: `/api/analyze`
- **Method**: `POST`
- **Purpose**: Computes objective numerical distortion metrics (MSE, SNR, PSNR, Pearson Correlation) between original carrier and stego audio files.
- **Content-Type**: `multipart/form-data`
- **Request Fields**:
  - `original_file` (UploadFile, required): Original carrier WAV file.
  - `stego_file` (UploadFile, required): Stego WAV file to evaluate.
- **Constraints**: Combined upload size cannot exceed 100 MB.
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
