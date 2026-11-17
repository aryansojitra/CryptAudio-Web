"""
app/api/routes.py
CryptAudio Web — API Router & Processing Endpoints

Provides secure REST endpoints for:
- Health check: GET /api/health
- Audio inspection: POST /api/audio/inspect
- Secret message embedding: POST /api/embed
- Secret message extraction: POST /api/extract
- Audio quality evaluation: POST /api/analyze
"""

from __future__ import annotations

import logging
import math
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

from app.audio.wav_handler import (
    AudioError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    calculate_capacity,
    inspect_wav,
)
from app.core.config import settings
from app.evaluation.audio_quality import (
    AudioEvaluationError,
    IncompatibleAudioError,
    UnsupportedEvaluationFormatError,
    compare_audio,
)
from app.services.cryptaudio_service import (
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    ServiceError,
    embed_message,
    extract_message,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["API"])


# ---------------------------------------------------------------------------
# Helper: Standard JSON Error Response
# ---------------------------------------------------------------------------

def api_error_response(
    status_code: int,
    code: str,
    message: str,
) -> JSONResponse:
    """Format consistent error responses as specified in project standards."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


def cleanup_files(*paths: Path | str | None) -> None:
    """Safely remove temporary files without raising exceptions."""
    for p in paths:
        if p:
            try:
                Path(p).unlink(missing_ok=True)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Helper: Safe Upload Handler with Streaming Size Limits
# ---------------------------------------------------------------------------

async def save_upload_safely(
    upload_file: UploadFile,
    max_bytes: int | None = None,
    prefix: str = "upload",
) -> Path:
    """
    Safely stream an UploadFile to a unique temporary file on disk while
    enforcing maximum byte ceilings and rejecting empty files.

    Guarantees:
    - Never uses user-supplied filenames on disk (prevents path traversal).
    - Enforces max upload size via streaming chunks (prevents memory exhaustion).
    - Cleans up incomplete files if limit is exceeded.
    - Rejects 0-byte uploads.
    """
    limit = max_bytes if max_bytes is not None else settings.MAX_UPLOAD_BYTES
    temp_path = settings.TEMP_DIR / f"{prefix}_{uuid.uuid4().hex}.wav"
    total_bytes = 0

    try:
        with open(temp_path, "wb") as f_out:
            while True:
                chunk = await upload_file.read(65536)  # 64 KB chunk
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > limit:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail={
                            "code": "FILE_TOO_LARGE",
                            "message": f"Uploaded file exceeds maximum allowed size of {limit} bytes.",
                        },
                    )
                f_out.write(chunk)
    except Exception:
        cleanup_files(temp_path)
        raise

    if total_bytes == 0:
        cleanup_files(temp_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "EMPTY_FILE",
                "message": "Uploaded audio file is empty (0 bytes).",
            },
        )

    return temp_path


# ---------------------------------------------------------------------------
# 1. Health Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    summary="Health check",
    description="Returns the operational status of the backend application.",
)
async def health_check() -> JSONResponse:
    """GET /api/health — Preserves Phase 2 specification."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "healthy",
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
        },
    )


# ---------------------------------------------------------------------------
# 2. Audio Inspection Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/audio/inspect",
    summary="Inspect audio WAV file",
    description="Inspects an uploaded WAV file and returns its technical metadata and LSB capacity.",
)
async def inspect_audio(file: UploadFile = File(...)) -> JSONResponse:
    """
    POST /api/audio/inspect

    Accepts a multipart/form-data WAV file upload.
    Returns:
        JSON with audio duration, sample rate, channels, bit depth, format,
        and theoretical raw LSB capacity.
    """
    temp_file: Path | None = None
    try:
        temp_file = await save_upload_safely(file, prefix="inspect")

        # Validate and inspect using Phase 4 modules
        info = inspect_wav(temp_file)
        cap = calculate_capacity(temp_file)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "filename": file.filename or "audio.wav",
                "audio": {
                    "duration_seconds": info.duration_seconds,
                    "sample_rate": info.sample_rate,
                    "channels": info.channels,
                    "sample_width": info.sample_width,
                    "bit_depth": info.bit_depth,
                    "frame_count": info.frame_count,
                    "audio_format": info.audio_format,
                },
                "capacity": {
                    "total_samples": cap.total_samples,
                    "raw_capacity_bits": cap.raw_capacity_bits,
                    "raw_capacity_bytes": cap.raw_capacity_bytes,
                },
            },
        )
    except HTTPException as exc:
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except AudioError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "AUDIO_ERROR", str(exc))
    finally:
        cleanup_files(temp_file)


# ---------------------------------------------------------------------------
# 3. Message Embedding Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/embed",
    summary="Encrypt and embed secret message",
    description="Encrypts a secret message with AES-256-GCM and embeds it into sample LSBs of an uploaded WAV file.",
)
async def embed(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    message: str = Form(""),
    password: str = Form(""),
) -> Any:
    """
    POST /api/embed

    Accepts multipart/form-data:
    - file: Carrier WAV file
    - message: Plaintext secret message
    - password: Secret passphrase

    Returns:
        Stego WAV file as a streaming download attachment with cleanup on completion.
    """
    # Validate non-empty fields
    if not message or len(message.strip()) == 0:
        return api_error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_MESSAGE",
            "Secret message cannot be empty.",
        )

    if not password or len(password) == 0:
        return api_error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_PASSWORD",
            "Password cannot be empty.",
        )

    temp_in: Path | None = None
    temp_out: Path | None = None

    try:
        temp_in = await save_upload_safely(file, prefix="carrier")
        temp_out = settings.TEMP_DIR / f"stego_{uuid.uuid4().hex}.wav"

        # Embed using Phase 6 centralized service
        result = embed_message(
            input_wav=temp_in,
            output_wav=temp_out,
            message=message,
            password=password,
        )

        # Attach background task to clean up temporary files AFTER streaming is complete
        background_tasks.add_task(cleanup_files, temp_in, temp_out)

        out_filename = "stego.wav"
        if file.filename:
            stem = Path(file.filename).stem
            out_filename = f"{stem}_stego.wav"

        headers = {
            "X-Payload-Size-Bytes": str(result.payload_size_bytes),
            "X-Framed-Size-Bytes": str(result.framed_size_bytes),
            "X-Utilization-Percent": str(result.utilization_percent),
        }

        return FileResponse(
            path=str(temp_out),
            media_type="audio/wav",
            filename=out_filename,
            headers=headers,
            background=background_tasks,
        )

    except HTTPException as exc:
        cleanup_files(temp_in, temp_out)
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except InsufficientAudioCapacityError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_422_UNPROCESSABLE_ENTITY, "INSUFFICIENT_CAPACITY", str(exc))
    except UnsupportedAudioFormatError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except MessageEmbeddingError as exc:
        cleanup_files(temp_in, temp_out)
        err_str = str(exc).lower()
        if "invalid carrier wav" in err_str or "wav" in err_str:
            return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
        return api_error_response(status.HTTP_422_UNPROCESSABLE_ENTITY, "EMBEDDING_FAILED", str(exc))
    except Exception as exc:
        cleanup_files(temp_in, temp_out)
        logger.exception("Unexpected error in /api/embed")
        return api_error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.")


# ---------------------------------------------------------------------------
# 4. Message Extraction Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/extract",
    summary="Extract and decrypt secret message",
    description="Extracts and decrypts a secret message from an uploaded stego WAV file.",
)
async def extract(
    file: UploadFile = File(...),
    password: str = Form(""),
) -> JSONResponse:
    """
    POST /api/extract

    Accepts multipart/form-data:
    - file: Stego WAV file
    - password: Secret passphrase

    Returns:
        JSON containing the recovered plaintext message.
    """
    if not password or len(password) == 0:
        return api_error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_PASSWORD",
            "Password cannot be empty.",
        )

    temp_stego: Path | None = None
    try:
        temp_stego = await save_upload_safely(file, prefix="extract")

        # Extract using Phase 6 centralized service
        secret_message = extract_message(stego_wav=temp_stego, password=password)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "message": secret_message,
            },
        )
    except HTTPException as exc:
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except MessageExtractionError as exc:
        err_str = str(exc)
        if "authentication or decryption failed" in err_str.lower():
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "AUTHENTICATION_FAILED",
                "Authentication or decryption failed: incorrect password or tampered payload.",
            )
        elif "corrupted" in err_str.lower():
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "PAYLOAD_CORRUPTED",
                "Extracted payload failed integrity checks (corrupted data).",
            )
        elif "no valid hidden payload" in err_str.lower():
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "NO_STEGO_PAYLOAD",
                "The audio file does not contain a valid hidden CryptAudio payload.",
            )
        elif "invalid stego audio file" in err_str.lower():
            return api_error_response(
                status.HTTP_400_BAD_REQUEST,
                "INVALID_WAV",
                str(exc),
            )
        return api_error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "EXTRACTION_FAILED",
            str(exc),
        )
    finally:
        cleanup_files(temp_stego)


# ---------------------------------------------------------------------------
# 5. Audio Quality Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    summary="Compare original and stego audio",
    description="Compares original and stego WAV files using numerical distortion metrics (MSE, SNR, PSNR, correlation).",
)
async def analyze(
    original_file: UploadFile = File(...),
    stego_file: UploadFile = File(...),
) -> JSONResponse:
    """
    POST /api/analyze

    Accepts multipart/form-data:
    - original_file: Original carrier WAV
    - stego_file: Stego WAV

    Returns:
        JSON with MSE, SNR (dB), PSNR (dB), Pearson correlation, sample difference stats,
        and qualitative assessment.
    """
    temp_orig: Path | None = None
    temp_stego: Path | None = None

    try:
        temp_orig = await save_upload_safely(original_file, prefix="orig_cmp")
        orig_size = temp_orig.stat().st_size

        # Check remaining allowed combined capacity
        remaining_budget = settings.MAX_COMBINED_UPLOAD_BYTES - orig_size
        if remaining_budget <= 0:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={
                    "code": "FILE_TOO_LARGE",
                    "message": "Combined upload size exceeds the maximum allowed limit.",
                },
            )

        temp_stego = await save_upload_safely(
            stego_file,
            max_bytes=min(settings.MAX_UPLOAD_BYTES, remaining_budget),
            prefix="stego_cmp",
        )

        # Run comparison using Phase 7 module
        report = compare_audio(original_wav=temp_orig, stego_wav=temp_stego)

        # Safe serialization of infinite / NaN float values for standard RFC 8259 JSON
        def safe_float(val: float | None) -> Any:
            if val is None or math.isnan(val):
                return None
            if math.isinf(val):
                return "Infinity" if val > 0 else "-Infinity"
            return round(val, 6)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "analysis": {
                    "mse": safe_float(report.mse),
                    "snr_db": safe_float(report.snr_db),
                    "psnr_db": safe_float(report.psnr_db),
                    "correlation": safe_float(report.correlation),
                    "quality_assessment": report.quality_assessment,
                    "sample_rate": report.sample_rate,
                    "channels": report.channels,
                    "bit_depth": report.bit_depth,
                    "total_samples": report.total_samples,
                    "modified_samples": report.modified_samples,
                    "max_absolute_difference": safe_float(report.max_absolute_difference),
                    "average_absolute_difference": safe_float(report.average_absolute_difference),
                },
            },
        )
    except HTTPException as exc:
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except IncompatibleAudioError as exc:
        return api_error_response(status.HTTP_422_UNPROCESSABLE_ENTITY, "INCOMPATIBLE_AUDIO", str(exc))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except AudioEvaluationError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "EVALUATION_ERROR", str(exc))
    finally:
        cleanup_files(temp_orig, temp_stego)
