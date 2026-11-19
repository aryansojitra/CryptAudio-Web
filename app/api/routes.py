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
import re
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
    CapacityEstimate,
    EmbedMessageResult,
    ExtractMessageResult,
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    ServiceError,
    embed_message,
    estimate_capacity,
    extract_message,
    extract_message_detailed,
    inspect_stego_metadata,
)
from app.steganography.base import (
    AlgorithmRegistryError,
    AudioFormatIncompatibleError,
    CapacityExceededError,
    CorruptedPayloadError,
    HeaderNotFoundError,
    StegoAlgorithmError,
    SynchronizationError,
    UnsupportedParameterError,
)
from app.steganography.registry import get_registry

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


def validate_stego_options(
    algorithm: str | None,
    delta: float | None = None,
    alpha: float | None = None,
    allow_auto: bool = False,
) -> tuple[str | None, dict[str, Any]]:
    """
    Strictly validate algorithm-specific parameters according to canonical rules.

    Rules:
    - When algorithm is None or empty:
      - If allow_auto=False, defaults to 'lsb'.
      - If allow_auto=True, defaults to automatic detection (None, {}).
    - When algorithm='auto' explicitly:
      - If allow_auto=True, returns (None, {}).
      - If allow_auto=False, raises UnsupportedParameterError ('auto' supported only for extraction).
    - Automatic extraction rejects any custom 'delta' or 'alpha'.
    - DWT-DCT-QIM accepts only 'delta' in {8.0, 16.0, 32.0, 64.0}.
    - Echo Hiding accepts only 'alpha' in [0.001, 0.50].
    - LSB accepts only framing options (rejects 'delta' and 'alpha').
    - Unsupported or irrelevant parameters raise UnsupportedParameterError.

    Returns:
        tuple[resolved_algorithm, options_dict]
    """
    clean_algo = algorithm.strip().lower() if algorithm is not None and str(algorithm).strip() else None

    # Handle explicit "auto"
    if clean_algo == "auto":
        if not allow_auto:
            raise UnsupportedParameterError(
                "Automatic algorithm selection ('auto') is only supported during extraction, "
                "not during embedding or capacity estimation. Please specify a concrete algorithm ('lsb', 'dwt_dct_qim', or 'echo')."
            )
        if delta is not None:
            raise UnsupportedParameterError(
                "Parameter 'delta' cannot be supplied during automatic algorithm detection. "
                "Automatic detection uses each detected algorithm's default extraction parameters."
            )
        if alpha is not None:
            raise UnsupportedParameterError(
                "Parameter 'alpha' cannot be supplied during automatic algorithm detection. "
                "Automatic detection uses each detected algorithm's default extraction parameters."
            )
        return None, {}

    # Handle omitted / None / empty algorithm
    if clean_algo is None:
        if not allow_auto:
            clean_algo = "lsb"
        else:
            if delta is not None:
                raise UnsupportedParameterError(
                    "Parameter 'delta' cannot be supplied during automatic algorithm detection. "
                    "Automatic detection uses each detected algorithm's default extraction parameters."
                )
            if alpha is not None:
                raise UnsupportedParameterError(
                    "Parameter 'alpha' cannot be supplied during automatic algorithm detection. "
                    "Automatic detection uses each detected algorithm's default extraction parameters."
                )
            return None, {}

    # Explicit algorithm
    if clean_algo == "lsb":
        if delta is not None:
            raise UnsupportedParameterError(
                "Parameter 'delta' is not supported by LSB steganography."
            )
        if alpha is not None:
            raise UnsupportedParameterError(
                "Parameter 'alpha' is not supported by LSB steganography."
            )
        return "lsb", {}

    elif clean_algo == "legacy_cslb":
        if delta is not None:
            raise UnsupportedParameterError(
                "Parameter 'delta' is not supported by legacy CSLB steganography."
            )
        if alpha is not None:
            raise UnsupportedParameterError(
                "Parameter 'alpha' is not supported by legacy CSLB steganography."
            )
        return "legacy_cslb", {"framing": "legacy_cslb"}

    elif clean_algo == "dwt_dct_qim":
        if alpha is not None:
            raise UnsupportedParameterError(
                "Parameter 'alpha' is not supported by DWT-DCT-QIM steganography."
            )
        options = {}
        if delta is not None:
            if delta not in (8.0, 16.0, 32.0, 64.0):
                raise UnsupportedParameterError(
                    f"Unsupported QIM quantization step: {delta}. Supported steps: [8.0, 16.0, 32.0, 64.0]."
                )
            options["delta"] = float(delta)
        return "dwt_dct_qim", options

    elif clean_algo == "echo":
        if delta is not None:
            raise UnsupportedParameterError(
                "Parameter 'delta' is not supported by Echo Hiding steganography."
            )
        options = {}
        if alpha is not None:
            if not (0.001 <= float(alpha) <= 0.50):
                raise UnsupportedParameterError(
                    f"Echo amplitude alpha must be in range [0.001, 0.50], got {alpha}."
                )
            options["alpha"] = float(alpha)
        return "echo", options

    else:
        # Check against registry
        reg = get_registry(include_echo=True)
        if not reg.is_registered(clean_algo):
            raise AlgorithmRegistryError(
                f"Unsupported steganography algorithm '{algorithm}'."
            )
        return clean_algo, {}


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
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
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
# 1. Health & Discovery Endpoints
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


@router.get(
    "/algorithms",
    summary="List supported steganography algorithms",
    description="Returns metadata and capabilities for all registered audio steganography algorithms.",
)
async def list_algorithms() -> JSONResponse:
    """
    GET /api/algorithms
    
    Returns:
        JSON list of available steganography algorithms (LSB, DWT-DCT-QIM, Echo Hiding).
    """
    reg = get_registry(include_echo=True)
    descriptors = reg.list_available()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "success": True,
            "algorithms": [d.to_dict() for d in descriptors],
        },
    )


# ---------------------------------------------------------------------------
# 2. Audio Inspection & Capacity Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/audio/inspect",
    summary="Inspect audio WAV file",
    description="Inspects an uploaded WAV file, returning technical audio metadata, raw capacity, and steganography signature inspection.",
)
async def inspect_audio(
    file: UploadFile = File(...),
    algorithm: str | None = Form(None),
) -> JSONResponse:
    """
    POST /api/audio/inspect

    Accepts a multipart/form-data WAV file upload and optional algorithm filter.
    Returns:
        JSON with audio duration, sample rate, channels, bit depth, format,
        raw capacity, and steganographic inspection summary.
    """
    temp_file: Path | None = None
    try:
        temp_file = await save_upload_safely(file, prefix="inspect")

        # Validate and inspect audio format
        info = inspect_wav(temp_file)
        cap = calculate_capacity(temp_file)

        # Multi-algorithm steganography inspection
        stego_inspection = inspect_stego_metadata(temp_file, algorithm=algorithm)

        reg = get_registry(include_echo=True)
        available_algorithms = [d.to_dict() for d in reg.list_available()]

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
                "stego_inspection": stego_inspection,
                "available_algorithms": available_algorithms,
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


@router.post(
    "/capacity",
    summary="Estimate carrier capacity for message and algorithm",
    description="Calculates algorithm-specific capacity for an uploaded WAV file and message.",
)
async def check_capacity(
    file: UploadFile = File(...),
    message: str = Form(""),
    algorithm: str = Form("lsb"),
    delta: float | None = Form(None),
    alpha: float | None = Form(None),
) -> JSONResponse:
    """
    POST /api/capacity

    Accepts multipart/form-data:
    - file: Carrier WAV file
    - message: Target secret message string
    - algorithm: Algorithm to evaluate ('lsb', 'dwt_dct_qim', 'echo', 'legacy_cslb')
    - delta: Optional QIM step size (only for DWT-DCT-QIM)
    - alpha: Optional echo amplitude (only for Echo Hiding)

    Returns:
        JSON with capacity metrics, utilization, and feasibility verdict.
    """
    if not message or len(message.strip()) == 0:
        return api_error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_MESSAGE",
            "Secret message cannot be empty.",
        )

    try:
        clean_algo, options = validate_stego_options(algorithm, delta, alpha, allow_auto=False)
    except UnsupportedParameterError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except AlgorithmRegistryError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "UNKNOWN_ALGORITHM", str(exc))

    temp_file: Path | None = None
    try:
        temp_file = await save_upload_safely(file, prefix="capacity")
        est = estimate_capacity(
            input_wav=temp_file,
            message=message,
            algorithm=clean_algo,
            **options,
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "can_fit": est.can_fit,
                "algorithm": est.algorithm_id,
                "message_utf8_bytes": est.message_utf8_bytes,
                "estimated_crypto_bytes": est.estimated_crypto_bytes,
                "framed_payload_bytes": est.framed_payload_bytes,
                "required_bits": est.required_bits,
                "available_bits": est.available_bits,
                "utilization_percent": est.utilization_percent,
                "bits_per_sample": est.bits_per_sample,
                "recommended_min_duration_sec": est.recommended_min_duration_sec,
            },
        )
    except HTTPException as exc:
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except AudioFormatIncompatibleError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except UnsupportedParameterError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except MessageEmbeddingError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "CAPACITY_ERROR", str(exc))
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
    description="Encrypts a secret message with AES-256-GCM and embeds it into carrier WAV audio using the selected algorithm.",
)
async def embed(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    message: str = Form(""),
    password: str = Form(""),
    algorithm: str = Form("lsb"),
    delta: float | None = Form(None),
    alpha: float | None = Form(None),
) -> Any:
    """
    POST /api/embed

    Accepts multipart/form-data:
    - file: Carrier WAV file
    - message: Plaintext secret message
    - password: Secret passphrase
    - algorithm: Steganography algorithm ('lsb', 'dwt_dct_qim', 'echo', default 'lsb')
    - delta: Optional QIM step size (for DWT-DCT-QIM)
    - alpha: Optional echo amplitude (for Echo Hiding)

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

    # Validate algorithm identifier and options
    try:
        clean_algo, options = validate_stego_options(algorithm, delta, alpha, allow_auto=False)
    except UnsupportedParameterError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except AlgorithmRegistryError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "UNKNOWN_ALGORITHM", str(exc))

    temp_in: Path | None = None
    temp_out: Path | None = None

    try:
        temp_in = await save_upload_safely(file, prefix="carrier")
        temp_out = settings.TEMP_DIR / f"stego_{uuid.uuid4().hex}.wav"

        # Embed using Centralized Service
        result = embed_message(
            input_wav=temp_in,
            output_wav=temp_out,
            message=message,
            password=password,
            algorithm=clean_algo,
            **options,
        )

        # Attach background task to clean up temporary files AFTER streaming is complete
        background_tasks.add_task(cleanup_files, temp_in, temp_out)

        out_filename = "stego.wav"
        if file.filename:
            raw_stem = Path(file.filename).stem
            clean_stem = re.sub(r"[^\w\-.]", "_", raw_stem).strip("._")
            out_filename = f"{clean_stem or 'audio'}_stego.wav"

        headers = {
            "X-Payload-Size-Bytes": str(result.payload_size_bytes),
            "X-Framed-Size-Bytes": str(result.framed_size_bytes),
            "X-Utilization-Percent": str(result.utilization_percent),
            "X-Stego-Algorithm": str(result.algorithm_id),
            "X-Required-Bits": str(result.required_capacity_bits),
            "X-Available-Bits": str(result.available_capacity_bits),
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
        return api_error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "INSUFFICIENT_CAPACITY", str(exc))
    except CapacityExceededError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "INSUFFICIENT_CAPACITY", str(exc))
    except UnsupportedParameterError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except AlgorithmRegistryError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_400_BAD_REQUEST, "UNKNOWN_ALGORITHM", str(exc))
    except UnsupportedAudioFormatError as exc:
        cleanup_files(temp_in, temp_out)
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except AudioFormatIncompatibleError as exc:
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
        if "insufficient capacity" in err_str:
            return api_error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "INSUFFICIENT_CAPACITY", str(exc))
        return api_error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "EMBEDDING_FAILED", str(exc))
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
    description="Extracts and decrypts a secret message from an uploaded stego WAV file with optional algorithm selection.",
)
async def extract(
    file: UploadFile = File(...),
    password: str = Form(""),
    algorithm: str | None = Form(None),
    delta: float | None = Form(None),
    alpha: float | None = Form(None),
) -> JSONResponse:
    """
    POST /api/extract

    Accepts multipart/form-data:
    - file: Stego WAV file
    - password: Secret passphrase
    - algorithm: Optional algorithm override ('lsb', 'dwt_dct_qim', 'echo', or 'auto')
    - delta: Optional QIM step size override (for DWT-DCT-QIM)
    - alpha: Optional echo amplitude override (for Echo Hiding)

    Returns:
        JSON containing recovered plaintext message and extraction metadata.
    """
    if not password or len(password) == 0:
        return api_error_response(
            status.HTTP_400_BAD_REQUEST,
            "INVALID_PASSWORD",
            "Password cannot be empty.",
        )

    # Validate explicit algorithm and options if specified
    try:
        clean_algo, options = validate_stego_options(algorithm, delta, alpha, allow_auto=True)
    except UnsupportedParameterError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except AlgorithmRegistryError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "UNKNOWN_ALGORITHM", str(exc))

    temp_stego: Path | None = None
    try:
        temp_stego = await save_upload_safely(file, prefix="extract")

        # Extract using Centralized Service
        result = extract_message_detailed(
            stego_wav=temp_stego,
            password=password,
            algorithm=clean_algo,
            **options,
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "message": result.message,
                "algorithm": result.algorithm_id,
                "payload_size_bytes": result.payload_size_bytes,
                "framing_checksum_verified": result.framing_checksum_verified,
            },
        )
    except HTTPException as exc:
        err_detail = exc.detail if isinstance(exc.detail, dict) else {"code": "BAD_REQUEST", "message": str(exc.detail)}
        return api_error_response(exc.status_code, err_detail.get("code", "ERROR"), err_detail.get("message", "Error"))
    except UnsupportedParameterError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_PARAMETER", str(exc))
    except AlgorithmRegistryError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "UNKNOWN_ALGORITHM", str(exc))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except AudioFormatIncompatibleError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except MessageExtractionError as exc:
        err_str = str(exc)
        if "authentication or decryption failed" in err_str.lower():
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "AUTHENTICATION_FAILED",
                "Authentication or decryption failed: incorrect password or tampered payload.",
            )
        elif "corrupted" in err_str.lower():
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "PAYLOAD_CORRUPTED",
                "Extracted payload failed integrity checks (corrupted data).",
            )
        elif any(phrase in err_str.lower() for phrase in ("no valid hidden payload", "synchronization", "header not found")):
            return api_error_response(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
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
            status.HTTP_422_UNPROCESSABLE_CONTENT,
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
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
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
        return api_error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "INCOMPATIBLE_AUDIO", str(exc))
    except UnsupportedAudioFormatError as exc:
        return api_error_response(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_FORMAT", str(exc))
    except InvalidWavError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "INVALID_WAV", str(exc))
    except AudioEvaluationError as exc:
        return api_error_response(status.HTTP_400_BAD_REQUEST, "EVALUATION_ERROR", str(exc))
    finally:
        cleanup_files(temp_orig, temp_stego)
