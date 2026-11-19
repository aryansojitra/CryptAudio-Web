"""
app/steganography/dwt_dct_qim.py
CryptAudio Web — DWT-DCT + QIM Steganography Engine (Phase M3)

Implements BaseStegoAlgorithm for the transform-domain steganography engine
combining 3-level Discrete Wavelet Transform (Daubechies-4, cD3 sub-band),
8-point Orthonormal Discrete Cosine Transform (DCT-II), and deterministic
Quantization Index Modulation (DM-QIM).

Mathematical Specification (M1.6 / MULTI_ALGORITHM_ARCHITECTURE.md Section 8):
================================================================================
1. Wavelet Decomposition:
   - Family: Daubechies 4 ('db4'), 1D DWT.
   - Decomposition Level: 3.
   - Boundary Mode: 'periodization'.
   - Detail Sub-band: cD3 (approx 2.75 kHz - 5.5 kHz at 44.1 kHz).
   - Audio Chunk Size: M = 1024 samples -> len(cD3) = 128 coefficients.

2. Block DCT-II:
   - Block Size: B = 8 coefficients -> 16 complete blocks per 1024-sample chunk.
   - Orthonormal DCT-II forward: X_k = alpha_k * sum(x_n * cos(pi/B * (n + 0.5) * k))
     where alpha_0 = sqrt(1/B), alpha_k = sqrt(2/B) for k >= 1.
   - Target Coefficient: Mid-frequency index k = 3 (one bit per 8-point DCT block).
   - Capacity: Exactly 16 bits per 1024-sample chunk on Channel 0.

3. Deterministic Quantization Index Modulation (DM-QIM):
   - Quantization step Delta in {8.0, 16.0, 32.0, 64.0}. Default Delta = 32.0.
   - Dithers: d0 = -Delta / 4, d1 = +Delta / 4.
   - Embedding: X' = floor((X - d_b) / Delta + 0.5) * Delta + d_b
     using strict floor-offset half-up rounding: round_half_up(u) = floor(u + 0.5).
   - Extraction: delta_0(Y) = (Y - d0) mod Delta in [0, Delta) using Euclidean floored modulo.
     Decision: Bit 1 if Delta / 4 < delta_0(Y) < 3 * Delta / 4, else Bit 0.
     Exact boundary ties deterministically decode to Bit 0.

4. Synchronization:
   - Canonical 16-bit sequence: 0xF9A9 (1111100110101001).
   - Bipolar mapping: 0 -> -1, 1 -> +1.
   - Normalized correlation detector: R = (1/16) * sum(P[i] * v[i]).
   - Correlation threshold: tau_sync = 0.875 (tolerates at most 1 bit error).
   - Synchronization occupies the first 16 DCT blocks (Chunk 0).

5. Audio Preservation & Channel Policy:
   - Process strictly Channel 0. Channel 1 remains bit-for-bit unchanged.
   - Trailing samples (N mod 1024) are passed through unmodulated.
   - Strict anti-wrap clipping and container sample-width preservation.
"""

from __future__ import annotations

import math
import struct
from typing import Any, Final

import numpy as np
import pywt

from app.audio.wav_handler import WavData
from app.steganography.base import (
    AudioFormatIncompatibleError,
    BaseStegoAlgorithm,
    CapacityExceededError,
    CapacityProfile,
    CorruptedPayloadError,
    DomainType,
    ExtractedPayload,
    HeaderNotFoundError,
    RobustnessEvaluationStatus,
    StegoInspection,
    StegoResult,
    SynchronizationError,
    UnsupportedParameterError,
)
from app.steganography.envelope import (
    ALGO_ID_DWT_DCT_QIM,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_HEADER_STRUCT,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_DWT_DCT_QIM,
    create_csma_envelope,
    parse_csma_envelope,
)
from app.steganography.lsb_engine import bits_to_bytes, bytes_to_bits

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_ID: Final[str] = "dwt_dct_qim"
DISPLAY_NAME: Final[str] = "Discrete Wavelet Transform + Discrete Cosine Transform with QIM"

# Signal processing parameters
WAVELET_NAME: Final[str] = "db4"
DECOMPOSITION_LEVEL: Final[int] = 3
WAVELET_MODE: Final[str] = "periodization"
CHUNK_SIZE: Final[int] = 1024  # M = 1024 samples per chunk
DCT_BLOCK_SIZE: Final[int] = 8  # B = 8 coefficients per block
CD3_COEFF_COUNT: Final[int] = 128  # 1024 / 2^3 = 128
BLOCKS_PER_CHUNK: Final[int] = 16  # 128 / 8 = 16 blocks
BITS_PER_CHUNK: Final[int] = 16  # 1 bit per block
TARGET_COEFF_INDEX: Final[int] = 3  # Mid-frequency coefficient k = 3

# Minimum chunks required to hold the 18-byte (144-bit) CSMA header
# ceil(144 / 16) = 9 chunks = 9 * 1024 = 9216 frames
MIN_HEADER_CHUNKS: Final[int] = 9
MIN_HEADER_FRAMES: Final[int] = MIN_HEADER_CHUNKS * CHUNK_SIZE  # 9216 frames

# Synchronization sequence: 0xF9A9 (1111100110101001)
CANONICAL_SYNC_WORD: Final[int] = SYNC_WORD_DWT_DCT_QIM  # 0xF9A9
CANONICAL_SYNC_BITS: Final[tuple[int, ...]] = (
    1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1
)
CANONICAL_SYNC_BIPOLAR: Final[np.ndarray] = np.array(
    [1.0, 1.0, 1.0, 1.0, 1.0, -1.0, -1.0, 1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0, -1.0, 1.0],
    dtype=np.float64,
)
SYNC_CORRELATION_THRESHOLD: Final[float] = 0.875  # Tolerates at most 1 bit error

# Standardized QIM Quantization Step Codebook (stored in CSMA flags uint16)
QIM_DELTA_CODEBOOK: Final[dict[int, float]] = {
    0: 8.0,
    1: 16.0,
    2: 32.0,  # Proposed default
    3: 64.0,
}
QIM_DELTA_TO_FLAG: Final[dict[float, int]] = {
    8.0: 0,
    16.0: 1,
    32.0: 2,
    64.0: 3,
}
DEFAULT_QIM_DELTA: Final[float] = 32.0
DEFAULT_QIM_FLAG: Final[int] = 2


# ---------------------------------------------------------------------------
# Precomputed 8x8 Orthonormal DCT-II Matrix
# ---------------------------------------------------------------------------

def _build_ortho_dct_matrix(b: int = 8) -> np.ndarray:
    """Precompute the BxB orthonormal DCT-II transformation matrix."""
    k = np.arange(b, dtype=np.float64).reshape(-1, 1)
    n = np.arange(b, dtype=np.float64).reshape(1, -1)
    alpha = np.where(k == 0, np.sqrt(1.0 / b), np.sqrt(2.0 / b))
    return alpha * np.cos((np.pi / b) * (n + 0.5) * k)


DCT_MATRIX_8X8: Final[np.ndarray] = _build_ortho_dct_matrix(DCT_BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Transform & QIM Pure Mathematical Primitives
# ---------------------------------------------------------------------------

def dct2_ortho(blocks: np.ndarray) -> np.ndarray:
    """
    Compute forward orthonormal DCT-II on a 2D array of shape (N, 8).
    
    Energy-preserving transformation conforming strictly to Section 8.2 A.
    """
    return blocks @ DCT_MATRIX_8X8.T


def idct2_ortho(x_blocks: np.ndarray) -> np.ndarray:
    """
    Compute inverse orthonormal DCT on a 2D array of shape (N, 8).
    
    Exact inverse: IDCT(DCT(x)) = x (within machine precision ~1e-15).
    """
    return x_blocks @ DCT_MATRIX_8X8


def round_half_up(u: float | np.ndarray) -> float | np.ndarray:
    """
    Deterministic floor-offset half-up rounding: floor(u + 0.5).
    
    Eliminates cross-platform floating-point round-to-even tie discrepancies.
    """
    return np.floor(u + 0.5)


def qim_embed_scalar(x: float, bit: int, delta: float) -> float:
    """
    Embed one bit into scalar coefficient X using DM-QIM with half-up rounding.
    
    Formula: X' = floor((X - d_b) / delta + 0.5) * delta + d_b
    """
    d_b = -delta / 4.0 if bit == 0 else delta / 4.0
    return float(np.floor((x - d_b) / delta + 0.5) * delta + d_b)


def qim_extract_scalar(y: float, delta: float) -> int:
    """
    Extract one bit from received scalar coefficient Y using Euclidean modulo.
    
    Formula: delta_0 = (Y - d0) mod delta in [0, delta)
    Decision: 1 if delta / 4 < delta_0 < 3 * delta / 4 else 0 (boundary ties decode to 0).
    """
    d0 = -delta / 4.0
    delta0 = (y - d0) % delta  # Python floored modulo produces [0, delta)
    if (delta / 4.0 < delta0 < 3.0 * delta / 4.0):
        return 1
    return 0


def calculate_sync_correlation(candidate_bits: list[int] | np.ndarray) -> float:
    """
    Calculate normalized cross-correlation between 16 candidate bits and canonical PN sequence.
    
    Formula: R = (1/16) * sum(P[i] * v[i]), where v[i] = 2 * bit - 1.
    """
    v = 2.0 * np.asarray(candidate_bits, dtype=np.float64) - 1.0
    return float(np.mean(CANONICAL_SYNC_BIPOLAR * v))


# ---------------------------------------------------------------------------
# Audio Sample Conversion Utilities (16-bit Reference Scale)
# ---------------------------------------------------------------------------

def _get_scale_factor(sample_width: int) -> float:
    """
    Return scale factor mapping integer PCM amplitudes to the 16-bit reference scale
    [-32768.0, 32767.0].
    """
    if sample_width == 1:
        # 8-bit unsigned [0, 255] centered to [-128, 127] scaled by 256.0 to 16-bit reference scale
        return 256.0
    elif sample_width == 2:
        # 16-bit signed [-32768, 32767] is already reference scale
        return 1.0
    elif sample_width == 3:
        # 24-bit signed [-8388608, 8388607] scaled to 16-bit
        return 1.0 / 256.0
    elif sample_width == 4:
        # 32-bit signed [-2147483648, 2147483647] scaled to 16-bit
        return 1.0 / 65536.0
    raise AudioFormatIncompatibleError(f"Unsupported sample width: {sample_width} bytes.")


def decode_pcm_to_ref16(raw_bytes: bytes, sample_width: int) -> np.ndarray:
    """
    Decode raw PCM bytes into a 1D float64 array scaled to 16-bit reference amplitude.
    
    For 8-bit PCM: reference = (unsigned_sample - 128) * 256
    """
    if sample_width == 1:
        u8 = np.frombuffer(raw_bytes, dtype=np.uint8)
        return (u8.astype(np.float64) - 128.0) * 256.0
    elif sample_width == 2:
        i16 = np.frombuffer(raw_bytes, dtype="<i2")
        return i16.astype(np.float64)
    elif sample_width == 3:
        raw = np.frombuffer(raw_bytes, dtype=np.uint8).reshape(-1, 3)
        b0 = raw[:, 0].astype(np.int32)
        b1 = raw[:, 1].astype(np.int32)
        b2 = raw[:, 2].astype(np.int32)
        val = b0 | (b1 << 8) | (b2 << 16)
        val = np.where(val >= 0x800000, val - 0x1000000, val)
        return val.astype(np.float64) / 256.0
    elif sample_width == 4:
        i32 = np.frombuffer(raw_bytes, dtype="<i4")
        return i32.astype(np.float64) / 65536.0
    raise AudioFormatIncompatibleError(f"Unsupported sample width: {sample_width} bytes.")


def encode_ref16_to_pcm(samples_ref16: np.ndarray, sample_width: int) -> bytes:
    """
    Denormalize 16-bit reference amplitude float64 samples to original PCM sample width,
    applying strict anti-wrap clipping.
    
    For 8-bit PCM: unsigned_sample = round(reference / 256) + 128, clipped to [0, 255].
    """
    if sample_width == 1:
        u8 = np.clip(np.round(samples_ref16 / 256.0) + 128.0, 0, 255).astype(np.uint8)
        return u8.tobytes()
    elif sample_width == 2:
        i16 = np.clip(np.round(samples_ref16), -32768, 32767).astype("<i2")
        return i16.tobytes()
    elif sample_width == 3:
        val24 = np.clip(np.round(samples_ref16 * 256.0), -8388608, 8388607).astype(np.int32)
        u24 = np.where(val24 < 0, val24 + 16777216, val24).astype(np.uint32)
        raw = np.empty((len(u24), 3), dtype=np.uint8)
        raw[:, 0] = u24 & 0xFF
        raw[:, 1] = (u24 >> 8) & 0xFF
        raw[:, 2] = (u24 >> 16) & 0xFF
        return raw.tobytes()
    elif sample_width == 4:
        i32 = np.clip(np.round(samples_ref16 * 65536.0), -2147483648, 2147483647).astype("<i4")
        return i32.tobytes()
    raise AudioFormatIncompatibleError(f"Unsupported sample width: {sample_width} bytes.")


def _validate_and_resolve_delta_flags(options: dict[str, Any]) -> tuple[float, int]:
    """
    Validate and resolve QIM quantization step delta and flags codebook index.

    Rejects:
    - None
    - Boolean values
    - Unsupported strings
    - Unsupported floating-point values
    - Unsupported integer values
    - NaN and infinity

    Valid Delta values: {8.0, 16.0, 32.0, 64.0}
    Valid flag indices: {0, 1, 2, 3}
    """
    has_delta = "delta" in options
    has_flags = "flags" in options

    if not has_delta and not has_flags:
        return DEFAULT_QIM_DELTA, DEFAULT_QIM_FLAG

    delta: float | None = None
    flags: int | None = None

    if has_delta:
        raw_delta = options["delta"]
        if raw_delta is None:
            raise UnsupportedParameterError("QIM quantization step (delta) cannot be None.")
        if isinstance(raw_delta, bool):
            raise UnsupportedParameterError("QIM quantization step (delta) cannot be a boolean value.")
        if isinstance(raw_delta, (int, float)):
            if math.isnan(raw_delta) or math.isinf(raw_delta):
                raise UnsupportedParameterError("QIM quantization step (delta) cannot be NaN or infinity.")
            val = float(raw_delta)
            if val not in QIM_DELTA_TO_FLAG:
                raise UnsupportedParameterError(
                    f"Unsupported QIM quantization step: {raw_delta}. "
                    f"Supported steps: {sorted(QIM_DELTA_TO_FLAG.keys())}."
                )
            delta = val
        elif isinstance(raw_delta, str):
            try:
                val = float(raw_delta)
            except ValueError:
                raise UnsupportedParameterError(f"Unsupported string for delta: {raw_delta!r}.")
            if math.isnan(val) or math.isinf(val) or val not in QIM_DELTA_TO_FLAG:
                raise UnsupportedParameterError(
                    f"Unsupported QIM quantization step string: {raw_delta!r}. "
                    f"Supported steps: {sorted(QIM_DELTA_TO_FLAG.keys())}."
                )
            delta = val
        else:
            raise UnsupportedParameterError(
                f"Unsupported type for delta: {type(raw_delta).__name__}. Expected numeric value."
            )

    if has_flags:
        raw_flags = options["flags"]
        if raw_flags is None:
            raise UnsupportedParameterError("QIM codebook flags index cannot be None.")
        if isinstance(raw_flags, bool):
            raise UnsupportedParameterError("QIM codebook flags index cannot be a boolean value.")
        if isinstance(raw_flags, int):
            val_flag = raw_flags
        elif isinstance(raw_flags, float):
            if math.isnan(raw_flags) or math.isinf(raw_flags):
                raise UnsupportedParameterError("QIM codebook flags index cannot be NaN or infinity.")
            if not raw_flags.is_integer():
                raise UnsupportedParameterError(
                    f"QIM codebook flags index must be an integer, got non-integer float {raw_flags}."
                )
            val_flag = int(raw_flags)
        elif isinstance(raw_flags, str):
            try:
                val_flag = int(raw_flags)
            except ValueError:
                raise UnsupportedParameterError(f"Unsupported string for flags: {raw_flags!r}.")
        else:
            raise UnsupportedParameterError(
                f"Unsupported type for flags: {type(raw_flags).__name__}. Expected integer value."
            )

        if val_flag not in QIM_DELTA_CODEBOOK:
            raise UnsupportedParameterError(
                f"Unsupported QIM codebook flag index: {raw_flags}. "
                f"Supported flag indices: {sorted(QIM_DELTA_CODEBOOK.keys())}."
            )
        flags = val_flag

    if delta is not None and flags is not None:
        if QIM_DELTA_TO_FLAG[delta] != flags:
            raise UnsupportedParameterError(
                f"Conflicting parameters: delta={delta} maps to flag {QIM_DELTA_TO_FLAG[delta]}, "
                f"but flags={flags} was explicitly supplied."
            )
        return delta, flags

    if delta is not None:
        return delta, QIM_DELTA_TO_FLAG[delta]

    assert flags is not None
    return QIM_DELTA_CODEBOOK[flags], flags


# ---------------------------------------------------------------------------
# DWTDCTQIMAlgorithm Implementation
# ---------------------------------------------------------------------------

class DWTDCTQIMAlgorithm(BaseStegoAlgorithm):
    """
    DWT-DCT-QIM transform-domain steganography strategy.
    
    Implements BaseStegoAlgorithm for Daubechies-4 DWT-3 detail sub-band cD3,
    orthonormal 8-point DCT-II, and deterministic Quantization Index Modulation.
    """

    @property
    def algorithm_id(self) -> str:
        """Unique machine identifier."""
        return ALGORITHM_ID

    @property
    def display_name(self) -> str:
        """Human-readable display title."""
        return DISPLAY_NAME

    @property
    def domain(self) -> DomainType:
        """Operational domain: Transform Domain."""
        return DomainType.TRANSFORM

    @property
    def robustness_objective(self) -> RobustnessEvaluationStatus:
        """Robustness evaluation status: Experimental target requiring empirical battery."""
        return RobustnessEvaluationStatus.EXPERIMENTAL_TARGET

    def _validate_audio_format(self, audio_data: WavData, strict: bool = True) -> bool:
        """Validate carrier audio format and structural parameters."""
        if not isinstance(audio_data, WavData):
            if strict:
                raise AudioFormatIncompatibleError("Audio data must be an instance of WavData.")
            return False

        channels = getattr(audio_data, "channels", None)
        if not isinstance(channels, int) or channels not in (1, 2):
            if strict:
                raise AudioFormatIncompatibleError(
                    f"DWT-DCT-QIM steganography supports 1 or 2 channels, found {channels}."
                )
            return False

        sample_width = getattr(audio_data, "sample_width", None)
        if not isinstance(sample_width, int) or sample_width not in (1, 2, 3, 4):
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Unsupported sample width: {sample_width} bytes."
                )
            return False

        frame_count = getattr(audio_data, "frame_count", None)
        if not isinstance(frame_count, int) or frame_count < 0:
            if strict:
                raise AudioFormatIncompatibleError("Invalid frame count in audio container.")
            return False

        frames = getattr(audio_data, "frames", None)
        if not isinstance(frames, (bytes, bytearray)):
            if strict:
                raise AudioFormatIncompatibleError("Audio frame data must be bytes or bytearray.")
            return False

        expected_bytes = frame_count * channels * sample_width
        if len(frames) != expected_bytes:
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Frame buffer size mismatch: expected {expected_bytes} bytes for "
                    f"{frame_count} frames, got {len(frames)} bytes."
                )
            return False

        return True

    def embed(
        self,
        audio_data: WavData,
        payload: bytes,
        **options: Any,
    ) -> StegoResult:
        """
        Embed binary payload into carrier audio Channel 0 using DWT-DCT-QIM.

        Parameters:
            audio_data: Input carrier WavData container.
            payload: Binary payload bytes to embed.
            options:
                - delta: Quantization step Delta in {8.0, 16.0, 32.0, 64.0} (default 32.0).
                - flags: Direct codebook index {0, 1, 2, 3} (optional).

        Returns:
            StegoResult: Embedding results and stego WavData.

        Raises:
            CapacityExceededError: If host audio lacks capacity for framed payload.
            AudioFormatIncompatibleError: If audio format is not supported.
            UnsupportedParameterError: If payload or parameters are invalid.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise UnsupportedParameterError("Payload must be bytes or bytearray.")
        if len(payload) == 0:
            raise UnsupportedParameterError("Payload cannot be empty.")
        if len(payload) > MAX_PAYLOAD_SIZE_BYTES:
            raise UnsupportedParameterError(
                f"Payload size ({len(payload)} bytes) exceeds maximum allowable limit "
                f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
            )

        self._validate_audio_format(audio_data, strict=True)
        channels = audio_data.channels
        sample_width = audio_data.sample_width
        frame_count = audio_data.frame_count

        # 1. Resolve quantization step Delta and flags codebook index with strict validation
        delta, flags = _validate_and_resolve_delta_flags(options)
        # In 8-bit PCM, 1 LSB is 256 units on the 16-bit reference scale; scale effective delta accordingly
        effective_delta = delta * 256.0 if sample_width == 1 else delta

        # 2. Prepare universal CSMA v1 envelope
        framed_envelope = create_csma_envelope(
            payload=bytes(payload),
            algorithm=ALGO_ID_DWT_DCT_QIM,
            flags=flags,
            sync_word=SYNC_WORD_DWT_DCT_QIM,
        )
        envelope_bits = bytes_to_bits(framed_envelope)
        required_bits = len(envelope_bits)
        required_chunks = int(np.ceil(required_bits / BITS_PER_CHUNK))

        # 3. Check capacity against complete 1024-sample chunks on Channel 0
        available_chunks = frame_count // CHUNK_SIZE
        available_bits = available_chunks * BITS_PER_CHUNK

        if required_chunks > available_chunks:
            raise CapacityExceededError(
                f"Insufficient capacity in DWT-DCT-QIM carrier: requires {required_bits} bits "
                f"({required_chunks} chunks / {required_chunks * CHUNK_SIZE} frames), "
                f"but carrier provides {available_bits} bits "
                f"({available_chunks} chunks / {available_chunks * CHUNK_SIZE} frames)."
            )

        # 4. Decode audio samples and separate Channel 0
        decoded_samples = decode_pcm_to_ref16(audio_data.frames, sample_width)
        if channels == 2:
            samples_2d = decoded_samples.reshape(-1, 2)
            ch0 = np.copy(samples_2d[:, 0])
            ch1 = samples_2d[:, 1]  # Preserved untouched
        else:
            ch0 = np.copy(decoded_samples)
            ch1 = None

        # 5. Modulate Channel 0 chunks
        for c in range(required_chunks):
            start_idx = c * CHUNK_SIZE
            end_idx = start_idx + CHUNK_SIZE
            chunk_samples = ch0[start_idx:end_idx]

            # Forward DWT-3 with Daubechies 4 and periodization
            coeffs = list(pywt.wavedec(chunk_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL))
            cd3 = coeffs[1]  # 128 coefficients
            blocks = cd3.reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)

            # Forward orthonormal DCT-II
            dct_blocks = dct2_ortho(blocks)

            # Embed bits into target coefficient k = 3
            for b in range(BLOCKS_PER_CHUNK):
                bit_idx = c * BITS_PER_CHUNK + b
                if bit_idx < required_bits:
                    bit = envelope_bits[bit_idx]
                    dct_blocks[b, TARGET_COEFF_INDEX] = qim_embed_scalar(
                        dct_blocks[b, TARGET_COEFF_INDEX], bit, effective_delta
                    )

            # Inverse orthonormal DCT
            reconstructed_blocks = idct2_ortho(dct_blocks)
            coeffs[1] = reconstructed_blocks.reshape(-1)

            # Inverse DWT-3
            reconstructed_chunk = pywt.waverec(coeffs, WAVELET_NAME, mode=WAVELET_MODE)
            ch0[start_idx:end_idx] = reconstructed_chunk

        # 6. Recombine channels preserving Channel 1 bit-for-bit
        if channels == 2:
            recombined = np.column_stack([ch0, ch1]).reshape(-1)
        else:
            recombined = ch0

        # 7. Encode back to original PCM format with anti-wrap clipping
        modified_frames = encode_ref16_to_pcm(recombined, sample_width)

        utilization = round((required_bits / available_bits) * 100, 4) if available_bits > 0 else 0.0

        modified_wav = WavData(
            channels=channels,
            sample_rate=audio_data.sample_rate,
            sample_width=sample_width,
            frame_count=frame_count,
            compression_type=audio_data.compression_type,
            compression_name=audio_data.compression_name,
            frames=modified_frames,
        )

        return StegoResult(
            success=True,
            algorithm_id=self.algorithm_id,
            modified_wav=modified_wav,
            payload_size_bytes=len(payload),
            framed_size_bytes=len(framed_envelope),
            required_bits=required_bits,
            available_bits=available_bits,
            utilization_percent=utilization,
            algorithm_parameters={
                "wavelet": WAVELET_NAME,
                "decomposition_level": DECOMPOSITION_LEVEL,
                "subband": "cD3",
                "dct_block_size": DCT_BLOCK_SIZE,
                "target_coeff_k": TARGET_COEFF_INDEX,
                "delta": delta,
                "flags": flags,
                "channel_policy": "channel_0_only",
            },
        )

    def extract(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> ExtractedPayload:
        """
        Extract embedded payload from carrier audio Channel 0 using DWT-DCT-QIM.

        Parameters:
            audio_data: Stego carrier WavData container.
            options: Extraction options.

        Returns:
            ExtractedPayload: Extracted and CRC32-verified payload data.

        Raises:
            HeaderNotFoundError: If synchronization cannot be locked or header is invalid.
            CorruptedPayloadError: If CRC32 fails, length exceeds audio, or payload is corrupted.
            AudioFormatIncompatibleError: If audio format is invalid.
        """
        self._validate_audio_format(audio_data, strict=True)
        channels = audio_data.channels
        sample_width = audio_data.sample_width
        frame_count = audio_data.frame_count

        available_chunks = frame_count // CHUNK_SIZE
        if available_chunks < MIN_HEADER_CHUNKS:
            raise HeaderNotFoundError(
                f"Audio carrier has only {frame_count} frames ({available_chunks} chunks); "
                f"at least {MIN_HEADER_FRAMES} frames ({MIN_HEADER_CHUNKS} chunks) are required "
                f"to contain a DWT-DCT-QIM CSMA v1 envelope."
            )

        # 1. Decode samples and isolate Channel 0
        decoded_samples = decode_pcm_to_ref16(audio_data.frames, sample_width)
        if channels == 2:
            ch0 = decoded_samples.reshape(-1, 2)[:, 0]
        else:
            ch0 = decoded_samples

        # 2. Forward transform Chunk 0 to detect synchronization across candidate Delta values
        chunk0_samples = ch0[:CHUNK_SIZE]
        coeffs0 = pywt.wavedec(chunk0_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
        blocks0 = coeffs0[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
        dct0 = dct2_ortho(blocks0)
        target_coeffs_chunk0 = [dct0[b, TARGET_COEFF_INDEX] for b in range(BLOCKS_PER_CHUNK)]

        detected_delta: float | None = None
        detected_correlation: float = -1.0

        for cand_delta in (32.0, 16.0, 8.0, 64.0):
            effective_cand = cand_delta * 256.0 if sample_width == 1 else cand_delta
            cand_bits = [qim_extract_scalar(c, effective_cand) for c in target_coeffs_chunk0]
            r = calculate_sync_correlation(cand_bits)
            if r >= SYNC_CORRELATION_THRESHOLD:
                detected_delta = cand_delta
                detected_correlation = r
                break

        if detected_delta is None:
            raise HeaderNotFoundError(
                "No valid DWT-DCT-QIM synchronization signature detected in carrier audio "
                f"(peak correlation fell below threshold {SYNC_CORRELATION_THRESHOLD})."
            )

        delta = detected_delta
        effective_delta = delta * 256.0 if sample_width == 1 else delta

        # 3. Extract complete 18-byte (144-bit) CSMA header from initial 9 chunks
        header_bits: list[int] = []
        for c in range(MIN_HEADER_CHUNKS):
            start_idx = c * CHUNK_SIZE
            end_idx = start_idx + CHUNK_SIZE
            chunk_samples = ch0[start_idx:end_idx]
            coeffs = pywt.wavedec(chunk_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
            blocks = coeffs[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
            dct_b = dct2_ortho(blocks)
            for b in range(BLOCKS_PER_CHUNK):
                header_bits.append(qim_extract_scalar(dct_b[b, TARGET_COEFF_INDEX], effective_delta))

        header_bytes = bits_to_bytes(header_bits[:CSMA_HEADER_SIZE_BYTES * 8])

        try:
            sync_word, magic, algo_id, version, flags, payload_len, expected_crc = struct.unpack(
                CSMA_HEADER_STRUCT, header_bytes
            )
        except struct.error as e:
            raise CorruptedPayloadError(f"Malformed CSMA header bytes: {e}")

        # Validate header parameters
        if magic != CSMA_MAGIC:
            raise HeaderNotFoundError(
                f"Invalid stego magic: expected {CSMA_MAGIC!r}, found {magic!r}. "
                "Data does not start with a valid CSMA envelope."
            )

        if version != CSMA_VERSION:
            raise UnsupportedParameterError(
                f"Unsupported CSMA format version: {version}. Expected version {CSMA_VERSION}."
            )

        if algo_id != ALGO_ID_DWT_DCT_QIM:
            raise UnsupportedParameterError(
                f"Algorithm mismatch: CSMA header declares algorithm {algo_id}, "
                f"expected {ALGO_ID_DWT_DCT_QIM} ({ALGORITHM_ID})."
            )

        if flags not in QIM_DELTA_CODEBOOK or QIM_DELTA_CODEBOOK[flags] != delta:
            raise CorruptedPayloadError(
                f"QIM step mismatch: detected step {delta} does not match declared header flags index {flags}."
            )

        if payload_len > MAX_PAYLOAD_SIZE_BYTES:
            raise CorruptedPayloadError(
                f"Declared DWT payload length ({payload_len} bytes) exceeds maximum allowable limit "
                f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
            )

        total_required_bits = (CSMA_HEADER_SIZE_BYTES + payload_len) * 8
        required_chunks = int(np.ceil(total_required_bits / BITS_PER_CHUNK))

        if required_chunks > available_chunks:
            raise CorruptedPayloadError(
                f"Declared DWT payload requires {required_chunks} chunks ({required_chunks * CHUNK_SIZE} frames), "
                f"but carrier contains only {available_chunks} chunks ({available_chunks * CHUNK_SIZE} frames)."
            )

        # 4. Extract remaining payload bits
        all_bits = list(header_bits)
        for c in range(MIN_HEADER_CHUNKS, required_chunks):
            start_idx = c * CHUNK_SIZE
            end_idx = start_idx + CHUNK_SIZE
            chunk_samples = ch0[start_idx:end_idx]
            coeffs = pywt.wavedec(chunk_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
            blocks = coeffs[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
            dct_b = dct2_ortho(blocks)
            for b in range(BLOCKS_PER_CHUNK):
                all_bits.append(qim_extract_scalar(dct_b[b, TARGET_COEFF_INDEX], effective_delta))

        # Truncate to exact envelope bit length and convert to bytes
        envelope_data = bits_to_bytes(all_bits[:total_required_bits])

        # 5. Parse and verify with parse_csma_envelope (validates CRC32, sync word, bounds)
        parsed_envelope = parse_csma_envelope(
            envelope_data,
            expected_algorithm=self.algorithm_id,
            enforce_sync_word=True,
        )

        return ExtractedPayload(
            success=True,
            algorithm_id=self.algorithm_id,
            payload=parsed_envelope.payload,
            integrity_verified=True,
            framing_checksum_verified=True,
            algorithm_parameters={
                "delta": delta,
                "flags": flags,
                "sync_correlation": round(detected_correlation, 4),
                "sync_word": hex(parsed_envelope.sync_word),
                "wavelet": WAVELET_NAME,
                "level": DECOMPOSITION_LEVEL,
                "subband": "cD3",
                "dct_k": TARGET_COEFF_INDEX,
            },
        )

    def estimate_capacity(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> CapacityProfile:
        """
        Calculate payload capacity for carrier audio using the DWT-DCT-QIM formula:
        C_raw = floor(N_frames / 1024) * 16 bits
        C_net_bytes = max(0, floor((C_raw - 144) / 8))
        """
        self._validate_audio_format(audio_data, strict=True)
        frame_count = audio_data.frame_count
        sample_rate = audio_data.sample_rate

        available_chunks = frame_count // CHUNK_SIZE
        available_bits = available_chunks * BITS_PER_CHUNK
        available_bytes = available_bits // 8

        envelope_bits = CSMA_HEADER_SIZE_BYTES * 8  # 144 bits
        max_payload_bytes = max(0, (available_bits - envelope_bits) // 8)

        # Minimum duration: 18B header (144 bits) + 49B min CAUD payload (392 bits) = 536 bits
        # Required chunks: ceil(536 / 16) = 34 chunks = 34,816 frames
        min_required_frames = int(np.ceil(536.0 / BITS_PER_CHUNK)) * CHUNK_SIZE
        recommended_min_duration = min_required_frames / sample_rate if sample_rate > 0 else 0.0

        bits_per_sample = float(BITS_PER_CHUNK) / float(CHUNK_SIZE)  # 16 / 1024 = 0.015625
        bits_per_second = float(sample_rate) * bits_per_sample

        return CapacityProfile(
            algorithm_id=self.algorithm_id,
            available_bits=available_bits,
            available_bytes=available_bytes,
            bits_per_sample=round(bits_per_sample, 6),
            bits_per_second=round(bits_per_second, 4),
            max_payload_bytes=max_payload_bytes,
            synchronization_overhead_bits=0,  # Subsumed within 144-bit envelope
            envelope_overhead_bits=envelope_bits,
            recommended_min_duration_sec=round(recommended_min_duration, 4),
        )

    def inspect_metadata(
        self,
        audio_data: WavData,
    ) -> StegoInspection:
        """
        Non-destructively inspect carrier audio for a DWT-DCT-QIM CSMA v1 signature.

        Inspection Semantics and Confidence:
        - Signature detected (`has_stego_signature`): Validates that the initial 16-bit
          synchronization sequence in Chunk 0 correlates with canonical sequence 0xF9A9
          above threshold 0.875 across codebook candidate Delta values.
        - Header structurally valid (`header_valid`): Validates CSMA magic, version 1,
          algorithm ID 2, flags codebook match, bounded payload length, and frame capacity.
        - Confidence score (`confidence_score`): Set to 1.0 if and only if synchronization
          and all header structural fields validate.
        - Payload CRC32 verified (`crc32_verified`): Remains False during inspect_metadata.
          Metadata inspection is non-destructive and strictly header-only (first 9 chunks);
          it does not decode, allocate, or verify full payload CRC32 checksums.
        - AES-GCM authentication verified: Cryptographic authentication is strictly not
          performed during steganography inspection; authenticity is verified solely by the
          AES-GCM decryption engine using the shared password and 128-bit authentication tag.
        """
        if not self._validate_audio_format(audio_data, strict=False):
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        frame_count = audio_data.frame_count
        available_chunks = frame_count // CHUNK_SIZE
        if available_chunks < MIN_HEADER_CHUNKS:
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        # Isolate Channel 0
        decoded_samples = decode_pcm_to_ref16(audio_data.frames, audio_data.sample_width)
        if audio_data.channels == 2:
            ch0 = decoded_samples.reshape(-1, 2)[:, 0]
        else:
            ch0 = decoded_samples

        # Transform Chunk 0 to check synchronization across candidate Delta values
        chunk0_samples = ch0[:CHUNK_SIZE]
        coeffs0 = pywt.wavedec(chunk0_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
        blocks0 = coeffs0[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
        dct0 = dct2_ortho(blocks0)
        target_coeffs_chunk0 = [dct0[b, TARGET_COEFF_INDEX] for b in range(BLOCKS_PER_CHUNK)]

        detected_delta: float | None = None
        for cand_delta in (32.0, 16.0, 8.0, 64.0):
            effective_cand = cand_delta * 256.0 if audio_data.sample_width == 1 else cand_delta
            cand_bits = [qim_extract_scalar(c, effective_cand) for c in target_coeffs_chunk0]
            if calculate_sync_correlation(cand_bits) >= SYNC_CORRELATION_THRESHOLD:
                detected_delta = cand_delta
                break

        if detected_delta is None:
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        delta = detected_delta
        effective_delta = delta * 256.0 if audio_data.sample_width == 1 else delta

        # Decode initial 9 chunks (144 bits = 18 bytes)
        header_bits: list[int] = []
        for c in range(MIN_HEADER_CHUNKS):
            start_idx = c * CHUNK_SIZE
            end_idx = start_idx + CHUNK_SIZE
            chunk_samples = ch0[start_idx:end_idx]
            coeffs = pywt.wavedec(chunk_samples, WAVELET_NAME, mode=WAVELET_MODE, level=DECOMPOSITION_LEVEL)
            blocks = coeffs[1].reshape(BLOCKS_PER_CHUNK, DCT_BLOCK_SIZE)
            dct_b = dct2_ortho(blocks)
            for b in range(BLOCKS_PER_CHUNK):
                header_bits.append(qim_extract_scalar(dct_b[b, TARGET_COEFF_INDEX], effective_delta))

        header_bytes = bits_to_bytes(header_bits[:CSMA_HEADER_SIZE_BYTES * 8])

        try:
            sync_word, magic, algo_id, version, flags, payload_len, expected_crc = struct.unpack(
                CSMA_HEADER_STRUCT, header_bytes
            )
        except struct.error:
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        # Full validation of CSMA header for DWT-DCT-QIM
        if (
            magic == CSMA_MAGIC
            and version == CSMA_VERSION
            and algo_id == ALGO_ID_DWT_DCT_QIM
            and sync_word == SYNC_WORD_DWT_DCT_QIM
            and flags in QIM_DELTA_CODEBOOK
            and QIM_DELTA_CODEBOOK[flags] == delta
            and 0 < payload_len <= MAX_PAYLOAD_SIZE_BYTES
        ):
            total_required_bits = (CSMA_HEADER_SIZE_BYTES + payload_len) * 8
            required_chunks = int(np.ceil(total_required_bits / BITS_PER_CHUNK))
            if required_chunks <= available_chunks:
                return StegoInspection(
                    has_stego_signature=True,
                    detected_algorithm=self.algorithm_id,
                    envelope_version=version,
                    payload_length_bytes=payload_len,
                    confidence_score=1.0,
                    header_valid=True,
                    crc32_verified=False,
                )

        return StegoInspection(
            has_stego_signature=False,
            detected_algorithm=None,
            envelope_version=None,
            payload_length_bytes=None,
            confidence_score=0.0,
            header_valid=False,
            crc32_verified=False,
        )
