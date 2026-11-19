"""
app/steganography/echo_hiding.py
CryptAudio Web — Echo Hiding Steganography Engine (Phase M4)

Implements BaseStegoAlgorithm for the acoustic time-domain steganography engine
using single-echo delay modulation, smooth windowed cross-fading, and real
cepstrum-based extraction.

Mathematical Specification (M1.6 / MULTI_ALGORITHM_ARCHITECTURE.md Section 9):
================================================================================
1. Echo Model:
   - Filter: h_b(n) = delta(n) + alpha * delta(n - d_b)
   - Echo Amplitude (alpha): 0.08 default (-22 dB relative to carrier).
   - Bit 0 Delay: delta_0 = 1.0 ms -> d_0 = round(F_s * 1.0 / 1000) samples.
   - Bit 1 Delay: delta_1 = 1.3 ms -> d_1 = round(F_s * 1.3 / 1000) samples.
   - At 44.1 kHz: d_0 = 44 samples, d_1 = 57 samples.
   - At 48.0 kHz: d_0 = 48 samples, d_1 = 62 samples.

2. Segment Partitioning & Capacity:
   - Segment Size: L_seg = 2048 samples on Channel 0.
   - Bits per Segment: 1 bit per 2048 samples (~21.5 bps at 44.1 kHz).
   - Incomplete trailing frames (N_frames mod 2048) are passed through unmodulated.

3. Boundary Handling & Continuous State Memory:
   - Trailing samples from segment m-1 are maintained in a history buffer of length
     d_max = max(d_0, d_1).
   - For n < d_b, delayed samples reference trailing samples of segment m-1:
     x_delayed(n) = x_{m-1}(L_seg - d_b + n).
   - First segment (m = 0) history is initialized with silence (zeros).
   - Smooth Hanning cross-fade is applied over the initial N_fade = 200 samples
     when d_prev != d_curr to eliminate phase discontinuity clicks:
     y_m(n) = x_m(n) + alpha * [w_fall(n) * x(n - d_prev) + w_rise(n) * x(n - d_curr)] (n < N_fade)
     y_m(n) = x_m(n) + alpha * x(n - d_curr)                                           (n >= N_fade)
     where w_rise(n) = 0.5 * (1 - cos(pi * n / N_fade)), w_fall(n) = 1.0 - w_rise(n).

4. Real Cepstrum Extraction:
   - C_m(n) = F^{-1} { ln | F { y_m(n) } | }
   - Decision Rule:
     b* = 0 if C_m(d_0) > C_m(d_1)
     b* = 1 if C_m(d_1) > C_m(d_0)
     b* = 0 if C_m(d_0) == C_m(d_1) (deterministic tie-break)

5. Synchronization & Preamble:
   - Logical Synchronization Word: 0x596A (b"\\x59\\x6A").
   - 16-bit Preamble Sequence: [0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0].
   - Physical Preamble Delay Pattern: [d_0, d_1, d_0, d_1, d_1, d_0, d_0, d_1, d_0, d_1, d_1, d_0, d_1, d_0, d_1, d_0].
   - Bipolar Vector: p = [-1, +1, -1, +1, +1, -1, -1, +1, -1, +1, +1, -1, +1, -1, +1, -1].
   - Subsumed in the 18-byte (144-segment) universal CSMA v1 envelope (bytes 0..1).

6. Audio Preservation & Channel Policy:
   - Process strictly Channel 0. Channel 1 remains bit-for-bit unchanged.
   - Total frame count and duration are preserved exactly.
   - Container sample width and metadata are preserved with anti-wrap clipping.
"""

from __future__ import annotations

import math
import struct
from typing import Any, Final

import numpy as np

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
from app.steganography.dwt_dct_qim import decode_pcm_to_ref16, encode_ref16_to_pcm
from app.steganography.envelope import (
    ALGO_ID_ECHO,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_HEADER_STRUCT,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_ECHO,
    create_csma_envelope,
    parse_csma_envelope,
)
from app.steganography.lsb_engine import bits_to_bytes, bytes_to_bits

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_ID: Final[str] = "echo"
DISPLAY_NAME: Final[str] = "Echo Hiding Acoustic Steganography"

# Default signal parameters
DEFAULT_SEGMENT_SIZE: Final[int] = 2048  # L_seg = 2048 samples
DEFAULT_DELAY_0_MS: Final[float] = 1.0   # delta_0 = 1.0 ms
DEFAULT_DELAY_1_MS: Final[float] = 1.3   # delta_1 = 1.3 ms
DEFAULT_ALPHA: Final[float] = 0.08       # Echo attenuation alpha = 0.08 (-22 dB)
DEFAULT_FADE_SAMPLES: Final[int] = 200   # N_fade = 200 samples
BITS_PER_SEGMENT: Final[int] = 1

# Preamble synchronization: 0x596A
CANONICAL_SYNC_WORD: Final[int] = SYNC_WORD_ECHO  # 0x596A
CANONICAL_PREAMBLE_BITS: Final[tuple[int, ...]] = (
    0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0
)
CANONICAL_PREAMBLE_BIPOLAR: Final[np.ndarray] = np.array(
    [-1.0, 1.0, -1.0, 1.0, 1.0, -1.0, -1.0, 1.0, -1.0, 1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0],
    dtype=np.float64,
)
MIN_PREAMBLE_SEGMENTS: Final[int] = 16
MIN_HEADER_SEGMENTS: Final[int] = CSMA_HEADER_SIZE_BYTES * 8  # 144 segments

# Preamble correlation detection threshold
SYNC_CORRELATION_THRESHOLD: Final[float] = 0.75

# Minimum required segments for minimum valid CryptAudio payload:
# 18-byte CSMA header (144 bits) + 49-byte minimum CAUD payload (392 bits) = 536 bits = 536 segments
MIN_VALID_PAYLOAD_SEGMENTS: Final[int] = 536


# ---------------------------------------------------------------------------
# Mathematical Signal Processing Helpers
# ---------------------------------------------------------------------------

def delay_ms_to_samples(sample_rate: int, delay_ms: float) -> int:
    """
    Convert delay in milliseconds to discrete sample count for the given sample rate.

    delay_samples = round(sample_rate * delay_ms / 1000)

    Parameters:
        sample_rate: Audio sampling frequency in Hz.
        delay_ms: Delay in milliseconds.

    Returns:
        int: Discrete delay in audio samples.
    """
    if sample_rate <= 0:
        raise AudioFormatIncompatibleError(f"Invalid sample rate: {sample_rate} Hz.")
    return int(round(sample_rate * delay_ms / 1000.0))


def compute_real_cepstrum(segment: np.ndarray) -> np.ndarray:
    """
    Compute the Real Cepstrum of an audio segment:
    C(n) = F^{-1} { ln | F { y(n) } | }

    Parameters:
        segment: 1D float64 array of audio samples.

    Returns:
        np.ndarray: 1D float64 array of real cepstrum coefficients.
    """
    # Use 1e-12 floor to avoid log(0) in silent or low-energy regions
    spectrum = np.fft.rfft(segment)
    mag = np.maximum(np.abs(spectrum), 1e-12)
    return np.fft.irfft(np.log(mag), n=len(segment))


def calculate_echo_sync_metrics(
    segments_16: list[np.ndarray],
    d0: int,
    d1: int,
) -> tuple[float, float]:
    """
    Calculate normalized pattern correlation rho and mean PNR across 16 preamble segments.

    Parameters:
        segments_16: List of 16 audio segments (each of length L_seg).
        d0: Bit 0 delay in samples.
        d1: Bit 1 delay in samples.

    Returns:
        tuple[float, float]: (normalized correlation rho, mean PNR).
    """
    if len(segments_16) < MIN_PREAMBLE_SEGMENTS:
        return 0.0, 0.0

    delta_c: list[float] = []
    pnrs: list[float] = []

    # Background lag window [20, 100] excluding guard bands [d - 2, d + 2]
    n_min, n_max = 20, 100
    guard = set(range(d0 - 2, d0 + 3)).union(set(range(d1 - 2, d1 + 3)))
    bg_bins = [n for n in range(n_min, n_max + 1) if n not in guard]

    for seg in segments_16:
        # Check signal energy: if silent (< 1e-6), PNR is 0
        std_val = float(np.std(seg))
        if std_val < 1e-6:
            delta_c.append(0.0)
            pnrs.append(0.0)
            continue

        c = compute_real_cepstrum(seg)
        v_cand = max(float(c[d0]), float(c[d1]))
        d_c = float(c[d1]) - float(c[d0])
        delta_c.append(d_c)

        if bg_bins:
            bg_vals = c[bg_bins]
            mu_bg = float(np.mean(bg_vals))
            sig_bg = float(np.std(bg_vals))
            pnr = (v_cand - mu_bg) / max(sig_bg, 1e-12)
        else:
            pnr = 0.0
        pnrs.append(pnr)

    delta_c_arr = np.array(delta_c, dtype=np.float64)
    norm_denom = math.sqrt(float(np.sum(delta_c_arr**2) * np.sum(CANONICAL_PREAMBLE_BIPOLAR**2)) + 1e-12)
    rho = float(np.sum(CANONICAL_PREAMBLE_BIPOLAR * delta_c_arr)) / norm_denom
    mean_pnr = float(np.mean(pnrs))

    return rho, mean_pnr


def validate_segment_size(raw_seg: Any) -> int:
    """
    Validate segment size parameter for Echo Hiding.

    Parameters:
        raw_seg: Candidate segment size value.

    Returns:
        int: Validated segment size in samples.

    Raises:
        UnsupportedParameterError: If raw_seg is not an int (or is a bool), or is < 256.
    """
    if raw_seg is None or isinstance(raw_seg, bool) or not isinstance(raw_seg, int):
        raise UnsupportedParameterError(
            f"Segment size must be an integer, got {type(raw_seg).__name__} (value: {raw_seg!r})."
        )
    segment_size = int(raw_seg)
    if segment_size < 256:
        raise UnsupportedParameterError(
            f"Segment size must be at least 256 samples, got {segment_size}."
        )
    return segment_size


def _validate_and_resolve_echo_options(
    options: dict[str, Any],
    sample_rate: int,
) -> tuple[float, float, float, int, int, int, int, int]:
    """
    Validate and resolve echo hiding algorithm parameters.

    Returns:
        tuple: (alpha, delay_0_ms, delay_1_ms, d0, d1, segment_size, fade_samples, flags)

    Raises:
        UnsupportedParameterError: If any parameter value or type is invalid.
    """
    # 0. Reject unexpected options
    allowed_options = {
        "alpha",
        "delay_0_ms",
        "delay_1_ms",
        "segment_size",
        "fade_samples",
        "flags",
    }
    unknown_options = set(options.keys()) - allowed_options
    if unknown_options:
        raise UnsupportedParameterError(
            f"Unsupported echo hiding options: {sorted(unknown_options)}."
        )

    # 1. Echo amplitude alpha
    raw_alpha = options.get("alpha", DEFAULT_ALPHA)
    if raw_alpha is None or isinstance(raw_alpha, bool) or not isinstance(raw_alpha, (int, float)):
        raise UnsupportedParameterError(
            f"Echo amplitude alpha must be a real number, got {type(raw_alpha).__name__} (value: {raw_alpha!r})."
        )
    alpha = float(raw_alpha)
    if math.isnan(alpha) or math.isinf(alpha) or not (0.001 <= alpha <= 0.50):
        raise UnsupportedParameterError(
            f"Echo amplitude alpha must be in range [0.001, 0.50], got {alpha}."
        )

    # 2. Delay 0 in ms
    raw_d0_ms = options.get("delay_0_ms", DEFAULT_DELAY_0_MS)
    if raw_d0_ms is None or isinstance(raw_d0_ms, bool) or not isinstance(raw_d0_ms, (int, float)):
        raise UnsupportedParameterError(
            f"Bit 0 delay must be a real number, got {type(raw_d0_ms).__name__}."
        )
    d0_ms = float(raw_d0_ms)
    if math.isnan(d0_ms) or math.isinf(d0_ms) or d0_ms <= 0:
        raise UnsupportedParameterError(f"Bit 0 delay must be positive, got {d0_ms} ms.")

    # 3. Delay 1 in ms
    raw_d1_ms = options.get("delay_1_ms", DEFAULT_DELAY_1_MS)
    if raw_d1_ms is None or isinstance(raw_d1_ms, bool) or not isinstance(raw_d1_ms, (int, float)):
        raise UnsupportedParameterError(
            f"Bit 1 delay must be a real number, got {type(raw_d1_ms).__name__}."
        )
    d1_ms = float(raw_d1_ms)
    if math.isnan(d1_ms) or math.isinf(d1_ms) or d1_ms <= 0:
        raise UnsupportedParameterError(f"Bit 1 delay must be positive, got {d1_ms} ms.")

    if d0_ms == d1_ms:
        raise UnsupportedParameterError(
            f"Bit 0 and Bit 1 delays cannot be identical: d0={d0_ms} ms, d1={d1_ms} ms."
        )

    # 4. Segment size
    raw_seg = options.get("segment_size", DEFAULT_SEGMENT_SIZE)
    segment_size = validate_segment_size(raw_seg)

    # Convert ms delays to discrete samples
    d0 = delay_ms_to_samples(sample_rate, d0_ms)
    d1 = delay_ms_to_samples(sample_rate, d1_ms)
    if d0 <= 0 or d1 <= 0:
        raise UnsupportedParameterError(
            f"Delays in samples must be positive: d0={d0}, d1={d1} at {sample_rate} Hz."
        )
    if d0 == d1:
        raise UnsupportedParameterError(
            f"Discrete delays in samples collapsed to identical values ({d0}) at {sample_rate} Hz."
        )
    if max(d0, d1) >= segment_size:
        raise UnsupportedParameterError(
            f"Max delay ({max(d0, d1)} samples) exceeds or equals segment size ({segment_size} samples)."
        )

    # 5. Crossfade window size
    raw_fade = options.get("fade_samples", DEFAULT_FADE_SAMPLES)
    if raw_fade is None or isinstance(raw_fade, bool) or not isinstance(raw_fade, int):
        raise UnsupportedParameterError(
            f"Fade samples must be an integer, got {type(raw_fade).__name__}."
        )
    fade_samples = int(raw_fade)
    if not (0 <= fade_samples < segment_size):
        raise UnsupportedParameterError(
            f"Fade samples must be in range [0, {segment_size - 1}], got {fade_samples}."
        )

    # 6. CSMA Flags
    raw_flags = options.get("flags", 0)
    if raw_flags is None or isinstance(raw_flags, bool) or not isinstance(raw_flags, int):
        raise UnsupportedParameterError(
            f"Flags must be an integer, got {type(raw_flags).__name__}."
        )
    flags = int(raw_flags)
    if not (0 <= flags <= 0xFFFF):
        raise UnsupportedParameterError(
            f"Flags must be an unsigned 16-bit integer (0..65535), got {flags}."
        )

    return alpha, d0_ms, d1_ms, d0, d1, segment_size, fade_samples, flags


# ---------------------------------------------------------------------------
# EchoHidingAlgorithm Implementation
# ---------------------------------------------------------------------------

class EchoHidingAlgorithm(BaseStegoAlgorithm):
    """
    Echo Hiding acoustic time-domain steganography strategy.

    Implements BaseStegoAlgorithm for single-echo delay modulation,
    continuous state memory buffering, smooth Hanning cross-fading,
    and real cepstrum-based payload recovery.
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
        """Operational domain: Acoustic Time Domain."""
        return DomainType.ACOUSTIC_TIME

    @property
    def robustness_objective(self) -> RobustnessEvaluationStatus:
        """Robustness evaluation status: Experimental target requiring empirical battery."""
        return RobustnessEvaluationStatus.EXPERIMENTAL_TARGET

    def _validate_audio_format(self, audio_data: WavData, strict: bool = True) -> bool:
        """
        Validate carrier audio format, channels, sample width, and buffer integrity.

        Parameters:
            audio_data: The audio container to validate.
            strict: If True, raises AudioFormatIncompatibleError on failure.
                    If False, returns False on failure.

        Returns:
            bool: True if format is valid.
        """
        if not isinstance(audio_data, WavData):
            if strict:
                raise AudioFormatIncompatibleError("Audio data must be an instance of WavData.")
            return False

        channels = getattr(audio_data, "channels", None)
        if not isinstance(channels, int) or channels not in (1, 2):
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Echo Hiding supports 1 (mono) or 2 (stereo) channels, found {channels}."
                )
            return False

        sample_width = getattr(audio_data, "sample_width", None)
        if not isinstance(sample_width, int) or sample_width not in (1, 2, 3, 4):
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Unsupported sample width: {sample_width} bytes. "
                    f"Supported widths: 1 (8-bit), 2 (16-bit), 3 (24-bit), 4 (32-bit)."
                )
            return False

        sample_rate = getattr(audio_data, "sample_rate", None)
        if not isinstance(sample_rate, int) or sample_rate <= 0:
            if strict:
                raise AudioFormatIncompatibleError(f"Invalid sample rate: {sample_rate} Hz.")
            return False

        frame_count = getattr(audio_data, "frame_count", None)
        if not isinstance(frame_count, int) or frame_count <= 0:
            if strict:
                raise AudioFormatIncompatibleError(f"Invalid frame count: {frame_count}.")
            return False

        frames = getattr(audio_data, "frames", None)
        if not isinstance(frames, (bytes, bytearray)):
            if strict:
                raise AudioFormatIncompatibleError("Audio frames must be bytes or bytearray.")
            return False

        expected_byte_len = frame_count * channels * sample_width
        if len(frames) != expected_byte_len:
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Frame buffer size mismatch: expected {expected_byte_len} bytes for "
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
        Embed binary payload into carrier audio Channel 0 using Echo Hiding.

        Parameters:
            audio_data: Input carrier WavData container.
            payload: Binary payload bytes to embed.
            options:
                - alpha: Echo attenuation coefficient (default 0.08).
                - delay_0_ms: Bit 0 delay in ms (default 1.0).
                - delay_1_ms: Bit 1 delay in ms (default 1.3).
                - segment_size: Segment length in samples (default 2048).
                - fade_samples: Crossfade samples (default 200).
                - flags: CSMA 16-bit flags (default 0).

        Returns:
            StegoResult: Structured embedding results and modified stego audio.

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
        sample_rate = audio_data.sample_rate
        frame_count = audio_data.frame_count

        # 1. Resolve and validate signal processing options
        alpha, d0_ms, d1_ms, d0, d1, segment_size, fade_samples, flags = (
            _validate_and_resolve_echo_options(options, sample_rate)
        )

        # 2. Prepare universal CSMA v1 envelope
        framed_envelope = create_csma_envelope(
            payload=bytes(payload),
            algorithm=ALGO_ID_ECHO,
            flags=flags,
            sync_word=SYNC_WORD_ECHO,
        )
        envelope_bits = bytes_to_bits(framed_envelope)
        required_bits = len(envelope_bits)
        required_segments = required_bits  # 1 bit per segment

        # 3. Capacity check
        available_segments = frame_count // segment_size
        available_bits = available_segments * BITS_PER_SEGMENT

        if required_segments > available_segments:
            raise CapacityExceededError(
                f"Insufficient capacity in Echo Hiding carrier: requires {required_bits} bits "
                f"({required_segments} segments / {required_segments * segment_size} frames), "
                f"but carrier provides {available_bits} bits "
                f"({available_segments} segments / {available_segments * segment_size} frames)."
            )

        # 4. Decode audio samples to 16-bit reference amplitude scale
        decoded_samples = decode_pcm_to_ref16(audio_data.frames, sample_width)
        if channels == 2:
            samples_2d = decoded_samples.reshape(-1, 2)
            ch0 = np.copy(samples_2d[:, 0])
            ch1 = samples_2d[:, 1]  # Preserved untouched
        else:
            ch0 = np.copy(decoded_samples)
            ch1 = None

        # 5. Echo Modulation on Channel 0
        d_max = max(d0, d1)
        history = np.zeros(d_max, dtype=np.float64)
        prev_d = d0

        # Cross-fade window setup
        n_fade = min(fade_samples, segment_size // 4)
        if n_fade > 0:
            w_rise = 0.5 * (1.0 - np.cos(np.pi * np.arange(n_fade, dtype=np.float64) / n_fade))
            w_fall = 1.0 - w_rise
        else:
            w_rise = np.zeros(0, dtype=np.float64)
            w_fall = np.zeros(0, dtype=np.float64)

        for m in range(required_segments):
            bit = envelope_bits[m]
            curr_d = d1 if bit == 1 else d0

            seg_start = m * segment_size
            seg_end = seg_start + segment_size
            original_seg = np.copy(ch0[seg_start:seg_end])

            # Construct delayed echo using history buffer for n < d
            def _get_delayed_component(d: int) -> np.ndarray:
                hist_part = history[-d:]
                orig_part = original_seg[:-d]
                return np.concatenate([hist_part, orig_part])

            del_curr = _get_delayed_component(curr_d)

            if m == 0 or curr_d == prev_d or n_fade == 0:
                modulated = original_seg + alpha * del_curr
            else:
                del_prev = _get_delayed_component(prev_d)
                fade_echo = w_fall * del_prev[:n_fade] + w_rise * del_curr[:n_fade]
                modulated = np.copy(original_seg)
                modulated[:n_fade] += alpha * fade_echo
                modulated[n_fade:] += alpha * del_curr[n_fade:]

            ch0[seg_start:seg_end] = modulated
            history = original_seg[-d_max:].copy()
            prev_d = curr_d

        # 6. Recombine stereo channels (Channel 1 untouched)
        if channels == 2:
            recombined = np.column_stack([ch0, ch1]).reshape(-1)
        else:
            recombined = ch0

        # 7. Encode back to original PCM format with anti-wrap clipping
        modified_frames = encode_ref16_to_pcm(recombined, sample_width)

        utilization = round((required_bits / available_bits) * 100, 4) if available_bits > 0 else 0.0

        modified_wav = WavData(
            channels=channels,
            sample_rate=sample_rate,
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
                "alpha": alpha,
                "delay_0_ms": d0_ms,
                "delay_1_ms": d1_ms,
                "delay_0_samples": d0,
                "delay_1_samples": d1,
                "segment_size": segment_size,
                "fade_samples": n_fade,
                "flags": flags,
                "sync_word": hex(SYNC_WORD_ECHO),
            },
        )

    def extract(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> ExtractedPayload:
        """
        Extract embedded payload from carrier audio Channel 0 using Echo Hiding.

        Parameters:
            audio_data: Stego audio WavData container.
            options: Optional extraction parameter overrides.

        Returns:
            ExtractedPayload: Extracted and CRC32-verified payload data.

        Raises:
            HeaderNotFoundError: If carrier is too short or CSMA magic is missing.
            SynchronizationError: If preamble synchronization correlation fails.
            CorruptedPayloadError: If payload length is invalid or CRC32 fails.
            AudioFormatIncompatibleError: If audio container is invalid.
        """
        self._validate_audio_format(audio_data, strict=True)
        channels = audio_data.channels
        sample_width = audio_data.sample_width
        sample_rate = audio_data.sample_rate
        frame_count = audio_data.frame_count

        alpha, d0_ms, d1_ms, d0, d1, segment_size, fade_samples, _ = (
            _validate_and_resolve_echo_options(options, sample_rate)
        )

        # Minimum duration check: 18-byte CSMA header requires at least 144 segments
        min_required_frames = MIN_HEADER_SEGMENTS * segment_size
        if frame_count < min_required_frames:
            raise HeaderNotFoundError(
                f"Carrier audio is too short for Echo Hiding CSMA header: requires at least "
                f"{MIN_HEADER_SEGMENTS} segments ({min_required_frames} frames), "
                f"found only {frame_count} frames."
            )

        # 1. Decode Channel 0 samples
        decoded_samples = decode_pcm_to_ref16(audio_data.frames, sample_width)
        if channels == 2:
            ch0 = decoded_samples.reshape(-1, 2)[:, 0]
        else:
            ch0 = decoded_samples

        # 2. Inspect initial 16 segments for synchronization preamble
        n_fade = min(fade_samples, segment_size // 4)
        preamble_segments: list[np.ndarray] = [
            ch0[m * segment_size + n_fade : (m + 1) * segment_size]
            for m in range(MIN_PREAMBLE_SEGMENTS)
        ]

        rho, mean_pnr = calculate_echo_sync_metrics(preamble_segments, d0, d1)
        if rho < SYNC_CORRELATION_THRESHOLD:
            raise SynchronizationError(
                f"Echo Hiding synchronization failed: preamble correlation rho={rho:.4f} "
                f"is below threshold {SYNC_CORRELATION_THRESHOLD} (mean PNR={mean_pnr:.4f})."
            )

        # 3. Extract complete 18-byte (144-bit) CSMA header from initial 144 segments
        header_bits: list[int] = []
        for m in range(MIN_HEADER_SEGMENTS):
            seg = ch0[m * segment_size + n_fade : (m + 1) * segment_size]
            c = compute_real_cepstrum(seg)
            bit = 1 if c[d1] > c[d0] else 0
            header_bits.append(bit)

        header_bytes = bits_to_bytes(header_bits)

        # 4. Validate header magic
        magic = header_bytes[2:6]
        if magic != CSMA_MAGIC:
            raise HeaderNotFoundError(
                f"Invalid stego magic: expected {CSMA_MAGIC!r}, found {magic!r}. "
                f"Data does not start with a valid CSMA envelope."
            )

        # 5. Safe payload length extraction
        payload_len = struct.unpack(">I", header_bytes[10:14])[0]
        if payload_len > MAX_PAYLOAD_SIZE_BYTES:
            raise CorruptedPayloadError(
                f"Declared CSMA payload length ({payload_len} bytes) exceeds maximum allowable limit "
                f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
            )

        total_required_bits = (CSMA_HEADER_SIZE_BYTES + payload_len) * 8
        total_required_segments = total_required_bits
        available_segments = frame_count // segment_size

        if total_required_segments > available_segments:
            raise CorruptedPayloadError(
                f"Declared Echo Hiding payload requires {total_required_segments} segments "
                f"({total_required_segments * segment_size} frames), but carrier audio provides only "
                f"{available_segments} segments ({frame_count} frames)."
            )

        # 6. Extract remaining payload bits
        all_bits = list(header_bits)
        for m in range(MIN_HEADER_SEGMENTS, total_required_segments):
            seg = ch0[m * segment_size + n_fade : (m + 1) * segment_size]
            c = compute_real_cepstrum(seg)
            bit = 1 if c[d1] > c[d0] else 0
            all_bits.append(bit)

        envelope_data = bits_to_bytes(all_bits[:total_required_bits])

        # 7. Parse and verify with parse_csma_envelope
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
                "alpha": alpha,
                "flags": parsed_envelope.flags,
                "delay_0_ms": d0_ms,
                "delay_1_ms": d1_ms,
                "delay_0_samples": d0,
                "delay_1_samples": d1,
                "segment_size": segment_size,
                "sync_word": hex(parsed_envelope.sync_word),
                "sync_correlation": round(rho, 4),
                "mean_pnr": round(mean_pnr, 4),
            },
        )

    def estimate_capacity(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> CapacityProfile:
        """
        Calculate payload capacity for carrier audio using the Echo Hiding formula:
        C_raw = floor(N_frames / 2048) * 1 bit
        C_net_bytes = max(0, floor((C_raw - 144) / 8))
        """
        self._validate_audio_format(audio_data, strict=True)
        frame_count = audio_data.frame_count
        sample_rate = audio_data.sample_rate

        allowed_options = {
            "segment_size",
            "alpha",
            "delay_0_ms",
            "delay_1_ms",
            "fade_samples",
            "flags",
        }
        unknown_options = set(options.keys()) - allowed_options
        if unknown_options:
            raise UnsupportedParameterError(
                f"Unsupported capacity estimation options: {sorted(unknown_options)}."
            )

        raw_seg = options.get("segment_size", DEFAULT_SEGMENT_SIZE)
        segment_size = validate_segment_size(raw_seg)

        available_segments = frame_count // segment_size
        available_bits = available_segments * BITS_PER_SEGMENT
        available_bytes = available_bits // 8

        envelope_bits = CSMA_HEADER_SIZE_BYTES * 8  # 144 bits
        max_payload_bytes = max(0, (available_bits - envelope_bits) // 8)

        # Minimum duration: 18B header (144 bits) + 49B min CAUD payload (392 bits) = 536 bits
        # Required segments: 536 segments = 536 * 2048 = 1,097,728 frames
        min_required_frames = MIN_VALID_PAYLOAD_SEGMENTS * segment_size
        recommended_min_duration = min_required_frames / sample_rate if sample_rate > 0 else 0.0

        bits_per_sample = float(BITS_PER_SEGMENT) / float(segment_size)
        bits_per_second = (float(sample_rate) / float(segment_size)) * BITS_PER_SEGMENT if segment_size > 0 else 0.0

        return CapacityProfile(
            algorithm_id=self.algorithm_id,
            available_bits=available_bits,
            available_bytes=available_bytes,
            bits_per_sample=round(bits_per_sample, 8),
            bits_per_second=round(bits_per_second, 4),
            max_payload_bytes=max_payload_bytes,
            synchronization_overhead_bits=16,
            envelope_overhead_bits=envelope_bits,
            recommended_min_duration_sec=round(recommended_min_duration, 4),
        )

    def inspect_metadata(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> StegoInspection:
        """
        Non-destructive signature detection and header inspection summary for Echo Hiding.

        Parameters:
            audio_data: Audio container to inspect.
            options: Optional extraction overrides.

        Returns:
            StegoInspection: Detection results.
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

        sample_rate = audio_data.sample_rate
        sample_width = audio_data.sample_width
        channels = audio_data.channels

        try:
            _, _, _, d0, d1, segment_size, fade_samples, _ = _validate_and_resolve_echo_options(options, sample_rate)
        except (UnsupportedParameterError, AudioFormatIncompatibleError, Exception):
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        if audio_data.frame_count < MIN_HEADER_SEGMENTS * segment_size:
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        decoded_samples = decode_pcm_to_ref16(audio_data.frames, sample_width)
        if channels == 2:
            ch0 = decoded_samples.reshape(-1, 2)[:, 0]
        else:
            ch0 = decoded_samples

        n_fade = min(fade_samples, segment_size // 4)

        # Inspect initial 16 segments
        preamble_segments: list[np.ndarray] = [
            ch0[m * segment_size + n_fade : (m + 1) * segment_size]
            for m in range(MIN_PREAMBLE_SEGMENTS)
        ]

        rho, mean_pnr = calculate_echo_sync_metrics(preamble_segments, d0, d1)
        if rho < SYNC_CORRELATION_THRESHOLD:
            confidence = max(0.0, float(rho))
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=round(confidence, 4),
                header_valid=False,
                crc32_verified=False,
            )

        # Decode initial 144 segments to extract 18-byte CSMA header
        header_bits: list[int] = []
        for m in range(MIN_HEADER_SEGMENTS):
            seg = ch0[m * segment_size + n_fade : (m + 1) * segment_size]
            c = compute_real_cepstrum(seg)
            header_bits.append(1 if c[d1] > c[d0] else 0)

        header_bytes = bits_to_bytes(header_bits)
        if len(header_bytes) < CSMA_HEADER_SIZE_BYTES:
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
                header_valid=False,
                crc32_verified=False,
            )

        sync_word, magic, algo_id, version, flags, payload_len, _ = struct.unpack(
            CSMA_HEADER_STRUCT, header_bytes[:CSMA_HEADER_SIZE_BYTES]
        )

        is_echo = (magic == CSMA_MAGIC and algo_id == ALGO_ID_ECHO)
        header_valid = (
            is_echo
            and version == CSMA_VERSION
            and sync_word == SYNC_WORD_ECHO
            and payload_len <= MAX_PAYLOAD_SIZE_BYTES
        )

        confidence = min(1.0, max(0.0, float(rho)))

        return StegoInspection(
            has_stego_signature=is_echo,
            detected_algorithm=self.algorithm_id if is_echo else None,
            envelope_version=version if is_echo else None,
            payload_length_bytes=payload_len if (header_valid and payload_len <= MAX_PAYLOAD_SIZE_BYTES) else None,
            confidence_score=round(confidence, 4) if is_echo else 0.0,
            header_valid=header_valid,
            crc32_verified=False,
        )
