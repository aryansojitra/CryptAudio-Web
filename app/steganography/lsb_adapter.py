"""
app/steganography/lsb_adapter.py
CryptAudio Web — LSB Steganography Strategy Adapter (Phase M2)

Implements BaseStegoAlgorithm wrapping the LSB replacement engine.
Supports modern CSMA v1 framing on Channel 0 while maintaining full backward
compatibility for extracting legacy CSLB v1 payloads.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any, Final

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
    UnsupportedParameterError,
)
from app.steganography.envelope import (
    ALGO_ID_LSB,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_HEADER_STRUCT,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_LSB,
    create_csma_envelope,
    parse_csma_envelope,
)
from app.steganography.lsb_engine import (
    HEADER_SIZE_BITS as CSLB_HEADER_SIZE_BITS,
    HEADER_SIZE_BYTES as CSLB_HEADER_SIZE_BYTES,
    STEGO_MAGIC as CSLB_MAGIC,
    STEGO_VERSION as CSLB_VERSION,
    bits_to_bytes,
    bytes_to_bits,
    create_framed_payload as create_cslb_framed_payload,
)


class LSBAdapter(BaseStegoAlgorithm):
    """
    Adapter integrating LSB audio steganography into the multi-algorithm architecture.

    Features:
    - Implements BaseStegoAlgorithm.
    - Default Embedding: Encapsulates payload in CSMA v1 envelope and embeds strictly
      into Channel 0 (Left channel). Channel 1 (Right channel) is preserved untouched.
    - Legacy Extraction: Automatically detects and extracts legacy CSLB v1 payloads
      as well as modern CSMA v1 payloads.
    - Strict capacity enforcement and non-destructive metadata inspection.
    """

    ALGORITHM_ID: Final[str] = "lsb"
    DISPLAY_NAME: Final[str] = "Least Significant Bit (LSB) Spatial Steganography"

    @property
    def algorithm_id(self) -> str:
        """Unique machine identifier."""
        return self.ALGORITHM_ID

    @property
    def display_name(self) -> str:
        """Human-readable display title."""
        return self.DISPLAY_NAME

    @property
    def domain(self) -> DomainType:
        """Operational domain classification: Spatial Time Domain."""
        return DomainType.SPATIAL_TIME

    @property
    def robustness_objective(self) -> RobustnessEvaluationStatus:
        """Robustness evaluation status: Fragile by design."""
        return RobustnessEvaluationStatus.FRAGILE_BY_DESIGN

    def _validate_audio_format(self, audio_data: WavData, strict: bool = True) -> bool:
        """
        Validate audio container format, sample width, channels, and frame buffer.

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
                    f"LSB steganography supports 1 or 2 channels, found {channels}."
                )
            return False

        sample_width = getattr(audio_data, "sample_width", None)
        if not isinstance(sample_width, int) or sample_width not in (1, 2, 3, 4):
            if strict:
                raise AudioFormatIncompatibleError(
                    f"Unsupported sample width: {sample_width} bytes ({sample_width * 8 if isinstance(sample_width, int) else 'unknown'}-bit)."
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
        Embed an arbitrary binary payload into carrier audio using 1-bit LSB replacement.

        Parameters:
            audio_data: Input carrier WavData container.
            payload: Binary payload bytes to conceal.
            options:
                - framing: 'csma' (default) or 'legacy_cslb'
                - flags: 16-bit flags for CSMA envelope (default 0)

        Returns:
            StegoResult: Embedding metadata and modified WavData.

        Raises:
            CapacityExceededError: If host audio lacks capacity for framed payload.
            AudioFormatIncompatibleError: If audio format is not supported uncompressed PCM.
            UnsupportedParameterError: If payload or options are invalid.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise UnsupportedParameterError("Payload must be bytes or bytearray.")
        if len(payload) == 0:
            raise UnsupportedParameterError("Payload cannot be empty.")

        allowed_options = {"framing", "flags"}
        unknown = set(options.keys()) - allowed_options
        if unknown:
            raise UnsupportedParameterError(
                f"LSB embedding does not support options: {sorted(unknown)}."
            )

        framing = options.get("framing", "csma")
        if not isinstance(framing, str):
            raise UnsupportedParameterError(
                f"Framing option must be a string, got {type(framing).__name__}."
            )
        normalized_framing = framing.strip().lower()
        if normalized_framing not in ("csma", "legacy_cslb"):
            raise UnsupportedParameterError(
                f"Unsupported framing protocol: '{framing}'. Supported: 'csma', 'legacy_cslb'."
            )

        self._validate_audio_format(audio_data, strict=True)
        channels = audio_data.channels
        sample_width = audio_data.sample_width
        frame_count = audio_data.frame_count

        # 1. Prepare framed payload
        if normalized_framing == "legacy_cslb":
            framed_payload = create_cslb_framed_payload(bytes(payload))
            bits = bytes_to_bits(framed_payload)
            required_bits = len(bits)
            # Legacy LSB allowed embedding across all available samples
            available_bits = frame_count * channels
            if required_bits > available_bits:
                raise CapacityExceededError(
                    f"Insufficient capacity for legacy CSLB payload: requires {required_bits} bits, "
                    f"carrier provides {available_bits} samples/bits."
                )
            # Embed sequentially into all samples (legacy behavior)
            frame_bytes = bytearray(audio_data.frames)
            for i, bit in enumerate(bits):
                offset = i * sample_width
                frame_bytes[offset] = (frame_bytes[offset] & 0xFE) | bit

        elif normalized_framing == "csma":
            flags = options.get("flags", 0)
            framed_payload = create_csma_envelope(
                payload=bytes(payload),
                algorithm=self.ALGORITHM_ID,
                flags=flags,
                sync_word=SYNC_WORD_LSB,
            )
            bits = bytes_to_bits(framed_payload)
            required_bits = len(bits)
            # Policy: Embedding restricted strictly to Channel 0
            available_bits = frame_count
            if required_bits > available_bits:
                raise CapacityExceededError(
                    f"Insufficient capacity on Channel 0: requires {required_bits} bits "
                    f"({len(framed_payload)} bytes), but carrier has {available_bits} frames."
                )

            # Embed strictly on Channel 0
            frame_bytes = bytearray(audio_data.frames)
            bytes_per_frame = channels * sample_width
            for frame_idx, bit in enumerate(bits):
                # Channel 0 sample starts at byte offset `frame_idx * bytes_per_frame`
                offset = frame_idx * bytes_per_frame
                frame_bytes[offset] = (frame_bytes[offset] & 0xFE) | bit

        utilization = round((required_bits / available_bits) * 100, 4)

        modified_wav = WavData(
            channels=channels,
            sample_rate=audio_data.sample_rate,
            sample_width=sample_width,
            frame_count=frame_count,
            compression_type=audio_data.compression_type,
            compression_name=audio_data.compression_name,
            frames=bytes(frame_bytes),
        )

        return StegoResult(
            success=True,
            algorithm_id=self.ALGORITHM_ID,
            modified_wav=modified_wav,
            payload_size_bytes=len(payload),
            framed_size_bytes=len(framed_payload),
            required_bits=required_bits,
            available_bits=available_bits,
            utilization_percent=utilization,
            algorithm_parameters={
                "framing": framing,
                "channel_policy": "channel_0_only" if framing == "csma" else "all_samples",
            },
        )

    def extract(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> ExtractedPayload:
        """
        Extract and verify an embedded payload from a stego audio container.

        Automatically detects and supports:
        1. Modern CSMA v1 envelope on Channel 0.
        2. Legacy CSLB v1 envelope across all samples or Channel 0.

        Parameters:
            audio_data: Input stego WavData container.
            options: Algorithm-specific extraction options.

        Returns:
            ExtractedPayload: Extracted payload bytes and verification metadata.

        Raises:
            AudioFormatIncompatibleError: If audio format is invalid or unsupported.
            HeaderNotFoundError: If neither CSMA nor CSLB headers can be found.
            CorruptedPayloadError: If payload CRC32 fails, length is invalid, or data is truncated.
        """
        self._validate_audio_format(audio_data, strict=True)
        allowed_options = {"framing"}
        unknown = set(options.keys()) - allowed_options
        if unknown:
            raise UnsupportedParameterError(
                f"LSB extraction does not support options: {sorted(unknown)}."
            )

        framing = options.get("framing", "csma")
        if not isinstance(framing, str):
            raise UnsupportedParameterError(
                f"Framing option must be a string, got {type(framing).__name__}."
            )
        normalized_framing = framing.strip().lower()
        if normalized_framing not in ("csma", "legacy_cslb"):
            raise UnsupportedParameterError(
                f"Unsupported framing protocol: '{framing}'. Supported: 'csma', 'legacy_cslb'."
            )

        channels = audio_data.channels
        sample_width = audio_data.sample_width
        frame_count = audio_data.frame_count
        frame_bytes = audio_data.frames
        bytes_per_frame = channels * sample_width

        # -------------------------------------------------------------------
        # 1. Attempt CSMA v1 extraction on Channel 0 (unless caller explicitly requested legacy_cslb)
        # -------------------------------------------------------------------
        if normalized_framing != "legacy_cslb" and frame_count >= CSMA_HEADER_SIZE_BYTES * 8:
            header_bits = [
                frame_bytes[n * bytes_per_frame] & 1
                for n in range(CSMA_HEADER_SIZE_BYTES * 8)
            ]
            header_bytes = bits_to_bytes(header_bits)
            magic = header_bytes[2:6]

            if magic == CSMA_MAGIC:
                # Unpack declared payload length safely
                payload_len = struct.unpack(">I", header_bytes[10:14])[0]
                if payload_len > MAX_PAYLOAD_SIZE_BYTES:
                    raise CorruptedPayloadError(
                        f"CSMA declared payload length ({payload_len} bytes) exceeds maximum allowable limit "
                        f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
                    )
                total_required_bits = (CSMA_HEADER_SIZE_BYTES + payload_len) * 8

                if total_required_bits > frame_count:
                    raise CorruptedPayloadError(
                        f"CSMA declared payload length ({payload_len} bytes) requires "
                        f"{total_required_bits} frames, but audio has only {frame_count} frames."
                    )

                # Extract complete envelope bytes from Channel 0
                all_bits = [
                    frame_bytes[n * bytes_per_frame] & 1
                    for n in range(total_required_bits)
                ]
                all_bytes = bits_to_bytes(all_bits)

                # Parse and verify CRC32
                parsed_envelope = parse_csma_envelope(
                    all_bytes,
                    expected_algorithm=self.ALGORITHM_ID,
                    enforce_sync_word=True,
                )

                if parsed_envelope.flags != 0:
                    raise CorruptedPayloadError(
                        f"Invalid flags in LSB CSMA header: {parsed_envelope.flags:#06x}. Expected 0x0000."
                    )

                return ExtractedPayload(
                    success=True,
                    algorithm_id=self.ALGORITHM_ID,
                    payload=parsed_envelope.payload,
                    integrity_verified=True,
                    framing_checksum_verified=True,
                    algorithm_parameters={
                        "framing": "csma_v1",
                        "channel_policy": "channel_0_only",
                        "sync_word": hex(parsed_envelope.sync_word),
                        "flags": parsed_envelope.flags,
                    },
                )

        # -------------------------------------------------------------------
        # 2. Attempt Legacy CSLB v1 extraction (sequential samples)
        # -------------------------------------------------------------------
        total_samples = frame_count * channels
        if total_samples >= CSLB_HEADER_SIZE_BITS:
            header_bits = [
                frame_bytes[i * sample_width] & 1
                for i in range(CSLB_HEADER_SIZE_BITS)
            ]
            header_bytes = bits_to_bytes(header_bits)
            magic = header_bytes[:4]

            if magic == CSLB_MAGIC:
                version = header_bytes[4]
                if version != CSLB_VERSION:
                    raise CorruptedPayloadError(
                        f"Unsupported legacy CSLB version: {version}. Expected {CSLB_VERSION}."
                    )

                payload_len = struct.unpack(">I", header_bytes[5:9])[0]
                if payload_len > MAX_PAYLOAD_SIZE_BYTES:
                    raise CorruptedPayloadError(
                        f"Legacy CSLB declared payload length ({payload_len} bytes) exceeds maximum allowable limit "
                        f"({MAX_PAYLOAD_SIZE_BYTES} bytes / 16 MB)."
                    )
                expected_crc = struct.unpack(">I", header_bytes[9:13])[0]
                total_required_bits = CSLB_HEADER_SIZE_BITS + (payload_len * 8)

                if total_required_bits > total_samples:
                    raise CorruptedPayloadError(
                        f"Legacy CSLB declared payload requires {total_required_bits} samples, "
                        f"but audio has only {total_samples} samples."
                    )

                payload_bits = [
                    frame_bytes[i * sample_width] & 1
                    for i in range(CSLB_HEADER_SIZE_BITS, total_required_bits)
                ]
                payload_bytes = bits_to_bytes(payload_bits)

                actual_crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF
                if actual_crc != expected_crc:
                    raise CorruptedPayloadError(
                        f"Legacy CSLB CRC32 mismatch: expected {expected_crc:#010x}, "
                        f"computed {actual_crc:#010x}."
                    )

                return ExtractedPayload(
                    success=True,
                    algorithm_id=self.ALGORITHM_ID,
                    payload=payload_bytes,
                    integrity_verified=True,
                    framing_checksum_verified=True,
                    algorithm_parameters={
                        "framing": "legacy_cslb",
                        "channel_policy": "all_samples_sequential",
                        "version": version,
                    },
                )

        # -------------------------------------------------------------------
        # 3. No recognizable header found
        # -------------------------------------------------------------------
        raise HeaderNotFoundError(
            "No valid CSMA v1 or legacy CSLB steganography header found in carrier audio."
        )

    def estimate_capacity(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> CapacityProfile:
        """
        Calculate payload capacity for the given carrier audio parameters.

        In CSMA mode, capacity is governed strictly by Channel 0 frames:
        C_raw = N_frames bits
        C_net_bytes = max(0, floor((C_raw - 144) / 8))
        """
        self._validate_audio_format(audio_data, strict=True)
        allowed_options = {"framing"}
        unknown = set(options.keys()) - allowed_options
        if unknown:
            raise UnsupportedParameterError(
                f"LSB capacity estimation does not support options: {sorted(unknown)}."
            )
        framing = options.get("framing", "csma")
        if not isinstance(framing, str):
            raise UnsupportedParameterError(
                f"Framing option must be a string, got {type(framing).__name__}."
            )
        normalized_framing = framing.strip().lower()
        if normalized_framing not in ("csma", "legacy_cslb"):
            raise UnsupportedParameterError(
                f"Unsupported framing protocol: '{framing}'. Supported: 'csma', 'legacy_cslb'."
            )

        frame_count = audio_data.frame_count
        sample_rate = audio_data.sample_rate

        if normalized_framing == "legacy_cslb":
            # Legacy capacity across all samples with 104-bit header
            total_samples = frame_count * audio_data.channels
            available_bits = total_samples
            envelope_bits = CSLB_HEADER_SIZE_BITS  # 104
            available_bytes = available_bits // 8
            max_payload_bytes = max(0, (available_bits - envelope_bits) // 8)
            recommended_min_duration = (536) / (sample_rate * audio_data.channels)
        else:
            # Modern CSMA policy: Channel 0 only with 144-bit envelope
            available_bits = frame_count
            envelope_bits = CSMA_HEADER_SIZE_BYTES * 8  # 144 bits
            available_bytes = available_bits // 8
            max_payload_bytes = max(0, (available_bits - envelope_bits) // 8)
            # Minimum duration for 49B CAUD payload (536 bits)
            recommended_min_duration = 536.0 / sample_rate

        duration_sec = frame_count / sample_rate if sample_rate > 0 else 0.0
        bits_per_sample = 1.0  # 1 bit per Channel 0 sample
        bits_per_second = float(sample_rate)

        return CapacityProfile(
            algorithm_id=self.ALGORITHM_ID,
            available_bits=available_bits,
            available_bytes=available_bytes,
            bits_per_sample=bits_per_sample,
            bits_per_second=bits_per_second,
            max_payload_bytes=max_payload_bytes,
            synchronization_overhead_bits=0,  # Subsumed within the 144-bit envelope
            envelope_overhead_bits=envelope_bits,
            recommended_min_duration_sec=round(recommended_min_duration, 4),
        )

    def inspect_metadata(
        self,
        audio_data: WavData,
    ) -> StegoInspection:
        """
        Non-destructively inspect carrier audio for CSMA or legacy CSLB signatures.

        Requires full validation of header fields (magic, version, algorithm ID,
        synchronization word, payload length bounds) before asserting a confident signature.
        Never extracts or allocates the complete payload during metadata inspection.
        """
        if not self._validate_audio_format(audio_data, strict=False):
            return StegoInspection(
                has_stego_signature=False,
                detected_algorithm=None,
                envelope_version=None,
                payload_length_bytes=None,
                confidence_score=0.0,
            )

        channels = audio_data.channels
        sample_width = audio_data.sample_width
        frame_count = audio_data.frame_count
        frame_bytes = audio_data.frames
        bytes_per_frame = channels * sample_width

        # Check Channel 0 for CSMA
        if frame_count >= CSMA_HEADER_SIZE_BYTES * 8:
            header_bits = [
                frame_bytes[n * bytes_per_frame] & 1
                for n in range(CSMA_HEADER_SIZE_BYTES * 8)
            ]
            header_bytes = bits_to_bytes(header_bits)
            try:
                sync_word, magic, algo_id, version, flags, payload_len, expected_crc = struct.unpack(
                    CSMA_HEADER_STRUCT, header_bytes
                )
            except struct.error:
                sync_word, magic, algo_id, version, flags, payload_len, expected_crc = (
                    None, None, None, None, None, None, None
                )

            # Full validation of CSMA header fields for LSB:
            # - magic must match CSMA_MAGIC (b"CSMA")
            # - version must match CSMA_VERSION (1)
            # - algo_id must match ALGO_ID_LSB (1)
            # - sync_word must match canonical SYNC_WORD_LSB (0xF9A9)
            # - payload_len must be within allowable bounds (0 < payload_len <= MAX_PAYLOAD_SIZE_BYTES)
            # - carrier must contain enough frames for declared payload
            if (
                magic == CSMA_MAGIC
                and version == CSMA_VERSION
                and algo_id == ALGO_ID_LSB
                and sync_word == SYNC_WORD_LSB
                and 0 < payload_len <= MAX_PAYLOAD_SIZE_BYTES
                and (CSMA_HEADER_SIZE_BYTES + payload_len) * 8 <= frame_count
            ):
                return StegoInspection(
                    has_stego_signature=True,
                    detected_algorithm=self.ALGORITHM_ID,
                    envelope_version=version,
                    payload_length_bytes=payload_len,
                    confidence_score=1.0,
                    header_valid=True,
                    crc32_verified=False,
                )

        # Check sequential samples for legacy CSLB
        total_samples = frame_count * channels
        if total_samples >= CSLB_HEADER_SIZE_BITS:
            header_bits = [
                frame_bytes[i * sample_width] & 1
                for i in range(CSLB_HEADER_SIZE_BITS)
            ]
            header_bytes = bits_to_bytes(header_bits)
            magic = header_bytes[:4]
            if magic == CSLB_MAGIC:
                version = header_bytes[4]
                try:
                    payload_len = struct.unpack(">I", header_bytes[5:9])[0]
                except struct.error:
                    payload_len = None

                if (
                    version == CSLB_VERSION
                    and payload_len is not None
                    and 0 < payload_len <= MAX_PAYLOAD_SIZE_BYTES
                    and CSLB_HEADER_SIZE_BITS + (payload_len * 8) <= total_samples
                ):
                    return StegoInspection(
                        has_stego_signature=True,
                        detected_algorithm=self.ALGORITHM_ID,
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
