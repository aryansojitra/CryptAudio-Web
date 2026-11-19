"""
app/steganography/base.py
CryptAudio Web — Common Audio Steganography Algorithm Interface (Phase M2)

Defines the abstract Strategy interface (`BaseStegoAlgorithm`), associated
domain/robustness enumerations, data models, and standardized exception hierarchy
governing all steganography algorithms in CryptAudio-Web.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from app.audio.wav_handler import WavData


# ---------------------------------------------------------------------------
# Domain & Robustness Enumerations
# ---------------------------------------------------------------------------

class DomainType(str, Enum):
    """Operational mathematical domain of the steganography algorithm."""

    SPATIAL_TIME = "spatial_time_domain"
    TRANSFORM = "transform_domain"
    ACOUSTIC_TIME = "acoustic_time_domain"


class RobustnessEvaluationStatus(str, Enum):
    """
    Evaluation status of algorithm channel robustness.
    
    Avoids asserting unverified capabilities prior to empirical testing.
    """

    FRAGILE_BY_DESIGN = "fragile_by_design"         # Altered by any bit/sample change (e.g. LSB)
    EXPERIMENTAL_TARGET = "experimental_target"     # Intended design objective
    ROBUSTNESS_UNVERIFIED = "robustness_unverified" # Verification pending empirical test battery
    NOT_EVALUATED = "not_evaluated"                 # No empirical channel tests performed


# ---------------------------------------------------------------------------
# Standardized Exception Hierarchy
# ---------------------------------------------------------------------------

class StegoAlgorithmError(Exception):
    """Base exception for all multi-algorithm steganography operations."""


class CapacityExceededError(StegoAlgorithmError):
    """Raised when the payload size exceeds carrier capacity for the chosen algorithm."""


class HeaderNotFoundError(StegoAlgorithmError):
    """Raised when expected steganography header, magic, or preamble is not found."""


class SynchronizationError(StegoAlgorithmError):
    """Raised when synchronization preamble detection or correlation fails."""


class CorruptedPayloadError(StegoAlgorithmError):
    """Raised when payload integrity (e.g. CRC32 checksum) fails or data is truncated."""


class AudioFormatIncompatibleError(StegoAlgorithmError):
    """Raised when carrier audio format (sample rate, bit-depth, channels) is incompatible."""


class UnsupportedParameterError(StegoAlgorithmError):
    """Raised when invalid or unsupported algorithm parameters/options are supplied."""


class AlgorithmRegistryError(StegoAlgorithmError):
    """Raised when registry encounters duplicate, unknown, or invalid algorithm registrations."""


# ---------------------------------------------------------------------------
# Standardized Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapacityProfile:
    """Parametric capacity breakdown for a specific carrier audio track and algorithm."""

    algorithm_id: str
    available_bits: int
    available_bytes: int
    bits_per_sample: float
    bits_per_second: float
    max_payload_bytes: int
    synchronization_overhead_bits: int
    envelope_overhead_bits: int
    recommended_min_duration_sec: float

    def to_dict(self) -> dict[str, Any]:
        """Convert profile to dictionary representation."""
        return asdict(self)


@dataclass(frozen=True)
class StegoResult:
    """Structured result of an in-memory steganographic embedding operation."""

    success: bool
    algorithm_id: str
    modified_wav: WavData
    payload_size_bytes: int
    framed_size_bytes: int
    required_bits: int
    available_bits: int
    utilization_percent: float
    algorithm_parameters: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        data = asdict(self)
        data["modified_wav"] = self.modified_wav.to_dict()
        return data


@dataclass(frozen=True)
class ExtractedPayload:
    """
    Structured result of a steganographic payload extraction operation.

    Integrity Terminology:
    - CRC32 verified = framing checksum passed (detects accidental transmission corruption).
      Reflected by `framing_checksum_verified`. This does NOT guarantee cryptographic
      authenticity or protect against deliberate tampering.
    - AES-GCM authenticated = cryptographic authentication succeeded during decryption
      via the 128-bit authentication tag using GHASH. Cryptographic authentication is
      handled exclusively at the decryption layer, NOT at the steganographic framing layer.
    """

    success: bool
    algorithm_id: str
    payload: bytes
    integrity_verified: bool  # [DEPRECATED] Alias for framing_checksum_verified; retained for backward compatibility.
    algorithm_parameters: dict[str, Any]
    framing_checksum_verified: bool = True  # Framing CRC32 checksum verification status

    def to_dict(self) -> dict[str, Any]:
        """
        Convert result to dictionary representation.

        Note: The deprecated `integrity_verified` attribute is excluded from serialized
        representations; `framing_checksum_verified` is exposed instead.
        """
        return {
            "success": self.success,
            "algorithm_id": self.algorithm_id,
            "payload_size_bytes": len(self.payload),
            "framing_checksum_verified": self.framing_checksum_verified,
            "algorithm_parameters": self.algorithm_parameters,
        }


@dataclass(frozen=True)
class StegoInspection:
    """
    Non-destructive signature detection and header inspection summary.

    Verification Distinction:
    - Signature detected: `has_stego_signature` indicates preamble/sync word match.
    - Header structurally valid: `header_valid` indicates valid magic, version, flags, and size.
    - Payload CRC32 verified: `crc32_verified` indicates complete payload checksum check.
      (Note: Metadata inspection only inspects the initial header chunks and therefore
      does NOT verify payload CRC32; `crc32_verified` remains False until full extraction).
    - AES-GCM authentication verified: Cryptographic authenticity is verified only
      during payload decryption with the secret key, never by steganography inspection.
    """

    has_stego_signature: bool
    detected_algorithm: str | None
    envelope_version: int | None
    payload_length_bytes: int | None
    confidence_score: float
    header_valid: bool = False
    crc32_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert inspection to dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Abstract Base Stego Algorithm Interface
# ---------------------------------------------------------------------------

class BaseStegoAlgorithm(ABC):
    """Abstract Strategy interface for all audio steganography implementations."""

    @property
    @abstractmethod
    def algorithm_id(self) -> str:
        """Unique machine identifier ('lsb', 'dwt_dct_qim', 'echo')."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display title."""

    @property
    @abstractmethod
    def domain(self) -> DomainType:
        """Operational domain classification."""

    @property
    @abstractmethod
    def robustness_objective(self) -> RobustnessEvaluationStatus:
        """Evaluation status of channel robustness."""

    @abstractmethod
    def embed(
        self,
        audio_data: WavData,
        payload: bytes,
        **options: Any,
    ) -> StegoResult:
        """
        Embed an opaque binary payload into carrier audio in-memory.

        Parameters:
            audio_data: Input carrier WavData container.
            payload: Binary payload bytes (e.g. encrypted CAUD blob).
            options: Algorithm-specific parameters (e.g. framing, delta, delays).

        Returns:
            StegoResult: Metadata and modified WavData containing the stego audio.

        Raises:
            CapacityExceededError: If audio lacks capacity for payload and envelope.
            AudioFormatIncompatibleError: If carrier format is unsupported.
            UnsupportedParameterError: If options are invalid.
            StegoAlgorithmError: On embedding failure.
        """

    @abstractmethod
    def extract(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> ExtractedPayload:
        """
        Extract concealed binary payload from stego audio in-memory.

        Parameters:
            audio_data: Input stego WavData container.
            options: Algorithm-specific parameters.

        Returns:
            ExtractedPayload: Extracted payload bytes and verification metadata.

        Raises:
            HeaderNotFoundError: If stego header or synchronization cannot be located.
            SynchronizationError: If frame/block alignment fails.
            CorruptedPayloadError: If payload fails integrity checks or is truncated.
            StegoAlgorithmError: On extraction failure.
        """

    @abstractmethod
    def estimate_capacity(
        self,
        audio_data: WavData,
        **options: Any,
    ) -> CapacityProfile:
        """
        Calculate payload capacity for the given carrier audio parameters.

        Parameters:
            audio_data: Input carrier WavData container.
            options: Algorithm-specific parameters.

        Returns:
            CapacityProfile: Structured capacity metrics.
        """

    @abstractmethod
    def inspect_metadata(
        self,
        audio_data: WavData,
    ) -> StegoInspection:
        """
        Non-destructive signature detection and header inspection.

        Parameters:
            audio_data: Input audio WavData container.

        Returns:
            StegoInspection: Inspection summary without modifying audio.
        """
