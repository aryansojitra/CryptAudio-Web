"""
app/steganography/registry.py
CryptAudio Web — Steganography Algorithm Registry (Phase M2)

Provides thread-safe registration, discovery, validation, and retrieval for
audio steganography algorithms conforming to BaseStegoAlgorithm.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass
from typing import Any, Final

from app.audio.wav_handler import WavData
from app.steganography.base import (
    AlgorithmRegistryError,
    BaseStegoAlgorithm,
    DomainType,
    RobustnessEvaluationStatus,
)

logger = logging.getLogger(__name__)

# Canonical machine identifiers
KNOWN_ALGORITHM_IDS: Final[frozenset[str]] = frozenset({
    "lsb",
    "dwt_dct_qim",
    "echo",
})


@dataclass(frozen=True)
class AlgorithmDescriptor:
    """Public summary metadata for an available steganography algorithm."""

    algorithm_id: str
    display_name: str
    domain: DomainType
    robustness_objective: RobustnessEvaluationStatus

    def to_dict(self) -> dict[str, Any]:
        """Convert descriptor to dictionary representation."""
        return {
            "algorithm_id": self.algorithm_id,
            "display_name": self.display_name,
            "domain": self.domain.value,
            "robustness_objective": self.robustness_objective.value,
        }


class StegoRegistry:
    """
    Central registry for all steganography algorithms.
    
    Thread-safe registry ensuring algorithms conform to BaseStegoAlgorithm
    and preventing duplicate or invalid registrations.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._algorithms: dict[str, BaseStegoAlgorithm] = {}

    def register(self, algorithm: BaseStegoAlgorithm) -> None:
        """
        Register a new steganography algorithm instance.

        Parameters:
            algorithm: An instance of a concrete BaseStegoAlgorithm subclass.

        Raises:
            AlgorithmRegistryError: If algorithm is invalid, not an instance of
                                    BaseStegoAlgorithm, has an unsupported ID,
                                    or is already registered.
        """
        if not isinstance(algorithm, BaseStegoAlgorithm):
            raise AlgorithmRegistryError(
                f"Cannot register {type(algorithm).__name__}: "
                f"must be an instance of BaseStegoAlgorithm."
            )

        algo_id = getattr(algorithm, "algorithm_id", None)
        if not isinstance(algo_id, str) or not algo_id.strip():
            raise AlgorithmRegistryError(
                f"Cannot register {type(algorithm).__name__}: "
                f"algorithm_id must be a non-empty string."
            )

        normalized_id = algo_id.strip().lower()
        if normalized_id not in KNOWN_ALGORITHM_IDS:
            raise AlgorithmRegistryError(
                f"Cannot register algorithm with unknown ID '{algo_id}'. "
                f"Supported IDs: {sorted(KNOWN_ALGORITHM_IDS)}."
            )

        with self._lock:
            if normalized_id in self._algorithms:
                raise AlgorithmRegistryError(
                    f"Algorithm '{normalized_id}' is already registered "
                    f"({type(self._algorithms[normalized_id]).__name__}). "
                    f"Duplicate registrations are rejected."
                )

            self._algorithms[normalized_id] = algorithm
            logger.info(
                "Registered steganography algorithm: %s (%s)",
                normalized_id,
                algorithm.display_name,
            )

    def unregister(self, algorithm_id: str) -> None:
        """
        Unregister an algorithm by ID (primarily for testing).

        Parameters:
            algorithm_id: Machine identifier.
        """
        normalized_id = algorithm_id.strip().lower()
        with self._lock:
            if normalized_id in self._algorithms:
                del self._algorithms[normalized_id]

    def clear(self) -> None:
        """Clear all registered algorithms (for testing)."""
        with self._lock:
            self._algorithms.clear()

    def get(self, algorithm_id: str | int) -> BaseStegoAlgorithm:
        """
        Retrieve a registered algorithm by its machine identifier or numeric ID.

        Parameters:
            algorithm_id: Machine identifier (e.g. 'lsb', 'echo') or integer ID (e.g. 1, 2, 3).

        Returns:
            BaseStegoAlgorithm: The registered algorithm instance.

        Raises:
            AlgorithmRegistryError: If algorithm_id is unknown or not registered.
        """
        if isinstance(algorithm_id, str) and algorithm_id.strip().lower() == "legacy_cslb":
            return self.get("lsb")

        if isinstance(algorithm_id, int) and not isinstance(algorithm_id, bool):
            from app.steganography.envelope import ALGO_ID_TO_NAME
            if algorithm_id not in ALGO_ID_TO_NAME:
                raise AlgorithmRegistryError(
                    f"Unsupported algorithm integer ID: {algorithm_id}."
                )
            normalized_id = ALGO_ID_TO_NAME[algorithm_id]
        elif isinstance(algorithm_id, str):
            normalized_id = algorithm_id.strip().lower()
            if normalized_id.startswith("0x"):
                try:
                    int_id = int(normalized_id, 16)
                    from app.steganography.envelope import ALGO_ID_TO_NAME
                    if int_id in ALGO_ID_TO_NAME:
                        normalized_id = ALGO_ID_TO_NAME[int_id]
                except ValueError:
                    pass
            elif normalized_id.isdigit():
                int_id = int(normalized_id)
                from app.steganography.envelope import ALGO_ID_TO_NAME
                if int_id in ALGO_ID_TO_NAME:
                    normalized_id = ALGO_ID_TO_NAME[int_id]
        else:
            raise AlgorithmRegistryError(
                f"Algorithm ID must be a string or integer, got {type(algorithm_id).__name__}."
            )

        with self._lock:
            if normalized_id not in self._algorithms:
                available = sorted(self._algorithms.keys())
                raise AlgorithmRegistryError(
                    f"Steganography algorithm '{algorithm_id}' is not registered. "
                    f"Available algorithms: {available}."
                )

            return self._algorithms[normalized_id]

    def list_available(self) -> list[AlgorithmDescriptor]:
        """
        List descriptors for all currently registered algorithms.

        Returns:
            list[AlgorithmDescriptor]: Ordered list of descriptors.
        """
        with self._lock:
            descriptors = [
                AlgorithmDescriptor(
                    algorithm_id=algo.algorithm_id,
                    display_name=algo.display_name,
                    domain=algo.domain,
                    robustness_objective=algo.robustness_objective,
                )
                for algo in self._algorithms.values()
            ]
        return sorted(descriptors, key=lambda d: d.algorithm_id)

    def is_registered(self, algorithm_id: str | int) -> bool:
        """Check if an algorithm is registered by name or numeric ID."""
        if isinstance(algorithm_id, str) and algorithm_id.strip().lower() == "legacy_cslb":
            return True

        if isinstance(algorithm_id, int) and not isinstance(algorithm_id, bool):
            from app.steganography.envelope import ALGO_ID_TO_NAME
            normalized_id = ALGO_ID_TO_NAME.get(algorithm_id, "")
        elif isinstance(algorithm_id, str):
            normalized_id = algorithm_id.strip().lower()
            if normalized_id.startswith("0x"):
                try:
                    int_id = int(normalized_id, 16)
                    from app.steganography.envelope import ALGO_ID_TO_NAME
                    normalized_id = ALGO_ID_TO_NAME.get(int_id, normalized_id)
                except ValueError:
                    pass
            elif normalized_id.isdigit():
                int_id = int(normalized_id)
                from app.steganography.envelope import ALGO_ID_TO_NAME
                normalized_id = ALGO_ID_TO_NAME.get(int_id, normalized_id)
        else:
            return False

        with self._lock:
            return normalized_id in self._algorithms

    def detect_algorithm(self, audio_data: WavData) -> BaseStegoAlgorithm | None:
        """
        Inspect carrier audio using registered algorithms to detect steganographic signature.

        Takes a snapshot of registered algorithms under lock and releases the lock before
        invoking inspect_metadata() on each candidate to prevent holding registry locks during
        carrier processing.

        Parameters:
            audio_data: Audio container to inspect.

        Returns:
            BaseStegoAlgorithm or None if no algorithm detects its signature.
        """
        with self._lock:
            candidates = list(self._algorithms.values())

        for algorithm in candidates:
            inspection = algorithm.inspect_metadata(audio_data)
            if inspection.has_stego_signature:
                return algorithm
        return None


# ---------------------------------------------------------------------------
# Global Singleton Access
# ---------------------------------------------------------------------------

_REGISTRY_LOCK: Final[threading.RLock] = threading.RLock()
_REGISTRY_INSTANCE: StegoRegistry | None = None


def get_registry(include_echo: bool = False) -> StegoRegistry:
    """
    Get or initialize the global StegoRegistry singleton in a thread-safe manner.
    
    Contains LSBAdapter and DWTDCTQIMAlgorithm as default active algorithms.
    If include_echo is True, EchoHidingAlgorithm is also registered.
    """
    global _REGISTRY_INSTANCE
    with _REGISTRY_LOCK:
        if _REGISTRY_INSTANCE is None:
            registry = StegoRegistry()
            from app.steganography.lsb_adapter import LSBAdapter
            from app.steganography.dwt_dct_qim import DWTDCTQIMAlgorithm
            registry.register(LSBAdapter())
            registry.register(DWTDCTQIMAlgorithm())
            _REGISTRY_INSTANCE = registry
        if include_echo and not _REGISTRY_INSTANCE.is_registered("echo"):
            from app.steganography.echo_hiding import EchoHidingAlgorithm
            _REGISTRY_INSTANCE.register(EchoHidingAlgorithm())
        return _REGISTRY_INSTANCE


def reset_registry() -> None:
    """Reset the global registry singleton in a thread-safe manner (for testing)."""
    global _REGISTRY_INSTANCE
    with _REGISTRY_LOCK:
        if _REGISTRY_INSTANCE is not None:
            _REGISTRY_INSTANCE.clear()
        _REGISTRY_INSTANCE = None
