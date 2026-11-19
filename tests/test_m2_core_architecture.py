"""
tests/test_m2_core_architecture.py
CryptAudio Web — Phase M2 Core Architecture Test Suite

Comprehensive tests for:
1. Base steganography interface, enums, dataclasses, and exception hierarchy.
2. StegoRegistry validation, registration, duplicate rejection, and lookup.
3. Universal CSMA v1 envelope packing, parsing, byte offsets, CRC32, and security bounds.
4. LSBAdapter embedding/extraction roundtrips (CSMA v1 & legacy CSLB v1),
   Channel 0-only policy preservation, capacity limits, and cryptographic integration.
"""

from __future__ import annotations

import concurrent.futures
import os
import struct
import sys
import threading
import zlib
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from app.audio.wav_handler import WavData, read_wav, write_wav
from app.crypto.aes_crypto import DecryptionError, decrypt_message, encrypt_message
from app.steganography.base import (
    AlgorithmRegistryError,
    AudioFormatIncompatibleError,
    BaseStegoAlgorithm,
    CapacityExceededError,
    CapacityProfile,
    CorruptedPayloadError,
    DomainType,
    ExtractedPayload,
    HeaderNotFoundError,
    RobustnessEvaluationStatus,
    StegoAlgorithmError,
    StegoInspection,
    StegoResult,
    SynchronizationError,
    UnsupportedParameterError,
)
from app.steganography.envelope import (
    ALGO_ID_DWT_DCT_QIM,
    ALGO_ID_ECHO,
    ALGO_ID_LSB,
    CSMA_HEADER_SIZE_BYTES,
    CSMA_HEADER_STRUCT,
    CSMA_MAGIC,
    CSMA_VERSION,
    MAX_PAYLOAD_SIZE_BYTES,
    SYNC_WORD_DWT_DCT_QIM,
    SYNC_WORD_ECHO,
    SYNC_WORD_LSB,
    CSMAEnvelope,
    create_csma_envelope,
    parse_csma_envelope,
    resolve_algorithm_id,
)
from app.steganography.lsb_adapter import LSBAdapter
from app.steganography.lsb_engine import (
    HEADER_SIZE_BITS as CSLB_HEADER_SIZE_BITS,
    HEADER_SIZE_BYTES as CSLB_HEADER_SIZE_BYTES,
    STEGO_MAGIC as CSLB_MAGIC,
    STEGO_VERSION as CSLB_VERSION,
    bytes_to_bits,
    create_framed_payload as create_cslb_framed_payload,
    embed_payload as original_lsb_embed_payload,
)
from app.steganography.registry import (
    AlgorithmDescriptor,
    StegoRegistry,
    get_registry,
    reset_registry,
)


# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_registry() -> StegoRegistry:
    """Provide an isolated, empty StegoRegistry instance."""
    return StegoRegistry()


@pytest.fixture
def default_adapter() -> LSBAdapter:
    """Provide a standard LSBAdapter instance."""
    return LSBAdapter()


def make_test_wav_data(
    frame_count: int = 2000,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
) -> WavData:
    """Create in-memory WavData with deterministic non-zero frame bytes."""
    bytes_per_frame = channels * sample_width
    frames = bytes((i * 5 + 13) % 256 for i in range(frame_count * bytes_per_frame))
    return WavData(
        channels=channels,
        sample_rate=sample_rate,
        sample_width=sample_width,
        frame_count=frame_count,
        compression_type="NONE",
        compression_name="not compressed",
        frames=frames,
    )


# ---------------------------------------------------------------------------
# 1. Base Interface, Enums, Dataclasses & Exception Hierarchy Tests
# ---------------------------------------------------------------------------

class TestBaseInterface:
    def test_abstract_class_cannot_be_instantiated(self) -> None:
        """BaseStegoAlgorithm cannot be instantiated directly without implementing abstract methods."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            BaseStegoAlgorithm()  # type: ignore

    def test_domain_type_enum_values(self) -> None:
        """DomainType enum contains expected operational domain strings."""
        assert DomainType.SPATIAL_TIME.value == "spatial_time_domain"
        assert DomainType.TRANSFORM.value == "transform_domain"
        assert DomainType.ACOUSTIC_TIME.value == "acoustic_time_domain"

    def test_robustness_evaluation_status_enum_values(self) -> None:
        """RobustnessEvaluationStatus enum contains neutral unverified evaluation labels."""
        assert RobustnessEvaluationStatus.FRAGILE_BY_DESIGN.value == "fragile_by_design"
        assert RobustnessEvaluationStatus.EXPERIMENTAL_TARGET.value == "experimental_target"
        assert RobustnessEvaluationStatus.ROBUSTNESS_UNVERIFIED.value == "robustness_unverified"
        assert RobustnessEvaluationStatus.NOT_EVALUATED.value == "not_evaluated"

    def test_dataclasses_construction_and_to_dict(self) -> None:
        """Dataclasses instantiate cleanly and export proper dictionaries."""
        wav = make_test_wav_data(frame_count=100)

        # CapacityProfile
        cap = CapacityProfile(
            algorithm_id="lsb",
            available_bits=100,
            available_bytes=12,
            bits_per_sample=1.0,
            bits_per_second=44100.0,
            max_payload_bytes=0,
            synchronization_overhead_bits=0,
            envelope_overhead_bits=144,
            recommended_min_duration_sec=0.0121,
        )
        d_cap = cap.to_dict()
        assert d_cap["algorithm_id"] == "lsb"
        assert d_cap["available_bits"] == 100

        # StegoResult
        res = StegoResult(
            success=True,
            algorithm_id="lsb",
            modified_wav=wav,
            payload_size_bytes=10,
            framed_size_bytes=28,
            required_bits=224,
            available_bits=800,
            utilization_percent=28.0,
            algorithm_parameters={"framing": "csma"},
        )
        d_res = res.to_dict()
        assert d_res["success"] is True
        assert "modified_wav" in d_res
        assert d_res["modified_wav"]["channels"] == 2

        # ExtractedPayload
        ext = ExtractedPayload(
            success=True,
            algorithm_id="lsb",
            payload=b"secret",
            integrity_verified=True,
            algorithm_parameters={"framing": "csma"},
        )
        d_ext = ext.to_dict()
        assert d_ext["payload_size_bytes"] == 6
        assert d_ext["framing_checksum_verified"] is True
        assert "integrity_verified" not in d_ext

        # StegoInspection
        insp = StegoInspection(
            has_stego_signature=True,
            detected_algorithm="lsb",
            envelope_version=1,
            payload_length_bytes=50,
            confidence_score=1.0,
        )
        d_insp = insp.to_dict()
        assert d_insp["has_stego_signature"] is True
        assert d_insp["confidence_score"] == 1.0

    def test_exception_hierarchy(self) -> None:
        """All specialized exceptions inherit from StegoAlgorithmError."""
        exceptions = [
            CapacityExceededError("too big"),
            HeaderNotFoundError("missing header"),
            SynchronizationError("sync failed"),
            CorruptedPayloadError("crc mismatch"),
            AudioFormatIncompatibleError("bad format"),
            UnsupportedParameterError("bad param"),
            AlgorithmRegistryError("registry issue"),
        ]
        for exc in exceptions:
            assert isinstance(exc, StegoAlgorithmError)
            assert isinstance(exc, Exception)


# ---------------------------------------------------------------------------
# 2. StegoRegistry Tests
# ---------------------------------------------------------------------------

class TestStegoRegistry:
    def test_successful_registration_and_get(self, clean_registry: StegoRegistry, default_adapter: LSBAdapter) -> None:
        """Valid algorithm registers successfully and can be retrieved by ID."""
        clean_registry.register(default_adapter)
        assert clean_registry.is_registered("lsb") is True
        retrieved = clean_registry.get("lsb")
        assert retrieved is default_adapter
        assert retrieved.algorithm_id == "lsb"

    def test_case_insensitive_lookup(self, clean_registry: StegoRegistry, default_adapter: LSBAdapter) -> None:
        """Algorithm lookup is case-insensitive and trims whitespace."""
        clean_registry.register(default_adapter)
        assert clean_registry.get("  LSB  ") is default_adapter
        assert clean_registry.get("Lsb") is default_adapter

    def test_duplicate_registration_rejected(self, clean_registry: StegoRegistry, default_adapter: LSBAdapter) -> None:
        """Registering the same algorithm ID twice raises AlgorithmRegistryError."""
        clean_registry.register(default_adapter)
        with pytest.raises(AlgorithmRegistryError, match="already registered"):
            clean_registry.register(default_adapter)

    def test_unknown_algorithm_id_rejected(self, clean_registry: StegoRegistry) -> None:
        """Attempting to get or register an unknown algorithm ID raises AlgorithmRegistryError."""
        with pytest.raises(AlgorithmRegistryError, match="not registered"):
            clean_registry.get("nonexistent")

        # Fake algorithm with unregistered ID
        class FakeAlgorithm(BaseStegoAlgorithm):
            algorithm_id = "unknown_algo"
            display_name = "Fake"
            domain = DomainType.SPATIAL_TIME
            robustness_objective = RobustnessEvaluationStatus.NOT_EVALUATED
            def embed(self, *a: Any, **kw: Any) -> Any: pass
            def extract(self, *a: Any, **kw: Any) -> Any: pass
            def estimate_capacity(self, *a: Any, **kw: Any) -> Any: pass
            def inspect_metadata(self, *a: Any, **kw: Any) -> Any: pass

        with pytest.raises(AlgorithmRegistryError, match="unknown ID 'unknown_algo'"):
            clean_registry.register(FakeAlgorithm())

    def test_invalid_algorithm_instance_rejected(self, clean_registry: StegoRegistry) -> None:
        """Passing an object that does not inherit from BaseStegoAlgorithm raises AlgorithmRegistryError."""
        with pytest.raises(AlgorithmRegistryError, match="must be an instance of BaseStegoAlgorithm"):
            clean_registry.register("not an algorithm")  # type: ignore

    def test_list_available_descriptors(self, clean_registry: StegoRegistry, default_adapter: LSBAdapter) -> None:
        """Listing available algorithms returns descriptors with expected fields."""
        clean_registry.register(default_adapter)
        descriptors = clean_registry.list_available()
        assert len(descriptors) == 1
        desc = descriptors[0]
        assert isinstance(desc, AlgorithmDescriptor)
        assert desc.algorithm_id == "lsb"
        assert desc.domain == DomainType.SPATIAL_TIME
        assert desc.robustness_objective == RobustnessEvaluationStatus.FRAGILE_BY_DESIGN
        d_dict = desc.to_dict()
        assert d_dict["domain"] == "spatial_time_domain"

    def test_clear_and_unregister(self, clean_registry: StegoRegistry, default_adapter: LSBAdapter) -> None:
        """Unregister and clear remove algorithms cleanly."""
        clean_registry.register(default_adapter)
        assert clean_registry.is_registered("lsb") is True
        clean_registry.unregister("lsb")
        assert clean_registry.is_registered("lsb") is False

        clean_registry.register(default_adapter)
        clean_registry.clear()
        assert len(clean_registry.list_available()) == 0

    def test_global_singleton_default_state(self) -> None:
        """Global get_registry() contains 'lsb' and 'dwt_dct_qim' registered by default."""
        reset_registry()
        reg = get_registry()
        assert reg.is_registered("lsb") is True
        assert reg.is_registered("dwt_dct_qim") is True
        assert len(reg.list_available()) == 2
        assert reg.get("lsb").algorithm_id == "lsb"
        assert reg.get("dwt_dct_qim").algorithm_id == "dwt_dct_qim"
        reset_registry()


# ---------------------------------------------------------------------------
# 3. Universal CSMA v1 Envelope Tests
# ---------------------------------------------------------------------------

class TestCSMAEnvelope:
    def test_valid_envelope_roundtrip(self) -> None:
        """Valid envelope serializes and deserializes accurately."""
        payload = b"TopSecretCryptAudioPayload12345"
        packed = create_csma_envelope(
            payload=payload,
            algorithm="lsb",
            flags=0x0002,
            sync_word=SYNC_WORD_LSB,
        )
        assert len(packed) == CSMA_HEADER_SIZE_BYTES + len(payload)

        parsed = parse_csma_envelope(packed, expected_algorithm="lsb")
        assert isinstance(parsed, CSMAEnvelope)
        assert parsed.sync_word == SYNC_WORD_LSB
        assert parsed.magic == CSMA_MAGIC
        assert parsed.algorithm_id == ALGO_ID_LSB
        assert parsed.algorithm_name == "lsb"
        assert parsed.version == CSMA_VERSION
        assert parsed.flags == 0x0002
        assert parsed.payload_length == len(payload)
        assert parsed.payload == payload
        assert parsed.actual_crc == zlib.crc32(payload) & 0xFFFFFFFF

    def test_exact_18_byte_header_offsets(self) -> None:
        """Exact byte-level verification of the 18-byte header layout."""
        payload = b"ABCDEF"
        flags = 0x1234
        packed = create_csma_envelope(payload, algorithm=ALGO_ID_LSB, flags=flags)

        header = packed[:18]
        # Offset 0..2: sync word (0xF9A9)
        sync_word = struct.unpack(">H", header[0:2])[0]
        assert sync_word == 0xF9A9

        # Offset 2..6: magic b"CSMA"
        magic = header[2:6]
        assert magic == b"CSMA"

        # Offset 6: algorithm ID (1 for LSB)
        algo_id = header[6]
        assert algo_id == 1

        # Offset 7: version (1)
        version = header[7]
        assert version == 1

        # Offset 8..10: flags
        unpacked_flags = struct.unpack(">H", header[8:10])[0]
        assert unpacked_flags == flags

        # Offset 10..14: payload length (6)
        length = struct.unpack(">I", header[10:14])[0]
        assert length == 6

        # Offset 14..18: CRC32
        crc = struct.unpack(">I", header[14:18])[0]
        assert crc == zlib.crc32(payload) & 0xFFFFFFFF

        # Offset 18+: payload
        assert packed[18:] == payload

    def test_algorithm_resolution(self) -> None:
        """Algorithm resolution supports integer IDs and string identifiers."""
        assert resolve_algorithm_id(1) == ALGO_ID_LSB
        assert resolve_algorithm_id("lsb") == ALGO_ID_LSB
        assert resolve_algorithm_id("DWT_DCT_QIM") == ALGO_ID_DWT_DCT_QIM
        assert resolve_algorithm_id("echo") == ALGO_ID_ECHO

        with pytest.raises(UnsupportedParameterError, match="Unsupported numeric algorithm ID"):
            resolve_algorithm_id(99)
        with pytest.raises(UnsupportedParameterError, match="Unsupported algorithm name"):
            resolve_algorithm_id("invalid_name")
        with pytest.raises(UnsupportedParameterError):
            resolve_algorithm_id(None)  # type: ignore
        with pytest.raises(UnsupportedParameterError, match="cannot be bool"):
            resolve_algorithm_id(True)  # type: ignore
        with pytest.raises(UnsupportedParameterError, match="cannot be bool"):
            resolve_algorithm_id(False)  # type: ignore

    def test_invalid_magic_rejected(self) -> None:
        """Header with non-CSMA magic raises HeaderNotFoundError."""
        payload = b"hello"
        packed = bytearray(create_csma_envelope(payload, algorithm="lsb"))
        packed[2:6] = b"XXXX"  # Corrupt magic
        with pytest.raises(HeaderNotFoundError, match="Invalid stego magic"):
            parse_csma_envelope(bytes(packed))

    def test_unsupported_version_rejected(self) -> None:
        """Header with unsupported version raises UnsupportedParameterError."""
        payload = b"hello"
        packed = bytearray(create_csma_envelope(payload, algorithm="lsb"))
        packed[7] = 2  # Version 2
        with pytest.raises(UnsupportedParameterError, match="Unsupported CSMA format version: 2"):
            parse_csma_envelope(bytes(packed))

    def test_unsupported_algorithm_id_rejected(self) -> None:
        """Header with unsupported algorithm ID raises UnsupportedParameterError."""
        payload = b"hello"
        packed = bytearray(create_csma_envelope(payload, algorithm="lsb"))
        packed[6] = 99  # Bad algo ID
        with pytest.raises(UnsupportedParameterError, match="Unsupported algorithm ID"):
            parse_csma_envelope(bytes(packed))

    def test_truncated_header_rejected(self) -> None:
        """Buffer shorter than 18 bytes raises HeaderNotFoundError."""
        short_buf = b"\xF9\xA9CSMA\x01\x01"  # 8 bytes
        with pytest.raises(HeaderNotFoundError, match="Buffer too short for CSMA header"):
            parse_csma_envelope(short_buf)

    def test_truncated_payload_rejected(self) -> None:
        """Buffer with declared length exceeding actual buffer raises CorruptedPayloadError."""
        payload = b"abcdefghij"  # 10 bytes
        packed = create_csma_envelope(payload, algorithm="lsb")
        # Truncate by 3 bytes
        truncated = packed[:-3]
        with pytest.raises(CorruptedPayloadError, match="Truncated CSMA payload"):
            parse_csma_envelope(truncated)

    def test_crc32_checksum_mismatch_rejected(self) -> None:
        """Payload byte alteration triggers CorruptedPayloadError on CRC32 mismatch."""
        payload = b"AuthenticData123"
        packed = bytearray(create_csma_envelope(payload, algorithm="lsb"))
        # Flip a bit in the payload portion (index 18)
        packed[18] ^= 0x01
        with pytest.raises(CorruptedPayloadError, match="Payload CRC32 checksum mismatch"):
            parse_csma_envelope(bytes(packed))

    def test_synchronization_word_mismatch_rejected(self) -> None:
        """Wrong synchronization word for the algorithm raises SynchronizationError in create and parse."""
        payload = b"Data"
        # 1. create_csma_envelope rejects mismatched sync word
        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, algorithm="lsb", sync_word=SYNC_WORD_ECHO)

        # 2. parse_csma_envelope rejects mismatched sync word if tampered
        packed = bytearray(create_csma_envelope(payload, algorithm="lsb"))
        struct.pack_into(">H", packed, 0, SYNC_WORD_ECHO)
        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            parse_csma_envelope(bytes(packed), expected_algorithm="lsb", enforce_sync_word=True)

    def test_boundary_empty_payload(self) -> None:
        """Empty payload can be encapsulated and verified cleanly."""
        packed = create_csma_envelope(b"", algorithm="lsb")
        assert len(packed) == CSMA_HEADER_SIZE_BYTES
        parsed = parse_csma_envelope(packed)
        assert parsed.payload_length == 0
        assert parsed.payload == b""

    def test_resolve_algorithm_id_rejections_and_types(self) -> None:
        """Comprehensive verification of resolve_algorithm_id strict parameter validation."""
        # 1. Valid integer IDs
        assert resolve_algorithm_id(ALGO_ID_LSB) == 1
        assert resolve_algorithm_id(ALGO_ID_DWT_DCT_QIM) == 2
        assert resolve_algorithm_id(ALGO_ID_ECHO) == 3

        # 2. Valid algorithm names (case-insensitive)
        assert resolve_algorithm_id("lsb") == 1
        assert resolve_algorithm_id("LSB") == 1
        assert resolve_algorithm_id("dwt_dct_qim") == 2
        assert resolve_algorithm_id("echo") == 3

        # 3. Explicit boolean rejection (bool is subclass of int in Python; True must not resolve to 1)
        with pytest.raises(UnsupportedParameterError, match="cannot be bool"):
            resolve_algorithm_id(True)
        with pytest.raises(UnsupportedParameterError, match="cannot be bool"):
            resolve_algorithm_id(False)

        # 4. Unsupported integers
        for invalid_int in (0, 4, 99, -1):
            with pytest.raises(UnsupportedParameterError, match="Unsupported numeric algorithm ID"):
                resolve_algorithm_id(invalid_int)

        # 5. Invalid strings
        for invalid_str in ("unknown", "cslb", "csma", ""):
            with pytest.raises(UnsupportedParameterError, match="Unsupported algorithm name"):
                resolve_algorithm_id(invalid_str)

        # 6. None and unsupported types
        for invalid_type in (None, 1.0, [1], {"algo": 1}):
            with pytest.raises(UnsupportedParameterError):
                resolve_algorithm_id(invalid_type)  # type: ignore

    def test_create_csma_envelope_flags_strict_validation(self) -> None:
        """create_csma_envelope strictly enforces integer flags in [0, 65535] and rejects booleans/floats/strings/None."""
        payload = b"FlagsTest"

        # Valid boundary values: 0 and 65535
        env_0 = create_csma_envelope(payload, "lsb", flags=0)
        assert struct.unpack(">H", env_0[8:10])[0] == 0

        env_max = create_csma_envelope(payload, "lsb", flags=65535)
        assert struct.unpack(">H", env_max[8:10])[0] == 65535

        # Boolean rejection (True/False must not be accepted as 1/0)
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got bool"):
            create_csma_envelope(payload, "lsb", flags=True)  # type: ignore
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got bool"):
            create_csma_envelope(payload, "lsb", flags=False)  # type: ignore

        # Float rejection
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got float"):
            create_csma_envelope(payload, "lsb", flags=0.0)  # type: ignore
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got float"):
            create_csma_envelope(payload, "lsb", flags=1.5)  # type: ignore

        # String rejection
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got str"):
            create_csma_envelope(payload, "lsb", flags="0")  # type: ignore

        # None rejection
        with pytest.raises(UnsupportedParameterError, match="Flags must be an integer, got NoneType"):
            create_csma_envelope(payload, "lsb", flags=None)  # type: ignore

        # Out-of-range rejection
        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", flags=-1)
        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", flags=65536)

    def test_create_csma_envelope_sync_word_strict_validation(self) -> None:
        """create_csma_envelope strictly enforces canonical sync word rules and rejects booleans/floats/strings."""
        payload = b"SyncWordTest"

        # Canonical defaults for all supported algorithms
        env_lsb = create_csma_envelope(payload, "lsb", sync_word=None)
        assert struct.unpack(">H", env_lsb[0:2])[0] == SYNC_WORD_LSB

        env_dwt = create_csma_envelope(payload, "dwt_dct_qim", sync_word=None)
        assert struct.unpack(">H", env_dwt[0:2])[0] == SYNC_WORD_DWT_DCT_QIM

        env_echo = create_csma_envelope(payload, "echo", sync_word=None)
        assert struct.unpack(">H", env_echo[0:2])[0] == SYNC_WORD_ECHO

        # Explicit canonical values accepted
        env_lsb_exp = create_csma_envelope(payload, "lsb", sync_word=SYNC_WORD_LSB)
        assert struct.unpack(">H", env_lsb_exp[0:2])[0] == SYNC_WORD_LSB

        env_dwt_exp = create_csma_envelope(payload, "dwt_dct_qim", sync_word=SYNC_WORD_DWT_DCT_QIM)
        assert struct.unpack(">H", env_dwt_exp[0:2])[0] == SYNC_WORD_DWT_DCT_QIM

        env_echo_exp = create_csma_envelope(payload, "echo", sync_word=SYNC_WORD_ECHO)
        assert struct.unpack(">H", env_echo_exp[0:2])[0] == SYNC_WORD_ECHO

        # Boolean rejection
        with pytest.raises(UnsupportedParameterError, match="Synchronization word must be an integer"):
            create_csma_envelope(payload, "lsb", sync_word=True)  # type: ignore
        with pytest.raises(UnsupportedParameterError, match="Synchronization word must be an integer"):
            create_csma_envelope(payload, "lsb", sync_word=False)  # type: ignore

        # Float rejection
        with pytest.raises(UnsupportedParameterError, match="Synchronization word must be an integer"):
            create_csma_envelope(payload, "lsb", sync_word=float(SYNC_WORD_LSB))  # type: ignore

        # String rejection
        with pytest.raises(UnsupportedParameterError, match="Synchronization word must be an integer"):
            create_csma_envelope(payload, "lsb", sync_word="0xF9A9")  # type: ignore

        # Out-of-range rejection
        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", sync_word=-1)
        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", sync_word=65536)

        # Noncanonical synchronization word rejection
        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, "lsb", sync_word=0x1234)
        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, "lsb", sync_word=SYNC_WORD_ECHO)


# ---------------------------------------------------------------------------
# 4. LSBAdapter Tests
# ---------------------------------------------------------------------------

class TestLSBAdapter:
    def test_csma_roundtrip_stereo(self, default_adapter: LSBAdapter) -> None:
        """CSMA v1 payload embeds into Channel 0 and extracts accurately on stereo audio."""
        wav = make_test_wav_data(frame_count=3000, channels=2, sample_width=2)
        payload = b"Classified Payload 2026 CSMA"

        result = default_adapter.embed(wav, payload, framing="csma")
        assert result.success is True
        assert result.algorithm_id == "lsb"
        assert result.payload_size_bytes == len(payload)
        assert result.framed_size_bytes == CSMA_HEADER_SIZE_BYTES + len(payload)
        assert result.required_bits == result.framed_size_bytes * 8
        assert result.available_bits == wav.frame_count

        # Verify Channel 1 is completely untouched
        orig_frames = wav.frames
        mod_frames = result.modified_wav.frames
        bytes_per_sample = wav.sample_width
        bytes_per_frame = wav.channels * bytes_per_sample

        for frame_idx in range(wav.frame_count):
            ch1_orig = orig_frames[frame_idx * bytes_per_frame + bytes_per_sample : (frame_idx + 1) * bytes_per_frame]
            ch1_mod = mod_frames[frame_idx * bytes_per_frame + bytes_per_sample : (frame_idx + 1) * bytes_per_frame]
            assert ch1_orig == ch1_mod, f"Channel 1 altered at frame {frame_idx}!"

        # Extract
        extracted = default_adapter.extract(result.modified_wav)
        assert extracted.success is True
        assert extracted.algorithm_id == "lsb"
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True
        assert extracted.integrity_verified is True
        d_csma = extracted.to_dict()
        assert d_csma["framing_checksum_verified"] is True
        assert "integrity_verified" not in d_csma
        assert extracted.algorithm_parameters["framing"] == "csma_v1"

    def test_csma_roundtrip_mono(self, default_adapter: LSBAdapter) -> None:
        """CSMA v1 embeds and extracts cleanly on mono PCM audio."""
        wav = make_test_wav_data(frame_count=2000, channels=1, sample_width=2)
        payload = b"MonoCarrierSecret"

        result = default_adapter.embed(wav, payload, framing="csma")
        assert result.success is True
        extracted = default_adapter.extract(result.modified_wav)
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True

    def test_legacy_cslb_roundtrip_backward_compatibility(self, default_adapter: LSBAdapter) -> None:
        """Legacy CSLB v1 framing can be embedded and extracted by the adapter seamlessly."""
        wav = make_test_wav_data(frame_count=2000, channels=2, sample_width=2)
        payload = b"Legacy CSLB v1 Test Message"

        # Embed with framing="legacy_cslb"
        result = default_adapter.embed(wav, payload, framing="legacy_cslb")
        assert result.algorithm_parameters["framing"] == "legacy_cslb"

        # Extract (adapter auto-detects legacy CSLB)
        extracted = default_adapter.extract(result.modified_wav)
        assert extracted.success is True
        assert extracted.payload == payload
        assert extracted.framing_checksum_verified is True
        assert extracted.integrity_verified is True
        d_legacy = extracted.to_dict()
        assert d_legacy["framing_checksum_verified"] is True
        assert "integrity_verified" not in d_legacy
        assert extracted.algorithm_parameters["framing"] == "legacy_cslb"
        assert extracted.payload == payload
        assert extracted.algorithm_parameters["framing"] == "legacy_cslb"

    def test_capacity_exceeded_error(self, default_adapter: LSBAdapter) -> None:
        """Embedding payload larger than carrier frames raises CapacityExceededError."""
        # Audio with 100 frames = 100 bits available on Channel 0
        wav = make_test_wav_data(frame_count=100, channels=2)
        # 18-byte envelope + 10-byte payload = 28 bytes = 224 bits > 100 frames
        payload = b"1234567890"

        with pytest.raises(CapacityExceededError, match="Insufficient capacity on Channel 0"):
            default_adapter.embed(wav, payload, framing="csma")

    def test_audio_format_incompatibility_checks(self, default_adapter: LSBAdapter) -> None:
        """Multi-channel (>2) audio raises AudioFormatIncompatibleError."""
        bad_wav = WavData(
            channels=4,  # Quadraphonic
            sample_rate=44100,
            sample_width=2,
            frame_count=1000,
            compression_type="NONE",
            compression_name="NONE",
            frames=b"\x00" * 8000,
        )
        with pytest.raises(AudioFormatIncompatibleError, match="supports 1 or 2 channels"):
            default_adapter.embed(bad_wav, b"test")

    def test_capacity_estimation(self, default_adapter: LSBAdapter) -> None:
        """CapacityProfile matches the approved architecture equations."""
        # 1-second 44,100 Hz stereo file
        wav = make_test_wav_data(frame_count=44100, channels=2, sample_rate=44100)
        profile = default_adapter.estimate_capacity(wav)

        assert profile.algorithm_id == "lsb"
        assert profile.available_bits == 44100
        assert profile.envelope_overhead_bits == 144
        # (44100 - 144) // 8 = 43956 // 8 = 5494 bytes
        assert profile.max_payload_bytes == (44100 - 144) // 8
        assert profile.bits_per_second == 44100.0
        assert profile.recommended_min_duration_sec == round(536.0 / 44100.0, 4)

    def test_non_destructive_metadata_inspection(self, default_adapter: LSBAdapter) -> None:
        """inspect_metadata identifies CSMA and CSLB signatures without false positives on clean audio."""
        clean_wav = make_test_wav_data(frame_count=1000)
        insp_clean = default_adapter.inspect_metadata(clean_wav)
        assert insp_clean.has_stego_signature is False
        assert insp_clean.detected_algorithm is None

        # Embed CSMA and inspect
        stego_csma = default_adapter.embed(clean_wav, b"InspectMeNow", framing="csma").modified_wav
        insp_csma = default_adapter.inspect_metadata(stego_csma)
        assert insp_csma.has_stego_signature is True
        assert insp_csma.detected_algorithm == "lsb"
        assert insp_csma.envelope_version == 1
        assert insp_csma.payload_length_bytes == len(b"InspectMeNow")

        # Embed CSLB and inspect
        stego_cslb = default_adapter.embed(clean_wav, b"InspectMeLegacy", framing="legacy_cslb").modified_wav
        insp_cslb = default_adapter.inspect_metadata(stego_cslb)
        assert insp_cslb.has_stego_signature is True
        assert insp_cslb.detected_algorithm == "lsb"
        assert insp_cslb.payload_length_bytes == len(b"InspectMeLegacy")

    def test_full_cryptographic_payload_integration(self, default_adapter: LSBAdapter) -> None:
        """
        Encrypt secret message via AES-256-GCM + PBKDF2, embed with LSBAdapter,
        extract with LSBAdapter, decrypt with correct password, and verify wrong password rejection.
        """
        secret_message = "Confidential Multi-Algorithm CryptAudio Message 2026"
        password = "CorrectStrongPassword#99"
        wrong_password = "IncorrectPassword#00"

        # 1. Encrypt message (opaque binary blob)
        encrypted_payload = encrypt_message(secret_message, password)
        assert encrypted_payload.startswith(b"CAUD")

        # 2. Embed into carrier audio using LSBAdapter
        carrier_wav = make_test_wav_data(frame_count=4000, channels=2)
        stego_result = default_adapter.embed(carrier_wav, encrypted_payload, framing="csma")

        # 3. Extract payload using LSBAdapter
        extracted = default_adapter.extract(stego_result.modified_wav)
        assert extracted.payload == encrypted_payload

        # 4. Decrypt with correct password
        recovered_message = decrypt_message(extracted.payload, password)
        assert recovered_message == secret_message

        # 5. Decrypt with wrong password fails with DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_message(extracted.payload, wrong_password)


# ---------------------------------------------------------------------------
# Phase M2.1: Corrective Test Suite
# ---------------------------------------------------------------------------

class TestM21ReviewCorrections:
    """
    Verification tests for M2.1 code review findings:
    1. CSLB unsupported version bug (CSSLB_VERSION typo fix).
    2. Original LSB engine backward compatibility verification.
    3. Canonical synchronization word enforcement during envelope creation.
    4. Registry thread-safety and concurrency controls.
    5. Rigorous metadata inspection confidence scoring.
    6. Adapter options and audio format validation across methods.
    7. Explicit envelope payload ceiling enforcement.
    """

    def test_finding_1_unsupported_cslb_version_raises_corrupted_payload_error(
        self,
        default_adapter: LSBAdapter,
    ) -> None:
        """
        Construct a CSLB header with an unsupported version and verify that
        extraction raises CorruptedPayloadError, not NameError.
        """
        wav = make_test_wav_data(frame_count=2000, channels=2, sample_width=2)
        frame_bytes = bytearray(wav.frames)

        # Header: magic (4B), version (1B = 99), length (4B = 5), crc (4B = 0)
        unsupported_version = 99
        cslb_header = (
            CSLB_MAGIC
            + struct.pack(">B", unsupported_version)
            + struct.pack(">I", 5)
            + struct.pack(">I", 0x12345678)
            + b"ABCDE"
        )
        bits = bytes_to_bits(cslb_header)
        for i, bit in enumerate(bits):
            offset = i * wav.sample_width
            frame_bytes[offset] = (frame_bytes[offset] & 0xFE) | bit

        modified_wav = WavData(
            channels=wav.channels,
            sample_rate=wav.sample_rate,
            sample_width=wav.sample_width,
            frame_count=wav.frame_count,
            compression_type="NONE",
            compression_name="NONE",
            frames=bytes(frame_bytes),
        )

        with pytest.raises(CorruptedPayloadError) as exc_info:
            default_adapter.extract(modified_wav)

        assert "Unsupported legacy CSLB version: 99" in str(exc_info.value)
        assert f"Expected {CSLB_VERSION}" in str(exc_info.value)

    def test_finding_2_original_engine_compatibility(
        self,
        tmp_path: Path,
        default_adapter: LSBAdapter,
    ) -> None:
        """
        Create a valid WAV carrier on disk, embed with original lsb_engine.embed_payload(),
        load resulting WAV data, and extract with LSBAdapter.extract().
        Verifies 100% bit-for-bit backward compatibility with original engine outputs.
        """
        # Test 1: Stereo carrier
        stereo_wav = make_test_wav_data(frame_count=3000, channels=2, sample_width=2)
        in_path_stereo = tmp_path / "carrier_stereo.wav"
        out_path_stereo = tmp_path / "stego_stereo.wav"
        write_wav(
            in_path_stereo,
            stereo_wav.frames,
            stereo_wav.channels,
            stereo_wav.sample_width,
            stereo_wav.sample_rate,
        )

        secret_stereo = b"CryptAudio original engine compatibility test payload (Stereo 16-bit)"
        embed_result_stereo = original_lsb_embed_payload(in_path_stereo, out_path_stereo, secret_stereo)
        assert embed_result_stereo.success is True

        stego_wav_stereo = read_wav(out_path_stereo)
        extracted_stereo = default_adapter.extract(stego_wav_stereo)
        assert extracted_stereo.success is True
        assert extracted_stereo.payload == secret_stereo
        assert extracted_stereo.integrity_verified is True
        assert extracted_stereo.algorithm_parameters["framing"] == "legacy_cslb"

        # Test 2: Mono carrier
        mono_wav = make_test_wav_data(frame_count=3000, channels=1, sample_width=2)
        in_path_mono = tmp_path / "carrier_mono.wav"
        out_path_mono = tmp_path / "stego_mono.wav"
        write_wav(
            in_path_mono,
            mono_wav.frames,
            mono_wav.channels,
            mono_wav.sample_width,
            mono_wav.sample_rate,
        )

        secret_mono = b"CryptAudio original engine compatibility test payload (Mono 16-bit)"
        embed_result_mono = original_lsb_embed_payload(in_path_mono, out_path_mono, secret_mono)
        assert embed_result_mono.success is True

        stego_wav_mono = read_wav(out_path_mono)
        extracted_mono = default_adapter.extract(stego_wav_mono)
        assert extracted_mono.success is True
        assert extracted_mono.payload == secret_mono
        assert extracted_mono.integrity_verified is True
        assert extracted_mono.algorithm_parameters["framing"] == "legacy_cslb"

    def test_finding_3_canonical_sync_word_enforcement(self) -> None:
        """
        create_csma_envelope() strictly enforces canonical synchronization words:
        - LSB: 0xF9A9
        - DWT-DCT-QIM: 0xF9A9
        - Echo: 0x596A
        Mismatches raise SynchronizationError; out of range raises UnsupportedParameterError.
        """
        payload = b"SyncWordValidationPayload"

        # 1. Defaults (None) must automatically assign canonical sync words
        env_lsb = create_csma_envelope(payload, "lsb")
        assert struct.unpack(">H", env_lsb[:2])[0] == SYNC_WORD_LSB  # 0xF9A9

        env_dwt = create_csma_envelope(payload, "dwt_dct_qim")
        assert struct.unpack(">H", env_dwt[:2])[0] == SYNC_WORD_DWT_DCT_QIM  # 0xF9A9

        env_echo = create_csma_envelope(payload, "echo")
        assert struct.unpack(">H", env_echo[:2])[0] == SYNC_WORD_ECHO  # 0x596A

        # 2. Explicit matching canonical sync words must succeed
        env_lsb_explicit = create_csma_envelope(payload, "lsb", sync_word=SYNC_WORD_LSB)
        assert struct.unpack(">H", env_lsb_explicit[:2])[0] == SYNC_WORD_LSB

        env_dwt_explicit = create_csma_envelope(payload, "dwt_dct_qim", sync_word=SYNC_WORD_DWT_DCT_QIM)
        assert struct.unpack(">H", env_dwt_explicit[:2])[0] == SYNC_WORD_DWT_DCT_QIM

        env_echo_explicit = create_csma_envelope(payload, "echo", sync_word=SYNC_WORD_ECHO)
        assert struct.unpack(">H", env_echo_explicit[:2])[0] == SYNC_WORD_ECHO

        # 3. Mismatched sync words must raise SynchronizationError
        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, "lsb", sync_word=SYNC_WORD_ECHO)

        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, "echo", sync_word=SYNC_WORD_LSB)

        with pytest.raises(SynchronizationError, match="Synchronization word mismatch"):
            create_csma_envelope(payload, "dwt_dct_qim", sync_word=0x1234)

        # 4. Out of 16-bit range values raise UnsupportedParameterError
        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", sync_word=-1)

        with pytest.raises(UnsupportedParameterError, match="unsigned 16-bit integer"):
            create_csma_envelope(payload, "lsb", sync_word=0x10000)

    def test_finding_4_registry_thread_safety(self) -> None:
        """
        StegoRegistry provides thread safety:
        - Concurrent lookups while registering
        - Concurrent duplicate registration rejection
        - Non-blocking detect_algorithm snapshotting
        - Global singleton thread-safe initialization
        """
        registry = StegoRegistry()
        adapter = LSBAdapter()
        errors: list[Exception] = []

        # 1. Concurrent duplicate registration: only 1 thread succeeds, others raise AlgorithmRegistryError
        def try_register() -> None:
            try:
                registry.register(adapter)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=try_register) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 succeeded, 9 raised AlgorithmRegistryError
        assert registry.is_registered("lsb") is True
        assert len(errors) == 9
        for err in errors:
            assert isinstance(err, AlgorithmRegistryError)

        # 2. Concurrent read / get / list_available operations
        def concurrent_reader() -> None:
            for _ in range(50):
                assert registry.is_registered("lsb") is True
                assert registry.get("lsb").algorithm_id == "lsb"
                assert len(registry.list_available()) == 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(concurrent_reader) for _ in range(16)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        # 3. Global singleton concurrency
        reset_registry()
        singletons: list[StegoRegistry] = []

        def access_singleton() -> None:
            singletons.append(get_registry())

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futs = [executor.submit(access_singleton) for _ in range(20)]
            for f in concurrent.futures.as_completed(futs):
                f.result()

        first_instance = singletons[0]
        for inst in singletons:
            assert inst is first_instance
        reset_registry()

    def test_finding_5_metadata_inspection_confidence(
        self,
        default_adapter: LSBAdapter,
    ) -> None:
        """
        inspect_metadata reports confidence 1.0 ONLY when all header fields validate.
        Partial, mismatched, or truncated headers return confidence 0.0 without allocating payload.
        """
        wav = make_test_wav_data(frame_count=2000, channels=2, sample_width=2)

        # 1. Clean audio without signature -> confidence 0.0
        insp_clean = default_adapter.inspect_metadata(wav)
        assert insp_clean.has_stego_signature is False
        assert insp_clean.confidence_score == 0.0
        assert insp_clean.detected_algorithm is None

        # 2. Valid CSMA header -> confidence 1.0
        stego_valid = default_adapter.embed(wav, b"ValidPayload", framing="csma").modified_wav
        insp_valid = default_adapter.inspect_metadata(stego_valid)
        assert insp_valid.has_stego_signature is True
        assert insp_valid.confidence_score == 1.0
        assert insp_valid.detected_algorithm == "lsb"
        assert insp_valid.envelope_version == 1
        assert insp_valid.payload_length_bytes == len(b"ValidPayload")

        # 3. Invalid sync word (0x0000 instead of 0xF9A9) -> confidence 0.0
        frame_bytes_bad_sync = bytearray(stego_valid.frames)
        # Flip sync word bits in Channel 0
        bad_sync_bits = [0] * 16
        for i, bit in enumerate(bad_sync_bits):
            offset = i * (wav.channels * wav.sample_width)
            frame_bytes_bad_sync[offset] = (frame_bytes_bad_sync[offset] & 0xFE) | bit
        wav_bad_sync = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes_bad_sync),
        )
        insp_bad_sync = default_adapter.inspect_metadata(wav_bad_sync)
        assert insp_bad_sync.has_stego_signature is False
        assert insp_bad_sync.confidence_score == 0.0

        # 4. Invalid version (e.g. 2 instead of 1) -> confidence 0.0
        frame_bytes_bad_ver = bytearray(stego_valid.frames)
        # Version is byte 7 (bits 56..63)
        ver_bits = [(2 >> (7 - b)) & 1 for b in range(8)]
        for b_idx, bit in enumerate(ver_bits):
            offset = (56 + b_idx) * (wav.channels * wav.sample_width)
            frame_bytes_bad_ver[offset] = (frame_bytes_bad_ver[offset] & 0xFE) | bit
        wav_bad_ver = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes_bad_ver),
        )
        insp_bad_ver = default_adapter.inspect_metadata(wav_bad_ver)
        assert insp_bad_ver.has_stego_signature is False
        assert insp_bad_ver.confidence_score == 0.0

        # 5. Invalid algorithm ID (e.g. 2 = DWT instead of 1 = LSB) -> confidence 0.0
        frame_bytes_dwt = bytearray(stego_valid.frames)
        # Algo ID is byte 6 (bits 48..55)
        algo_bits = [(ALGO_ID_DWT_DCT_QIM >> (7 - b)) & 1 for b in range(8)]
        for b_idx, bit in enumerate(algo_bits):
            offset = (48 + b_idx) * (wav.channels * wav.sample_width)
            frame_bytes_dwt[offset] = (frame_bytes_dwt[offset] & 0xFE) | bit
        wav_dwt = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes_dwt),
        )
        insp_dwt = default_adapter.inspect_metadata(wav_dwt)
        assert insp_dwt.has_stego_signature is False
        assert insp_dwt.confidence_score == 0.0

        # 6. Truncated header (frame_count < 144 bits) -> confidence 0.0
        tiny_wav = make_test_wav_data(frame_count=50)
        insp_tiny = default_adapter.inspect_metadata(tiny_wav)
        assert insp_tiny.has_stego_signature is False
        assert insp_tiny.confidence_score == 0.0

        # 7. Valid legacy CSLB header -> confidence 1.0
        stego_cslb = default_adapter.embed(wav, b"LegacyPayload", framing="legacy_cslb").modified_wav
        insp_cslb = default_adapter.inspect_metadata(stego_cslb)
        assert insp_cslb.has_stego_signature is True
        assert insp_cslb.confidence_score == 1.0
        assert insp_cslb.detected_algorithm == "lsb"
        assert insp_cslb.envelope_version == 1
        assert insp_cslb.payload_length_bytes == len(b"LegacyPayload")

        # 8. Legacy CSLB with invalid version (e.g. version 2) -> confidence 0.0
        frame_bytes_cslb_bad = bytearray(stego_cslb.frames)
        # Version is byte 4 in CSLB (bits 32..39)
        bad_ver_bits = [(2 >> (7 - b)) & 1 for b in range(8)]
        for b_idx, bit in enumerate(bad_ver_bits):
            offset = (32 + b_idx) * wav.sample_width
            frame_bytes_cslb_bad[offset] = (frame_bytes_cslb_bad[offset] & 0xFE) | bit
        wav_cslb_bad = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes_cslb_bad),
        )
        insp_cslb_bad = default_adapter.inspect_metadata(wav_cslb_bad)
        assert insp_cslb_bad.has_stego_signature is False
        assert insp_cslb_bad.confidence_score == 0.0

    def test_finding_6_adapter_options_and_audio_format_validation(
        self,
        default_adapter: LSBAdapter,
    ) -> None:
        """
        Validate adapter options and audio format consistency across embed, extract,
        estimate_capacity, and inspect_metadata without unexpected unhandled exceptions.
        """
        valid_wav = make_test_wav_data(frame_count=2000, channels=2, sample_width=2)

        # 1. Invalid framing option types
        with pytest.raises(UnsupportedParameterError, match="Framing option must be a string"):
            default_adapter.embed(valid_wav, b"data", framing=123)

        with pytest.raises(UnsupportedParameterError, match="Framing option must be a string"):
            default_adapter.estimate_capacity(valid_wav, framing=[])

        # 2. Unsupported framing values
        with pytest.raises(UnsupportedParameterError, match="Unsupported framing protocol"):
            default_adapter.embed(valid_wav, b"data", framing="unknown_proto")

        with pytest.raises(UnsupportedParameterError, match="Unsupported framing protocol"):
            default_adapter.estimate_capacity(valid_wav, framing="unknown_proto")

        # 3. Incompatible channels in embed & extract
        bad_channels_wav = WavData(
            channels=6, sample_rate=44100, sample_width=2, frame_count=1000,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * 12000,
        )
        with pytest.raises(AudioFormatIncompatibleError, match="supports 1 or 2 channels"):
            default_adapter.embed(bad_channels_wav, b"data")

        with pytest.raises(AudioFormatIncompatibleError, match="supports 1 or 2 channels"):
            default_adapter.extract(bad_channels_wav)

        with pytest.raises(AudioFormatIncompatibleError, match="supports 1 or 2 channels"):
            default_adapter.estimate_capacity(bad_channels_wav)

        # 4. Incompatible sample width in embed & extract
        bad_width_wav = WavData(
            channels=2, sample_rate=44100, sample_width=5, frame_count=1000,
            compression_type="NONE", compression_name="NONE", frames=b"\x00" * 10000,
        )
        with pytest.raises(AudioFormatIncompatibleError, match="Unsupported sample width"):
            default_adapter.embed(bad_width_wav, b"data")

        with pytest.raises(AudioFormatIncompatibleError, match="Unsupported sample width"):
            default_adapter.extract(bad_width_wav)

        with pytest.raises(AudioFormatIncompatibleError, match="Unsupported sample width"):
            default_adapter.estimate_capacity(bad_width_wav)

        # 5. Non-WavData input
        with pytest.raises(AudioFormatIncompatibleError, match="must be an instance of WavData"):
            default_adapter.embed("not_wav_data", b"data")  # type: ignore

        with pytest.raises(AudioFormatIncompatibleError, match="must be an instance of WavData"):
            default_adapter.extract({"not": "wav"})  # type: ignore

        # 6. Safe behavior in inspect_metadata for malformed/non-WavData inputs
        assert default_adapter.inspect_metadata("invalid").has_stego_signature is False  # type: ignore
        assert default_adapter.inspect_metadata(bad_channels_wav).has_stego_signature is False
        assert default_adapter.inspect_metadata(bad_width_wav).has_stego_signature is False

    def test_finding_7_envelope_payload_limit_enforcement(
        self,
        default_adapter: LSBAdapter,
    ) -> None:
        """
        Enforce application-level MAX_PAYLOAD_SIZE_BYTES (16 MiB):
        - create_csma_envelope() rejects payloads exceeding limit.
        - parse_csma_envelope() rejects declared payload lengths exceeding limit before buffer check.
        - LSBAdapter.extract() rejects declared payload lengths exceeding limit.
        """
        assert MAX_PAYLOAD_SIZE_BYTES == 16 * 1024 * 1024  # 16 MiB

        # 1. create_csma_envelope rejects payload exceeding MAX_PAYLOAD_SIZE_BYTES
        oversized_payload = bytearray(MAX_PAYLOAD_SIZE_BYTES + 1)
        with pytest.raises(UnsupportedParameterError, match="exceeds maximum allowable limit"):
            create_csma_envelope(oversized_payload, "lsb")

        # 2. parse_csma_envelope rejects declared payload_len > MAX_PAYLOAD_SIZE_BYTES
        header_oversized = struct.pack(
            CSMA_HEADER_STRUCT,
            SYNC_WORD_LSB,
            CSMA_MAGIC,
            ALGO_ID_LSB,
            CSMA_VERSION,
            0,  # flags
            MAX_PAYLOAD_SIZE_BYTES + 1024,  # payload length exceeding 16 MiB
            0x12345678,  # crc
        )
        with pytest.raises(CorruptedPayloadError, match="exceeds maximum allowable limit"):
            parse_csma_envelope(header_oversized)

        # 3. LSBAdapter.extract rejects declared payload_len > MAX_PAYLOAD_SIZE_BYTES
        wav = make_test_wav_data(frame_count=1000, channels=2, sample_width=2)
        frame_bytes = bytearray(wav.frames)
        bits = bytes_to_bits(header_oversized)
        bytes_per_frame = wav.channels * wav.sample_width
        for i, bit in enumerate(bits):
            offset = i * bytes_per_frame
            frame_bytes[offset] = (frame_bytes[offset] & 0xFE) | bit

        wav_oversized = WavData(
            channels=wav.channels, sample_rate=wav.sample_rate, sample_width=wav.sample_width,
            frame_count=wav.frame_count, compression_type="NONE", compression_name="NONE",
            frames=bytes(frame_bytes),
        )

        with pytest.raises(CorruptedPayloadError, match="exceeds maximum allowable limit"):
            default_adapter.extract(wav_oversized)
