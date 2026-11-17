"""
tests/test_service.py
CryptAudio Web — Service Integration Test Suite (Phase 6)

Tests end-to-end embedding, extraction, encryption, decryption, capacity calculation,
Unicode scripts, tamper detection, and file integrity through the centralized service layer.

Run:
    .venv\\Scripts\\python.exe -m pytest tests/test_service.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.audio.wav_handler import inspect_wav, read_wav, validate_wav, write_wav
from app.services.cryptaudio_service import (
    CapacityEstimate,
    EmbedMessageResult,
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    embed_message,
    estimate_capacity,
    extract_message,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def create_carrier_wav(
    file_path: Path,
    channels: int = 2,
    sample_width: int = 2,
    sample_rate: int = 44100,
    num_frames: int = 4000,
) -> Path:
    """Helper to create a standard valid carrier PCM WAV file."""
    frame_size = channels * sample_width
    frames = bytes((i * 7 + 13) % 256 for i in range(num_frames * frame_size))
    write_wav(
        output_path=file_path,
        frames=frames,
        channels=channels,
        sample_width=sample_width,
        sample_rate=sample_rate,
    )
    return file_path


# ---------------------------------------------------------------------------
# 1-13. Embedding Tests
# ---------------------------------------------------------------------------

def test_embed_english_message(tmp_path: Path) -> None:
    """1. Embed a standard English message and verify success."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "Operation CryptAudio: Top secret mission rendezvous at dawn."
    pwd = "CorrectPassword123"

    result = embed_message(carrier, stego, msg, pwd)
    assert isinstance(result, EmbedMessageResult)
    assert result.success is True
    assert stego.is_file()
    assert result.output_path == str(stego.resolve())


def test_embed_gujarati_message(tmp_path: Path) -> None:
    """2. Embed a Gujarati Unicode message."""
    carrier = create_carrier_wav(tmp_path / "carrier_guj.wav")
    stego = tmp_path / "stego_guj.wav"
    msg = "નમસ્તે! આ એક અત્યંત ગુપ્ત ક્રિપ્ટોગ્રાફિક સંદેશ છે."
    pwd = "ગુજરાતી_પાસવર્ડ_૨૦૨૬"

    result = embed_message(carrier, stego, msg, pwd)
    assert result.success is True
    assert extract_message(stego, pwd) == msg


def test_embed_hindi_message(tmp_path: Path) -> None:
    """3. Embed a Hindi Unicode message."""
    carrier = create_carrier_wav(tmp_path / "carrier_hin.wav")
    stego = tmp_path / "stego_hin.wav"
    msg = "नमस्ते भारत! यह ऑडियो फ़ाइल में छिपाया गया गोपनीय संदेश है।"
    pwd = "सुरक्षित_पासवर्ड_१२૩"

    result = embed_message(carrier, stego, msg, pwd)
    assert result.success is True
    assert extract_message(stego, pwd) == msg


def test_embed_emoji_message(tmp_path: Path) -> None:
    """4. Embed a message containing emojis and symbols."""
    carrier = create_carrier_wav(tmp_path / "carrier_emoji.wav")
    stego = tmp_path / "stego_emoji.wav"
    msg = "🔐 Confidential Audio Stego 🎵✨! Shield 🛡️ Key 🗝️ 100% 🚀"
    pwd = "EmojiPassphrase_🥳🚀"

    result = embed_message(carrier, stego, msg, pwd)
    assert result.success is True
    assert extract_message(stego, pwd) == msg


def test_embed_special_characters_message(tmp_path: Path) -> None:
    """5. Embed a message with dense special and whitespace characters."""
    carrier = create_carrier_wav(tmp_path / "carrier_special.wav")
    stego = tmp_path / "stego_special.wav"
    msg = "<!XML? & 'quotes' \"double\" \n\t tab \\ / [brackets] {braces} ~`*#$%>"
    pwd = "ComplexP@ssw0rd!#$%"

    result = embed_message(carrier, stego, msg, pwd)
    assert result.success is True
    assert extract_message(stego, pwd) == msg


def test_output_wav_exists(tmp_path: Path) -> None:
    """6. Output WAV file exists upon successful embedding."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego_exists.wav"
    assert not stego.exists()

    embed_message(carrier, stego, "Confirm file created", "Pass123")
    assert stego.is_file()
    assert stego.stat().st_size > 0


def test_output_wav_is_valid(tmp_path: Path) -> None:
    """7. Output WAV is a strictly valid PCM WAV file."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego_valid.wav"

    embed_message(carrier, stego, "Valid WAV verification", "Pass123")
    wav_data = validate_wav(stego)
    assert wav_data.channels == 2
    assert wav_data.sample_width == 2


def test_original_wav_remains_unchanged(tmp_path: Path) -> None:
    """8. Original carrier audio is never modified or corrupted."""
    carrier = create_carrier_wav(tmp_path / "carrier_immutable.wav")
    stego = tmp_path / "stego_out.wav"
    orig_bytes = carrier.read_bytes()
    orig_mtime = carrier.stat().st_mtime_ns

    embed_message(carrier, stego, "Immutability check", "Pass123")

    assert carrier.read_bytes() == orig_bytes
    assert carrier.stat().st_mtime_ns == orig_mtime


def test_reject_insufficient_capacity(tmp_path: Path) -> None:
    """9. Rejects embedding when carrier audio has insufficient samples."""
    # Carrier with only 50 frames (100 samples)
    tiny_carrier = create_carrier_wav(tmp_path / "tiny.wav", channels=2, num_frames=50)
    stego = tmp_path / "wont_work.wav"

    with pytest.raises(InsufficientAudioCapacityError, match="insufficient capacity"):
        embed_message(tiny_carrier, stego, "Large message that cannot fit in tiny audio", "Pass123")


def test_reject_invalid_input_wav(tmp_path: Path) -> None:
    """10. Rejects non-WAV input file."""
    fake_wav = tmp_path / "not_audio.wav"
    fake_wav.write_bytes(b"PLAIN TEXT FILE")
    stego = tmp_path / "stego.wav"

    with pytest.raises(MessageEmbeddingError, match="Invalid carrier WAV audio"):
        embed_message(fake_wav, stego, "Message", "Pass123")


def test_reject_empty_message(tmp_path: Path) -> None:
    """11. Rejects empty secret message."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"

    with pytest.raises(MessageEmbeddingError, match="Message must be a non-empty string"):
        embed_message(carrier, stego, "", "ValidPass123")


def test_reject_empty_password(tmp_path: Path) -> None:
    """12. Rejects empty password during embedding."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"

    with pytest.raises(MessageEmbeddingError, match="Password must be a non-empty string"):
        embed_message(carrier, stego, "Valid message", "")


def test_reject_identical_input_and_output_paths(tmp_path: Path) -> None:
    """13. Rejects identical input and output paths."""
    carrier = create_carrier_wav(tmp_path / "same.wav")

    with pytest.raises(MessageEmbeddingError, match="Input and output paths cannot be identical"):
        embed_message(carrier, carrier, "Message", "Pass123")


# ---------------------------------------------------------------------------
# 14-22. Extraction Tests
# ---------------------------------------------------------------------------

def test_extract_english_message(tmp_path: Path) -> None:
    """14. Extract English message successfully."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "Extracted English secret text."
    pwd = "EnglishPassword"

    embed_message(carrier, stego, msg, pwd)
    extracted = extract_message(stego, pwd)
    assert extracted == msg


def test_extract_gujarati_message(tmp_path: Path) -> None:
    """15. Extract Gujarati message successfully."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "સફળતાપૂર્વક મેળવેલ ગુજરાતી સંદેશ."
    pwd = "પાસવર્ડ_ગુજરાતી"

    embed_message(carrier, stego, msg, pwd)
    extracted = extract_message(stego, pwd)
    assert extracted == msg


def test_extract_hindi_message(tmp_path: Path) -> None:
    """16. Extract Hindi message successfully."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "सफलतापूर्वक निकाला गया हिंदी संदेश।"
    pwd = "हिंदी_पासवर्ड"

    embed_message(carrier, stego, msg, pwd)
    extracted = extract_message(stego, pwd)
    assert extracted == msg


def test_extract_emoji_message(tmp_path: Path) -> None:
    """17. Extract emoji message successfully."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "🎉 Success 🚀 Audio Stego 🔐 Verified!"
    pwd = "PasswordEmoji123"

    embed_message(carrier, stego, msg, pwd)
    extracted = extract_message(stego, pwd)
    assert extracted == msg


def test_reject_incorrect_password(tmp_path: Path) -> None:
    """18. Decryption fails with MessageExtractionError when password is wrong."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    msg = "Confidential payload."
    pwd = "CorrectPassword123"
    wrong_pwd = "WrongPassword999"

    embed_message(carrier, stego, msg, pwd)

    with pytest.raises(MessageExtractionError, match="Authentication or decryption failed"):
        extract_message(stego, wrong_pwd)


def test_reject_wav_without_embedded_payload(tmp_path: Path) -> None:
    """19. Extracting from audio without stego payload raises MessageExtractionError."""
    plain_carrier = create_carrier_wav(tmp_path / "plain.wav")

    with pytest.raises(MessageExtractionError, match="No valid hidden payload found"):
        extract_message(plain_carrier, "AnyPassword123")


def test_reject_corrupted_encrypted_payload(tmp_path: Path) -> None:
    """20. Rejects audio where the embedded payload bits have been tampered with."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego_tampered.wav"
    embed_message(carrier, stego, "Tamper check message", "Password123")

    # Tamper with an audio sample in the payload region (sample 120)
    data = read_wav(stego)
    corrupted_frames = bytearray(data.frames)
    corrupted_frames[120 * data.sample_width] ^= 1
    write_wav(stego, bytes(corrupted_frames), data.channels, data.sample_width, data.sample_rate)

    with pytest.raises(MessageExtractionError):
        extract_message(stego, "Password123")


def test_reject_corrupted_wav_file(tmp_path: Path) -> None:
    """21. Rejects extracting from a corrupted WAV container."""
    corrupt_file = tmp_path / "corrupt.wav"
    corrupt_file.write_bytes(b"INVALID DATA")

    with pytest.raises(MessageExtractionError, match="Invalid stego audio file"):
        extract_message(corrupt_file, "Password123")


def test_no_partial_plaintext_returned(tmp_path: Path) -> None:
    """22. Verifies that upon wrong password or corruption, no partial plaintext is returned."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    embed_message(carrier, stego, "NeverReturnThisSecretPartially", "RealPassword")

    try:
        extract_message(stego, "WrongPassword")
        pytest.fail("Should have raised MessageExtractionError")
    except MessageExtractionError as exc:
        assert "NeverReturn" not in str(exc)


# ---------------------------------------------------------------------------
# 23-27. Integration & Security Architecture Tests
# ---------------------------------------------------------------------------

def test_full_encrypt_embed_extract_decrypt_workflow(tmp_path: Path) -> None:
    """23. Full round-trip end-to-end integration test."""
    carrier = create_carrier_wav(tmp_path / "carrier_e2e.wav", channels=2, sample_width=3, num_frames=5000)
    stego = tmp_path / "stego_e2e.wav"
    secret = (
        "Multi-lingual End-to-End CryptAudio Test:\n"
        "1. English: AES-256-GCM + LSB Stego is working.\n"
        "2. Gujarati: સુરક્ષિત ઓડિયો સ્ટેગનોગ્રાફી.\n"
        "3. Hindi: अत्यंत गोपनीय ऑडियो संदेश.\n"
        "4. Emoji & symbols: 🔐🛡️⚡ — 100% Verified!"
    )
    passphrase = "MasterKey#2026!StrongPass"

    result = embed_message(carrier, stego, secret, passphrase)
    assert result.success is True

    recovered = extract_message(stego, passphrase)
    assert recovered == secret


def test_different_passwords_cannot_decrypt(tmp_path: Path) -> None:
    """24. Only the exact matching passphrase can decrypt the concealed message."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    embed_message(carrier, stego, "Exclusive access message", "Key1")

    with pytest.raises(MessageExtractionError):
        extract_message(stego, "Key2")


def test_plaintext_never_present_in_stego_file(tmp_path: Path) -> None:
    """25. Plaintext string is never stored directly in the stego audio file."""
    carrier = create_carrier_wav(tmp_path / "carrier.wav")
    stego = tmp_path / "stego.wav"
    plaintext = "UNENCRYPTED_PLAINTEXT_MARKER_STRING_XYZ_98765"

    embed_message(carrier, stego, plaintext, "EncryptionPassword")

    stego_raw_bytes = stego.read_bytes()
    assert plaintext.encode("utf-8") not in stego_raw_bytes


def test_output_audio_properties_match_original(tmp_path: Path) -> None:
    """26. Output stego audio has identical duration, sample rate, channels, and width."""
    carrier = create_carrier_wav(tmp_path / "carrier_props.wav", channels=2, sample_width=2, sample_rate=48000)
    stego = tmp_path / "stego_props.wav"

    orig_info = inspect_wav(carrier)
    embed_message(carrier, stego, "Properties check", "Password123")
    stego_info = inspect_wav(stego)

    assert stego_info.sample_rate == orig_info.sample_rate
    assert stego_info.channels == orig_info.channels
    assert stego_info.sample_width == orig_info.sample_width
    assert stego_info.duration_seconds == orig_info.duration_seconds
    assert stego_info.frame_count == orig_info.frame_count


def test_repeated_embedding_produces_different_stego_audio(tmp_path: Path) -> None:
    """27. Fresh cryptographic randomness (salt & nonce) generates different stego files."""
    carrier = create_carrier_wav(tmp_path / "carrier_random.wav")
    stego1 = tmp_path / "stego_run1.wav"
    stego2 = tmp_path / "stego_run2.wav"
    msg = "Same message for both runs"
    pwd = "SamePassword123"

    embed_message(carrier, stego1, msg, pwd)
    embed_message(carrier, stego2, msg, pwd)

    # Both must decrypt to the identical original message
    assert extract_message(stego1, pwd) == msg
    assert extract_message(stego2, pwd) == msg

    # But their raw audio frames must differ due to fresh salt and nonce
    data1 = read_wav(stego1)
    data2 = read_wav(stego2)
    assert data1.frames != data2.frames


# ---------------------------------------------------------------------------
# Capacity Estimation Tests
# ---------------------------------------------------------------------------

def test_estimate_capacity_helper(tmp_path: Path) -> None:
    """Tests the estimate_capacity utility function."""
    carrier = create_carrier_wav(tmp_path / "carrier_est.wav", channels=2, num_frames=1000)
    # Available samples = 2000 bits
    msg = "Test estimation"

    est = estimate_capacity(carrier, msg)
    assert isinstance(est, CapacityEstimate)
    assert est.can_fit is True
    assert est.available_bits == 2000
    assert est.required_bits > 0
    assert est.utilization_percent > 0
