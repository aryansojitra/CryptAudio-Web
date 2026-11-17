"""
app/audio package initialization.
Exposes public audio reading, writing, inspecting, capacity calculation, and exception classes.
"""

from app.audio.wav_handler import (
    AudioError,
    AudioReadError,
    AudioWriteError,
    InvalidWavError,
    UnsupportedAudioFormatError,
    WavCapacity,
    WavData,
    WavInspection,
    calculate_capacity,
    inspect_wav,
    read_wav,
    validate_wav,
    write_wav,
)

__all__ = [
    "read_wav",
    "inspect_wav",
    "validate_wav",
    "write_wav",
    "calculate_capacity",
    "WavData",
    "WavInspection",
    "WavCapacity",
    "AudioError",
    "InvalidWavError",
    "UnsupportedAudioFormatError",
    "AudioReadError",
    "AudioWriteError",
]
