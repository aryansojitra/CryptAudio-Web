"""
app/evaluation package initialization.
Exposes public audio quality evaluation functions, metrics, data models, and exception classes.
"""

from app.evaluation.audio_quality import (
    PEAK_AMPLITUDES,
    AudioComparisonReport,
    AudioEvaluationError,
    IncompatibleAudioError,
    UnsupportedEvaluationFormatError,
    calculate_correlation,
    calculate_mse,
    calculate_psnr,
    calculate_snr,
    classify_quality,
    compare_audio,
    decode_pcm_samples,
)

__all__ = [
    "compare_audio",
    "calculate_mse",
    "calculate_snr",
    "calculate_psnr",
    "calculate_correlation",
    "classify_quality",
    "decode_pcm_samples",
    "AudioComparisonReport",
    "AudioEvaluationError",
    "IncompatibleAudioError",
    "UnsupportedEvaluationFormatError",
    "PEAK_AMPLITUDES",
]
