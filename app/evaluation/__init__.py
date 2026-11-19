"""
app/evaluation package initialization.
Exposes public audio quality evaluation functions, metrics, data models, exception classes,
and Phase M7/M7.1 comparative benchmarking suite components.
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
from app.evaluation.benchmark import (
    AccuracyMetrics,
    AlgorithmBenchmarkResult,
    BenchmarkCarrierConfig,
    BenchmarkSuiteResult,
    CapacityMetrics,
    PerformanceMetrics,
    QualityMetrics,
    RobustnessResult,
    encode_pcm_samples,
    generate_carrier_wav,
    run_algorithm_benchmark,
    run_full_benchmark_suite,
    validate_carrier_config,
    validate_trials,
)
from app.evaluation.benchmark_report import (
    generate_markdown_report,
    save_csv_report,
    save_json_report,
)

__all__ = [
    # Audio quality
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
    # Benchmarking
    "BenchmarkCarrierConfig",
    "CapacityMetrics",
    "QualityMetrics",
    "PerformanceMetrics",
    "AccuracyMetrics",
    "RobustnessResult",
    "AlgorithmBenchmarkResult",
    "BenchmarkSuiteResult",
    "encode_pcm_samples",
    "generate_carrier_wav",
    "validate_carrier_config",
    "validate_trials",
    "run_algorithm_benchmark",
    "run_full_benchmark_suite",
    # Benchmark reporting
    "save_json_report",
    "save_csv_report",
    "generate_markdown_report",
]
