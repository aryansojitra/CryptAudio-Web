#!/usr/bin/env python3
"""
scripts/run_algorithm_benchmark.py
CLI runner for CryptAudio-Web Phase M7.1 Steganography Algorithm Benchmarking.

Executes scientific benchmarking across LSB, DWT-DCT-QIM, and Echo Hiding,
generating comprehensive JSON, CSV, and Markdown evaluation reports.

Usage:
    python scripts/run_algorithm_benchmark.py [--output-dir benchmark_results] [--quick] [--trials 1]
"""

import argparse
import math
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.evaluation.benchmark import run_full_benchmark_suite
from app.evaluation.benchmark_report import (
    generate_markdown_report,
    save_csv_report,
    save_json_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CryptAudio-Web Phase M7.1 Steganography Algorithm Benchmark Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default="benchmark_results",
        help="Directory to save output benchmark reports and carriers",
    )
    parser.add_argument(
        "--carrier-duration",
        "-d",
        type=float,
        default=33.0,
        help="Duration of the primary benchmark carrier in seconds",
    )
    parser.add_argument(
        "--trials",
        "-t",
        type=int,
        default=1,
        help="Number of measurement trials for timing averaging (integer >= 1)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Quick run (standard defaults only, skip parameter sweeps)",
    )

    args = parser.parse_args()

    # Validate CLI inputs
    if math.isnan(args.carrier_duration) or math.isinf(args.carrier_duration) or args.carrier_duration <= 0.0:
        print(f"Error: --carrier-duration must be a positive finite number, got {args.carrier_duration}", file=sys.stderr)
        return 1

    if args.trials <= 0:
        print(f"Error: --trials must be a positive integer (>= 1), got {args.trials}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(" CryptAudio-Web Phase M7.1: Steganography Algorithm Benchmarking Suite")
    print("=" * 80)
    print(f"Target Output Directory : {out_dir}")
    print(f"Carrier Duration        : {args.carrier_duration:.1f}s")
    print(f"Execution Mode          : {'Quick (defaults only)' if args.quick else 'Full (with parameter sweeps)'}")
    print(f"Timing Trials           : {args.trials}")
    print("-" * 80)
    print("Executing benchmark suite... Please wait.")

    try:
        suite_result = run_full_benchmark_suite(
            output_dir=out_dir,
            duration_seconds=args.carrier_duration,
            quick=args.quick,
            trials=args.trials,
        )
    except Exception as exc:
        print(f"Benchmark execution failed: {exc}", file=sys.stderr)
        return 1

    # Save outputs
    json_path = out_dir / "benchmark_report.json"
    csv_path = out_dir / "benchmark_report.csv"
    md_path = out_dir / "benchmark_report.md"

    save_json_report(suite_result, json_path)
    save_csv_report(suite_result, csv_path)
    generate_markdown_report(suite_result, md_path)

    print("\n" + "=" * 80)
    print(" BENCHMARK EXECUTION COMPLETE — SUMMARY OF RESULTS")
    print("=" * 80)
    print(f"{'Algorithm':<14} {'Params':<14} {'Status':<10} {'PSNR (dB)':<12} {'SNR (dB)':<12} {'Pipeline Mean':<16} {'Traced Mem':<12}")
    print("-" * 80)

    for r in suite_result.results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        psnr_str = f"{r.quality.psnr_db:.2f} dB" if r.quality else "N/A"
        snr_str = f"{r.quality.snr_db:.2f} dB" if r.quality else "N/A"
        time_str = f"{r.performance.total_pipeline_time_seconds:.4f} s" if r.performance else "N/A"
        mem_str = f"{r.performance.peak_traced_memory_mb:.1f} MB" if r.performance else "N/A"

        print(f"{r.algorithm_id:<14} {p_str:<14} {r.status:<10} {psnr_str:<12} {snr_str:<12} {time_str:<16} {mem_str:<12}")

    print("=" * 80)
    print("Generated Artifacts:")
    print(f"  - JSON Report : {json_path}")
    print(f"  - CSV Report  : {csv_path}")
    print(f"  - Markdown    : {md_path}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
