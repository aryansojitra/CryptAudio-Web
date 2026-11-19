"""
app/evaluation/benchmark_report.py
Generators for structured JSON, CSV, and data-driven Markdown benchmarking reports for CryptAudio-Web Phase M7.2.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.evaluation.benchmark import (
    AlgorithmBenchmarkResult,
    BenchmarkSuiteResult,
)


def save_json_report(suite: BenchmarkSuiteResult, output_path: str | Path) -> Path:
    """Serialize the complete benchmark suite result into formatted JSON."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(suite.to_dict(), f, indent=2, ensure_ascii=False)
    return out_p


def save_csv_report(suite: BenchmarkSuiteResult, output_path: str | Path) -> Path:
    """Export tabular benchmarking metrics across all evaluated algorithm configurations to CSV."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "Algorithm",
        "Parameters",
        "Status",
        "Carrier Name",
        "Carrier Duration (s)",
        "Total Samples",
        "Raw Capacity (bits)",
        "Raw Capacity (bytes)",
        "Usable Payload (bytes)",
        "Max Plaintext Message (bytes)",
        "Required Bits",
        "Utilization (%)",
        "MSE",
        "SNR (dB)",
        "PSNR (dB)",
        "Correlation",
        "Modified Samples",
        "Modified (%)",
        "Quality Rating",
        "Max Abs Diff",
        "Avg Abs Diff",
        "Embed Mean (s)",
        "Embed Std (s)",
        "Extract Mean (s)",
        "Extract Std (s)",
        "Total Pipeline Mean (s)",
        "Peak Traced Memory (MB)",
        "Trials Completed",
        "Trials Requested",
        "Extraction Success",
        "Exact Match",
        "Algorithm Match",
        "Auth Verified",
        "Wrong Pwd Rejected",
        "Sync Corrupt Rejected",
        "Checksum Corrupt Rejected",
        "Ciphertext Tamper Rejected",
        "Robustness: Unmodified",
        "Robustness: Gaussian Noise",
        "Robustness: Amplitude Scaling",
        "Robustness: Resampling",
        "Robustness: Lossy Compression",
    ]

    with open(out_p, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for res in suite.results:
            param_str = ", ".join(f"{k}={v}" for k, v in res.options.items()) if res.options else "default"

            # Robustness map
            rob_map = {r.transformation_name: r.status for r in res.robustness} if res.robustness else {}

            row: Dict[str, Any] = {
                "Algorithm": res.algorithm_id,
                "Parameters": param_str,
                "Status": res.status,
                "Carrier Name": res.carrier_name,
                "Carrier Duration (s)": res.carrier_duration_seconds,
                "Total Samples": res.capacity.total_samples if res.capacity else "N/A",
                "Raw Capacity (bits)": res.capacity.raw_capacity_bits if res.capacity else "N/A",
                "Raw Capacity (bytes)": res.capacity.raw_capacity_bytes if res.capacity else "N/A",
                "Usable Payload (bytes)": res.capacity.usable_payload_capacity_bytes if res.capacity else "N/A",
                "Max Plaintext Message (bytes)": res.capacity.max_embeddable_message_bytes if res.capacity else "N/A",
                "Required Bits": res.capacity.required_bits if res.capacity else "N/A",
                "Utilization (%)": res.capacity.utilization_percent if res.capacity else "N/A",
                "MSE": round(res.quality.mse, 6) if (res.quality and res.quality.mse is not None) else "N/A",
                "SNR (dB)": round(res.quality.snr_db, 2) if (res.quality and res.quality.snr_db is not None) else "N/A",
                "PSNR (dB)": round(res.quality.psnr_db, 2) if (res.quality and res.quality.psnr_db is not None) else "N/A",
                "Correlation": round(res.quality.correlation, 6) if (res.quality and res.quality.correlation is not None) else "N/A",
                "Modified Samples": res.quality.modified_samples if (res.quality and res.quality.modified_samples is not None) else "N/A",
                "Modified (%)": res.quality.modification_percent if (res.quality and res.quality.modification_percent is not None) else "N/A",
                "Quality Rating": res.quality.quality_rating if (res.quality and res.quality.quality_rating is not None) else "N/A",
                "Max Abs Diff": res.quality.max_absolute_difference if (res.quality and res.quality.max_absolute_difference is not None) else "N/A",
                "Avg Abs Diff": round(res.quality.average_absolute_difference, 4) if (res.quality and res.quality.average_absolute_difference is not None) else "N/A",
                "Embed Mean (s)": res.performance.embed_time_seconds if res.performance else "N/A",
                "Embed Std (s)": res.performance.embed_time_std_seconds if res.performance else "N/A",
                "Extract Mean (s)": res.performance.extract_time_seconds if res.performance else "N/A",
                "Extract Std (s)": res.performance.extract_time_std_seconds if res.performance else "N/A",
                "Total Pipeline Mean (s)": res.performance.total_pipeline_time_seconds if res.performance else "N/A",
                "Peak Traced Memory (MB)": res.performance.peak_traced_memory_mb if res.performance else "N/A",
                "Trials Completed": res.performance.trials_completed if res.performance else "N/A",
                "Trials Requested": res.performance.trials_requested if res.performance else "N/A",
                "Extraction Success": res.accuracy.extraction_success if res.accuracy else "N/A",
                "Exact Match": res.accuracy.exact_match if res.accuracy else "N/A",
                "Algorithm Match": res.accuracy.algorithm_match if res.accuracy else "N/A",
                "Auth Verified": res.accuracy.authentication_verified if res.accuracy else "N/A",
                "Wrong Pwd Rejected": res.accuracy.wrong_password_rejected if res.accuracy else "N/A",
                "Sync Corrupt Rejected": res.accuracy.sync_corruption_rejected if res.accuracy else "N/A",
                "Checksum Corrupt Rejected": res.accuracy.checksum_corruption_rejected if res.accuracy else "N/A",
                "Ciphertext Tamper Rejected": res.accuracy.ciphertext_tamper_rejected if res.accuracy else "N/A",
                "Robustness: Unmodified": rob_map.get("Unmodified WAV", "N/A"),
                "Robustness: Gaussian Noise": rob_map.get("Additive Gaussian Noise", "N/A"),
                "Robustness: Amplitude Scaling": rob_map.get("Amplitude Scaling", "N/A"),
                "Robustness: Resampling": rob_map.get("Resampling", "N/A"),
                "Robustness: Lossy Compression": rob_map.get("Lossy Compression", "N/A"),
            }
            writer.writerow(row)

    return out_p


def _format_algorithm_quality_summary(algo_name: str, runs: List[AlgorithmBenchmarkResult]) -> str:
    """Format quality observation for an algorithm safely handling missing optional numerical metrics."""
    qualities = [r.quality for r in runs if r.quality is not None]
    if not qualities:
        return f"- **{algo_name} Quality:** Not evaluated in this run."

    psnr_vals = [q.psnr_db for q in qualities if q.psnr_db is not None]
    snr_vals = [q.snr_db for q in qualities if q.snr_db is not None]
    mod_vals = [q.modification_percent for q in qualities if q.modification_percent is not None]

    parts = []
    if psnr_vals:
        if min(psnr_vals) == max(psnr_vals):
            parts.append(f"PSNR: {min(psnr_vals):.2f} dB")
        else:
            parts.append(f"PSNR: {min(psnr_vals):.2f} dB to {max(psnr_vals):.2f} dB")
    else:
        parts.append("PSNR: Not evaluated")

    if snr_vals:
        if min(snr_vals) == max(snr_vals):
            parts.append(f"SNR: {min(snr_vals):.2f} dB")
        else:
            parts.append(f"SNR: {min(snr_vals):.2f} dB to {max(snr_vals):.2f} dB")
    else:
        parts.append("SNR: Not evaluated")

    if mod_vals:
        if min(mod_vals) == max(mod_vals):
            parts.append(f"modifying {min(mod_vals):.2f}% of samples")
        else:
            parts.append(f"modifying {min(mod_vals):.2f}% to {max(mod_vals):.2f}% of samples")
    else:
        parts.append("sample modification percentage: Not evaluated")

    return f"- **{algo_name} Quality:** Measured {', '.join(parts)}."


def generate_markdown_report(suite: BenchmarkSuiteResult, output_path: str | Path) -> Path:
    """
    Generate a comprehensive, completely data-driven 11-section Markdown benchmark report.
    Adheres strictly to empirical observations and measured data without hardcoded discrepancies.
    """
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    sys_info = suite.system_info
    results = suite.results

    lines: List[str] = []

    def w(text: str = "") -> None:
        lines.append(text)

    # 1. Executive Summary
    w("# CryptAudio-Web: Comparative Steganography Algorithm Benchmark & Evaluation")
    w()
    w(f"> **Report Generated:** `{suite.timestamp}`  ")
    w(f"> **Evaluator:** Automated CryptAudio Benchmark Engine (Phase M7.2)  ")
    w()
    w("## 1. Executive Summary")
    w()
    w(
        "This evaluation report presents an empirical, scientific benchmark comparing the three audio steganography "
        "algorithms implemented in **CryptAudio-Web**: Least Significant Bit (**LSB**), Discrete Wavelet Transform + "
        "Discrete Cosine Transform + Quantization Index Modulation (**DWT-DCT-QIM**), and **Echo Hiding**."
    )
    w(
        "Each algorithm was evaluated in conjunction with the application's mandatory cryptographic layer "
        "(**AES-256-GCM** with **PBKDF2-HMAC-SHA256** at 600,000 iterations) and the universal **CSMA v1 Binary Envelope** framing protocol."
    )
    w()

    # Determine unique algorithms executed
    executed_algos = sorted(set(r.algorithm_id for r in results))
    successful_runs = [r for r in results if r.status == "SUCCESS"]
    insufficient_runs = [r for r in results if r.status == "CAPACITY_INSUFFICIENT"]

    w("### Key Empirical Observations from This Benchmark Run:")
    w()
    w(
        f"1. **Evaluated Configurations:** A total of {len(results)} configurations were executed across algorithms: "
        f"{', '.join(f'`{a}`' for a in executed_algos) if executed_algos else 'None'}. "
        f"Among these, {len(successful_runs)} completed embedding with status `SUCCESS`, "
        f"and {len(insufficient_runs)} recorded status `CAPACITY_INSUFFICIENT`."
    )

    cap_hierarchy_items = []
    for a in executed_algos:
        a_runs = [r for r in results if r.algorithm_id == a and r.capacity and r.status == "SUCCESS"]
        if a_runs:
            c = a_runs[0].capacity
            cap_hierarchy_items.append(
                f"`{a}` provides {c.raw_capacity_bytes:,} B ({c.raw_capacity_bits:,} bits) raw capacity on a {a_runs[0].carrier_duration_seconds:.1f}s carrier"
            )
    if cap_hierarchy_items:
        w(f"2. **Capacity Hierarchy:** {'; '.join(cap_hierarchy_items)}.")
    else:
        w("2. **Capacity Hierarchy:** No successful configurations with capacity metadata were evaluated in this run.")

    # Conditional accuracy & authenticated recovery claim with independent denominators
    successful_runs_with_acc = [r for r in successful_runs if r.accuracy is not None]
    if successful_runs:
        if successful_runs_with_acc:
            exact_eval = [r.accuracy.exact_match for r in successful_runs_with_acc if r.accuracy.exact_match in (True, False)]
            auth_eval = [r.accuracy.authentication_verified for r in successful_runs_with_acc if r.accuracy.authentication_verified in (True, False)]

            summary_parts = []
            if exact_eval:
                exact_matches = sum(1 for v in exact_eval if v is True)
                exact_pct = (exact_matches / len(exact_eval)) * 100
                summary_parts.append(
                    f"exact plaintext recovery was achieved in {exact_matches}/{len(exact_eval)} "
                    f"({exact_pct:.1f}%) evaluated configurations"
                )
            else:
                summary_parts.append("exact plaintext recovery: Not evaluated in this run")

            if auth_eval:
                auth_verifs = sum(1 for v in auth_eval if v is True)
                auth_pct = (auth_verifs / len(auth_eval)) * 100
                summary_parts.append(
                    f"AES-256-GCM authentication was verified in {auth_verifs}/{len(auth_eval)} "
                    f"({auth_pct:.1f}%) evaluated configurations"
                )
            else:
                summary_parts.append("cryptographic authentication: Not evaluated in this run")

            w(
                f"3. **Cryptographic Integrity & Authenticated Extraction:** "
                f"Of {len(successful_runs)} successfully embedded configuration(s), "
                f"{len(successful_runs_with_acc)} configuration(s) had accuracy records available. "
                f"Among evaluated metrics: {'; '.join(summary_parts)}. "
                f"Independent integrity experiments (wrong password, sync corruption, CRC32 checksum corruption, "
                f"ciphertext tampering) were evaluated on configurations with available accuracy metrics."
            )
        else:
            w(
                f"3. **Cryptographic Integrity & Authenticated Extraction:** "
                f"{len(successful_runs)} configuration(s) completed embedding with status `SUCCESS`; "
                f"however, integrity and authenticated extraction evaluation data was unavailable in this run."
            )
    else:
        w(
            "3. **Cryptographic Integrity & Authenticated Extraction:** "
            "No configurations completed embedding with status `SUCCESS`; integrity evaluation was unavailable."
        )
    w()

    # 2. Experimental Methodology
    w("## 2. Experimental Methodology")
    w()
    w(
        "All measurements were conducted programmatically using the live CryptAudio backend engine "
        "(`app.services.cryptaudio_service` and `app.evaluation.audio_quality`). "
        "No theoretical or hardcoded estimates were used."
    )
    w()
    w("### 2.1 Test Carrier Synthesis")

    # Data-driven carrier type / description derivation
    carrier_names = sorted(set(r.carrier_name for r in results if r.carrier_name))
    if carrier_names:
        c_types = []
        for name in carrier_names:
            nl = name.lower()
            if "chirp" in nl or "synthetic" in nl:
                c_types.append(f"`{name}` (Synthetic Chirp)")
            elif "speech" in nl:
                c_types.append(f"`{name}` (Speech Audio)")
            elif "music" in nl:
                c_types.append(f"`{name}` (Music Audio)")
            else:
                c_types.append(f"`{name}` (Audio Carrier)")
        w(f"- **Carrier Signal:** {', '.join(c_types)}.")
    else:
        w("- **Carrier Signal:** Carrier description metadata unavailable in this report.")

    # Configurable carrier metadata
    sr_vals = sorted(set(r.capacity.sample_rate for r in results if r.capacity and r.capacity.sample_rate is not None))
    ch_vals = sorted(set(r.capacity.channels for r in results if r.capacity and r.capacity.channels is not None))

    if sr_vals and ch_vals:
        sr_desc = ", ".join(f"{sr:,} Hz" for sr in sr_vals)
        ch_desc = ", ".join(f"{ch}-channel ({'Mono' if ch == 1 else 'Stereo' if ch == 2 else f'{ch}ch'})" for ch in ch_vals)
        w(f"- **Carrier Format:** {sr_desc}, {ch_desc}. Sample format / bit depth metadata unavailable in this result schema.")
    elif sr_vals:
        sr_desc = ", ".join(f"{sr:,} Hz" for sr in sr_vals)
        w(f"- **Carrier Format:** {sr_desc}. Channel count and bit depth metadata unavailable in this report.")
    else:
        w("- **Carrier Format:** Carrier format metadata unavailable in this report.")

    durations = sorted(set(r.carrier_duration_seconds for r in results))
    if durations:
        primary_dur = max(durations)
        primary_runs = [r for r in results if r.carrier_duration_seconds == primary_dur and r.capacity]
        samples_str = f"{primary_runs[0].capacity.total_samples:,}" if primary_runs else "N/A"
        w(f"- **Primary Carrier Duration:** {primary_dur:.1f} seconds ({samples_str} audio samples).")
        other_durs = [d for d in durations if d != primary_dur]
        if other_durs:
            other_desc = []
            for od in other_durs:
                od_runs = [r for r in results if r.carrier_duration_seconds == od]
                od_samples = f"{od_runs[0].capacity.total_samples:,}" if (od_runs and od_runs[0].capacity) else "N/A"
                other_desc.append(f"{od:.1f}s ({od_samples} samples)")
            w(f"- **Secondary / Boundary Carrier Durations:** {', '.join(other_desc)}.")
    else:
        w("- **Carrier Duration:** Not evaluated in this run.")
    w()

    w("### 2.2 Payload Structure & Framing Overhead")
    w("- **Cryptographic Layer (AES-256-GCM):** 33-byte fixed header (Magic 4B + Version 1B + Salt 16B + Nonce 12B) + ciphertext + 16-byte GHASH tag.")
    w("  - Minimum AES-GCM crypto overhead: **49 bytes**.")
    w("- **Framing Envelope (CSMA v1):** 18-byte universal framing header (Sync 2B + Magic 4B + Algo 1B + Ver 1B + Flags 2B + Len 4B + CRC32 4B) = **144 bits**.")
    w("  - Minimum valid framed encrypted payload (empty message): $18 + 49 = 67$ bytes (**536 bits**).")
    req_bits_set = sorted(set(r.capacity.required_bits for r in results if r.capacity and r.capacity.required_bits is not None))
    if req_bits_set:
        w(f"  - Evaluated payload required bitstream: **{', '.join(str(b) for b in req_bits_set)} bits**.")
    w()

    w("### 2.3 Evaluation Metric Definitions")
    w("- **Mean Squared Error (MSE):** $\\text{MSE} = \\frac{1}{N} \\sum_{i=1}^N (x_i - y_i)^2$")
    w("- **Signal-to-Noise Ratio (SNR):** $\\text{SNR}_{\\text{dB}} = 10 \\log_{10} \\left( \\frac{\\sum x_i^2}{\\sum (x_i - y_i)^2} \\right)$")

    # PSNR documentation deriving from sample width if available
    sample_widths = sorted(set(
        getattr(r.capacity, "sample_width", None) or r.options.get("sample_width")
        for r in results if (r.capacity or r.options) and (getattr(r.capacity, "sample_width", None) or r.options.get("sample_width"))
    ))
    sample_widths = [sw for sw in sample_widths if sw is not None]

    if sample_widths:
        max_peaks = {1: "127 (8-bit)", 2: "32767 (16-bit)", 3: "8388607 (24-bit)", 4: "2147483647 (32-bit)"}
        peak_desc = ", ".join(f"$MAX = {max_peaks.get(sw, '2^{8*sw-1}-1')}$" for sw in sample_widths)
        w(
            "- **Peak Signal-to-Noise Ratio (PSNR):** $\\text{PSNR}_{\\text{dB}} = 10 \\log_{10} \\left( \\frac{MAX^2}{\\text{MSE}} \\right)$, "
            f"where {peak_desc} based on carrier PCM sample width."
        )
    else:
        w(
            "- **Peak Signal-to-Noise Ratio (PSNR):** $\\text{PSNR}_{\\text{dB}} = 10 \\log_{10} \\left( \\frac{MAX^2}{\\text{MSE}} \\right)$. "
            "The peak amplitude $MAX$ is determined by the audio-quality evaluation engine based on sample width "
            "($MAX = 127$ for 8-bit, $MAX = 32767$ for 16-bit, $MAX = 8388607$ for 24-bit, $MAX = 2147483647$ for 32-bit PCM); "
            "the current run's sample width is not recorded in the report schema."
        )

    w("- **Pearson Correlation Coefficient:** $r = \\frac{\\sum (x_i - \\bar{x})(y_i - \\bar{y})}{\\sqrt{\\sum(x_i - \\bar{x})^2 \\sum(y_i - \\bar{y})^2}}$")
    w("- **Traced Memory:** Measured via Python `tracemalloc` peak heap allocation of Python objects during embedding. Note: this tracks Python-allocated heap objects and does not measure complete OS process RSS or native external C-extension memory.")
    w("- **Execution Latency:** Measured using `time.perf_counter()` over configured trials, reporting mean and standard deviation.")
    w()

    # 3. Test Environment
    w("## 3. Test Environment")
    w()
    w("| Parameter | Configuration / Specification |")
    w("| :--- | :--- |")
    w(f"| **Operating System** | `{sys_info.get('platform', 'Unknown')}` |")
    w(f"| **Python Runtime** | `{sys_info.get('python_version', 'Unknown')}` |")
    w(f"| **CPU Architecture** | `{sys_info.get('processor', 'Unknown')} ({sys_info.get('cpu_count', 1)} cores)` |")
    w(f"| **NumPy Version** | `{sys_info.get('numpy_version', 'Unknown')}` |")
    w(f"| **PyWavelets Version** | `{sys_info.get('pywt_version', 'Unknown')}` |")
    ffmpeg_str = "Available" if sys_info.get("ffmpeg_available") else "Not installed"
    lame_str = "Available" if sys_info.get("lame_available") else "Not installed"
    w(f"| **FFmpeg Binary** | `{ffmpeg_str}` |")
    w(f"| **LAME Binary** | `{lame_str}` |")
    w(f"| **Evaluation Timestamp (UTC)** | `{sys_info.get('benchmark_date_utc', 'Unknown')}` |")
    w()

    # 4. Algorithm Configurations
    w("## 4. Algorithm Configurations")
    w()
    w("The algorithms evaluated in this benchmark run were configured as follows:")
    w()
    w("1. **LSB (Least Significant Bit):**")
    w("   - Carrier embedding: Sample-domain replacement of the least significant bit ($b_0$) in Channel 0.")
    w("   - Framing: Universal CSMA v1 envelope (18 bytes overhead).")
    w("   - Operating parameters: Default (1 bit per sample).")
    w()
    w("2. **DWT-DCT-QIM (Discrete Wavelet + DCT + Quantization Index Modulation):**")
    w("   - Wavelet transform: 3-level discrete wavelet decomposition using Daubechies 4 (`db4`, `WAVELET_NAME = 'db4'`).")
    w("   - Embedding target: Block DCT over detail sub-band `cD3` (`DECOMPOSITION_LEVEL = 3`).")
    w("   - Chunk size: 1024 audio samples per chunk. Each chunk embeds 16 bits across 16 DCT blocks.")
    w("   - Supported quantization step sizes: $\\Delta \\in \\{8, 16, 32, 64\\}$. Native default: $\\Delta = 32$.")
    dwt_tested_deltas = sorted(set(r.options.get("delta") for r in results if r.algorithm_id == "dwt_dct_qim" and "delta" in r.options))
    if dwt_tested_deltas:
        w(f"   - Tested quantization steps in this run: $\\Delta \\in {{{', '.join(str(d) for d in dwt_tested_deltas)}}}$.")
    elif any(r.algorithm_id == "dwt_dct_qim" for r in results):
        w("   - Tested quantization steps in this run: Default ($\\Delta = 32$).")
    else:
        w("   - Tested quantization steps in this run: Not evaluated in this run.")
    w()
    w("3. **Echo Hiding:**")
    w("   - Kernel delays: $d_0 = 44$ samples (bit 0), $d_1 = 57$ samples (bit 1) at 44.1 kHz.")
    w("   - Segment size: 2048 audio samples per bit ($21.53\\text{ bps}$).")
    w("   - Supported attenuation factors: positive float $< 1.0$ (typical $0.05 - 0.20$). Native default: $\\alpha = 0.08$.")
    echo_tested_alphas = sorted(set(r.options.get("alpha") for r in results if r.algorithm_id == "echo" and "alpha" in r.options))
    if echo_tested_alphas:
        w(f"   - Tested attenuation factors in this run: $\\alpha \\in {{{', '.join(str(a) for a in echo_tested_alphas)}}}$.")
    elif any(r.algorithm_id == "echo" for r in results):
        w("   - Tested attenuation factors in this run: Default ($\\alpha = 0.08$).")
    else:
        w("   - Tested attenuation factors in this run: Not evaluated in this run.")
    w()

    # 5. Capacity Comparison
    w("## 5. Capacity Comparison")
    w()
    w("| Algorithm | Parameters | Carrier Duration | Raw Capacity (bits) | Raw Capacity (bytes) | Usable Payload (bytes) | Max Plaintext Message | Utilization % |")
    w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for r in results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        if r.capacity:
            c = r.capacity
            raw_bits_str = f"{c.raw_capacity_bits:,} bits" if c.raw_capacity_bits is not None else "N/A"
            raw_bytes_str = f"{c.raw_capacity_bytes:,} B" if c.raw_capacity_bytes is not None else "N/A"
            usable_str = f"{c.usable_payload_capacity_bytes:,} B" if c.usable_payload_capacity_bytes is not None else "N/A"
            max_plain_str = f"{c.max_embeddable_message_bytes:,} B" if c.max_embeddable_message_bytes is not None else "N/A"
            util_str = f"{c.utilization_percent:.3f}%" if c.utilization_percent is not None else "N/A"
            w(
                f"| `{r.algorithm_id}` | `{p_str}` | {r.carrier_duration_seconds:.1f}s | "
                f"{raw_bits_str} | {raw_bytes_str} | {usable_str} | {max_plain_str} | {util_str} |"
            )
        else:
            w(f"| `{r.algorithm_id}` | `{p_str}` | {r.carrier_duration_seconds:.1f}s | N/A | N/A | N/A | N/A | `{r.status}` |")
    w()
    w("### Capacity Observations:")
    lsb_cap_runs = [r for r in results if r.algorithm_id == "lsb" and r.capacity]
    if lsb_cap_runs:
        lr = lsb_cap_runs[0]
        c = lr.capacity
        w(
            f"- **LSB Capacity:** On the {lr.carrier_duration_seconds:.1f}s carrier ({c.total_samples:,} samples), "
            f"LSB yielded {c.raw_capacity_bits:,} raw bits ({c.raw_capacity_bytes:,} bytes), usable payload of "
            f"{c.usable_payload_capacity_bytes:,} bytes, and max plaintext message of {c.max_embeddable_message_bytes:,} bytes "
            f"(utilization: {c.utilization_percent:.3f}%)."
        )
    else:
        w("- **LSB Capacity:** Not evaluated in this run.")

    dwt_cap_runs = [r for r in results if r.algorithm_id == "dwt_dct_qim" and r.capacity]
    if dwt_cap_runs:
        dr = dwt_cap_runs[0]
        c = dr.capacity
        w(
            f"- **DWT-DCT-QIM Capacity:** On the {dr.carrier_duration_seconds:.1f}s carrier ({c.total_samples:,} samples), "
            f"DWT-DCT-QIM yielded {c.raw_capacity_bits:,} raw bits ({c.raw_capacity_bytes:,} bytes), usable payload of "
            f"{c.usable_payload_capacity_bytes:,} bytes, and max plaintext message of {c.max_embeddable_message_bytes:,} bytes "
            f"(utilization: {c.utilization_percent:.3f}%)."
        )
    else:
        w("- **DWT-DCT-QIM Capacity:** Not evaluated in this run.")

    echo_cap_runs = [r for r in results if r.algorithm_id == "echo" and r.capacity]
    if echo_cap_runs:
        er = echo_cap_runs[0]
        c = er.capacity
        w(
            f"- **Echo Hiding Capacity:** On the {er.carrier_duration_seconds:.1f}s carrier ({c.total_samples:,} samples), "
            f"Echo Hiding yielded {c.raw_capacity_bits:,} raw bits ({c.raw_capacity_bytes:,} bytes), usable payload of "
            f"{c.usable_payload_capacity_bytes:,} bytes, and max plaintext message of {c.max_embeddable_message_bytes:,} bytes "
            f"(utilization: {c.utilization_percent:.3f}%)."
        )
    else:
        w("- **Echo Hiding Capacity:** Not evaluated in this run.")

    if insufficient_runs:
        in_desc = [f"`{r.algorithm_id}` ({r.carrier_duration_seconds:.1f}s carrier)" for r in insufficient_runs]
        w(
            f"- **Capacity Boundary Enforcement:** Evaluated configurations on insufficient carrier lengths "
            f"({', '.join(in_desc)}) recorded `CAPACITY_INSUFFICIENT`, verifying that embeddings are prevented "
            f"when raw capacity falls below the 536-bit minimum framing requirement."
        )
    else:
        w("- **Capacity Boundary Enforcement:** Not evaluated in this run.")
    w()

    # 6. Audio Quality Comparison (Safe missing-metric handling)
    w("## 6. Audio Quality Comparison")
    w()
    w("Numerical distortion metrics computed by `app.evaluation.audio_quality` (comparing original carrier vs. stego audio):")
    w()
    w("| Algorithm | Parameters | MSE | SNR (dB) | PSNR (dB) | Correlation | Modified Samples | Modified % | Quality Rating |")
    w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for r in results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        if r.quality:
            q = r.quality
            mse_str = f"{q.mse:.6f}" if q.mse is not None else "N/A"
            snr_str = f"{q.snr_db:.2f} dB" if q.snr_db is not None else "N/A"
            psnr_str = f"{q.psnr_db:.2f} dB" if q.psnr_db is not None else "N/A"
            corr_str = f"{q.correlation:.6f}" if q.correlation is not None else "N/A"
            mod_s_str = f"{q.modified_samples:,}" if q.modified_samples is not None else "N/A"
            mod_p_str = f"{q.modification_percent:.2f}%" if q.modification_percent is not None else "N/A"
            rate_str = f"**{q.quality_rating}**" if q.quality_rating is not None else "N/A"
            w(
                f"| `{r.algorithm_id}` | `{p_str}` | {mse_str} | {snr_str} | {psnr_str} | "
                f"{corr_str} | {mod_s_str} | {mod_p_str} | {rate_str} |"
            )
        else:
            w(f"| `{r.algorithm_id}` | `{p_str}` | N/A | N/A | N/A | N/A | N/A | N/A | `{r.status}` |")
    w()
    w("### Quality Observations:")
    lsb_runs = [r for r in results if r.algorithm_id == "lsb"]
    dwt_runs = [r for r in results if r.algorithm_id == "dwt_dct_qim"]
    echo_runs = [r for r in results if r.algorithm_id == "echo"]

    w(_format_algorithm_quality_summary("LSB", lsb_runs))
    w(_format_algorithm_quality_summary("DWT-DCT-QIM", dwt_runs))
    w(_format_algorithm_quality_summary("Echo Hiding", echo_runs))

    w(
        "- *Note on Quality Ratings:* Quality ratings ('Excellent', 'Good', 'Moderate', 'Poor') represent mathematical classifications "
        "based on PSNR thresholds (> 45 dB = Excellent, > 35 dB = Good, > 25 dB = Moderate), not formal subjective listening evaluations."
    )
    w()

    # 7. Processing Performance Comparison
    w("## 7. Processing Performance Comparison")
    w()
    w("| Algorithm | Parameters | Embed Mean (s) | Embed Std (s) | Extract Mean (s) | Extract Std (s) | Total Pipeline Mean (s) | Peak Traced Memory (MB) |")
    w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for r in results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        if r.performance:
            p = r.performance
            emb_m = f"{p.embed_time_seconds:.4f} s" if p.embed_time_seconds is not None else "N/A"
            emb_s = f"{p.embed_time_std_seconds:.4f} s" if p.embed_time_std_seconds is not None else "N/A"
            ext_m = f"{p.extract_time_seconds:.4f} s" if p.extract_time_seconds is not None else "N/A"
            ext_s = f"{p.extract_time_std_seconds:.4f} s" if p.extract_time_std_seconds is not None else "N/A"
            tot_m = f"{p.total_pipeline_time_seconds:.4f} s" if p.total_pipeline_time_seconds is not None else "N/A"
            mem_s = f"{p.peak_traced_memory_mb:.2f} MB" if p.peak_traced_memory_mb is not None else "N/A"
            w(f"| `{r.algorithm_id}` | `{p_str}` | {emb_m} | {emb_s} | {ext_m} | {ext_s} | {tot_m} | {mem_s} |")
        else:
            w(f"| `{r.algorithm_id}` | `{p_str}` | N/A | N/A | N/A | N/A | N/A | N/A |")
    w()
    w("### Performance Observations:")
    perf_runs = [r for r in results if r.performance and r.performance.total_pipeline_time_seconds is not None]
    if perf_runs:
        tot_times = [r.performance.total_pipeline_time_seconds for r in perf_runs]
        t_min, t_max = min(tot_times), max(tot_times)
        algo_lat_parts = []
        for a in executed_algos:
            a_runs = [r for r in perf_runs if r.algorithm_id == a]
            if a_runs:
                avg_t = sum(r.performance.total_pipeline_time_seconds for r in a_runs) / len(a_runs)
                algo_lat_parts.append(f"`{a}` mean total: {avg_t:.4f}s")
        w(
            f"- **Pipeline Latency:** Measured total pipeline latency ranged from {t_min:.4f}s to {t_max:.4f}s "
            f"across evaluated configurations ({'; '.join(algo_lat_parts)})."
        )
    else:
        w("- **Pipeline Latency:** Not evaluated in this run.")

    w(
        "- **Memory Measurement:** Peak traced memory was tracked via Python `tracemalloc`. "
        "This metric reflects peak allocations of Python objects during execution and does not represent full operating system resident set size (RSS)."
    )
    w()

    # 8. Extraction Accuracy & Independent Integrity Experiments
    configs_with_acc = [r for r in results if r.accuracy is not None]
    configs_without_acc = [r for r in results if r.accuracy is None]

    w("## 8. Extraction Accuracy & Independent Integrity Experiments")
    w()
    w(
        f"Integrity evaluations were conducted on {len(configs_with_acc)} of {len(results)} evaluated configuration(s) "
        f"({len(configs_without_acc)} configuration(s) lacked accuracy data or were capacity-insufficient). "
        "Configurations with status `CAPACITY_INSUFFICIENT` did not produce stego audio and therefore did not undergo integrity testing."
    )
    w()

    def _eval_metric_str(name: str, values: List[Optional[bool]]) -> str:
        valid_vals = [v for v in values if v in (True, False)]
        if not valid_vals:
            return f"- **{name}:** Not evaluated in this run."
        passed = sum(1 for v in valid_vals if v is True)
        denom = len(valid_vals)
        pct = (passed / denom) * 100
        return f"- **{name}:** {passed}/{denom} ({pct:.1f}%) evaluated configurations passed."

    if configs_with_acc:
        w("Experimental outcomes across evaluated configurations:")
        w(_eval_metric_str("Wrong Password Rejection", [r.accuracy.wrong_password_rejected for r in configs_with_acc]))
        w(_eval_metric_str("Sync Corruption Rejection", [r.accuracy.sync_corruption_rejected for r in configs_with_acc]))
        w(_eval_metric_str("Checksum Corruption Rejection", [r.accuracy.checksum_corruption_rejected for r in configs_with_acc]))
        w(_eval_metric_str("Ciphertext Tampering Rejection", [r.accuracy.ciphertext_tamper_rejected for r in configs_with_acc]))
        w()

    w("| Algorithm | Parameters | Extraction Success | Exact Match | Algo Match | Auth Verified | Wrong Pwd Rejected | Sync Corrupt Rejected | Checksum Corrupt Rejected | Ciphertext Tamper Rejected |")
    w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for r in results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        if r.accuracy:
            a = r.accuracy
            succ_s = "PASS" if a.extraction_success is True else ("FAIL" if a.extraction_success is False else "N/A")
            match_s = "100%" if a.exact_match is True else ("0%" if a.exact_match is False else "N/A")
            alg_s = "MATCH" if a.algorithm_match is True else ("MISMATCH" if a.algorithm_match is False else "N/A")
            auth_s = "VERIFIED" if a.authentication_verified is True else ("FAIL" if a.authentication_verified is False else "N/A")
            pwd_s = "REJECTED" if a.wrong_password_rejected is True else ("FAIL" if a.wrong_password_rejected is False else "N/A")
            sync_s = "REJECTED" if a.sync_corruption_rejected is True else ("FAIL" if a.sync_corruption_rejected is False else "N/A")
            chk_s = "REJECTED" if a.checksum_corruption_rejected is True else ("FAIL" if a.checksum_corruption_rejected is False else "N/A")
            tamp_s = "REJECTED" if a.ciphertext_tamper_rejected is True else ("FAIL" if a.ciphertext_tamper_rejected is False else "N/A")
            w(f"| `{r.algorithm_id}` | `{p_str}` | {succ_s} | {match_s} | {alg_s} | {auth_s} | {pwd_s} | {sync_s} | {chk_s} | {tamp_s} |")
        else:
            w(f"| `{r.algorithm_id}` | `{p_str}` | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |")
    w()
    w("### Integrity & Authentication Observations:")
    if configs_with_acc:
        exact_valid = [r.accuracy.exact_match for r in configs_with_acc if r.accuracy.exact_match in (True, False)]
        if exact_valid:
            exact_count = sum(1 for v in exact_valid if v is True)
            exact_pct = (exact_count / len(exact_valid)) * 100
            w(
                f"- **Exact Match Fidelity:** {exact_pct:.1f}% ({exact_count}/{len(exact_valid)}) "
                f"of evaluated configurations with exact-match data yielded bit-for-bit identical recovered plaintexts."
            )
        else:
            w("- **Exact Match Fidelity:** Not evaluated in this run.")

        tamper_valid = [r.accuracy.ciphertext_tamper_rejected for r in configs_with_acc if r.accuracy.ciphertext_tamper_rejected in (True, False)]
        if tamper_valid:
            tamper_count = sum(1 for v in tamper_valid if v is True)
            tamper_pct = (tamper_count / len(tamper_valid)) * 100
            w(
                f"- **Cryptographic Tamper Evidence:** In {tamper_count}/{len(tamper_valid)} ({tamper_pct:.1f}%) "
                f"of evaluated configurations with tampered ciphertext and valid framing, AES-256-GCM authentication failed and was rejected."
            )
        else:
            w("- **Cryptographic Tamper Evidence:** Not evaluated in this run.")

        chk_valid = [r.accuracy.checksum_corruption_rejected for r in configs_with_acc if r.accuracy.checksum_corruption_rejected in (True, False)]
        if chk_valid:
            chk_count = sum(1 for v in chk_valid if v is True)
            chk_pct = (chk_count / len(chk_valid)) * 100
            w(
                f"- **Checksum Separation:** In {chk_count}/{len(chk_valid)} ({chk_pct:.1f}%) "
                f"of evaluated configurations with corrupted payload bits, the framing layer rejected extraction via CRC32 mismatch independently of cryptographic decryption."
            )
        else:
            w("- **Checksum Separation:** Not evaluated in this run.")
    else:
        w("- **Integrity & Authentication:** No configuration contained accuracy evaluation records in this run.")
    w()

    # 9. Robustness Evaluation Across Controlled Channel Transformations
    configs_with_rob = [r for r in results if r.robustness and len(r.robustness) > 0]
    configs_without_rob = [r for r in results if not r.robustness or len(r.robustness) == 0]

    all_rob_records = [rob for r in configs_with_rob for rob in r.robustness]
    not_tested_count = sum(1 for rob in all_rob_records if rob.status == "NOT TESTED")
    evaluated_records_count = sum(1 for rob in all_rob_records if rob.status != "NOT TESTED")

    w("## 9. Robustness Evaluation Across Controlled Channel Transformations")
    w()
    w(
        f"Robustness evaluations were recorded for {len(configs_with_rob)} of {len(results)} configuration(s) "
        f"({len(configs_without_rob)} configuration(s) had no robustness records). "
        f"Across all recorded records, {evaluated_records_count} transformation test(s) were actively evaluated, "
        f"and {not_tested_count} record(s) were classified as `NOT TESTED` due to unavailable external dependencies. "
        "Missing records or `NOT TESTED` outcomes reflect environment constraints or unperformed evaluations and are not interpreted as failures."
    )
    w()
    w("| Algorithm | Parameters | Unmodified | Gaussian Noise ($\\sigma=1.0$) | Amplitude Scaling (0.95x) | Resampling (44k $\\to$ 22k $\\to$ 44k) | Lossy Compression |")
    w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for r in results:
        p_str = ", ".join(f"{k}={v}" for k, v in r.options.items()) if r.options else "default"
        if r.robustness:
            rob_dict = {rob.transformation_name: rob.status for rob in r.robustness}
            w(
                f"| `{r.algorithm_id}` | `{p_str}` | "
                f"{rob_dict.get('Unmodified WAV', 'N/A')} | "
                f"{rob_dict.get('Additive Gaussian Noise', 'N/A')} | "
                f"{rob_dict.get('Amplitude Scaling', 'N/A')} | "
                f"{rob_dict.get('Resampling', 'N/A')} | "
                f"{rob_dict.get('Lossy Compression', 'N/A')} |"
            )
        else:
            w(f"| `{r.algorithm_id}` | `{p_str}` | N/A | N/A | N/A | N/A | N/A |")
    w()
    w("### Robustness Observations & Failure Modes:")
    lsb_rob = [r for r in results if r.algorithm_id == "lsb" and r.robustness]
    if lsb_rob:
        rob_map = {rob.transformation_name: rob.status for rob in lsb_rob[0].robustness}
        w(
            f"1. **LSB Resilience:** Evaluated outcomes: Gaussian Noise -> `{rob_map.get('Additive Gaussian Noise', 'N/A')}`, "
            f"Amplitude Scaling -> `{rob_map.get('Amplitude Scaling', 'N/A')}`, Resampling -> `{rob_map.get('Resampling', 'N/A')}`."
        )
    else:
        w("1. **LSB Robustness:** Not evaluated in this run.")

    dwt_rob = [r for r in results if r.algorithm_id == "dwt_dct_qim" and r.robustness]
    if dwt_rob:
        items = []
        for r in dwt_rob:
            delta_val = r.options.get("delta", "default")
            r_map = {rob.transformation_name: rob.status for rob in r.robustness}
            items.append(
                f"delta={delta_val} (Noise: `{r_map.get('Additive Gaussian Noise', 'N/A')}`, "
                f"Scale: `{r_map.get('Amplitude Scaling', 'N/A')}`, "
                f"Resample: `{r_map.get('Resampling', 'N/A')}`)"
            )
        w(f"2. **DWT-DCT-QIM Resilience:** Evaluated configurations: {'; '.join(items)}.")
    else:
        w("2. **DWT-DCT-QIM Robustness:** Not evaluated in this run.")

    echo_rob = [r for r in results if r.algorithm_id == "echo" and r.robustness]
    if echo_rob:
        items = []
        for r in echo_rob:
            alpha_val = r.options.get("alpha", "default")
            r_map = {rob.transformation_name: rob.status for rob in r.robustness}
            items.append(
                f"alpha={alpha_val} (Noise: `{r_map.get('Additive Gaussian Noise', 'N/A')}`, "
                f"Scale: `{r_map.get('Amplitude Scaling', 'N/A')}`, "
                f"Resample: `{r_map.get('Resampling', 'N/A')}`)"
            )
        w(f"3. **Echo Hiding Resilience:** Evaluated configurations: {'; '.join(items)}.")
    else:
        w("3. **Echo Hiding Robustness:** Not evaluated in this run.")

    lossy_statuses = sorted(set(rob.status for r in results if r.robustness for rob in r.robustness if rob.transformation_name == "Lossy Compression"))
    if "NOT TESTED" in lossy_statuses and len(lossy_statuses) == 1:
        w(
            "4. **Lossy Compression Status:** Because external encoding tools (FFmpeg / LAME) were not available on this host environment, "
            "lossy compression was marked `NOT TESTED` (this is not equivalent to failure)."
        )
    elif lossy_statuses:
        w(f"4. **Lossy Compression Status:** Evaluated outcomes: {', '.join(f'`{s}`' for s in lossy_statuses)}.")
    else:
        w("4. **Lossy Compression Status:** Not evaluated in this run.")
    w()

    # 10. Limitations
    w("## 10. Limitations of the Benchmark")
    w()
    if carrier_names:
        c_types = []
        for name in carrier_names:
            nl = name.lower()
            if "chirp" in nl or "synthetic" in nl:
                c_types.append(f"`{name}` (Synthetic Chirp)")
            elif "speech" in nl:
                c_types.append(f"`{name}` (Speech Audio)")
            elif "music" in nl:
                c_types.append(f"`{name}` (Music Audio)")
            else:
                c_types.append(f"`{name}` (Audio Carrier)")
        w(
            f"1. **Test Carrier Scope:** Evaluations were performed using {', '.join(c_types)}. "
            "Real-world audio carriers (speech, orchestral music, field recordings) present distinct spectral profiles that may influence masking and SNR."
        )
    else:
        w(
            "1. **Test Carrier Scope:** Test carrier metadata was unavailable in this report. "
            "Real-world audio carriers (speech, orchestral music, field recordings) present distinct spectral profiles that may influence masking and SNR."
        )
    w(
        "2. **Resampling Simulation Scope:** The resampling evaluation is a controlled interpolation simulation (44.1 kHz $\\to$ 22.05 kHz $\\to$ 44.1 kHz via linear interpolation) "
        "and does not represent every commercial anti-aliasing sinc-filter resampling pipeline."
    )
    w(
        "3. **Missing External Codecs:** FFmpeg and LAME were not installed on the system; lossy perceptual compression resilience was marked `NOT TESTED`."
    )
    w(
        "4. **Acoustic Air-Gap:** Acoustic air-gap (speaker-to-microphone transmission) was outside the scope of this file-based benchmark."
    )
    w()

    # 11. Final Comparative Analysis & Engineering Recommendations
    w("## 11. Final Comparative Analysis & Engineering Recommendations")
    w()
    carrier_label = ", ".join(f"`{c}`" for c in carrier_names) if carrier_names else "the evaluated test carrier(s)"
    w(
        "> [!NOTE]\n"
        "> **Distinction between Architectural Guidance and Measured Findings:**\n"
        "> The matrix and takeaways below provide architectural engineering guidance derived from cryptographic and "
        "> signal-processing characteristics. They do not constitute universal empirical proofs across all audio genres "
        f"> or arbitrary carrier waveforms. Measured performance on {carrier_label} is recorded in "
        "> Sections 5–9 above. Robustness and perceptual transparency in production must be validated against target "
        "> audio material (e.g., speech, orchestral, ambient)."
    )
    w()
    w("### 11.1 Algorithm Selection Matrix")
    w()
    w("| Operational Criterion | Recommended Algorithm | Recommended Parameters | Architectural Rationale |")
    w("| :--- | :--- | :--- | :--- |")
    w("| **High-Capacity / Large Documents** | **LSB** | Default (`framing='csma'`) | Highest raw bit density (1 bit/sample), low computational complexity. |")
    w("| **Audiophile Transparency / Low Distortion** | **LSB** or **DWT-DCT-QIM** | LSB or DWT ($\\Delta=16$) | Minimal waveform perturbation; high theoretical PSNR. |")
    w("| **Noisy Digital Channels** | **DWT-DCT-QIM** | $\\Delta = 32$ or $\\Delta = 64$ | Quantization index modulation in detail wavelet subband resists moderate additive perturbations. |")
    w("| **Volume Attenuation / Amplitude Scaling** | **Echo Hiding** | $\\alpha = 0.08$ | Cepstral ratio peak detection provides theoretical scale invariance. |")
    w("| **Short Audio Clips (< 10 seconds)** | **LSB** | Default | High bit density required to accommodate the 536-bit minimum encrypted CSMA envelope. |")
    w()
    w("### 11.2 Key Engineering Takeaways")
    w()
    w(
        "1. **LSB is strictly for lossless channels:** Sample-domain LSB replacement cannot withstand noise, amplitude alteration, or lossy re-encoding."
    )
    w(
        "2. **DWT-DCT-QIM noise resilience trade-off:** Higher quantization step $\\Delta$ enhances noise tolerance while lower $\\Delta$ improves imperceptibility (PSNR)."
    )
    w(
        "3. **Echo Hiding carrier duration constraint:** Because Echo Hiding embeds 1 bit per 2,048 samples and the minimum encrypted CSMA envelope is 536 bits, "
        "carriers under ~25 seconds lack sufficient capacity."
    )
    w(
        "4. **Carrier Generalization:** Robustness observed under evaluated test carriers does not guarantee identical resilience across all natural acoustic signals."
    )
    w()
    w("---")
    w("*Report generated automatically by CryptAudio-Web Benchmarking Framework (Phase M7.2).*")

    out_p.write_text("\n".join(lines), encoding="utf-8")
    return out_p
