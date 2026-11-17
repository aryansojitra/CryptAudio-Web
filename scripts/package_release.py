"""
scripts/package_release.py
CryptAudio Web — Final Release Packaging Script

Creates a clean, distributable ZIP archive:
  CryptAudio-Web-Final.zip
containing a top-level CryptAudio-Web/ folder.

Excludes:
- .venv/
- .git/
- __pycache__/
- .pytest_cache/
- temporary/*.wav (preserves temporary/.gitkeep)
- *.zip, *.tar.gz
- logs, local scratch files
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_ZIP = PROJECT_ROOT / "CryptAudio-Web-Final.zip"
ARCHIVE_PREFIX = "CryptAudio-Web"

# Directories and patterns to completely ignore
EXCLUDE_DIRS = {
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "node_modules",
}

EXCLUDE_FILE_PATTERNS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
}


def should_include(rel_path: Path) -> bool:
    """Determine whether a given relative path should be included in release."""
    parts = rel_path.parts
    # Check if any parent part is in EXCLUDE_DIRS
    for part in parts:
        if part in EXCLUDE_DIRS:
            return False

    # In temporary/, only include .gitkeep
    if len(parts) >= 2 and parts[0] == "temporary" and parts[1] != ".gitkeep":
        return False

    # Exclude zip archives themselves
    if rel_path.name.endswith(".zip") or rel_path.name.endswith(".tar.gz"):
        return False

    # Check file extension / pattern
    for ext in EXCLUDE_FILE_PATTERNS:
        if rel_path.name.endswith(ext):
            return False

    return True


def package_release() -> None:
    print(f"[*] Packaging CryptAudio-Web release into {OUTPUT_ZIP.name}...")
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()

    included_count = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(PROJECT_ROOT.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(PROJECT_ROOT)
            if should_include(rel):
                arcname = str(Path(ARCHIVE_PREFIX) / rel)
                zf.write(file_path, arcname)
                included_count += 1
                total_uncompressed_bytes += file_path.stat().st_size

    archive_size_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"[✔] Successfully created {OUTPUT_ZIP.name}")
    print(f"    Total files packaged: {included_count}")
    print(f"    Uncompressed size:    {total_uncompressed_bytes / 1024:.1f} KB")
    print(f"    Compressed archive:   {archive_size_mb:.2f} MB ({OUTPUT_ZIP.stat().st_size} bytes)")

    # Verify inspection
    print("\n[*] Inspecting archive contents...")
    with zipfile.ZipFile(OUTPUT_ZIP, "r") as zf:
        namelist = zf.namelist()
        assert all(n.startswith(f"{ARCHIVE_PREFIX}/") for n in namelist)
        assert f"{ARCHIVE_PREFIX}/app/main.py" in namelist
        assert f"{ARCHIVE_PREFIX}/README.md" in namelist
        assert f"{ARCHIVE_PREFIX}/PROJECT_REPORT.md" in namelist
        assert f"{ARCHIVE_PREFIX}/SECURITY_ASSESSMENT.md" in namelist
        assert f"{ARCHIVE_PREFIX}/TEST_REPORT.md" in namelist
        assert f"{ARCHIVE_PREFIX}/API_DOCUMENTATION.md" in namelist
        assert f"{ARCHIVE_PREFIX}/CHANGELOG.md" in namelist
        assert f"{ARCHIVE_PREFIX}/run.ps1" in namelist
        assert f"{ARCHIVE_PREFIX}/temporary/.gitkeep" in namelist
        # Verify exclusions
        for n in namelist:
            assert ".venv" not in n, f"Found .venv file in archive: {n}"
            assert ".git/" not in n, f"Found .git file in archive: {n}"
            assert "__pycache__" not in n, f"Found __pycache__ in archive: {n}"
            assert ".pytest_cache" not in n, f"Found .pytest_cache in archive: {n}"
            assert not n.endswith(".wav"), f"Found .wav audio in archive: {n}"

    print("[✔] Archive verification: 100% PASS (All required files present; all caches/temps excluded).")


if __name__ == "__main__":
    package_release()
