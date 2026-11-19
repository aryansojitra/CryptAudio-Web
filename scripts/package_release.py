"""
scripts/package_release.py
CryptAudio Web — Final Release Packaging Script

Creates a clean, distributable ZIP archive:
  CryptAudio-Web-Final.zip
containing a top-level CryptAudio-Web/ folder.

Excludes:
- .venv/, .git/, __pycache__/, .pytest_cache/, .idea/, .vscode/, node_modules/, etc.
- Sensitive environment files (.env, .env.* except safe .env.example)
- Private key and certificate files (.pem, .key, .p12, .pfx, .pkcs12, .crt, .cer, .der)
- Credentials and secrets (id_rsa, credentials.json, token.json, secrets.json, etc.)
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

# Directories to completely ignore anywhere in relative path
EXCLUDE_DIRS = {
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "node_modules",
    ".mypy_cache",
    ".ruff_cache",
}

# Binary / cache / intermediate file extensions to ignore
EXCLUDE_FILE_PATTERNS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".wav",
}

# Private keys, certificates, and keystore extensions to exclude strictly
SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".pkcs12",
    ".crt",
    ".cer",
    ".der",
    ".kdbx",
}

# Credential and sensitive exact filenames to exclude
SENSITIVE_EXACT_NAMES = {
    ".env",
    "credentials.json",
    "token.json",
    "client_secret.json",
    "service_account.json",
    "secrets.json",
    ".htpasswd",
    ".netrc",
    "id_rsa",
    "id_rsa.pub",
    "id_dsa",
    "id_dsa.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
}


def is_sensitive_path_component(name: str) -> bool:
    """Determine whether a single path component (filename or directory) is sensitive."""
    lower_name = name.lower()

    # Exact sensitive names
    if lower_name in SENSITIVE_EXACT_NAMES:
        return True

    # Environment files: .env and .env.* (e.g. .env.local, .env.production)
    # .env.example is permitted ONLY as an intentional safe configuration template
    if lower_name == ".env" or lower_name.endswith(".env"):
        return True
    if lower_name.startswith(".env.") and lower_name != ".env.example":
        return True

    # Sensitive key/certificate extensions
    for ext in SENSITIVE_EXTENSIONS:
        if lower_name.endswith(ext):
            return True

    # Private SSH / TLS key file prefixes
    for prefix in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        if lower_name.startswith(prefix):
            return True

    return False


def should_include(rel_path: Path) -> bool:
    """Determine whether a given relative path should be included in the release ZIP."""
    parts = rel_path.parts

    # Check if any part in the path is an excluded directory
    for part in parts:
        if part in EXCLUDE_DIRS:
            return False

    # Check if any part in the path (directory or filename) is sensitive
    for part in parts:
        if is_sensitive_path_component(part):
            return False

    # In temporary/, only include .gitkeep
    if len(parts) >= 2 and parts[0] == "temporary" and parts[1] != ".gitkeep":
        return False

    # Exclude zip and tar archives
    if rel_path.name.endswith(".zip") or rel_path.name.endswith(".tar.gz"):
        return False

    # Exclude binary/cache file extensions (.wav, .pyc, etc.)
    for ext in EXCLUDE_FILE_PATTERNS:
        if rel_path.name.endswith(ext):
            return False

    return True


def create_release_archive(
    source_root: Path,
    output_zip: Path,
    archive_prefix: str = ARCHIVE_PREFIX,
) -> tuple[int, int]:
    """
    Package source_root into output_zip under archive_prefix applying should_include rules.
    Returns (included_count, total_uncompressed_bytes).
    """
    if output_zip.exists():
        output_zip.unlink()

    included_count = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_root.rglob("*")):
            if not file_path.is_file():
                continue
            rel = file_path.relative_to(source_root)
            if should_include(rel):
                arcname = str(Path(archive_prefix) / rel) if archive_prefix else str(rel)
                zf.write(file_path, arcname)
                included_count += 1
                total_uncompressed_bytes += file_path.stat().st_size

    return included_count, total_uncompressed_bytes


def package_release() -> None:
    print(f"[*] Packaging CryptAudio-Web release into {OUTPUT_ZIP.name}...")

    included_count, total_uncompressed_bytes = create_release_archive(
        PROJECT_ROOT, OUTPUT_ZIP, ARCHIVE_PREFIX
    )

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
        assert f"{ARCHIVE_PREFIX}/run.py" in namelist
        assert f"{ARCHIVE_PREFIX}/render.yaml" in namelist
        assert f"{ARCHIVE_PREFIX}/run.ps1" in namelist
        assert f"{ARCHIVE_PREFIX}/temporary/.gitkeep" in namelist
        assert f"{ARCHIVE_PREFIX}/frontend/assets/.gitkeep" in namelist
        assert f"{ARCHIVE_PREFIX}/frontend/index.html" in namelist

        # Verify exclusions
        for n in namelist:
            name_lower = n.lower()
            assert ".venv" not in n, f"Found .venv file in archive: {n}"
            assert ".git/" not in n, f"Found .git file in archive: {n}"
            assert "__pycache__" not in n, f"Found __pycache__ in archive: {n}"
            assert ".pytest_cache" not in n, f"Found .pytest_cache in archive: {n}"
            assert not n.endswith(".wav"), f"Found .wav audio in archive: {n}"

            # Verify no environment secrets
            leaf = Path(n).name.lower()
            if leaf == ".env" or (leaf.startswith(".env.") and leaf != ".env.example") or leaf.endswith(".env"):
                raise AssertionError(f"Found sensitive environment file in archive: {n}")

            # Verify no private keys or certificates
            for ext in SENSITIVE_EXTENSIONS:
                assert not name_lower.endswith(ext), f"Found private key/certificate file in archive: {n}"

            # Verify no credentials
            assert leaf not in SENSITIVE_EXACT_NAMES or leaf == ".env.example", f"Found credential file in archive: {n}"

    print("[✔] Archive verification: 100% PASS (All required files present; all secrets/caches/temps excluded).")


if __name__ == "__main__":
    package_release()
