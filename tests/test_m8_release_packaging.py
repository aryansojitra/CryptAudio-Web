"""
tests/test_m8_release_packaging.py
CryptAudio-Web — Phase M8 Release Packaging Security & Exclusion Tests

Automated verification of release packaging rules:
- .env is excluded
- .env.local is excluded
- .env.production is excluded
- Private key files (.pem, .key, .p12, .pfx, etc.) are excluded
- Nested sensitive files in subdirectories are excluded
- Approved non-sensitive project files remain included
- Required frontend, backend, configuration, and documentation files remain in the archive
"""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest

from scripts.package_release import (
    ARCHIVE_PREFIX,
    create_release_archive,
    is_sensitive_path_component,
    should_include,
)


@pytest.fixture
def mock_project_tree(tmp_path: Path) -> Path:
    """Create a temporary project structure containing both valid and sensitive files."""
    project_root = tmp_path / "mock_project"
    project_root.mkdir()

    # Required project files
    (project_root / "app").mkdir()
    (project_root / "app" / "main.py").write_text("# main app")
    (project_root / "app" / "core").mkdir()
    (project_root / "app" / "core" / "config.py").write_text("# config")

    (project_root / "frontend").mkdir()
    (project_root / "frontend" / "index.html").write_text("<!DOCTYPE html><html></html>")
    (project_root / "frontend" / "assets").mkdir()
    (project_root / "frontend" / "assets" / ".gitkeep").write_text("")

    (project_root / "temporary").mkdir()
    (project_root / "temporary" / ".gitkeep").write_text("")
    (project_root / "temporary" / "orphaned_audio.wav").write_bytes(b"RIFFjunkWAVE")

    (project_root / "README.md").write_text("# CryptAudio-Web")
    (project_root / "PROJECT_REPORT.md").write_text("# Report")
    (project_root / "SECURITY_ASSESSMENT.md").write_text("# Security")
    (project_root / "TEST_REPORT.md").write_text("# Tests")
    (project_root / "API_DOCUMENTATION.md").write_text("# API")
    (project_root / "CHANGELOG.md").write_text("# Changelog")
    (project_root / "run.py").write_text("# runner")
    (project_root / "render.yaml").write_text("# render")
    (project_root / "run.ps1").write_text("# powershell")
    (project_root / "requirements.txt").write_text("fastapi\n")

    # Safe configuration template (if present)
    (project_root / ".env.example").write_text("HOST=127.0.0.1\nPORT=8000\n")

    # Sensitive files that MUST be excluded
    (project_root / ".env").write_text("SECRET_KEY=supersecret123\n")
    (project_root / ".env.local").write_text("DB_PASSWORD=localpass\n")
    (project_root / ".env.production").write_text("API_TOKEN=prod_token_xyz\n")
    (project_root / ".env.staging").write_text("STAGING_KEY=stage_secret\n")
    (project_root / "private_key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
    (project_root / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nMIIE...\n")
    (project_root / "keystore.p12").write_bytes(b"\x30\x82\x01\x00")
    (project_root / "cert.pfx").write_bytes(b"\x30\x82\x02\x00")
    (project_root / "credentials.json").write_text('{"client_id": "secret"}')
    (project_root / "secrets.json").write_text('{"api_key": "topsecret"}')
    (project_root / "id_rsa").write_text("fake rsa key")
    (project_root / "id_ed25519").write_text("fake ed25519 key")

    # Nested sensitive files
    nested_dir = project_root / "nested" / "subfolder"
    nested_dir.mkdir(parents=True)
    (nested_dir / ".env").write_text("NESTED_SECRET=123")
    (nested_dir / ".env.local").write_text("NESTED_LOCAL=456")
    (nested_dir / "database.key").write_text("fake key")
    (nested_dir / "client.pem").write_text("fake pem")
    (nested_dir / "safe_document.txt").write_text("This is safe")

    # Build / cache artifacts that must be excluded
    venv_dir = project_root / ".venv" / "Lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "site_package.py").write_text("# venv code")

    cache_dir = project_root / "app" / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "main.cpython-313.pyc").write_bytes(b"\x00" * 20)

    pytest_dir = project_root / ".pytest_cache"
    pytest_dir.mkdir()
    (pytest_dir / "state.json").write_text("{}")

    (project_root / "carrier_audio.wav").write_bytes(b"RIFF\x24\x00\x00\x00WAVE")

    return project_root


class TestReleasePackagingSecurity:
    """End-to-end tests for release packaging exclusion and inclusion logic."""

    def test_env_files_are_excluded(self, mock_project_tree: Path, tmp_path: Path) -> None:
        """.env, .env.local, .env.production, and nested .env files must be strictly excluded."""
        zip_path = tmp_path / "test_release.zip"
        create_release_archive(mock_project_tree, zip_path, archive_prefix="CryptAudio-Web")

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()

            # Ensure .env variants are absent
            assert "CryptAudio-Web/.env" not in namelist
            assert "CryptAudio-Web/.env.local" not in namelist
            assert "CryptAudio-Web/.env.production" not in namelist
            assert "CryptAudio-Web/.env.staging" not in namelist
            assert "CryptAudio-Web/nested/subfolder/.env" not in namelist
            assert "CryptAudio-Web/nested/subfolder/.env.local" not in namelist

            # No filename in archive should end with or contain sensitive env
            for name in namelist:
                leaf = Path(name).name.lower()
                assert leaf != ".env", f"Found .env file: {name}"
                if leaf.startswith(".env."):
                    assert leaf == ".env.example", f"Found sensitive env file: {name}"

    def test_private_keys_and_certificates_are_excluded(
        self, mock_project_tree: Path, tmp_path: Path
    ) -> None:
        """Private keys (.pem, .key, .p12, .pfx) and SSH keys must be strictly excluded."""
        zip_path = tmp_path / "test_release.zip"
        create_release_archive(mock_project_tree, zip_path, archive_prefix="CryptAudio-Web")

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()

            assert "CryptAudio-Web/private_key.pem" not in namelist
            assert "CryptAudio-Web/server.key" not in namelist
            assert "CryptAudio-Web/keystore.p12" not in namelist
            assert "CryptAudio-Web/cert.pfx" not in namelist
            assert "CryptAudio-Web/credentials.json" not in namelist
            assert "CryptAudio-Web/secrets.json" not in namelist
            assert "CryptAudio-Web/id_rsa" not in namelist
            assert "CryptAudio-Web/id_ed25519" not in namelist
            assert "CryptAudio-Web/nested/subfolder/database.key" not in namelist
            assert "CryptAudio-Web/nested/subfolder/client.pem" not in namelist

            for name in namelist:
                lower = name.lower()
                for ext in (".pem", ".key", ".p12", ".pfx", ".pkcs12", ".cer", ".crt"):
                    assert not lower.endswith(ext), f"Found private key/cert in release: {name}"

    def test_caches_virtualenvs_and_wavs_are_excluded(
        self, mock_project_tree: Path, tmp_path: Path
    ) -> None:
        """Virtualenvs, pycache, temporary audio, and root wav files must be excluded."""
        zip_path = tmp_path / "test_release.zip"
        create_release_archive(mock_project_tree, zip_path, archive_prefix="CryptAudio-Web")

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()

            for name in namelist:
                assert ".venv" not in name, f"Found .venv in release: {name}"
                assert "__pycache__" not in name, f"Found __pycache__ in release: {name}"
                assert ".pytest_cache" not in name, f"Found .pytest_cache in release: {name}"
                assert not name.endswith(".wav"), f"Found .wav audio in release: {name}"
                assert not name.endswith(".pyc"), f"Found .pyc in release: {name}"

    def test_approved_non_sensitive_project_files_remain_included(
        self, mock_project_tree: Path, tmp_path: Path
    ) -> None:
        """All required code, documentation, and asset files must remain present in the archive."""
        zip_path = tmp_path / "test_release.zip"
        create_release_archive(mock_project_tree, zip_path, archive_prefix="CryptAudio-Web")

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()

            # Core application files
            assert "CryptAudio-Web/app/main.py" in namelist
            assert "CryptAudio-Web/app/core/config.py" in namelist
            assert "CryptAudio-Web/frontend/index.html" in namelist
            assert "CryptAudio-Web/frontend/assets/.gitkeep" in namelist
            assert "CryptAudio-Web/temporary/.gitkeep" in namelist

            # Documentation and deployment
            assert "CryptAudio-Web/README.md" in namelist
            assert "CryptAudio-Web/PROJECT_REPORT.md" in namelist
            assert "CryptAudio-Web/SECURITY_ASSESSMENT.md" in namelist
            assert "CryptAudio-Web/TEST_REPORT.md" in namelist
            assert "CryptAudio-Web/API_DOCUMENTATION.md" in namelist
            assert "CryptAudio-Web/CHANGELOG.md" in namelist
            assert "CryptAudio-Web/run.py" in namelist
            assert "CryptAudio-Web/render.yaml" in namelist
            assert "CryptAudio-Web/run.ps1" in namelist
            assert "CryptAudio-Web/requirements.txt" in namelist

            # Safe nested file
            assert "CryptAudio-Web/nested/subfolder/safe_document.txt" in namelist

            # Safe configuration template (.env.example)
            assert "CryptAudio-Web/.env.example" in namelist
