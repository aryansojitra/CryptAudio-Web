"""
tests/test_environment.py
CryptAudio Web — Phase 1 Environment Tests

Verifies:
  - Required project directories exist.
  - Required Python packages can be imported.
  - Package __init__.py structure is valid.

Run with:
    .venv\\Scripts\\python.exe -m pytest tests/test_environment.py -v
"""

import importlib
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Project root resolution
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Directory existence tests
# ---------------------------------------------------------------------------

REQUIRED_DIRS = [
    "app",
    "app/api",
    "app/core",
    "app/crypto",
    "app/audio",
    "app/steganography",
    "app/services",
    "app/evaluation",
    "frontend",
    "frontend/css",
    "frontend/js",
    "frontend/assets",
    "tests",
    "scripts",
    "temporary",
]


@pytest.mark.parametrize("rel_path", REQUIRED_DIRS)
def test_required_directory_exists(rel_path: str) -> None:
    """Each required project directory must exist."""
    abs_path = os.path.join(PROJECT_ROOT, rel_path.replace("/", os.sep))
    assert os.path.isdir(abs_path), f"Directory missing: {rel_path}"


# ---------------------------------------------------------------------------
# Required file existence tests
# ---------------------------------------------------------------------------

REQUIRED_FILES = [
    "requirements.txt",
    "README.md",
    ".gitignore",
    "app/__init__.py",
    "app/main.py",
    "app/api/__init__.py",
    "app/core/__init__.py",
    "app/crypto/__init__.py",
    "app/audio/__init__.py",
    "app/steganography/__init__.py",
    "app/services/__init__.py",
    "app/evaluation/__init__.py",
    "frontend/index.html",
    "temporary/.gitkeep",
    "scripts/verify_environment.py",
]


@pytest.mark.parametrize("rel_path", REQUIRED_FILES)
def test_required_file_exists(rel_path: str) -> None:
    """Each required project file must exist."""
    abs_path = os.path.join(PROJECT_ROOT, rel_path.replace("/", os.sep))
    assert os.path.isfile(abs_path), f"File missing: {rel_path}"


# ---------------------------------------------------------------------------
# Python package import tests
# ---------------------------------------------------------------------------

REQUIRED_PACKAGES = [
    ("fastapi", "FastAPI"),
    ("uvicorn", "Uvicorn"),
    ("cryptography", "cryptography"),
    ("numpy", "NumPy"),
    ("matplotlib", "Matplotlib"),
    ("pytest", "pytest"),
    ("httpx", "HTTPX"),
    ("python_multipart", "python-multipart"),
    ("wave", "wave (stdlib)"),
]


@pytest.mark.parametrize("module_name,friendly_name", REQUIRED_PACKAGES)
def test_package_importable(module_name: str, friendly_name: str) -> None:
    """Each required package must be importable."""
    try:
        importlib.import_module(module_name)
    except ImportError as exc:
        pytest.fail(f"Cannot import {friendly_name} ({module_name}): {exc}")


# ---------------------------------------------------------------------------
# Python package __init__.py validity tests
# ---------------------------------------------------------------------------

APP_PACKAGES = [
    "app",
    "app.api",
    "app.core",
    "app.crypto",
    "app.audio",
    "app.steganography",
    "app.services",
    "app.evaluation",
]


@pytest.mark.parametrize("package", APP_PACKAGES)
def test_app_package_importable(package: str) -> None:
    """Each app sub-package must be importable as a Python package."""
    # Add project root to sys.path so app.* packages resolve correctly
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    try:
        importlib.import_module(package)
    except ImportError as exc:
        pytest.fail(f"Cannot import package '{package}': {exc}")


# ---------------------------------------------------------------------------
# Python version test
# ---------------------------------------------------------------------------


def test_python_version() -> None:
    """Python version must be 3.13 or later."""
    assert sys.version_info >= (3, 13), (
        f"Python 3.13+ required; found {sys.version_info.major}.{sys.version_info.minor}"
    )
