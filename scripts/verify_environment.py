"""
scripts/verify_environment.py
CryptAudio Web — Environment Verification Script

Checks Python version, virtual environment, required packages,
and project directory structure.

Usage:
    .venv\\Scripts\\python.exe scripts\\verify_environment.py
"""

import sys
import os
import importlib

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []  # (label, status, detail)


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = PASS if condition else FAIL
    results.append((label, status, detail))
    indicator = "✔" if condition else "✘"
    print(f"  [{indicator}] {status:4s}  {label}" + (f" — {detail}" if detail else ""))
    return condition


def try_import(module_name: str, friendly_name: str | None = None) -> bool:
    name = friendly_name or module_name
    try:
        importlib.import_module(module_name)
        return check(f"Import: {name}", True)
    except ImportError as exc:
        return check(f"Import: {name}", False, str(exc))


# ---------------------------------------------------------------------------
# 1. Python Version
# ---------------------------------------------------------------------------

print("\n── Python Version ─────────────────────────────────────────────────────")
py_ver = sys.version_info
version_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
check(
    "Python 3.13+",
    py_ver.major == 3 and py_ver.minor >= 13,
    f"Detected: Python {version_str}",
)

# ---------------------------------------------------------------------------
# 2. Virtual Environment Interpreter
# ---------------------------------------------------------------------------

print("\n── Virtual Environment ─────────────────────────────────────────────────")
interpreter = sys.executable
in_venv = (
    hasattr(sys, "real_prefix")
    or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
)
check("Running inside a virtual environment", in_venv, f"Interpreter: {interpreter}")

# ---------------------------------------------------------------------------
# 3. Required Package Imports
# ---------------------------------------------------------------------------

print("\n── Required Packages ───────────────────────────────────────────────────")
try_import("fastapi", "FastAPI")
try_import("uvicorn", "Uvicorn")
try_import("cryptography", "cryptography")
try_import("numpy", "NumPy")
try_import("matplotlib", "Matplotlib")
try_import("pytest", "pytest")
try_import("httpx", "HTTPX")
try_import("multipart", "python-multipart")

# Standard library
try_import("wave", "wave (stdlib)")

# ---------------------------------------------------------------------------
# 4. Project Directory Structure
# ---------------------------------------------------------------------------

print("\n── Project Directories ─────────────────────────────────────────────────")

# Resolve project root (parent of scripts/)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

required_dirs = [
    "app",
    "app/api",
    "app/core",
    "app/crypto",
    "app/audio",
    "app/steganography",
    "app/services",
    "app/evaluation",
    "app/static",
    "app/static/css",
    "app/static/js",
    "app/static/assets",
    "tests",
    "scripts",
    "temporary",
]

required_files = [
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
    "app/static/index.html",
    "temporary/.gitkeep",
]

for rel_path in required_dirs:
    abs_path = os.path.join(project_root, rel_path.replace("/", os.sep))
    check(f"Directory: {rel_path}", os.path.isdir(abs_path))

print()
for rel_path in required_files:
    abs_path = os.path.join(project_root, rel_path.replace("/", os.sep))
    check(f"File:      {rel_path}", os.path.isfile(abs_path))

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------

passed = sum(1 for _, s, _ in results if s == PASS)
failed = sum(1 for _, s, _ in results if s == FAIL)
total = len(results)

print("\n── Summary ─────────────────────────────────────────────────────────────")
print(f"  Total checks : {total}")
print(f"  Passed       : {passed}")
print(f"  Failed       : {failed}")

if failed == 0:
    print("\n  ✔ ENVIRONMENT VERIFICATION: PASS\n")
    sys.exit(0)
else:
    print(f"\n  ✘ ENVIRONMENT VERIFICATION: FAIL  ({failed} check(s) failed)\n")
    sys.exit(1)
