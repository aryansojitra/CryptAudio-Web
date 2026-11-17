"""
app/main.py
CryptAudio Web — FastAPI Application Entry Point

Phase 2: Backend Foundation
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core.config import settings

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent          # app/
PROJECT_ROOT = BASE_DIR.parent                      # Project root
FRONTEND_DIR = PROJECT_ROOT / "frontend"           # frontend/
INDEX_HTML = FRONTEND_DIR / "index.html"

# ---------------------------------------------------------------------------
# Application Lifespan (Startup & Shutdown Lifecycle)
# ---------------------------------------------------------------------------

def cleanup_orphaned_temp_files() -> int:
    """Clean any orphaned temporary files on application startup or maintenance."""
    count = 0
    try:
        if settings.TEMP_DIR.exists():
            for tmp_file in settings.TEMP_DIR.glob("*.wav"):
                try:
                    tmp_file.unlink(missing_ok=True)
                    count += 1
                except OSError:
                    pass
    except Exception as exc:
        logger.warning("Failed to clean temporary directory: %s", exc)
    return count


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Clean any orphaned temporary files on application startup."""
    cleanup_orphaned_temp_files()
    yield


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    # Swagger UI available at /docs; ReDoc at /redoc
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Enforce browser security headers across all responses:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Referrer-Policy: no-referrer
    - X-XSS-Protection: 0
    - Content-Security-Policy (CSP)
    - Anti-caching for sensitive /api/* requests
    """
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "0"

    # Dedicated Content-Security-Policy:
    # - Swagger UI (/docs, /redoc, /openapi.json) requires Swagger UI assets
    # - Application routes (/, /static/*, /api/*) enforce hardened CSP with NO CDN and NO unsafe-inline scripts
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self';"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "media-src 'self' blob:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

# ---------------------------------------------------------------------------
# API routes  (/api/*)
# ---------------------------------------------------------------------------

app.include_router(api_router)

# ---------------------------------------------------------------------------
# Static file serving  (/static/*)
# ---------------------------------------------------------------------------

app.mount(
    "/static",
    StaticFiles(directory=str(FRONTEND_DIR)),
    name="static",
)

# ---------------------------------------------------------------------------
# Root route — serve the frontend
# ---------------------------------------------------------------------------

@app.get(
    "/",
    summary="Frontend",
    description="Serves the CryptAudio Web browser interface.",
    include_in_schema=False,   # Keep Swagger docs uncluttered
)
async def serve_index(request: Request) -> FileResponse:
    """Return the main HTML page."""
    return FileResponse(str(INDEX_HTML), media_type="text/html")


# ---------------------------------------------------------------------------
# Centralized exception handlers — no stack traces exposed to callers
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle validation errors with HTTP 400 and standard error JSON format.
    """
    logger.warning("Validation error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": {
                "code": "INVALID_REQUEST",
                "message": "Invalid or missing request parameters.",
            },
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all handler for unhandled server errors.

    Logs the full exception server-side; returns a safe generic message
    to the caller so internal details are never leaked.
    """
    logger.exception(
        "Unhandled exception on %s %s", request.method, request.url.path
    )
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. Please try again.",
            },
        },
    )
