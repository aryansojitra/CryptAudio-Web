"""
app/main.py
CryptAudio Web — FastAPI Application Entry Point

Phase 2: Backend Foundation
"""

from __future__ import annotations

import logging
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
STATIC_DIR = BASE_DIR / "static"                   # app/static/
INDEX_HTML = STATIC_DIR / "index.html"

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    # Swagger UI available at /docs; ReDoc at /redoc
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# API routes  (/api/*)
# ---------------------------------------------------------------------------

app.include_router(api_router)

# ---------------------------------------------------------------------------
# Static file serving  (/static/*)
# ---------------------------------------------------------------------------

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
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
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please try again.",
        },
    )
