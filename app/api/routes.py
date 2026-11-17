"""
app/api/routes.py
CryptAudio Web — API Router

All application endpoints are registered here under the /api prefix.
Future phases will add sub-routers for crypto, audio, and steganography operations.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.config import settings

router = APIRouter(prefix="/api", tags=["API"])


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    summary="Health check",
    description="Returns the operational status of the application.",
    response_description="Application health information.",
)
async def health_check() -> JSONResponse:
    """
    GET /api/health

    Returns HTTP 200 with a JSON payload confirming the application is running.
    """
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
        },
    )
