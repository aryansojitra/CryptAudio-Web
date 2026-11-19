"""
run.py
CryptAudio-Web — Standard Application Launcher
"""

from __future__ import annotations

import os
import sys
import uvicorn

from app.core.config import settings


def main() -> None:
    """Launch the CryptAudio-Web application server."""
    host = os.getenv("HOST", settings.HOST)
    port = int(os.getenv("PORT", str(settings.PORT)))

    print("\n" + "=" * 60)
    print("                 CryptAudio-Web Server")
    print(f"       Running on http://{host}:{port}")
    print("=" * 60 + "\n")

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=settings.DEBUG,
        log_level="info",
    )


if __name__ == "__main__":
    main()
