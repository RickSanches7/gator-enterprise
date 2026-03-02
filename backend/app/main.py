"""
GATOR PRO Enterprise v2.0
Banking Penetration Testing Platform
gator.uz | GatorSupport@ya.ru
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import asyncio
import os

from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.logging import logger
from app.api import (
    router_scans,
    router_findings,
    router_engagements,
    router_reports,
    router_dashboard,
    router_tools,
    router_auth,
    router_ws,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("═" * 60)
    logger.info("  GATOR PRO ENTERPRISE v{} starting...", settings.VERSION)
    logger.info("  gator.uz | Banking Pentest Platform")
    logger.info("═" * 60)

    # Create DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.success("Database tables initialized")

    # Check tools availability
    from app.utils.tool_checker import check_all_tools
    tools = await check_all_tools()
    available = [t for t, v in tools.items() if v["available"]]
    missing = [t for t, v in tools.items() if not v["available"]]
    logger.info("Tools available: {}", ", ".join(available) if available else "none")
    if missing:
        logger.warning("Tools missing: {} — install for full functionality", ", ".join(missing))

    # Init Telegram bot if configured
    if settings.TELEGRAM_BOT_TOKEN:
        from app.services.telegram_service import telegram_service
        await telegram_service.start()
        logger.success("Telegram bot started")

    logger.success("GATOR PRO ready → http://0.0.0.0:{}", settings.BACKEND_PORT)
    logger.info("─" * 60)

    yield

    # Shutdown
    logger.info("GATOR PRO shutting down...")
    await engine.dispose()


# ─── FastAPI Application ─────────────────────────────────────
app = FastAPI(
    title="GATOR PRO Enterprise",
    description="Banking-grade Penetration Testing Platform",
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ─── Middleware ───────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # в production ограничь конкретными origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ─── API Routers ─────────────────────────────────────────────
API_PREFIX = "/api/v1"

app.include_router(router_auth.router,        prefix=API_PREFIX, tags=["Auth"])
app.include_router(router_scans.router,       prefix=API_PREFIX, tags=["Scans"])
app.include_router(router_findings.router,    prefix=API_PREFIX, tags=["Findings"])
app.include_router(router_engagements.router, prefix=API_PREFIX, tags=["Engagements"])
app.include_router(router_reports.router,     prefix=API_PREFIX, tags=["Reports"])
app.include_router(router_dashboard.router,   prefix=API_PREFIX, tags=["Dashboard"])
app.include_router(router_tools.router,       prefix=API_PREFIX, tags=["Tools"])
app.include_router(router_ws.router,          prefix="/ws",       tags=["WebSocket"])


# ─── Health & Status ─────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return {"service": "GATOR PRO Enterprise", "version": settings.VERSION, "status": "running"}


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "healthy", "version": settings.VERSION}


@app.get("/api/v1/status")
async def status():
    """Full system status — backend, DB, Redis, tools."""
    from app.utils.tool_checker import check_all_tools
    from app.core.database import check_db_connection
    from app.core.redis import check_redis_connection

    db_ok = await check_db_connection()
    redis_ok = await check_redis_connection()
    tools = await check_all_tools()

    return {
        "version": settings.VERSION,
        "status": "operational" if db_ok and redis_ok else "degraded",
        "services": {
            "database": "ok" if db_ok else "error",
            "redis": "ok" if redis_ok else "error",
        },
        "tools": tools,
        "features": {
            "telegram_alerts": bool(settings.TELEGRAM_BOT_TOKEN),
            "nvd_cve_api": bool(settings.NVD_API_KEY),
            "scheduled_scans": True,
        }
    }


# ─── Global exception handler ────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("Unhandled exception: {} — {}", type(exc).__name__, str(exc))
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc) if settings.ENVIRONMENT == "development" else "Contact administrator"}
    )
