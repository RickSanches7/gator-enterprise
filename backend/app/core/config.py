"""
GATOR PRO — Application Configuration
Loads from environment variables / .env file
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional
import os


class Settings(BaseSettings):
    # ─── Application ─────────────────────────────────────────
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = "production"
    BACKEND_PORT: int = 8000
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # ─── Database ─────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://gator:password@localhost:5432/gator_enterprise"
    DATABASE_SYNC_URL: str = "postgresql://gator:password@localhost:5432/gator_enterprise"

    # ─── Redis / Celery ───────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""

    # ─── External APIs ────────────────────────────────────────
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    NVD_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None

    # ─── Scan Settings ────────────────────────────────────────
    MAX_CONCURRENT_SCANS: int = 10
    SCAN_TIMEOUT_SECONDS: int = 3600       # 1 hour max per scan
    PORT_SCAN_TIMEOUT: float = 1.0
    HTTP_REQUEST_TIMEOUT: int = 10
    MAX_THREADS_PER_SCAN: int = 50
    NVD_RATE_LIMIT_DELAY: float = 6.0     # seconds between NVD requests (no key)

    # ─── Report Settings ─────────────────────────────────────
    REPORT_OUTPUT_DIR: str = "/app/reports/output"
    REPORT_COMPANY_NAME: str = "GATOR CyberSec Solutions"
    REPORT_COMPANY_URL: str = "gator.uz"
    REPORT_COMPANY_EMAIL: str = "GatorSupport@ya.ru"
    REPORT_COMPANY_PHONE: str = "+998 33 069-34-34"

    # ─── Security ─────────────────────────────────────────────
    CVSS_CRITICAL_THRESHOLD: float = 9.0
    CVSS_HIGH_THRESHOLD: float = 7.0
    CVSS_MEDIUM_THRESHOLD: float = 4.0

    @field_validator("CELERY_BROKER_URL", mode="before")
    @classmethod
    def set_celery_broker(cls, v, info):
        if not v:
            redis_url = info.data.get("REDIS_URL", "redis://localhost:6379/0")
            return redis_url
        return v

    @field_validator("CELERY_RESULT_BACKEND", mode="before")
    @classmethod
    def set_celery_backend(cls, v, info):
        if not v:
            redis_url = info.data.get("REDIS_URL", "redis://localhost:6379/0")
            return redis_url
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
