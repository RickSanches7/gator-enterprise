"""
GATOR PRO — Celery Task Queue
Async scan execution with Redis broker
"""

from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

# ─── Celery App ──────────────────────────────────────────────
celery_app = Celery(
    "gator_enterprise",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.report_tasks",
        "app.tasks.alert_tasks",
    ]
)

# ─── Configuration ────────────────────────────────────────────
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Tashkent",
    enable_utc=True,

    # Queues — разделяем типы задач
    task_queues={
        "scans": {"exchange": "scans", "routing_key": "scan.*"},
        "reports": {"exchange": "reports", "routing_key": "report.*"},
        "alerts": {"exchange": "alerts", "routing_key": "alert.*"},
    },
    task_default_queue="scans",
    task_routes={
        "app.tasks.scan_tasks.*": {"queue": "scans"},
        "app.tasks.report_tasks.*": {"queue": "reports"},
        "app.tasks.alert_tasks.*": {"queue": "alerts"},
    },

    # Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,

    # Timeouts
    task_soft_time_limit=settings.SCAN_TIMEOUT_SECONDS,
    task_time_limit=settings.SCAN_TIMEOUT_SECONDS + 300,
    result_expires=86400 * 7,   # 7 days

    # Scheduled tasks (Celery Beat)
    beat_schedule={
        # Обновлять Nuclei шаблоны каждый день в 3:00
        "update-nuclei-templates": {
            "task": "app.tasks.scan_tasks.update_nuclei_templates",
            "schedule": crontab(hour=3, minute=0),
        },
        # Cleanup старых сканов каждую неделю
        "cleanup-old-scans": {
            "task": "app.tasks.scan_tasks.cleanup_old_scans",
            "schedule": crontab(hour=4, minute=0, day_of_week=0),
        },
    },
)
