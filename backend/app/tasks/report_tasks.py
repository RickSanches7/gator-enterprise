from app.core.celery_app import celery_app
from app.services.report_generator import generate_report
import logging
logger = logging.getLogger(__name__)

@celery_app.task(name="tasks.generate_report", bind=True)
def generate_report_task(self, scan_data: dict, output_dir: str = "/app/reports/output",
                         telegram_token: str = None, telegram_chat_id: str = None):
    try:
        return generate_report(scan_data, output_dir, telegram_token, telegram_chat_id)
    except Exception as exc:
        logger.error(f"Report generation failed: {exc}")
        raise self.retry(exc=exc, countdown=30, max_retries=3)
