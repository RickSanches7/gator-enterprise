from app.core.celery_app import celery_app
import logging
logger = logging.getLogger(__name__)

@celery_app.task(name="tasks.send_alert")
def send_alert_task(message: str, token: str = None, chat_id: str = None):
    if not token or not chat_id:
        return {"status": "skipped"}
    try:
        import urllib.request, urllib.parse, json, ssl
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": message[:4096], "parse_mode": "Markdown"}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        logger.error(f"Alert failed: {e}")
        return {"status": "error", "error": str(e)}
