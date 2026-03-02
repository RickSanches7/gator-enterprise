"""
GATOR PRO Enterprise — Telegram Alert Bot
══════════════════════════════════════════
Real-time security alerts via Telegram:
  • Critical finding alerts (CVSS ≥ 9.0)
  • High finding alerts (CVSS ≥ 7.0)
  • Scan completion summary
  • PCI DSS / SWIFT compliance failures
  • Daily digest of all active scans
  • Formatted messages with emoji severity icons
"""

import json
import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Optional


SEVERITY_EMOJI = {
    "critical": "🚨",
    "high":     "⚠️",
    "medium":   "🔶",
    "low":      "🔷",
    "info":     "ℹ️",
}

SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
}


class TelegramBot:
    """Telegram notification bot for GATOR PRO alerts."""

    def __init__(self, bot_token: str, chat_id: str):
        self.token   = bot_token
        self.chat_id = chat_id
        self.api     = f"https://api.telegram.org/bot{bot_token}"

    def send(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send a message to the configured chat."""
        if not self.token or not self.chat_id:
            return False
        try:
            url  = f"{self.api}/sendMessage"
            data = json.dumps({
                "chat_id":    self.chat_id,
                "text":       text[:4096],
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False

    def send_file(self, path: str, caption: str = "") -> bool:
        """Send a document file."""
        if not self.token or not self.chat_id:
            return False
        try:
            import os
            with open(path, "rb") as f:
                file_data = f.read()
            filename = os.path.basename(path)
            boundary = b"----GatorBoundary"
            body = (
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="chat_id"\r\n\r\n' +
                self.chat_id.encode() + b"\r\n"
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="document"; filename="' +
                filename.encode() + b'"\r\n' +
                b"Content-Type: application/octet-stream\r\n\r\n" +
                file_data + b"\r\n"
                b"--" + boundary + b"--\r\n"
            )
            if caption:
                body = (
                    b"--" + boundary + b"\r\n"
                    b'Content-Disposition: form-data; name="caption"\r\n\r\n' +
                    caption[:1024].encode() + b"\r\n" + body
                )
            req = urllib.request.Request(
                f"{self.api}/sendDocument", data=body, method="POST")
            req.add_header("Content-Type",
                f"multipart/form-data; boundary={boundary.decode()}")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ─── Formatted Alerts ─────────────────────────────────────

    def alert_critical_finding(self, finding: dict, target: str, scan_id: str) -> bool:
        """Send critical/high finding alert."""
        sev   = finding.get("severity","info")
        cvss  = finding.get("cvss", 0)
        title = finding.get("title","")
        host  = finding.get("host","")
        url   = finding.get("url","")
        owasp = finding.get("owasp_category","")
        rec   = finding.get("recommendation","")[:300]
        emoji = SEVERITY_EMOJI.get(sev, "🔶")

        msg = (
            f"{emoji} <b>GATOR PRO — {sev.upper()} FINDING</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"📋 <b>Scan ID:</b> <code>{scan_id}</code>\n\n"
            f"<b>🔍 {title}</b>\n\n"
            f"📊 <b>CVSS:</b> {cvss} | <b>Severity:</b> {sev.upper()}\n"
            f"🌐 <b>Host:</b> <code>{host}</code>\n"
        )
        if url:
            msg += f"🔗 <b>URL:</b> <code>{url[:100]}</code>\n"
        if owasp:
            msg += f"📚 <b>OWASP:</b> {owasp}\n"
        if rec:
            msg += f"\n💡 <b>Fix:</b> {rec[:200]}\n"
        msg += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        return self.send(msg)

    def alert_scan_started(self, target: str, scan_id: str, scan_type: str) -> bool:
        msg = (
            f"🚀 <b>GATOR PRO — Scan Started</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"🔬 <b>Type:</b> {scan_type}\n"
            f"📋 <b>Scan ID:</b> <code>{scan_id}</code>\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"🔄 Scan in progress... You will receive alerts for critical findings."
        )
        return self.send(msg)

    def alert_scan_complete(self, scan_data: dict) -> bool:
        target   = scan_data.get("target","")
        scan_id  = str(scan_data.get("id",""))
        duration = scan_data.get("duration_seconds", 0)
        findings = scan_data.get("findings", [])
        sev_counts = {s: len([f for f in findings if f.get("severity")==s])
                      for s in ("critical","high","medium","low","info")}
        pci_fail = scan_data.get("pci_fail_count", 0)

        risk_icon = "🔴" if sev_counts["critical"] else ("🟠" if sev_counts["high"] else "🟡")

        mins = duration // 60
        secs = duration % 60

        msg = (
            f"✅ <b>GATOR PRO — Scan Complete</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"📋 <b>Scan ID:</b> <code>{scan_id}</code>\n"
            f"⏱ <b>Duration:</b> {mins}m {secs}s\n\n"
            f"{risk_icon} <b>Findings Summary:</b>\n"
            f"  🚨 Critical: {sev_counts['critical']}\n"
            f"  ⚠️  High:    {sev_counts['high']}\n"
            f"  🔶 Medium:  {sev_counts['medium']}\n"
            f"  🔷 Low:     {sev_counts['low']}\n"
            f"  ℹ️  Info:   {sev_counts['info']}\n"
            f"  <b>Total:   {len(findings)}</b>\n"
        )
        if pci_fail:
            msg += f"\n❌ <b>PCI DSS Failures:</b> {pci_fail}\n"

        # Top 3 critical findings
        top_critical = [f for f in findings if f.get("severity") == "critical"][:3]
        if top_critical:
            msg += "\n🔴 <b>Top Critical:</b>\n"
            for f in top_critical:
                msg += f"  • {f.get('title','')[:60]}\n"

        msg += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        return self.send(msg)

    def alert_pci_fail(self, requirement: str, control: str,
                       detail: str, target: str) -> bool:
        msg = (
            f"❌ <b>PCI DSS COMPLIANCE FAILURE</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"📋 <b>Requirement:</b> {requirement}\n"
            f"🔍 <b>Control:</b> {control}\n"
            f"📝 <b>Detail:</b> {detail[:300]}\n\n"
            f"⚠️ This finding must be remediated before PCI DSS audit.\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        return self.send(msg)

    def alert_swift_fail(self, control_id: str, name: str,
                          detail: str, target: str) -> bool:
        msg = (
            f"❌ <b>SWIFT CSCF COMPLIANCE FAILURE</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"🔐 <b>Control:</b> {control_id} — {name}\n"
            f"📝 <b>Detail:</b> {detail[:300]}\n\n"
            f"⚠️ SWIFT CSCF mandatory control failure.\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        return self.send(msg)

    def send_report_ready(self, target: str, report_path: str,
                           pdf_path: str = None) -> bool:
        msg = (
            f"📊 <b>GATOR PRO — Report Ready</b>\n"
            f"{'─'*35}\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"📄 Report generated and available for download.\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )
        sent = self.send(msg)
        if pdf_path:
            try:
                import os
                if os.path.exists(pdf_path) and os.path.getsize(pdf_path) < 20*1024*1024:
                    self.send_file(pdf_path, f"Pentest Report — {target}")
            except Exception:
                pass
        return sent

    def test_connection(self) -> bool:
        """Test bot token and chat_id validity."""
        try:
            req = urllib.request.Request(f"{self.api}/getMe")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                data = json.loads(resp.read())
                return data.get("ok", False)
        except Exception:
            return False


def get_bot() -> Optional[TelegramBot]:
    """Create bot instance from app settings."""
    try:
        from app.core.config import settings
        if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
            return TelegramBot(settings.TELEGRAM_BOT_TOKEN, settings.TELEGRAM_CHAT_ID)
    except Exception:
        pass
    return None
