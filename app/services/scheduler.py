import os
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.models import Host, OSType
from app.services.ansible_service import run_online_scan
from app.services.scan_parser import flatten_win_updates_result

load_dotenv()

logger = logging.getLogger("scheduler")
scheduler = BackgroundScheduler(timezone="Africa/Casablanca")

SCHEDULER_HOUR = int(os.getenv("SCHEDULER_HOUR", "2"))
SCHEDULER_MINUTE = int(os.getenv("SCHEDULER_MINUTE", "0"))


def scheduled_scan_all_hosts():
    db: Session = SessionLocal()
    try:
        hosts = db.query(Host).all()
        for host in hosts:
            try:
                result = run_online_scan(str(host.id), host_limit=host.hostname)
                if result["rc"] != 0:
                    logger.error(
                        "[scheduler] scan failed for %s: rc=%s",
                        host.hostname, result["rc"],
                    )
                    continue

                raw = result.get("missing_updates", {}) or {}
                flat = flatten_win_updates_result(raw)
                host.cached_scan_result = {"available_updates": flat}
                host.cached_scan_at = datetime.utcnow()
                host.last_seen = datetime.utcnow()
                db.add(host)
                db.commit()
                logger.info(
                    "[scheduler] scanned %s: %d missing updates",
                    host.hostname, len(flat),
                )
            except Exception as exc:
                logger.error("[scheduler] scan failed for %s: %s", host.hostname, exc)
                db.rollback()
    finally:
        db.close()


def start_scheduler():
    scheduler.add_job(
        scheduled_scan_all_hosts,
        trigger=CronTrigger(hour=SCHEDULER_HOUR, minute=SCHEDULER_MINUTE),
        id="daily_compliance_scan",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
    logger.info(
        "Compliance scan scheduler started (daily @ %02d:%02d Africa/Casablanca)",
        SCHEDULER_HOUR, SCHEDULER_MINUTE,
    )


def stop_scheduler():
    scheduler.shutdown(wait=False)
    logger.info("Compliance scan scheduler stopped")
