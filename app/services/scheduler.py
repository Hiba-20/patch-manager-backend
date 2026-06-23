import os
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.models import Host, PatchDeployment, PatchStatus
from app.services.ansible_service import normalize_scan_result, run_online_deploy, run_online_scan

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
                os_str = host.os_type.value.lower()
                is_linux = os_str.startswith("linux")
                host_limit = None if is_linux else host.hostname

                result = run_online_scan(str(host.id), host_limit=host_limit, os_type=os_str)
                if result["rc"] != 0:
                    logger.error(
                        "[scheduler] scan failed for %s: rc=%s",
                        host.hostname, result["rc"],
                    )
                    continue

                flat = normalize_scan_result(result, os_str)
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


def execute_scheduled_deployments():
    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        deps = (
            db.query(PatchDeployment)
            .filter(PatchDeployment.status == PatchStatus.APPROVED)
            .filter(PatchDeployment.scheduled_at <= now)
            .all()
        )
        logger.info(
            "[executor] checking %d APPROVED deployments (now=%s)",
            len(deps), now.isoformat(),
        )
        for dep in deps:
            host = dep.host
            if not host:
                logger.warning("[executor] dep %s has no host, skipping", dep.id)
                continue
            os_str = host.os_type.value.lower()
            logger.info(
                "[executor] executing scheduled %s on %s "
                "(scheduled_at=%s, now=%s)",
                dep.patch.name, host.hostname,
                dep.scheduled_at.isoformat() if dep.scheduled_at else "N/A",
                now.isoformat(),
            )
            dep.status = PatchStatus.IN_PROGRESS
            dep.started_at = datetime.utcnow()
            db.commit()

            ansible_result = run_online_deploy(
                str(host.id), dep.patch.name, False, os_type=os_str,
            )

            dep.finished_at = datetime.utcnow()
            dep.status = (
                PatchStatus.SUCCESS if ansible_result["rc"] == 0 else PatchStatus.FAILED
            )
            dep.reboot_required = bool(ansible_result.get("reboot_required", False))
            dep.logs = str(ansible_result.get("events", []))
            if dep.status == PatchStatus.SUCCESS:
                host.cached_scan_result = None
                host.cached_scan_at = None
            db.commit()
            logger.info(
                "[executor] %s finished: %s (rc=%s)",
                dep.patch.name, dep.status, ansible_result["rc"],
            )
    except Exception as exc:
        logger.error("[executor] error: %s", exc)
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
    scheduler.add_job(
        execute_scheduled_deployments,
        trigger=IntervalTrigger(seconds=30),
        id="deployment_executor",
        replace_existing=True,
        max_instances=3,
    )
    scheduler.start()
    logger.info(
        "Compliance scan scheduler started (daily @ %02d:%02d Africa/Casablanca)",
        SCHEDULER_HOUR, SCHEDULER_MINUTE,
    )
    logger.info("Deployment executor started (polling every 30s)")


def stop_scheduler():
    scheduler.shutdown(wait=False)
    logger.info("Compliance scan scheduler stopped")
