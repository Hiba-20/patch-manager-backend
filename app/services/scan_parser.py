import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HardwareInfo, ScanResult, Software


def parse_inventory_data(scan: ScanResult, db: Session) -> None:
    raw_output = scan.raw_output or {}
    inventory_data: dict[str, Any] | None = raw_output.get("inventory_data")
    if not inventory_data or not isinstance(inventory_data, dict):
        return

    os_data = inventory_data.get("os", {})
    cpu_data = inventory_data.get("cpu", {})
    ram_data = inventory_data.get("memory", {})
    disk_data = inventory_data.get("disk", {})
    packages_data = inventory_data.get("packages", [])

    existing_hw = (
        db.query(HardwareInfo)
        .filter(HardwareInfo.host_id == scan.host_id)
        .first()
    )

    if cpu_data or ram_data or disk_data:
        hw_data = {
            "cpu_model": cpu_data.get("model"),
            "cpu_cores": cpu_data.get("cores"),
            "ram_total_gb": ram_data.get("total_gb"),
            "ram_used_percent": ram_data.get("used_percent"),
            "disk_total_gb": disk_data.get("total_gb"),
            "disk_used_percent": disk_data.get("used_percent"),
            "updated_at": datetime.utcnow(),
        }

        if existing_hw:
            for key, val in hw_data.items():
                setattr(existing_hw, key, val)
            existing_hw.scan_id = scan.id
        else:
            hw = HardwareInfo(
                id=uuid.uuid4(),
                host_id=scan.host_id,
                scan_id=scan.id,
                **hw_data,
            )
            db.add(hw)

        if os_data:
            host = scan.host
            if host:
                host.os_version = os_data.get("version", host.os_version)
                host.os_architecture = os_data.get("architecture", host.os_architecture)

    if packages_data and isinstance(packages_data, list):
        existing_pkg_names = {
            s.name
            for s in db.query(Software).filter(Software.host_id == scan.host_id).all()
        }

        for pkg in packages_data:
            pkg_name = (pkg.get("name") or "").strip()
            if not pkg_name or pkg_name in existing_pkg_names:
                continue

            install_date_str = pkg.get("install_date")
            parsed_date = None
            if install_date_str:
                try:
                    parsed_date = date.fromisoformat(install_date_str)
                except (ValueError, TypeError):
                    pass

            sw = Software(
                id=uuid.uuid4(),
                host_id=scan.host_id,
                scan_id=scan.id,
                name=pkg_name,
                version=pkg.get("version"),
                vendor=pkg.get("vendor"),
                install_date=parsed_date,
                package_manager=pkg.get("package_manager"),
            )
            db.add(sw)
            existing_pkg_names.add(pkg_name)

    db.commit()
