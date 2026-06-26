import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import HardwareInfo, ScanResult, Software


def _try_get(d: dict[str, Any], *keys: str) -> Any | None:
    for key in keys:
        val = d.get(key)
        if val is not None:
            return val
    return None


def _try_get_str(d: dict[str, Any], *keys: str) -> str | None:
    val = _try_get(d, *keys)
    return str(val) if val is not None else None


def _try_get_float(d: dict[str, Any], *keys: str) -> float | None:
    val = _try_get(d, *keys)
    if val is not None:
        try:
            return float(val)
        except (ValueError, TypeError):
            return None
    return None


def _try_get_int(d: dict[str, Any], *keys: str) -> int | None:
    val = _try_get(d, *keys)
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            return None
    return None


def _parse_disk_info(disk_info: Any) -> tuple[float | None, float | None]:
    if isinstance(disk_info, dict):
        total = _try_get_float(disk_info, "total_gb", "total")
        used_pct = _try_get_float(disk_info, "used_percent", "used_pct")
        return total, used_pct
    if isinstance(disk_info, str):
        parts = disk_info.split()
        if len(parts) >= 3:
            try:
                total_str = parts[0].rstrip("G")
                used_str = parts[2].rstrip("%")
                return float(total_str), float(used_str)
            except (ValueError, IndexError):
                pass
    return None, None


def flatten_win_updates_result(raw_updates: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for _guid, update in raw_updates.items():
        if not isinstance(update, dict):
            continue
        kb_list = update.get("kb") or []
        kb_raw = kb_list[0] if kb_list else None
        if not kb_raw:
            continue
        kb_str = str(kb_raw).strip()
        kb_id = f"KB{kb_str}" if not kb_str.startswith("KB") else kb_str

        categories = update.get("categories") or []
        if isinstance(categories, list):
            cat_strs = [str(c) for c in categories]
        else:
            cat_strs = [str(categories)]

        result.append({
            "kb_id": kb_id,
            "title": update.get("title", ""),
            "severity": update.get("severity", "Important"),
            "categories": cat_strs,
            "installed": bool(update.get("installed", False)),
        })
    return result


def parse_inventory_data(scan: ScanResult, db: Session) -> None:
    raw_output = scan.raw_output or {}
    inventory_data: dict[str, Any] | None = raw_output.get("inventory_data")
    if not inventory_data or not isinstance(inventory_data, dict):
        return

    os_version = _try_get_str(inventory_data, "os_version")
    os_architecture = _try_get_str(inventory_data, "os_architecture")
    cpu_model = _try_get_str(inventory_data, "cpu_model")
    cpu_cores = _try_get_int(inventory_data, "cpu_cores")
    ram_total_gb = _try_get_float(inventory_data, "ram_total_gb")
    ram_used_percent = _try_get_float(inventory_data, "ram_used_percent")

    disk_info_raw = inventory_data.get("disk_info")
    disk_total_gb, disk_used_percent = _parse_disk_info(disk_info_raw)

    packages_data = inventory_data.get("packages", [])

    existing_hw = (
        db.query(HardwareInfo)
        .filter(HardwareInfo.host_id == scan.host_id)
        .first()
    )

    if any([cpu_model, cpu_cores, ram_total_gb, ram_used_percent, disk_total_gb, disk_used_percent]):
        hw_data = {
            "cpu_model": cpu_model or existing_hw.cpu_model if existing_hw else cpu_model,
            "cpu_cores": cpu_cores or existing_hw.cpu_cores if existing_hw else cpu_cores,
            "ram_total_gb": ram_total_gb or existing_hw.ram_total_gb if existing_hw else ram_total_gb,
            "ram_used_percent": ram_used_percent or existing_hw.ram_used_percent if existing_hw else ram_used_percent,
            "disk_total_gb": disk_total_gb or existing_hw.disk_total_gb if existing_hw else disk_total_gb,
            "disk_used_percent": disk_used_percent or existing_hw.disk_used_percent if existing_hw else disk_used_percent,
            "updated_at": datetime.utcnow(),
        }
        hw_data = {k: v for k, v in hw_data.items() if v is not None}

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

    if os_version or os_architecture:
        host = scan.host
        if host:
            if os_version:
                host.os_version = os_version
            if os_architecture:
                host.os_architecture = os_architecture

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
