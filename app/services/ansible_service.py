import os
import platform
from pathlib import Path
from typing import Any

import ansible_runner

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PLAYBOOK = BASE_DIR / "ansible/playbooks/collect_inventory.yml"
INVENTORY = BASE_DIR / "ansible/inventory/hosts.ini"


def _resolve_limit(os_type: str) -> str:
    normalized = os_type.lower()
    if normalized in ("linux", "linux_debian", "linux_rhel", "linux_other"):
        return "linux"
    if normalized == "windows":
        return "windows"
    raise ValueError(f"Unsupported os_type: {os_type}")


def _extract_inventory_data(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in events:
        if event.get("event") != "runner_on_ok":
            continue
        event_data = event.get("event_data", {})
        if event_data.get("task") != "Return inventory data":
            continue
        res = event_data.get("res", {})
        if isinstance(res.get("inventory_data"), dict):
            return res["inventory_data"]
    return None


def _collect_events(runner: ansible_runner.Runner) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event in runner.events:
        events.append(dict(event))
    return events


def run_inventory_playbook(host_id: str, os_type: str) -> dict[str, Any]:
    if platform.system() == "Darwin":
        os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"

    limit = _resolve_limit(os_type)

    runner = ansible_runner.run(
        private_data_dir=str(BASE_DIR),
        playbook=str(PLAYBOOK),
        inventory=str(INVENTORY),
        limit=limit,
        ident=f"inventory-{host_id}",
    )

    events = _collect_events(runner)
    inventory_data = _extract_inventory_data(events)

    return {
        "status": runner.status,
        "rc": runner.rc,
        "inventory_data": inventory_data,
        "events": events,
    }
