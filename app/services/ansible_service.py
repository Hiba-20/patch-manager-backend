import os
import platform
import uuid
from pathlib import Path
from typing import Any

import ansible_runner

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INVENTORY_PLAYBOOK = BASE_DIR / "ansible/playbooks/collect_inventory.yml"
CHECK_UPDATES_PLAYBOOK = BASE_DIR / "ansible/playbooks/check_windows_updates_offline.yml"
CHECK_UPDATES_ONLINE_PLAYBOOK = BASE_DIR / "ansible/playbooks/check_windows_updates_online.yml"
CHECK_LINUX_UPDATES_PLAYBOOK = BASE_DIR / "ansible/playbooks/check_linux_updates.yml"
CHECK_LINUX_RHEL_UPDATES_PLAYBOOK = BASE_DIR / "ansible/playbooks/check_linux_updates_rhel.yml"
DEPLOY_PATCH_PLAYBOOK = BASE_DIR / "ansible/playbooks/deploy_windows_patch_offline.yml"
MSU_DEPLOY_PLAYBOOK = BASE_DIR / "ansible/playbooks/deploy_windows_patch_msu.yml"
ONLINE_DEPLOY_PLAYBOOK = BASE_DIR / "ansible/playbooks/deploy_windows_patch_online.yml"
DEPLOY_LINUX_PATCH_PLAYBOOK = BASE_DIR / "ansible/playbooks/deploy_linux_patch.yml"
DEPLOY_LINUX_RHEL_PATCH_PLAYBOOK = BASE_DIR / "ansible/playbooks/deploy_linux_patch_rhel.yml"
GET_HOTFIX_PLAYBOOK = BASE_DIR / "ansible/playbooks/get_hotfix.yml"
INVENTORY = BASE_DIR / "ansible/inventory/hosts.ini"


def _resolve_limit(os_type: str) -> str:
    normalized = os_type.lower()
    if normalized in ("linux", "linux_debian", "linux_rhel", "linux_other"):
        return "linux"
    if normalized == "windows":
        return "windows"
    raise ValueError(f"Unsupported os_type: {os_type}")


def _is_debian_like(os_type: str) -> bool:
    return os_type.lower() in ("linux_debian", "linux")


def _is_rhel_like(os_type: str) -> bool:
    return os_type.lower() in ("linux_rhel",)


def _is_linux(os_type: str) -> bool:
    return os_type.lower() in ("linux", "linux_debian", "linux_rhel", "linux_other")


def _collect_events(runner: ansible_runner.Runner) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event in runner.events:
        events.append(dict(event))
    return events


def _extract_debug_var(
    events: list[dict[str, Any]], task_name: str, var_name: str
) -> Any | None:
    found = None
    for event in events:
        if event.get("event") != "runner_on_ok":
            continue
        event_data = event.get("event_data", {})
        if event_data.get("task") != task_name:
            continue
        res = event_data.get("res", {})
        value = res.get(var_name)
        if value is not None:
            found = value
    return found


def _extract_ansible_fact(
    events: list[dict[str, Any]], fact_name: str
) -> Any | None:
    found = None
    for event in events:
        if event.get("event") != "runner_on_ok":
            continue
        event_data = event.get("event_data", {})
        res = event_data.get("res", {})
        ansible_facts = res.get("ansible_facts", {})
        value = ansible_facts.get(fact_name)
        if value is not None:
            found = value
    return found


def _run_playbook(
    playbook: Path,
    limit: str,
    ident: str,
    extra_vars: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if platform.system() == "Darwin":
        os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"

    runner = ansible_runner.run(
        private_data_dir=str(BASE_DIR),
        playbook=str(playbook),
        inventory=str(INVENTORY),
        limit=limit,
        ident=ident,
        extravars=extra_vars or {},
    )

    events = _collect_events(runner)
    return {
        "status": runner.status,
        "rc": runner.rc,
        "events": events,
    }


def run_inventory_playbook(host_id: str, os_type: str) -> dict[str, Any]:
    limit = _resolve_limit(os_type)
    result = _run_playbook(
        INVENTORY_PLAYBOOK, limit, f"inventory-{host_id}-{uuid.uuid4().hex[:8]}"
    )
    inventory_data = _extract_debug_var(
        result["events"], "Return inventory data", "inventory_data"
    )
    result["inventory_data"] = inventory_data
    return result


def run_update_check(host_id: str) -> dict[str, Any]:
    result = _run_playbook(
        CHECK_UPDATES_PLAYBOOK, "windows", f"update-check-{host_id}-{uuid.uuid4().hex[:8]}"
    )
    update_data = _extract_debug_var(
        result["events"], "Return update data", "update_data"
    )
    result["update_data"] = update_data
    return result


def run_linux_scan(host_id: str, os_type: str) -> dict[str, Any]:
    playbook = CHECK_LINUX_UPDATES_PLAYBOOK if _is_debian_like(os_type) else CHECK_LINUX_RHEL_UPDATES_PLAYBOOK
    result = _run_playbook(
        playbook,
        "linux",
        f"linux-scan-{host_id}-{uuid.uuid4().hex[:8]}",
    )
    upgradable = _extract_ansible_fact(
        result["events"], "upgradable_packages"
    )
    result["upgradable_packages"] = upgradable or []
    return result


def run_linux_deploy(host_id: str, package_name: str, os_type: str) -> dict[str, Any]:
    playbook = DEPLOY_LINUX_PATCH_PLAYBOOK if _is_debian_like(os_type) else DEPLOY_LINUX_RHEL_PATCH_PLAYBOOK
    result = _run_playbook(
        playbook,
        "linux",
        f"linux-deploy-{host_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"package_name": package_name},
    )
    deploy_result = _extract_ansible_fact(
        result["events"], "deploy_result"
    )
    result["deploy_result"] = deploy_result
    reboot_required = _extract_ansible_fact(
        result["events"], "reboot_required"
    )
    result["reboot_required"] = reboot_required or False
    return result


def run_online_scan(host_id: str, host_limit: str | None = None, os_type: str | None = None) -> dict[str, Any]:
    if os_type and _is_linux(os_type):
        return run_linux_scan(host_id, os_type)
    limit = host_limit or "windows"
    result = _run_playbook(
        CHECK_UPDATES_ONLINE_PLAYBOOK,
        limit,
        f"online-scan-{host_id}-{uuid.uuid4().hex[:8]}",
    )
    missing_updates = _extract_ansible_fact(
        result["events"], "missing_updates"
    )
    result["missing_updates"] = missing_updates
    return result


def run_online_deploy(host_id: str, kb_id: str, auto_reboot: bool = False, os_type: str | None = None) -> dict[str, Any]:
    if os_type and _is_linux(os_type):
        return run_linux_deploy(host_id, kb_id, os_type)
    bare_kb = kb_id.replace("KB", "").replace("kb", "")
    result = _run_playbook(
        ONLINE_DEPLOY_PLAYBOOK,
        "windows",
        f"online-deploy-{host_id}-{bare_kb}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": bare_kb, "auto_reboot": auto_reboot},
    )
    reboot_required = _extract_ansible_fact(
        result["events"], "reboot_required"
    )
    result["reboot_required"] = reboot_required
    return result


def run_deploy_patch(host_id: str, kb_id: str) -> dict[str, Any]:
    result = _run_playbook(
        DEPLOY_PATCH_PLAYBOOK,
        "windows",
        f"deploy-{host_id}-{kb_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": kb_id},
    )
    deploy_result = _extract_debug_var(
        result["events"], "Return deployment result", "deploy_result"
    )
    result["deploy_result"] = deploy_result
    return result


def run_deploy_msu(host_id: str, kb_id: str) -> dict[str, Any]:
    result = _run_playbook(
        MSU_DEPLOY_PLAYBOOK,
        "windows",
        f"deploy-msu-{host_id}-{kb_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": kb_id},
    )
    deploy_result = _extract_debug_var(
        result["events"], "Return deployment result", "deploy_result"
    )
    result["deploy_result"] = deploy_result
    return result


def run_get_hotfix(host_id: str) -> dict[str, Any]:
    result = _run_playbook(
        GET_HOTFIX_PLAYBOOK,
        "windows",
        f"hotfix-{host_id}-{uuid.uuid4().hex[:8]}",
    )
    hotfix_json = _extract_debug_var(
        result["events"], "Return hotfix data", "msg"
    )
    result["hotfix_data"] = hotfix_json
    return result
