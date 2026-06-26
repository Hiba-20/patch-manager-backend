import multiprocessing
import os
import platform
import tempfile
import uuid
from pathlib import Path
from typing import Any

import ansible_runner

from app.models.models import Host
from app.services.scan_parser import flatten_win_updates_result

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


def _build_host_inventory(host: Host | None) -> str | None:
    if host is None:
        return None
    is_windows = host.os_type.value.lower() == "windows"
    ansible_host = host.ip_address or host.hostname

    if is_windows:
        winrm_user = host.winrm_user or os.getenv("WINRM_USER") or ""
        winrm_password = host.winrm_password or os.getenv("WINRM_PASSWORD") or ""
        if winrm_user and winrm_password:
            return (
                f"[windows]\n"
                f"{host.hostname} ansible_host={ansible_host} "
                f"ansible_user={winrm_user} ansible_password={winrm_password}\n"
                f"[windows:vars]\n"
                f"ansible_connection=winrm\n"
                f"ansible_port=5985\n"
                f"ansible_winrm_scheme=http\n"
                f"ansible_winrm_transport=basic\n"
                f"ansible_winrm_server_cert_validation=ignore\n"
                f"ansible_winrm_operation_timeout_sec=90\n"
                f"ansible_winrm_read_timeout_sec=120\n"
                f"ansible_become_method=runas\n"
                f"ansible_become_user=SYSTEM\n"
                f"ansible_become_password={winrm_password}\n"
            )
    else:
        ssh_user = host.ssh_user or os.getenv("SSH_USER") or "root"
        ssh_password = host.ssh_password or os.getenv("SSH_PASSWORD") or ""
        ssh_key_path = os.getenv("SSH_KEY_PATH", "")
        extra_vars = f"ansible_user={ssh_user}"
        if ssh_password:
            extra_vars += f" ansible_password={ssh_password}"
            extra_vars += f" ansible_become_password={ssh_password}"
        if ssh_key_path:
            extra_vars += f" ansible_ssh_private_key_file={ssh_key_path}"
        return (
            f"[linux]\n"
            f"{host.hostname} ansible_host={ansible_host} "
            f"{extra_vars}\n"
            f"[linux:vars]\n"
            f"ansible_connection=ssh\n"
        )
    return None


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


def normalize_scan_result(result: dict, os_type: str) -> list[dict]:
    if os_type.lower().startswith("linux"):
        raw = result.get("upgradable_packages", []) or []
        return [
            {
                "kb_id": pkg["package"],
                "title": f"{pkg.get('available_version', '')} (installed: {pkg.get('installed_version', '')})",
                "severity": "Important",
                "categories": ["Linux"],
                "installed": False,
            }
            for pkg in raw
        ]
    raw = result.get("missing_updates", {}) or {}
    return flatten_win_updates_result(raw)


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


def _run_playbook_target(
    playbook: Path,
    limit: str,
    ident: str,
    extra_vars: dict[str, Any] | None,
    inventory_path: str,
    result_queue: multiprocessing.Queue,
) -> None:
    runner = ansible_runner.run(
        private_data_dir=str(BASE_DIR),
        playbook=str(playbook),
        inventory=inventory_path,
        limit=limit,
        ident=ident,
        extravars=extra_vars or {},
    )
    events = _collect_events(runner)
    result_queue.put({
        "status": runner.status,
        "rc": runner.rc,
        "events": events,
    })


def _run_playbook_sync(
    playbook: Path,
    limit: str,
    ident: str,
    extra_vars: dict[str, Any] | None = None,
    inventory_path: str | None = None,
) -> dict[str, Any]:
    runner = ansible_runner.run(
        private_data_dir=str(BASE_DIR),
        playbook=str(playbook),
        inventory=inventory_path or str(INVENTORY),
        limit=limit,
        ident=ident,
        extravars=extra_vars or {},
    )
    events = _collect_events(runner)
    return {"status": runner.status, "rc": runner.rc, "events": events}


def _run_playbook(
    playbook: Path,
    limit: str,
    ident: str,
    extra_vars: dict[str, Any] | None = None,
    inventory_content: str | None = None,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    inventory_path = str(INVENTORY)
    tmp_inventory = None
    if inventory_content:
        tmp_inventory = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
        try:
            tmp_inventory.write(inventory_content)
            tmp_inventory.flush()
            inventory_path = tmp_inventory.name
        except Exception:
            os.unlink(tmp_inventory.name)
            raise

    if platform.system() == "Darwin":
        os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
        try:
            return _run_playbook_sync(playbook, limit, ident, extra_vars, inventory_path)
        finally:
            if tmp_inventory is not None:
                try:
                    os.unlink(tmp_inventory.name)
                except OSError:
                    pass

    result_queue: multiprocessing.Queue = multiprocessing.Queue()

    process = multiprocessing.Process(
        target=_run_playbook_target,
        args=(playbook, limit, ident, extra_vars, inventory_path, result_queue),
        daemon=True,
    )
    try:
        process.start()
        process.join(timeout_seconds)

        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
            return {"status": "timeout", "rc": -1, "events": []}

        return result_queue.get_nowait()
    finally:
        if tmp_inventory is not None:
            try:
                os.unlink(tmp_inventory.name)
            except OSError:
                pass


def run_inventory_playbook(host_id: str, os_type: str, host: Host | None = None) -> dict[str, Any]:
    limit = _resolve_limit(os_type)
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        INVENTORY_PLAYBOOK, limit, f"inventory-{host_id}-{uuid.uuid4().hex[:8]}",
        inventory_content=inv_content,
    )
    inventory_data = _extract_debug_var(
        result["events"], "Return inventory data", "inventory_data"
    )
    result["inventory_data"] = inventory_data
    return result


def run_update_check(host_id: str, host: Host | None = None) -> dict[str, Any]:
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        CHECK_UPDATES_PLAYBOOK, "windows", f"update-check-{host_id}-{uuid.uuid4().hex[:8]}",
        inventory_content=inv_content,
    )
    update_data = _extract_debug_var(
        result["events"], "Return update data", "update_data"
    )
    result["update_data"] = update_data
    return result


def run_linux_scan(host_id: str, os_type: str, host: Host | None = None) -> dict[str, Any]:
    playbook = CHECK_LINUX_UPDATES_PLAYBOOK if _is_debian_like(os_type) else CHECK_LINUX_RHEL_UPDATES_PLAYBOOK
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        playbook,
        "linux",
        f"linux-scan-{host_id}-{uuid.uuid4().hex[:8]}",
        inventory_content=inv_content,
    )
    upgradable = _extract_ansible_fact(
        result["events"], "upgradable_packages"
    )
    result["upgradable_packages"] = upgradable or []
    return result


def run_linux_deploy(host_id: str, package_name: str, os_type: str, host: Host | None = None) -> dict[str, Any]:
    playbook = DEPLOY_LINUX_PATCH_PLAYBOOK if _is_debian_like(os_type) else DEPLOY_LINUX_RHEL_PATCH_PLAYBOOK
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        playbook,
        "linux",
        f"linux-deploy-{host_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"package_name": package_name},
        inventory_content=inv_content,
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


def run_online_scan(host_id: str, host_limit: str | None = None, os_type: str | None = None, host: Host | None = None) -> dict[str, Any]:
    if os_type and _is_linux(os_type):
        return run_linux_scan(host_id, os_type, host=host)
    limit = host_limit or "windows"
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        CHECK_UPDATES_ONLINE_PLAYBOOK,
        limit,
        f"online-scan-{host_id}-{uuid.uuid4().hex[:8]}",
        inventory_content=inv_content,
    )
    missing_updates = _extract_ansible_fact(
        result["events"], "missing_updates"
    )
    result["missing_updates"] = missing_updates
    return result


def run_online_deploy(host_id: str, kb_id: str, auto_reboot: bool = False, os_type: str | None = None, host: Host | None = None) -> dict[str, Any]:
    if os_type and _is_linux(os_type):
        return run_linux_deploy(host_id, kb_id, os_type, host=host)
    bare_kb = kb_id.replace("KB", "").replace("kb", "")
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        ONLINE_DEPLOY_PLAYBOOK,
        "windows",
        f"online-deploy-{host_id}-{bare_kb}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": bare_kb, "auto_reboot": auto_reboot},
        inventory_content=inv_content,
    )
    reboot_required = _extract_ansible_fact(
        result["events"], "reboot_required"
    )
    result["reboot_required"] = reboot_required
    return result


def run_deploy_patch(host_id: str, kb_id: str, host: Host | None = None) -> dict[str, Any]:
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        DEPLOY_PATCH_PLAYBOOK,
        "windows",
        f"deploy-{host_id}-{kb_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": kb_id},
        inventory_content=inv_content,
    )
    deploy_result = _extract_debug_var(
        result["events"], "Return deployment result", "deploy_result"
    )
    result["deploy_result"] = deploy_result
    return result


def run_deploy_msu(host_id: str, kb_id: str, host: Host | None = None) -> dict[str, Any]:
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        MSU_DEPLOY_PLAYBOOK,
        "windows",
        f"deploy-msu-{host_id}-{kb_id}-{uuid.uuid4().hex[:8]}",
        extra_vars={"kb_id": kb_id},
        inventory_content=inv_content,
    )
    deploy_result = _extract_debug_var(
        result["events"], "Return deployment result", "deploy_result"
    )
    result["deploy_result"] = deploy_result
    return result


def run_get_hotfix(host_id: str, host: Host | None = None) -> dict[str, Any]:
    inv_content = _build_host_inventory(host)
    result = _run_playbook(
        GET_HOTFIX_PLAYBOOK,
        "windows",
        f"hotfix-{host_id}-{uuid.uuid4().hex[:8]}",
        inventory_content=inv_content,
    )
    hotfix_json = _extract_debug_var(
        result["events"], "Return hotfix data", "msg"
    )
    result["hotfix_data"] = hotfix_json
    return result
