import datetime as dt
import json
import shutil
from pathlib import Path

from . import inventory, scanner
from .util import MonitorError, age_seconds, digest, lock, utcnow, run as run_command


def evaluate(store, cfg, doctor=False):
    adapters = []
    expected = [("os", 8 * 3600)]
    for kind, seconds in (("apps", 36 * 3600), ("wordpress", 2 * 3600), ("containers", 36 * 3600)):
        if cfg[kind]:
            expected.extend((kind + ":" + i["name"], seconds) for i in cfg[kind])
        else:
            adapters.append({"name": kind, "status": "not_configured", "note": "Нет настроенных областей; покрытие не заявлено"})
    for scope, max_age in expected:
        run = store.db.execute("SELECT * FROM runs WHERE scope=?", (scope,)).fetchone()
        if not run:
            adapters.append({"name": scope, "status": "not_scanned", "last_success": None})
        else:
            status = run["status"]
            if status == "fresh" and age_seconds(run["last_success"]) > max_age:
                status = "stale"
            adapters.append({"name": scope, "status": status, "last_success": run["last_success"],
                             "duration": run["duration"], "findings": run["count"], "error": run["error"]})
            snap = store.db.execute("SELECT payload FROM snapshots WHERE scope=?", (scope,)).fetchone()
            if snap:
                data = json.loads(snap[0])
                gaps = data.get("limitations", [])
                packages = data.get("packages", {})
                unknown = sum(p.get("origin") not in {"Ubuntu", "Debian"} for p in packages.values())
                adapters[-1]["coverage"] = {"mode": "partial" if gaps or unknown else "selected_components",
                                             "origin_gaps": unknown, "limitations": gaps}
    sources = ["kev"] + (["wordfence"] if cfg["wordpress"] else [])
    for name in sources:
        row = store.db.execute("SELECT * FROM feeds WHERE name=?", (name,)).fetchone()
        status = "not_loaded" if not row else row["status"]
        if row and status == "fresh" and age_seconds(row["last_success"]) > cfg["feed_max_age_hours"] * 3600:
            status = "stale"
        adapters.append({"name": name, "status": status, "last_success": row["last_success"] if row else None,
                         "error": row["error"] if row else None})
    outbox = dict(store.db.execute("""SELECT count(*) pending, sum(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) failed
                                  FROM outbox WHERE sent_at IS NULL""").fetchone())
    status = inventory.platform_status()
    warnings = []
    if status["status"] != "tested":
        warnings.append("Платформа " + status["status"] + ": runtime-приёмка есть только для Ubuntu 24.04 x86_64")
    if not cfg["notifications_enabled"]:
        warnings.append("Telegram выключен: уведомления сохранены в локальной очереди")
    checks = {}
    if doctor:
        try:
            scanner.executable(cfg)
            checks["trivy"] = "ok"
        except MonitorError as exc:
            checks["trivy"] = str(exc)
        checks["sqlite"] = store.db.execute("PRAGMA quick_check").fetchone()[0]
        checks["free_disk_bytes"] = shutil.disk_usage(store.directory).free
        checks["systemd_available"] = bool(shutil.which("systemctl"))
        if Path("/etc/security-monitor/.managed").exists() and checks["systemd_available"]:
            try:
                value, _ = run_command(["systemctl", "show", "security-monitor-scan.service", "--property=Result", "--value"], timeout=5)
                checks["last_scan_unit_result"] = value.strip()
                if value.strip() not in {"", "success"}:
                    adapters.append({"name": "scheduler:scan", "status": "error", "error": "systemd job: " + value.strip()})
            except MonitorError:
                checks["last_scan_unit_result"] = "unknown"
        if checks["free_disk_bytes"] < 3 * 1024**3:
            warnings.append("Свободного места меньше 3 GiB; обновление DB может не поместиться")
    degraded = any(a["status"] in {"error", "stale", "not_scanned", "not_loaded"} for a in adapters)
    degraded |= bool(outbox["failed"])
    if doctor:
        degraded |= checks.get("trivy") != "ok" or checks.get("sqlite") != "ok"
    return {"status": "degraded" if degraded else "ok", "platform": status, "adapters": adapters,
            "notifications": outbox, "warnings": warnings, "checks": checks}


def record_health(store, cfg):
    from .engine import observe_updates
    with lock(store.directory / "health.lock"):
        try:
            if inventory.platform_status()["status"] != "unsupported":
                observe_updates(store, cfg)
        except MonitorError:
            with store.db:
                store.set_meta("package-observation-error", "Не удалось проверить APT availability")
        report = evaluate(store, cfg, doctor=True)
        previous = store.meta("health-statuses", {})
        current = {a["name"]: a["status"] for a in report["adapters"]}
        with store.db:
            for name, status in current.items():
                if status != previous.get(name) and status not in {"not_configured"}:
                    store.queue("health:" + digest([name, status, utcnow()]),
                                {"kind": "health", "scope": name, "text": "Состояние проверки: " + status}, "SYSTEM")
            store.set_meta("health-statuses", current)
        return report
