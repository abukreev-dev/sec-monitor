import datetime as dt
import json
import shutil
from pathlib import Path

from . import inventory, scanner
from .util import MonitorError, age_seconds, digest, lock, utcnow, run as run_command
from .labels import label


def evaluate(store, cfg, doctor=False):
    adapters = []
    expected = [("os", 8 * 3600)]
    for kind, seconds in (("apps", 36 * 3600), ("wordpress", 2 * 3600), ("containers", 36 * 3600)):
        if cfg[kind]:
            expected.extend((kind + ":" + i["name"], seconds) for i in cfg[kind])
        elif kind != 'containers' or not cfg.get('docker_monitor'):
            adapters.append({"name": kind, "status": "not_configured", "note": "Нет настроенных областей; покрытие не заявлено"})
    dynamic_scopes = set()
    if cfg.get('docker_monitor'):
        from .containers import scope_name
        discovery = store.meta('docker-inventory') or {}
        images = discovery.get('images', [])
        pending, failed, stale, details = 0, 0, 0, []
        for item in images:
            scope = 'containers:' + scope_name(item['image_id'])
            dynamic_scopes.add(scope)
            row = store.db.execute('SELECT status,last_success FROM runs WHERE scope=?', (scope,)).fetchone()
            if row and row['status'] == 'error':
                failed += 1
            elif not row or not row['last_success']:
                pending += 1
            elif age_seconds(row['last_success']) > 48 * 3600:
                stale += 1
            details.append({'image_id': item['image_id'], 'containers': [c['name'] for c in item['containers']],
                            'status': row['status'] if row else 'not_scanned', 'last_success': row['last_success'] if row else None})
        discovery_age = age_seconds(discovery.get('observed_at'))
        status = 'not_scanned' if not discovery else 'stale' if discovery_age > 3 * 3600 or stale else 'error' if failed else 'not_scanned' if pending else 'fresh'
        adapters.append({'name': 'docker', 'status': status, 'images': len(images), 'pending': pending,
                         'failed': failed, 'stale': stale, 'last_inventory': discovery.get('observed_at'), 'details': details,
                         'note': 'Проверяются образы; writable layers и volumes не входят в охват'})
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
                if scope == "os":
                    adapters[-1]["runtime"] = {"running_kernel": data.get("running_kernel"),
                                               "reboot_required": data.get("reboot_required"),
                                               "observed_at": data.get("observed_at")}
    configured_scopes = {scope for scope, _ in expected} | dynamic_scopes
    for row in store.db.execute("SELECT scope,last_success FROM runs"):
        if row["scope"] not in configured_scopes and not (cfg.get('docker_monitor') and row['scope'].startswith('containers:docker-')):
            count = store.db.execute("SELECT count(*) FROM findings WHERE scope=? AND remediation!='remediated_verified'", (row["scope"],)).fetchone()[0]
            adapters.append({"name": row["scope"], "status": "disabled_with_open_findings" if count else "disabled",
                             "last_success": row["last_success"], "findings": count,
                             "note": "Область исключена из конфигурации; это не устранение находок"})
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
        try:
            managed = Path("/etc/security-monitor/.managed").exists()
        except OSError:
            managed = False
        if managed and checks["systemd_available"]:
            try:
                value, _ = run_command(["systemctl", "show", "security-monitor-scan.service", "--property=Result", "--value"], timeout=5)
                checks["last_scan_unit_result"] = value.strip()
                if value.strip() not in {"", "success"}:
                    adapters.append({"name": "scheduler:scan", "status": "error", "error": "systemd job: " + value.strip()})
            except MonitorError:
                checks["last_scan_unit_result"] = "unknown"
        if checks["free_disk_bytes"] < 3 * 1024**3:
            warnings.append("Свободного места меньше 3 GiB; обновление DB может не поместиться")
    degraded = status["status"] == "unsupported" or any(a["status"] in {"error", "stale", "not_scanned", "not_loaded", "disabled_with_open_findings"} for a in adapters)
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
        store.maintenance()
        previous = store.meta("health-statuses", {})
        current = {a["name"]: a["status"] for a in report["adapters"]}
        with store.db:
            os_adapter = next((a for a in report["adapters"] if a["name"] == "os"), None)
            last_success = os_adapter.get("last_success") if os_adapter else None
            os_overdue = not last_success or age_seconds(last_success) > 8 * 3600
            alerted = store.meta("os-monitor-alerted", False)
            if os_overdue and not alerted:
                reason = (os_adapter or {}).get("error") or "нет свежего успешного сканирования"
                store.queue("os-monitor:" + digest(["overdue", utcnow()]),
                            {"kind": "health", "scope": "os", "text": "Нет свежего успешного сканирования ОС за последние 8 часов: " + reason + ". Нужна диагностика монитора."}, "SYSTEM")
                store.set_meta("os-monitor-alerted", True)
            elif not os_overdue and alerted and os_adapter and os_adapter["status"] == "fresh":
                store.queue("os-monitor:" + digest(["recovered", utcnow()]),
                            {"kind": "health", "scope": "os", "text": "Проверка ОС восстановлена, данные снова свежие. Действия не требуются."}, "SYSTEM")
                store.set_meta("os-monitor-alerted", False)
            for name, status in current.items():
                if name in {"os", "scheduler:scan"}:
                    continue
                if status != previous.get(name) and status not in {"not_configured"}:
                    text = "Состояние проверки: " + label(status)
                    if name == 'docker':
                        item = next(a for a in report['adapters'] if a['name'] == 'docker')
                        if status == 'not_scanned' and item['images']:
                            text = f"Первичная проверка образов продолжается: осталось {item['pending']} из {item['images']}. Действия не требуются."
                        elif status == 'not_scanned':
                            text = 'Инвентарь Docker ещё не получен; монитор выполнит проверку автоматически.'
                        elif status == 'fresh':
                            text = f"Проверка образов завершена: актуальны все {item['images']}."
                        elif status == 'error':
                            text = f"Не удалось проверить образов: {item['failed']}. Подробности: security-monitor doctor."
                        elif status == 'stale':
                            text = 'Инвентарь Docker или результаты проверки устарели. Подробности: security-monitor doctor.'
                    store.queue("health:" + digest([name, status, utcnow()]),
                                {"kind": "health", "scope": name, "text": text}, "SYSTEM")
            store.set_meta("health-statuses", current)
        return report
