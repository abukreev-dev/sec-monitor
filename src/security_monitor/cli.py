"""Public CLI; no command for applying a security fix exists."""
import argparse
import datetime as dt
import getpass
import json
import os
import pwd
import sys
import sqlite3
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__, config, deploy, engine, health, inventory, notifier, report, scanner
from .storage import Store
from .util import BusyError, MonitorError, atomic_write, digest, json_text, private_dir, redact, utcnow


def output(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parser():
    root = argparse.ArgumentParser(prog="security-monitor", description="Read-only монитор уязвимостей Linux. Исправления выполняет администратор.")
    root.add_argument("--config", type=Path, default=None, help="JSON config (до имени команды)")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("version")
    discover = sub.add_parser("discover", help="Read-only инвентаризация")
    discover.add_argument("--read-only", action="store_true", help="Совместимость: инвентаризация всегда read-only")
    discover.add_argument("--output", type=Path)
    configure = sub.add_parser("configure", help="Создать настройки без включения служб")
    configure.add_argument("--defaults", action="store_true", help="Записать значения по умолчанию без мастера")
    bootstrap = sub.add_parser("bootstrap", help="Явно загрузить проверенный Trivy; не использует APT")
    bootstrap.add_argument("--dry-run", action="store_true")
    scan = sub.add_parser("scan")
    scan.add_argument("--target", choices=["os", "apps", "wordpress", "containers", "all"], default="os")
    scan.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    feed = sub.add_parser("feeds").add_subparsers(dest="feed_action", required=True).add_parser("refresh")
    feed.add_argument("--source", choices=["kev", "wordfence", "all"], default="all")
    feed.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("status")
    hc = sub.add_parser("health")
    hc.add_argument("--record", action="store_true")
    sub.add_parser("doctor")
    rep = sub.add_parser("report")
    rep.add_argument("--format", choices=["text", "json"], default="text")
    rep.add_argument("--severity", default="P1,P2,P3")
    rep.add_argument("--open-only", action="store_true", default=True)
    rep.add_argument("--include-closed", action="store_true")
    rep.add_argument("--limit", type=int, default=50)
    ns = sub.add_parser("notifications").add_subparsers(dest="notify_action", required=True)
    for name in ("test", "flush", "retry-failed", "status"):
        ns.add_parser(name)
    sub.add_parser("digest")
    backup = sub.add_parser("backup")
    backup.add_argument("destination", type=Path)
    install = sub.add_parser("install")
    install.add_argument("--dry-run", action="store_true")
    install.add_argument("--trivy-path")
    install.add_argument("--secrets-file", type=Path)
    sub.add_parser("rollback")
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.add_argument("--purge", action="store_true")
    service = sub.add_parser("service")
    service.add_argument("action", choices=["enable", "disable", "stop", "status"])
    return root


def configure(path, cfg, noninteractive=False):
    if not noninteractive:
        if not sys.stdin.isatty():
            raise MonitorError("Мастер требует терминал; используйте configure --defaults и отредактируйте JSON")
        cfg["server_name"] = input(f"Псевдоним сервера [{cfg['server_name']}]: ").strip() or cfg["server_name"]
        cfg["timezone"] = input(f"Часовой пояс [{cfg['timezone']}]: ").strip() or cfg["timezone"]
        enabled = input("Настроить Telegram? [y/N]: ").strip().lower() in {"y", "yes", "д", "да"}
        if enabled:
            token = getpass.getpass("Telegram bot token (скрыт): ")
            chat = input("Telegram chat_id: ").strip()
            if not token or not chat:
                raise MonitorError("Нужны bot token и chat_id; конфигурация не сохранена")
            existing = config.secrets(cfg)
            existing.update(TELEGRAM_BOT_TOKEN=token, TELEGRAM_CHAT_ID=chat)
            atomic_write(cfg["secrets_file"], "\n".join(k + "=" + v for k, v in existing.items()) + "\n")
            if os.geteuid() == 0 and Path(cfg["state_dir"]) == deploy.DATA and deploy.DATA.exists():
                meta = deploy.DATA.stat()
                os.chown(cfg["secrets_file"], meta.st_uid, meta.st_gid)
            cfg["notifications_enabled"] = True
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    config.save(path, cfg)
    return {"status": "configured", "config": str(path), "notifications_enabled": cfg["notifications_enabled"], "services_started": False}


def drop_installed_privileges(cfg):
    """Root operator commands use the same unprivileged state owner as timers."""
    path = Path(cfg["state_dir"])
    if os.geteuid() == 0 and path == deploy.DATA and path.exists() and path.stat().st_uid != 0:
        user = pwd.getpwuid(path.stat().st_uid)
        if user.pw_name != "security-monitor":
            raise MonitorError("Некорректный владелец установленного состояния")
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        os.environ["HOME"] = str(path)


def scheduled_scan(store, cfg, target):
    from .util import age_seconds
    filtered = dict(cfg)
    seconds = {"apps": 12 * 3600, "containers": 24 * 3600, "wordpress": 3600}
    for kind in seconds:
        filtered[kind] = []
        for item in cfg[kind]:
            row = store.db.execute("SELECT last_success FROM runs WHERE scope=?", (kind + ":" + item["name"],)).fetchone()
            previous = store.db.execute("SELECT payload FROM snapshots WHERE scope=?", (kind + ":" + item["name"],)).fetchone()
            changed = not previous or json.loads(previous[0]).get("target_config") != digest(item)
            if not row or changed or age_seconds(row[0]) >= seconds[kind]:
                filtered[kind].append(item)
    results = []
    if target in {"all", "os"}:
        row = store.db.execute("SELECT last_success FROM runs WHERE scope='os'").fetchone()
        if not row or age_seconds(row[0]) >= 6 * 3600:
            results.extend(engine.scan_targets(store, cfg, "os"))
    for kind in ("apps", "wordpress", "containers"):
        if target in {kind, "all"} and filtered[kind]:
            results.extend(engine.scan_targets(store, filtered, kind))
    return results or [{"status": "recent", "note": "Интервалы проверок ещё не истекли"}]


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    loaded_secrets = {}
    try:
        cfg = config.load(args.config)
        path = args.config or config.default_path()
        cmd = args.command
        if cmd == "version":
            print(__version__)
            return 0
        if cmd == "configure":
            output(configure(path, cfg, args.defaults))
            return 0
        if cmd == "bootstrap":
            result = scanner.bootstrap(cfg, args.dry_run)
            if not args.dry_run:
                cfg["trivy_path"] = result["destination"]
                config.save(path, cfg)
            output(result)
            return 0
        if cmd == "install":
            output(deploy.install(cfg, args.trivy_path, args.secrets_file, args.dry_run))
            return 0
        if cmd == "uninstall":
            output(deploy.uninstall(args.purge, args.dry_run))
            return 0
        if cmd == "rollback":
            output(deploy.rollback())
            return 0
        if cmd == "service":
            if args.action == "status":
                text, _ = deploy.systemctl("list-timers", "--all", "--no-pager", "security-monitor-*", check=False)
                print(text)
            else:
                output(deploy.service(args.action))
            return 0
        drop_installed_privileges(cfg)
        if cmd == "discover":
            data = inventory.discover(cfg)
            if args.output:
                atomic_write(args.output, json.dumps(data, ensure_ascii=False, indent=2))
                output({"status": "saved", "private_inventory": str(args.output)})
            else:
                output(data)
            return 0
        with Store(config.state_path(cfg)) as store:
            if cmd == "scan":
                result = scheduled_scan(store, cfg, args.target) if args.scheduled else engine.scan_targets(store, cfg, args.target)
                output(result)
                return 1 if any(r.get("status") == "error" for r in result) else 0
            if cmd == "feeds":
                loaded_secrets = config.secrets(cfg)
                sources = ["kev"] + (["wordfence"] if cfg["wordpress"] else []) if args.source == "all" else [args.source]
                result = engine.refresh_feeds(store, cfg, loaded_secrets, sources, args.scheduled)
                output(result)
                return 1 if any(r["status"] in {"error", "backoff"} for r in result) else 0
            if cmd in {"status", "health", "doctor"}:
                result = health.record_health(store, cfg) if cmd == "health" and args.record else health.evaluate(store, cfg, cmd == "doctor")
                counts = store.db.execute("SELECT priority,count(*) FROM findings WHERE remediation!='remediated_verified' GROUP BY priority").fetchall()
                result["open_component_findings"] = {r[0]: r[1] for r in counts}
                output(result)
                # Recording a degraded state is a successful health task, not a restart loop.
                return 0 if cmd == "status" or (cmd == "health" and args.record) else int(result["status"] != "ok")
            if cmd == "report":
                priorities = args.severity.split(",")
                if set(priorities) - {"P1", "P2", "P3"} or args.limit < 0:
                    raise MonitorError("Неверный фильтр приоритета/limit")
                groups = report.grouped(store, priorities, not args.include_closed)
                if args.format == "json":
                    output({"groups": groups[:args.limit] if args.limit else groups, "total_groups": len(groups),
                            "coverage": health.evaluate(store, cfg), "automatic_remediation": False})
                else:
                    print(report.text_report(groups, args.limit))
                return 0
            if cmd == "notifications":
                if args.notify_action == "status":
                    output(health.evaluate(store, cfg)["notifications"])
                    return 0
                loaded_secrets = config.secrets(cfg)
                if args.notify_action == "test":
                    identifier = notifier.send(loaded_secrets, notifier.render(cfg, {"kind": "test", "text": "Тестовое сообщение: канал работает. Обновления серверного ПО не выполняются."}, "TEST"))
                    output({"status": "accepted_by_telegram", "message_id": identifier, "read_by_user": "unknown"})
                    return 0
                if args.notify_action == "retry-failed":
                    with store.db:
                        store.db.execute("UPDATE outbox SET next_retry=NULL WHERE sent_at IS NULL")
                result = notifier.flush(store, cfg, loaded_secrets)
                output(result)
                return int(bool(result.get("failed")))
            if cmd == "digest":
                groups = report.grouped(store)
                counts = {}
                for g in groups:
                    counts[g["priority"]] = counts.get(g["priority"], 0) + 1
                date = dt.datetime.now(ZoneInfo(cfg["timezone"])).date().isoformat()
                current = health.evaluate(store, cfg)
                text = f"Группы уязвимостей: {len(groups)}; {counts}. Мониторинг: {current['status']}."
                with store.db:
                    store.queue("digest:" + date, {"kind": "digest", "scope": "monitor", "text": text})
                output({"status": "queued", "date": date})
                return 0
            if cmd == "backup":
                store.backup(args.destination)
                output({"status": "backup_verified", "destination": str(args.destination)})
                return 0
    except BusyError as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except sqlite3.Error:
        print("Ошибка SQLite: сохраните БД/WAL и проверьте backup/quick_check; состояние не считается безопасным", file=sys.stderr)
        return 2
    except (MonitorError, OSError, ValueError) as exc:
        message = str(exc) if isinstance(exc, MonitorError) else "Ошибка чтения/формата; проверьте конфигурацию и права"
        print(redact(message, loaded_secrets.values()), file=sys.stderr)
        return 2
    return 0
