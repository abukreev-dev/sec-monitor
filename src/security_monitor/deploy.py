"""Explicit installation of this monitor only. Never calls APT or application services."""
import json
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

from . import __version__, config, inventory, scanner
from .util import MonitorError, atomic_write, digest, json_text, run

BASE = Path("/opt/security-monitor")
ETC = Path("/etc/security-monitor")
DATA = Path("/var/lib/security-monitor")
UNITS = Path("/etc/systemd/system")
LAUNCHER = Path("/usr/local/bin/security-monitor")
MARKER = "sec-monitor-managed-v1"
JOBS = ("scan", "feeds", "health", "notify", "digest")


def systemctl(*args, check=True):
    result = subprocess.run(["systemctl", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=90)
    if check and result.returncode:
        raise MonitorError("systemctl: операция над units монитора не завершена")
    return result.stdout.strip(), result.returncode


def assert_root():
    if os.geteuid() != 0:
        raise MonitorError("Установка/управление systemd требует root")


def unit_files(cfg):
    calendars = {"scan": "hourly", "feeds": "*-*-* *:00/15:00", "health": "*-*-* *:00/15:00",
                 "notify": "*-*-* *:*:00", "digest": "*-*-* 09:00:00 " + cfg["timezone"]}
    commands = {"scan": "scan --target all --scheduled", "feeds": "feeds refresh --source all --scheduled",
                "health": "health --record", "notify": "notifications flush", "digest": "digest"}
    files = {}
    for job in JOBS:
        on_failure = "OnFailure=security-monitor-health.service\n" if job == "scan" else ""
        hide_secrets = "InaccessiblePaths=-/etc/security-monitor/secrets.env\n" if job in {"scan", "health", "digest"} else ""
        files[f"security-monitor-{job}.service"] = f"""# {MARKER}
[Unit]
Description=Security Monitor {job} (read-only)
After=network-online.target
Wants=network-online.target
{on_failure}
[Service]
Type=oneshot
User=security-monitor
Group=security-monitor
WorkingDirectory=/var/lib/security-monitor
Environment=HOME=/var/lib/security-monitor
Environment=GOMAXPROCS=1
Environment=GOMEMLIMIT=600MiB
ExecStart=/usr/local/bin/security-monitor --config /etc/security-monitor/config.json {commands[job]}
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/security-monitor
{hide_secrets}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
CPUQuota=100%
MemoryMax=1G
MemorySwapMax=0
Nice=10
IOWeight=10
TasksMax=128
LimitFSIZE=4G
TimeoutStartSec=600
KillMode=control-group
OOMPolicy=stop
"""
        files[f"security-monitor-{job}.timer"] = f"""# {MARKER}
[Unit]
Description=Schedule Security Monitor {job}
[Timer]
OnCalendar={calendars[job]}
Persistent=true
RandomizedDelaySec={'30' if job == 'notify' else '60'}
AccuracySec=1min
Unit=security-monitor-{job}.service
[Install]
WantedBy=timers.target
"""
    return files


def plan(cfg, trivy_path=None):
    return {"code": str(BASE), "config": str(ETC / "config.json"), "state": str(DATA),
            "user": "security-monitor", "launcher": str(LAUNCHER), "units": sorted(unit_files(cfg)),
            "trivy": trivy_path or cfg["trivy_path"], "starts_timers": False,
            "system_packages_changed": False, "application_services_restarted": False,
            "network_ports_opened": False}


def owned():
    if BASE.is_symlink():
        return False
    p = BASE / ".managed"
    return p.is_file() and not p.is_symlink() and p.read_text().strip() == MARKER


def retained_owned():
    if ETC.is_symlink():
        return False
    p = ETC / ".managed"
    return p.is_file() and not p.is_symlink() and p.read_text().strip() == MARKER


def install(cfg, trivy_path=None, secrets_source=None, dry_run=False):
    status = inventory.platform_status()
    if status["status"] != "tested" and not cfg["allow_untested_os"]:
        raise MonitorError("Для timers проверена Ubuntu 24.04 x86_64; непроверенная ОС требует allow_untested_os")
    if status["status"] == "unsupported":
        raise MonitorError("Установка на этой OS не поддерживается")
    description = plan(cfg, trivy_path)
    if dry_run:
        return description
    assert_root()
    if any(p.is_symlink() for p in (BASE, ETC, DATA)):
        raise MonitorError("Каталоги установки не должны быть symlink")
    checked_secrets = None
    if secrets_source:
        if not Path(secrets_source).is_file():
            raise MonitorError("Файл секретов не найден; установка не начата")
        checked_secrets = config.secrets({**cfg, "secrets_file": str(Path(secrets_source).absolute())})
    if BASE.exists() and not owned():
        raise MonitorError("Каталог /opt/security-monitor занят; чужие файлы не изменены")
    if (ETC.exists() or DATA.exists()) and not (owned() or retained_owned()):
        raise MonitorError("Каталог конфигурации/данных занят; чужие файлы не изменены")
    if LAUNCHER.exists() and (LAUNCHER.is_symlink() or MARKER not in LAUNCHER.read_text()):
        raise MonitorError("Launcher уже существует и не принадлежит монитору")
    for name in unit_files(cfg):
        p = UNITS / name
        if p.exists() and (p.is_symlink() or MARKER not in p.read_text()):
            raise MonitorError("Имя systemd unit занято чужим файлом")
    candidate = trivy_path or cfg["trivy_path"]
    candidate = candidate if Path(candidate).is_absolute() else shutil.which(candidate)
    if not candidate or not Path(candidate).is_file():
        raise MonitorError("Trivy отсутствует; сначала bootstrap")
    if Path(candidate).stat().st_size > 250 * 1024 * 1024:
        raise MonitorError("Неожиданный размер бинарника Trivy")
    binary_bytes = Path(candidate).read_bytes()
    if __import__("hashlib").sha256(binary_bytes).hexdigest() != scanner.BINARY_SHA256:
        raise MonitorError("Trivy не прошёл SHA256; чужой бинарник от root не запускается")
    source = Path(__file__).resolve().parents[2]
    if not (source / "LICENSE").is_file():
        raise MonitorError("Исходная поставка неполна: отсутствует LICENSE")
    fingerprint = digest([(str(p.relative_to(source)), __import__("hashlib").sha256(p.read_bytes()).hexdigest())
                          for p in sorted((source / "src/security_monitor").glob("*")) if p.is_file()])[:12]
    release_name = __version__ + "-" + fingerprint
    release = BASE / "releases" / release_name
    try:
        user = pwd.getpwnam("security-monitor")
        if not (owned() or retained_owned()) or user.pw_uid == 0 or user.pw_dir != str(DATA) or user.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}:
            raise MonitorError("Существующий пользователь security-monitor не принадлежит этой установке")
    except KeyError:
        BASE.mkdir(parents=True, mode=0o755, exist_ok=True)
        atomic_write(BASE / ".managed", MARKER + "\n")
        run(["useradd", "--system", "--user-group", "--home-dir", str(DATA), "--no-create-home", "--shell", "/usr/sbin/nologin", "security-monitor"])
        user = pwd.getpwnam("security-monitor")
    BASE.mkdir(parents=True, exist_ok=True, mode=0o755)
    BASE.chmod(0o755)
    (BASE / "releases").mkdir(exist_ok=True, mode=0o755)
    (BASE / "releases").chmod(0o755)
    atomic_write(BASE / ".managed", MARKER + "\n")
    for path in (ETC, DATA):
        if path.is_symlink():
            raise MonitorError("Системные каталоги монитора не должны быть symlink")
        path.mkdir(mode=0o750 if path == ETC else 0o700, exist_ok=True)
    os.chown(ETC, 0, user.pw_gid)
    os.chmod(ETC, 0o750)
    atomic_write(ETC / ".managed", MARKER + "\n")
    os.chown(DATA, user.pw_uid, user.pw_gid)
    os.chmod(DATA, 0o700)
    if not release.exists():
        staging = BASE / "releases" / (".staging-" + fingerprint)
        if staging.exists():
            shutil.rmtree(staging)
        (staging / "src").mkdir(parents=True, mode=0o755)
        staging.chmod(0o755)
        shutil.copytree(source / "src/security_monitor", staging / "src/security_monitor", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("security-monitor", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            if (source / name).exists():
                shutil.copy2(source / name, staging / name)
        (staging / "bin").mkdir(mode=0o755)
        atomic_write(staging / "bin/trivy", binary_bytes, 0o755)
        scanner.executable({**cfg, "trivy_path": str(staging / "bin/trivy")})
        for path in staging.rglob("*"):
            if path.is_file():
                path.chmod(0o755 if path.name in {"trivy", "security-monitor"} else 0o644)
            elif path.is_dir():
                path.chmod(0o755)
        os.replace(staging, release)
    enabled = []
    for job in JOBS:
        _, rc = systemctl("is-enabled", f"security-monitor-{job}.timer", check=False)
        if rc == 0:
            enabled.append(job)
    if (BASE / "current").exists():
        systemctl("stop", *[f"security-monitor-{j}.timer" for j in JOBS], check=False)
        systemctl("stop", *[f"security-monitor-{j}.service" for j in JOBS], check=False)
        database = DATA / "state.sqlite3"
        if database.exists():
            import sqlite3
            backup_dir = ETC / "backups"
            backup_dir.mkdir(mode=0o700, exist_ok=True)
            backup = backup_dir / ("state-" + str(time.time_ns()) + ".sqlite3")
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as original, sqlite3.connect(backup) as saved:
                original.backup(saved)
                if saved.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise MonitorError("Backup перед обновлением не прошёл quick_check")
            backup.chmod(0o600)
        old = (BASE / "current").resolve()
        if old != release:
            previous = BASE / ".previous-new"
            previous.unlink(missing_ok=True)
            previous.symlink_to(old)
            os.replace(previous, BASE / "previous")
    installed_cfg = {**cfg, "state_dir": str(DATA), "trivy_path": str(BASE / "current/bin/trivy"),
                     "secrets_file": str(ETC / "secrets.env")}
    config_path = ETC / "config.json"
    if config_path.exists():
        # Preserve administrator settings on reinstall; tool and data locations remain owned.
        installed_cfg = {**config.load(config_path), "trivy_path": str(BASE / "current/bin/trivy"), "state_dir": str(DATA), "secrets_file": str(ETC / "secrets.env")}
        shutil.copy2(config_path, ETC / "config.previous.json")
    config.save(config_path, installed_cfg)
    os.chown(config_path, 0, user.pw_gid)
    config_path.chmod(0o640)
    if secrets_source:
        # Write literal env values; never source/execute this file.
        content = "\n".join(k + "=" + v for k, v in checked_secrets.items()) + "\n"
        atomic_write(ETC / "secrets.env", content)
        os.chown(ETC / "secrets.env", user.pw_uid, user.pw_gid)
    for name, contents in unit_files(installed_cfg).items():
        atomic_write(UNITS / name, contents, 0o644)
    atomic_write(LAUNCHER, f'#!/bin/sh\n# {MARKER}\nexec /usr/bin/python3 /opt/security-monitor/current/security-monitor "$@"\n', 0o755)
    link = BASE / ".current-new"
    link.unlink(missing_ok=True)
    link.symlink_to(release)
    os.replace(link, BASE / "current")
    systemctl("daemon-reload")
    for job in enabled:
        systemctl("start", f"security-monitor-{job}.timer")
    atomic_write(BASE / "manifest.json", json.dumps({**description, "release": release_name, "timers_previously_enabled": enabled}, indent=2))
    return {**description, "release": release_name, "status": "installed", "timers_restored": enabled}


def service(action):
    assert_root()
    if not owned():
        raise MonitorError("Собственная установка монитора не найдена")
    timers = [f"security-monitor-{j}.timer" for j in JOBS]
    if action == "enable":
        systemctl("enable", "--now", *timers)
    elif action in {"disable", "stop"}:
        systemctl("disable", "--now", *timers)
        systemctl("stop", *[f"security-monitor-{j}.service" for j in JOBS], check=False)
    else:
        raise MonitorError("Неизвестное действие службы")
    return {"action": action, "units": timers}


def rollback():
    assert_root()
    if not owned() or not (BASE / "previous").exists():
        raise MonitorError("Предыдущий релиз отсутствует")
    previous = (BASE / "previous").resolve()
    if previous.parent != BASE / "releases":
        raise MonitorError("Некорректная ссылка previous")
    # Schema v1 has no destructive migrations; future releases must extend this guard.
    import sqlite3
    database = DATA / "state.sqlite3"
    if database.exists():
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise MonitorError("Для rollback схемы потребуется согласованный backup; автоматический откат запрещён")
    service("disable")
    link = BASE / ".rollback-new"
    link.unlink(missing_ok=True)
    link.symlink_to(previous)
    os.replace(link, BASE / "current")
    systemctl("daemon-reload")
    return {"status": "rolled_back", "timers": "disabled", "release": previous.name}


def uninstall(purge=False, dry_run=False):
    if not owned():
        raise MonitorError("Собственная установка монитора не найдена")
    result = {"remove": [str(BASE), str(LAUNCHER), *[str(UNITS / f"security-monitor-{j}.{s}") for j in JOBS for s in ("service", "timer")]],
              "retain": [] if purge else [str(DATA), str(ETC)], "purge": purge}
    if dry_run:
        return result
    assert_root()
    service("disable")
    for job in JOBS:
        for suffix in ("service", "timer"):
            path = UNITS / f"security-monitor-{job}.{suffix}"
            if path.is_file() and MARKER in path.read_text():
                path.unlink()
    if LAUNCHER.is_file() and MARKER in LAUNCHER.read_text():
        LAUNCHER.unlink()
    shutil.rmtree(BASE)
    if purge:
        for path in (DATA, ETC):
            if path.is_symlink():
                raise MonitorError("Отказ от purge через symlink")
            shutil.rmtree(path)
        ETC.mkdir(mode=0o700)
        atomic_write(ETC / ".managed", MARKER + "\n")
    systemctl("daemon-reload")
    result["user_retained"] = "security-monitor (system account retained; no login shell)"
    result["ownership_marker_retained"] = str(ETC / ".managed")
    return result
