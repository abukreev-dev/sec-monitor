import json
import os
import re
import stat
import pwd
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .util import MonitorError, atomic_write, bounded_json, private_dir


def default_path():
    system = Path("/etc/security-monitor/config.json")
    return system if system.exists() else Path.home() / ".config/sec-monitor/config.json"


def defaults():
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "sec-monitor"
    return {"schema": 1, "server_name": "linux-server", "timezone": "UTC",
            "state_dir": str(state), "trivy_path": "trivy", "scan_timeout": 300,
            "db_max_age_hours": 48, "apt_max_age_hours": 48,
            "feed_max_age_hours": 48, "artifact_retention_days": 14,
            "secrets_file": str(Path.home() / ".config/sec-monitor/secrets.env"),
            "notifications_enabled": False, "max_notifications_per_run": 10,
            "apps": [], "wordpress": [], "containers": [],
            "discovery_roots": ["/var/www", "/srv"], "allow_untested_os": False}


def load(path=None):
    path = Path(path or default_path())
    cfg = defaults()
    if path.exists():
        if path.is_symlink():
            raise MonitorError("Конфигурация не должна быть symlink")
        data = bounded_json(path)
        if not isinstance(data, dict) or set(data) - set(cfg):
            raise MonitorError("Неизвестные поля конфигурации; проверьте config.example.json")
        cfg.update(data)
    validate(cfg)
    return cfg


def validate(cfg):
    if type(cfg.get("schema")) is not int or cfg["schema"] != 1:
        raise MonitorError("Неподдерживаемая версия конфигурации")
    if not isinstance(cfg["server_name"], str) or not re.fullmatch(r"[A-Za-z0-9А-Яа-яЁё ._-]{1,64}", cfg["server_name"]):
        raise MonitorError("server_name: используйте короткий псевдоним без путей")
    for field in ("state_dir", "secrets_file"):
        if not isinstance(cfg[field], str) or not Path(cfg[field]).is_absolute():
            raise MonitorError(f"{field}: требуется абсолютный путь")
    if not isinstance(cfg["trivy_path"], str) or not cfg["trivy_path"]:
        raise MonitorError("trivy_path должен указывать на Trivy")
    for field in ("scan_timeout", "db_max_age_hours", "apt_max_age_hours",
                  "feed_max_age_hours", "artifact_retention_days", "max_notifications_per_run"):
        if type(cfg[field]) is not int or not 1 <= cfg[field] <= 86400:
            raise MonitorError(f"Некорректное ограничение: {field}")
    for field in ("notifications_enabled", "allow_untested_os"):
        if type(cfg[field]) is not bool:
            raise MonitorError(f"{field}: ожидается boolean")
    try:
        ZoneInfo(cfg["timezone"])
    except (ZoneInfoNotFoundError, TypeError):
        raise MonitorError("Неизвестная timezone") from None
    for kind in ("apps", "wordpress", "containers"):
        if not isinstance(cfg[kind], list):
            raise MonitorError(f"{kind}: ожидается список")
        names = set()
        for item in cfg[kind]:
            if not isinstance(item, dict) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", item.get("name", "")):
                raise MonitorError(f"{kind}: укажите уникальный безопасный name")
            if item["name"] in names:
                raise MonitorError(f"{kind}: повтор имени")
            names.add(item["name"])
            allowed = {"name", "path"} if kind != "containers" else {"name", "image", "archive"}
            if set(item) - allowed:
                raise MonitorError(f"{kind}: неизвестное поле")
            if kind == "containers":
                if bool(item.get("image")) == bool(item.get("archive")):
                    raise MonitorError("containers: укажите image либо archive")
                if item.get("image") and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}", item["image"]):
                    raise MonitorError("Контейнер: нужен immutable repo@sha256 digest")
            path = item.get("path", item.get("archive"))
            if path is not None and (not isinstance(path, str) or not Path(path).is_absolute()):
                raise MonitorError(f"{kind}: требуется абсолютный path/archive")
    if not isinstance(cfg["discovery_roots"], list) or any(not isinstance(p, str) or not Path(p).is_absolute() for p in cfg["discovery_roots"]):
        raise MonitorError("discovery_roots: ожидаются абсолютные пути")


def save(path, cfg):
    validate(cfg)
    path = Path(path)
    previous = path.stat() if path.exists() and not path.is_symlink() else None
    atomic_write(path, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    if previous and stat.S_IMODE(previous.st_mode) == 0o640:
        path.chmod(0o640)
        if os.geteuid() == 0:
            os.chown(path, previous.st_uid, previous.st_gid)


def state_path(cfg):
    return private_dir(cfg["state_dir"])


def secrets(cfg):
    path = Path(cfg["secrets_file"])
    if not path.exists():
        return {}
    meta = path.lstat()
    allowed = {0, os.geteuid()}
    if os.geteuid() == 0 and path == Path("/etc/security-monitor/secrets.env"):
        try:
            allowed.add(pwd.getpwnam("security-monitor").pw_uid)
        except KeyError:
            pass
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_uid not in allowed:
        raise MonitorError("secrets_file должен быть обычным файлом 0600 владельца root/текущего пользователя")
    if meta.st_size > 16384:
        raise MonitorError("Слишком большой secrets_file")
    allowed = {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "WORDFENCE_API_KEY"}
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key.strip() not in allowed:
            raise MonitorError("Неизвестная строка secrets_file; используйте .env.example")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if any(ord(c) < 32 for c in value):
            raise MonitorError("Недопустимый символ в secrets_file")
        result[key.strip()] = value
    return result
