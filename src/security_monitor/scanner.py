"""Pinned Trivy adapter. Completed observations are published atomically."""
import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

from .util import MonitorError, age_seconds, atomic_write, bounded_json, private_dir, run, utcnow

TRIVY_VERSION = "0.76.2"
ARCHIVE = "trivy_0.76.2_Linux-64bit.tar.gz"
ARCHIVE_SHA256 = "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
BINARY_SHA256 = "6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3"
ARCHIVE_URL = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{ARCHIVE}"
MAX_RESULT_BYTES = 128 * 1024 * 1024


def executable(cfg):
    value = cfg["trivy_path"]
    path = shutil.which(value) if not Path(value).is_absolute() else value
    if not path or not Path(path).is_file():
        raise MonitorError("Trivy отсутствует: выполните явную команду bootstrap или настройте trivy_path")
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != BINARY_SHA256:
        raise MonitorError("SHA256 бинарника Trivy не совпала с проверенным Linux x86_64 релизом")
    text, _ = run([path, "--version", "--format", "json"], timeout=10)
    try:
        version = json.loads(text)["Version"]
    except (ValueError, KeyError, TypeError):
        raise MonitorError("Trivy вернул неизвестный формат версии") from None
    if version != TRIVY_VERSION:
        raise MonitorError(f"Нужен проверенный Trivy {TRIVY_VERSION}; другая версия не принимается автоматически")
    return str(path)


def bootstrap(cfg, dry_run=False):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise MonitorError("Bootstrap пока проверен только для Linux x86_64")
    state = private_dir(cfg["state_dir"])
    tools = private_dir(state / "tools")
    destination = tools / ("trivy-" + TRIVY_VERSION)
    plan = {"url": ARCHIVE_URL, "sha256": ARCHIVE_SHA256, "destination": str(destination),
            "system_packages_changed": False}
    if dry_run:
        return plan
    if destination.exists():
        executable({**cfg, "trivy_path": str(destination)})
        return {**plan, "already_present": True}
    fd, name = tempfile.mkstemp(dir=tools, prefix=".download-")
    os.close(fd)
    archive = Path(name)
    try:
        req = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "sec-monitor/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=60) as response, archive.open("wb") as out:
                count = 0
                while block := response.read(1024 * 1024):
                    count += len(block)
                    if count > 80 * 1024 * 1024:
                        raise MonitorError("Архив Trivy превышает лимит")
                    out.write(block)
        except OSError:
            raise MonitorError("Не удалось загрузить официальный архив Trivy") from None
        sha = hashlib.sha256()
        with archive.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                sha.update(block)
        if sha.hexdigest() != ARCHIVE_SHA256:
            raise MonitorError("Контрольная сумма Trivy не совпала; бинарник не установлен")
        with tarfile.open(archive) as container:
            members = [m for m in container.getmembers() if m.isfile() and m.name in {"trivy", "./trivy"}]
            if len(members) != 1 or members[0].size > 250 * 1024 * 1024:
                raise MonitorError("Неожиданное содержимое архива Trivy")
            with container.extractfile(members[0]) as source:
                atomic_write(destination, source.read(), mode=0o700)
            for member in container.getmembers():
                if member.isfile() and member.name in {"LICENSE", "NOTICE"} and member.size < 1024 * 1024:
                    with container.extractfile(member) as source:
                        atomic_write(tools / ("TRIVY-" + member.name), source.read())
        executable({**cfg, "trivy_path": str(destination)})
        return plan
    finally:
        archive.unlink(missing_ok=True)


def parse_result(path):
    """Strict framing distinguishes valid zero findings from a truncated/empty file."""
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
        raise MonitorError("Нет результата Trivy либо превышен лимит размера")
    findings, packages, targets = [], {}, []
    started, completed = False, False
    try:
        with path.open(encoding="utf-8") as source:
            for line in source:
                if len(line) > 2 * 1024 * 1024:
                    raise MonitorError("Слишком большая строка Trivy")
                if not line.strip():
                    continue
                obj = json.loads(line)
                if not isinstance(obj, dict) or completed:
                    raise MonitorError("Неверная последовательность записей Trivy")
                kind = obj.get("kind")
                if not started:
                    if obj != {"kind": "schema", "version": 1}:
                        raise MonitorError("Неизвестная схема Trivy")
                    started = True
                elif kind == "complete":
                    if obj.get("version") != 1:
                        raise MonitorError("Неизвестная версия завершения Trivy")
                    completed = True
                elif kind == "target":
                    if obj.get("class") not in {"os-pkgs", "lang-pkgs"} or not isinstance(obj.get("type"), str):
                        raise MonitorError("Trivy: неизвестный тип target")
                    targets.append(obj)
                elif kind == "package":
                    p = obj.get("data")
                    if not isinstance(p, dict) or not p.get("Name") or not isinstance(p.get("Version"), str):
                        raise MonitorError("Trivy: неверная запись package")
                    key = p.get("ID") or p["Name"] + "@" + p["Version"]
                    packages[(obj.get("target", ""), key)] = p
                elif kind == "finding":
                    if not all(isinstance(obj.get(k), str) and obj[k] for k in ("id", "pkg", "installed")):
                        raise MonitorError("Trivy: неверная запись finding")
                    if obj.get("severity") not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                        raise MonitorError("Trivy: неизвестная severity")
                    if not isinstance(obj.get("fixed", ""), str) or not isinstance(obj.get("source"), (dict, type(None))):
                        raise MonitorError("Trivy: неизвестная схема evidence")
                    findings.append(obj)
                else:
                    raise MonitorError("Trivy: неизвестная запись")
    except (ValueError, UnicodeError, OSError):
        raise MonitorError("Результат Trivy повреждён; предыдущее состояние сохранено") from None
    if not started or not completed:
        raise MonitorError("Trivy не завершил выдачу; предыдущее состояние сохранено")
    return {"findings": findings, "packages": packages, "targets": targets}


def scan(cfg, kind="os", path=None, image=None, archive=None):
    state = private_dir(cfg["state_dir"])
    artifacts = private_dir(state / "artifacts")
    cache = private_dir(state / "cache")
    binary = executable(cfg)
    temporary = artifacts / (".scan-" + uuid.uuid4().hex + ".jsonl")
    target = "rootfs" if kind == "os" else "fs" if kind == "apps" else "image"
    argv = [binary, target, "--quiet", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
            "--config=", "--ignorefile=", "--format", "template", "--template", "@" + str(Path(__file__).with_name("trivy.tpl")),
            "--output", str(temporary), "--cache-dir", str(cache / "trivy"), "--timeout", str(cfg["scan_timeout"]) + "s"]
    if kind == "os":
        argv.extend(["--pkg-types", "os", "/"])
    elif kind == "apps":
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_dir() or str(resolved) in {"/", "/etc", "/proc", "/sys", "/dev"}:
            raise MonitorError("Для apps нужен отдельный каталог проекта")
        argv.extend(["--pkg-types", "library", "--skip-dirs", ".git,node_modules,vendor,.venv,uploads,backups", str(resolved)])
    elif archive:
        argv.extend(["--input", str(Path(archive).resolve(strict=True))])
    else:
        argv.extend(["--image-src", "remote", image])
    started = time.monotonic()
    try:
        run(argv, timeout=cfg["scan_timeout"] + 20, max_output=1024 * 1024,
            env={"GOMAXPROCS": "1", "GOMEMLIMIT": "600MiB", "TRIVY_DISABLE_TELEMETRY": "true",
                 "TMPDIR": str(private_dir(state / "tmp")), "DOCKER_CONFIG": str(private_dir(state / "registry"))})
        metadata = bounded_json(cache / "trivy/db/metadata.json")
        age = age_seconds(metadata.get("UpdatedAt"))
        if age < -3600 or age > cfg["db_max_age_hours"] * 3600:
            raise MonitorError("База Trivy устарела или время системы неверно")
        result = parse_result(temporary)
        if kind == "os" and not any(t.get("class") == "os-pkgs" for t in result["targets"]):
            raise MonitorError("Trivy не подтвердил OS coverage; нулевая выдача не считается успехом")
        result["db_updated_at"] = metadata["UpdatedAt"]
        result["duration"] = time.monotonic() - started
        dest = artifacts / (utcnow().replace(":", "-") + "-" + uuid.uuid4().hex[:8] + ".jsonl")
        temporary.chmod(0o600)
        os.replace(temporary, dest)
        result["artifact"] = str(dest)
        for old in artifacts.glob("*.jsonl"):
            if old != dest and time.time() - old.stat().st_mtime > cfg["artifact_retention_days"] * 86400:
                old.unlink()
        return result
    finally:
        temporary.unlink(missing_ok=True)
