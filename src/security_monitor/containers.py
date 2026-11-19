"""Read-only Docker container inventory; image export and scanning are separate."""
import json
import os
import pwd
import re
import resource
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .util import MonitorError, command_env, age_seconds, utcnow

IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
CONTAINER_ID = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")


def inventory(run=subprocess.run):
    """Enumerate running containers and immutable local image IDs; keep no config/env."""
    def docker(*args):
        try:
            p = run(["docker", *args], env=command_env(), capture_output=True, text=True, timeout=30, cwd="/")
        except (OSError, subprocess.TimeoutExpired):
            raise MonitorError("Docker недоступен для инвентаризации") from None
        if p.returncode != 0:
            raise MonitorError("Docker не подтвердил инвентаризацию контейнеров")
        return p.stdout

    ids = docker("ps", "--quiet", "--no-trunc").splitlines()
    if len(ids) > 10000 or len(set(ids)) != len(ids) or any(not CONTAINER_ID.fullmatch(x) for x in ids):
        raise MonitorError("Docker вернул некорректный список контейнеров")
    if not ids:
        return []
    fmt = '{{json .Id}}\t{{json .Image}}\t{{json .Name}}\t{{json .State.Running}}'
    try:
        entries = [list(map(json.loads, line.split('\t'))) for line in
                   docker("inspect", "--type", "container", "--format", fmt, *ids).splitlines()]
    except (TypeError, ValueError):
        raise MonitorError("Docker вернул некорректные сведения о контейнерах") from None
    if not isinstance(entries, list) or len(entries) != len(ids):
        raise MonitorError("Состав контейнеров изменился во время проверки")
    result, seen = {}, set()
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 4:
            raise MonitorError("Docker вернул неизвестную схему контейнера")
        identifier, image, name, running = entry
        name = name[1:] if isinstance(name, str) and name.startswith("/") else name
        if (identifier not in ids or identifier in seen or not isinstance(image, str) or not IMAGE_ID.fullmatch(image)
                or not isinstance(name, str) or not NAME.fullmatch(name) or running is not True):
            raise MonitorError("Состав или состояние контейнеров изменились во время проверки")
        seen.add(identifier)
        result.setdefault(image, []).append({"id": identifier, "name": name})
    return [{"image_id": image, "containers": sorted(items, key=lambda x: x["name"])}
            for image, items in sorted(result.items())]


def scope_name(image_id):
    if not IMAGE_ID.fullmatch(image_id):
        raise MonitorError("Некорректный локальный ID образа")
    return "docker-" + image_id[7:55]


def choose_image(items, runs):
    """At most one image per run; failed attempts are retried after 30 minutes."""
    candidates = []
    for item in items:
        name = scope_name(item["image_id"])
        run = runs.get(name, {})
        if run.get("status") == "error" and age_seconds(run.get("last_attempt")) < 1800:
            continue
        if not run.get("last_success") or age_seconds(run["last_success"]) >= 24 * 3600:
            candidates.append((run.get("last_attempt") or "", name, item))
    return min(candidates, key=lambda x: (x[0], x[1]))[2] if candidates else None


def worker(config_path, inventory_file, image_id=None, archive=None):
    """Runs under the unprivileged monitor UID, without Docker socket access."""
    from . import config, engine
    from .storage import Store
    cfg = config.load(config_path)
    with open(inventory_file, encoding="utf-8") as f:
        items = json.load(f)
    with Store(cfg["state_dir"]) as store:
        with store.db:
            store.set_meta("docker-inventory", {"observed_at": utcnow(), "images": items})
        if image_id:
            if archive == '__export_failed__':
                store.run_failed('containers:' + scope_name(image_id), 'Не удалось подготовить локальный образ для проверки')
                return 1
            selected = {**cfg, "containers": [{"name": scope_name(image_id), "archive": archive}]}
            result = engine.scan_targets(store, selected, "containers")
            print(json.dumps(result, ensure_ascii=False))
            return 1 if any(x.get("status") == "error" for x in result) else 0
    return 0


def collect(config_path):
    """Privileged, bounded image export; scanner itself runs as security-monitor."""
    from . import config
    cfg = config.load(config_path)
    if not cfg["docker_monitor"]:
        return 0
    if os.geteuid() != 0:
        raise MonitorError("Docker collector требует отдельной привилегированной службы")
    user = pwd.getpwnam("security-monitor")
    stage = Path('/var/lib/security-monitor-exports')
    if stage.is_symlink() or not stage.is_dir() or stage.stat().st_uid != 0 or stage.stat().st_mode & 0o022:
        raise MonitorError("Каталог экспорта Docker не защищён")
    marker = stage / '.managed'
    if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != 'sec-monitor-managed-v1':
        raise MonitorError('Каталог экспорта не принадлежит монитору')
    for old in stage.glob('export-*'):
        if not old.is_symlink() and old.is_dir() and old.stat().st_uid == 0 and time.time() - old.stat().st_mtime > 7200:
            shutil.rmtree(old)
    items = inventory()
    prefixes = [scope_name(item['image_id']) for item in items]
    if len(prefixes) != len(set(prefixes)):
        raise MonitorError("Неоднозначные идентификаторы образов")
    with sqlite3.connect('file:' + cfg['state_dir'] + '/state.sqlite3?mode=ro', uri=True) as db:
        runs = {row[0].split(':', 1)[1]: {'last_success': row[1], 'last_attempt': row[2], 'status': row[3]}
                for row in db.execute("SELECT scope,last_success,last_attempt,status FROM runs WHERE scope LIKE 'containers:docker-%'")}
    selected = choose_image(items, runs)
    temp = Path(tempfile.mkdtemp(prefix='export-', dir=stage))
    data = base = kwargs = None
    try:
        os.chown(temp, 0, user.pw_gid)
        os.chmod(temp, 0o710)
        data = temp / 'inventory.json'
        data.write_text(json.dumps(items, ensure_ascii=False))
        os.chown(data, 0, user.pw_gid)
        os.chmod(data, 0o640)
        base = ['/usr/bin/python3','-m','security_monitor.containers','worker',str(config_path),str(data)]
        kwargs = {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': [], 'timeout': 1200,
                  'env': {**command_env(), 'HOME': cfg['state_dir'], 'PYTHONPATH': '/opt/security-monitor/current/src'}}
        if subprocess.run(base, **kwargs).returncode:
            raise MonitorError('Не удалось сохранить инвентарь контейнеров')
        archive = None
        if selected:
            image_id = selected['image_id']
            p = subprocess.run(['docker','image','inspect','--format','{{.Size}}',image_id], capture_output=True, text=True, timeout=30, env=command_env())
            if p.returncode or not p.stdout.strip().isdigit():
                raise MonitorError('Не удалось определить размер образа')
            size = int(p.stdout.strip())
            if size <= 0 or size > 4 * 1024**3 or shutil.disk_usage(stage).free < size + 3 * 1024**3:
                raise MonitorError('Образ слишком велик или недостаточно места для безопасного экспорта')
            archive = temp / 'image.tar'
            def limit_archive():
                resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**3, 4 * 1024**3))
            p = subprocess.run(['docker','image','save','--output',str(archive),image_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600, env=command_env(), preexec_fn=limit_archive)
            if p.returncode or not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 4 * 1024**3:
                raise MonitorError('Не удалось безопасно экспортировать локальный образ')
            os.chown(archive, user.pw_uid, user.pw_gid)
            os.chmod(archive, 0o600)
        args = list(base)
        if selected:
            args.extend([selected['image_id'],str(archive)])
        return subprocess.run(args, **kwargs).returncode if selected else 0
    except (MonitorError, OSError, subprocess.TimeoutExpired):
        if selected and data and data.exists() and base and kwargs:
            try:
                subprocess.run(base + [selected['image_id'], '__export_failed__'], **kwargs)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise
    finally:
        shutil.rmtree(temp)


if __name__ == '__main__':
    try:
        if len(sys.argv) in (4, 6) and sys.argv[1] == 'worker':
            sys.exit(worker(*sys.argv[2:]))
        if len(sys.argv) == 3 and sys.argv[1] == 'collect':
            sys.exit(collect(sys.argv[2]))
        raise MonitorError('Некорректный вызов Docker collector')
    except (MonitorError, OSError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
        print('Ошибка проверки контейнеров: ' + (str(exc) if isinstance(exc, MonitorError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
