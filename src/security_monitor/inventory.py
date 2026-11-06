"""Read-only Linux inventory. No package refresh, shell or project execution."""
import os
import platform
import re
import shutil
import time
from pathlib import Path

from .util import MonitorError, run, utcnow

PKG = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?\Z")


def os_release(path=Path("/etc/os-release")):
    result = {}
    try:
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and re.fullmatch(r"[A-Z_]+", key):
                result[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return result


def platform_status(info=None):
    info = os_release() if info is None else info
    family, version = info.get("ID", "unknown"), info.get("VERSION_ID", "unknown")
    if platform.system() != "Linux" or family not in {"ubuntu", "debian"}:
        return {"status": "unsupported", "id": family, "version": version}
    tested = family == "ubuntu" and version == "24.04" and platform.machine() == "x86_64"
    return {"status": "tested" if tested else "experimental", "id": family, "version": version}


def parse_dpkg(text):
    result = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise MonitorError("Изменилась схема dpkg-query")
        name, arch, version, source, source_version, status = fields
        if not status.startswith("ii"):
            continue
        if not PKG.fullmatch(name):
            raise MonitorError("Некорректное имя пакета dpkg")
        result[name] = {"name": name, "arch": arch, "version": version,
                        "source_package": source or name, "source_version": source_version or version,
                        "origin": "unknown", "candidate": None, "candidate_origin": "unknown", "held": False}
    return result


def policy_sources(text):
    result, current = {}, None
    for line in text.splitlines():
        m = re.match(r"\s*-?\d+\s+(https?://\S+\s+.+Packages)\s*$", line)
        if m:
            current = " ".join(m[1].split())
            result[current] = "unknown"
        elif current and line.strip().startswith("release "):
            values = dict(x.split("=", 1) for x in line.strip()[8:].split(",") if "=" in x)
            result[current] = values.get("o", "unknown")
    return result


def parse_policy(text, packages, sources):
    current, version = None, None
    candidates = {}
    origins = {}
    for line in text.splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            current, version = line[:-1], None
            continue
        if current not in packages:
            continue
        if line.strip().startswith("Candidate:"):
            val = line.split(":", 1)[1].strip()
            candidates[current] = None if val == "(none)" else val
        m = re.match(r"\s+(?:\*\*\*\s+)?(\S+)\s+-?\d+\s*$", line)
        if m:
            version = m[1]
            continue
        m = re.match(r"\s*-?\d+\s+(https?://\S+\s+.+Packages)\s*$", line)
        if m and version:
            descriptor = " ".join(m[1].split())
            origins.setdefault((current, version), set()).add(sources.get(descriptor, "third_party"))
    for name, component in packages.items():
        component["candidate"] = candidates.get(name)
        for version, key in ((component["version"], "origin"), (component["candidate"], "candidate_origin")):
            values = origins.get((name, version), set())
            # Ambiguous or unavailable origin is deliberately not promoted to official.
            component[key] = next(iter(values)) if len(values) == 1 else "unknown"
    return packages


def package_inventory():
    fmt = "${binary:Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"
    text, _ = run(["dpkg-query", "-W", "-f=" + fmt])
    packages = parse_dpkg(text)
    errors = []
    try:
        policy, _ = run(["apt-cache", "policy"])
        detailed, _ = run(["apt-cache", "policy", *packages], timeout=60)
        parse_policy(detailed, packages, policy_sources(policy))
        holds, _ = run(["apt-mark", "showhold"])
        for name in holds.splitlines():
            if name in packages:
                packages[name]["held"] = True
    except MonitorError as exc:
        errors.append(str(exc))
    stamp = Path("/var/lib/apt/periodic/update-success-stamp")
    # A downloaded InRelease mtime is not the last successful conditional refresh.
    apt_age = max(0, time.time() - stamp.stat().st_mtime) if stamp.exists() else None
    return {"packages": packages, "apt_age_seconds": apt_age, "errors": errors}


def discover_projects(roots, budget=5, limit=10000):
    skip = {".git", "node_modules", "vendor", ".venv", "venv", "cache", "backups", "uploads", "media"}
    locks = {"composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "uv.lock"}
    result = {"apps": [], "wordpress": [], "truncated": False, "unreadable_roots": []}
    seen = 0
    start = time.monotonic()
    for root in roots:
        path = Path(root)
        if not path.exists():
            continue
        if not os.access(path, os.R_OK | os.X_OK):
            result["unreadable_roots"].append(root)
            continue
        for directory, dirs, files in os.walk(path, followlinks=False):
            seen += 1
            if seen > limit or time.monotonic() - start > budget:
                result["truncated"] = True
                return result
            depth = len(Path(directory).relative_to(path).parts)
            dirs[:] = [d for d in dirs if d not in skip and not (Path(directory) / d).is_symlink() and depth < 5]
            if set(files) & locks:
                result["apps"].append(directory)
            if "wp-includes" in dirs and (Path(directory) / "wp-includes/version.php").is_file():
                result["wordpress"].append(directory)
                dirs[:] = [d for d in dirs if d not in {"wp-includes", "wp-admin", "wp-content"}]
    return result


def discover(cfg, include_packages=True):
    info = os_release()
    result = {"observed_at": utcnow(), "platform": platform_status(info), "arch": platform.machine(),
              "running_kernel": platform.release(), "uid": os.geteuid(),
              "tools": {name: bool(shutil.which(name)) for name in ("dpkg-query", "apt-cache", "systemctl", "docker", "php", "wp")},
              "projects": discover_projects(cfg["discovery_roots"]), "limitations": []}
    if include_packages and result["platform"]["status"] != "unsupported":
        result.update(package_inventory())
    else:
        result["packages"] = {}
    if result["projects"]["truncated"]:
        result["limitations"].append("Поиск проектов ограничен временем/глубиной; задайте пути явно")
    result["limitations"].append("Фактическое выполнение кода и сетевые атаки не проверяются")
    return result
