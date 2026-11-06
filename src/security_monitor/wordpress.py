"""Static WordPress metadata only. No PHP, WP-CLI, hooks or database access."""
import re
from pathlib import Path
from urllib.parse import urlsplit

from .util import MonitorError, safe_url
from .versions import wp_affected, wp_compare, wp_tokens


def header(path, key):
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        with path.open("rb") as f:
            text = f.read(8192).decode("utf-8", "replace")
    except OSError:
        return ""
    match = re.search(r"^[\s/*#@]*" + re.escape(key) + r"\s*:\s*(.+?)\s*$", text, re.M | re.I)
    return match[1].strip().removesuffix("*/").strip() if match else ""


def inventory(path):
    root = Path(path).resolve(strict=True)
    version_file = root / "wp-includes/version.php"
    if version_file.is_symlink() or not version_file.is_file():
        raise MonitorError("WordPress: не найден обычный wp-includes/version.php")
    with version_file.open("rb") as f:
        content = f.read(65536).decode("utf-8", "replace")
    match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content)
    if not match:
        raise MonitorError("WordPress: версия core неизвестна")
    components = [{"kind": "core", "slug": "wordpress", "version": match[1], "source_verified": True}]
    gaps = ["Статическая инвентаризация: active/auto-update/multisite неизвестны; PHP и DB не запускались"]
    for kind, directory in (("plugin", "plugins"), ("plugin", "mu-plugins"), ("theme", "themes")):
        folder = root / "wp-content" / directory
        if not folder.exists():
            continue
        entries = sorted(folder.iterdir())
        if len(entries) > 2000:
            raise MonitorError("WordPress: превышен лимит компонентов")
        for entry in entries:
            if entry.is_symlink():
                gaps.append("Symlink компонента не прочитан")
                continue
            if kind == "theme" and entry.is_dir():
                candidates = [entry / "style.css"]
            elif entry.is_dir():
                preferred = entry / (entry.name + ".php")
                candidates = [preferred, *sorted(entry.glob("*.php"))[:50]]
            elif directory == "mu-plugins" and entry.suffix == ".php":
                candidates = [entry]
            else:
                continue
            slug = entry.stem if entry.is_file() else entry.name
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,199}", slug):
                gaps.append("Неоднозначный slug компонента")
                continue
            named = [p for p in candidates if header(p, "Theme Name" if kind == "theme" else "Plugin Name")]
            if not named:
                gaps.append("Компонент без читаемого header: " + slug)
                continue
            source = named[0]
            version = header(source, "Version")
            uri = header(source, "Theme URI" if kind == "theme" else "Plugin URI")
            try:
                parsed = urlsplit(uri)
                verified = (parsed.scheme == "https" and parsed.netloc == "wordpress.org" and
                            parsed.path.rstrip("/") == ("/themes/" if kind == "theme" else "/plugins/") + slug)
            except ValueError:
                verified = False
            components.append({"kind": kind, "slug": slug, "version": version,
                               "source_verified": verified, "directory": directory})
    for filename in ("advanced-cache.php", "object-cache.php", "db.php", "sunrise.php"):
        if (root / "wp-content" / filename).exists():
            gaps.append("Drop-in требует ручной идентификации: " + filename)
    return {"components": components, "limitations": gaps}


def match_findings(snapshot, feed):
    index = {}
    for advisory in feed["records"]:
        for software in advisory["software"]:
            index.setdefault((software["type"], software["slug"]), []).append((advisory, software))
    findings = []
    for component in snapshot["components"]:
        for advisory, software in index.get((component["kind"], component["slug"]), []):
            try:
                affected = wp_affected(component["version"], software["affected_versions"])
                certain = component["source_verified"]
            except MonitorError:
                affected, certain = True, False
            if not affected:
                continue
            fixed = []
            for version in software.get("patched_versions") or []:
                try:
                    wp_tokens(version)
                    fixed.append(version)
                except MonitorError:
                    pass
            cvss = advisory.get("cvss") or {}
            score = cvss.get("score") if isinstance(cvss, dict) else None
            severity = "CRITICAL" if isinstance(score, (int, float)) and score >= 9 else "HIGH" if isinstance(score, (int, float)) and score >= 7 else "UNKNOWN"
            refs = advisory.get("references") or []
            url = next((x for x in refs if x.startswith("https://www.wordfence.com/")), "https://www.wordfence.com/threat-intel/vulnerabilities")
            findings.append({"component": component["kind"] + ":" + component["slug"],
                             "component_label": component["slug"], "vuln": advisory.get("cve") or "WORDFENCE-" + advisory["id"],
                             "aliases": ["WORDFENCE-" + advisory["id"]], "installed": component["version"],
                             "applicability": "affected" if certain else "potentially_affected",
                             "upstream_fixed": fixed, "fix_status": "upstream_fix_available" if fixed else "no_fix_available",
                             "repo_fixed": None, "severity": severity, "cvss": cvss, "source": "wordfence",
                             "url": safe_url(url), "published_at": advisory.get("published"),
                             "notice": feed["notices"].get(advisory["notice_key"], {}),
                             "title": advisory.get("title", ""), "confidence": "high" if certain else "low",
                             "runtime_verification": "file_metadata_only", "priority": "P2" if certain and severity in {"HIGH", "CRITICAL"} else "P3"})
    return findings


def verify_missing(finding, snapshot):
    kind, slug = finding["component"].split(":", 1)
    current = next((p for p in snapshot["components"] if p["kind"] == kind and p["slug"] == slug), None)
    if current and current["source_verified"] and current["version"] != finding["installed"]:
        try:
            if any(wp_compare(current["version"], fixed) >= 0 for fixed in finding.get("upstream_fixed", [])):
                return {"remediation": "remediated_verified", "observed_version": current["version"],
                        "verification": "Исправленная версия файлов и повторная проверка диапазона; runtime не проверен"}
        except MonitorError:
            pass
        return {"remediation": "update_installed_pending_verification", "observed_version": current["version"]}
    return {"remediation": "needs_reverification", "verification": "Нет достаточных доказательств устранения"}
