"""Orchestration and evidence policy, separate from scanner exit codes."""
import json
import time
from pathlib import Path

from . import feeds, inventory, scanner, wordpress
from .util import MonitorError, age_seconds, clean_text, digest, json_text, lock, private_dir, safe_url, utcnow
from .versions import dpkg_ge
from .storage import detail, message_details


def score(cvss):
    numbers = []
    if isinstance(cvss, dict):
        for value in cvss.values():
            if isinstance(value, dict):
                for key in ("V4Score", "V3Score", "V2Score", "score"):
                    n = value.get(key)
                    if isinstance(n, (int, float)) and not isinstance(n, bool) and 0 <= n <= 10:
                        numbers.append(n)
    return max(numbers) if numbers else None


def apply_priority(row, kev_ids):
    row["kev"] = row["vuln"] in kev_ids or row.get("kev", False)
    if row["applicability"] != "affected":
        row["priority"] = "P3"
    elif row["kev"]:
        row["priority"] = "P1"
    elif row.get("severity") in {"HIGH", "CRITICAL"} or (score(row.get("cvss")) or 0) >= 8:
        row["priority"] = "P2"
    else:
        row["priority"] = "P3"
    return row


def apt_fix(component, vendor_fixed, cfg, apt_age):
    expected = "Ubuntu" if cfg.get("os_id") == "ubuntu" else "Debian"
    candidate = component.get("candidate")
    fresh = apt_age is not None and apt_age <= cfg["apt_max_age_hours"] * 3600
    trusted = component.get("origin") == expected and component.get("candidate_origin") == expected
    if vendor_fixed and fresh and trusted and candidate and dpkg_ge(candidate, vendor_fixed) is True:
        return "repo_fix_available", candidate
    return ("vendor_fix_available" if vendor_fixed else "no_vendor_fix_known"), None


def normalize(result, snapshot, kind, cfg, kev_ids):
    packages = snapshot.get("packages", {})
    expected = "Ubuntu" if snapshot.get("platform", {}).get("id") == "ubuntu" else "Debian"
    scan_packages = result["packages"]
    rows = {}
    for item in result["findings"]:
        name = item["pkg"]
        package = scan_packages.get((item.get("target", ""), item.get("pkg_id", "")), {})
        arch = package.get("Arch", "")
        if kind == "os":
            # dpkg-query may report a multiarch suffix where Trivy uses the base name.
            native_name = name if name in packages else name + ":" + arch
            if native_name not in packages:
                candidates = [n for n in packages if n.split(":", 1)[0] == name]
                if len(candidates) == 1:
                    native_name = candidates[0]
            native = packages.get(native_name, {})
            vendor = (item.get("source") or {}).get("ID")
            trusted = (native.get("origin") == expected and vendor == snapshot["platform"]["id"] and
                       native.get("version") == item["installed"])
            component = native_name
            fix, repo = apt_fix(native, item.get("fixed"), {**cfg, "os_id": snapshot["platform"]["id"]}, snapshot.get("apt_age_seconds"))
            origin = native.get("origin", "unknown")
        else:
            native = {}
            # Keep distinct copies of a dependency inside a single project/image.
            component = name + ":" + digest([item.get("target"), item.get("pkg_path"), item.get("pkg_id"), arch])[:16]
            trusted = bool(item.get("source"))
            fix, repo, origin = ("upstream_fix_available" if item.get("fixed") else "no_fix_known"), None, "lockfile_or_image"
        row = {"component": component, "component_label": name, "vuln": item["id"],
               "installed": item["installed"], "vendor_fixed": item.get("fixed") if kind == "os" else None,
               "upstream_fixed": [item["fixed"]] if kind != "os" and item.get("fixed") else [],
               "repo_fixed": repo, "fix_status": fix, "origin": origin,
               "source_package": native.get("source_package", package.get("SrcName") or name),
               "held": native.get("held", False), "applicability": "affected" if trusted else "potentially_affected",
               "severity": item["severity"], "cvss": item.get("cvss") or {},
               "source": (item.get("source") or {}).get("ID", "unknown"),
               "url": safe_url(item.get("url")) or safe_url((item.get("source") or {}).get("URL")),
               "published_at": item.get("published"), "modified_at": item.get("modified"),
               "title": item.get("title", ""), "confidence": "high" if trusted else "low",
               "runtime_verification": "installed_package_only" if kind == "os" else "declared_dependency_or_image_only"}
        key = (component, row["vuln"])
        apply_priority(row, kev_ids)
        if key in rows and rows[key] != row:
            raise MonitorError("Неоднозначные дубли компонента Trivy; нужна ручная проверка")
        rows[key] = row
    return list(rows.values())


def verify_os(finding, snapshot):
    current = snapshot.get("packages", {}).get(finding["component"])
    if not current:
        return {"remediation": "needs_reverification", "verification": "Компонент больше не найден; это не доказательство установленного фикса"}
    if current["version"] != finding["installed"]:
        expected = "Ubuntu" if snapshot["platform"]["id"] == "ubuntu" else "Debian"
        fixed = finding.get("vendor_fixed")
        if fixed and current["origin"] == expected and dpkg_ge(current["version"], fixed) is True:
            # Runtime kernel/library restarts are a separate observation; never inferred.
            return {"remediation": "remediated_verified", "observed_version": current["version"],
                    "verification": "Исправленная vendor-версия установлена; свежий OS-скан не находит CVE. Runtime/restart не подтверждён"}
        return {"remediation": "update_installed_pending_verification", "observed_version": current["version"]}
    return {"remediation": "needs_reverification", "verification": "CVE исчезла без изменения версии; требуется подтверждение"}


def verify_dependency(finding, snapshot):
    # A lockfile is not proof that the running deployment was rebuilt/restarted.
    return {"remediation": "needs_reverification", "verification": "Повторный скан не находит CVE; подтвердите версию и развёртывание зависимости/образа"}


def kev_ids(store, cfg):
    payload = feeds.cached(store, "kev", cfg["feed_max_age_hours"])
    return set(payload["records"]) if payload else set()


def enrich_kev(store, ids):
    changed = {}
    with store.db:
        for old in store.db.execute("SELECT * FROM findings WHERE remediation!='remediated_verified'").fetchall():
            data = json.loads(old["payload"])
            if data["vuln"] not in ids or data.get("kev"):
                continue
            apply_priority(data, ids)
            revision = old["revision"] + 1
            store.db.execute("UPDATE findings SET revision=?,fingerprint=?,priority=?,payload=? WHERE key=?",
                             (revision, digest(data), data["priority"], json_text(data), old["key"]))
            event = store.event(old["scope"], "kev_added", old["key"], revision,
                                {"vuln": data["vuln"], "priority": data["priority"], "component": data["component"], "detail": detail(data)})
            changed.setdefault((old["scope"], data["priority"]), []).append(event)
        for (scope, priority), values in changed.items():
            store.queue(digest([v["key"] for v in values]), {"kind": "changes", "scope": scope,
                        "count": len(values), "ids": sorted({v["vuln"] for v in values})[:12], "kinds": ["kev_added"],
                        **message_details(values)}, priority)
    return sum(map(len, changed.values()))


def refresh_feeds(store, cfg, credentials, sources, periodic=False):
    results = []
    with lock(store.directory / "feeds.lock"):
        for name in sources:
            if name == "wordfence" and periodic:
                row = store.db.execute("SELECT last_success FROM feeds WHERE name=?", (name,)).fetchone()
                if row and age_seconds(row[0]) < 3600:
                    continue
            result = feeds.refresh(store, name, credentials)
            if name == "kev" and result["status"] == "fresh":
                result["finding_events"] = enrich_kev(store, kev_ids(store, cfg))
            results.append(result)
    return results


def scan_targets(store, cfg, target="os"):
    status = inventory.platform_status()
    if status["status"] == "unsupported":
        raise MonitorError("OS не поддерживается; доступна read-only discover")
    outcomes = []
    scopes = []
    if target in {"os", "all"}:
        scopes.append(("os", "os", None))
    for kind in ("apps", "wordpress", "containers"):
        if target in {kind, "all"}:
            for item in cfg[kind]:
                scopes.append((kind + ":" + item["name"], kind, item))
    if not scopes:
        return [{"target": target, "status": "not_configured", "note": "Области не настроены; это не скан без уязвимостей"}]
    with lock(store.directory / "scan.lock"):
        ids = kev_ids(store, cfg)
        for scope, kind, item in scopes:
            start = time.monotonic()
            try:
                if kind == "wordpress":
                    snapshot = wordpress.inventory(item["path"])
                    feed = feeds.cached(store, "wordfence", cfg["feed_max_age_hours"], require_fresh=True)
                    rows = wordpress.match_findings(snapshot, feed)
                    for row in rows:
                        apply_priority(row, ids)
                    verify = wordpress.verify_missing
                else:
                    if kind == "os":
                        snapshot = inventory.discover(cfg)
                        if not snapshot["packages"]:
                            raise MonitorError("Не удалось получить установленную пакетную базу")
                    else:
                        snapshot = {"kind": kind, "coverage": "selected_paths_or_images"}
                    result = scanner.scan(cfg, kind=kind, **({"path": item["path"]} if kind == "apps" else
                                         {k: v for k, v in item.items() if k in {"image", "archive"}} if kind == "containers" else {}))
                    if kind != "os" and not result["targets"]:
                        raise MonitorError("Trivy не нашёл поддерживаемые зависимости; coverage unknown")
                    rows = normalize(result, snapshot, kind, cfg, ids)
                    if kind != "os":
                        snapshot["components"] = [{"name": p["Name"], "version": p["Version"]} for p in result["packages"].values()]
                    snapshot["db_updated_at"] = result["db_updated_at"]
                    snapshot["artifact"] = Path(result["artifact"]).name
                    verify = verify_os if kind == "os" else verify_dependency
                snapshot["target_config"] = digest(item)
                outcome = store.reconcile(scope, rows, snapshot, verify, duration=time.monotonic() - start)
                outcomes.append({**outcome, "status": "fresh"})
            except (MonitorError, OSError) as exc:
                # OS paths may contain secrets; do not print OSError's filename.
                error = str(exc) if isinstance(exc, MonitorError) else "Не удалось прочитать настроенную область"
                store.run_failed(scope, error, time.monotonic() - start)
                outcomes.append({"scope": scope, "status": "error", "error": error})
    return outcomes


def observe_updates(store, cfg):
    """Hourly APT observation can announce an update, but never close a finding."""
    last = store.meta("last-package-observation")
    if last and age_seconds(last) < 3600:
        return {"status": "recent"}
    snapshot = inventory.package_inventory()
    os_id = inventory.os_release().get("ID")
    changes = []
    with store.db:
        for old in store.db.execute("SELECT * FROM findings WHERE scope='os' AND remediation!='remediated_verified'").fetchall():
            data = json.loads(old["payload"])
            current = snapshot["packages"].get(old["component"])
            if not current:
                continue
            updated = dict(data)
            event_kind = None
            if current["version"] != data["installed"]:
                updated.update(observed_version=current["version"], remediation="update_installed_pending_verification")
                event_kind = "update_detected"
            fix, candidate = apt_fix(current, data.get("vendor_fixed"), {**cfg, "os_id": os_id}, snapshot["apt_age_seconds"])
            updated.update(fix_status=fix, repo_fixed=candidate, held=current["held"])
            if data.get("fix_status") != "repo_fix_available" and fix == "repo_fix_available":
                event_kind = "repo_fix_available"
            if digest(updated) != old["fingerprint"]:
                revision = old["revision"] + 1
                store.db.execute("UPDATE findings SET revision=?,fingerprint=?,remediation=?,payload=? WHERE key=?",
                                 (revision, digest(updated), updated.get("remediation", "open"), json_text(updated), old["key"]))
                if event_kind:
                    changes.append(store.event("os", event_kind, old["key"], revision,
                                   {"vuln": old["vuln"], "component": old["component"], "priority": old["priority"], "detail": detail(updated)}))
        for priority in ("P1", "P2", "P3"):
            selected = [c for c in changes if c["priority"] == priority]
            if selected:
                store.queue(digest([x["key"] for x in selected]), {"kind": "changes", "scope": "os", "count": len(selected),
                            "ids": sorted({x["vuln"] for x in selected})[:12], "kinds": sorted({x["kind"] for x in selected}),
                            **message_details(selected)}, priority)
        store.set_meta("last-package-observation", utcnow())
    return {"status": "fresh", "events": len(changes)}
