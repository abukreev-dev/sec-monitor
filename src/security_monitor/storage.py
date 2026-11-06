"""Transactional observations, immutable events and durable notification outbox."""
import contextlib
import json
import os
import sqlite3
import uuid
from pathlib import Path

from .util import MonitorError, digest, json_text, private_dir, utcnow

SCHEMA = 1


def detail(item):
    fields = ("vuln", "component_label", "installed", "applicability", "severity", "kev", "source", "url", "cvss", "published_at",
              "vendor_fixed", "upstream_fixed", "repo_fixed", "fix_status", "remediation", "notice")
    return {k: item[k] for k in fields if k in item}


def message_details(items):
    examples, notices, seen = [], {}, set()
    for item in items:
        d = item.get("detail", item)
        if d.get("notice"):
            notices[digest(d["notice"])] = d["notice"]
        if d.get("vuln") not in seen and len(examples) < 3:
            seen.add(d.get("vuln"))
            examples.append({k: v for k, v in detail(d).items() if k != "notice"})
    return {"details": examples, "notices": list(notices.values())}


class Store:
    def __init__(self, directory):
        self.directory = private_dir(directory)
        path = self.directory / "state.sqlite3"
        if path.is_symlink():
            raise MonitorError("База данных не должна быть symlink")
        self.db = sqlite3.connect(path, timeout=30)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA:
            self.db.close()
            raise MonitorError("База новее программы; используйте соответствующий релиз")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs(scope TEXT PRIMARY KEY, last_success TEXT, last_attempt TEXT,
          status TEXT NOT NULL, error TEXT, duration REAL, count INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS snapshots(scope TEXT PRIMARY KEY, observed_at TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS run_history(id INTEGER PRIMARY KEY, scope TEXT NOT NULL, at TEXT NOT NULL,
          status TEXT NOT NULL, duration REAL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(key TEXT PRIMARY KEY, scope TEXT NOT NULL, component TEXT NOT NULL,
          vuln TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, revision INTEGER NOT NULL,
          fingerprint TEXT NOT NULL, priority TEXT NOT NULL, remediation TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS findings_scope ON findings(scope);
        CREATE INDEX IF NOT EXISTS findings_open ON findings(remediation,priority);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL,
          finding_key TEXT, scope TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL,
          priority TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, sent_at TEXT,
          attempts INTEGER NOT NULL DEFAULT 0, next_retry TEXT, last_error TEXT);
        CREATE TABLE IF NOT EXISTS feeds(name TEXT PRIMARY KEY, last_success TEXT, last_attempt TEXT,
          status TEXT NOT NULL, error TEXT, etag TEXT, modified TEXT, payload TEXT);
        """)
        self.db.execute(f"PRAGMA user_version={SCHEMA}")
        self.db.commit()

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json_text(value)))

    def queue(self, key, payload, priority="P3"):
        self.db.execute("INSERT OR IGNORE INTO outbox(event_key,priority,payload,created_at) VALUES(?,?,?,?)",
                        (key, priority, json_text(payload), utcnow()))

    def event(self, scope, kind, finding_key, revision, payload):
        key = digest([scope, kind, finding_key, revision])
        self.db.execute("INSERT OR IGNORE INTO events(event_key,finding_key,scope,kind,created_at,payload) VALUES(?,?,?,?,?,?)",
                        (key, finding_key, scope, kind, utcnow(), json_text(payload)))
        return {"key": key, "kind": kind, **payload}

    def run_failed(self, scope, error, duration=0):
        now = utcnow()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            prev = self.db.execute("SELECT status FROM runs WHERE scope=?", (scope,)).fetchone()
            self.db.execute("""INSERT INTO runs(scope,last_attempt,status,error,duration) VALUES(?,?,?,?,?)
              ON CONFLICT(scope) DO UPDATE SET last_attempt=excluded.last_attempt,status=excluded.status,
              error=excluded.error,duration=excluded.duration""", (scope, now, "error", error, duration))
            self.db.execute("INSERT INTO run_history(scope,at,status,duration,payload) VALUES(?,?,?,?,?)",
                            (scope, now, "error", duration, json_text({"error": error})))
            if not prev or prev[0] != "error":
                key = "scan-failed:" + digest([scope, now])
                self.queue(key, {"kind": "health", "scope": scope, "text": "Ошибка проверки: " + error}, "SYSTEM")

    def reconcile(self, scope, rows, snapshot, verify_missing, duration=0):
        """Only called after a complete, validated scan. One atomic state transition."""
        now = utcnow()
        changes = []
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            baseline = not self.meta("baseline:" + scope, False)
            previous = {r["key"]: r for r in self.db.execute("SELECT * FROM findings WHERE scope=?", (scope,))}
            present = set()
            for item in rows:
                key = digest([scope, item["component"], item["vuln"]])
                if key in present:
                    raise MonitorError("Повтор ключа находки в результате сканера")
                present.add(key)
                payload = dict(item)
                payload.setdefault("remediation", "open")
                old = previous.get(key)
                old_data = json.loads(old["payload"]) if old else {}
                # A scan started before a KEV refresh must not erase positive exploitation evidence.
                if old_data.get("kev"):
                    payload["kev"] = True
                    if payload["applicability"] == "affected":
                        payload["priority"] = "P1"
                fingerprint = digest(payload)
                revision = old["revision"] + 1 if old else 1
                first = old["first_seen"] if old else now
                if not old or fingerprint != old["fingerprint"]:
                    kinds = ["new_finding"] if not old else []
                    if old:
                        if old["remediation"] == "remediated_verified":
                            kinds.append("finding_reopened")
                        if old_data.get("installed") != payload.get("installed"):
                            kinds.append("update_detected")
                        if not old_data.get("kev") and payload.get("kev"):
                            kinds.append("kev_added")
                        if ((old_data.get("upstream_fixed") != payload.get("upstream_fixed") and payload.get("upstream_fixed")) or
                                (old_data.get("vendor_fixed") != payload.get("vendor_fixed") and payload.get("vendor_fixed"))):
                            kinds.append("fix_published")
                        if old_data.get("fix_status") != "repo_fix_available" and payload.get("fix_status") == "repo_fix_available":
                            kinds.append("repo_fix_available")
                        if old["priority"] != payload["priority"]:
                            kinds.append("priority_changed")
                        if not kinds:
                            kinds.append("evidence_changed")
                    self.db.execute("""INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                                    (key, scope, payload["component"], payload["vuln"], first, now, revision,
                                     fingerprint, payload["priority"], payload["remediation"], json_text(payload)))
                    # Explicit column count checked by tests; events store changes, not entire advisories.
                    for kind in kinds:
                        changes.append(self.event(scope, kind, key, revision,
                                                  {"vuln": payload["vuln"], "component": payload["component"], "priority": payload["priority"],
                                                   "before": detail(old_data), "detail": detail(payload)}))
                else:
                    self.db.execute("UPDATE findings SET last_seen=? WHERE key=?", (now, key))
            for key in previous.keys() - present:
                old = previous[key]
                if old["remediation"] == "remediated_verified":
                    continue
                data = json.loads(old["payload"])
                resolution = verify_missing(data, snapshot)
                updated = {**data, **resolution}
                if digest(updated) != old["fingerprint"]:
                    revision = old["revision"] + 1
                    self.db.execute("UPDATE findings SET revision=?,fingerprint=?,remediation=?,payload=? WHERE key=?",
                                    (revision, digest(updated), updated["remediation"], json_text(updated), key))
                    kind = "remediation_verified" if updated["remediation"] == "remediated_verified" else "needs_reverification"
                    changes.append(self.event(scope, kind, key, revision,
                                              {"vuln": old["vuln"], "component": old["component"], "priority": old["priority"],
                                               "before": detail(data), "detail": detail(updated)}))
            previous_run = self.db.execute("SELECT status FROM runs WHERE scope=?", (scope,)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?)", (scope, now, now, "fresh", None, duration, len(present)))
            self.db.execute("INSERT OR REPLACE INTO snapshots VALUES(?,?,?)", (scope, now, json_text(snapshot)))
            self.db.execute("INSERT INTO run_history(scope,at,status,duration,payload) VALUES(?,?,?,?,?)",
                            (scope, now, "fresh", duration, json_text({"count": len(present), "artifact": snapshot.get("artifact"), "db_updated_at": snapshot.get("db_updated_at")})))
            if baseline:
                self.set_meta("baseline:" + scope, True)
                counts = {}
                ids = set()
                for item in rows:
                    counts[item["priority"]] = counts.get(item["priority"], 0) + 1
                    if item["priority"] == "P1":
                        ids.add(item["vuln"])
                self.queue("baseline:" + scope, {"kind": "baseline", "scope": scope, "count": len(present),
                                                 "counts": counts, "p1_ids": sorted(ids)[:12],
                                                 **message_details(sorted(rows, key=lambda x: x["priority"]))}, "P1" if ids else "P3")
            elif changes:
                for priority in ("P1", "P2", "P3"):
                    selected = [x for x in changes if x["priority"] == priority]
                    if selected:
                        self.queue(digest([x["key"] for x in selected]), {"kind": "changes", "scope": scope,
                                   "count": len(selected), "ids": sorted({x["vuln"] for x in selected})[:12],
                                   "kinds": sorted({x["kind"] for x in selected}), **message_details(selected)}, priority)
            if previous_run and previous_run[0] == "error":
                self.queue("scan-recovered:" + digest([scope, now]), {"kind": "health", "scope": scope, "text": "Проверка восстановлена"}, "SYSTEM")
        return {"scope": scope, "findings": len(present), "events": len(changes), "baseline": baseline}

    def findings(self, open_only=True, priorities=None):
        for row in self.db.execute("SELECT * FROM findings ORDER BY priority,vuln,component"):
            if open_only and row["remediation"] == "remediated_verified":
                continue
            if priorities and row["priority"] not in priorities:
                continue
            yield {**json.loads(row["payload"]), "scope": row["scope"], "first_seen": row["first_seen"], "last_seen": row["last_seen"]}

    def backup(self, destination):
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise MonitorError("Файл backup уже существует")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = sqlite3.connect(destination)
        try:
            self.db.backup(target)
            if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise MonitorError("Backup SQLite не прошёл quick_check")
        finally:
            target.close()
            destination.chmod(0o600)

    def maintenance(self):
        from .util import age_seconds
        import datetime as dt
        if age_seconds(self.meta("last-maintenance")) < 86400:
            return
        now = dt.datetime.now(dt.timezone.utc)
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at<?", ((now - dt.timedelta(days=90)).isoformat(),))
            self.db.execute("DELETE FROM run_history WHERE at<?", ((now - dt.timedelta(days=365)).isoformat(),))
            self.set_meta("last-maintenance", utcnow())
