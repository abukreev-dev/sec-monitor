"""Telegram plain text, strict API acknowledgement, persistent retries."""
import datetime as dt
import json
import os
import tempfile
import time
from zoneinfo import ZoneInfo

from .feeds import HTTPFailure, request_json
from .util import MonitorError, clean_text, lock, utcnow, private_dir
from .labels import label
from . import actions


def cvss_text(value):
    if not isinstance(value, dict):
        return "неизвестно"
    if type(value.get("score")) in {int, float}:
        return str(value["score"]) + " " + str(value.get("vector", ""))
    scores = []
    for source, metrics in sorted(value.items()):
        if isinstance(metrics, dict):
            for version in ("V4", "V3", "V2"):
                if type(metrics.get(version + "Score")) in {int, float}:
                    scores.append(f"{metrics[version + 'Score']} ({version}, {source})")
                    break
    return ", ".join(scores[:3]) or "неизвестно"


def render(cfg, payload, priority):
    heading = f"СВОДКА (максимум {priority})" if payload.get("kind") == "baseline" else priority
    lines = [f"Security Monitor — {heading}", "Сервер: " + cfg["server_name"],
             "Область: " + clean_text(payload.get("scope", "monitor"), 80)]
    kind = payload.get("kind")
    plans = payload.get("actions") or actions.summaries(payload.get("details", []))
    for plan in plans:
        lines += ["", "Что делать: " + plan["summary"]]
        if plan.get("reason"):
            lines.append("Почему: " + plan["reason"])
        lines.extend(plan.get("steps", []))
    if kind == "baseline":
        lines += ["Первичная сводка", "Связей компонент–уязвимость: " + str(payload["count"]),
                  "Приоритеты: " + ", ".join(f"{p}: {n}" for p, n in sorted(payload["counts"].items()))]
        if payload.get("p1_ids"):
            lines.append("P1 требуют внимания: " + ", ".join(payload["p1_ids"]))
    elif kind == "changes":
        lines += ["Событий: " + str(payload["count"]) + " (не число новых CVE)",
                  "Изменения: " + ", ".join(label(x) for x in payload.get("kinds", [])),
                  "Уязвимости: " + ", ".join(payload.get("ids", []))]
    elif kind == "digest":
        lines += ["Ежедневная сводка", payload["text"]]
        if payload.get("deferred_events"):
            lines += [f"Справочные события P3: {payload['deferred_events']}; уникальных CVE: {payload['deferred_cves']}.",
                      ", ".join(f"{label(k)}: {v}" for k, v in sorted(payload["deferred_kinds"].items()))]
    else:
        lines.append(payload.get("text", "Проверка уведомлений"))
    for d in payload.get("details", []):
        fixed = d.get("repo_fixed") or d.get("vendor_fixed") or ", ".join(d.get("upstream_fixed", [])) or "не подтверждено"
        lines += ["", f"{d.get('priority', 'приоритет не указан')} · {d.get('vuln')} · {d.get('component_label')}",
                  "Решение: " + actions.recommendation(d)["summary"],
                  ("Ранее обнаружено: " if d.get("observed_version") else "Установлено: ") + str(d.get("installed", "неизвестно")),
                  *(["Установлено при последней проверке пакетов: " + str(d["observed_version"])] if d.get("observed_version") else []),
                  "Применимость: " + label(d.get("applicability", "unknown")),
                  "Оценка: " + d.get("applicability_reason", "см. источник и локальный отчёт"),
                  "CVSS: " + cvss_text(d.get("cvss")) + " / KEV: " + ("да" if d.get("kev") else "нет подтверждения"),
                  "Исправление: " + label(d.get("fix_status", "unknown")) + " / " + fixed,
                  "Источник: " + str(d.get("source", "unknown")) + " " + str(d.get("url", ""))]
    if kind != "health":
        lines += ["Монитор ничего не обновляет. Сверьте advisory и источник пакета; изменения выполняет администратор. Затем повторите scan.",
                  "Подробности и инструкции: security-monitor report"]
    lines += ["Подготовлено: " + dt.datetime.now(ZoneInfo(cfg["timezone"])).isoformat(timespec="seconds")]
    for notice in payload.get("notices", []):
        lines += ["Attribution источника:", json.dumps(notice, ensure_ascii=False)]
    return "\n".join(clean_text(line, max(800, len(line))) for line in lines)


def message_parts(text, limit=3500):
    """Telegram limits are UTF-16 code units, not Python character count."""
    parts, current, length = [], [], 0
    for char in text:
        weight = 2 if ord(char) > 0xFFFF else 1
        if length + weight > limit:
            parts.append("".join(current))
            current, length = [], 0
        current.append(char)
        length += weight
    if current:
        parts.append("".join(current))
    return parts


def write_notification_log(store, row, payload, rendered, retention_days):
    """Keep the complete notification and the baseline findings in a private file."""
    directory = private_dir(store.directory / "notification-logs")
    destination = directory / ("notification-" + str(row["id"]) + ".jsonl")
    if destination.is_symlink():
        raise MonitorError("Журнал уведомления не должен быть symlink")
    if destination.exists():
        return destination
    fd, name = tempfile.mkstemp(prefix=".notification-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(json.dumps({"type": "notification", "created_at": row["created_at"],
                                  "logged_at": utcnow(), "priority": row["priority"], "text": rendered,
                                  "findings_note": "Текущее состояние на момент записи журнала" if payload.get("kind") == "baseline" else None}, ensure_ascii=False) + "\n")
            if payload.get("kind") == "baseline":
                for finding in store.db.execute("SELECT payload FROM findings WHERE scope=? ORDER BY priority,vuln,component", (payload.get("scope"),)):
                    out.write('{"type":"finding","data":' + finding[0] + '}\n')
            event_keys = payload.get("event_keys", [])
            for offset in range(0, len(event_keys), 500):
                batch = event_keys[offset:offset + 500]
                placeholders = ",".join("?" for _ in batch)
                for event in store.db.execute("SELECT event_key,kind,created_at,payload FROM events WHERE event_key IN (" + placeholders + ")", batch):
                    out.write(json.dumps({"type": "event", "key": event["event_key"], "kind": event["kind"],
                                          "created_at": event["created_at"], "data": json.loads(event["payload"])}, ensure_ascii=False) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, destination)
        for old in directory.glob("notification-*.jsonl"):
            if old != destination and old.is_file() and not old.is_symlink() and time.time() - old.stat().st_mtime > retention_days * 86400:
                old.unlink()
        return destination
    except OSError as exc:
        raise MonitorError("Не удалось сохранить полный журнал уведомления") from exc
    finally:
        if os.path.exists(name):
            os.unlink(name)


def compact_message(rendered, log_path, limit=3500):
    """Keep one UTF-16 bounded message with an explicit pointer to the full log."""
    suffix = "\n\nПолный журнал: " + str(log_path)
    if len((rendered + suffix).encode("utf-16-le")) // 2 <= limit:
        return rendered + suffix
    suffix = "\n\nСообщение сокращено." + suffix
    budget = limit - len(suffix.encode("utf-16-le")) // 2
    if budget <= 0:
        raise MonitorError("Путь журнала превышает лимит сообщения")
    return message_parts(rendered, budget)[0] + suffix


def send(credentials, text, fetch=request_json, proxy_url=None):
    token, chat = credentials.get("TELEGRAM_BOT_TOKEN"), credentials.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        raise MonitorError("Telegram не настроен: нужны TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID")
    if len(text.encode("utf-16-le")) // 2 > 4096:
        raise MonitorError("Telegram сообщение требует разбиения; содержимое не обрезано")
    body = json.dumps({"chat_id": chat, "text": text, "link_preview_options": {"is_disabled": True}}).encode()
    status, _, payload = fetch("https://api.telegram.org/bot" + token + "/sendMessage",
                               headers={"Content-Type": "application/json"}, data=body, limit=65536,
                               **({"proxy_url": proxy_url} if proxy_url else {}))
    if status != 200 or not isinstance(payload, dict) or payload.get("ok") is not True:
        retry = (payload.get("parameters") or {}).get("retry_after", 60) if isinstance(payload, dict) else 60
        raise HTTPFailure("Telegram не подтвердил доставку", retry if isinstance(retry, int) else 60)
    result = payload.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("message_id"), int):
        raise HTTPFailure("Telegram вернул неизвестную схему ответа", 120)
    return result["message_id"]


def flush(store, cfg, credentials, fetch=request_json):
    if not cfg["notifications_enabled"]:
        return {"mode": "local", "sent": 0, "pending": store.db.execute("SELECT count(*) FROM outbox WHERE sent_at IS NULL").fetchone()[0]}
    results = {"mode": "telegram", "sent": 0, "failed": 0, "parts_sent": 0}
    with lock(store.directory / "notify.lock"):
        rows = store.db.execute("""SELECT * FROM outbox WHERE sent_at IS NULL AND (next_retry IS NULL OR next_retry<=?)
          ORDER BY CASE priority WHEN 'P1' THEN 0 WHEN 'SYSTEM' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END,id LIMIT ?""",
                                (utcnow(), cfg["max_notifications_per_run"])).fetchall()
        for row in rows:
            if results["parts_sent"] >= cfg["max_notifications_per_run"]:
                break
            try:
                payload = json.loads(row["payload"])
                if "_parts" not in payload:
                    rendered = render(cfg, payload, row["priority"])
                    log = write_notification_log(store, row, payload, rendered, cfg["artifact_retention_days"])
                    payload["_parts"] = [compact_message(rendered, log)]
                    payload["_delivered_parts"] = 0
                    with store.db:
                        store.db.execute("UPDATE outbox SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), row["id"]))
                while payload["_delivered_parts"] < len(payload["_parts"]) and results["parts_sent"] < cfg["max_notifications_per_run"]:
                    send(credentials, payload["_parts"][payload["_delivered_parts"]], fetch, cfg.get("telegram_proxy_url"))
                    payload["_delivered_parts"] += 1
                    results["parts_sent"] += 1
                    with store.db:
                        store.db.execute("UPDATE outbox SET payload=?,attempts=attempts+1 WHERE id=?", (json.dumps(payload, ensure_ascii=False), row["id"]))
                if payload["_delivered_parts"] < len(payload["_parts"]):
                    break
                with store.db:
                    store.db.execute("UPDATE outbox SET sent_at=?,last_error=NULL WHERE id=?", (utcnow(), row["id"]))
                results["sent"] += 1
            except MonitorError as exc:
                delay = getattr(exc, "retry_after", min(3600, 30 * 2 ** min(row["attempts"], 7)))
                retry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=delay)).isoformat(timespec="seconds")
                with store.db:
                    store.db.execute("UPDATE outbox SET attempts=attempts+1,next_retry=?,last_error=? WHERE id=?",
                                     (retry, str(exc), row["id"]))
                results["failed"] += 1
                # Respect global Telegram outages/rate limits rather than retrying every queued message.
                break
    return results
