"""Telegram plain text, strict API acknowledgement, persistent retries."""
import datetime as dt
import json

from .feeds import HTTPFailure, request_json
from .util import MonitorError, clean_text, lock, utcnow


def render(cfg, payload, priority):
    lines = [f"Security Monitor — {priority}", "Сервер: " + cfg["server_name"],
             "Область: " + clean_text(payload.get("scope", "monitor"), 80)]
    kind = payload.get("kind")
    if kind == "baseline":
        lines += ["Первичная сводка", "Связей компонент–уязвимость: " + str(payload["count"]),
                  "Приоритеты: " + ", ".join(f"{p}: {n}" for p, n in sorted(payload["counts"].items()))]
        if payload.get("p1_ids"):
            lines.append("P1 требуют внимания: " + ", ".join(payload["p1_ids"]))
    elif kind == "changes":
        lines += ["Существенных событий: " + str(payload["count"]),
                  "Изменения: " + ", ".join(payload.get("kinds", [])),
                  "Уязвимости: " + ", ".join(payload.get("ids", []))]
    elif kind == "digest":
        lines += ["Ежедневная сводка", payload["text"]]
    else:
        lines.append(payload.get("text", "Проверка уведомлений"))
    for d in payload.get("details", []):
        fixed = d.get("repo_fixed") or d.get("vendor_fixed") or ", ".join(d.get("upstream_fixed", [])) or "не подтверждено"
        lines += ["", f"{d.get('vuln')} · {d.get('component_label')}",
                  "Установлено: " + str(d.get("installed", "неизвестно")),
                  "Применимость: " + str(d.get("applicability", "unknown")),
                  "Исправление: " + str(d.get("fix_status", "unknown")) + " / " + fixed,
                  "Источник: " + str(d.get("source", "unknown")) + " " + str(d.get("url", ""))]
    lines += ["Монитор ничего не обновляет. Сверьте advisory и источник пакета; изменения выполняет администратор. Затем повторите scan.",
              "Подробности и инструкции: security-monitor report", utcnow()]
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


def send(credentials, text, fetch=request_json):
    token, chat = credentials.get("TELEGRAM_BOT_TOKEN"), credentials.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        raise MonitorError("Telegram не настроен: нужны TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID")
    if len(text.encode("utf-16-le")) // 2 > 4096:
        raise MonitorError("Telegram сообщение требует разбиения; содержимое не обрезано")
    body = json.dumps({"chat_id": chat, "text": text, "link_preview_options": {"is_disabled": True}}).encode()
    status, _, payload = fetch("https://api.telegram.org/bot" + token + "/sendMessage",
                               headers={"Content-Type": "application/json"}, data=body, limit=65536)
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
                    payload["_parts"] = message_parts(render(cfg, payload, row["priority"]))
                    payload["_delivered_parts"] = 0
                    with store.db:
                        store.db.execute("UPDATE outbox SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), row["id"]))
                while payload["_delivered_parts"] < len(payload["_parts"]) and results["parts_sent"] < cfg["max_notifications_per_run"]:
                    send(credentials, payload["_parts"][payload["_delivered_parts"]], fetch)
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
