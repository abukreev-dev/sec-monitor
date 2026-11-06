"""Whole-feed downloads: no server inventory is sent to advisory providers."""
import datetime as dt
import codecs
import json
import re
import urllib.error
import urllib.request

from .util import MonitorError, age_seconds, digest, json_text, safe_url, utcnow
from .versions import wp_affected

URLS = {
    "kev": "https://raw.githubusercontent.com/CISAGov/kev-data/develop/known_exploited_vulnerabilities.json",
    "wordfence": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
}


class HTTPFailure(MonitorError):
    def __init__(self, message, retry_after=60):
        super().__init__(message)
        self.retry_after = max(30, min(retry_after, 86400))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, headers=None, data=None, limit=128 * 1024 * 1024, record_stream=False, proxy_url=None):
    req = urllib.request.Request(url, headers={"User-Agent": "sec-monitor/0.1", **(headers or {})}, data=data)
    try:
        proxy = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})
        with urllib.request.build_opener(proxy, NoRedirect()).open(req, timeout=30) as response:
            if record_stream and response.status == 200:
                return response.status, dict(response.headers), read_wordfence(response)
            body = response.read(limit + 1)
            if len(body) > limit:
                raise HTTPFailure("Ответ API превышает лимит размера", 3600)
            try:
                return response.status, dict(response.headers), json.loads(body)
            except (ValueError, UnicodeError):
                raise HTTPFailure("API вернул некорректный JSON", 300) from None
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, dict(exc.headers), None
        try:
            retry = int(exc.headers.get("Retry-After", 60))
        except (ValueError, TypeError):
            retry = 60
        try:
            error_body = json.loads(exc.read(65536))
            value = (error_body.get("parameters") or {}).get("retry_after")
            if type(value) is int:
                retry = value
        except (ValueError, OSError, AttributeError):
            pass
        finally:
            exc.close()
        raise HTTPFailure(f"API: HTTP {exc.code}", retry) from None
    except (OSError, TimeoutError):
        raise HTTPFailure("API недоступен или истёк timeout", 120) from None


def validate_kev(obj):
    if not isinstance(obj, dict) or not isinstance(obj.get("vulnerabilities"), list) or not obj["vulnerabilities"]:
        raise MonitorError("Изменилась схема KEV или каталог пуст")
    if not isinstance(obj.get("dateReleased"), str) or not isinstance(obj.get("catalogVersion"), str):
        raise MonitorError("KEV: отсутствует версия/время каталога")
    if age_seconds(obj["dateReleased"]) < -3600 or age_seconds(obj["dateReleased"]) == float("inf"):
        raise MonitorError("KEV: недостоверное время публикации")
    if type(obj.get("count")) is not int or obj["count"] != len(obj["vulnerabilities"]):
        raise MonitorError("KEV: count не совпадает с каталогом")
    records = {}
    for record in obj["vulnerabilities"]:
        if not isinstance(record, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", record.get("cveID", "")):
            raise MonitorError("KEV: некорректная запись")
        records[record["cveID"]] = {"dateAdded": record.get("dateAdded"),
                                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}
    return {"published_at": obj["dateReleased"], "version": obj["catalogVersion"], "records": records}


def validate_wordfence(obj):
    if not isinstance(obj, dict) or not obj:
        raise MonitorError("Изменилась схема Wordfence или feed пуст")
    records, notices = [], {}
    for key, record in obj.items():
        if not isinstance(record, dict) or record.get("id") != key or not isinstance(record.get("software"), list):
            raise MonitorError("Wordfence: неизвестная схема записи")
        if not re.fullmatch(r"[a-fA-F0-9-]{36}", key):
            raise MonitorError("Wordfence: неизвестный ID")
        software = []
        for item in record["software"]:
            if not isinstance(item, dict) or item.get("type") not in {"core", "plugin", "theme"} or not isinstance(item.get("slug"), str):
                raise MonitorError("Wordfence: неизвестный тип software")
            # Validate every range, not only ranges which happen to match the host.
            wp_affected("0.0.0", item.get("affected_versions"))
            patched = item.get("patched_versions", [])
            if not isinstance(patched, list) or not all(isinstance(x, str) for x in patched):
                raise MonitorError("Wordfence: неизвестные patched_versions")
            software.append({k: item.get(k) for k in ("type", "slug", "affected_versions", "patched", "patched_versions")})
        notice = record.get("copyrights") or {}
        if not isinstance(notice, dict):
            raise MonitorError("Wordfence: неизвестная схема copyright")
        notice_key = digest(notice)
        notices[notice_key] = notice
        cve = record.get("cve")
        if cve is not None and (not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)):
            raise MonitorError("Wordfence: некорректный CVE")
        records.append({"id": key, "cve": cve, "title": str(record.get("title", ""))[:500],
                        "software": software, "references": [safe_url(x) for x in record.get("references", []) if isinstance(x, str) and safe_url(x)],
                        "cvss": record.get("cvss"), "published": record.get("published"),
                        "updated": record.get("updated"), "notice_key": notice_key})
    return {"records": records, "notices": notices}


def read_wordfence(stream, limit=512 * 1024 * 1024, record_limit=8 * 1024 * 1024):
    """Decode the keyed catalog one advisory at a time, retaining only normalized data."""
    decoder, utf8 = json.JSONDecoder(), codecs.getincrementaldecoder("utf-8")()
    buffer, total, eof = "", 0, False

    def more():
        nonlocal buffer, total, eof
        chunk = stream.read(65536)
        total += len(chunk)
        if total > limit:
            raise HTTPFailure("Wordfence: каталог превышает лимит 512 MiB", 3600)
        eof = not chunk
        try:
            buffer += utf8.decode(chunk, final=eof)
        except UnicodeError:
            raise MonitorError("Wordfence: некорректная кодировка каталога") from None
        if len(buffer) > record_limit:
            raise HTTPFailure("Wordfence: запись превышает лимит размера", 3600)

    def whitespace():
        nonlocal buffer
        buffer = buffer.lstrip()
        while not buffer and not eof:
            more()
            buffer = buffer.lstrip()

    def token(expected):
        nonlocal buffer
        whitespace()
        if not buffer.startswith(expected):
            raise MonitorError("Wordfence: неполный или некорректный каталог")
        buffer = buffer[len(expected):]

    def value():
        nonlocal buffer
        whitespace()
        while True:
            try:
                result, end = decoder.raw_decode(buffer)
                buffer = buffer[end:]
                return result
            except ValueError:
                if eof:
                    raise MonitorError("Wordfence: неполный или некорректный JSON") from None
                more()

    records, notices, seen = [], {}, set()
    token("{")
    whitespace()
    if buffer.startswith("}"):
        raise MonitorError("Wordfence: пустой каталог")
    while True:
        key = value()
        if not isinstance(key, str) or key in seen:
            raise MonitorError("Wordfence: неизвестный или повторный ID")
        token(":")
        normalized = validate_wordfence({key: value()})
        seen.add(key)
        records.extend(normalized["records"])
        notices.update(normalized["notices"])
        whitespace()
        if buffer.startswith("}"):
            token("}")
            break
        token(",")
    whitespace()
    if buffer:
        raise MonitorError("Wordfence: лишние данные после каталога")
    return {"records": records, "notices": notices}


def refresh(store, name, credentials, fetch=request_json):
    if name not in URLS:
        raise MonitorError("Неизвестный источник")
    old = store.db.execute("SELECT * FROM feeds WHERE name=?", (name,)).fetchone()
    now = utcnow()
    retry = store.meta("retry-feed:" + name, {})
    deadlines = [retry.get("until")]
    if name == "wordfence":
        deadlines.append(store.meta("wordfence-next-request"))
    until = max((x for x in deadlines if x), default=None)
    if until and age_seconds(until) < 0:
        return {"source": name, "status": "backoff", "retry_at": until}
    headers = {}
    if old:
        if old["etag"]:
            headers["If-None-Match"] = old["etag"]
        if old["modified"]:
            headers["If-Modified-Since"] = old["modified"]
    try:
        if name == "wordfence":
            token = credentials.get("WORDFENCE_API_KEY")
            if not token:
                raise MonitorError("Для WordPress требуется WORDFENCE_API_KEY в secrets_file")
            headers["Authorization"] = "Bearer " + token
            # Reserve the provider budget before I/O, including interrupted downloads/parse failures.
            with store.db:
                store.set_meta("wordfence-next-request", (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat(timespec="seconds"))
        streamed = name == "wordfence" and fetch is request_json
        status, response_headers, body = fetch(URLS[name], headers=headers, **({"record_stream": True} if streamed else {}))
        if status == 304:
            if not old or not old["payload"]:
                raise MonitorError("API вернул 304 без валидного кэша")
            payload = json.loads(old["payload"])
        elif status == 200:
            payload = body if streamed else validate_kev(body) if name == "kev" else validate_wordfence(body)
        else:
            raise MonitorError("Неожиданный HTTP status источника")
        header = {k.lower(): v for k, v in response_headers.items()}
        with store.db:
            store.db.execute("INSERT OR REPLACE INTO feeds VALUES(?,?,?,?,?,?,?,?)",
                             (name, now, now, "fresh", None, header.get("etag", old["etag"] if old else None),
                              header.get("last-modified", old["modified"] if old else None), json_text(payload)))
            store.set_meta("retry-feed:" + name, {})
            if old and old["status"] != "fresh":
                store.queue("feed-recovered:" + digest([name, now]), {"kind": "health", "scope": name, "text": "Источник восстановлен"}, "SYSTEM")
        return {"source": name, "status": "fresh", "records": len(payload["records"])}
    except MonitorError as exc:
        error = str(exc)
        delay = getattr(exc, "retry_after", min(3600, 60 * 2 ** min(retry.get("failures", 0), 5)))
        if name == "wordfence" and error == "API: HTTP 429":
            delay = max(delay, 1800)
        until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=delay)).isoformat(timespec="seconds")
        with store.db:
            store.db.execute("""INSERT INTO feeds(name,last_attempt,status,error) VALUES(?,?,?,?)
              ON CONFLICT(name) DO UPDATE SET last_attempt=excluded.last_attempt,status=excluded.status,error=excluded.error""",
                             (name, now, "error", error))
            store.set_meta("retry-feed:" + name, {"until": until, "failures": retry.get("failures", 0) + 1})
            if not old or old["status"] == "fresh":
                store.queue("feed-failed:" + digest([name, now]), {"kind": "health", "scope": name, "text": error}, "SYSTEM")
        return {"source": name, "status": "error", "error": error}


def cached(store, name, max_age_hours, require_fresh=False):
    row = store.db.execute("SELECT * FROM feeds WHERE name=?", (name,)).fetchone()
    if not row or not row["payload"]:
        if require_fresh:
            raise MonitorError("Источник " + name + " ещё не загружен")
        return None
    stale = age_seconds(row["last_success"]) > max_age_hours * 3600
    if require_fresh and (stale or row["status"] != "fresh"):
        raise MonitorError("Источник " + name + " устарел/недоступен; старые находки сохранены")
    return json.loads(row["payload"])
