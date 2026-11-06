"""Small, bounded I/O primitives shared by collectors and services."""
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class MonitorError(Exception):
    """An actionable error whose message is safe to show to the operator."""


class BusyError(MonitorError):
    pass


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def age_seconds(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return float("inf")
        return (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds()
    except (ValueError, TypeError, AttributeError):
        return float("inf")


def json_text(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(json_text(obj).encode()).hexdigest()


def private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise MonitorError("Каталог данных не должен быть symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.geteuid():
        raise MonitorError("Каталог данных принадлежит другому пользователю")
    path.chmod(0o700)
    return path


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise MonitorError("Отказ от записи через symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".secmon-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            out.write(content.encode() if isinstance(content, str) else content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextlib.contextmanager
def lock(path):
    path = Path(path)
    if path.is_symlink():
        raise MonitorError("Lock file не должен быть symlink")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BusyError("Другая задача уже работает; повторите позже") from None
        yield
    finally:
        os.close(fd)


def clean_text(value, maximum=300):
    return re.sub(r"[\x00-\x1f\x7f\ud800-\udfff]", " ", str(value))[:maximum]


def redact(value, secrets=()):
    value = str(value)
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"\d{6,}:[A-Za-z0-9_-]{15,}", "[REDACTED]", value)
    value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return value


def safe_url(value):
    try:
        parts = urlsplit(value or "")
        if parts.scheme not in {"https", "http"} or not parts.hostname or parts.username or parts.password:
            return ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except (TypeError, ValueError):
        return ""


def command_env(extra=None):
    # Never forward SSH credentials, bot tokens, or project environment to tools.
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for key in ("HOME", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    env.update(extra or {})
    return env


def run(argv, timeout=30, max_output=16 * 1024 * 1024, env=None):
    """No shell. Bound output on disk, kill the complete child process group."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen([str(x) for x in argv], stdout=out, stderr=err,
                                    env=command_env(env), start_new_session=True)
        except OSError:
            raise MonitorError(f"Не удалось запустить {Path(argv[0]).name}") from None
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise MonitorError(f"Timeout: {Path(argv[0]).name}") from None
        out.seek(0)
        err.seek(0)
        data = out.read(max_output + 1)
        diagnostic = err.read(8192)
        if len(data) > max_output:
            raise MonitorError(f"Слишком большой ответ: {Path(argv[0]).name}")
        if proc.returncode:
            # Do not expose arbitrary tool output, URLs or config fragments.
            raise MonitorError(f"{Path(argv[0]).name}: exit {proc.returncode}")
        return data.decode("utf-8", "replace"), diagnostic.decode("utf-8", "replace")


def bounded_json(path, limit=8 * 1024 * 1024):
    path = Path(path)
    if path.stat().st_size > limit:
        raise MonitorError("JSON превышает допустимый размер")
    try:
        return json.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise MonitorError("Некорректный JSON") from None
