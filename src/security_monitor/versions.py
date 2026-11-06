"""Native DPKG comparisons; conservative PHP/WordPress version comparison."""
import re
import subprocess

from .util import MonitorError, command_env


def dpkg_ge(installed, fixed):
    if not all(isinstance(v, str) and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,255}", v) for v in (installed, fixed)):
        return None
    try:
        result = subprocess.run(["dpkg", "--compare-versions", installed, "ge", fixed],
                                env=command_env(), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return True if result.returncode == 0 else False if result.returncode == 1 else None


_SPECIAL = {"dev": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4,
            "rc": -3, "pl": 1, "p": 1}


def wp_tokens(version):
    if not isinstance(version, str) or not re.fullmatch(r"\d[\w.+-]{0,99}", version, flags=re.ASCII):
        raise MonitorError("Неоднозначная версия WordPress/PHP")
    tokens = re.findall(r"\d+|[A-Za-z]+", version)
    if any(not t.isdigit() and t.lower() not in _SPECIAL for t in tokens):
        raise MonitorError("Неизвестный prerelease WordPress/PHP")
    return tokens


def wp_compare(left, right):
    a, b = wp_tokens(left), wp_tokens(right)
    for i in range(max(len(a), len(b))):
        x, y = a[i] if i < len(a) else "0", b[i] if i < len(b) else "0"
        if x.isdigit() and y.isdigit():
            one, two = int(x), int(y)
        else:
            one = 0 if x.isdigit() else _SPECIAL[x.lower()]
            two = 0 if y.isdigit() else _SPECIAL[y.lower()]
        if one != two:
            return 1 if one > two else -1
    return 0


def wp_affected(version, affected):
    """Wordfence keyed version ranges; malformed ranges never mean unaffected."""
    if not isinstance(affected, dict) or not affected:
        raise MonitorError("Отсутствуют диапазоны версий Wordfence")
    wp_tokens(version)
    matched = False
    for spec in affected.values():
        if not isinstance(spec, dict) or not {"from_version", "to_version", "from_inclusive", "to_inclusive"} <= set(spec):
            raise MonitorError("Изменилась схема диапазона Wordfence")
        lower, upper = spec["from_version"], spec["to_version"]
        if type(spec["from_inclusive"]) is not bool or type(spec["to_inclusive"]) is not bool:
            raise MonitorError("Неверные границы Wordfence")
        low = True if lower == "*" else wp_compare(version, lower) >= (0 if spec["from_inclusive"] else 1)
        high = True if upper == "*" else wp_compare(version, upper) <= (0 if spec["to_inclusive"] else -1)
        if low and high:
            matched = True
    return matched
