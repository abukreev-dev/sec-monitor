"""Private observations -> compact public-safe summaries and manual instructions."""
import json
import shlex
from collections import Counter

from .util import clean_text, safe_url
from .labels import label


def instructions(row):
    if row["applicability"] != "affected":
        return ["Применимость не подтверждена. Проверьте происхождение пакета/slug и advisory; не применяйте Ubuntu-фикс к сторонней сборке автоматически."]
    result = []
    if row.get("source") in {"ubuntu", "debian"}:
        package = row["component"]
        if row.get("repo_fixed") and row.get("fix_status") == "repo_fix_available":
            result += ["Доступный пакет подтверждён локальными APT metadata. Сначала backup и просмотр плана; выполнение только администратором.",
                       "Ниже пример для одного компонента; у группы проверьте все связанные пакеты.",
                       "Проверка: apt-cache policy " + shlex.quote(package),
                       "План: sudo apt-get --simulate install --only-upgrade " + shlex.quote(package + "=" + row["repo_fixed"])]
            if row.get("held"):
                result.append("Пакет held/pinned: решение об изменении ограничений принимает администратор.")
        elif row.get("vendor_fixed"):
            result.append("Поставщик указывает исправленную сборку, но её доступность в ваших репозиториях не подтверждена. Проверьте APT metadata вручную.")
        else:
            result.append("Исправление для пакета не подтверждено. Изучите vendor advisory и допустимые меры снижения риска.")
        if package.startswith("linux-"):
            result.append("Различайте установленные пакеты и работающее ядро (uname -r). Перезагрузку планирует администратор.")
    elif row.get("source") == "wordfence":
        result.append("Проверьте источник компонента и резервную копию сайта; обновление core/плагина/темы выполняется вручную по advisory.")
    else:
        result.append("Исправьте зависимость либо пересоберите образ вручную по advisory; изменение lockfile не доказывает обновление работающего приложения.")
    result.append("После ручных действий повторите security-monitor scan. Монитор не выполняет обновления и рестарты.")
    return result


def grouped(store, priorities=None, open_only=True):
    groups = {}
    for row in store.findings(open_only=open_only, priorities=priorities):
        key = (row["scope"], row["vuln"], row.get("source_package", row["component_label"]),
               row["priority"], row["applicability"], row["fix_status"], row["remediation"])
        if key not in groups:
            groups[key] = {"scope": row["scope"], "vuln": row["vuln"], "priority": row["priority"],
                           "component": clean_text(row.get("source_package", row["component_label"])),
                           "applicability": row["applicability"], "fix_status": row["fix_status"],
                           "remediation": row["remediation"], "severity": row["severity"], "kev": row.get("kev", False),
                           "source": row.get("source"), "url": safe_url(row.get("url")), "cvss": row.get("cvss", {}),
                           "first_seen": row["first_seen"], "last_seen": row["last_seen"], "links": 0,
                           "installed": set(), "vendor_fixed": set(), "upstream_fixed": set(), "repo_fixed": set(),
                           "instructions": instructions(row), "notice": row.get("notice", {}),
                           "runtime_verification": row.get("runtime_verification", "unknown")}
        group = groups[key]
        group["links"] += 1
        group["installed"].add(row["installed"])
        for field in ("vendor_fixed", "repo_fixed"):
            if row.get(field):
                group[field].add(row[field])
        group["upstream_fixed"].update(row.get("upstream_fixed", []))
    result = []
    for g in groups.values():
        for k in ("installed", "vendor_fixed", "upstream_fixed", "repo_fixed"):
            g[k] = sorted(g[k])
        result.append(g)
    return sorted(result, key=lambda x: (x["priority"], x["scope"], x["vuln"], x["component"]))


def text_report(groups, limit=50):
    counts = Counter(g["priority"] for g in groups)
    lines = ["Security Monitor — локальный отчёт", "Групп находок: " + str(len(groups)),
             "Приоритеты: " + (", ".join(f"{p}: {n}" for p, n in sorted(counts.items())) or "нет"),
             "Отсутствие находок не доказывает безопасность; проверьте health и coverage."]
    notices = {}
    for g in groups[:limit] if limit else groups:
        lines += ["", f"[{g['priority']}] {g['vuln']} · {clean_text(g['component'])} · {g['scope']}",
                  "Установлено: " + ", ".join(clean_text(v) for v in g["installed"]),
                  f"Применимость: {label(g['applicability'])} | исправление: {label(g['fix_status'])} | устранение: {label(g['remediation'])}",
                  f"KEV: {'да' if g['kev'] else 'нет подтверждения'} | связанных компонентов: {g['links']}",
                  "Исправленная vendor-версия: " + (", ".join(g["vendor_fixed"]) or "неизвестно"),
                  "Доступно в репозитории: " + (", ".join(g["repo_fixed"]) or "не подтверждено"),
                  "Upstream fix: " + (", ".join(g["upstream_fixed"]) or "неизвестно"),
                  "Источник: " + str(g["source"]) + " " + g["url"],
                  *g["instructions"]]
        if g["notice"]:
            notices[json.dumps(g["notice"], sort_keys=True)] = g["notice"]
    if limit and len(groups) > limit:
        lines.append(f"\nПоказано {limit} из {len(groups)} групп. --limit 0 выводит все.")
    for notice in notices.values():
        lines.append("\nAttribution источника: " + json.dumps(notice, ensure_ascii=False))
    return "\n".join(lines)
