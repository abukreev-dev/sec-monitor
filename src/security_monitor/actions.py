"""Evidence-based operator actions. This module never executes a recommendation."""
import re

from .versions import dpkg_ge


def kernel_evidence(row, snapshot, cache=None):
    cache = {} if cache is None else cache
    if not re.match(r"^linux-(?:image|headers|modules)(?:-extra)?-\d", row["component"]):
        # User-space tools must not be declared fixed by booting another kernel.
        if row["component"].startswith("linux-tools-"):
            for field in ("kernel_state", "running_kernel", "fixed_kernel"):
                row.pop(field, None)
            row["runtime_verification"] = "installed_package_only"
        return
    running = snapshot.get("running_kernel")
    row.update(running_kernel=running, kernel_state="unknown", fixed_kernel=None)
    fixed = row.get("vendor_fixed")
    match = re.fullmatch(r"(\d+\.\d+)\.\d+-\d+-(.+)", running or "")
    if not fixed or not match or row.get("applicability") != "affected":
        return
    branch = re.search(r"-(\d+\.\d+)\.\d+-", row["component"])
    if not branch or branch[1] != match[1]:
        return
    packages = snapshot.get("packages", {})
    expected = {"ubuntu": "Ubuntu", "debian": "Debian"}.get(snapshot.get("platform", {}).get("id"))
    current = packages.get("linux-image-" + running) or packages.get("linux-image-unsigned-" + running)
    if not expected or not current or current.get("origin") != expected:
        return

    def ge(version):
        key = (version, fixed)
        if key not in cache:
            cache[key] = dpkg_ge(version, fixed)
        return cache[key]

    current_fixed = ge(current.get("source_version") or current["version"])
    if current_fixed is True:
        row.update(kernel_state="running_fixed_old_package", runtime_verification="running_kernel_version_checked")
        return
    if current_fixed is not False:
        return
    image_key = ("images", match[1], match[2], fixed, expected)
    if image_key not in cache:
        candidates = []
        for name, package in packages.items():
            image = re.fullmatch(r"linux-image-(?:unsigned-)?((\d+\.\d+)\.\d+-\d+-(.+))", name)
            if (image and image[2] == match[1] and image[3] == match[2] and package.get("origin") == expected and
                    ge(package.get("source_version") or package["version"]) is True):
                candidates.append(image[1])
        cache[image_key] = sorted(candidates)
    candidates = cache[image_key]
    row.update(kernel_state="running_affected_fix_installed" if candidates else "running_affected",
               fixed_kernel=sorted(candidates)[0] if candidates else None,
               runtime_verification="running_kernel_version_checked")


def recommendation(row):
    if row.get("remediation") == "remediated_verified":
        return {"code": "verified", "summary": "Пакетное исправление проверено; отдельно проверьте работающие процессы.", "steps": []}
    if row.get("remediation") == "update_installed_pending_verification":
        version = row.get("observed_version", "неизвестна")
        if row.get("installed_fix_confirmed"):
            return {"code": "fix_pending_scan", "summary": "Исправленная версия уже установлена; ожидается подтверждение следующим сканированием.",
                    "reason": "Обнаружена установленная версия: " + str(version), "steps": []}
        return {"code": "version_pending_scan", "summary": "Версия пакета изменилась; монитор проверит исправление при следующем сканировании.",
                "reason": "Обнаружена установленная версия: " + str(version) + "; применимость исправления пока не подтверждена.", "steps": []}
    state = row.get("kernel_state")
    if state == "running_affected_fix_installed":
        return {"code": "reboot_required", "summary": "Запланировать перезагрузку: исправленное ядро уже установлено.",
                "reason": f"Работает {row['running_kernel']}; установлен подходящий образ {row['fixed_kernel']}.",
                "steps": ["Согласуйте окно обслуживания и проверьте выбор ядра при загрузке.",
                          "После перезагрузки: uname -r; затем security-monitor scan --target os."]}
    if state == "running_fixed_old_package":
        return {"code": "inactive_kernel", "summary": "Срочное действие по работающему ядру не требуется; проверить оставшиеся старые пакеты.",
                "reason": f"Работающее ядро {row['running_kernel']} не ниже известной исправленной сборки для этой CVE.",
                "steps": ["Старый установленный пакет остаётся находкой. Сохраните резервное ядро; удаление решает администратор."]}
    if row.get("verification", "").startswith("Компонент больше не найден"):
        return {"code": "component_absent", "summary": "Пакет больше не обнаружен; запись сохранена для истории.",
                "reason": "Удаление пакета не подтверждает состояние работающих процессов или других копий.", "steps": []}
    if row.get("applicability") != "affected":
        return {"code": "review_applicability", "summary": "Монитор не смог подтвердить применимость и выбрать обновление; нужна ручная оценка advisory.",
                "reason": row.get("applicability_reason", "Источник или применимость требуют проверки."), "steps": []}
    if row.get("fix_status") == "repo_fix_available" and row.get("repo_fixed"):
        return {"code": "plan_update", "summary": "Подготовить ручное обновление пакета до доступной исправленной версии.",
                "reason": "Доступная версия: " + str(row["repo_fixed"]),
                "steps": ["Проверьте план зависимостей и резервную копию; команды проверки есть в локальном отчёте."]}
    if row.get("vendor_fixed") or row.get("upstream_fixed"):
        return {"code": "check_fix_availability", "summary": "Монитор не подтвердил доступность исправления в настроенных источниках; нужна проверка APT и advisory.",
                "steps": []}
    return {"code": "monitor_advisory", "summary": "Монитор не установил наличие исправления; нужна оценка условий эксплуатации и advisory.",
            "steps": []}


def summaries(items, limit=3):
    result, seen = [], set()
    for item in items:
        action = item.get("action") or recommendation(item)
        key = (action["code"], action["summary"], action.get("reason"))
        if key not in seen:
            seen.add(key)
            result.append(action)
            if len(result) == limit:
                break
    return result
