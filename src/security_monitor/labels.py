"""Human labels; stable machine enums stay unchanged in JSON and SQLite."""
LABELS = {
    "affected": "подтверждена", "potentially_affected": "возможна, требуется проверка",
    "unknown": "неизвестно", "not_affected": "не затронуто",
    "open": "открыто", "remediated_verified": "пакетное исправление проверено",
    "needs_reverification": "нужна перепроверка",
    "update_installed_pending_verification": "изменение версии обнаружено, проверка не завершена",
    "repo_fix_available": "исправление доступно в репозитории",
    "vendor_fix_available": "поставщик опубликовал исправленную сборку",
    "upstream_fix_available": "исправление опубликовано upstream",
    "no_vendor_fix_known": "исправление поставщика не подтверждено",
    "no_fix_known": "исправление не подтверждено", "no_fix_available": "исправление не известно источнику",
    "new_finding": "новая находка", "kev_added": "добавление в KEV",
    "fix_published": "публикация исправления", "update_detected": "изменение установленной версии",
    "priority_changed": "изменение приоритета", "evidence_changed": "изменение доказательств",
    "finding_reopened": "повторное открытие", "remediation_verified": "устранение проверено",
    "fresh": "данные свежие", "stale": "данные устарели", "error": "ошибка проверки",
    "not_scanned": "ещё не проверено", "not_loaded": "ещё не загружено",
    "disabled": "отключено", "disabled_with_open_findings": "отключено при открытых находках",
}


def label(value):
    return LABELS.get(value, value)
