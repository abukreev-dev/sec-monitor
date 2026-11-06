# Технический план v0.1

Согласованный подход: самостоятельный open-source `sec-monitor`, Trivy 0.76.2 как внешний процесс; форк не нужен. Экспериментальный профиль — Ubuntu 24.04 x86_64. Debian — кандидат без runtime-приёмки. Статус реализации pre-release; исходный план сохраняется ниже, фактические ограничения перечислены в COVERAGE.

## Реализация

1. Python >=3.10, стандартная библиотека, JSON-конфигурация, SQLite. Запуск из clone без pip-зависимостей; инструменты загружаются только явной командой bootstrap. Токены читаются из отдельного файла 0600.
2. Ограниченная read-only инвентаризация: dpkg/APT origins и candidates, kernel, сервисы, настроенные каталоги, контейнеры только при доступном локальном socket. Ни установки пакетов, ни APT refresh.
3. Trivy rootfs/fs/image, компактный JSONL с маркерами схемы и окончания, pin версии, telemetry off, explicit vuln-only. Результат принимается только целиком, после проверки exit status, fresh DB и структуры. Артефакты приватные, атомарные, с retention.
4. KEV и Wordfence V3: кэш, условные запросы, backoff, schema validation. Ошибка не заменяет предыдущие данные. Применимость стороннего пакета не подтверждается Ubuntu CVE по одному имени.
5. Независимые applicability/fix/remediation/health, события в транзакции, baseline отдельно по scope, durable outbox. Исчезновение без version/fix evidence требует перепроверки. Повторный одинаковый результат не создаёт новых уведомлений.
6. Русские text/JSON отчёты, группировка связанных kernel-компонентов с сохранением всех связей; минимальные сообщения без путей/секретов. Telegram timeout/429/ok=false; accepted не равно read.
7. Явные адаптеры приложений, WordPress и образов: не исполняют проектный код; сайты/каталоги и immutable image digests настраиваются. Нет Docker-группы у службы; нет WP-CLI bootstrap по умолчанию. Неизвестный slug/version и отсутствие feed-ключа — coverage gap.
8. Ручные install/update/rollback/uninstall монитора с собственным пользователем и отдельными oneshot timers. CI, fixtures, failure/injection tests, инструкция восстановления, лицензия, SECURITY и CONTRIBUTING.

## Footprint экспериментальной установки

- Код и проверенный Trivy: `/opt/security-monitor/releases/<version>/`, переключатель `current`, предыдущая версия для rollback.
- Только собственные файлы: `/etc/security-monitor/config.json`, секреты при предоставлении, `/var/lib/security-monitor/` (SQLite/cache/private artifacts), launcher `/usr/local/bin/security-monitor`.
- Системный пользователь/группа `security-monitor`, без shell/login/sudo/Docker-группы. Конфигурация root-owned, состояние доступно только пользователю монитора и root.
- Units `security-monitor-{scan,feeds,health,notify,digest}.service/.timer`, sandbox, CPUQuota 100%, MemoryMax 1G, swap 0, Nice 10; тяжёлые задачи сериализованы flock. Timer enable — отдельное действие установки/проверки после smoke.
- Никаких новых слушающих портов, cron других приложений, apt/dpkg installs/upgrades/refresh, изменений nginx/PHP/SSH/firewall/Docker. Перезапуск возможен только у собственных units монитора.
- Отсутствие Telegram credentials не блокирует локальный режим и установку, но доставка остаётся непроверенной.

## Верификация и границы

Fixtures и mocked APIs проверяют lifecycle, backports, source drift, очередь, секреты и malformed input. На экспериментальном хосте — реальные inventory/OS scan, повтор без событий, timer syntax, startup/restart собственного job, backup/restore на копии, dry-run/идемпотентность/rollback своего install. Снимки системной пакетной базы/конфигов до и после. Реальный Telegram — только с предоставленными реквизитами.

Первый стабильный runtime-профиль — Ubuntu 24.04 x86_64. Другие Linux могут выполнять read-only CLI по поддерживаемым возможностям, но установка timers без явного допуска для непроверенной ОС запрещена. Debian, полная перезагрузка host, Wordfence с настоящим ключом и изменение реальных пакетов не объявляются проверенными без доказательств.
