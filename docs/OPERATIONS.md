# Эксплуатация v0.1

Статус pre-release. Linux, Python >=3.10, локальная FS. Проверенный профиль OS-сканирования — Ubuntu 24.04 x86_64. Debian требует приёмки; `allow_untested_os` — допуск к экспериментальной установке, а не подтверждение поддержки.

## Конфигурация

`--config PATH` указывается перед командой. Без него читается `/etc/security-monitor/config.json`, если существует, иначе `~/.config/sec-monitor/config.json`. `configure` создаёт настройки, не включая службы. [Пример](../config.example.json): замените `/home/USER` своими путями либо используйте мастер.

`server_name` — псевдоним без IP. `timezone` задаёт зону дайджеста (09:00). `discovery_roots` ограничены глубиной/временем; найденные проекты не включаются автоматически. Области задаются явно:

```json
{
  "apps": [{"name": "shop", "path": "/srv/shop"}],
  "wordpress": [{"name": "blog", "path": "/var/www/blog"}],
  "containers": []
}
```

Для контейнера: `{"name":"api","image":"registry.example/app@sha256:<64 hex>"}` с реальным digest либо `{"name":"api","archive":"/private/image.tar"}`. `latest` не принимается. Службе не выдаются Docker socket, root, sudo, дополнительные группы или массовые ACL. Недоступные пути дают явный coverage gap.

## Секреты

[.env.example](../.env.example) копируется вне Git, права 0600. Это буквальные `KEY=value`, не shell-скрипт. Поддерживаются TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WORDFENCE_API_KEY. Боту нужно разрешить диалог (`/start`) или добавить его в чат.

`notifications_enabled=false` сохраняет события локально. `notifications test` явно отправляет тест даже до фонового включения. `notifications flush` отправляет очередь при включённом канале; `retry-failed` сбрасывает ожидание. API acknowledgement не означает прочтение. Сетевой timeout после принятия Telegram может дать дубль.

После долгой работы без канала просмотрите очередь и отчёт до первого flush. Wordfence требует личный ключ и собственные условия/attribution. Без ключа настроенная WordPress-область сообщает об ошибке; отсутствие WordPress в настройках не является ошибкой.

## Установка и команды

`install --dry-run` показывает собственный footprint. Установка требует root и не вызывает APT. Пути: `/opt/security-monitor/releases`, `current`, `/etc/security-monitor`, `/var/lib/security-monitor`, launcher `/usr/local/bin/security-monitor`. Config root-owned 0640; секреты сервисного пользователя 0600; данные 0700. Таймеры включаются отдельно.

Обычные команды установленного CLI автоматически понижают root до пользователя состояния. Административные install/service/rollback/uninstall остаются root-операциями. Активный релиз — отдельная root-owned копия, независимая от checkout.

```sh
security-monitor status
security-monitor doctor
security-monitor scan --target all
security-monitor feeds refresh --source all
security-monitor report --severity P1,P2
security-monitor report --format json --limit 0
security-monitor report --include-closed
security-monitor notifications status
security-monitor notifications flush
sudo security-monitor service enable
sudo security-monitor service disable
security-monitor service status
```

Скан не обновляет пакеты и не перезапускает приложения. Команды в рекомендациях — текст для администратора; строки advisory не исполняются.

## Расписание и ресурсы

Scan timer раз в час проверяет сроки: OS — 6 часов, apps — 12, images — 24, WordPress — час. Изменённая настройка проекта/digest сбрасывает отсрочку. Feeds/health — 15 минут, scheduled Wordfence не чаще часа, notify — минута, дайджест — сутки. Jitter/flock сериализуют тяжёлые задачи; `Persistent=true` восстанавливает календарное расписание. Реальный reboot host не считается проверенным по одному наличию этой директивы.

CPUQuota 100%, MemoryMax 1 GiB, swap 0, Nice 10, IOWeight 10, timeout 600 секунд, GOMEMLIMIT 600MiB. Большой проект может превысить бюджет: это отказ с сохранением старых находок. Замер сканера под лимитом 1 GiB не является приёмкой всего VPS с 1 GiB RAM.

Перед сканом требуется 3 GiB свободного места. Отдельный файл Trivy ограничен 2 GiB; рост базы сверх бюджета даёт ошибку вместо заполнения всего диска. Hard memory/CPU sandbox относится к установленным systemd jobs; ручной CLI использует timeout/Go soft memory limit и file-size limit, но не создаёт собственную memory cgroup.

APT indexes не обновляются монитором. Без успешного refresh stamp/при старых индексах доступность пакета неизвестна. CVE DB — данные в собственном кэше, не обновление программ. Для начальной DB и временных файлов оставьте несколько GiB свободного места.

Health удаляет только доставленные outbox-записи старше 90 дней и run-history старше года; недоставленные сообщения, findings и история событий не удаляются. SQLite использует освобождённые страницы повторно; это не обещание немедленного уменьшения файла на диске.

## Ручное обновление и rollback

Из проверенного checkout/release:

```sh
sudo ./security-monitor --config /etc/security-monitor/config.json install --dry-run
sudo ./security-monitor --config /etc/security-monitor/config.json install
security-monitor doctor
```

Релиз копируется отдельно, `current` переключается атомарно, предыдущий путь сохраняется. Config сохраняется; останавливаются только собственные units. Перед upgrade SQLite копируется backup API в приватный `/etc/security-monitor/backups`; ранее включённые таймеры восстанавливаются. Runtime jobs не выполняют git pull/pip install или self-update.

`sudo security-monitor rollback` переключает previous и оставляет таймеры выключенными до проверки. Несовместимая схема БД блокирует автоматический откат. Текущая схема v1; будущая миграция требует проверки восстановления. Повторный install того же source hash идемпотентен.

## Backup и восстановление

```sh
security-monitor backup /var/lib/security-monitor/backup-manual.sqlite3
```

Файл не перезаписывается, backup проходит `PRAGMA quick_check`. Для восстановления остановите свои таймеры/jobs, сохраните исходные БД и WAL/SHM как остановленный набор, config/secrets и совместимый код. Восстановленную копию проверьте quick_check, задайте владельца `security-monitor:security-monitor`, права 0600/0700. Не копируйте основной файл активной WAL-базы обычным cp.

Перед `service enable` проверьте doctor, историю, очередь и тестовую доставку. Не запускайте backup как второй production instance на другом хосте: namespace состояния принадлежит одному серверу.

## Удаление

```sh
sudo security-monitor uninstall --dry-run
sudo security-monitor uninstall
# Отдельное решение удалить историю и секреты:
sudo security-monitor uninstall --purge
```

По умолчанию данные/config сохраняются. Purge удаляет их; системный пользователь без shell и ownership marker `/etc/security-monitor/.managed` остаются для безопасного повторного узнавания своей учётной записи. Независимый Trivy, пакеты и чужие службы не удаляются.

## Диагностика

`doctor`: версия/хэш Trivy, SQLite, диск, freshness. `health --record`: переходы health и лёгкие APT-наблюдения. Последние inventory snapshots и неизменяемые события находятся в БД; приватные JSONL артефакты сохраняются 14 дней. Одна БД — один хост.

Журналы: `journalctl -u security-monitor-scan.service` и соответствующие feed/health/notify units. Не публикуйте сырые логи/config. `rc=0` принимается только вместе со схемой и маркером окончания Trivy output. Полный инвентарь предназначен администратору, а не для GitHub issues.
