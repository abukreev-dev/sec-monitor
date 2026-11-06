# Runtime verification — 2026-11-06

This is a sanitized engineering record for the initial **pre-release**, not acceptance of every requirement in the original specification. Raw host inventories, configuration, credentials and scanner artifacts remain private.

## Environment and checks

Ubuntu 24.04.4 LTS, x86_64, Python 3.12, systemd, 16 GiB host RAM. External scanner: pinned Trivy 0.76.2, archive and executable SHA256 verified. This environment does not establish a whole-host 1 GiB RAM minimum.

| Check | Observed result |
|---|---|
| Automated suite | 70 tests pass locally (native DPKG test skipped on macOS); also run natively on Ubuntu |
| Real OS inventory/scan | Successful complete scan; subsequent identical scan produced no new finding events |
| KEV | Real catalog fetched and validated; exact CVE enrichment exercised |
| Application dependencies | Actual Trivy scan of a synthetic Python/Node project: 15 component findings; repeat produced no new events |
| Container image | Actual remote scan of an explicitly pinned public Alpine image digest; valid complete result, zero findings; repeat produced no new events |
| WordPress | Static synthetic plugin matched a synthetic Wordfence record; changing its file version verified metadata remediation; restoring the vulnerable version reopened the finding |
| Project execution | Synthetic postinstall/PHP execution sentinels were absent after scanning |
| Installation | Dedicated nologin user, immutable release directories, verified scanner, own launcher and units installed |
| systemd | Unit syntax verified; all five own jobs succeeded; all five timers enabled and active |
| Worker limits | MemoryMax 1 GiB, CPU quota one CPU, NoNewPrivileges; a real OS scan completed under the installed service limits |
| Diagnostics | Installed `doctor`: OK; SQLite schema 1, WAL, `quick_check`: OK |
| Backup/rollback | SQLite backup passed quick_check; own previous release restored, then current code reinstalled; repeated same-source installation was idempotent |
| Protected host files | SHA256 unchanged for package status, Ubuntu APT source configuration and SSH daemon configuration |
| Telegram | Real test accepted and receipt confirmed by the operator through an existing local HTTP CONNECT proxy; five queued messages accepted, immediate repeat sent zero. Mocked API tests cover rate limiting, retries and multipart resume |
| Wordfence live attempt | Authenticated response exceeded the original 128 MiB loader budget. Streaming normalization now has synthetic coverage; live retry awaits the provider's rate-limit window. No complete live feed was accepted yet |

Only the monitor's own files, account and units were installed or restarted. The monitor did not refresh APT indexes, upgrade packages, change applications, replace containers or restart workloads. Vulnerability database downloads are monitor data updates.

## Remaining boundaries

Debian runtime/installation, real Wordfence authenticated delivery, a full host reboot, small-memory host capacity and verified deployed application remediation remain untested. WordPress evidence is static file metadata, not proof of runtime code. A zero-finding image result is a scanner observation, not a security guarantee.

See [coverage](COVERAGE.md) for implementation gaps and [operations](OPERATIONS.md) for safe administration. GitHub Actions records validation against each published commit.
