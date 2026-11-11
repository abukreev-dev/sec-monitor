# Actionable reports — 2026-11-11

Follow-up verification for the pre-release on Ubuntu 24.04 x86_64. This does not establish Debian support or acceptance of the complete original specification. Real inventories and database copies remain private.

The change addresses four operator problems: recommendations before scanner details, reference-only P3 changes in the daily digest, conservative applicability when vendor triage is not independently established, and separation of installed and running kernel images.

## Evidence

- 84 tests, including scenario tests for installed-but-not-running fixes, simulated reboot, remaining/removed old kernel packages, mismatched kernel branch/flavour/origin, unknown vendor status, digest persistence and no lost events after a repeated daily invocation.
- Replay of a private SQLite backup and the existing complete scanner artifact: first reconciliation records the new evidence policy; an identical repeat creates zero events. No advisory API or Telegram call is used by the replay.
- In the real host state, the running image is below a known fixed build and a suitable official fixed image is already installed. The generated message recommends a planned reboot and gives the reason and post-reboot checks before event counts.
- A simulated running-image change to the installed fixed image removes the corresponding runtime P1 classification, retaining KEV evidence and open old-package findings. The host was not rebooted.
- A fresh installed OS scan completed successfully with MemoryMax 1 GiB and CPUQuota 100%. The monitor's package inventory, APT source configuration and SSH configuration checksums were unchanged by the work.

Reference-only P3 events remain immutable in `events` and are indexed for the next daily digest. Creation of the durable digest outbox record and marking its included events happen in one SQLite transaction; delivery retries use the existing outbox. Immediate fix/KEV/update/runtime events retain separate notifications.

The additive `digest_events` table remains compatible with schema v1; no findings or historical events are deleted or reset. Reclassification changes may produce a larger one-time digest after this upgrade. A changed count does not itself imply a changed installed package or a newly exploitable host.

## Limits

There is no new live Ubuntu tracker adapter. The original Trivy status is preserved, but Ubuntu findings without a known fixed build remain potential applicability because compact engine evidence alone does not independently confirm current vendor triage. Genuinely affected unpatched packages can be in that group; potential does not mean safe.

The kernel check uses trusted installed image package versions of the same branch/flavour and native DPKG comparison. User-space `linux-tools` packages are excluded from the runtime inference: rebooting does not prove they are fixed. The check does not inspect bootloader choice, detect all livepatch states, prove library/process restarts or delete old packages. A real reboot and subsequent scan are still separate operator actions.

No Wordfence requests, OS package upgrades, APT index refreshes, workload restarts or host reboot were performed by this verification. Only the monitor's own code and jobs were managed. See [coverage](COVERAGE.md) and [operations](OPERATIONS.md).
