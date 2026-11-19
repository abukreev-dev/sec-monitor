# Coverage and support

This is a pre-release monitor, not an assurance that a host is safe. Each adapter has freshness and a separate coverage boundary.

| Area | Implemented behavior | Limits |
|---|---|---|
| Ubuntu 24.04 x86_64 | Native DPKG/APT inventory and pinned Trivy rootfs scanning | [Runtime verification](ACCEPTANCE_2026-11-06.md); arbitrary third-party builds are not fully covered |
| Debian / other Ubuntu releases | Shared read-only DPKG/APT adapter | Experimental until runtime/installer evidence exists; timers require explicit `allow_untested_os` |
| RPM, Alpine host, non-Linux | No host-adapter support | Unsupported; no success/zero-vulnerability claim |
| APT fixes | Installed origin, vendor fixed build, candidate origin/version, hold and metadata age | Reads existing indexes only; missing successful-refresh stamp means availability unknown. An old package no longer present in repositories has unknown origin |
| Backports | Vendor-specific Trivy evidence; native `dpkg --compare-versions` | No upstream-only version comparison for OS packages. Third-party/ambiguous origins are potentially affected, not confirmed |
| KEV | Whole official catalog, exact CVE match, reprioritization and events | No inference of host compromise. Failed fetch retains positive historical evidence and raises health degradation |
| WordPress | Static core/plugin/theme/MU metadata, Wordfence V3 ranges and notices | Configured paths; active status, auto-update and multisite DB enumeration unknown. Unverified slug/version is potential. Drop-ins/custom code require review. No WP-CLI/PHP execution |
| Application dependencies | Trivy on explicitly configured project directories | Declared dependencies/lockfiles, not proof of deployed runtime. No scripts/hooks executed. Multiple copies remain separate; disappearance requires manual verification |
| Container images | Explicit immutable registry digest or local archive; optionally discover running Docker image IDs and export one local image per collector run for an unprivileged scan | Separate root collector accesses Docker socket; scanner has no Docker group/socket. Only image contents are scanned, not writable layers, volumes, live configuration or deployment verification. Initial coverage takes multiple timer runs; health reports missing, failed and stale scans. No automatic image replacement |
| Runtime state | Running kernel compared with installed official images of the same branch/flavour and known vendor fixed build; explicit reboot recommendation | Unknown/custom/foreign images remain unverified. Loading a fixed kernel is a version observation, not proof of complete remediation; old packages remain open |
| Notifications | Action/reason first, durable outbox, plain-text Telegram; reference-only P3 changes collected in the daily digest | Fix/KEV/update/runtime transitions remain immediate. API acknowledgement does not prove reading. A timeout after Telegram accepts can duplicate a message |
| Early vendor signals | Trivy vendor database, KEV, Wordfence when configured | Per-product early-release RSS/vendor adapters and OSV API are not implemented. Self-compiled binaries/control panels are manual-review gaps |

No automatic updates, active exploitation, firewall actions, public listener, central SaaS or shared feed key are included.

## State interpretation

`applicability`, `fix_status`, `remediation` and adapter health are independent. `vendor_fix_available` means an advisory names a vendor build; it does not mean the build is currently obtainable from this host's configured repository. `repo_fix_available` additionally requires a fresh-enough successful APT refresh stamp, matching origin and a native version comparison.

A package removed from inventory, a CVE missing from a scan or an unavailable source yields `needs_reverification`, not `remediated_verified`. OS remediation requires a changed installed vendor version at least as new as the known fixed build plus a fresh successful scan. Process/library restarts remain unknown. Dependencies/images deliberately remain conservative until deployment can be verified.

`scanner_status` retains the engine's original status. Missing/unknown/under-investigation statuses never independently confirm applicability. Ubuntu findings without a known fixed build are conservatively `potentially_affected`: the compact engine data does not independently establish the current Ubuntu tracker triage state. This may include genuinely affected unpatched packages; it does not mean they are safe. There is no per-CVE live tracker lookup. See the [Trivy status definitions](https://github.com/aquasecurity/trivy-db/blob/main/pkg/types/status.go) and [Ubuntu adapter](https://github.com/aquasecurity/trivy-db/blob/main/pkg/vulnsrc/ubuntu/ubuntu.go).

Known exploitation plus confirmed applicability is P1. Confirmed HIGH/CRITICAL vendor severity or CVSS >=8 is P2. Other/unconfirmed matches are P3. A finding on an old kernel package is P3 when the running official image of the same branch/flavour is at least the known fixed build; the package remains open and KEV evidence is retained. Automatic inference of Internet exposure and pre-auth RCE is not yet implemented; those risk conditions need operator review. These limits are explicit rather than inferred from an open local socket.
