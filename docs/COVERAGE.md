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
| Container images | Explicit immutable registry digest or local image archive | No Docker-group access, no runtime mutation, no automatic image replacement. Private registry auth and arbitrary container discovery are not included in the initial CLI |
| Runtime state | Running kernel inventory, distinction between installed/deployed state | No promise that libraries/processes were restarted. An installed vendor fix is verified as a package fix, not runtime remediation |
| Notifications | Durable baseline/change/health/digest outbox, plain-text Telegram, retries | API acknowledgement does not prove reading. A timeout after Telegram accepts can duplicate a message |
| Early vendor signals | Trivy vendor database, KEV, Wordfence when configured | Per-product early-release RSS/vendor adapters and OSV API are not implemented. Self-compiled binaries/control panels are manual-review gaps |

No automatic updates, active exploitation, firewall actions, public listener, central SaaS or shared feed key are included.

## State interpretation

`applicability`, `fix_status`, `remediation` and adapter health are independent. `vendor_fix_available` means an advisory names a vendor build; it does not mean the build is currently obtainable from this host's configured repository. `repo_fix_available` additionally requires a fresh-enough successful APT refresh stamp, matching origin and a native version comparison.

A package removed from inventory, a CVE missing from a scan or an unavailable source yields `needs_reverification`, not `remediated_verified`. OS remediation requires a changed installed vendor version at least as new as the known fixed build plus a fresh successful scan. Runtime restart is still unknown. Dependencies/images deliberately remain conservative until deployment can be verified.

Known exploitation plus confirmed applicability is P1. Confirmed HIGH/CRITICAL vendor severity or CVSS >=8 is P2. Other/unconfirmed matches are P3. Automatic inference of Internet exposure and pre-auth RCE is not yet implemented; those risk conditions need operator review. These limits are explicit rather than inferred from an open local socket.
