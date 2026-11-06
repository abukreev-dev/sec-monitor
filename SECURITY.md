# Security policy

Security Monitor is an observational tool. It never upgrades packages, edits application configuration, changes firewall rules or restarts workloads. It cannot establish that a host is safe or uncompromised.

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/abukreev-dev/sec-monitor/security/advisories/new) for vulnerabilities in this project. Do not place tokens, inventories, private addresses or scanner output in public issues. If the private reporting form is unavailable, open a public issue requesting a private contact without including exploit details or sensitive data.

The project is pre-release. There is currently no security-support SLA or stable API guarantee. Findings in monitored software should be reported to that software's vendor.

## Trust boundaries

- The installer requires explicit root execution and only manages its own account, files and units. Workers run as `security-monitor`, without sudo or Docker-group membership.
- Configured project paths are administrator-controlled. PHP, WP-CLI, project hooks, package-manager install scripts and remediation commands are never executed by a scan.
- Advisory data and filenames are untrusted. Child processes use argv arrays, not shell interpolation. Telegram uses plain text, with previews disabled.
- Trivy is pinned and checked against known SHA256 values. This authenticates it against the reviewed project pin, not an independently verified Sigstore identity. Review pins and upstream advisories before updating the dependency.
- Secrets live outside Git in a 0600 file. Network and scanner errors omit raw requests/URLs. Scanner child processes do not inherit bot keys or SSH credentials.
- OS origin, installed fix, repository availability and running-code state are separate claims. A missing result or failed scan never proves remediation.

## Privacy

There is no developer telemetry or project backend. Trivy telemetry is explicitly disabled. Vulnerability databases are fetched as whole feeds; the full host inventory is not uploaded. Configured image references are sent to their registries. Telegram receives configured host aliases and selected security observations; enabling notifications authorizes that disclosure.

State and raw artifacts are private to the service account and root. Public reports omit application paths and credentials. The state directory must be on a local filesystem; NFS/SMB database storage is not supported. A compromised root account can modify observations and secrets; this tool is not a root-compromise detector.

A stopped host cannot report its own outage. Use an independent dead-man monitor if required; no external account is created automatically.
