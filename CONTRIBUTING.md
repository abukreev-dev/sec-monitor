# Contributing

The project is pre-release. Small, evidence-backed changes are welcome.

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
./security-monitor --help
```

There are no required runtime Python dependencies. Native DPKG tests run on Linux; a passing macOS fixture run does not validate Linux installation or systemd.

Keep these boundaries:

- No automatic remediation, package upgrades, application restarts or secret scanning.
- No new external data transfer by default. Explain the disclosure and keep integrations opt-in.
- Use synthetic fixtures, including failure cases. Never commit real inventories, feeds, chat IDs, tokens or private service names.
- Preserve applicability, fix availability, remediation and source health as independent dimensions.
- Every new Linux/version/architecture support claim needs runtime evidence. A container package-parser check does not validate systemd or a whole host.
- Keep adapters explicit and local. Do not dynamically load Python/PHP from monitored projects.

For a new source, document its terms, provenance, freshness, backoff and schema-drift behavior. Include version-boundary tests and prove that failure does not close existing findings. Changes to Trivy require a reviewed binary pin, template-contract tests and resource measurements.

Pull requests should state the problem, resulting behavior, evidence and remaining limits. Contributions are made under the repository's Apache-2.0 license.
