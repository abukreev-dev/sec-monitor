# Third-party software and data

Security Monitor's original source is licensed under Apache-2.0. It executes an external scanner; it does not incorporate Vuls code.

## Trivy

[Trivy](https://github.com/aquasecurity/trivy), Aqua Security and contributors, Apache-2.0. The bootstrap command downloads a pinned official release after an explicit request and checks SHA256 of the archive and binary. The release's LICENSE is retained alongside the downloaded tool. Installed distributions include this notice and the Apache-2.0 license. No moving `latest` binary is used.

## Vulnerability information

- [CISA KEV](https://github.com/CISAGov/kev-data): official data repository, CC0. KEV indicates known exploitation in the wild, not compromise of a monitored host.
- [Wordfence Intelligence](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/): optional, authenticated data feed with its own terms and record-specific attribution. Original notices are retained and included with exported findings. A key is provided by each operator; there is no shared project key.
- Trivy databases aggregate upstream/vendor sources with their respective terms. Reports retain source identity and advisory links. The code license does not relicense the data.

Complete third-party feeds, real server inventories and credentials are never included in this repository. Test advisories are synthetic fixtures.
