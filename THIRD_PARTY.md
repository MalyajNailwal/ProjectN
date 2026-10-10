# Third-party scanners and rules

ProjectN's root [MIT license](LICENSE) covers ProjectN's own code and documentation. The upstream scanner repositories, their rules, templates, and add-ons keep their own licenses. They are not stored in this repository: the setup scripts download them into Git-ignored `tools/` folders from the URLs in `config/scanners.json` at the revisions in `config/source-lock.json`. Run `python scripts/source_manifest.py` after cloning to record each checkout's commit and license files in `data/source-manifest.json`.

## What you can do

**Use ProjectN as an internal tool: yes.** Running ProjectN with all 16 upstream components on your own computers, for your own or your organization's assessments, fits every license listed below, including the Semgrep Rules License, which grants use "for your own internal business purposes".

**Share, fork, or publish the ProjectN repository: yes.** The repository contains only ProjectN's MIT-licensed code. Each person who clones it downloads the scanners and rules from their upstream projects with the setup scripts and receives them under those projects' licenses. Nmap's license states that it does not control software that runs an Nmap the user has installed themselves.

**Distribute a ready-made bundle with the scanners included (archive or installer): doable, this way:**

- MIT and Apache 2.0 components (Nuclei, nuclei-templates, Katana, Interactsh, Gitleaks, OSV-Scanner, ZAP and its add-ons, Playwright, Lighthouse): include each component's license and any NOTICE file.
- Semgrep engine (LGPL 2.1), WhatWeb (GPL v2), and axe-core (MPL 2.0): ship them as separate programs or files with their license texts, and make their source code available alongside (WhatWeb and axe-core are already distributed as source).
- Nmap (Nmap Public Source License): either leave it out and let users install it, as the Windows setup already does, or redistribute it under its license terms, which include providing source code. A proprietary or commercial product can use Nmap's OEM licensing.
- Semgrep rules: leave them out of the bundle and let each user fetch them for their own internal use with `scripts/clone_sources.py`, which is how ProjectN already works. To ship rules inside a bundle, use ProjectN's own rules in [`rules/`](rules/README.md), rules under an open license, or written permission from Semgrep.

**Offer ProjectN as a hosted service (SaaS): doable, this way:**

- Show a notice such as "This service uses the Nmap Security Scanner" with a link to https://nmap.org, as Nmap's license requires for external deployments.
- Use source-analysis rules that are licensed for use in a service: ProjectN's own rules in [`rules/`](rules/README.md), other rules under an open license, or permission from Semgrep. The Semgrep Rules License covers internal use, not making the rules available to others as a service.
- Keep the other components' license notices available to your users.

This page is a practical summary, not legal advice. The license text in each checkout is authoritative, and downloaded runtimes and dependencies (browsers, the JDK, npm and Go modules) carry their own terms.

## License files at the pinned revisions

Read from the top-level license file of each checkout at the revisions in `config/source-lock.json` (October 2026).

| Local folder | Upstream | License file states |
| --- | --- | --- |
| `tools/web/technology-profiler/source` | WhatWeb | GNU GPL v2 |
| `tools/web/template-scanner/engine` | Nuclei | MIT |
| `tools/web/template-scanner/checks` | nuclei-templates | MIT |
| `tools/network/port-and-service-mapper/source` | Nmap | Nmap Public Source License 0.95 |
| `tools/web/endpoint-crawler/source` | Katana | MIT |
| `tools/web/browser-journeys/python-bindings` | Playwright for Python | Apache 2.0 |
| `tools/web/browser-journeys/engine` | Playwright | Apache 2.0 |
| `tools/web/application-scanner/core` | ZAP | Apache 2.0 |
| `tools/web/application-scanner/add-ons` | ZAP extensions | Apache 2.0 |
| `tools/web/callback-service/source` | Interactsh | MIT |
| `tools/quality/accessibility/source` | axe-core | Mozilla Public License 2.0 (plus a third-party notices file) |
| `tools/quality/performance/source` | Lighthouse | Apache 2.0 |
| `tools/code/static-analyzer/source` | Semgrep | GNU LGPL 2.1 |
| `tools/code/static-analyzer/checks` | semgrep-rules | [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license) |
| `tools/code/secret-detector/source` | Gitleaks | MIT |
| `tools/code/dependency-risk/source` | OSV-Scanner | Apache 2.0 |
