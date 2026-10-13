# Validation status

Last updated 2026-10-13. Every CI result below starts from a fresh repository checkout on a GitHub-hosted runner and does not reuse scanner sources, binaries, or runtimes from the developer's Mac. Runner images: `macos-26-arm64` and `windows-2025-vs2026`.

The per-capability tables below were last fully rebuilt for the original 12-capability scan; the summary row directly below links the latest run covering everything added since (infrastructure/stack fingerprinting, Supabase and Firebase exposure, GraphQL introspection, signup rate limiting, dependency name verification, port-depth presets). Each of those was additionally verified end-to-end against a local fake server or a real locally-served fixture at the commit that introduced it; see that commit's message in `git log` for what was specifically checked.

## Summary

| Check | macOS | Windows |
| --- | --- | --- |
| Full scan requiring all current capabilities (12 external scanners + 10 built-in checks, ~20 stages) with the SQLite WAL-mode and poll-resilience fixes in place | Passed locally, 20 stages, 248 findings | Passed in [native CI](https://github.com/MalyajNailwal/ProjectN/actions/runs/38116408113) |
| Project-owned Chromium runtime after shared-cache loss; doctor launches the browser, and rendered Full fixture scan completes | Browser, accessibility, and Lighthouse adapters completed on the bundled fixture; doctor 12/12 ready. Deliberately missing runtime marks all four browser-dependent capabilities unavailable. | Passed in [Windows rendered scan CI](https://github.com/MalyajNailwal/ProjectN/actions/runs/38403688444) at `afcfea3` |
| Fresh clone: app and dashboard bootstrap, 47 Python tests, API and dashboard startup, bundled-site scan with a real WhatWeb stage | Passed in [native CI](https://github.com/MalyajNailwal/ProjectN/actions/runs/38025107938) | Passed in [native CI](https://github.com/MalyajNailwal/ProjectN/actions/runs/38025107938) |
| Fresh clone: real-browser dashboard check. Playwright and Chromium installed automatically, scan launched from the form, live progress, step list and Stop control, report and Coverage pages, no console errors | Passed in native CI | Passed in native CI |
| Fresh clone: each page and open finding has a URL; browser Back closes a finding and Back/Forward stay inside the dashboard | Passed in native CI | Passed in native CI |
| Stop scan terminates the scanner's whole process tree (`tests/test_cancel.py`) | Passed in native CI | Passed in native CI (`taskkill /T`) |
| Full scanner setup with the README command (`bootstrap.py --with-scanners`) from a fresh clone | Not verified on a fresh macOS clone (see below) | Passed in 40 minutes; `doctor.py --strict` 12/12 ready ([run](https://github.com/MalyajNailwal/ProjectN/actions/runs/38022503817)) |
| All 16 upstream sources at the pinned revisions | Developer Mac, `clone_sources.py --verify` | Cloned and verified in the Windows full setup |
| ProjectN's own checks in `rules/` with the real Semgrep and Nuclei | Passed on the developer Mac | Passed in the Windows full setup |
| Full scan of the bundled site and this repository requiring all 12 capabilities (`smoke_local.py --all-capabilities`) | Passed on the developer Mac (macOS 26.4.1, Apple Silicon), 737 s | Passed in the Windows full setup, 19 minutes, 15 stages |

## Each capability in the 12-capability scan

macOS: developer Mac. Windows: [full setup run 38022503817](https://github.com/MalyajNailwal/ProjectN/actions/runs/38022503817) at commit `8d0f320`.

| Capability | macOS | Windows | Windows runtime |
| --- | --- | --- | --- |
| Technology profile (WhatWeb) | Completed | Completed | Cloned Ruby source, Ruby 3.3.12 |
| Vulnerability checks (Nuclei + templates + `rules/nuclei`) | Completed, 12 template matches | Completed, 12 template matches | Built from source with Go 1.27.2 |
| Ports and services (Nmap) | Completed, built from cloned source | Completed | Official Nmap 7.991 release (Chocolatey); data files and NSE scripts read from the cloned source |
| Site and API discovery (Katana) | Completed | Completed | Built from source |
| Rendered pages and forms (Playwright) | Completed | Completed | Playwright 1.63.0 with Chromium, matching the cloned bindings |
| Configured login/signup journeys | Completed with the fixture journey | Completed with the fixture journey | Same runtime |
| Application security checks (ZAP) | Completed, 5 alerts | Completed, 5 alerts | Core and 13 add-ons built from source with Gradle and Java 17 |
| Accessibility checks (axe) | Completed | Completed | axe-core 4.14.0, matching the cloned source |
| Performance and page quality (Lighthouse) | Completed | Completed | Lighthouse matching the cloned source, Node.js 22 |
| Source analysis (Semgrep + rule packs + `rules/semgrep`) | Partial: 190 results in 78 files; one long TSX file parsed partially | Partial: 190 results in 63 files; same partial parse | Semgrep 1.180.0 in Python UTF-8 mode |
| Secret detection (Gitleaks) | Completed | Completed; its one finding was a fake test value, removed in `2164643` (history now scans clean) | Built from source |
| Dependency vulnerabilities (OSV-Scanner) | Completed: 1 lockfile, 120 packages, 0 advisories | Same | Built from source |

The HTTPS-only stages (TLS certificate and TLS cipher enumeration) are skipped in these runs because the bundled site is served over HTTP; the report records that limitation.

## Problems found and fixed during validation

- Source analysis passed the whole semgrep-rules repository as one config; Semgrep rejected non-rule YAML and analyzed no files while showing ready (fixed in `cb00db7`).
- Windows: Python read text with the legacy code page, so Lighthouse setup crashed and stopped the rest of setup (`7ed145e`); Semgrep itself hit the same error reading rule files (`8d0f320`).
- Rerunning setup after a failure stopped at an existing Python environment (`2a3bbc8`).
- The smoke test stalled on long scans because the app's output filled an unread pipe (`2612490`), and on Windows its cleanup failed on a briefly locked SQLite file (`83ad47d`).
- Semgrep severities and dependency results were reported ambiguously (`516892c`, `11597cd`), and the crawler checked GitHub for updates on every scan (`6f0c0bf`).

Earlier partial Windows runs, kept for history: [Semgrep pattern scan](https://github.com/MalyajNailwal/ProjectN/actions/runs/38007222627), [Go scanner builds](https://github.com/MalyajNailwal/ProjectN/actions/runs/38006368963), [rendered scan](https://github.com/MalyajNailwal/ProjectN/actions/runs/38007967365), [10/12 before the encoding fix](https://github.com/MalyajNailwal/ProjectN/actions/runs/38013957818), and [11/12 before the Semgrep fix](https://github.com/MalyajNailwal/ProjectN/actions/runs/38017044408).

## Not verified yet

- **macOS full scanner setup from a fresh clone.** All 12 capabilities are verified on the developer Mac's existing setup, and the macOS fresh-clone app path is verified in CI. A fresh macOS full setup was not run: the developer Mac had about 1 GB of free disk, and macOS CI minutes cost about ten times Linux minutes on a private repository. Next step: run `bootstrap.py --with-scanners --verify` on a Mac with free disk, or add a macOS job to the full setup workflow.
- **Compiling Nmap on Windows.** Windows uses the official Nmap runtime while the source stays cloned; compiling it needs the upstream `nmap-mswin32-aux` dependencies and Visual Studio, which ProjectN does not automate. ProjectN uses TCP connect scans, so Npcap raw-packet modes were not exercised.
- **Real-world detection coverage.** The bundled site is deliberately tiny: these runs prove each scanner runs, parses, and reports on both platforms, not how much it detects. HTTPS checks, out-of-band callbacks, and journeys with real test accounts need an authorized target.

Run `python scripts/doctor.py --strict` after setup to check the current machine, and `python scripts/smoke_local.py --ui` or `--all-capabilities` to repeat these checks.
