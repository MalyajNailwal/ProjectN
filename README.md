# ProjectN

Local security assessment workstation for macOS and Windows. The dashboard accepts a website URL, a local code folder, or a public GitHub repository URL. Scanner source repositories live under purpose-based folders in `tools/`; the application runs their local executables and records incomplete coverage as scan limitations.

## Quick start from a GitHub clone

Install Python 3.11+ and Node.js 22.19+ (or 24+) first. These commands work from the repository root and install the app plus dashboard. They do not download the large scanner runtimes.

macOS Terminal:

```sh
git clone https://github.com/MalyajNailwal/ProjectN.git
cd ProjectN
python3 scripts/bootstrap.py
.venv/bin/python scripts/run_local.py
```

Windows PowerShell:

```powershell
git clone https://github.com/MalyajNailwal/ProjectN.git
cd ProjectN
py -3 scripts/bootstrap.py
.\.venv\Scripts\python.exe scripts\run_local.py
```

Open `http://127.0.0.1:8000`. A fork uses the same commands with its own clone URL. The dashboard and built-in HTTP/TLS checks can run after this setup; `/api/scanners` lists which external scanners still need installation. To download all pinned scanner sources and build/install their runtimes, first install the Go, Java, Ruby, uv, and native build prerequisites below, then run `python3 scripts/bootstrap.py --with-scanners` on macOS or `py -3 scripts/bootstrap.py --with-scanners` on Windows. This step is large and on Windows you must first install the official Nmap release and put `nmap.exe` on PATH (or set `PROJECTN_SCANNER_PORTS`). Its source is still cloned locally. Run `python scripts/smoke_local.py` with the environment's Python to check the dashboard and API.

## Current status

The FastAPI API, SQLite scan history, React dashboard, source cloning, adapters, JSON export, and scan comparison are implemented. All 16 configured upstream source repositories are present locally. On this Mac, all 12 configured scanner capabilities show ready: WhatWeb, Nuclei, Nmap, Katana, Playwright rendered discovery, Playwright configured journeys, ZAP with source-built add-ons, axe, Lighthouse, Semgrep, Gitleaks, and OSV-Scanner. Nuclei, Nmap, Katana, Gitleaks, OSV-Scanner, ZAP core, and ZAP add-ons were built from cloned source. WhatWeb runs its cloned Ruby source. Playwright, Semgrep, axe, and Lighthouse use local released runtimes whose versions are checked against their cloned sources; their source repositories remain available for inspection and modification. The axe source dependency install and Lighthouse source lockfile install hit upstream network errors, so their matching releases were used for runtime verification.

Website scans run the HTTP response probe, a verified TLS handshake for HTTPS, WhatWeb, Katana, Nmap, and optional Nuclei checks. Full mode adds Nmap TLS protocol/cipher enumeration, rendered page/form/API discovery, source-built ZAP active/passive checks, axe accessibility checks, Lighthouse scores and audits, and optional configured login/signup journeys. An optional local OpenAPI JSON/YAML file is compared with observed API routes; declarations are not treated as proof of reachability or authorization. A local folder or public GitHub URL adds Semgrep, Gitleaks, and OSV dependency advisories. Full mode requires scan-time authorization for a website; the port range, crawling, template rate, inventory, and rendered-page limits are editable in the UI with defaults in `config/full_scan.json`. Scanner arguments and timeouts are in `config/scanners.json`.

The report records observed evidence, remediation guidance, source/rules revisions, stage status, and coverage gaps from `config/coverage.json`. API counts include only endpoints observed during scoped crawling or browser traffic. A repeated finding is marked absent only when the same completed check and revision ran again; partial or changed checks are not verifiable. Configured account journeys use values from environment variables and record no credential values. See [the journey example](docs/journeys.example.json); supply your own test selectors and account values. Journeys only cover the categories listed in their `covers` field after their assertions pass.

Remaining coverage is reported per scan: out-of-band checks need a reachable callback service; website-only input cannot reveal private source or authenticated pages; and an account journey needs controlled test accounts. Optional AI remediation drafts need an explicitly configured provider and never replace scanner evidence or deterministic fix guidance. Full TLS enumeration runs only for an authorized HTTPS Full scan. OSV vulnerability matching may query its advisory service unless configured for offline use. Native Windows execution is prepared by the setup script and a macOS/Windows smoke workflow in `.github/workflows/native-smoke.yml`. The workflow bootstraps a fresh clone, runs Python tests, starts the dashboard/API, and completes a scan against the bundled local fixture on both operating systems. Full scanner builds and runtime behavior still need verification on a Windows machine.

## Full scanner setup

The quick start above prepares the app and dashboard. External scanner setup also requires Git, Go, Java 17+, Ruby, uv, and scanner-specific native toolchains. On Windows, install the official Nmap release separately; compiling Nmap from source needs additional `nmap-mswin32-aux` dependencies and Visual Studio. On macOS, source compilation needs a C compiler and Make. Docker and Supabase are not required.

Run `python3 scripts/bootstrap.py --with-scanners` on macOS or `py -3 scripts/bootstrap.py --with-scanners` on Windows after installing those prerequisites. The script downloads the 16 pinned upstream source repositories and builds or installs the 12 scanner capabilities. This can require several gigabytes and substantial setup time. Check `/api/scanners` for each scanner's actual readiness; the macOS and Windows CI jobs verify fresh app setup, tests, dashboard, and API startup, but do not compile every scanner. Full native scanner builds on Windows still need verification on a Windows machine.

`scripts/setup_native.py` also accepts individual components (`go`, `callback`, `semgrep`, `browser`, `application`, `accessibility`, `performance`, `technology`, `nmap`). The source clone script checks existing repositories against `config/source-lock.json` and fetches the pinned revision for new clones. It reports a mismatch instead of changing an existing checkout. Run `python scripts/clone_sources.py --verify` to check local commits and origin URLs without network access. `scripts/run_local.py` accepts `--port` and defaults to loopback binding on both platforms.

Scanner source paths, expected executable names, and CLI arguments are in `config/scanners.json`. Native executable files go in `tools/bin/` (`.exe` on Windows). `PROJECTN_SCANNER_<ID>` can point to a custom local executable for a scanner. `/api/scanners` shows setup status and the resolution for missing components.

For OOB checks, build the local callback server with `python scripts/setup_native.py callback`, deploy it on an HTTPS origin with public DNS and reachable callback ports, and enter that origin in the Full scan form. Set its optional token in a local environment variable and enter only the variable name in the UI. The app checks whether the origin responds from this machine; target-to-callback reachability remains unverified until an actual interaction is recorded. Without a configured server, Nuclei's OOB templates remain disabled. A loopback-only callback cannot prove OOB behavior for a remote target.

AI drafting is optional and runs only when a finding's draft button is clicked. OpenRouter is the configured default provider; set `OPENROUTER_API_KEY` in the local environment before starting the app. `openrouter/free` is the configured default model; `PROJECTN_OPENROUTER_MODEL` can override it. The app requires a per-finding checkbox before sending normalized evidence to OpenRouter and asks OpenRouter for zero-data-retention routing. A model or provider that cannot satisfy that routing may return an error; the app does not silently relax it. To use a local model instead, set `PROJECTN_AI_PROVIDER=ollama` and `PROJECTN_LOCAL_MODEL` to an already installed Ollama model; ProjectN does not download one. Secrets and source-code findings are excluded from AI prompts. API keys and model replies are not stored in scan reports. Model replies are marked as drafts and must cite the finding fingerprint. See `config/assistant.json` for provider policy and limits.

Reports can be downloaded as JSON at `/api/scans/<id>/export`. Compare two complete scans of the same target at `/api/scans/<new-id>/compare/<old-id>`.

The committed `config/source-lock.json` records the exact upstream source revisions needed on another computer. Run `python scripts/source_manifest.py` to write `data/source-manifest.json` with the actual local commits, working-tree state, and top-level license files. The runtime manifest is local data and is not committed. Third-party source checkouts, compiled executables, browser runtimes, virtual environments, scan data, and caches stay under ignored `tools/` and `data/` paths; run the setup scripts to obtain them on each computer.

Only scan websites and networks you are authorized to assess. A public GitHub repository is cloned at the default-branch tip without submodules or Git LFS downloads and is treated as untrusted input; the app does not run its build scripts. Earlier Git history requires a local full clone and is reported as a coverage gap for public-URL scans.

## Documentation

- [Five-minute reviewer demo](docs/reviewer-demo.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [ProjectN license](LICENSE) and [third-party licenses](THIRD_PARTY.md)
- [Scan architecture and coverage contract](docs/scan-architecture.md)
- [Product research](docs/product-research.md)
