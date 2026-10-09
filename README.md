# ProjectN

Local security assessment workstation for macOS and Windows. The dashboard accepts a website URL, a local code folder, or a public GitHub repository URL. Scanner source repositories live under purpose-based folders in `tools/`; the application runs their local executables and records incomplete coverage as scan limitations.

## Current status

The FastAPI API, SQLite scan history, React dashboard, source cloning, adapters, JSON export, and scan comparison are implemented. All 16 configured upstream source repositories are present locally. On this Mac, all 12 configured scanner capabilities show ready: WhatWeb, Nuclei, Nmap, Katana, Playwright rendered discovery, Playwright configured journeys, ZAP with source-built add-ons, axe, Lighthouse, Semgrep, Gitleaks, and OSV-Scanner. Nuclei, Nmap, Katana, Gitleaks, OSV-Scanner, ZAP core, and ZAP add-ons were built from cloned source. WhatWeb runs its cloned Ruby source. Playwright, Semgrep, axe, and Lighthouse use local released runtimes whose versions are checked against their cloned sources; their source repositories remain available for inspection and modification. The axe source dependency install and Lighthouse source lockfile install hit upstream network errors, so their matching releases were used for runtime verification.

Website scans run the HTTP response probe, a verified TLS handshake for HTTPS, WhatWeb, Katana, Nmap, and optional Nuclei checks. Full mode adds Nmap TLS protocol/cipher enumeration, rendered page/form/API discovery, source-built ZAP active/passive checks, axe accessibility checks, Lighthouse scores and audits, and optional configured login/signup journeys. An optional local OpenAPI JSON/YAML file is compared with observed API routes; declarations are not treated as proof of reachability or authorization. A local folder or public GitHub URL adds Semgrep, Gitleaks, and OSV dependency advisories. Full mode requires scan-time authorization for a website; the port range, crawling, template rate, inventory, and rendered-page limits are editable in the UI with defaults in `config/full_scan.json`. Scanner arguments and timeouts are in `config/scanners.json`.

The report records observed evidence, remediation guidance, source/rules revisions, stage status, and coverage gaps from `config/coverage.json`. API counts include only endpoints observed during scoped crawling or browser traffic. A repeated finding is marked absent only when the same completed check and revision ran again; partial or changed checks are not verifiable. Configured account journeys use values from environment variables and record no credential values. See [the journey example](docs/journeys.example.json); supply your own test selectors and account values. Journeys only cover the categories listed in their `covers` field after their assertions pass.

Remaining coverage is reported per scan: out-of-band checks need a reachable callback service; website-only input cannot reveal private source or authenticated pages; and an account journey needs controlled test accounts. Optional AI remediation drafts need an explicitly configured provider and never replace scanner evidence or deterministic fix guidance. Full TLS enumeration runs only for an authorized HTTPS Full scan. OSV vulnerability matching may query its advisory service unless configured for offline use. Native Windows execution is prepared by the setup script and a macOS/Windows smoke workflow in `.github/workflows/native-smoke.yml`. The workflow verifies app dependencies, native paths, Python tests, and the dashboard build on both operating systems. Full scanner builds and runtime behavior still need verification on a Windows machine.

## Run locally

Requires Python 3.11+, Node.js 22.19+ or 24+, Git, Go, Java 17+, Ruby, uv, and the scanner-specific native toolchains. Windows Nmap source compilation needs a suitable Visual Studio/MSBuild and Npcap SDK setup. Docker and Supabase are not required.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
python3 scripts/clone_sources.py
python3 scripts/setup_native.py all
cd web
npm install
npm run build
cd ..
.venv/bin/python scripts/run_local.py
```

Open `http://127.0.0.1:8000`. On Windows, use `.venv\Scripts\python.exe` and `python scripts/setup_native.py all --clone` from a suitable developer shell. `scripts/setup_native.py` also accepts individual components (`go`, `callback`, `semgrep`, `browser`, `application`, `accessibility`, `performance`, `technology`, `nmap`). The source clone script skips repositories that already exist. `scripts/run_local.py` accepts `--port` and defaults to loopback binding on both platforms.

Scanner source paths, expected executable names, and CLI arguments are in `config/scanners.json`. Native executable files go in `tools/bin/` (`.exe` on Windows). `PROJECTN_SCANNER_<ID>` can point to a custom local executable for a scanner. `/api/scanners` shows setup status and the resolution for missing components.

For OOB checks, build the local callback server with `python scripts/setup_native.py callback`, deploy it on an HTTPS origin with public DNS and reachable callback ports, and enter that origin in the Full scan form. Set its optional token in a local environment variable and enter only the variable name in the UI. The app checks whether the origin responds from this machine; target-to-callback reachability remains unverified until an actual interaction is recorded. Without a configured server, Nuclei's OOB templates remain disabled. A loopback-only callback cannot prove OOB behavior for a remote target.

AI drafting is optional and runs only when a finding's draft button is clicked. OpenRouter is the configured default provider; set `OPENROUTER_API_KEY` in the local environment before starting the app. `openrouter/free` is the configured default model; `PROJECTN_OPENROUTER_MODEL` can override it. The app requires a per-finding checkbox before sending normalized evidence to OpenRouter and asks OpenRouter for zero-data-retention routing. A model or provider that cannot satisfy that routing may return an error; the app does not silently relax it. To use a local model instead, set `PROJECTN_AI_PROVIDER=ollama` and `PROJECTN_LOCAL_MODEL` to an already installed Ollama model; ProjectN does not download one. Secrets and source-code findings are excluded from AI prompts. API keys and model replies are not stored in scan reports. Model replies are marked as drafts and must cite the finding fingerprint. See `config/assistant.json` for provider policy and limits.

Reports can be downloaded as JSON at `/api/scans/<id>/export`. Compare two complete scans of the same target at `/api/scans/<new-id>/compare/<old-id>`.

Run `python scripts/source_manifest.py` to write `data/source-manifest.json` with every local upstream commit, working-tree state, and top-level license file. The manifest is local data and is not committed.

Only scan websites and networks you are authorized to assess. A public GitHub repository is cloned at the default-branch tip without submodules or Git LFS downloads and is treated as untrusted input; the app does not run its build scripts. Earlier Git history requires a local full clone and is reported as a coverage gap for public-URL scans.

## Documentation

- [Scan architecture and coverage contract](docs/scan-architecture.md)
- [Product research](docs/product-research.md)
