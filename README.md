# ProjectN

Local security assessment workstation for macOS and Windows. Scan a website you are authorized to test, a local source folder, or a public GitHub repository, and get observed evidence, severity, remediation, scanner coverage, and explicit limitations in one report. Everything runs on your machine: FastAPI backend, SQLite history, React dashboard. No Docker, no cloud account.

Zero findings never means "secure": every report lists what ran, what did not, and how to close each gap.

## Quick start (app and dashboard, a few minutes)

Requirements: Git, Python 3.11+, and Node.js 22.19+ (or 24+).

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

Open `http://127.0.0.1:8000`. A fork uses the same commands with its own clone URL. The built-in HTTP/TLS checks work right away; the **Tool setup** page and `scripts/doctor.py` show which external scanners still need installation. Then follow the [five-minute demo](docs/reviewer-demo.md), which scans a bundled local test site.

## Set up with an AI coding agent

Open the cloned folder in Claude Code, Codex, Cursor, or another coding agent and ask:

> Set up ProjectN on this computer and verify it.

The agent follows [AGENTS.md](AGENTS.md): it runs `scripts/doctor.py`, asks before installing any prerequisite, runs `scripts/bootstrap.py --verify` (add `--with-scanners` for all 12 scanners), and proves the result with a real browser test that launches a scan from the dashboard. It scans only the bundled test site unless you name a target you are authorized to test. You can run the same commands yourself:

```sh
python3 scripts/bootstrap.py --verify                   # Windows: py -3 scripts/bootstrap.py --verify
python3 scripts/bootstrap.py --with-scanners --verify   # all 12 scanners; 30–60 minutes, about 4 GB kept (see Full scanner setup)
```

## Full scanner setup (all 12 capabilities)

Install the toolchain once:

| | macOS (Homebrew) | Windows (PowerShell, winget) |
| --- | --- | --- |
| Command | `xcode-select --install`<br>`brew install node go ruby uv`<br>`brew install --cask temurin@17` | `winget install Git.Git OpenJS.NodeJS.LTS GoLang.Go EclipseAdoptium.Temurin.17.JDK RubyInstallerTeam.RubyWithDevKit.3.3 astral-sh.uv Insecure.Nmap` |
| Nmap | Built from the cloned source (needs `make` and a C compiler) | Official Windows release (`Insecure.Nmap`); `nmap.exe` must be on PATH or set `PROJECTN_SCANNER_PORTS` |

Open a new terminal so PATH changes apply, then from the ProjectN folder (on Windows use `py -3` instead of `python3`):

```sh
python3 scripts/doctor.py                      # shows missing prerequisites and the install command
python3 scripts/bootstrap.py --with-scanners   # clones, builds, and verifies every scanner
```

`--with-scanners` clones the 16 pinned upstream repositories into Git-ignored `tools/` folders, builds or installs the 12 scanner capabilities, and finishes with `doctor.py --strict`, which fails if any capability is not ready. A first run takes 30–60 minutes (42 minutes on a GitHub Windows runner) and leaves about 4 GB in `tools/` and the browser cache. Build downloads go to `tools/.cache` and are deleted after each component, so your own Go, Gradle, npm, and uv caches are untouched. Setup is safe to rerun after a failure.

Low on disk, or only need some checks? Each component checks its own free space before it starts and clones only its own sources, so a component that does not fit is skipped with a message while the others install. Set up just what you need with `scripts/setup_native.py <component>`:

| Component | Capabilities | Peak disk while building |
| --- | --- | --- |
| `semgrep` | Source analysis | about 1.2 GB |
| `go` | Vulnerability checks, site and API discovery, secret detection, dependency vulnerabilities | about 3 GB |
| `technology` | Technology profile | about 0.1 GB |
| `nmap` | Ports and services | about 0.5 GB |
| `browser` | Rendered pages, configured journeys (needed by `accessibility` and `performance`) | about 1 GB |
| `accessibility` / `performance` | axe / Lighthouse checks | about 0.2 / 0.8 GB |
| `application` | ZAP application security checks | about 3 GB |
| `callback` | Self-hosted out-of-band callback server (optional) | about 0.8 GB |

For example, code scanning only: `python3 scripts/setup_native.py semgrep go`. Scanners that are not set up appear in every report as coverage gaps with the command that adds them. Docker is not needed and would not save space: the scanner images and the Docker runtime are larger than these native installs.

On Windows, ProjectN uses the official Nmap runtime and keeps the Nmap source cloned for inspection; compiling Nmap on Windows additionally needs the upstream `nmap-mswin32-aux` dependencies and Visual Studio, which ProjectN does not automate.

| Capability | Scanner | Runs when |
| --- | --- | --- |
| Technology profile | WhatWeb (cloned Ruby source) | Every website scan |
| Ports and services | Nmap | Every website scan |
| Site and API discovery | Katana (built from source) | Every website scan |
| Vulnerability checks | Nuclei + nuclei-templates (built from source) | Deep and Full |
| Rendered pages and forms | Playwright Chromium | Full |
| Configured login/signup journeys | Playwright + your journey file | Full with a journey file |
| Application security checks | ZAP core + add-ons (built from source) | Full |
| Accessibility checks | axe-core | Full |
| Performance and page quality | Lighthouse | Full |
| Source analysis | Semgrep + semgrep-rules | Local folder or GitHub repository |
| Secret detection | Gitleaks (built from source) | Local folder or GitHub repository |
| Dependency vulnerabilities | OSV-Scanner (built from source) | Local folder or GitHub repository |

These 10 need no extra install; they are pure-Python checks built into the app itself and run as part of every applicable scan:

| Capability | Runs when |
| --- | --- |
| HTTP surface (headers, links, forms) | Every website scan |
| TLS certificate and connection | Every website scan over HTTPS |
| TLS protocol and cipher configuration | Full |
| Infrastructure and stack (hosting/CDN, backend-as-a-service, frontend framework) | Every website scan |
| Supabase exposure (tables and storage buckets readable without authentication, and a leaked service_role admin key) | Full, if a Supabase project or key is found on the page or a linked script |
| Firebase database exposure | Full, if a Firebase project is found on the page |
| GraphQL introspection | Full |
| Signup rate limiting | Full, if the browser stage found a signup-shaped form |
| Dependency name verification (hallucinated/unpublished package names) | Local folder or GitHub repository |
| OpenAPI contract comparison | When an OpenAPI file is supplied |

The Supabase, Firebase, GraphQL, and signup checks make a small, bounded number of read-only requests against the project/target they already discovered; see [docs/scan-architecture.md](docs/scan-architecture.md) for what evidence each one keeps and what it never stores.

Exact verification results for each platform are in [docs/validation.md](docs/validation.md).

## Using the app

- **Profiles.** Standard runs discovery and inventory. Deep adds template-based vulnerability checks. Full adds every TCP port, JavaScript crawling, rendered pages, ZAP, axe, Lighthouse, and TLS cipher enumeration, and requires you to confirm authorization for intrusive checks. Full limits (ports, crawl depth and time, request rate, page limits) are editable in the form; defaults are in `config/full_scan.json`.
- **Live progress and stopping.** While a scan runs, the dashboard shows the planned steps, the step running now with its elapsed time, and the share of steps finished. **Stop scan** terminates the running scanner and its child processes; the partial report is kept and marks every step that did not run.
- **Reports.** Findings include evidence, severity, confidence, remediation, and a verification step. The Coverage page lists every stage and every limitation with a concrete next action. Export JSON at `/api/scans/<id>/export`. A rescan of the same target is compared automatically (`/api/scans/<new>/compare/<old>`): a finding is marked not observed only when the same check and revision completed again; otherwise it is "not verifiable".
- **Where your data lives.** Scan history and reports are stored only on your computer, in one SQLite database at `data/scans.sqlite3` (Git-ignored; set `PROJECTN_DATA_DIR` to move it). Each scan's temporary scanner files are deleted when it ends. Delete a single scan or clear all finished scans from **Recent scans** on the Overview page; a running scan must be stopped first. Deleting the `data/` folder removes everything.
- **API contracts and journeys.** An optional local OpenAPI JSON/YAML file is compared with observed routes. Configured login/signup journeys read account values from environment variables (see [the journey example](docs/journeys.example.json)) and only cover the categories in their `covers` field after their assertions pass.
- **Out-of-band checks.** Build the callback server with `python scripts/setup_native.py callback`, host it on a public HTTPS origin, and enter that origin in the Full form (and optionally the name of an environment variable holding its token). Without it, OOB templates stay disabled and the report says so. A callback that only responds locally does not prove the target can reach it.
- **Optional AI remediation drafts.** Off unless configured. Set `OPENROUTER_API_KEY` in the environment (or `PROJECTN_AI_PROVIDER=ollama` with `PROJECTN_LOCAL_MODEL`), then tick the per-finding consent box. Secrets and source-code findings are never sent; drafts cite the finding fingerprint and never replace scanner evidence. Policy is in `config/assistant.json`.

## What a scan cannot see

A URL-only scan cannot inspect source code, Git history, or authenticated pages; authenticated coverage needs controlled test accounts and journeys. A public GitHub repository is cloned at its default-branch tip without submodules or Git LFS, treated as untrusted input, and never built or executed; earlier history needs a local full clone. OSV matching may query its online advisory service. Rule and template coverage changes with the pinned revisions. Each report records these limits for the specific scan.

Only scan websites, networks, and code you are authorized to assess.

## Development

```sh
.venv/bin/python -m unittest discover -s tests -v   # Windows: .\.venv\Scripts\python.exe
.venv/bin/python scripts/smoke_local.py             # starts the app and scans the bundled fixture
npm run build --prefix web
```

ProjectN's own checks live in [`rules/`](rules/README.md). `config/scanners.json` holds scanner paths, arguments, and timeouts; `config/source-lock.json` pins upstream revisions, which change only when you run `python scripts/clone_sources.py --update` (`--upstream` shows what is newer, `--verify` checks local checkouts offline; see [CONTRIBUTING](CONTRIBUTING.md#update-scanner-versions)); `config/coverage.json` maps missing stages to limitations and next actions. `PROJECTN_SCANNER_<ID>` points a scanner at a custom executable, and `PROJECTN_DATA_DIR` moves scan history out of `data/`. Third-party sources, binaries, runtimes, virtual environments, and scan data stay in Git-ignored `tools/` and `data/`; never commit them.

## Documentation

- [Five-minute reviewer demo](docs/reviewer-demo.md)
- [Platform validation matrix](docs/validation.md)
- [Scan architecture and coverage contract](docs/scan-architecture.md)
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md)
- [ProjectN license (MIT)](LICENSE) and [third-party licenses: what you can do](THIRD_PARTY.md). Internal use and sharing the repository are fine as is; bundles and hosted use are doable with the steps listed there.
- [Product research](docs/product-research.md)
