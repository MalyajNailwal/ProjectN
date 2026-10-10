# ProjectN working instructions

## Set up ProjectN for a user

When the user asks to set up, install, run, or verify ProjectN on their computer, follow these steps and run these scripts; do not substitute your own setup.

1. Use `python3` on macOS and `py -3` in Windows PowerShell. Run `scripts/doctor.py`. It lists missing prerequisites (Git, Python 3.11+, Node.js 22.19+, and for scanners Go, Java 17+, Ruby, plus Nmap on Windows or a C toolchain on macOS) with the install command for this OS.
2. Before installing anything, show the user what will be installed and ask. Some installers need administrator approval or open a window the user must finish (Xcode command-line tools on macOS, the Nmap/Npcap installer on Windows). Afterwards open a new terminal so PATH changes apply.
3. Ask whether the user wants the app only (a few minutes) or all 12 scanners (30–60 minutes and about 10 GB of free disk), then run one of:
   - `scripts/bootstrap.py --verify`
   - `scripts/bootstrap.py --with-scanners --verify`

   `--verify` runs the tests, launches a scan from the dashboard in headless Chromium (installing Playwright and Chromium first if they are missing), and, with scanners, runs a Full scan of the bundled test site and this repository that must complete with every scanner.
4. If a step fails, read its message. `doctor.py` and the setup scripts print the next command for each missing component, such as `scripts/setup_native.py technology --clone`. Fix the cause and rerun the same command; setup is safe to rerun.
5. Start the app with `.venv/bin/python scripts/run_local.py` (macOS) or `.\.venv\Scripts\python.exe scripts\run_local.py` (Windows). Give the user `http://127.0.0.1:8000`, the browser check screenshot at `data/ui-check.png`, and the `doctor.py` result.

While doing this:

- Scan only the bundled test site. Never scan a website, network, or repository unless the user names it and confirms they are authorized to test it; Full mode sends intrusive requests.
- Never commit or upload anything from `tools/`, `data/`, `.venv/`, or scan reports, and never write API keys into files; optional keys such as `OPENROUTER_API_KEY` belong in the user's environment.
- Report what actually happened: which capabilities are ready, which steps failed, and what the user still needs to do. Do not claim complete coverage.

## Product goal

Build a local security scanning application that runs natively on Windows and macOS without Docker or a hosted backend. Keep the source repositories for every scanner and its rules or add-ons locally. The application must support website URL scans and, when supplied, local source-code scans. Use SQLite for local scan history; do not add Supabase unless the user changes this decision.

## Non-negotiable behavior

- Report observed findings with source evidence, affected asset, scanner and rule versions, confidence, severity, remediation steps, and a way to verify the fix.
- Report coverage and scan limitations alongside findings. Zero findings never implies complete coverage or a secure target.
- Derive limitation states from actual runtime signals: scanner readiness, exit status, stderr, timeouts, target responses, crawl coverage, authentication verification, skipped files/rules/templates, and configured scope. Give a specific next action for each observed limitation.
- Do not invent findings, proof, exact file locations, or successful verification. AI explanations must cite the underlying scanner evidence and preserve uncertainty.
- Use configuration and versioned scanner adapters for commands, paths, policies, timeouts, rule locations, and thresholds. Avoid target-specific hardcoded assumptions. Some stable schemas and adapter protocols necessarily remain in code.
- Keep active or intrusive checks separate from passive checks and require explicit user selection for an authorized target.
- Keep secret values out of logs, reports, and AI prompts. Redact scanner output before storage or display.
- Treat supplied public GitHub repositories and websites as untrusted input. Clone into a managed workspace at a recorded revision; do not execute repository build/install/test scripts, downloaded binaries, Git submodules, or repository-supplied scanner rules by default. Static scan workers need resource and scope limits. A temporary workspace alone is not a security sandbox.
- Validate Windows and macOS behavior with native paths and process invocation; do not assume a Unix shell or WSL.
- Maintain clear setup, architecture, limitations, scanner integration, and troubleshooting documentation as implementation progresses.

## Source layout and naming

Use purpose-based local clone directories. Do not use scanner product names as local folder names. Record upstream URLs and pinned revisions in a manifest. The planned upstream repositories are WhatWeb, Nuclei, nuclei-templates, ZAP core, zap-extensions, Semgrep, and Gitleaks. Keep third-party source separate from application adapters and user data.

## Agent architecture

The scan workflow and limitation detection must be deterministic and usable without an LLM. LangGraph may coordinate evidence-based triage, remediation explanations, and rescan follow-up. Any local LLM is optional and may not initiate new target actions outside the configured scope or silently change scan policy.
