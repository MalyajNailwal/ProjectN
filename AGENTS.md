# ProjectN working instructions

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
