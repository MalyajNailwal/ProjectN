# Scan architecture and coverage contract

This document defines the application architecture and the verification criteria for each scanner integration.

## Local components

- Python/FastAPI: scan API, deterministic orchestration, scanner adapters, normalization, and reporting.
- React/TypeScript: local dashboard for configuration, progress, findings, coverage, and rescans.
- SQLite: local history and optional LangGraph checkpoints.
- Optional AI draft provider: local Ollama or explicit-consent OpenRouter, grounded in one normalized finding and cited by fingerprint. Scanning and deterministic remediation work without a model. LangGraph remains optional if multi-step human-reviewed triage is later needed.
- Scanner repositories: 16 pinned upstream repositories cloned under `tools/`, recorded with their revisions in [`config/source-lock.json`](../config/source-lock.json); see the capability table in [README.md](../README.md#full-scanner-setup-all-12-capabilities) for which capability each one provides.
- Built-in checks: ten further checks run with no external tool and no extra install — HTTP surface, TLS certificate/connection, TLS protocol and cipher configuration, infrastructure and stack fingerprinting, Supabase exposure, Firebase database exposure, GraphQL introspection, signup rate limiting, dependency name verification (slopsquatting), and OpenAPI contract comparison. Each is a small, self-contained module under `app/` (for example `app/supabase_probe.py`); see the README's built-in-checks table for when each runs.

## Target inputs

The UI accepts a website URL, a local source folder, or a public GitHub repository URL. A public repository URL is cloned to a managed local workspace at a recorded commit before Semgrep and Gitleaks run. A website URL is scanned by the web tools. The two inputs may be linked in one project, but the app must not assume the repository is the code currently deployed at that website. Git history scanning, file scanning, and branch/commit selection are separate options.

Repository intake uses allowlisted GitHub HTTPS URLs, a size/time budget, a fixed workspace, and no automatic submodule or build/install/test execution. Run static scanners with local pinned rules, restricted process privileges where supported, resource limits, and redacted logs. The managed workspace is isolation for files and cleanup, not a strong OS security sandbox. If execution of repository code is ever needed, require a tested OS-level isolation mode; do not silently run it on the host.

Website-only assessment combines DNS/host resolution, scoped network port discovery, technology profiling, standard and browser/JavaScript crawling, API traffic/spec discovery, passive and explicitly selected active web tests, TLS and header checks, and quality checks. Authenticated or role-specific coverage requires suitable test sessions/accounts. Coverage is recorded per route, role, host, port range, rule family, and scanner. The report must distinguish observed public surface, tested authenticated surface, and untested or unknown surface.

Out-of-band checks require a reachable callback service. The cloned callback server can be built natively, and an HTTPS self-hosted origin can be supplied for authorized Full scans. The app tests local reachability and records whether Nuclei returned an interaction; absent interactions do not establish that the target could reach the callback. Offline-only scans mark OOB checks unavailable. Full subdomain takeover coverage requires a supplied or discovered in-scope subdomain inventory. Cloud misconfiguration checks require actual discovered cloud assets or authorized cloud configuration, not only a website URL.

## API, journey, quality, network, and dependency coverage

The API inventory distinguishes observed endpoints from operations declared in an optional local OpenAPI 3 or Swagger 2 JSON/YAML file. The parser expands concrete in-scope server base paths and matches path parameters without executing requests or loading remote references. Routes only declared in the specification remain unverified. Observed routes missing from the specification are reported separately. Authenticated reachability still requires controlled browser journeys; role-specific API authorization tests require additional target information. A count is scoped to what was discovered, not a claim of complete inventory. ProjectDiscovery Katana provides the crawling input; ZAP's OpenAPI and GraphQL add-ons are part of the cloned ZAP extensions repository, and a separate, bounded built-in check tests whether GraphQL schema introspection itself is left enabled (`app/graphql_probe.py`).

Signup, login, password reset, and role-specific checks need controlled test accounts and repeatable browser journeys (Playwright Python, `app/browser_probe.py` and the `journeys` capability), which capture observed validation, enumeration, session, and authorization behavior without bulk account creation. Separately, `app/signup_probe.py` tests whether a signup form the browser stage already found rate-limits repeated submissions: every submission carries deliberately invalid field values built from that form's own field names (a malformed email, a one-character password), so no account can be created by the check, bounded to 8 attempts and stopping at the first sign of a limit.

An AI-generated-site provenance verdict cannot be inferred reliably from website appearance, so ProjectN does not attempt one. It reports an evidence-based site quality review instead: accessibility (axe-core), performance (Lighthouse), and the infrastructure/stack signals in `app/infra_probe.py` (hosting/CDN, backend-as-a-service, frontend framework), each a literal count of named signals matched, not an estimated confidence. Provenance, quality, and security stay separate report sections.

Network exposure is a separate inventory from API endpoints. Source: Nmap, cloned under `tools/network/port-and-service-mapper/source/`. Full scope offers a port-depth preset (Quick/Standard/Thorough/All 65535/Custom, `config/full_scan.json`) instead of always scanning every port, since a full 65535-port scan routinely takes hours against a real host behind a firewall or CDN and typically finds the same open ports a `--top-ports` scan would. The report records host/IP, scan vantage point, protocol, port state (open, closed, filtered, or uncertain), detected service/version confidence, and exactly which ports were scanned (read from Nmap's own output, so it is correct regardless of which preset was chosen). Do not treat an unscanned port as closed or an open port as a vulnerability. Windows uses the official Nmap runtime; see the README for how it is installed.

If a public source repository or local folder is supplied, dependency risk is reported from two separate, complementary checks. OSV-Scanner (built from source) matches lockfiles and SBOMs against known CVEs with vulnerability database freshness and package/version evidence. `app/slopsquat_probe.py` separately checks whether each declared package name actually exists on its registry (npm or PyPI) — a name that returns 404 is a live slopsquatting risk, not proof of compromise, since research puts roughly a fifth of AI-generated code's referenced packages at not existing at all. Neither dependency check is inferred from a website URL alone.

## Backend-as-a-service exposure (Supabase, Firebase)

`app/supabase_probe.py` and `app/firebase_probe.py` run only in Full scope, where the authorization checkbox is already required before anything starts. Each only queries a project discovered in the target's own already-fetched page body, or, if that fails, one of a bounded number of same-host JavaScript files the surface stage already found linked from that page (`app/core.py::discover_in_linked_scripts`/`fetch_same_host_scripts`, never a guessed or arbitrary URL, never a cross-origin request): a regex match on the project's URL shape. The script fallback exists because frameworks such as Next.js and Vite inline the project URL and key into a bundled script rather than server-rendered HTML, so a root-page-only search misses most modern single-page apps. Supabase tests whether PostgREST tables are readable without authentication (schema-introspected table names first, a short fixed guess list only if that is blocked) and whether any Storage bucket is marked public; Firebase tests the Realtime Database root with Firebase's own `shallow=true` option, which returns only top-level key names, never their values. Evidence never includes actual row or key values, only table/bucket/key names and column names.

Independently of project discovery, `app/supabase_probe.py` decodes the payload of every JWT found on the page or its linked scripts (never verifying its signature -- the payload is plain base64, not encrypted) and flags one whose claims are `role=service_role` and `iss=supabase` as a critical finding: Supabase's admin key, which bypasses every Row Level Security policy on every table and bucket regardless of the checks above. This runs even when no project URL is found, and the key's actual value is never included in the report, only its role/issuer/project-ref claims.

## Purpose-based source folders

```text
tools/web/technology-profiler/source/
tools/web/template-scanner/engine/
tools/web/template-scanner/checks/
tools/web/application-scanner/core/
tools/web/application-scanner/add-ons/
tools/code/static-analyzer/source/
tools/code/secret-detector/source/
```

Each folder is a separate upstream repository. Keep a manifest with upstream URL, commit, license, build method, executable path, and detected version. Keep app adapters, custom rules, and user data elsewhere.

## Scan state

Every scanner stage records `planned`, `running`, `completed`, `partial`, `failed`, or `skipped`, plus machine-readable reasons. A finding is distinct from a coverage gap. The combined report shows both.

For each scan, record target scope and redirects, selected profile, scanner and ruleset versions, reachable and discovered URLs, tested URLs, authentication status, skipped or failed checks, timeouts, rate-limit or WAF signals, raw evidence references, normalized findings, and redacted logs. Store only necessary sensitive data; never store plaintext credentials or detected secrets in report text.

## Dynamic limitation handling

| Observed runtime signal | Reported limitation | Suggested action |
| --- | --- | --- |
| Login verification fails or repeated logged-out responses | Authenticated pages were not covered | Recheck credentials/session setup and rerun authenticated scan |
| Crawl ends at configured depth, duration, or page cap | Some routes were not reached | Increase limits or provide sitemap/API specification |
| High 403/429 counts, CAPTCHA, or connection throttling | Target blocked or slowed the scan | Reduce rate, verify allowlisting, then rescan |
| Scanner executable or ruleset absent | That scanner's checks were skipped | Complete local setup or select a valid source/build path |
| Scanner exits with error, times out, or outputs invalid data | Its results are incomplete | Inspect redacted diagnostic and retry after correcting cause |
| Template/rule selection excludes categories | Those categories were not tested | Inspect profile and enable appropriate rules |
| No source folder provided | Code and Git history were not analyzed | Attach a local project folder for Semgrep/Gitleaks |
| Secret scan runs on files but not Git history | Historical secrets were not checked | Enable Git-history mode on a Git repository |

The table describes behaviors, not fixed target assumptions. Adapters must emit typed telemetry; a versioned limitation policy maps telemetry to UI explanations and actions. Unknown failures stay `unknown` with diagnostics rather than being falsely classified.

## Finding quality

Every finding should include: scanner and rule IDs, target URL or file, evidence, severity, confidence, affected component, impact, precise remediation guidance when supported by evidence, and a rescan check. Cross-tool agreement can raise confidence but cannot substitute for proof. Findings that need manual confirmation remain labeled as such. A rescan result is `fixed`, `still present`, or `not verifiable`; it is never inferred from an LLM answer.

## Limits that cannot be removed by orchestration alone

Generic black-box tools cannot know all business rules. Authenticated and role-specific areas need working sessions and representative accounts. A URL-only scan cannot inspect source code or Git history. Semgrep Community Edition does not provide full cross-file analysis, and the Apex and Elixir rule packs need Semgrep Pro language support, so ProjectN does not run them. Rule/template coverage changes with installed versions. These facts must be disclosed in each scan's coverage section when applicable.

## Verification gates

For each scanner, build or run it from its local source on Windows and macOS, capture its installed version, run a known safe fixture, verify output parsing, force a failure case, and verify the UI shows the resulting limitation and remedy. Run end-to-end URL scans against an authorized test application with public and authenticated routes. Check that disabled checks, missing tools, login failure, rate limits, timeouts, and empty findings produce distinct coverage states. Verify remediation guidance against observed evidence and rescan behavior after a controlled fix.
