# Product research: local security assessment

Research date: 2026-10-09. This is a feature benchmark from primary product documentation, not an implementation status report.

## Patterns worth adopting

| Product/documentation | Observed capability | Local product implication |
| --- | --- | --- |
| Burp Scanner | Browser-powered crawl, authenticated and unauthenticated paths, crawl map, configurable audit, granular scan failures | Preserve crawl path and authentication state; show per-check failures |
| Detectify | Surface monitoring for assets/services and deep application/API scans as separate workflows | Separate network/domain discovery from targeted web/API tests |
| Pentest-Tools.com | Proof-backed findings, screenshots/request evidence, remediation and rescan | Require evidence and fix verification for each finding |
| MDN HTTP Observatory | Focused header/configuration assessment with linked remediation | Provide a dedicated hardening section, not only vulnerability alerts |
| Qualys SSL Labs | Detailed TLS configuration testing | Treat TLS as its own assessment with protocol/certificate evidence |
| OWASP ASVS | Requirements across authentication, sessions, access control, validation, API, and configuration | Use versioned control mapping and mark untested controls explicitly |

## Differentiation to validate

One local project can connect website, network host, API specification, and source repository evidence without sending scan data to a hosted platform. Report coverage, failed checks, and required next inputs alongside findings. Use concrete remediation and post-fix rescan states. Keep security, site quality, and uncertain AI provenance separate.

## Primary sources

- https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans/full-crawl-and-audit
- https://portswigger.net/burp/documentation/scanner/auditing
- https://docs.detectify.com/getting-started/your-first-scan
- https://pentest-tools.com/website-vulnerability-scanning/website-scanner
- https://developer.mozilla.org/en-US/observatory
- https://www.ssllabs.com/ssltest/index/
- https://devguide.owasp.org/en/03-requirements/05-asvs/
- https://nmap.org/book/man-port-scanning-basics.html
- https://nmap.org/book/inst-windows.html
