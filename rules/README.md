# ProjectN's own checks

This folder holds checks written for ProjectN. They are part of this repository under ProjectN's MIT license, run alongside the pinned upstream rule sets, and can be used, shared, bundled, or offered in a hosted service without the restrictions that apply to some upstream rules.

| Folder | Scanner | Runs in |
| --- | --- | --- |
| `semgrep/` | Semgrep rules (YAML) | Every scan with a local folder or GitHub repository |
| `nuclei/` | Nuclei templates (YAML) | Deep and Full website scans |

Current checks:

- `semgrep/browser-secrets.yaml` → `public-env-secret`: a browser-public environment variable (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `PUBLIC_`) whose name says it holds a secret, private key, password, or service role.
- `semgrep/browser-secrets.yaml` → `supabase-service-role-key`: a Supabase JWT with the `service_role` claim written in a file.
- `nuclei/supabase-service-role-key-exposed.yaml`: the same key in a page or its first same-origin script.
- `nuclei/client-side-api-keys-exposed.yaml`: a secret OpenAI, Anthropic, Stripe, or AWS key in a page or its first same-origin script (the same patterns Gitleaks already uses for source code, applied to the live site so a URL-only scan catches it too).

## Add a check

1. Add a rule file to `semgrep/` or a template to `nuclei/`. Put the fix in `metadata.fix` (Semgrep) or `info.remediation` (Nuclei); ProjectN shows it as the finding's remediation.
2. Prefer checks the upstream sets do not already cover (search `tools/code/static-analyzer/checks` and `tools/web/template-scanner/checks`), so reports do not repeat the same issue under two rule IDs.
3. Add a case to `tests/test_own_rules.py` that proves the check finds the issue and ignores the safe variant. Build any key-shaped test values at test time; never commit real or realistic secrets.
4. Run `python -m unittest tests.test_own_rules -v` with the environment's Python. The tests use the installed scanners and skip when they are not set up.

The rule revision recorded with each scan includes these files, so changing a check makes rescans of earlier findings "not verifiable" instead of reporting them as fixed.
