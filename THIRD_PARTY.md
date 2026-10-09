# Third-party scanners and rules

ProjectN's root [MIT license](LICENSE) covers ProjectN's own code and documentation. It does not relicense the upstream scanner repositories, their rules, templates, add-ons, dependencies, or downloaded runtimes. Those are downloaded into ignored `tools/` folders from the URLs in `config/scanners.json` at the revisions in `config/source-lock.json`.

Each upstream repository has its own license file. Run `python scripts/source_manifest.py` after cloning sources to record the local commit and top-level license filenames in `data/source-manifest.json`. Review the actual license text in each checkout before redistributing its source or binaries.

The Semgrep-maintained rules repository uses the separate [Semgrep Rules License](https://semgrep.dev/legal/rules-license/). Its terms limit use to internal business purposes and do not allow offering those rules as a service. ProjectN does not include those rules in its Git repository. A future hosted service must use rules licensed for that service or obtain permission from the rights holder.

WhatWeb has a GPL license; distribution of WhatWeb or modified copies requires separate compliance with its license. ProjectN runs it as a separate local program. The project also uses Nmap, ZAP, Nuclei, Gitleaks, Playwright, axe, Lighthouse, OSV-Scanner, and other upstream components; do not assume ProjectN's MIT license applies to them.
