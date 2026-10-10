# Contributing to ProjectN

ProjectN is a local security assessment app. Changes to ProjectN's dashboard, API, scanner adapters, reports, documentation, and setup scripts belong in this repository. Third-party scanner sources under `tools/` are separate Git repositories; send upstream changes to their respective maintainers and update `config/source-lock.json` when ProjectN adopts a new revision.

## Set up

Follow the platform-specific quick start in [README.md](README.md). `python3 scripts/bootstrap.py` on macOS or `py -3 scripts/bootstrap.py` on Windows installs the app and dashboard. Full scanner setup is optional and needs additional native toolchains. The app remains usable with missing scanners and reports those gaps at `/api/scanners` and in each scan report.

## Verify a change

Run the Python suite with your local environment's Python:

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/smoke_local.py
```

On Windows PowerShell, replace `.venv/bin/python` with `.\.venv\Scripts\python.exe`. Run `npm run build --prefix web` after changing the dashboard. GitHub Actions runs these checks on macOS and Windows for every pull request.

Do not commit `tools/`, `.venv/`, `web/node_modules/`, `web/dist/`, `data/`, API keys, customer scan reports, or scanner output. Put scanner paths, arguments, and timeouts in `config/scanners.json`; keep source revisions in `config/source-lock.json`. Add focused tests for changed behavior and document observable coverage limits.

## Add a check

ProjectN's own Semgrep rules and Nuclei templates live in [`rules/`](rules/README.md) under ProjectN's MIT license and run with every scan. Add the check there with a test in `tests/test_own_rules.py`; do not edit the upstream rule sets under `tools/`.

## Update scanner versions

Upstream sources stay pinned in `config/source-lock.json` and never update on their own. To bring them forward deliberately:

```sh
python scripts/clone_sources.py --upstream                 # shows which pins have newer upstream commits
python scripts/clone_sources.py --update --path <folder>   # moves those pins and clean local checkouts
```

The command prints the `setup_native.py` components to rebuild. Run them, then `scripts/doctor.py --strict`, the tests, and `scripts/smoke_local.py`, and commit the lock file only after they pass. A checkout with local edits is never moved. To change a scanner itself, fork it and point its `upstream` URL in `config/scanners.json` and its commit in `config/source-lock.json` at the fork.

For a security issue in ProjectN itself, follow [SECURITY.md](SECURITY.md). Only scan targets you are authorized to assess.
