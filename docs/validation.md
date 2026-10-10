# Validation status

The GitHub Actions jobs are run from a fresh repository checkout. They do not reuse scanner binaries or source repositories from the developer's Mac.

| Check | macOS | Windows |
| --- | --- | --- |
| App and dashboard bootstrap from clone | Passed in [native CI](https://github.com/MalyajNailwal/ProjectN/actions/workflows/native-smoke.yml) | Passed in native CI |
| Python tests, API startup, dashboard response | Passed in native CI | Passed in native CI |
| Bundled local website fixture scan and report | Passed in native CI | Passed in native CI |
| Pinned WhatWeb source clone, Ruby setup, and real scanner stage | Passed in native CI | Passed in native CI |
| Pinned Semgrep engine/rules source, native runtime, and local pattern scan | Not in native CI; local runtime ready | Passed in [Windows source scanner CI](https://github.com/MalyajNailwal/ProjectN/actions/runs/38007222627) |
| All 16 upstream source repositories present locally | Passed on developer Mac with `clone_sources.py --verify` | Not part of native CI |
| All 12 scanner capabilities ready | Passed on developer Mac with `doctor.py --strict` | Not yet verified |
| Go scanner binaries built from pinned source | Passed on developer Mac | Separate [Windows build workflow](https://github.com/MalyajNailwal/ProjectN/actions/workflows/windows-go-scanners.yml); check latest run |
| Full active website scan with ZAP and browser checks | Tested on developer Mac against local fixture | Not yet verified |

Fresh clone quick start and the reviewer demo are in [README.md](../README.md). Run `python scripts/doctor.py --strict` with the project's virtual environment after full setup; it lists each missing component and exits unsuccessfully unless every configured scanner is ready.

The native CI confirms the app and one real external scanner on both platforms. It does not demonstrate complete website coverage or full Windows scanner installation. Scanner versions, target responses, authenticated journeys, and rules determine actual per-scan coverage, which the report records separately.
