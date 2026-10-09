"""Copy locally built ZAP add-ons into the locally built core distribution."""

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ADDONS = ROOT / "tools/web/application-scanner/add-ons/addOns"
PLUGINS = ROOT / "tools/web/application-scanner/core/zap/build/distFiles/plugin"
CONFIG = json.loads((ROOT / "config/application_scan.json").read_text())


def main():
    PLUGINS.mkdir(parents=True, exist_ok=True)
    missing = []
    for name in CONFIG["addons"]:
        candidates = sorted((ADDONS / name / "build/zapAddOn/bin").glob("*.zap"))
        if not candidates:
            missing.append(name)
            continue
        shutil.copy2(candidates[-1], PLUGINS / candidates[-1].name)
        print(f"{name}: {candidates[-1].name}")
    if missing:
        raise SystemExit("Missing built add-ons: " + ", ".join(missing))


if __name__ == "__main__":
    main()
