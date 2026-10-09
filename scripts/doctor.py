"""Show local scanner readiness and return a failure for incomplete full setups."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import readiness, specs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Exit with an error if any configured scanner is not ready")
    options = parser.parse_args()
    states = [readiness(spec) for spec in specs()]
    for state in states:
        print(f"{'READY  ' if state['ready'] else 'MISSING'} {state['label']}")
        if not state["ready"]:
            for reason in state["limitations"]:
                print(f"        {reason}")
            if state["resolution"]:
                print(f"        Next: {state['resolution']}")
    count = sum(state["ready"] for state in states)
    print(f"{count}/{len(states)} scanner capabilities ready")
    return 1 if options.strict and count != len(states) else 0


if __name__ == "__main__":
    raise SystemExit(main())
