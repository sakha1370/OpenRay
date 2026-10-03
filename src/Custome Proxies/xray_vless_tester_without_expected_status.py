"""Compatibility status tester; synthetic probes use supervised core workers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from openray.custom_cli import main

if __name__ == "__main__":
    raise SystemExit(main(expected=False))
