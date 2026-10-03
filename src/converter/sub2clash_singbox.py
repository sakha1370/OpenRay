"""Legacy five-argument converter command; shared protocol implementation."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from openray.converter_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
