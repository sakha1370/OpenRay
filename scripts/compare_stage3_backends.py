"""Compatibility benchmark command. Uses equal bounded concurrency and true wall time."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from openray.benchmarks import main

if __name__ == "__main__":
    raise SystemExit(main(["--core", *sys.argv[1:]]))
