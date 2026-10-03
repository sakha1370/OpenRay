"""Compatibility maintenance command; SQLite observations are preserved."""

import sys
from openray.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["maintenance", *sys.argv[1:]]))
