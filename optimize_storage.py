"""Compatibility maintenance command; default is a non-mutating dry run."""

import sys
from openray.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["maintenance", *sys.argv[1:]]))
