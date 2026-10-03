"""Compatibility ranking command: exports one consistent SQLite view."""

from openray.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["export", "--install"]))
