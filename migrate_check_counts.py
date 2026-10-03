"""Compatibility migration command. Legacy files are backed up and retained."""

from openray.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["migrate"]))
