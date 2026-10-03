"""Legacy converter entry point; five positional arguments match the shared converter."""

from openray.converter_cli import legacy

if __name__ == "__main__":
    raise SystemExit(legacy())
