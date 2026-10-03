"""Compatibility connection audit; repairs require --apply and preserve a backup."""

from openray.audit_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
