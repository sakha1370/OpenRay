"""Compatibility entry point. The implementation lives in openray."""

from openray.cli import legacy


def main() -> int:
    return legacy("sites")


if __name__ == "__main__":
    raise SystemExit(main())
