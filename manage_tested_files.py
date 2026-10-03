"""Compatibility state status and maintenance command."""

import argparse
from openray.cli import main

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["status", "monitor", "cleanup"], default="status", nargs="?")
    p.add_argument("--cleanup-days", type=int, default=90)
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()
    command = (
        ["maintenance", "--retention-days", str(a.cleanup_days)] if a.action == "cleanup" else ["status"]
    )
    if a.apply and a.action == "cleanup":
        command.append("--apply")
    raise SystemExit(main(command))
