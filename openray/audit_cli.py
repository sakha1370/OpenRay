"""Non-destructive output audit; applying a repair always preserves a backup."""

import argparse
from pathlib import Path

from .config import Settings
from .domain import ParseError, extract_uris, parse_uri
from .files import atomic_write, json_text, lines_text
from .storage import file_sha256


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path", nargs="?", type=Path, default=Settings.from_env().root / "output/all_valid_proxies.txt"
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    content = args.path.read_text(encoding="utf-8")
    if any(line.startswith(("<<<<<<<", "=======", ">>>>>>>")) for line in content.splitlines()):
        raise ValueError(
            "conflict markers require a verified snapshot restore; automatic side selection is disabled"
        )
    values, duplicates, invalid = {}, 0, 0
    for uri in extract_uris(content):
        try:
            proxy = parse_uri(uri)
            if proxy.identity in values:
                duplicates += 1
            else:
                values[proxy.identity] = proxy
        except ParseError:
            invalid += 1
    if args.apply:
        backup = args.path.with_name(args.path.name + "." + file_sha256(args.path)[:12] + ".bak")
        if not backup.exists():
            atomic_write(backup, args.path.read_bytes())
        atomic_write(args.path, lines_text(p.uri for p in sorted(values.values(), key=lambda p: p.identity)))
    print(
        json_text(
            {
                "connections": len(values),
                "duplicates": duplicates,
                "invalid": invalid,
                "dry_run": not args.apply,
            }
        ),
        end="",
    )
    return 0
