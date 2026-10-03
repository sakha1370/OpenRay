from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from .config import Settings
from .domain import ParseError, extract_uris, parse_uri
from .fetch import Fetcher, Source
from .files import atomic_write, json_text
from .render import convert
from .storage import Store
from .yamlio import dump_yaml


def main(argv=None) -> int:
    import yaml

    p = argparse.ArgumentParser(description="Convert subscriptions with explicit capability reports")
    for name in ("input", "clash_template", "singbox_template", "clash_output", "singbox_output"):
        p.add_argument(name, type=Path if name != "input" else str)
    args = p.parse_args(argv)
    report = []
    if args.input.startswith(("http://", "https://")):

        async def fetch():
            with (
                tempfile.TemporaryDirectory() as temporary,
                Store(Path(temporary) / "state.sqlite3") as store,
            ):
                async with Fetcher(Settings.from_env(), store) as fetcher:
                    result = await fetcher.fetch(Source(args.input))
                    outcome = store.db.execute(
                        "SELECT outcome FROM source WHERE url=?", (args.input,)
                    ).fetchone()
                    if not outcome or outcome[0] != "success":
                        raise ValueError("subscription fetch failed; existing exports retained")
                    return result

        uris = asyncio.run(fetch())
    else:
        uris = extract_uris(Path(args.input).read_text(encoding="utf-8"))
    proxies = {}
    for uri in uris:
        try:
            proxy = parse_uri(uri)
            proxies.setdefault(proxy.identity, proxy)
        except (ParseError, UnicodeError):
            report.append({"format": "input", "reason": "invalid URI"})
    if not proxies:
        print("No valid input connections; existing exports retained")
        return 2
    clash, sing, omissions = convert(
        list(proxies.values()),
        yaml.safe_load(args.clash_template.read_text(encoding="utf-8")),
        json.loads(args.singbox_template.read_text(encoding="utf-8")),
    )
    atomic_write(args.clash_output, dump_yaml(clash))
    atomic_write(args.singbox_output, json_text(sing))
    atomic_write(args.singbox_output.with_suffix(".report.json"), json_text(report + omissions))
    print(
        json_text(
            {
                "input": len(uris),
                "connections": len(proxies),
                "omissions": len(omissions),
                "invalid": len(report),
            }
        ),
        end="",
    )
    return 2 if uris and not proxies else 0


def legacy(regional: bool = False, argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        settings = Settings.from_env()
        root = settings.root
        assets = Path(__file__).parent / "assets"
        clash = root / "src/converter/config.yaml"
        sing = root / "src/converter/singbox.json"
        if not clash.is_file():
            clash = assets / "clash-template.json"
        if not sing.is_file():
            sing = assets / "singbox-template.json"
        args = [
            str(root / ("output_iran/all_valid_proxies_for_iran.txt" if regional else "test.txt")),
            str(clash),
            str(sing),
            str(root / ("output_iran/converted/clash.yaml" if regional else "clash.yaml")),
            str(
                root
                / (
                    "output_iran/converted/iran_all_valid_proxies_singbox_config.json"
                    if regional
                    else "singbox.json"
                )
            ),
        ]
    return main(args)
