"""Compatibility grouped exports with deterministic identities and empty cleanup."""

from collections import defaultdict
from pathlib import Path
from openray.domain import parse_uri
from openray.files import atomic_write, lines_text
from .constants import AVAILABLE_FILE, KIND_DIR, COUNTRY_DIR
from .io_ops import read_lines


def write_grouped_outputs():
    values = {}
    for uri in read_lines(AVAILABLE_FILE):
        if not uri.strip():
            continue
        p = parse_uri(uri)
        values.setdefault(p.identity, p)
    for directory, attribute in [(Path(KIND_DIR), "scheme"), (Path(COUNTRY_DIR), "country")]:
        groups = defaultdict(list)
        for p in sorted(values.values(), key=lambda p: p.identity):
            groups[getattr(p, attribute)].append(p.uri)
        directory.mkdir(parents=True, exist_ok=True)
        for name, uris in groups.items():
            atomic_write(directory / (name + ".txt"), lines_text(uris))
        for path in directory.glob("*.txt"):
            if path.stem not in groups:
                path.unlink()


def regroup_available_by_country():
    values = {}
    for uri in read_lines(AVAILABLE_FILE):
        if not uri.strip():
            continue
        p = parse_uri(uri)
        values.setdefault(p.identity, p)
    atomic_write(
        Path(AVAILABLE_FILE),
        lines_text(p.uri for p in sorted(values.values(), key=lambda p: (p.country, p.identity))),
    )
    write_grouped_outputs()
