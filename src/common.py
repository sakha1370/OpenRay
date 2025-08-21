from __future__ import annotations

import base64
import hashlib
import threading

try:
    from tqdm import tqdm as _tqdm  # type: ignore

    def progress(iterable, total=None):
        return _tqdm(iterable, total=total)
except Exception:

    def progress(iterable, total=None):
        return iterable

_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8', errors='ignore')).hexdigest()


def safe_b64decode_to_bytes(s: str) -> bytes | None:
    """Try to base64-decode a string with leniency (padding, URL-safe). Returns None on failure."""
    if not s:
        return None
    # Remove whitespace
    compact = ''.join(s.split())
    # Convert URL-safe variants
    compact = compact.replace('-', '+').replace('_', '/')
    # Pad
    padding = (-len(compact)) % 4
    compact += '=' * padding
    try:
        return base64.b64decode(compact, validate=False)
    except Exception:
        return None
