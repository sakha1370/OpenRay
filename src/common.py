"""Compatibility helpers backed by the shared connection model."""

import hashlib
import threading
from openray.domain import b64decode, parse_uri

_lock = threading.Lock()


def log(msg):
    with _lock:
        print(msg, flush=True)


def progress(iterable, total=None):
    return iterable


def sha1_hex(value):
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def safe_b64decode_to_bytes(value):
    try:
        return b64decode("".join(value.split()))
    except ValueError:
        return None


def normalize_proxy_uri(uri):
    return parse_uri(uri).identity


def get_proxy_connection_hash(uri):
    return sha1_hex(normalize_proxy_uri(uri))


def get_openray_dedup_key(uri):
    return parse_uri(uri).identity


get_v2rayn_connection_key = get_openray_dedup_key
