"""Compatibility file helpers. SQLite is authoritative for history; imports are read-only."""

import os
import time
from pathlib import Path
from openray.config import Settings
from openray.files import atomic_write, lines_text
from openray.storage import Store
from .constants import STATE_DIR, OUTPUT_DIR, AVAILABLE_FILE, TESTED_FILE

TESTED_BIN_FILE = TESTED_FILE + ".bin"


def get_state_dir():
    return STATE_DIR


def get_output_dir():
    return OUTPUT_DIR


def get_available_file():
    return AVAILABLE_FILE


def get_tested_file():
    return TESTED_FILE


def get_tested_bin_file():
    return TESTED_BIN_FILE


def ensure_dirs():
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)


def read_lines(path):
    p = Path(path)
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


def write_text_file_atomic(path, lines):
    atomic_write(Path(path), lines_text(lines))


def append_lines(path, lines):
    from openray.locking import file_lock

    p = Path(path)
    with file_lock(p.with_suffix(p.suffix + ".lock")):
        write_text_file_atomic(p, read_lines(p) + list(lines))


def load_existing_available():
    return set(read_lines(AVAILABLE_FILE))


def hash_to_bytes(value):
    raw = bytes.fromhex(value)
    if len(raw) != 20:
        raise ValueError("SHA1 requires twenty bytes")
    return raw


def bytes_to_hash(value):
    return value.hex()


def load_tested_hashes_optimized():
    with Store(Settings.from_env().database) as store:
        return {bytes(r[0]).hex() for r in store.db.execute("SELECT hash FROM legacy_tested")}


load_tested_hashes = load_tested_hashes_optimized


def append_tested_hashes_optimized(hashes):
    with Store(Settings.from_env().database) as store, store.transaction() as db:
        db.executemany(
            "INSERT OR IGNORE INTO legacy_tested VALUES(?,?)",
            [(hash_to_bytes(h), int(time.time())) for h in hashes],
        )


migrate_to_optimized_format = append_tested_hashes_optimized


def cleanup_old_hashes(days_to_keep=90):
    from openray.maintenance import maintain

    with Store(Settings.from_env().database) as store:
        return maintain(store, days_to_keep, True)["legacy_hashes_to_prune"]


def get_storage_stats():
    with Store(Settings.from_env().database) as store:
        return dict(store.status(), binary_size_mb=store.path.stat().st_size / (1024 * 1024))


def get_all_tested_files():
    return [str(p) for p in sorted(Path(STATE_DIR).glob("tested*.txt*")) if p.is_file()]


def get_current_tested_file():
    files = get_all_tested_files()
    return files[-1] if files else TESTED_FILE


def should_rotate_tested_file(max_size_mb=10):
    return False


def rotate_tested_file():
    raise RuntimeError("SQLite replaces legacy history rotation; use openray maintenance")


def load_streaks():
    return {}


def save_streaks(values):
    if values:
        raise ValueError("host-keyed streak state was retired; use connection health")
