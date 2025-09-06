from __future__ import annotations

import json
import os
import hashlib
import struct
import time
from typing import Iterable, List, Set, Dict

try:
    from .constants import STATE_DIR, OUTPUT_DIR, TESTED_FILE, AVAILABLE_FILE, STREAKS_FILE
except ImportError:
    # Fallback for standalone usage
    import os
    REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATE_DIR = os.path.join(REPO_ROOT, '.state')
    OUTPUT_DIR = os.path.join(REPO_ROOT, 'output')
    TESTED_FILE = os.path.join(STATE_DIR, 'tested.txt')
    AVAILABLE_FILE = os.path.join(OUTPUT_DIR, 'all_valid_proxies.txt')
    STREAKS_FILE = os.path.join(STATE_DIR, 'streaks.json')


def ensure_dirs() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.rstrip('\r\n') for line in f]


def append_lines(path: str, lines: Iterable[str]) -> None:
    if not lines:
        return
    with open(path, 'a', encoding='utf-8', errors='ignore') as f:
        for line in lines:
            f.write(line)
            if not line.endswith('\n'):
                f.write('\n')


def write_text_file_atomic(path: str, lines: List[str]) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
        for ln in lines:
            f.write(ln)
            f.write('\n')
    os.replace(tmp, path)


# Persistence helpers

def load_tested_hashes() -> Set[str]:
    tested: Set[str] = set()
    for line in read_lines(TESTED_FILE):
        h = line.strip()
        if h:
            tested.add(h)
    return tested


def load_existing_available() -> Set[str]:
    existing: Set[str] = set()
    for line in read_lines(AVAILABLE_FILE):
        s = line.strip()
        if s:
            existing.add(s)
    return existing


def load_streaks() -> Dict[str, Dict[str, int]]:
    try:
        if not os.path.exists(STREAKS_FILE):
            return {}
        with open(STREAKS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Ensure numeric fields are ints
                cleaned: Dict[str, Dict[str, int]] = {}
                for host, obj in data.items():
                    if not isinstance(obj, dict):
                        continue
                    streak = int(obj.get('streak', 0))
                    last_test = int(obj.get('last_test', 0))
                    last_success = int(obj.get('last_success', 0))
                    cleaned[host] = {'streak': streak, 'last_test': last_test, 'last_success': last_success}
                return cleaned
    except Exception:
        pass
    return {}


def save_streaks(streaks: Dict[str, Dict[str, int]]) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STREAKS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
            json.dump(streaks, f, ensure_ascii=False)
        os.replace(tmp, STREAKS_FILE)
    except Exception:
        # best-effort; ignore
        pass


# Optimized tested hashes storage using binary format
TESTED_BIN_FILE = TESTED_FILE + '.bin'

def hash_to_bytes(hash_str: str) -> bytes:
    """Convert hex hash string to 20 bytes."""
    return bytes.fromhex(hash_str)

def bytes_to_hash(hash_bytes: bytes) -> str:
    """Convert 20 bytes back to hex hash string."""
    return hash_bytes.hex()

def load_tested_hashes_optimized() -> Set[str]:
    """Load tested hashes from optimized binary storage with fallback to text."""
    tested: Set[str] = set()

    # Try optimized binary format first
    if os.path.exists(TESTED_BIN_FILE):
        try:
            with open(TESTED_BIN_FILE, 'rb') as f:
                # Read file in chunks for memory efficiency
                while True:
                    # Read timestamp (8 bytes) + hash (20 bytes) = 28 bytes per entry
                    entry = f.read(28)
                    if not entry:
                        break
                    if len(entry) != 28:
                        continue  # Skip malformed entries
                    timestamp, hash_bytes = struct.unpack('>Q20s', entry)
                    tested.add(bytes_to_hash(hash_bytes))
            return tested
        except Exception:
            # Fallback to text format if binary is corrupted
            pass

    # Fallback to text format
    tested.update(load_tested_hashes())

    # Migrate to optimized format in background
    if tested:
        try:
            migrate_to_optimized_format(tested)
        except Exception:
            pass  # Migration failure shouldn't break loading

    return tested

def migrate_to_optimized_format(hashes: Set[str]) -> None:
    """Migrate existing text format to optimized binary format."""
    if not hashes:
        return

    current_time = int(time.time())
    entries = []

    for hash_str in hashes:
        hash_str = hash_str.strip()
        if not hash_str:
            continue
        try:
            hash_bytes = hash_to_bytes(hash_str)
            entries.append(struct.pack('>Q20s', current_time, hash_bytes))
        except Exception as e:
            # Log invalid hashes but continue
            print(f"Warning: Skipping invalid hash: {hash_str[:16]}... ({e})")
            continue

    if entries:
        try:
            # Write all entries at once for better performance
            with open(TESTED_BIN_FILE + '.tmp', 'wb') as f:
                f.write(b''.join(entries))
            os.replace(TESTED_BIN_FILE + '.tmp', TESTED_BIN_FILE)
            print(f"Successfully migrated {len(entries)} hashes to binary format")
        except Exception as e:
            print(f"Migration failed: {e}")
            pass  # Migration failure is non-critical

def append_tested_hashes_optimized(new_hashes: Iterable[str]) -> None:
    """Append new hashes to optimized storage with deduplication."""
    if not new_hashes:
        return

    # Load existing hashes to check for duplicates
    existing_hashes = load_tested_hashes_optimized()
    current_time = int(time.time())
    new_entries = []

    for hash_str in new_hashes:
        hash_str = hash_str.strip()
        if not hash_str or hash_str in existing_hashes:
            continue

        try:
            hash_bytes = hash_to_bytes(hash_str)
            new_entries.append(struct.pack('>Q20s', current_time, hash_bytes))
            existing_hashes.add(hash_str)
        except Exception:
            continue  # Skip invalid hashes

    if new_entries:
        try:
            with open(TESTED_BIN_FILE, 'ab') as f:
                for entry in new_entries:
                    f.write(entry)
        except Exception:
            # Fallback to text format
            append_lines(TESTED_FILE, (h for h in new_hashes if h.strip()))

def cleanup_old_hashes(days_to_keep: int = 30) -> int:
    """Remove hashes older than specified days. Returns number of removed entries."""
    if not os.path.exists(TESTED_BIN_FILE):
        return 0

    cutoff_time = int(time.time()) - (days_to_keep * 24 * 60 * 60)
    kept_entries = []
    removed_count = 0

    try:
        with open(TESTED_BIN_FILE, 'rb') as f:
            while True:
                entry = f.read(28)
                if not entry:
                    break
                if len(entry) != 28:
                    continue
                timestamp, hash_bytes = struct.unpack('>Q20s', entry)
                if timestamp >= cutoff_time:
                    kept_entries.append(entry)
                else:
                    removed_count += 1

        if removed_count > 0:
            # Rewrite file with only kept entries
            with open(TESTED_BIN_FILE + '.tmp', 'wb') as f:
                for entry in kept_entries:
                    f.write(entry)
            os.replace(TESTED_BIN_FILE + '.tmp', TESTED_BIN_FILE)

    except Exception:
        pass  # Cleanup failure is non-critical

    return removed_count

def get_storage_stats() -> Dict[str, int]:
    """Get statistics about current storage usage."""
    stats = {
        'text_file_size': 0,
        'binary_file_size': 0,
        'text_entries': 0,
        'binary_entries': 0,
        'unique_hashes': 0
    }

    # Text file stats
    if os.path.exists(TESTED_FILE):
        stats['text_file_size'] = os.path.getsize(TESTED_FILE)
        try:
            with open(TESTED_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip()]
                stats['text_entries'] = len(lines)
                stats['unique_hashes'] = len(set(lines))
        except Exception:
            pass

    # Binary file stats
    if os.path.exists(TESTED_BIN_FILE):
        stats['binary_file_size'] = os.path.getsize(TESTED_BIN_FILE)
        stats['binary_entries'] = stats['binary_file_size'] // 28  # 28 bytes per entry

    return stats
