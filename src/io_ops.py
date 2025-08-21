from __future__ import annotations

import json
import os
from typing import Iterable, List, Set, Dict

from .constants import STATE_DIR, OUTPUT_DIR, TESTED_FILE, AVAILABLE_FILE, STREAKS_FILE


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
