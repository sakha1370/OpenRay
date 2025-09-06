from __future__ import annotations

import os
from typing import List, Dict
import socket
import json

# Patch constants BEFORE importing modules that read them
from . import constants as C

# Determine input proxies file (existing curated list)
INPUT_FILE = os.path.join(C.REPO_ROOT, 'output', 'all_valid_proxies.txt')

# Redirect state and output to Iran-specific locations
C.STATE_DIR = os.path.join(C.REPO_ROOT, '.state_iran')
C.OUTPUT_DIR = os.path.join(C.REPO_ROOT, 'output_iran')

# Recompute dependent constant paths
C.TESTED_FILE = os.path.join(C.STATE_DIR, 'tested.txt')
C.AVAILABLE_FILE = os.path.join(C.OUTPUT_DIR, 'all_valid_proxies_for_iran.txt')
C.STREAKS_FILE = os.path.join(C.STATE_DIR, 'streaks.json')
C.KIND_DIR = os.path.join(C.OUTPUT_DIR, 'kind')
C.COUNTRY_DIR = os.path.join(C.OUTPUT_DIR, 'country')

# Provide an empty sources file so the main pipeline skips fetching new sources
EMPTY_SOURCES = os.path.join(C.REPO_ROOT, 'sources_iran.txt')
C.SOURCES_FILE = EMPTY_SOURCES

# Iran-specific check count tracking files
CHECK_COUNTS_FILE = os.path.join(C.STATE_DIR, 'check_counts.json')
TOP100_FILE = os.path.join(C.OUTPUT_DIR, 'iran_top100_checked.txt')

# Now import the rest of the pipeline after patching constants
from .common import log  # noqa: E402
from .io_ops import ensure_dirs, read_lines, write_text_file_atomic  # noqa: E402
from . import main as main_pipeline  # noqa: E402


def _seed_available_from_input() -> None:
    """Seed the Iran-specific AVAILABLE_FILE with contents of INPUT_FILE (if present)."""
    try:
        ensure_dirs()
        lines: List[str] = []
        if os.path.exists(INPUT_FILE):
            lines = [ln.strip() for ln in read_lines(INPUT_FILE) if ln.strip()]
        else:
            log(f"Input not found: {INPUT_FILE}")
        # write_text_file_atomic(C.AVAILABLE_FILE, lines)
        # Ensure empty sources file exists so main() doesn't exit
        try:
            if not os.path.exists(EMPTY_SOURCES):
                with open(EMPTY_SOURCES, 'w', encoding='utf-8') as f:
                    f.write('')
        except Exception:
            pass
    except Exception as e:
        log(f"Seeding available proxies failed: {e}")

def _load_check_counts() -> Dict[str, int]:
    try:
        if os.path.exists(CHECK_COUNTS_FILE):
            with open(CHECK_COUNTS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # ensure keys are strings and values are ints
                    return {str(k): int(v) for k, v in data.items()}
    except Exception as e:
        log(f"Failed to load check counts: {e}")
    return {}


def _cleanup_check_counts(active_proxies: List[str]) -> None:
    """Remove check counts for proxies that are no longer active."""
    if not active_proxies:
        return

    counts = _load_check_counts()
    active_set = set(active_proxies)

    # Filter counts to only include active proxies
    cleaned_counts = {proxy: count for proxy, count in counts.items() if proxy in active_set}

    # Only save if there are changes
    if len(cleaned_counts) != len(counts):
        removed_count = len(counts) - len(cleaned_counts)
        log(f"Cleaned up check counts: removed {removed_count} inactive proxies")
        _save_check_counts(cleaned_counts)


def _save_check_counts(counts: Dict[str, int]) -> None:
    try:
        ensure_dirs()
        os.makedirs(os.path.dirname(CHECK_COUNTS_FILE), exist_ok=True)
        tmp = CHECK_COUNTS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
            json.dump(counts, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CHECK_COUNTS_FILE)
    except Exception as e:
        log(f"Failed to save check counts: {e}")


def _update_check_counts_for_proxies(proxies: List[str], active_proxies: List[str] = None) -> None:
    if not proxies:
        return
    counts = _load_check_counts()

    # If active_proxies is provided, only update counts for active proxies
    active_set = set(active_proxies) if active_proxies else None

    for p in proxies:
        if not p:
            continue
        # Skip if proxy is not in active list (when provided)
        if active_set is not None and p not in active_set:
            continue
        counts[p] = int(counts.get(p, 0)) + 1
    _save_check_counts(counts)


def _write_top100_by_checks(active_proxies: List[str]) -> None:
    try:
        counts = _load_check_counts()
        # Score each active proxy by its check count (default 0)
        scored = [(counts.get(p, 0), idx, p) for idx, p in enumerate(active_proxies)]
        # Sort by count desc, then by original order asc (stable tie-break)
        scored.sort(key=lambda t: (-t[0], t[1]))
        top = [p for _, _, p in scored[:100]]
        write_text_file_atomic(TOP100_FILE, top)
        log(f"Wrote top {len(top)} checked active proxies to {TOP100_FILE}")
    except Exception as e:
        log(f"Failed to write top100 checked proxies: {e}")


def check_internet_socket(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False


def main() -> int:
    _seed_available_from_input()

    # Capture the list of proxies that will be rechecked by the main pipeline this run
    pre_existing: List[str] = []
    try:
        if os.path.exists(C.AVAILABLE_FILE):
            pre_existing = [ln.strip() for ln in read_lines(C.AVAILABLE_FILE) if ln.strip()]
    except Exception:
        pre_existing = []

    rc = main_pipeline.main()

    if rc == 0:
        # Build top 100 among currently active proxies
        try:
            active_now: List[str] = []
            if os.path.exists(C.AVAILABLE_FILE):
                active_now = [ln.strip() for ln in read_lines(C.AVAILABLE_FILE) if ln.strip()]

            # Clean up check counts to only include active proxies
            _cleanup_check_counts(active_now)

            # After pipeline finishes, update check counts for proxies that were revalidated
            # Only update counts for proxies that are still active
            _update_check_counts_for_proxies(pre_existing, active_now)

            _write_top100_by_checks(active_now)
        except Exception as e:
            log(f"Active proxies processing failed: {e}")
    else:
        log(f"Skipping check-count update and top100 generation due to pipeline return code {rc}")

    return rc


if __name__ == '__main__':
    if check_internet_socket():
        print("✅ Internet connection is available")
        raise SystemExit(main())
    else:
        print("❌ No internet connection")
