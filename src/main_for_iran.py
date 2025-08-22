from __future__ import annotations

import os
from typing import List
import socket

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

def check_internet_socket(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False

def main() -> int:
    _seed_available_from_input()
    return main_pipeline.main()


if __name__ == '__main__':
    if check_internet_socket():
        print("✅ Internet connection is available")
        raise SystemExit(main())
    else:
        print("❌ No internet connection")
