from __future__ import annotations

import os
from typing import Dict, List, Set

from .constants import AVAILABLE_FILE, KIND_DIR, COUNTERY_DIR
from .common import log
from .io_ops import read_lines, write_text_file_atomic
from .parsing import _extract_our_cc_and_num_from_uri


def write_grouped_outputs() -> None:
    """Generate per-kind and per-country files from AVAILABLE_FILE.

    - output\kind\<scheme>.txt
    - output\countery\<CC>.txt (uses existing remark format; falls back to XX)
    """
    try:
        lines = [ln.strip() for ln in read_lines(AVAILABLE_FILE) if ln.strip()]
        if not lines:
            return

        # Group by scheme (kind)
        kind_order: List[str] = []
        kind_groups: Dict[str, List[str]] = {}
        for s in lines:
            scheme = s.split('://', 1)[0].lower() if '://' in s else 'unknown'
            if not scheme:
                scheme = 'unknown'
            if scheme not in kind_groups:
                kind_groups[scheme] = []
                kind_order.append(scheme)
            kind_groups[scheme].append(s)

        os.makedirs(KIND_DIR, exist_ok=True)
        produced_kind: Set[str] = set()
        for scheme in kind_order:
            out_path = os.path.join(KIND_DIR, f'{scheme}.txt')
            write_text_file_atomic(out_path, kind_groups[scheme])
            produced_kind.add(f'{scheme}.txt')
        # Remove stale kind txt files
        try:
            for name in os.listdir(KIND_DIR):
                p = os.path.join(KIND_DIR, name)
                if os.path.isfile(p) and name.lower().endswith('.txt') and name not in produced_kind:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
        except Exception:
            pass

        # Group by country code (from our remark); fallback to XX
        cc_order: List[str] = []
        cc_groups: Dict[str, List[str]] = {}
        for s in lines:
            parsed = _extract_our_cc_and_num_from_uri(s)
            cc = parsed[0] if parsed else 'XX'
            if cc not in cc_groups:
                cc_groups[cc] = []
                cc_order.append(cc)
            cc_groups[cc].append(s)

        os.makedirs(COUNTERY_DIR, exist_ok=True)
        produced_cc: Set[str] = set()
        for cc in cc_order:
            out_path = os.path.join(COUNTERY_DIR, f'{cc}.txt')
            write_text_file_atomic(out_path, cc_groups[cc])
            produced_cc.add(f'{cc}.txt')
        # Remove stale country txt files
        try:
            for name in os.listdir(COUNTERY_DIR):
                p = os.path.join(COUNTERY_DIR, name)
                if os.path.isfile(p) and name.lower().endswith('.txt') and name not in produced_cc:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
        except Exception:
            pass

    except Exception as e:
        log(f"Writing grouped outputs failed: {e}")


def regroup_available_by_country() -> None:
    try:
        lines = read_lines(AVAILABLE_FILE)
        if not lines:
            return
        order: List[str] = []
        groups: Dict[str, List[str]] = {}
        for line in lines:
            s = line.strip()
            if not s:
                continue
            parsed = _extract_our_cc_and_num_from_uri(s)
            cc = parsed[0] if parsed else 'XX'
            if cc not in groups:
                groups[cc] = []
                order.append(cc)
            groups[cc].append(s)
        tmp_path = AVAILABLE_FILE + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8', errors='ignore') as f:
            for cc in order:
                for item in groups[cc]:
                    f.write(item)
                    f.write('\n')
        os.replace(tmp_path, AVAILABLE_FILE)
        log(f"Regrouped available proxies by country into {len(order)} groups")
    except Exception as e:
        log(f"Regroup failed: {e}")
