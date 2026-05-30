from __future__ import annotations

import json
import os
from typing import Dict, Optional, Tuple


def prepare_config_for_uri(uri: str, http_port: int, http_listen: str = '127.0.0.1') -> Optional[Dict]:
    """Build full Xray config with HTTP inbound on a fixed port."""
    try:
        from ..v2ray import build_config_for_uri
    except Exception:
        return None

    built = build_config_for_uri(uri)
    if not built:
        return None
    _tag, cfg = built
    inb = cfg.get('inbounds') or []
    if not isinstance(inb, list):
        inb = []
    inb.append({
        'listen': http_listen,
        'port': int(http_port),
        'protocol': 'http',
        'settings': {},
        'tag': 'openray-test-in',
    })
    cfg['inbounds'] = inb
    return cfg


def write_config(path: str, cfg: Dict) -> None:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)


def worker_config_path(state_dir: str, worker_id: int) -> str:
    d = os.path.join(state_dir, 'stage3')
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f'worker_{worker_id}.json')
