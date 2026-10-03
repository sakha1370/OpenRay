from __future__ import annotations

import json
import os
from typing import Dict, Optional, Tuple

CANDIDATE_OUTBOUND_TAG = "openray-candidate"
HTTP_INBOUND_TAG = "openray-test-in"
API_INBOUND_TAG = "api"


def build_pool_daemon_config(http_port: int, api_port: int, http_listen: str = "127.0.0.1") -> Dict:
    """Long-lived worker config: HTTP test inbound + API, blackhole placeholder outbound."""
    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": API_INBOUND_TAG,
            "services": ["HandlerService"],
        },
        "inbounds": [
            {
                "listen": http_listen,
                "port": int(api_port),
                "protocol": "dokodemo-door",
                "settings": {"address": http_listen},
                "tag": API_INBOUND_TAG,
            },
            {
                "listen": http_listen,
                "port": int(http_port),
                "protocol": "http",
                "settings": {},
                "tag": HTTP_INBOUND_TAG,
            },
        ],
        "outbounds": [
            {"protocol": "blackhole", "tag": CANDIDATE_OUTBOUND_TAG},
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "freedom", "tag": API_INBOUND_TAG},
        ],
        "routing": {
            "rules": [
                {"inboundTag": [API_INBOUND_TAG], "outboundTag": API_INBOUND_TAG},
                {"inboundTag": [HTTP_INBOUND_TAG], "outboundTag": CANDIDATE_OUTBOUND_TAG},
            ],
        },
    }


def prepare_config_for_uri(uri: str, http_port: int, http_listen: str = "127.0.0.1") -> Optional[Dict]:
    """Build full Xray config with HTTP inbound on a fixed port."""
    try:
        from ..v2ray import build_config_for_uri
    except Exception:
        return None

    built = build_config_for_uri(uri)
    if not built:
        return None
    _tag, cfg = built
    # Validation owns exactly one inbound. Never retain the legacy fixed SOCKS port.
    inb = []
    inb.append(
        {
            "listen": http_listen,
            "port": int(http_port),
            "protocol": "http",
            "settings": {},
            "tag": HTTP_INBOUND_TAG,
        }
    )
    cfg["inbounds"] = inb
    return cfg


def write_config(path: str, cfg: Dict) -> None:
    from pathlib import Path
    from openray.files import atomic_write, json_text

    atomic_write(Path(path), json_text(cfg))


def worker_config_path(state_dir: str, worker_id: int) -> str:
    d = os.path.join(state_dir, "stage3")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"worker_{worker_id}.json")


def worker_outbound_config_path(state_dir: str, worker_id: int) -> str:
    d = os.path.join(state_dir, "stage3")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"worker_{worker_id}_outbound.json")
