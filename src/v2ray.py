"""Compatibility exports for Xray-supported connections."""

from pathlib import Path
import re
from openray.domain import parse_uri
from openray.files import atomic_write, json_text
from openray.render import xray_outbound
from .constants import OUTPUT_DIR


def build_outbound_for_uri(uri):
    try:
        return xray_outbound(parse_uri(uri))
    except (ValueError, KeyError):
        return None


def build_config_for_uri(uri):
    outbound = build_outbound_for_uri(uri)
    if not outbound:
        return None
    p = parse_uri(uri)
    return p.remark or p.identity[:12], {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound],
    }


def export_v2ray_configs(uris, out_dir=None):
    count = 0
    directory = Path(out_dir or Path(OUTPUT_DIR) / "v2ray_configs")
    for uri in uris:
        built = build_config_for_uri(uri)
        if built:
            name = re.sub(r'[\\/:*?"<>|]', "_", built[0])
            name = re.sub(r"\s+", "_", name).strip("._ ")[:120] or "config"
            atomic_write(directory / (name + ".json"), json_text(built[1]))
            count += 1
    return count


build_vless_config = build_vmess_config = build_trojan_config = build_ss_config = build_ssr_config = (
    build_hysteria_config
) = build_tuic_config = build_juicity_config = build_wireguard_config = build_config_for_uri
