from __future__ import annotations

import os
import subprocess
import threading
from typing import Any, Dict, Optional

from .config_helpers import CANDIDATE_OUTBOUND_TAG, write_config


def _encode_remove_outbound_request(tag: str) -> bytes:
    """Minimal protobuf wire encoding for RemoveOutboundRequest { string tag = 1; }."""
    tag_bytes = tag.encode('utf-8')
    if len(tag_bytes) > 127:
        raise ValueError('tag too long')
    return bytes([0x0A, len(tag_bytes)]) + tag_bytes


def _api_timeout_s() -> int:
    val = os.environ.get('OPENRAY_STAGE3_API_TIMEOUT_S')
    if val is None:
        return 5
    try:
        return max(1, min(int(val), 60))
    except Exception:
        return 5


def _grpc_swap_enabled() -> bool:
    val = os.environ.get('OPENRAY_STAGE3_GRPC_SWAP', '1').strip().lower()
    return val not in ('0', 'false', 'no', 'off')


def _creationflags() -> int:
    return (
        subprocess.CREATE_NO_WINDOW
        if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW')
        else 0
    )


class XrayApiSession:
    """Persistent gRPC channel for HandlerService/RemoveOutbound on one Xray daemon."""

    _REMOVE_METHOD = '/xray.app.proxyman.command.HandlerService/RemoveOutbound'

    def __init__(self, api_addr: str):
        self.api_addr = api_addr
        self._lock = threading.Lock()
        self._channel = None
        self._stub = None

    def _ensure_stub(self):
        if self._stub is not None:
            return True
        try:
            import grpc
        except ImportError:
            return False

        host, _, port_s = self.api_addr.rpartition(':')
        if not host:
            host, port_s = '127.0.0.1', self.api_addr
        target = f'{host}:{port_s}'
        try:
            self._channel = grpc.insecure_channel(target)
            self._stub = self._channel.unary_unary(
                self._REMOVE_METHOD,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            return True
        except Exception:
            self.close()
            return False

    def remove_outbound(self, tag: str) -> bool:
        if not tag or not _grpc_swap_enabled():
            return False
        with self._lock:
            if not self._ensure_stub():
                return False
            try:
                self._stub(_encode_remove_outbound_request(tag), timeout=float(_api_timeout_s()))
                return True
            except Exception:
                self.close()
                return False

    def close(self) -> None:
        with self._lock:
            if self._channel is not None:
                try:
                    self._channel.close()
                except Exception:
                    pass
            self._channel = None
            self._stub = None


def remove_outbound_via_cli(core_path: str, api_addr: str, tag: str) -> bool:
    """Remove an outbound via `xray api rmo` (best-effort)."""
    path = (core_path or '').strip()
    if not path or not tag:
        return False
    try:
        proc = subprocess.run(
            [path, 'api', 'rmo', f'-server={api_addr}', tag],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_api_timeout_s(),
            creationflags=_creationflags(),
        )
        return proc.returncode == 0
    except Exception:
        return False


def add_outbound_via_cli(core_path: str, api_addr: str, outbound_path: str) -> bool:
    """Add outbound(s) from JSON file via `xray api ado`."""
    path = (core_path or '').strip()
    if not path or not outbound_path or not os.path.exists(outbound_path):
        return False
    try:
        proc = subprocess.run(
            [path, 'api', 'ado', f'-server={api_addr}', outbound_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_api_timeout_s(),
            creationflags=_creationflags(),
        )
        return proc.returncode == 0
    except Exception:
        return False


def swap_candidate_outbound(
    core_path: str,
    api_addr: str,
    outbound: Dict[str, Any],
    outbound_path: str,
    tag: str = CANDIDATE_OUTBOUND_TAG,
    session: Optional[XrayApiSession] = None,
) -> bool:
    """Replace the candidate outbound on a running daemon without restarting Xray."""
    ob = dict(outbound)
    ob['tag'] = tag
    write_config(outbound_path, {'outbounds': [ob]})
    removed = False
    if session is not None:
        removed = session.remove_outbound(tag)
    if not removed:
        remove_outbound_via_cli(core_path, api_addr, tag)
    return add_outbound_via_cli(core_path, api_addr, outbound_path)


def remove_outbound(tag: str, api_addr: str) -> bool:
    """Best-effort RemoveOutbound via gRPC; returns True if call succeeded."""
    session = XrayApiSession(api_addr)
    try:
        return session.remove_outbound(tag)
    finally:
        session.close()


def add_outbound_from_config(
    outbound: Dict[str, Any],
    api_addr: str,
    core_path: Optional[str] = None,
    outbound_path: Optional[str] = None,
) -> bool:
    """Add outbound via CLI when core_path and outbound_path are provided."""
    if not core_path or not outbound_path:
        return False
    ob = dict(outbound)
    if not ob.get('tag'):
        ob['tag'] = CANDIDATE_OUTBOUND_TAG
    write_config(outbound_path, {'outbounds': [ob]})
    return add_outbound_via_cli(core_path, api_addr, outbound_path)
