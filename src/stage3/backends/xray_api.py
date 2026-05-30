from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional

from ...constants import REPO_ROOT, V2RAY_CORE_PATH
from ..config_helpers import write_config
from ..grpc_client import remove_outbound
from ..metrics import record_check
from ..probe import probe_http_proxy
from ..types import TimingStats
from .base import Stage3Backend
from .pool import PoolBackend
from .subprocess import _min_attempt_seconds, _stage3_env_int, _terminate_proc

_CANDIDATE_TAG = 'candidate'


def _parse_api_addr(api_addr: str) -> tuple:
    if ':' in api_addr:
        host, port_s = api_addr.rsplit(':', 1)
        return host, int(port_s)
    return '127.0.0.1', int(api_addr)


def _build_daemon_config(outbound: Dict, http_port: int, api_port: int) -> Dict:
    ob = dict(outbound)
    ob['tag'] = _CANDIDATE_TAG
    return {
        'log': {'loglevel': 'warning'},
        'api': {
            'tag': 'api',
            'services': ['HandlerService'],
        },
        'inbounds': [
            {
                'listen': '127.0.0.1',
                'port': api_port,
                'protocol': 'dokodemo-door',
                'settings': {'address': '127.0.0.1'},
                'tag': 'api',
            },
            {
                'listen': '127.0.0.1',
                'port': http_port,
                'protocol': 'http',
                'settings': {},
                'tag': 'openray-test-in',
            },
        ],
        'outbounds': [
            ob,
            {'protocol': 'freedom', 'tag': 'direct'},
            {'protocol': 'freedom', 'tag': 'api'},
        ],
        'routing': {
            'rules': [
                {'inboundTag': ['api'], 'outboundTag': 'api'},
                {'inboundTag': ['openray-test-in'], 'outboundTag': _CANDIDATE_TAG},
            ],
        },
    }


class XrayApiBackend(Stage3Backend):
    """
    Single long-lived Xray daemon with API enabled.
    Swaps outbound by reloading config (grpc RemoveOutbound for cleanup when possible).
    Falls back to pool backend per URI on failure.
    """

    def __init__(self) -> None:
        path = (V2RAY_CORE_PATH or '').strip()
        self._core_path = path
        self._enabled = bool(path and os.path.exists(path))
        self._http_port = _stage3_env_int('OPENRAY_STAGE3_BASE_PORT', 31888, 1024, 60000)
        api_addr = os.environ.get('OPENRAY_STAGE3_API_ADDR', '127.0.0.1:10085').strip()
        self._api_host, self._api_port = _parse_api_addr(api_addr)
        self._api_addr = f'{self._api_host}:{self._api_port}'
        self._config_path = os.path.join(REPO_ROOT, '.state', 'stage3', 'api_daemon.json')
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._pool_fallback = PoolBackend(pool_size=_stage3_env_int('OPENRAY_STAGE3_POOL_SIZE', 4, 1, 64))

    def _creationflags(self) -> int:
        return (
            subprocess.CREATE_NO_WINDOW
            if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW')
            else 0
        )

    def _stop_daemon(self) -> None:
        with self._lock:
            _terminate_proc(self._proc)
            self._proc = None

    def _wait_ready(self, proc: subprocess.Popen) -> bool:
        start = time.time()
        while time.time() - start < 2.0:
            if proc.poll() is not None:
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    if s.connect_ex(('127.0.0.1', self._http_port)) == 0:
                        return True
            except Exception:
                pass
            time.sleep(0.08)
        return False

    def _restart_daemon(self, cfg: Dict) -> bool:
        with self._lock:
            remove_outbound(_CANDIDATE_TAG, self._api_addr)
            write_config(self._config_path, cfg)
            _terminate_proc(self._proc)
            self._proc = None
            try:
                self._proc = subprocess.Popen(
                    [self._core_path, '-config', self._config_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=self._creationflags(),
                )
            except Exception:
                return False
            return self._wait_ready(self._proc)

    def validate_one(self, uri: str, timeout_s: int = 60) -> Optional[bool]:
        if not self._enabled:
            return None

        timing = TimingStats()
        t0 = time.perf_counter()
        try:
            from ...v2ray import build_outbound_for_uri
        except Exception:
            return self._pool_fallback.validate_one(uri, timeout_s)

        outbound = build_outbound_for_uri(uri)
        timing.config_ms = (time.perf_counter() - t0) * 1000
        if not outbound:
            record_check(None, timing)
            return None

        cfg = _build_daemon_config(outbound, self._http_port, self._api_port)
        t_spawn = time.perf_counter()
        if not self._restart_daemon(cfg):
            return self._pool_fallback.validate_one(uri, timeout_s)
        timing.spawn_ms = (time.perf_counter() - t_spawn) * 1000

        attempt_timeout = max(_min_attempt_seconds(), float(timeout_s))
        t_fetch = time.perf_counter()
        ok = probe_http_proxy(self._http_port, time.time() + attempt_timeout)
        timing.fetch_ms = (time.perf_counter() - t_fetch) * 1000

        result = True if ok else False
        record_check(result, timing)
        if not ok:
            return result
        return result

    def validate_many(self, uris: List[str], timeout_s: int) -> Dict[str, Optional[bool]]:
        if not self._enabled:
            return {u: None for u in uris if u}
        return {u: self.validate_one(u, timeout_s) for u in uris if u}

    def shutdown(self) -> None:
        self._stop_daemon()
        self._pool_fallback.shutdown()
